"""Command line entrypoint for the standalone LRSA workflow."""

import argparse
import subprocess
import sys
from pathlib import Path

from requests.exceptions import RequestException

from .auth import extract_token_from_file, save_json
from .boot_chain import (
    DEFAULT_BOOT_CHAIN_LABELS,
    format_verify_result,
    verify_boot_chain,
)
from .client import LRSAClient
from .config import (
    DEFAULT_EDL,
    DEFAULT_MODEL,
    DEFAULT_SN,
    DEFAULT_STOCK_DIR,
    DEFAULT_WORK_DIR,
)
from .device_preflight import format_usb_devices, require_qualcomm_edl_device
from .firmware import (
    pick_firmware_url,
    response_payload,
)
from .flow_checks import validate_fastboot_recipe_checks
from .login import guest_login as run_guest_login, lenovoid_login as run_lenovoid_login
from .qfil import format_command, resolve_qfil_image_dir
from qfil import (
    build_qfil_module_command,
    parse_program_entries,
    parse_rescue_cmd,
    run_qfil_plan,
    summarize_plan,
)
from .resources import (
    api_payload,
    content_list,
    is_success_payload,
    resource_at,
    resource_summary,
)
from .software_fix_flow import (
    DEFAULT_WHISKY_BOTTLE,
    is_mobile_or_tablet,
    load_flow,
    prepare_artifacts,
    whisky_command,
)


def resource_match_preflight(
    resource, lookup_kind, lookup_value, require_success=False
):
    rom_match_id = str(resource.get("romMatchId") or "")
    model = (
        resource.get("modelName") or resource.get("realModelName") or "(unknown model)"
    )
    platform = resource.get("platform") or "(unknown platform)"
    category = resource.get("category") or "(unknown category)"
    status = "PASS" if rom_match_id.lower().startswith("success") else "CHECK"
    print(
        f"Resource preflight [{status}]: {lookup_kind}={lookup_value} -> "
        f"{model} / {platform} / {category} / romMatchId={rom_match_id or '(none)'}"
    )
    if require_success and not rom_match_id.lower().startswith("success"):
        raise RuntimeError(
            f"Refusing to flash: Lenovo did not return a success romMatchId ({rom_match_id or 'none'})."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Run LRSA login -> firmware -> QFIL workflow"
    )
    parser.add_argument(
        "--menu", action="store_true", help="Open the interactive menu."
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--sn", default=DEFAULT_SN)
    parser.add_argument(
        "--imei", help="Use IMEI lookup for phones/mobile devices instead of SN lookup."
    )
    parser.add_argument("--imei2", help="Second IMEI for dual-SIM phone lookup.")
    parser.add_argument(
        "--firmware-index",
        type=int,
        help="Select one resource from a multi-firmware response.",
    )
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument(
        "--image-dir",
        type=Path,
        help="Use an existing extracted firmware/image directory",
    )
    parser.add_argument("--stock-dir", type=Path, default=DEFAULT_STOCK_DIR)
    parser.add_argument("--token")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--client-uuid")
    parser.add_argument(
        "--login", choices=["guest", "lenovoid", "none"], default="lenovoid"
    )
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--download", action="store_true", help="Download firmware URL returned by LRSA"
    )
    parser.add_argument(
        "--extract", action="store_true", help="Extract downloaded firmware archive"
    )
    parser.add_argument(
        "--flow",
        choices=["software-fix"],
        default="software-fix",
        help="Use Lenovo Software Fix artifacts and the native qfil module.",
    )
    parser.add_argument(
        "--no-tool-download",
        action="store_true",
        help="Skip downloading/extracting the Software Fix flash tool package.",
    )
    parser.add_argument(
        "--backend",
        choices=["native", "whisky"],
        default="native",
        help="native uses the local qfil module for Rescue.cmd flows; whisky runs Lenovo's Windows tools.",
    )
    parser.add_argument("--whisky-bottle", default=DEFAULT_WHISKY_BOTTLE)
    parser.add_argument(
        "--com-port",
        help="Detected Qualcomm port for Software Fix startup files, e.g. COM3 or 3.",
    )
    parser.add_argument(
        "--skip-api",
        action="store_true",
        help="Skip LRSA API calls and only prepare QFIL",
    )
    parser.add_argument(
        "--only-login", action="store_true", help="Authenticate, save session, and exit"
    )
    parser.add_argument("--edl", type=Path, default=DEFAULT_EDL)
    parser.add_argument("--loader", type=Path)
    parser.add_argument(
        "--fastboot",
        type=Path,
        help="Native fastboot binary for recipes that require fastboot checks.",
    )
    parser.add_argument(
        "--skip-edl-preflight",
        action="store_true",
        help="Skip Qualcomm 9008 USB detection before --flash.",
    )
    parser.add_argument(
        "--allow-stock-flash",
        action="store_true",
        help="Allow --flash using --stock-dir fallback instead of an official downloaded/extracted ROM.",
    )
    parser.add_argument("--all-xml", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--flash",
        action="store_true",
        help="Execute the selected flashing flow when supported.",
    )
    parser.add_argument(
        "--verify-boot-chain",
        action="store_true",
        help="Read back critical boot-chain partitions from EDL and compare with the selected image directory.",
    )
    parser.add_argument(
        "--boot-chain-labels",
        default=",".join(DEFAULT_BOOT_CHAIN_LABELS),
        help="Comma-separated labels for --verify-boot-chain.",
    )
    parser.add_argument(
        "--verify-timeout",
        type=int,
        default=90,
        help="Per-partition timeout in seconds for --verify-boot-chain readbacks.",
    )
    args = parser.parse_args()

    if args.menu:
        from .menu import main as menu_main

        menu_main()
        return

    if args.verify_boot_chain:
        image_dir = args.image_dir or args.work_dir / "software_fix" / "rom"
        image_dir = resolve_qfil_image_dir(image_dir)
        if not image_dir.exists():
            raise RuntimeError(f"Image directory does not exist: {image_dir}")
        if not args.edl.exists():
            raise RuntimeError(f"edl.py not found: {args.edl}")
        if not args.skip_edl_preflight:
            devices = require_qualcomm_edl_device()
            print(f"EDL preflight passed: {format_usb_devices(devices)}")
        labels = tuple(
            part.strip() for part in args.boot_chain_labels.split(",") if part.strip()
        )
        print(f"Verifying boot-chain readback against: {image_dir}")
        print(f"Labels: {', '.join(labels)}")
        results = verify_boot_chain(
            image_dir,
            args.work_dir,
            args.edl,
            loader=args.loader,
            labels=labels,
            timeout=args.verify_timeout,
        )
        output_path = args.work_dir / "boot_chain_verify.json"
        save_json(output_path, {"imageDir": str(image_dir), "results": results})
        for result in results:
            print(format_verify_result(result))
        failed = [result for result in results if result.get("status") == "FAIL"]
        print(f"Boot-chain verification saved: {output_path}")
        if failed:
            raise RuntimeError(
                f"{len(failed)} boot-chain partition(s) failed verification."
            )
        return

    token = args.token
    if args.token_file:
        token = extract_token_from_file(args.token_file)
    elif args.login == "lenovoid" and not args.only_login:
        session = run_lenovoid_login(
            open_browser=not args.no_browser,
            client_uuid=args.client_uuid,
            token=token,
        )
        token = session.get("token")
        save_json(args.work_dir / "login_session.json", session)

    client = LRSAClient(token=token, client_uuid=args.client_uuid)

    if args.only_login:
        if token:
            session = {"method": "existing-token", "token": token}
        elif args.login == "guest":
            session = run_guest_login()
        elif args.login == "lenovoid":
            session = run_lenovoid_login(
                open_browser=not args.no_browser,
                client_uuid=args.client_uuid,
                token=token,
            )
        else:
            session = {"method": "none", "token": token}
        save_json(args.work_dir / "login_session.json", session)
        print(f"Saved login session: {args.work_dir / 'login_session.json'}")
        return

    if args.login == "guest" and not token and not args.skip_api:
        print("Bootstrapping guest session...")
        for name, result in client.bootstrap_guest_session():
            print(f"{name}: HTTP {result['status']}")
        if client.token:
            print("Guest token captured.")

    firmware_url = None
    resource = None
    if not args.skip_api:
        if args.imei:
            print(f"\nQuerying rescue ROM by IMEI: {args.imei}")
            result = client.get_resources_by_imei(args.imei, args.imei2)
        else:
            if not args.model or not args.sn:
                parser.error(
                    "SN lookup requires --model and --sn, or use --imei for phone/mobile lookup."
                )
            print(f"\nQuerying rescue ROM by SN: model={args.model}, sn={args.sn}")
            result = client.get_rescue_rom(args.model, args.sn)
        payload = response_payload(result)
        save_json(args.work_dir / "rescue_rom_response.json", payload)
        print(f"Rescue response saved: {args.work_dir / 'rescue_rom_response.json'}")

        api = api_payload(result)
        if not is_success_payload(api):
            code = api.get("code") if isinstance(api, dict) else None
            desc = api.get("desc") if isinstance(api, dict) else None
            raise RuntimeError(
                f"LRSA resource lookup failed: code={code or '(none)'} desc={desc or '(none)'}. "
                "Run Login / capture Lenovo token again if the token is invalid or expired."
            )

        resources = content_list(api)
        if not resources:
            raise RuntimeError(
                "LRSA returned success but no firmware resources. Check the device identity: "
                "use IMEI for phones/mobile, or correct Model + SN for tablet/laptop lookup."
            )
        if len(resources) > 1:
            print("\nAvailable firmware resources:")
            for index, candidate in enumerate(resources):
                summary = resource_summary(candidate)
                print(
                    f"  [{index}] {summary.get('firmwareName') or '(unnamed firmware)'} "
                    f"- {summary.get('modelName') or '(unknown model)'} "
                    f"romMatchId={summary.get('romMatchId') or '(none)'}"
                )

        resource = resource_at(api, args.firmware_index)
        summary = resource_summary(resource)
        if summary:
            print(
                f"Matched resource: {summary.get('modelName')} ({summary.get('category')})"
            )
            if summary.get("firmwareName"):
                print(f"Firmware: {summary['firmwareName']}")
        if resource:
            resource_match_preflight(
                resource,
                "IMEI" if args.imei else "SN",
                args.imei or args.sn,
                require_success=args.flash,
            )

        firmware_url = pick_firmware_url(payload, resource_index=args.firmware_index)
        if firmware_url:
            print(f"Firmware URL candidate: {firmware_url}")
        else:
            print("No firmware URL found in response.")
    else:
        print("Skipping LRSA API calls.")

    if args.flow == "software-fix":
        if not resource:
            raise RuntimeError(
                "Software Fix flow needs a firmware resource response; remove --skip-api"
            )
        if not is_mobile_or_tablet(resource):
            raise RuntimeError(
                f"Software Fix mobile/tablet flow does not support category: {resource.get('category')}"
            )

        print("\nPreparing Software Fix artifacts...")
        manifest = prepare_artifacts(
            resource,
            args.work_dir,
            download_rom=args.download,
            extract_rom=args.extract,
            download_tool=(args.backend == "whisky" and not args.no_tool_download),
            extract_tool=(args.backend == "whisky" and not args.no_tool_download),
            com_port=args.com_port,
        )
        manifest_path = args.work_dir / "software_fix" / "manifest.json"
        save_json(manifest_path, manifest)
        print(f"Software Fix manifest saved: {manifest_path}")

        if manifest.get("flashFlowSummary"):
            print("\nSoftware Fix flash flow:")
            for line in manifest["flashFlowSummary"]:
                print(f"  {line}")

        if manifest.get("toolDir"):
            print(f"\nTool package ready: {manifest['toolDir']}")
        if manifest.get("toolMd5"):
            status = manifest["toolMd5"]
            if status.get("skipped"):
                print("Tool MD5 check skipped: Lenovo did not provide an MD5.")
            else:
                print(f"Tool MD5 verified: {status['actual']}")
        if manifest.get("romArchive"):
            print(f"ROM archive ready: {manifest['romArchive']}")
        if manifest.get("romMd5"):
            status = manifest["romMd5"]
            if status.get("skipped"):
                print("ROM MD5 check skipped: Lenovo did not provide an MD5.")
            else:
                print(f"ROM MD5 verified: {status['actual']}")
        if manifest.get("decryptedFiles"):
            print(
                f"Decrypted Software Fix ROM helper files: {len(manifest['decryptedFiles'])}"
            )
        if not manifest.get("romArchive") and manifest.get("romUrl"):
            print("ROM archive not downloaded. Add --download to fetch it.")
        if manifest.get("expectedStartupFiles"):
            print(
                "Startup file not found. Add --download --extract so the ROM package can provide "
                + "/".join(manifest["expectedStartupFiles"])
                + "."
            )
        if manifest.get("startupCommands"):
            print("\nSoftware Fix startup command plan:")
            for item in manifest["startupCommands"]:
                exe = item.get("executable") or f"missing:{item.get('exePattern')}"
                print(f"  {Path(exe).name}: {item.get('arguments', '')}")
        if manifest.get("missingStartupTools"):
            print(
                f"Missing startup tools: {', '.join(manifest['missingStartupTools'])}"
            )

        if args.backend == "native":
            if (
                args.flash
                and not args.allow_stock_flash
                and not manifest.get("romDir")
                and not args.image_dir
            ):
                raise RuntimeError(
                    "Refusing native --flash from stock fallback. Use --download --extract for the matched Lenovo ROM, "
                    "or pass --image-dir for a verified extracted ROM, or --allow-stock-flash explicitly."
                )
            native_base_dir = Path(
                manifest.get("romDir") or args.image_dir or args.stock_dir
            ).resolve()
            if not native_base_dir.exists():
                raise RuntimeError(
                    f"Native backend image directory does not exist: {native_base_dir}"
                )
            native_image_dir = resolve_qfil_image_dir(
                native_base_dir, manifest.get("startupFile")
            )
            if not native_image_dir.exists():
                raise RuntimeError(
                    f"Native backend image directory does not exist: {native_image_dir}"
                )
            if manifest.get("flashFlowPath"):
                flow = load_flow(Path(manifest["flashFlowPath"]))
                fastboot_result = validate_fastboot_recipe_checks(
                    flow,
                    resource,
                    image_dir=native_image_dir,
                    fastboot=args.fastboot,
                    require=args.flash,
                )
                if fastboot_result["requiredSteps"]:
                    print(
                        f"Fastboot recipe checks: {', '.join(fastboot_result['requiredSteps'])}"
                    )
                    if fastboot_result["checked"]:
                        print("Fastboot property preflight passed.")
                    elif fastboot_result.get("warning"):
                        print(
                            f"Fastboot property preflight warning: {fastboot_result['warning']}"
                        )
                else:
                    print("Fastboot recipe checks: none required by this flow.")
            if args.all_xml:
                raise RuntimeError(
                    "--all-xml is no longer supported for flashing; native QFIL follows Rescue.cmd exactly."
                )
            if not manifest.get("startupFile"):
                raise RuntimeError(
                    "Native QFIL requires the official Software Fix StartupFile. "
                    "Run with --download --extract so the ROM package provides Rescue.cmd/Flash.cmd."
                )
            qfil_plan = parse_rescue_cmd(
                Path(manifest["startupFile"]), native_image_dir
            )
            if (
                args.loader
                and qfil_plan.programmer
                and Path(args.loader).resolve() != qfil_plan.programmer.loader
            ):
                raise RuntimeError(
                    "Refusing loader override because Rescue.cmd provides the official programmer: "
                    f"{qfil_plan.programmer.loader}"
                )
            print("\nSoftware Fix QFIL compatibility plan:")
            for line in summarize_plan(qfil_plan):
                print(f"  {line}")
            rawprograms = list(qfil_plan.firehose.rawprograms)
            patches = list(qfil_plan.firehose.patches)
            command = build_qfil_module_command(qfil_plan)
            missing_xml = [
                str(path)
                for path in [*rawprograms, *patches]
                if not Path(path).exists()
            ]
            if missing_xml:
                raise RuntimeError(
                    f"Native QFIL XML preflight failed under {native_image_dir}: missing {', '.join(missing_xml)}"
                )
            print("\nNative Python Sahara/Firehose plan:")
            print(f"Rawprogram XMLs: {', '.join(p.name for p in rawprograms)}")
            print(
                f"Patch XMLs: {', '.join(p.name for p in patches) if patches else '(none)'}"
            )
            program_entries = parse_program_entries(rawprograms)
            if program_entries:
                print(f"Program entries: {len(program_entries)}")
                print("Program order:")
                for entry in program_entries[:24]:
                    sectors = entry.sectors if entry.sectors is not None else "dynamic"
                    print(
                        f"  {entry.xml.name}: {entry.filename} -> {entry.label} "
                        f"lun={entry.lun} sector={entry.start_sector} sectors={sectors}"
                    )
                if len(program_entries) > 24:
                    print(f"  ... {len(program_entries) - 24} more entries")
            print(" ".join(command))
            if args.flash:
                if not args.skip_edl_preflight:
                    devices = require_qualcomm_edl_device()
                    print(f"EDL preflight passed: {format_usb_devices(devices)}")
                print(
                    "\nExecuting native flash. Device must already be in Qualcomm 9008 EDL mode."
                )
                run_qfil_plan(qfil_plan, dry_run=False)
            else:
                print("\nDry run only. Add --flash to execute native flashing.")
            return

        startup = manifest.get("startupFile")
        if args.flash:
            startup_commands = manifest.get("startupCommands") or []
            if startup and startup_commands:
                if manifest.get("startupRequiresComPort") and not args.com_port:
                    raise RuntimeError(
                        "Startup file needs a COM port. Re-run with --com-port COMx."
                    )
                if manifest.get("missingStartupTools"):
                    raise RuntimeError(
                        "Startup file references tools that were not found: "
                        + ", ".join(manifest["missingStartupTools"])
                    )

                print("\nExecuting Software Fix command plan:")
                for item in startup_commands:
                    executable = Path(item["executable"])
                    command = whisky_command(
                        executable, args.whisky_bottle, *item.get("argv", [])
                    )
                    print(format_command(command, cwd=executable.parent))
                    subprocess.run(command, cwd=executable.parent, check=True)
            else:
                raise RuntimeError(
                    "Software Fix flow did not produce the StartupFile yet. "
                    "Download and extract the ROM package; Software Fix expects Rescue.cmd/Flash.cmd there."
                )
        elif manifest.get("qfilExe"):
            command = whisky_command(
                Path(manifest["qfilExe"]), args.whisky_bottle, "--command"
            )
            print("\nQFIL launch command through Whisky:")
            print(format_command(command, cwd=Path(manifest["qfilExe"]).parent))
            print(
                "\nDry run only. Add --download --extract, then --flash after the startup file is present."
            )
        else:
            print(
                "\nWhisky backend selected, but QFIL.exe was not prepared. Remove --no-tool-download."
            )
        return

    raise RuntimeError(
        "Unsupported flow. Native flashing must use the Software Fix qfil module path."
    )


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError,
        IndexError,
        RequestException,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
