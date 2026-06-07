"""Command line entrypoint for the reusable LRSA workflow."""

from lrsa.logging import get_logger

import argparse
from pathlib import Path

from requests.exceptions import RequestException

from .auth import extract_token_from_file, save_json
from .api.client import LRSAClient
from .api.firmware import (
    pick_firmware_url,
    response_payload,
)
from .api.resources import (
    api_payload,
    content_list,
    is_success_payload,
    resource_at,
    resource_summary,
)
from .device.flow_checks import validate_fastboot_recipe_checks
from .device.preflight import ensure_qualcomm_edl_device, format_usb_devices
from .config import (
    DEFAULT_MODEL,
    DEFAULT_SN,
    DEFAULT_STOCK_DIR,
    DEFAULT_WORK_DIR,
)
from .auth.login import (
    guest_login as run_guest_login,
    lenovoid_login as run_lenovoid_login,
)
from .flash.qfil import resolve_qfil_image_dir
from qfil import (
    build_qfil_module_command,
    parse_program_entries,
    parse_rescue_cmd,
    summarize_plan,
)
from qfil.tools.qfil import run_qfil_plan
from .flash.software_fix_flow import (
    is_mobile_or_tablet,
    load_flow,
    prepare_artifacts,
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
    get_logger(__name__).info(
        f"Resource preflight [{status}]: {lookup_kind}={lookup_value} -> "
        f"{model} / {platform} / {category} / romMatchId={rom_match_id or '(none)'}"
    )
    if require_success and not rom_match_id.lower().startswith("success"):
        raise RuntimeError(
            f"Refusing to flash: Lenovo did not return a success romMatchId ({rom_match_id or 'none'})."
        )


def find_rescue_cmd(root: Path) -> Path | None:
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower() == "rescue.cmd":
            return path
    return None


def run_qfil_image_plan(
    *,
    base_dir: Path,
    startup_file: Path | None,
    loader: Path | None,
    flash: bool,
    skip_edl_preflight: bool,
) -> None:
    native_base_dir = base_dir.resolve()
    if not native_base_dir.exists():
        raise RuntimeError(
            f"Native qfil image directory does not exist: {native_base_dir}"
        )
    startup = startup_file or find_rescue_cmd(native_base_dir)
    if startup is None:
        raise RuntimeError(f"No Rescue.cmd found under {native_base_dir}")
    startup = startup.resolve()
    native_image_dir = resolve_qfil_image_dir(native_base_dir, startup)
    if not native_image_dir.exists():
        raise RuntimeError(
            f"Native qfil image directory does not exist: {native_image_dir}"
        )
    qfil_plan = parse_rescue_cmd(startup, native_image_dir)
    if (
        loader
        and qfil_plan.programmer
        and loader.resolve() != qfil_plan.programmer.loader
    ):
        raise RuntimeError(
            "Refusing loader override because Rescue.cmd provides the official programmer: "
            f"{qfil_plan.programmer.loader}"
        )
    get_logger(__name__).info("\nSoftware Fix qfil compatibility plan:")
    for line in summarize_plan(qfil_plan):
        get_logger(__name__).info(f"  {line}")
    rawprograms = list(qfil_plan.firehose.rawprograms)
    patches = list(qfil_plan.firehose.patches)
    command = build_qfil_module_command(qfil_plan)
    missing_xml = [
        str(path) for path in [*rawprograms, *patches] if not Path(path).exists()
    ]
    if missing_xml:
        raise RuntimeError(
            f"Native qfil XML preflight failed under {native_image_dir}: missing {', '.join(missing_xml)}"
        )
    get_logger(__name__).info("\nNative Python Sahara/Firehose plan:")
    get_logger(__name__).info(
        f"Rawprogram XMLs: {', '.join(p.name for p in rawprograms)}"
    )
    get_logger(__name__).info(
        f"Patch XMLs: {', '.join(p.name for p in patches) if patches else '(none)'}"
    )
    program_entries = parse_program_entries(rawprograms)
    if program_entries:
        get_logger(__name__).info(f"Program entries: {len(program_entries)}")
        get_logger(__name__).info("Program order:")
        for entry in program_entries[:24]:
            sectors = entry.sectors if entry.sectors is not None else "dynamic"
            get_logger(__name__).info(
                f"  {entry.xml.name}: {entry.filename} -> {entry.label} "
                f"lun={entry.lun} sector={entry.start_sector} sectors={sectors}"
            )
        if len(program_entries) > 24:
            get_logger(__name__).info(f"  ... {len(program_entries) - 24} more entries")
    get_logger(__name__).info(" ".join(command))
    if flash:
        if not skip_edl_preflight:
            devices = ensure_qualcomm_edl_device()
            get_logger(__name__).info(
                f"EDL preflight passed: {format_usb_devices(devices)}"
            )
        get_logger(__name__).info(
            "\nExecuting native flash. Device must already be in Qualcomm 9008 EDL mode."
        )
        run_qfil_plan(qfil_plan, dry_run=False)
    else:
        get_logger(__name__).info(
            "\nDry run only. Add --flash to execute native flashing."
        )


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="Run LRSA login -> firmware -> QFIL workflow"
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
    parser.add_argument(
        "--startup-file",
        type=Path,
        help="Rescue.cmd path to use with --image-dir/--skip-api.",
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
        "--com-port",
        help="Accepted for compatibility. Native qfil auto-detects the EDL USB transport.",
    )
    parser.add_argument(
        "--skip-api",
        action="store_true",
        help="Skip LRSA API calls and only prepare QFIL",
    )
    parser.add_argument(
        "--only-login", action="store_true", help="Authenticate, save session, and exit"
    )
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
    args = parser.parse_args(argv)

    token = args.token
    if args.model is not None:
        args.model = args.model.strip()
    if args.sn is not None:
        args.sn = args.sn.strip()
    if args.imei is not None:
        args.imei = args.imei.strip()
    if args.imei2 is not None:
        args.imei2 = args.imei2.strip()
    if args.token_file:
        try:
            token = extract_token_from_file(args.token_file)
        except (OSError, ValueError) as exc:
            parser.error(f"Could not read --token-file {args.token_file}: {exc}")
    elif args.login == "lenovoid" and not args.only_login and not args.skip_api:
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
        get_logger(__name__).info(
            f"Saved login session: {args.work_dir / 'login_session.json'}"
        )
        return

    if args.login == "guest" and not token and not args.skip_api:
        get_logger(__name__).info("Bootstrapping guest session...")
        for name, result in client.bootstrap_guest_session():
            get_logger(__name__).info(f"{name}: HTTP {result['status']}")
        if client.token:
            get_logger(__name__).info("Guest token captured.")

    firmware_url = None
    resource = None
    if not args.skip_api:
        if args.imei:
            get_logger(__name__).info(f"\nQuerying rescue ROM by IMEI: {args.imei}")
            result = client.get_resources_by_imei(args.imei, args.imei2)
        else:
            if not args.model or not args.sn:
                parser.error(
                    "SN lookup requires --model and --sn, or use --imei for phone/mobile lookup."
                )
            get_logger(__name__).info(
                f"\nQuerying rescue ROM by SN: model={args.model}, sn={args.sn}"
            )
            result = client.get_rescue_rom(args.model, args.sn)
        payload = response_payload(result)
        save_json(args.work_dir / "rescue_rom_response.json", payload)
        get_logger(__name__).info(
            f"Rescue response saved: {args.work_dir / 'rescue_rom_response.json'}"
        )

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
            get_logger(__name__).info("\nAvailable firmware resources:")
            for index, candidate in enumerate(resources):
                summary = resource_summary(candidate)
                get_logger(__name__).info(
                    f"  [{index}] {summary.get('firmwareName') or '(unnamed firmware)'} "
                    f"- {summary.get('modelName') or '(unknown model)'} "
                    f"romMatchId={summary.get('romMatchId') or '(none)'}"
                )

        resource = resource_at(api, args.firmware_index)
        summary = resource_summary(resource)
        if summary:
            get_logger(__name__).info(
                f"Matched resource: {summary.get('modelName')} ({summary.get('category')})"
            )
            if summary.get("firmwareName"):
                get_logger(__name__).info(f"Firmware: {summary['firmwareName']}")
        if resource:
            resource_match_preflight(
                resource,
                "IMEI" if args.imei else "SN",
                args.imei or args.sn,
                require_success=args.flash,
            )

        firmware_url = pick_firmware_url(payload, resource_index=args.firmware_index)
        if firmware_url:
            get_logger(__name__).info(f"Firmware URL candidate: {firmware_url}")
        else:
            get_logger(__name__).info("No firmware URL found in response.")
    else:
        if args.skip_api and args.image_dir:
            get_logger(__name__).info("Skipping LRSA API calls.")
            run_qfil_image_plan(
                base_dir=args.image_dir,
                startup_file=args.startup_file,
                loader=args.loader,
                flash=args.flash,
                skip_edl_preflight=args.skip_edl_preflight,
            )
            return
        get_logger(__name__).info("Skipping LRSA API calls.")
    if args.flow == "software-fix":
        if not resource:
            raise RuntimeError(
                "Software Fix flow needs a firmware resource response; remove --skip-api"
            )
        if not is_mobile_or_tablet(resource):
            raise RuntimeError(
                f"Software Fix mobile/tablet flow does not support category: {resource.get('category')}"
            )

        get_logger(__name__).info("\nPreparing Software Fix artifacts...")
        manifest = prepare_artifacts(
            resource,
            args.work_dir,
            download_rom=args.download,
            extract_rom=args.extract,
        )
        manifest_path = args.work_dir / "software_fix" / "manifest.json"
        save_json(manifest_path, manifest)
        get_logger(__name__).info(f"Software Fix manifest saved: {manifest_path}")

        if manifest.get("flashFlowSummary"):
            get_logger(__name__).info("\nSoftware Fix flash flow:")
            for line in manifest["flashFlowSummary"]:
                get_logger(__name__).info(f"  {line}")

        if manifest.get("romArchive"):
            get_logger(__name__).info(f"ROM archive ready: {manifest['romArchive']}")
        if manifest.get("romMd5"):
            status = manifest["romMd5"]
            if status.get("skipped"):
                get_logger(__name__).info(
                    "ROM MD5 check skipped: Lenovo did not provide an MD5."
                )
            else:
                get_logger(__name__).info(f"ROM MD5 verified: {status['actual']}")
        if manifest.get("decryptedFiles"):
            get_logger(__name__).info(
                f"Decrypted Software Fix ROM helper files: {len(manifest['decryptedFiles'])}"
            )
        if not manifest.get("romArchive") and manifest.get("romUrl"):
            get_logger(__name__).info(
                "ROM archive not downloaded. Add --download to fetch it."
            )
        if manifest.get("expectedStartupFiles"):
            get_logger(__name__).info(
                "Startup file not found. Add --download --extract so the ROM package can provide "
                + "/".join(manifest["expectedStartupFiles"])
                + "."
            )
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
                f"Native qfil image directory does not exist: {native_base_dir}"
            )
        native_image_dir = resolve_qfil_image_dir(
            native_base_dir, manifest.get("startupFile")
        )
        if not native_image_dir.exists():
            raise RuntimeError(
                f"Native qfil image directory does not exist: {native_image_dir}"
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
                get_logger(__name__).info(
                    f"Fastboot recipe checks: {', '.join(fastboot_result['requiredSteps'])}"
                )
                if fastboot_result.get("warning"):
                    get_logger(__name__).warning(
                        "Fastboot property preflight warning: %s",
                        fastboot_result["warning"],
                    )
                elif fastboot_result["checked"]:
                    get_logger(__name__).info("Fastboot property preflight passed.")
            else:
                get_logger(__name__).info(
                    "Fastboot recipe checks: none required by this flow."
                )
        if args.all_xml:
            raise RuntimeError(
                "--all-xml is no longer supported for flashing; native qfil follows Rescue.cmd exactly."
            )
        if not manifest.get("startupFile"):
            raise RuntimeError(
                "Native qfil requires the official Software Fix StartupFile. "
                "Run with --download --extract so the ROM package provides Rescue.cmd/Flash.cmd."
            )
        qfil_plan = parse_rescue_cmd(Path(manifest["startupFile"]), native_image_dir)
        if (
            args.loader
            and qfil_plan.programmer
            and Path(args.loader).resolve() != qfil_plan.programmer.loader
        ):
            raise RuntimeError(
                "Refusing loader override because Rescue.cmd provides the official programmer: "
                f"{qfil_plan.programmer.loader}"
            )
        get_logger(__name__).info("\nSoftware Fix qfil compatibility plan:")
        for line in summarize_plan(qfil_plan):
            get_logger(__name__).info(f"  {line}")
        rawprograms = list(qfil_plan.firehose.rawprograms)
        patches = list(qfil_plan.firehose.patches)
        command = build_qfil_module_command(qfil_plan)
        missing_xml = [
            str(path) for path in [*rawprograms, *patches] if not Path(path).exists()
        ]
        if missing_xml:
            raise RuntimeError(
                f"Native qfil XML preflight failed under {native_image_dir}: missing {', '.join(missing_xml)}"
            )
        get_logger(__name__).info("\nNative Python Sahara/Firehose plan:")
        get_logger(__name__).info(
            f"Rawprogram XMLs: {', '.join(p.name for p in rawprograms)}"
        )
        get_logger(__name__).info(
            f"Patch XMLs: {', '.join(p.name for p in patches) if patches else '(none)'}"
        )
        program_entries = parse_program_entries(rawprograms)
        if program_entries:
            get_logger(__name__).info(f"Program entries: {len(program_entries)}")
            get_logger(__name__).info("Program order:")
            for entry in program_entries[:24]:
                sectors = entry.sectors if entry.sectors is not None else "dynamic"
                get_logger(__name__).info(
                    f"  {entry.xml.name}: {entry.filename} -> {entry.label} "
                    f"lun={entry.lun} sector={entry.start_sector} sectors={sectors}"
                )
            if len(program_entries) > 24:
                get_logger(__name__).info(
                    f"  ... {len(program_entries) - 24} more entries"
                )
        get_logger(__name__).info(" ".join(command))
        if args.flash:
            if not args.skip_edl_preflight:
                devices = ensure_qualcomm_edl_device()
                get_logger(__name__).info(
                    f"EDL preflight passed: {format_usb_devices(devices)}"
                )
            get_logger(__name__).info(
                "\nExecuting native flash. Device must already be in Qualcomm 9008 EDL mode."
            )
            run_qfil_plan(qfil_plan, dry_run=False)
        else:
            get_logger(__name__).info(
                "\nDry run only. Add --flash to execute native flashing."
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
    ) as exc:
        get_logger(__name__).error("Error: %s", exc)
        raise SystemExit(1)
