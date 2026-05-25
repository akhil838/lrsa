"""Software Fix style firmware artifact preparation and flow inspection."""

from __future__ import annotations

from lrsa.logging import get_logger

import json
import shutil
from pathlib import Path
from typing import Any, Callable, cast

from ..api.firmware import download_file, download_json, extract_archive, verify_md5
from .constants import MOBILE_TABLET_CATEGORIES, QUALCOMM_PLATFORMS
from .rom_decrypt import decrypt_rom_files

ProgressCallback = Callable[[str, int, int | None, str], None]


def dict_value(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def is_mobile_or_tablet(resource: dict[str, Any]) -> bool:
    return normalize(resource.get("category")) in MOBILE_TABLET_CATEGORIES


def is_qualcomm(resource: dict[str, Any]) -> bool:
    return normalize(resource.get("platform")) in QUALCOMM_PLATFORMS


def load_flow(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def flow_shell_steps(flow: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for step in flow.get("Steps", []) if step.get("Step") == "Shell"]


def flow_decrypt_file_types(flow: dict[str, Any]) -> str | None:
    for step in flow_shell_steps(flow):
        decrypt_file_type = (step.get("Args") or {}).get("DecryptFileType")
        if decrypt_file_type:
            return str(decrypt_file_type)
    return None


def summarize_flow(flow: dict[str, Any]) -> list[str]:
    lines = [
        f"{flow.get('Name', 'Unknown flow')} ({flow.get('UseCase', 'unknown use case')})"
    ]
    for idx, step in enumerate(flow.get("Steps", []), 1):
        args = step.get("Args") or {}
        detail = []
        if args.get("FlashToolType"):
            detail.append(f"tool={args['FlashToolType']}")
        if args.get("StartupFile"):
            detail.append(f"startup={args['StartupFile']}")
        if args.get("ComPorts"):
            detail.append(f"ports={','.join(args['ComPorts'])}")
        suffix = f" [{'; '.join(detail)}]" if detail else ""
        lines.append(f"{idx}. {step.get('Step')}: {step.get('Name')}{suffix}")
    return lines


def find_startup_file(root: Path, flow: dict[str, Any]) -> Path | None:
    for step in flow_shell_steps(flow):
        startup = (step.get("Args") or {}).get("StartupFile")
        if startup:
            matches = sorted(root.rglob(startup))
            if matches:
                return matches[0]
    return None


def flow_startup_names(flow: dict[str, Any]) -> list[str]:
    names = []
    for step in flow_shell_steps(flow):
        startup = (step.get("Args") or {}).get("StartupFile")
        if startup and startup not in names:
            names.append(startup)
    for fallback in ("Rescue.cmd", "Flash.cmd"):
        if fallback not in names:
            names.append(fallback)
    return names


def resource_filename(resource_info: dict[str, Any]) -> str | None:
    name = resource_info.get("name")
    if name:
        return str(name)
    uri = resource_info.get("uri")
    if not uri:
        return None
    from urllib.parse import unquote, urlparse

    return Path(unquote(urlparse(str(uri)).path)).name or None


def find_existing_archive(
    downloads_dir: Path, resource_info: dict[str, Any]
) -> Path | None:
    filename = resource_filename(resource_info)
    if not filename:
        return None
    path = Path(downloads_dir) / filename
    if path.exists() and path.stat().st_size > 0:
        return path
    return None


def extracted_rom_has_flash_files(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False
    return any(path.rglob("rawprogram*.xml")) and any(path.rglob("patch*.xml"))


def prepare_artifacts(
    resource: dict[str, Any],
    work_dir: Path,
    download_rom: bool = False,
    extract_rom: bool = False,
    decrypt_rom: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Download/extract the same artifacts Software Fix references.

    This prepares the package; it intentionally does not invent a missing
    Rescue.cmd. Execution should follow the downloaded flashFlow metadata.
    """
    work_dir = Path(work_dir)
    downloads_dir = work_dir / "software_fix" / "downloads"
    rom_dir = work_dir / "software_fix" / "rom"
    flow_path = work_dir / "software_fix" / "flash_flow.json"

    rom = dict_value(resource.get("romResource"))
    result: dict[str, Any] = {
        "category": resource.get("category"),
        "platform": resource.get("platform"),
        "modelName": resource.get("modelName"),
        "marketName": resource.get("marketName"),
        "romName": rom.get("name"),
        "romUrl": rom.get("uri"),
        "flashFlowUrl": resource.get("flashFlow"),
    }

    if resource.get("flashFlow"):
        if progress_callback:
            progress_callback("metadata", 0, 1, "Downloading flash flow")
        result["flashFlowPath"] = str(download_json(resource["flashFlow"], flow_path))
        if progress_callback:
            progress_callback("metadata", 1, 1, "Flash flow saved")
        flow = load_flow(flow_path)
        result["flashFlowSummary"] = summarize_flow(flow)
        decrypt_file_types = flow_decrypt_file_types(flow)
        if decrypt_file_types:
            result["decryptFileType"] = decrypt_file_types
    else:
        flow = {}
        decrypt_file_types = None

    existing_rom_archive = find_existing_archive(downloads_dir, rom)
    if existing_rom_archive:
        result["romArchive"] = str(existing_rom_archive)
        rom_md5 = verify_md5(existing_rom_archive, rom.get("md5"))
        result["romMd5"] = rom_md5
        if rom_md5["verified"] is False:
            raise RuntimeError(
                f"ROM MD5 mismatch for {existing_rom_archive}: expected {rom_md5['expected']}, got {rom_md5['actual']}"
            )

    if download_rom and rom.get("uri"):
        rom_archive = download_file(
            rom["uri"], downloads_dir, progress_callback=progress_callback
        )
        result["romArchive"] = str(rom_archive)
        rom_md5 = verify_md5(rom_archive, rom.get("md5"))
        result["romMd5"] = rom_md5
        if rom_md5["verified"] is False:
            raise RuntimeError(
                f"ROM MD5 mismatch for {rom_archive}: expected {rom_md5['expected']}, got {rom_md5['actual']}"
            )
        if extract_rom:
            decrypted = []
            if extracted_rom_has_flash_files(rom_dir):
                get_logger(__name__).info("Using existing extracted ROM: %s", rom_dir)
                if progress_callback:
                    progress_callback("extract", 1, 1, "Using existing extracted ROM")
            else:
                extract_archive(
                    rom_archive, rom_dir, progress_callback=progress_callback
                )
            result["romDir"] = str(rom_dir.resolve())
            if decrypt_rom and decrypt_file_types:
                if progress_callback:
                    progress_callback("decrypt", 0, None, "Decrypting ROM files")
                decrypted = decrypt_rom_files(rom_dir, decrypt_file_types)
                if progress_callback:
                    progress_callback("decrypt", 1, 1, "ROM decrypt complete")
            if decrypted:
                result["decryptedFiles"] = [str(path.resolve()) for path in decrypted]
    elif extract_rom and existing_rom_archive:
        if extracted_rom_has_flash_files(rom_dir):
            get_logger(__name__).info("Using existing extracted ROM: %s", rom_dir)
            if progress_callback:
                progress_callback("extract", 1, 1, "Using existing extracted ROM")
        else:
            extract_archive(
                existing_rom_archive,
                rom_dir,
                progress_callback=progress_callback,
            )
        result["romDir"] = str(rom_dir.resolve())
        if decrypt_rom and decrypt_file_types:
            if progress_callback:
                progress_callback("decrypt", 0, None, "Decrypting ROM files")
            decrypted = decrypt_rom_files(rom_dir, decrypt_file_types)
            if progress_callback:
                progress_callback("decrypt", 1, 1, "ROM decrypt complete")
            if decrypted:
                result["decryptedFiles"] = [str(path.resolve()) for path in decrypted]
    elif extract_rom and not existing_rom_archive:
        raise RuntimeError(
            "ROM archive is not downloaded yet. Run Download ROM before Extract ROM."
        )
    elif extracted_rom_has_flash_files(rom_dir):
        result["romDir"] = str(rom_dir.resolve())
        if decrypt_rom and decrypt_file_types:
            decrypted = decrypt_rom_files(rom_dir, decrypt_file_types)
            if decrypted:
                result["decryptedFiles"] = [str(path.resolve()) for path in decrypted]

    startup = find_startup_file(work_dir / "software_fix", flow) if flow else None
    if startup:
        result["startupFile"] = str(startup)
    elif flow:
        result["expectedStartupFiles"] = flow_startup_names(flow)

    return result


def copy_existing_rom_package(source_dir: Path, work_dir: Path) -> Path:
    target = Path(work_dir) / "software_fix" / "rom"
    target.mkdir(parents=True, exist_ok=True)
    source_dir = Path(source_dir)
    if source_dir.resolve() == target.resolve():
        return target
    for item in source_dir.iterdir():
        dest = target / item.name
        if item.is_dir():
            if not dest.exists():
                shutil.copytree(item, dest)
        elif not dest.exists():
            shutil.copy2(item, dest)
    return target
