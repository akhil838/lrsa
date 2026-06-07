"""Software Fix style firmware artifact preparation and flow inspection."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable, cast


from ..api.firmware import download_file, download_json, extract_archive, verify_md5
from .constants import MOBILE_TABLET_CATEGORIES, QUALCOMM_PLATFORMS
from .rom_decrypt import decrypt_rom_files

ProgressCallback = Callable[[str, int, int | None, str], None]

RESOURCE_KINDS = (
    ("rom", "romResource", "rom"),
    ("tool", "toolResource", "tool"),
    ("countryCode", "countryCodeResource", "country_code"),
)


def dict_value(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def is_mobile_or_tablet(resource: dict[str, Any]) -> bool:
    return normalize(resource.get("category")) in MOBILE_TABLET_CATEGORIES


def is_qualcomm(resource: dict[str, Any]) -> bool:
    return normalize(resource.get("platform")) in QUALCOMM_PLATFORMS


def load_flow(path: Path) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except OSError as exc:
        raise RuntimeError(f"Failed to read flow JSON at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse flow JSON at {path}: {exc}") from exc


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


def _artifact_target_dir(work_dir: Path, relative_dir: str) -> Path:
    return work_dir / "software_fix" / relative_dir


def _resource_components(resource: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for kind, field, relative_dir in RESOURCE_KINDS:
        info = dict_value(resource.get(field))
        if not info:
            continue
        components.append(
            {
                "kind": kind,
                "field": field,
                "relativeDir": relative_dir,
                "info": info,
            }
        )
    return components


def _artifact_status(
    *,
    kind: str,
    relative_dir: str,
    info: dict[str, Any],
    work_dir: Path,
) -> dict[str, Any]:
    artifact = {
        "kind": kind,
        "name": info.get("name"),
        "type": info.get("type"),
        "url": info.get("uri"),
        "unZip": bool(info.get("unZip")),
        "md5": info.get("md5"),
        "relativeDir": relative_dir,
    }
    target_dir = _artifact_target_dir(work_dir, relative_dir)
    artifact["targetDir"] = str(target_dir.resolve())
    return artifact


def _prepare_component(
    *,
    kind: str,
    relative_dir: str,
    info: dict[str, Any],
    work_dir: Path,
    downloads_dir: Path,
    download_resources: bool,
    extract_resources: bool,
    decrypt_rom: bool,
    decrypt_file_types: str | None,
    progress_callback: ProgressCallback | None,
) -> dict[str, Any]:
    artifact = _artifact_status(
        kind=kind,
        relative_dir=relative_dir,
        info=info,
        work_dir=work_dir,
    )
    target_dir = _artifact_target_dir(work_dir, relative_dir)
    expected_archive = find_existing_archive(downloads_dir, info)
    if expected_archive:
        artifact["archive"] = str(expected_archive)
        artifact["archiveMd5"] = verify_md5(expected_archive, info.get("md5"))
        artifact["downloaded"] = True
        artifact["reusedDownload"] = True
        if artifact["archiveMd5"]["verified"] is False:
            raise RuntimeError(
                f"{kind} MD5 mismatch for {expected_archive}: expected {artifact['archiveMd5']['expected']}, got {artifact['archiveMd5']['actual']}"
            )
    else:
        artifact["downloaded"] = False
        artifact["reusedDownload"] = False

    if download_resources and info.get("uri"):
        archive = download_file(
            str(info["uri"]),
            downloads_dir,
            progress_callback=progress_callback,
        )
        artifact["archive"] = str(archive)
        artifact["archiveMd5"] = verify_md5(archive, info.get("md5"))
        artifact["downloaded"] = True
        artifact["reusedDownload"] = False
        if artifact["archiveMd5"]["verified"] is False:
            raise RuntimeError(
                f"{kind} MD5 mismatch for {archive}: expected {artifact['archiveMd5']['expected']}, got {artifact['archiveMd5']['actual']}"
            )

    archive_path = artifact.get("archive")
    if not archive_path:
        return artifact

    if not extract_resources or not info.get("unZip"):
        return artifact

    archive = Path(str(archive_path))
    target_dir.mkdir(parents=True, exist_ok=True)
    if kind == "rom":
        has_existing_extract = extracted_rom_has_flash_files(target_dir)
    else:
        has_existing_extract = (
            any(target_dir.iterdir()) if target_dir.exists() else False
        )

    if has_existing_extract:
        artifact["reusedExtract"] = True
    else:
        extract_archive(archive, target_dir, progress_callback=progress_callback)
        artifact["reusedExtract"] = False

    artifact["extractedDir"] = str(target_dir.resolve())
    artifact["extracted"] = True

    if kind == "rom" and decrypt_rom and decrypt_file_types:
        if progress_callback:
            progress_callback("decrypt", 0, None, "Decrypting ROM files")
        decrypted = decrypt_rom_files(target_dir, decrypt_file_types)
        if progress_callback:
            progress_callback("decrypt", 1, 1, "ROM decrypt complete")
        if decrypted:
            artifact["decryptedFiles"] = [str(path.resolve()) for path in decrypted]

    return artifact


def prepare_artifacts(
    resource: dict[str, Any],
    work_dir: Path,
    download_rom: bool = False,
    extract_rom: bool = False,
    decrypt_rom: bool = True,
    downloads_dir: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Download/extract the same artifacts Software Fix references."""
    work_dir = Path(work_dir)
    downloads_dir = (
        Path(downloads_dir)
        if downloads_dir is not None
        else work_dir / "software_fix" / "downloads"
    )
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
        "downloadsDir": str(downloads_dir.resolve()),
        "resourceArtifacts": [],
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

    for component in _resource_components(resource):
        artifact = _prepare_component(
            kind=str(component["kind"]),
            relative_dir=str(component["relativeDir"]),
            info=cast(dict[str, Any], component["info"]),
            work_dir=work_dir,
            downloads_dir=downloads_dir,
            download_resources=download_rom,
            extract_resources=extract_rom,
            decrypt_rom=decrypt_rom,
            decrypt_file_types=decrypt_file_types,
            progress_callback=progress_callback,
        )
        result["resourceArtifacts"].append(artifact)
        kind = artifact["kind"]
        archive = artifact.get("archive")
        extracted_dir = artifact.get("extractedDir")
        md5_status = artifact.get("archiveMd5")
        if kind == "rom":
            if archive:
                result["romArchive"] = archive
            if md5_status:
                result["romMd5"] = md5_status
            if extracted_dir:
                result["romDir"] = extracted_dir
            if artifact.get("decryptedFiles"):
                result["decryptedFiles"] = artifact["decryptedFiles"]
        elif kind == "tool":
            if archive:
                result["toolArchive"] = archive
            if md5_status:
                result["toolMd5"] = md5_status
            if extracted_dir:
                result["toolDir"] = extracted_dir
        elif kind == "countryCode":
            if archive:
                result["countryCodeArchive"] = archive
            if md5_status:
                result["countryCodeMd5"] = md5_status
            if extracted_dir:
                result["countryCodeDir"] = extracted_dir

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
