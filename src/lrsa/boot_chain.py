"""Read-only boot-chain verification helpers for Qualcomm QFIL packages."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .qfil import (
    discover_firehose_loader,
    discover_qfil_files,
    resolve_qfil_image_dir,
    select_qfil_set,
)

DEFAULT_BOOT_CHAIN_LABELS = (
    "xbl_a",
    "xbl_b",
    "xbl_config_a",
    "xbl_config_b",
    "abl_a",
    "abl_b",
    "uefi_a",
    "uefi_b",
    "tz_a",
    "tz_b",
    "hyp_a",
    "hyp_b",
    "vbmeta_a",
    "vbmeta_b",
    "vbmeta_system_a",
    "vbmeta_system_b",
)


@dataclass(frozen=True)
class ProgramEntry:
    xml: Path
    label: str
    filename: str
    lun: int
    start_sector: int
    sectors: int
    sector_size: int
    file_sector_offset: int
    sparse: bool

    @property
    def byte_count(self) -> int:
        return self.sectors * self.sector_size


def parse_int(value: str | None, default: int = 0) -> int:
    if value is None or str(value).strip() == "":
        return default
    return int(str(value).strip(), 0)


def parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"true", "1", "yes"}


def parse_program_entries(xml_path: Path) -> list[ProgramEntry]:
    root = ET.parse(xml_path).getroot()
    entries: list[ProgramEntry] = []
    for node in root.findall(".//program"):
        label = str(node.attrib.get("label") or "").strip()
        filename = str(node.attrib.get("filename") or "").strip()
        if not label or not filename or filename.upper() == "DISK":
            continue
        try:
            sectors = parse_int(node.attrib.get("num_partition_sectors"))
            start_sector = parse_int(node.attrib.get("start_sector"))
            lun = parse_int(node.attrib.get("physical_partition_number"))
            sector_size = parse_int(node.attrib.get("SECTOR_SIZE_IN_BYTES"), 4096)
            file_sector_offset = parse_int(node.attrib.get("file_sector_offset"))
        except ValueError:
            continue
        if sectors <= 0:
            continue
        entries.append(
            ProgramEntry(
                xml=xml_path,
                label=label,
                filename=filename,
                lun=lun,
                start_sector=start_sector,
                sectors=sectors,
                sector_size=sector_size,
                file_sector_offset=file_sector_offset,
                sparse=parse_bool(node.attrib.get("sparse")),
            )
        )
    return entries


def discover_boot_chain_entries(
    image_dir: Path, labels: tuple[str, ...] = DEFAULT_BOOT_CHAIN_LABELS
) -> list[ProgramEntry]:
    image_dir = resolve_qfil_image_dir(image_dir)
    rawprograms, patches = discover_qfil_files(image_dir)
    rawprograms, _ = select_qfil_set(rawprograms, patches)
    wanted = set(labels)
    selected: dict[str, ProgramEntry] = {}
    for xml_path in rawprograms:
        for entry in parse_program_entries(xml_path):
            if entry.label in wanted and entry.label not in selected:
                selected[entry.label] = entry
    return [selected[label] for label in labels if label in selected]


def expected_bytes(image_dir: Path, entry: ProgramEntry) -> bytes:
    source = image_dir / entry.filename
    data = source.read_bytes()
    offset = entry.file_sector_offset * entry.sector_size
    if offset:
        data = data[offset:]
    if len(data) >= entry.byte_count:
        return data[: entry.byte_count]
    return data + b"\x00" * (entry.byte_count - len(data))


def sha256_prefix(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def verify_readback(
    expected: bytes, actual: bytes, source_len: int
) -> dict[str, object]:
    prefix_len = min(source_len, len(expected), len(actual))
    prefix_match = actual[:prefix_len] == expected[:prefix_len]
    tail = actual[prefix_len:]
    expected_tail = expected[prefix_len:]
    tail_match = tail == expected_tail
    first_diff = None
    for index, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            first_diff = index
            break
    if first_diff is None and len(expected) != len(actual):
        first_diff = min(len(expected), len(actual))
    return {
        "prefixMatch": prefix_match,
        "tailMatch": tail_match,
        "match": expected == actual,
        "firstDiff": first_diff,
        "expectedSha256": sha256_prefix(expected),
        "actualSha256": sha256_prefix(actual),
    }


def read_partition(
    edl: Path,
    loader: Path,
    entry: ProgramEntry,
    out_path: Path,
    *,
    memory: str = "ufs",
    timeout: int = 90,
) -> None:
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(edl),
        "rs",
        str(entry.start_sector),
        str(entry.sectors),
        str(out_path),
        f"--lun={entry.lun}",
        f"--memory={memory}",
        f"--loader={loader}",
        "--vid=0x05c6",
        "--pid=0x9008",
    ]
    subprocess.run(command, cwd=Path(edl).parent, check=True, timeout=timeout)


def verify_boot_chain(
    image_dir: Path,
    work_dir: Path,
    edl: Path,
    loader: Path | None = None,
    *,
    labels: tuple[str, ...] = DEFAULT_BOOT_CHAIN_LABELS,
    memory: str = "ufs",
    timeout: int = 90,
) -> list[dict[str, object]]:
    image_dir = resolve_qfil_image_dir(image_dir)
    loader = loader or discover_firehose_loader(image_dir)
    if loader is None:
        raise RuntimeError(f"Could not find a firehose loader under {image_dir}")

    entries = discover_boot_chain_entries(image_dir, labels)
    if not entries:
        raise RuntimeError(f"No boot-chain rawprogram entries found under {image_dir}")

    readback_dir = Path(work_dir) / "boot_chain_readback"
    results: list[dict[str, object]] = []
    for entry in entries:
        if entry.sparse:
            results.append(
                {"label": entry.label, "status": "SKIP", "reason": "sparse entry"}
            )
            continue
        source = image_dir / entry.filename
        if not source.exists():
            results.append(
                {
                    "label": entry.label,
                    "status": "FAIL",
                    "reason": f"missing source {entry.filename}",
                }
            )
            continue
        out_path = readback_dir / f"{entry.label}.bin"
        read_partition(edl, loader, entry, out_path, memory=memory, timeout=timeout)
        expected = expected_bytes(image_dir, entry)
        actual = out_path.read_bytes()
        source_len = max(
            0,
            min(
                source.stat().st_size - entry.file_sector_offset * entry.sector_size,
                len(expected),
            ),
        )
        comparison = verify_readback(expected, actual, source_len)
        results.append(
            {
                "label": entry.label,
                "status": "PASS" if comparison["match"] else "FAIL",
                "file": entry.filename,
                "xml": entry.xml.name,
                "lun": entry.lun,
                "startSector": entry.start_sector,
                "sectors": entry.sectors,
                "sourceBytes": source.stat().st_size,
                "readback": str(out_path),
                **comparison,
            }
        )
    return results


def format_verify_result(result: dict[str, object]) -> str:
    status = result.get("status")
    label = result.get("label")
    if status == "PASS":
        return (
            f"[PASS] {label}: {result.get('file')} "
            f"lun={result.get('lun')} sector={result.get('startSector')} sectors={result.get('sectors')}"
        )
    if status == "SKIP":
        return f"[SKIP] {label}: {result.get('reason')}"
    return (
        f"[FAIL] {label}: {result.get('file') or result.get('reason')} "
        f"prefix={result.get('prefixMatch')} tail={result.get('tailMatch')} "
        f"firstDiff={result.get('firstDiff')} sha={result.get('actualSha256')} expected={result.get('expectedSha256')}"
    )
