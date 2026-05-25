#!/usr/bin/env python3
"""Inventory, decompile, and port audit for the bundled Lenovo/QFIL tools.

Records file coverage, PE/.NET metadata, imports, embedded strings, URLs,
environment-like names, and the feature delta against this repository's native
Python qfil module for the 1v1 port effort.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

import dnfile
import pefile


DEFAULT_ROOT = Path("lrsa_work/software_fix")
DEFAULT_OUTPUT = Path("lrsa_work/qfil_audit")

CODE_SUFFIXES = {
    ".exe",
    ".dll",
    ".ocx",
    ".tlb",
    ".resources",
    ".cmd",
    ".cnt",
    ".hlp",
    ".htm",
    ".html",
    ".json",
    ".xml",
    ".il",
    ".txt",
}
FIRMWARE_SUFFIXES = {".img", ".bin", ".elf", ".mbn", ".melf", ".hex", ".fv", ".x", ".t"}
HASH_LIMIT_BYTES = 128 * 1024 * 1024
STRING_SCAN_LIMIT_BYTES = 64 * 1024 * 1024

URL_RE = re.compile(rb"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
PATH_RE = re.compile(rb"(?:[A-Za-z]:\\|\\\\\.\\|/)[A-Za-z0-9_.$%~+@(){}\\/\- ]{4,}")
ENV_RE = re.compile(rb"%[A-Za-z_][A-Za-z0-9_]*%|\$[A-Za-z_][A-Za-z0-9_]*")
PROTO_RE = re.compile(
    rb"\b(?:sahara|firehose|fh_loader|qsahara|qdloader|qfil|ufs|emmc|xml|rawprogram|patch|setbootablestoragedrive|configure|program|erase|read|power|reset|noprompt|zlpawarehost|memoryname)\b",
    re.IGNORECASE,
)


def rel(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_limited(path: Path) -> str | None:
    size = path.stat().st_size
    if size > HASH_LIMIT_BYTES:
        return None
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_limited(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(STRING_SCAN_LIMIT_BYTES + 1)


def ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(match.group(0).decode("ascii", errors="ignore"))
    return out


def utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % min_len
    for match in re.finditer(pattern, data):
        out.append(match.group(0).decode("utf-16-le", errors="ignore"))
    return out


def unique_sorted(values: list[str], limit: int | None = None) -> list[str]:
    result = sorted(set(value.strip() for value in values if value and value.strip()))
    return result if limit is None else result[:limit]


def extract_indicators(data: bytes) -> dict[str, list[str]]:
    strings = ascii_strings(data) + utf16le_strings(data)
    joined = "\n".join(strings).encode("utf-8", errors="ignore")
    raw_hits = {
        "urls": [
            m.group(0).decode("utf-8", errors="ignore") for m in URL_RE.finditer(joined)
        ],
        "paths": [
            m.group(0).decode("utf-8", errors="ignore")
            for m in PATH_RE.finditer(joined)
        ],
        "env": [
            m.group(0).decode("utf-8", errors="ignore") for m in ENV_RE.finditer(joined)
        ],
        "protocol_terms": [
            m.group(0).decode("utf-8", errors="ignore")
            for m in PROTO_RE.finditer(joined)
        ],
    }
    interesting = [
        s
        for s in strings
        if any(
            token in s.lower()
            for token in (
                "sahara",
                "firehose",
                "fh_loader",
                "qsahara",
                "qfil",
                "qdloader",
                "rawprogram",
                "patch",
                "program",
                "configure",
                "memoryname",
                "zlp",
                "reset",
                "port",
                "http",
                "url",
                "env",
                "token",
                "auth",
                "lenovo",
                "qualcomm",
            )
        )
    ]
    raw_hits["interesting_strings"] = interesting
    return {key: unique_sorted(values, 500) for key, values in raw_hits.items()}


def pe_metadata(path: Path) -> dict[str, Any] | None:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        return {"parse_error": str(exc)}

    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore")
            imports[dll] = unique_sorted(
                [
                    imp.name.decode("utf-8", errors="ignore")
                    if imp.name
                    else f"ordinal_{imp.ordinal}"
                    for imp in entry.imports
                ],
                250,
            )

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = unique_sorted(
            [
                symbol.name.decode("utf-8", errors="ignore")
                if symbol.name
                else f"ordinal_{symbol.ordinal}"
                for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
            ],
            500,
        )

    com_descriptor = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
    ]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "imports": imports,
        "exports": exports,
        "sections": [
            {
                "name": section.Name.rstrip(b"\x00").decode("utf-8", errors="ignore"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 3),
            }
            for section in pe.sections
        ],
        "is_dotnet": bool(com_descriptor.VirtualAddress and com_descriptor.Size),
    }


def dotnet_metadata(path: Path) -> dict[str, Any] | None:
    try:
        dn = dnfile.dnPE(str(path))
    except Exception as exc:
        return {"parse_error": str(exc)}
    if not getattr(dn, "net", None):
        return None

    info: dict[str, Any] = {"types": [], "methods": [], "member_refs": []}
    tables = getattr(dn.net, "mdtables", None)
    if not tables:
        return info

    typedef = getattr(tables, "TypeDef", None)
    if typedef:
        for row in typedef.rows:
            name = str(row.TypeName or "")
            ns = str(row.TypeNamespace or "")
            if name:
                info["types"].append(f"{ns}.{name}" if ns else name)

    methoddef = getattr(tables, "MethodDef", None)
    if methoddef:
        for row in methoddef.rows:
            name = str(row.Name or "")
            if name:
                info["methods"].append(name)

    memberref = getattr(tables, "MemberRef", None)
    if memberref:
        for row in memberref.rows:
            name = str(row.Name or "")
            if name:
                info["member_refs"].append(name)

    return {key: unique_sorted(value, 1000) for key, value in info.items()}


def classify(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".exe", ".dll", ".ocx", ".tlb"}:
        return "windows-binary"
    if suffix in {
        ".cmd",
        ".json",
        ".xml",
        ".il",
        ".resources",
        ".cnt",
        ".hlp",
        ".htm",
        ".html",
        ".txt",
    }:
        return "metadata-or-script"
    if suffix in FIRMWARE_SUFFIXES:
        return "firmware-or-payload"
    return "other"


def analyze_file(path: Path, root: Path) -> dict[str, Any]:
    stat = path.stat()
    suffix = path.suffix.lower()
    item: dict[str, Any] = {
        "path": rel(path, root),
        "size": stat.st_size,
        "suffix": suffix,
        "kind": classify(path),
        "sha256": sha256_limited(path),
    }
    if suffix in CODE_SUFFIXES or stat.st_size <= 2 * 1024 * 1024:
        data = read_limited(path)
        item["truncated_string_scan"] = len(data) > STRING_SCAN_LIMIT_BYTES
        item["indicators"] = extract_indicators(data)
    if suffix in {".exe", ".dll", ".ocx", ".tlb"}:
        item["pe"] = pe_metadata(path)
        dotnet = dotnet_metadata(path)
        if dotnet:
            item["dotnet"] = dotnet
    return item


def summarize_coverage(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    by_suffix: dict[str, int] = {}
    urls: list[tuple[str, str]] = []
    env: list[tuple[str, str]] = []
    protocol_terms: dict[str, int] = {}
    binaries: list[dict[str, Any]] = []

    for item in items:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        by_suffix[item["suffix"]] = by_suffix.get(item["suffix"], 0) + 1
        indicators = item.get("indicators") or {}
        for url in indicators.get("urls", []):
            urls.append((item["path"], url))
        for name in indicators.get("env", []):
            env.append((item["path"], name))
        for term in indicators.get("protocol_terms", []):
            protocol_terms[term.lower()] = protocol_terms.get(term.lower(), 0) + 1
        if item["kind"] == "windows-binary":
            pe = item.get("pe") or {}
            binaries.append(
                {
                    "path": item["path"],
                    "size": item["size"],
                    "dotnet": bool(pe.get("is_dotnet")),
                    "imports": sorted((pe.get("imports") or {}).keys()),
                    "exports": pe.get("exports") or [],
                }
            )

    return {
        "file_count": len(items),
        "by_kind": dict(sorted(by_kind.items())),
        "by_suffix": dict(sorted(by_suffix.items())),
        "urls": urls,
        "env": env,
        "protocol_terms": dict(sorted(protocol_terms.items())),
        "windows_binaries": binaries,
    }


def compare_python_port(root: Path) -> list[dict[str, str]]:
    """Static, conservative feature gap checklist from the native indicators."""
    qfil_files = [
        Path("qfil/protocol/sahara.py"),
        Path("qfil/protocol/firehose.py"),
        Path("qfil/tools/fh_loader.py"),
        Path("qfil/tools/qsahara_server.py"),
        Path("qfil/software_fix/rescue_cmd.py"),
    ]
    source = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in qfil_files
        if path.exists()
    ).lower()
    checks = [
        (
            "Sahara hello/read/done programmer upload",
            ("hello", "read_data", "done_req", "done_rsp"),
        ),
        ("Sahara reset state machine packet", ("reset_req",)),
        (
            "Sahara command execution / serial read commandop01.bin",
            ("commandop01", "cmd_exec"),
        ),
        ("Sahara memory dump mode", ("memdump",)),
        ("COM port selection / Windows QDLoader abstraction", ("--port", "com")),
        (
            "Firehose configure MemoryName/ZLPAwareHost",
            ("memoryname", "zlpawarehost", "configure"),
        ),
        ("Firehose set bootable storage drive", ("setbootablestoragedrive",)),
        ("Firehose program payload streaming", ("program(", "sparseimagereader")),
        ("Firehose patch XML handling", ("patch_file",)),
        ("Firehose erase XML command", ("def erase",)),
        ("Firehose read XML command", ("<read", "def read")),
        (
            "Firehose getstorageinfo/fixgpt/firmwarewrite/verify",
            ("getstorageinfo", "fixgpt", "firmwarewrite", "verify_programming"),
        ),
        (
            "Firehose XML tag sorting full fh_loader behavior",
            ("_firehose_tag_order", "configure", "erase", "patch", "power"),
        ),
        ("Rawprogram comma-separated --sendxml compatibility", ('split(","',)),
        (
            "Rescue.cmd exact command extraction",
            ("rescue.cmd", "qsaharaserver", "fh_loader"),
        ),
    ]
    out: list[dict[str, str]] = []
    for name, tokens in checks:
        present = all(token in source for token in tokens)
        out.append(
            {
                "feature": name,
                "status": "covered" if present else "missing-or-partial",
                "evidence": ", ".join(tokens),
            }
        )
    return out


def write_markdown(
    root: Path,
    out_dir: Path,
    items: list[dict[str, Any]],
    summary: dict[str, Any],
    gaps: list[dict[str, str]],
) -> None:
    report = out_dir / "NATIVE_QFIL_AUDIT.md"
    todo = out_dir / "NATIVE_QFIL_TODO.md"
    inventory = out_dir / "INVENTORY.md"

    inventory_lines = [
        "# Native QFIL / Software Fix Inventory",
        "",
        f"Root: `{root}`",
        f"Total files: {len(items)}",
        "",
        "| # | Path | Kind | Size | SHA-256 |",
        "|---:|---|---|---:|---|",
    ]
    for index, item in enumerate(items, 1):
        sha = item.get("sha256") or "skipped-large-file"
        inventory_lines.append(
            f"| {index} | `{item['path']}` | {item['kind']} | {item['size']} | `{sha}` |"
        )
    inventory.write_text("\n".join(inventory_lines) + "\n", encoding="utf-8")

    report_lines = [
        "# Native QFIL / Software Fix Decompile And Port Audit",
        "",
        "This audit catalogs shipped files, decompiled metadata, imports, strings, URLs, environment-like tokens, protocol indicators, and Python port coverage.",
        "",
        "## Coverage Summary",
        "",
        f"- Files analyzed: {summary['file_count']}",
        f"- By kind: `{json.dumps(summary['by_kind'], sort_keys=True)}`",
        f"- By suffix: `{json.dumps(summary['by_suffix'], sort_keys=True)}`",
        "",
        "## Windows Binaries",
        "",
        "| Path | .NET | Imports | Exports |",
        "|---|---:|---|---|",
    ]
    for binary in summary["windows_binaries"]:
        imports = ", ".join(binary["imports"][:20])
        exports = ", ".join(binary["exports"][:20])
        report_lines.append(
            f"| `{binary['path']}` | {binary['dotnet']} | {imports} | {exports} |"
        )

    report_lines.extend(
        [
            "",
            "## Extracted URLs",
            "",
        ]
    )
    if summary["urls"]:
        for path, url in summary["urls"]:
            report_lines.append(f"- `{path}`: `{url}`")
    else:
        report_lines.append("- None found in scanned files.")

    report_lines.extend(["", "## Extracted Environment/Path Tokens", ""])
    if summary["env"]:
        for path, name in summary["env"]:
            report_lines.append(f"- `{path}`: `{name}`")
    else:
        report_lines.append("- None found in scanned files.")

    report_lines.extend(
        [
            "",
            "## Protocol Term Counts",
            "",
            "```json",
            json.dumps(summary["protocol_terms"], indent=2),
            "```",
            "",
        ]
    )
    report_lines.extend(
        [
            "## Python Port Coverage Delta",
            "",
            "| Feature | Status | Evidence Tokens |",
            "|---|---|---|",
        ]
    )
    for gap in gaps:
        report_lines.append(
            f"| {gap['feature']} | {gap['status']} | `{gap['evidence']}` |"
        )
    report.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    todo_lines = [
        "# Native QFIL Port Todo",
        "",
        "Each local file is accounted for. `done` means inventoried and statically analyzed where applicable. `port-target` means it can affect Python parity.",
        "",
        "## Feature Todo",
        "",
    ]
    for gap in gaps:
        state = "x" if gap["status"] == "covered" else " "
        todo_lines.append(f"- [{state}] {gap['feature']} ({gap['status']})")

    todo_lines.extend(["", "## Per-File Todo", ""])
    for item in items:
        port_target = item["kind"] in {"windows-binary", "metadata-or-script"}
        label = "port-target" if port_target else "catalog-only"
        todo_lines.append(
            f"- [x] `{item['path']}` - {label}; kind={item['kind']}; size={item['size']}"
        )
    todo.write_text("\n".join(todo_lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit local Lenovo/QFIL files against the Python qfil port."
    )
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(path for path in root.rglob("*") if path.is_file())
    items = [analyze_file(path, root) for path in files]
    summary = summarize_coverage(items)
    gaps = compare_python_port(root)

    (out_dir / "native_qfil_analysis.json").write_text(
        json.dumps(items, indent=2, sort_keys=True), encoding="utf-8"
    )
    (out_dir / "native_qfil_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    (out_dir / "python_port_delta.json").write_text(
        json.dumps(gaps, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_markdown(root, out_dir, items, summary, gaps)

    print(f"Analyzed {len(items)} files under {root}")
    print(f"Wrote {out_dir / 'INVENTORY.md'}")
    print(f"Wrote {out_dir / 'NATIVE_QFIL_AUDIT.md'}")
    print(f"Wrote {out_dir / 'NATIVE_QFIL_TODO.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
