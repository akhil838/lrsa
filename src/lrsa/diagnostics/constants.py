"""Diagnostic tool defaults."""

from pathlib import Path
import re

DEFAULT_LRSA_DIR = Path("lrsa_work/software_fix/tools")
DEFAULT_QFIL_AUDIT_ROOT = Path("lrsa_work/software_fix")
DEFAULT_QFIL_AUDIT_OUTPUT = Path("lrsa_work/qfil_audit")
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
    rb"\b(?:sahara|firehose|fh_loader|qsahara|qdloader|qfil|ufs|emmc|xml|"
    rb"rawprogram|patch|setbootablestoragedrive|configure|program|erase|read|"
    rb"power|reset|noprompt|zlpawarehost|memoryname)\b",
    re.IGNORECASE,
)
ZUX_MAGIC = b"1a2blenovo3c4d5e"
ZUX_IMAGE_SIZE = 100 + 256
ZUX_SERIAL_OFFSET = 0x24
ZUX_SERIAL_LEN = 64
