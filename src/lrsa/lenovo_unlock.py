"""Lenovo bootloader unlock image helpers.

This implements the small ZUX-style sn.img container used by newer Lenovo
tablets. It does not unlock or flash by itself; it only creates the file that
Lenovo ABL expects to find in the unlock/lenovolock partition.
"""

from __future__ import annotations

import argparse
from pathlib import Path


ZUX_MAGIC = b"1a2blenovo3c4d5e"
ZUX_IMAGE_SIZE = 100 + 256
ZUX_SERIAL_OFFSET = 0x24
ZUX_SERIAL_LEN = 64


def normalize_bootloader_sn(value: str) -> str:
    sn = "".join(value.split()).upper()
    if len(sn) != ZUX_SERIAL_LEN:
        raise ValueError(
            f"ZUX bootloader serial must be {ZUX_SERIAL_LEN} hex characters, got {len(sn)}"
        )
    try:
        bytes.fromhex(sn)
    except ValueError as exc:
        raise ValueError(
            "ZUX bootloader serial must contain only hex characters"
        ) from exc
    return sn


def build_zux_unlock_image(bootloader_sn: str) -> bytes:
    sn = normalize_bootloader_sn(bootloader_sn)
    image = bytearray(ZUX_IMAGE_SIZE)
    image[0 : len(ZUX_MAGIC)] = ZUX_MAGIC

    # Header layout observed from public Lenovo ZUX sn.img generators:
    #   0x00: 16-byte magic
    #   0x10: uint32 version major/reserved = 0
    #   0x14: uint32 version minor/format = 1
    #   0x18: uint64 reserved = 0
    #   0x20: uint32 serial record type = 1
    #   0x24: 64-byte ASCII bootloader SN
    image[0x14:0x18] = (1).to_bytes(4, "little")
    image[0x20:0x24] = (1).to_bytes(4, "little")
    image[ZUX_SERIAL_OFFSET : ZUX_SERIAL_OFFSET + ZUX_SERIAL_LEN] = sn.encode("ascii")
    return bytes(image)


def write_zux_unlock_image(bootloader_sn: str, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(build_zux_unlock_image(bootloader_sn))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a Lenovo ZUX bootloader sn.img locally."
    )
    parser.add_argument(
        "bootloader_sn", help="Bootloader_SN_Part1 + Bootloader_SN_Part2, 64 hex chars"
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("sn.img"))
    args = parser.parse_args()

    out = write_zux_unlock_image(args.bootloader_sn, args.output)
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
