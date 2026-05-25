"""Native device preflight checks."""

from __future__ import annotations

import subprocess
from pathlib import Path

QUALCOMM_EDL_IDS = {
    (0x05C6, 0x9008),
    (0x05C6, 0x900E),
    (0x05C6, 0x9006),
}


def find_qualcomm_edl_devices() -> list[dict[str, str]]:
    try:
        import usb.core
    except ImportError:
        return []

    devices = []
    for vid, pid in QUALCOMM_EDL_IDS:
        for dev in usb.core.find(find_all=True, idVendor=vid, idProduct=pid) or []:
            devices.append(
                {
                    "vendorId": f"{vid:04x}",
                    "productId": f"{pid:04x}",
                    "bus": str(getattr(dev, "bus", "")),
                    "address": str(getattr(dev, "address", "")),
                }
            )
    return devices


def require_qualcomm_edl_device() -> list[dict[str, str]]:
    devices = find_qualcomm_edl_devices()
    if not devices:
        raise RuntimeError(
            "No Qualcomm 9008/QDLoader USB device found. Put the device in EDL mode before flash/readback."
        )
    return devices


def run_fastboot_getvar_all(
    fastboot: str | Path = "fastboot", timeout: int = 20
) -> dict[str, str]:
    proc = subprocess.run(
        [str(fastboot), "getvar", "all"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    text = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    props: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("(bootloader)"):
            line = line[len("(bootloader)") :].strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        props[key.strip().lower()] = value.strip()
    if proc.returncode != 0 and not props:
        raise RuntimeError(
            f"fastboot getvar all failed: {text.strip() or proc.returncode}"
        )
    return props


def format_usb_devices(devices: list[dict[str, str]]) -> str:
    return ", ".join(
        f"{d['vendorId']}:{d['productId']} bus={d['bus']} addr={d['address']}"
        for d in devices
    )
