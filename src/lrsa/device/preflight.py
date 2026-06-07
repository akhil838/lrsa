"""Native device preflight checks."""

from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from lrsa.logging import get_logger
from lrsa.process import command_text, format_process_output

from .constants import QUALCOMM_EDL_IDS


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
    return run_fastboot_getvar_all_with_warning(fastboot, timeout)[0]


def run_fastboot_getvar_all_with_warning(
    fastboot: str | Path = "fastboot", timeout: int = 20
) -> tuple[dict[str, str], str | None]:
    command = [str(fastboot), "getvar", "all"]
    get_logger(__name__).info("Running fastboot preflight: %s", command_text(command))
    proc = subprocess.run(
        command,
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
    warning = None
    if proc.returncode != 0:
        detail = format_process_output(proc.stdout, proc.stderr)
        if props:
            warning = (
                f"fastboot getvar all returned exit code {proc.returncode} "
                f"but {len(props)} properties were parsed.\n{detail}"
            )
            get_logger(__name__).warning(warning)
        else:
            raise RuntimeError(
                f"fastboot getvar all failed with exit code {proc.returncode}: "
                f"{command_text(command)}\n{detail}"
            )
    else:
        get_logger(__name__).debug(
            "fastboot getvar all parsed %s properties", len(props)
        )
    return props, warning


def format_usb_devices(devices: list[dict[str, str]]) -> str:
    return ", ".join(
        f"{d['vendorId']}:{d['productId']} bus={d['bus']} addr={d['address']}"
        for d in devices
    )


def run_probe(
    command: list[str], timeout: int = 5
) -> subprocess.CompletedProcess[str] | None:
    if not shutil.which(command[0]):
        return None
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def scan_adb_devices() -> list[dict[str, str]]:
    proc = run_probe(["adb", "devices"], timeout=5)
    if proc is None:
        return []
    devices: list[dict[str, str]] = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        detail = ""
        if state == "device":
            model_proc = run_probe(
                ["adb", "-s", serial, "shell", "getprop", "ro.product.model"],
                timeout=3,
            )
            if model_proc and model_proc.returncode == 0:
                detail = model_proc.stdout.strip()
        devices.append(
            {
                "transport": "adb",
                "serial": serial,
                "state": state,
                "detail": detail,
            }
        )
    return devices


def fastboot_getvar(name: str, serial: str | None = None) -> str:
    command = ["fastboot"]
    if serial:
        command.extend(["-s", serial])
    command.extend(["getvar", name])
    proc = run_probe(command, timeout=5)
    if proc is None:
        return ""
    text = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("(bootloader)"):
            line = line[len("(bootloader)") :].strip()
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return ""


def scan_fastboot_devices() -> list[dict[str, str]]:
    proc = run_probe(["fastboot", "devices"], timeout=5)
    if proc is None:
        return []
    devices: list[dict[str, str]] = []
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "fastboot"
        detail_parts = []
        for key in ("product", "current-slot", "unlocked"):
            value = fastboot_getvar(key, serial)
            if value:
                detail_parts.append(f"{key}={value}")
        devices.append(
            {
                "transport": "fastboot",
                "serial": serial,
                "state": state,
                "detail": ", ".join(detail_parts),
            }
        )
    return devices


def scan_connected_devices() -> list[dict[str, str]]:
    devices = []
    for edl in find_qualcomm_edl_devices():
        devices.append(
            {
                "transport": "edl",
                "serial": f"{edl['vendorId']}:{edl['productId']}",
                "state": "Qualcomm 9008/QDLoader",
                "detail": f"bus={edl['bus']} addr={edl['address']}",
            }
        )
    devices.extend(scan_fastboot_devices())
    devices.extend(scan_adb_devices())
    return devices


def format_device_states(devices: list[dict[str, str]]) -> str:
    if not devices:
        return "No ADB, fastboot, or Qualcomm EDL device detected."
    lines = []
    for device in devices:
        detail = f" - {device['detail']}" if device.get("detail") else ""
        lines.append(
            f"{device['transport'].upper()}: {device['serial']} [{device['state']}]{detail}"
        )
    return "\n".join(lines)
