"""Arrow-key interactive TUI for the LRSA CLI."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import textwrap
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, cast
from urllib.parse import unquote, urlparse

from lrsa.logging import get_logger
from lrsa.process import command_text

from .api.client import LRSAClient
from .api.firmware import response_payload
from .api.resources import content_list, is_success_payload, resource_summary
from .auth import extract_token_from_file, save_json
from .cli import main as run_lrsa_cli
from .config import DEFAULT_MODEL, DEFAULT_SN, DEFAULT_WORK_DIR
from .device.preflight import (
    format_device_states,
    scan_connected_devices,
)
from .flash.software_fix_flow import (
    is_mobile_or_tablet,
    prepare_artifacts,
    resource_filename,
)
from .flash.qfil import resolve_qfil_image_dir
from .menu_constants import (
    BORDER,
    MIN_UI_WIDTH,
    PATH_FIELDS,
    STATE_FILE,
    STATE_VERSION,
    UI_WIDTH,
)

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import HSplit, Layout
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.mouse_events import MouseEventType
from prompt_toolkit.shortcuts import input_dialog
from prompt_toolkit.styles import Style
from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Static,
    TextArea,
)
from qfil import (
    build_qfil_module_command,
    parse_program_entries,
    parse_rescue_cmd,
    run_qfil_plan,
    summarize_plan,
)


@dataclass
class MenuState:
    token_file: Path = DEFAULT_WORK_DIR / "capture" / "login_session.json"
    work_dir: Path = DEFAULT_WORK_DIR
    model: str = DEFAULT_MODEL
    sn: str = DEFAULT_SN
    imei: str = ""
    imei2: str = ""
    image_dir: str = ""
    firmware_index: int | None = None


@dataclass(frozen=True)
class MenuItem:
    key: str
    title: str
    description: str


@dataclass(frozen=True)
class SettingItem:
    key: str
    title: str
    getter: Callable[[MenuState], str]
    setter: Callable[[MenuState, str], None]


def dict_value(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def quote_command(command: list[str]) -> str:
    return command_text(command)


def path_or_auto(value: str) -> str:
    return value or "(auto)"


def value_or_unset(value: str) -> str:
    return value or "(not set)"


def fit_text(value: str, width: int) -> str:
    if len(value) <= width:
        return value.ljust(width)
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "."


def ui_width() -> int:
    columns = shutil.get_terminal_size((100, 30)).columns
    if columns <= MIN_UI_WIDTH:
        return max(24, columns)
    return min(UI_WIDTH, columns - 4)


def ui_margin(width: int) -> str:
    columns = shutil.get_terminal_size((100, 30)).columns
    return " " * max(0, (columns - width) // 2)


def ui_top_padding(rows: int) -> str:
    lines = shutil.get_terminal_size((100, 30)).lines
    return "\n" * max(0, (lines - rows) // 2)


def box_line(text: str = "", *, width: int, margin: str) -> str:
    return f"{margin}│ {fit_text(text, width - 4)} │\n"


def wrap_for_box(text: str, *, width: int, subsequent_indent: str = "  ") -> list[str]:
    """Wrap log text to fit inside a bordered panel without clipping."""
    inner_width = max(8, width - 4)
    value = str(text).expandtabs(4)
    if not value:
        return [""]
    leading = value[: len(value) - len(value.lstrip(" "))]
    indent = leading + subsequent_indent
    return textwrap.wrap(
        value,
        width=inner_width,
        subsequent_indent=indent[: max(0, inner_width - 1)],
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]


def wrap_lines_for_box(text: str, *, width: int) -> list[str]:
    lines: list[str] = []
    for value in str(text).splitlines() or [""]:
        lines.extend(wrap_for_box(value, width=width))
    return lines or [""]


def styled_box_line(text: str, *, width: int, margin: str, style: str):
    return [
        ("class:screen", margin),
        ("class:border", "│ "),
        (style, fit_text(text, width - 4)),
        ("class:border", " │\n"),
    ]


def box_rule(*, width: int, margin: str, kind: str = "mid") -> str:
    left, right = BORDER.get(kind, BORDER["mid"])
    return f"{margin}{left}" + "─" * (width - 2) + f"{right}\n"


def title_rule(title: str, *, width: int, margin: str):
    left, right = BORDER["top"]
    inner_width = max(0, width - 2)
    label = f" {title} "
    if len(label) > inner_width:
        label = fit_text(label, inner_width)
    left_rule = max(0, (inner_width - len(label)) // 2)
    right_rule = max(0, inner_width - len(label) - left_rule)
    return [
        ("class:screen", margin),
        ("class:border", left + "─" * left_rule),
        ("class:title", label),
        ("class:border", "─" * right_rule + right + "\n"),
    ]


def centered_box_line(text: str, *, width: int, margin: str, style: str):
    inner_width = max(0, width - 4)
    value = fit_text(text, inner_width)
    padding = max(0, inner_width - len(value.rstrip()))
    left_padding = padding // 2
    right_padding = padding - left_padding
    return [
        ("class:screen", margin),
        ("class:border", "│ "),
        (style, " " * left_padding + value.rstrip() + " " * right_padding),
        ("class:border", " │\n"),
    ]


def clickable_log_controls(
    *,
    width: int,
    margin: str,
    older: Callable,
    newer: Callable,
    latest: Callable,
):
    inner_width = max(0, width - 4)
    labels = [("[ Older ]", older), ("  [ Newer ]", newer), ("  [ Latest ]", latest)]
    if inner_width < 32:
        labels = [("[Old]", older), (" [New]", newer), (" [End]", latest)]
    text_width = sum(len(label) for label, _ in labels)
    left_padding = max(0, (inner_width - text_width) // 2)
    right_padding = max(0, inner_width - text_width - left_padding)
    fragments: list[tuple[Any, ...]] = [
        ("class:screen", margin),
        ("class:border", "│ "),
        ("class:normal", " " * left_padding),
    ]
    for label, handler in labels:
        fragments.append(("class:button-focus", label, handler))
    fragments.extend(
        [
            ("class:normal", " " * right_padding),
            ("class:border", " │\n"),
        ]
    )
    return fragments


def state_to_json(state: MenuState) -> dict[str, str | int]:
    return {
        "version": STATE_VERSION,
        "token_file": str(state.token_file),
        "work_dir": str(state.work_dir),
        "model": state.model,
        "sn": state.sn,
        "imei": state.imei,
        "imei2": state.imei2,
        "image_dir": state.image_dir,
        "firmware_index": state.firmware_index
        if state.firmware_index is not None
        else "",
    }


def load_state() -> MenuState:
    state = MenuState()
    if not STATE_FILE.exists():
        return state
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return state

    for key in state_to_json(state):
        if key == "version" or key not in data:
            continue
        value = data[key]
        if key == "firmware_index":
            if isinstance(value, int):
                state.firmware_index = value
            elif isinstance(value, str) and value.isdigit():
                state.firmware_index = int(value)
            continue
        if isinstance(value, str):
            setattr(state, key, Path(value) if key in PATH_FIELDS else value)
    return state


def save_state(state: MenuState) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = STATE_FILE.with_suffix(".tmp")
    tmp_path.write_text(
        json.dumps(state_to_json(state), indent=2) + "\n", encoding="utf-8"
    )
    tmp_path.replace(STATE_FILE)


def status_text(state: MenuState) -> str:
    return "\n".join(
        [
            f"State file: {STATE_FILE}",
            f"Token file: {state.token_file}",
            f"Login capture dir: {state.token_file.parent}",
            f"Work dir:   {state.work_dir}",
            f"Software Fix dir: {state.work_dir / 'software_fix'}",
            f"Rescue response: {state.work_dir / 'rescue_rom_response.json'}",
            f"Model:      {value_or_unset(state.model)}",
            f"SN:         {value_or_unset(state.sn)}",
            f"IMEI:       {value_or_unset(state.imei)}",
            f"IMEI2:      {value_or_unset(state.imei2)}",
            f"Selected ROM: {state.firmware_index if state.firmware_index is not None else 'not selected'}",
            f"Image dir:  {path_or_auto(state.image_dir)}",
        ]
    )


def menu_text(state: MenuState) -> str:
    return (
        f"SN: {value_or_unset(state.sn)}    IMEI: {value_or_unset(state.imei)}\n"
        f"Model: {value_or_unset(state.model)}\n"
        f"Selected ROM: {state.firmware_index if state.firmware_index is not None else 'not selected'}\n"
        f"Token: {state.token_file}\n"
        f"Work: {state.work_dir}\n"
        f"ROM/tool cache: {state.work_dir / 'software_fix'}"
    )


def cli_args_base(state: MenuState) -> list[str]:
    args = [
        "--token-file",
        str(state.token_file),
        "--work-dir",
        str(state.work_dir),
    ]
    if state.model:
        args.extend(["--model", state.model])
    if state.sn:
        args.extend(["--sn", state.sn])
    if state.imei:
        args.extend(["--imei", state.imei])
    if state.imei2:
        args.extend(["--imei2", state.imei2])
    if state.image_dir:
        args.extend(["--image-dir", state.image_dir])
    if state.firmware_index is not None:
        args.extend(["--firmware-index", str(state.firmware_index)])
    return args


def quote_lrsa_args(args: list[str]) -> str:
    return command_text(["lrsa", *args])


def format_bytes(value: int | str | None) -> str:
    if value in (None, ""):
        return "unknown"
    try:
        size = int(value)
    except (TypeError, ValueError):
        return str(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(size)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{size} B"
        amount /= 1024
    return f"{size} B"


def resource_url_label(url: str | None) -> str:
    if not url:
        return "(none)"
    parsed = urlparse(url)
    filename = Path(unquote(parsed.path)).name
    return f"{parsed.netloc}/{filename}" if filename else parsed.netloc or url


def matching_manifest(resource: dict | None, work_dir: Path | None) -> dict | None:
    if not resource or work_dir is None:
        return None
    path = Path(work_dir) / "software_fix" / "manifest.json"
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    rom = dict_value(resource.get("romResource"))
    if manifest.get("romName") != rom.get("name"):
        return None
    return manifest


def local_rom_archive_size(resource: dict | None, work_dir: Path | None) -> str | None:
    if not resource or work_dir is None:
        return None
    rom = dict_value(resource.get("romResource"))
    filename = resource_filename(rom)
    if not filename:
        return None
    path = Path(work_dir) / "software_fix" / "downloads" / filename
    if path.exists() and path.stat().st_size > 0:
        return f"cached file: {format_bytes(path.stat().st_size)}"
    manifest = matching_manifest(resource, work_dir)
    archive = Path(manifest.get("romArchive", "")) if manifest else None
    if archive and archive.exists() and archive.stat().st_size > 0:
        return f"cached file: {format_bytes(archive.stat().st_size)}"
    return None


def resource_known_size(
    resource: dict | None, work_dir: Path | None = None
) -> str | None:
    if not resource:
        return None
    rom = dict_value(resource.get("romResource"))
    for key in (
        "size",
        "fileSize",
        "downloadSize",
        "contentLength",
        "length",
        "bytes",
    ):
        if rom.get(key) not in (None, ""):
            return format_bytes(rom.get(key))
    return local_rom_archive_size(resource, work_dir)


def manifest_flash_flow_label(manifest: dict | None) -> str | None:
    if not manifest:
        return None
    summary = manifest.get("flashFlowSummary")
    if not isinstance(summary, list) or not summary:
        return None
    flow_name = str(summary[0])
    tools: list[str] = []
    startups: list[str] = []
    ports: list[str] = []
    for line in summary[1:]:
        text = str(line)
        if "tool=" in text:
            tools.append(text.split("tool=", 1)[1].split(";", 1)[0].split("]", 1)[0])
        if "startup=" in text:
            startups.append(
                text.split("startup=", 1)[1].split(";", 1)[0].split("]", 1)[0]
            )
        if "ports=" in text:
            ports.append(text.split("ports=", 1)[1].split(";", 1)[0].split("]", 1)[0])
    details = [*dict.fromkeys(tools), *dict.fromkeys(startups), *dict.fromkeys(ports)]
    return f"{flow_name} ({', '.join(details)})" if details else flow_name


def resource_install_mode(resource: dict | None, manifest: dict | None = None) -> str:
    if not resource:
        return "unknown"
    if manifest:
        flow_label = manifest_flash_flow_label(manifest) or ""
        flow_text = json.dumps(
            manifest.get("flashFlowSummary", []), default=str
        ).lower()
        if "qfil" in flow_text or "qdloader" in flow_text:
            return f"EDL / QFIL - {flow_label}" if flow_label else "EDL / QFIL"
        if "fastboot" in flow_text:
            return f"Fastboot - {flow_label}" if flow_label else "Fastboot"
    platform = str(resource.get("platform") or "").lower()
    tool = dict_value(resource.get("toolResource"))
    tool_name = str(tool.get("name") or "")
    flash_flow = str(resource.get("flashFlow") or "")
    if resource.get("fastboot") is True:
        return "Fastboot"
    if (
        "qcom" in platform
        or "qfil" in tool_name.lower()
        or "recoveryqcom" in flash_flow.lower()
    ):
        return "EDL / QFIL"
    return "unknown"


def firmware_table_row(index: int, resource: dict) -> tuple[str, str, str, str, str]:
    summary = resource_summary(resource)
    firmware = summary.get("firmwareName") or "(unnamed ROM)"
    model = (
        summary.get("modelName") or summary.get("realModelName") or "(unknown model)"
    )
    rom = dict_value(resource.get("romResource"))
    published = rom.get("publishDate")
    return (
        str(index),
        str(firmware),
        str(model),
        resource_install_mode(resource),
        str(published or "(no date)"),
    )


def firmware_detail_text(
    resource: dict | None,
    *,
    index: int | None = None,
    download_size: str | None = None,
    work_dir: Path | None = None,
) -> str:
    if not resource:
        return "No firmware selected."
    summary = resource_summary(resource)
    rom = dict_value(resource.get("romResource"))
    tool = dict_value(resource.get("toolResource"))
    manifest = matching_manifest(resource, work_dir)
    size = (
        download_size
        or resource_known_size(resource, work_dir)
        or "not provided by API; shown during download"
    )
    flash_flow = manifest_flash_flow_label(manifest)
    if not flash_flow:
        flash_flow = (
            "available, not loaded yet" if resource.get("flashFlow") else "missing"
        )
    lines = [
        f"Selection: {index if index is not None else '(none)'}",
        f"Firmware: {summary.get('firmwareName') or '(unnamed ROM)'}",
        f"Model: {summary.get('modelName') or summary.get('realModelName') or '(unknown)'}",
        f"Market: {summary.get('marketName') or '(unknown)'}",
        f"Category / platform: {resource.get('category') or '(unknown)'} / {resource.get('platform') or '(unknown)'}",
        f"Install mode: {resource_install_mode(resource, manifest)}",
        f"Download size: {size}",
        f"Publish date: {rom.get('publishDate') or '(none)'}",
        f"ROM package: {rom.get('name') or '(none)'}",
        f"ROM MD5: {rom.get('md5') or '(none)'}",
        f"ROM unzip: {rom.get('unZip')}",
        f"Tool package: {tool.get('name') or '(none)'}",
        f"Tool unzip: {tool.get('unZip')}",
        f"Flash flow: {flash_flow}",
        f"Fastboot flag: {resource.get('fastboot')}",
        f"Match id: {summary.get('romMatchId') or '(none)'}",
        f"ROM URL: {resource_url_label(summary.get('firmwareUrl'))}",
    ]
    return "\n".join(lines)


def read_manifest(work_dir: Path) -> dict | None:
    path = Path(work_dir) / "software_fix" / "manifest.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def find_startup_candidate(root: Path) -> Path | None:
    if not root.exists():
        return None
    for name in ("Rescue.cmd", "Flash.cmd", "flash.cmd", "rescue.cmd"):
        candidate = root / name
        if candidate.exists():
            return candidate
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate.name.lower() in {
            "rescue.cmd",
            "flash.cmd",
        }:
            return candidate
    return None


def qfil_xml_summary(root: Path) -> str:
    if not root.exists():
        return "missing"
    rawprograms = list(root.rglob("rawprogram*.xml"))
    patches = list(root.rglob("patch*.xml"))
    if not rawprograms:
        return "missing rawprogram XML"
    return f"{len(rawprograms)} rawprogram, {len(patches)} patch"


def add_local_firmware_candidate(
    candidates: list[dict[str, str]],
    seen: set[Path],
    *,
    path: Path,
    name: str,
    source: str,
    startup: str = "",
    flow: str = "",
) -> None:
    if not path.exists() or not path.is_dir():
        return
    resolved = path.resolve()
    if resolved in seen:
        return
    seen.add(resolved)
    startup_path = Path(startup) if startup else find_startup_candidate(resolved)
    candidates.append(
        {
            "name": name or resolved.name,
            "path": str(resolved),
            "source": source,
            "startup": str(startup_path) if startup_path else "",
            "flow": flow,
            "qfil": qfil_xml_summary(resolved),
        }
    )


def local_firmware_candidates(state: MenuState) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[Path] = set()
    manifest = read_manifest(state.work_dir)
    if manifest:
        rom_dir_value = str(manifest.get("romDir") or "")
        if rom_dir_value:
            rom_dir = Path(rom_dir_value)
            flow = manifest_flash_flow_label(manifest) or ""
            add_local_firmware_candidate(
                candidates,
                seen,
                path=rom_dir,
                name=str(manifest.get("romName") or rom_dir.name),
                source="Software Fix manifest",
                startup=str(manifest.get("startupFile") or ""),
                flow=flow,
            )
    if state.image_dir:
        image_dir = Path(state.image_dir)
        add_local_firmware_candidate(
            candidates,
            seen,
            path=image_dir,
            name=image_dir.name,
            source="Configured image dir",
        )
    rom_dir = Path(state.work_dir) / "software_fix" / "rom"
    add_local_firmware_candidate(
        candidates,
        seen,
        path=rom_dir,
        name=rom_dir.name,
        source="Extracted Software Fix ROM",
    )
    return candidates


def local_firmware_detail_text(
    candidate: dict[str, str] | None,
    device: dict[str, str] | None = None,
) -> str:
    if not candidate:
        return "Select a locally extracted firmware package."
    device_line = "not selected"
    if device:
        detail = f" - {device['detail']}" if device.get("detail") else ""
        device_line = (
            f"{device.get('transport', '').upper()}: {device.get('serial')} "
            f"[{device.get('state')}]{detail}"
        )
    lines = [
        f"Firmware: {candidate.get('name') or '(unnamed local firmware)'}",
        f"Path: {candidate.get('path')}",
        f"Source: {candidate.get('source')}",
        f"Startup file: {candidate.get('startup') or '(missing Rescue.cmd / Flash.cmd)'}",
        f"QFIL files: {candidate.get('qfil') or 'unknown'}",
        f"Flash flow: {candidate.get('flow') or 'local qfil plan'}",
        f"Selected device: {device_line}",
    ]
    return "\n".join(lines)


def run_local_qfil_flash(candidate: dict[str, str], *, flash: bool) -> None:
    if not candidate.get("startup"):
        raise RuntimeError(
            "Selected firmware has no Rescue.cmd or Flash.cmd. Run Extract ROM first."
        )
    base_dir = Path(candidate["path"]).resolve()
    startup = Path(candidate["startup"]).resolve()
    image_dir = resolve_qfil_image_dir(base_dir, startup)
    qfil_plan = parse_rescue_cmd(startup, image_dir)
    get_logger(__name__).info("\nNative qfil compatibility plan:")
    for line in summarize_plan(qfil_plan):
        get_logger(__name__).info("  %s", line)
    rawprograms = list(qfil_plan.firehose.rawprograms)
    patches = list(qfil_plan.firehose.patches)
    missing_xml = [
        str(path) for path in [*rawprograms, *patches] if not Path(path).exists()
    ]
    if missing_xml:
        raise RuntimeError(
            "Native qfil XML preflight failed: " + ", ".join(missing_xml)
        )
    program_entries = parse_program_entries(rawprograms)
    get_logger(__name__).info("Program entries: %s", len(program_entries))
    get_logger(__name__).info(" ".join(build_qfil_module_command(qfil_plan)))
    run_qfil_plan(qfil_plan, dry_run=not flash)


def login_command(state: MenuState) -> list[str]:
    return [
        "sudo",
        "-S",
        "-p",
        "",
        sys.executable,
        "-u",
        "-m",
        "lrsa.servers.capture",
        "--out-dir",
        str(state.token_file.parent),
    ]


def dry_run_args(state: MenuState) -> list[str]:
    args = cli_args_base(state)
    args.extend(["--login", "none"])
    return args


def download_args(state: MenuState) -> list[str]:
    args = cli_args_base(state)
    args.extend(["--login", "none", "--download"])
    return args


def extract_args(state: MenuState) -> list[str]:
    args = cli_args_base(state)
    args.extend(["--login", "none", "--extract"])
    return args


def ui_style():
    if Style is None:
        return None
    return Style.from_dict(
        {
            "dialog": "bg:#111111",
            "root": "bg:#111111 #e6e6e6",
            "screen": "bg:#111111 #e6e6e6",
            "dialog frame-label": "bg:#111111 #ff3b30 bold",
            "dialog.body": "bg:#111111 #e6e6e6",
            "dialog shadow": "bg:#000000",
            "button": "bg:#303030 #e6e6e6",
            "button.focused": "bg:#ffffff #111111",
            "radio": "#bbbbbb",
            "radio-checked": "#ffffff bold",
            "text-area": "bg:#202020 #ffffff",
            "title": "bg:#111111 #ff3b30 bold",
            "normal": "bg:#111111 #e6e6e6",
            "selected": "bg:#333333 #ffffff bold",
            "selected-detail": "bg:#111111 #c8c8c8",
            "muted": "bg:#111111 #c8c8c8",
            "footer": "bg:#111111 #9a9a9a",
            "border": "bg:#111111 #b8b8b8",
            "section": "bg:#111111 #ff3b30 bold",
            "shortcut": "bg:#111111 #8ab4f8",
            "progress": "bg:#111111 #7dd3fc bold",
            "button-focus": "bg:#333333 #e6e6e6 bold",
        }
    )


def choose_item(
    title: str, text: str, items: list[MenuItem], default: str
) -> str | None:
    if Application is None:
        return fallback_choose(title, items)
    selected = next(
        (index for index, item in enumerate(items) if item.key == default), 0
    )

    def fragments():
        width = ui_width()
        margin = ui_margin(width)
        text_lines = wrap_lines_for_box(text, width=width)
        content_rows = 9 + len(text_lines) + len(items)
        selected_item = items[selected]

        result = [("class:screen", ui_top_padding(content_rows))]
        result.extend(title_rule(title, width=width, margin=margin))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for line in text_lines:
            result.append(("class:muted", box_line(line, width=width, margin=margin)))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for index, item in enumerate(items):
            active = index == selected
            prefix = "> " if active else "  "
            marker_style = "class:selected" if active else "class:normal"
            shortcut = (
                f"{index + 1}. " if index < 9 else ("0. " if index == 9 else "   ")
            )
            if active:
                result.extend(
                    styled_box_line(
                        f"{prefix}{shortcut}{item.title}",
                        width=width,
                        margin=margin,
                        style=marker_style,
                    )
                )
            else:
                result.append(
                    (
                        marker_style,
                        box_line(
                            f"{prefix}{shortcut}{item.title}",
                            width=width,
                            margin=margin,
                        ),
                    )
                )
        result.append(("class:border", box_rule(width=width, margin=margin)))
        result.append(
            (
                "class:selected-detail",
                box_line(
                    f" Selected: {selected_item.description}",
                    width=width,
                    margin=margin,
                ),
            )
        )
        result.append(
            (
                "class:footer",
                box_line(
                    " Up/Down: move   Enter: select   Esc/q: back",
                    width=width,
                    margin=margin,
                ),
            )
        )
        result.append(
            ("class:border", box_rule(width=width, margin=margin, kind="bottom"))
        )
        return result

    control = FormattedTextControl(fragments, focusable=True)
    window = Window(control, wrap_lines=True, style="class:screen")
    bindings = KeyBindings()

    @bindings.add("up")
    @bindings.add("k")
    def _up(event):
        nonlocal selected
        selected = (selected - 1) % len(items)
        event.app.invalidate()

    @bindings.add("down")
    @bindings.add("j")
    def _down(event):
        nonlocal selected
        selected = (selected + 1) % len(items)
        event.app.invalidate()

    @bindings.add("enter")
    def _enter(event):
        event.app.exit(result=items[selected].key)

    for key in "123456789":
        index = int(key) - 1
        if index >= len(items):
            continue

        @bindings.add(key)
        def _number(event, item_index=index):
            event.app.exit(result=items[item_index].key)

    if len(items) >= 10:

        @bindings.add("0")
        def _zero(event):
            event.app.exit(result=items[9].key)

    @bindings.add("escape")
    @bindings.add("q")
    @bindings.add("c-c")
    def _back(event):
        event.app.exit(result=None)

    app = Application(
        layout=Layout(HSplit([window], style="class:screen"), focused_element=window),
        key_bindings=bindings,
        style=ui_style(),
        full_screen=True,
        mouse_support=False,
    )
    return app.run()


def show_message(title: str, text: str) -> None:
    if Application is None or not sys.stdin.isatty() or not sys.stdout.isatty():
        get_logger(__name__).info(f"\n{title}\n{text}\n")
        return

    def fragments():
        width = ui_width()
        margin = ui_margin(width)
        lines = wrap_lines_for_box(text, width=width)
        rows = 5 + len(lines)
        result = [("class:screen", ui_top_padding(rows))]
        result.extend(title_rule(title, width=width, margin=margin))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for line in lines:
            result.append(("class:muted", box_line(line, width=width, margin=margin)))
        result.append(("class:normal", box_line("", width=width, margin=margin)))
        result.extend(
            centered_box_line(
                "<  Back  >", width=width, margin=margin, style="class:button-focus"
            )
        )
        result.append(
            ("class:border", box_rule(width=width, margin=margin, kind="bottom"))
        )
        return result

    control = FormattedTextControl(fragments, focusable=True)
    window = Window(control, wrap_lines=False, style="class:screen")
    bindings = KeyBindings()

    @bindings.add("enter")
    @bindings.add("escape")
    @bindings.add("q")
    @bindings.add("c-c")
    def _close(event):
        event.app.exit()

    app = Application(
        layout=Layout(HSplit([window], style="class:screen"), focused_element=window),
        key_bindings=bindings,
        style=ui_style(),
        full_screen=True,
        mouse_support=False,
    )
    app.run()


def prompt_value(title: str, label: str, default: str) -> str | None:
    if input_dialog is None:
        value = input(f"{label} [{default}]: ").strip()
        return value or default
    value = input_dialog(
        title=title, text=label, default=default, style=ui_style()
    ).run()
    if value is None:
        return None
    return value.strip()


def prompt_secret(title: str, label: str) -> str | None:
    if input_dialog is None:
        value = input(f"{label}: ")
        return value
    value = input_dialog(title=title, text=label, password=True, style=ui_style()).run()
    if value is None:
        return None
    return value


def confirm_action(title: str, command: list[str]) -> bool:
    choice = choose_item(
        title,
        "Command:\n\n"
        f"{quote_command(command)}\n\n"
        "Review the command before running it.",
        [
            MenuItem(
                "run", "Run command", "Execute this command in the current terminal."
            ),
            MenuItem("back", "Back", "Return without running anything."),
        ],
        "back",
    )
    return choice == "run"


def confirm_flash(command: list[str]) -> bool:
    if Application is not None and sys.stdin.isatty() and sys.stdout.isatty():
        return confirm_flash_view(command)
    typed = prompt_value(
        "Flash Confirmation",
        "Flashing writes device partitions. Put the device in Qualcomm 9008/EDL mode.\n"
        "Type FLASH to run:\n\n"
        f"{quote_command(command)}",
        "",
    )
    return typed == "FLASH"


def confirm_flash_view(command: list[str]) -> bool:
    typed = {"value": "", "error": ""}
    result = {"confirmed": False}
    command_lines = wrap_for_box(
        quote_command(command), width=ui_width(), subsequent_indent="  "
    )

    def fragments():
        width = ui_width()
        margin = ui_margin(width)
        rows = 15 + len(command_lines)
        input_value = typed["value"] or ""
        cursor = " " if input_value else "_"
        result_fragments = [("class:screen", ui_top_padding(rows))]
        result_fragments.extend(
            title_rule("Flash Confirmation", width=width, margin=margin)
        )
        result_fragments.append(("class:border", box_rule(width=width, margin=margin)))
        result_fragments.append(
            (
                "class:normal",
                box_line(
                    " This will write device partitions.", width=width, margin=margin
                ),
            )
        )
        result_fragments.append(
            (
                "class:normal",
                box_line(
                    " Device must be in Qualcomm 9008/EDL mode.",
                    width=width,
                    margin=margin,
                ),
            )
        )
        result_fragments.append(("class:border", box_rule(width=width, margin=margin)))
        result_fragments.append(
            ("class:section", box_line(" Command", width=width, margin=margin))
        )
        for line in command_lines:
            result_fragments.append(
                ("class:muted", box_line(line, width=width, margin=margin))
            )
        result_fragments.append(("class:border", box_rule(width=width, margin=margin)))
        result_fragments.append(
            (
                "class:section",
                box_line(" Type FLASH to continue", width=width, margin=margin),
            )
        )
        result_fragments.append(
            (
                "class:selected",
                box_line(f" > {input_value}{cursor}", width=width, margin=margin),
            )
        )
        if typed["error"]:
            result_fragments.append(
                (
                    "class:footer",
                    box_line(f" {typed['error']}", width=width, margin=margin),
                )
            )
        else:
            result_fragments.append(
                (
                    "class:footer",
                    box_line(
                        " Enter: confirm   Esc/Ctrl-C: cancel   Backspace: edit",
                        width=width,
                        margin=margin,
                    ),
                )
            )
        result_fragments.append(
            ("class:border", box_rule(width=width, margin=margin, kind="bottom"))
        )
        return result_fragments

    control = FormattedTextControl(fragments, focusable=True)
    window = Window(control, wrap_lines=False, style="class:screen")
    bindings = KeyBindings()

    @bindings.add("enter")
    def _enter(event):
        if typed["value"] == "FLASH":
            result["confirmed"] = True
            event.app.exit()
        else:
            typed["error"] = "Confirmation text must be exactly FLASH."
            event.app.invalidate()

    @bindings.add("backspace")
    @bindings.add("c-h")
    def _backspace(event):
        typed["value"] = typed["value"][:-1]
        typed["error"] = ""
        event.app.invalidate()

    @bindings.add("escape")
    @bindings.add("c-c")
    def _cancel(event):
        result["confirmed"] = False
        event.app.exit()

    @bindings.add("<any>")
    def _type(event):
        data = event.data
        if data and data.isprintable() and len(data) == 1:
            typed["value"] = (typed["value"] + data)[:16]
            typed["error"] = ""
            event.app.invalidate()

    app = Application(
        layout=Layout(HSplit([window], style="class:screen"), focused_element=window),
        key_bindings=bindings,
        style=ui_style(),
        full_screen=True,
        mouse_support=False,
    )
    app.run()
    return result["confirmed"]


def run_command_view(command: list[str], *, stdin_text: str | None = None) -> int:
    lines: list[str] = ["Running:", quote_command(command), ""]
    state: dict[str, bool | int | None] = {"done": False, "returncode": None}
    scroll = {"offset": 0}
    process_holder: dict[str, subprocess.Popen[str] | None] = {"process": None}
    app_holder: dict[str, Application | None] = {"app": None}
    lock = threading.Lock()

    def append_line(line: str) -> None:
        with lock:
            lines.append(line.rstrip("\n"))
            del lines[:-2000]
        app = app_holder["app"]
        if app is not None:
            app.invalidate()

    def worker() -> None:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if stdin_text is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            process_holder["process"] = process
            if stdin_text is not None and process.stdin is not None:
                process.stdin.write(stdin_text)
                process.stdin.flush()
                process.stdin.close()
            if process.stdout is not None:
                for output_line in process.stdout:
                    append_line(output_line)
            returncode = process.wait()
        except Exception as exc:
            append_line(f"Command failed to start: {exc}")
            returncode = 1
        with lock:
            state["done"] = True
            state["returncode"] = returncode
        append_line(
            f"Command finished with exit code {returncode}."
            if returncode
            else "Command finished successfully."
        )

    def wrapped_lines(width: int) -> list[str]:
        wrapped: list[str] = []
        with lock:
            source = list(lines)
        for line in source:
            wrapped.extend(wrap_for_box(line, width=width))
        return wrapped

    def output_height() -> int:
        terminal_lines = shutil.get_terminal_size((100, 30)).lines
        panel_rows = min(max(12, terminal_lines - 4), terminal_lines)
        return max(3, panel_rows - 7)

    def max_scroll(width: int, height: int) -> int:
        return max(0, len(wrapped_lines(width)) - height)

    def visible_lines(width: int, height: int) -> list[str]:
        wrapped = wrapped_lines(width)
        if height <= 0:
            return []
        with lock:
            scroll["offset"] = min(scroll["offset"], max(0, len(wrapped) - height))
            offset = scroll["offset"]
        end = max(0, len(wrapped) - offset)
        start = max(0, end - height)
        return wrapped[start:end]

    def set_scroll_by(delta: int) -> None:
        width = ui_width()
        height = output_height()
        with lock:
            scroll["offset"] = max(
                0, min(scroll["offset"] + delta, max_scroll(width, height))
            )
        app = app_holder["app"]
        if app is not None:
            app.invalidate()

    def scroll_by(delta: int, event) -> None:
        set_scroll_by(delta)
        event.app.invalidate()

    def click_older(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            set_scroll_by(output_height())

    def click_newer(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            set_scroll_by(-output_height())

    def click_latest(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            with lock:
                scroll["offset"] = 0
            app = app_holder["app"]
            if app is not None:
                app.invalidate()

    def fragments():
        width = ui_width()
        margin = ui_margin(width)
        terminal_lines = shutil.get_terminal_size((100, 30)).lines
        panel_rows = min(max(12, terminal_lines - 4), terminal_lines)
        height = max(3, panel_rows - 7)
        with lock:
            done = bool(state["done"])
            returncode = state["returncode"]
        result = [("class:screen", ui_top_padding(panel_rows))]
        result.extend(title_rule("Command Output", width=width, margin=margin))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for line in visible_lines(width, height):
            result.append(("class:muted", box_line(line, width=width, margin=margin)))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        if done:
            status = (
                "Exit code: 0"
                if returncode == 0
                else f"Exit code: {returncode if returncode is not None else 'unknown'}"
            )
            result.append(
                ("class:footer", box_line(status, width=width, margin=margin))
            )
            result.append(
                (
                    "class:footer",
                    box_line(
                        "Up/PgUp: older  Down/PgDn/End: newer  Enter: back",
                        width=width,
                        margin=margin,
                    ),
                )
            )
            result.extend(
                clickable_log_controls(
                    width=width,
                    margin=margin,
                    older=click_older,
                    newer=click_newer,
                    latest=click_latest,
                )
            )
            result.extend(
                centered_box_line(
                    "<  Back  >",
                    width=width,
                    margin=margin,
                    style="class:button-focus",
                )
            )
        else:
            result.append(
                (
                    "class:footer",
                    box_line(
                        "Running... Up/PgUp: older  End: latest  Ctrl-C: stop",
                        width=width,
                        margin=margin,
                    ),
                )
            )
            result.extend(
                clickable_log_controls(
                    width=width,
                    margin=margin,
                    older=click_older,
                    newer=click_newer,
                    latest=click_latest,
                )
            )
        result.append(
            ("class:border", box_rule(width=width, margin=margin, kind="bottom"))
        )
        return result

    control = FormattedTextControl(fragments, focusable=True)
    window = Window(control, wrap_lines=False, style="class:screen")
    bindings = KeyBindings()

    @bindings.add("enter")
    @bindings.add("escape")
    @bindings.add("q")
    def _close_when_done(event):
        with lock:
            done = bool(state["done"])
        if done:
            event.app.exit()

    @bindings.add("up")
    @bindings.add("k")
    def _scroll_up(event):
        scroll_by(1, event)

    @bindings.add("down")
    @bindings.add("j")
    def _scroll_down(event):
        scroll_by(-1, event)

    @bindings.add(Keys.ScrollUp)
    def _mouse_scroll_up(event):
        scroll_by(3, event)

    @bindings.add(Keys.ScrollDown)
    def _mouse_scroll_down(event):
        scroll_by(-3, event)

    @bindings.add("pageup")
    @bindings.add("c-b")
    def _page_up(event):
        scroll_by(output_height(), event)

    @bindings.add("pagedown")
    @bindings.add("c-f")
    def _page_down(event):
        scroll_by(-output_height(), event)

    @bindings.add("home")
    def _home(event):
        width = ui_width()
        height = output_height()
        with lock:
            scroll["offset"] = max_scroll(width, height)
        event.app.invalidate()

    @bindings.add("end")
    def _end(event):
        with lock:
            scroll["offset"] = 0
        event.app.invalidate()

    @bindings.add("c-c")
    def _cancel(event):
        process = process_holder["process"]
        if process is not None and process.poll() is None:
            append_line("Stopping command...")
            process.terminate()
            return
        event.app.exit()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    app = Application(
        layout=Layout(HSplit([window], style="class:screen"), focused_element=window),
        key_bindings=bindings,
        style=ui_style(),
        full_screen=True,
        mouse_support=True,
    )
    app_holder["app"] = app
    app.run()
    thread.join(timeout=0.2)
    with lock:
        return int(state["returncode"] or 0)


def run_direct_view(title: str, command_line: str, target: Callable[[], None]) -> int:
    lines: list[str] = ["Running:", command_line, ""]
    state: dict[str, bool | int | None] = {"done": False, "returncode": None}
    scroll = {"offset": 0}
    app_holder: dict[str, Application | None] = {"app": None}
    lock = threading.Lock()

    def append_line(line: str) -> None:
        with lock:
            lines.append(line.rstrip("\n"))
            del lines[:-2000]
        app = app_holder["app"]
        if app is not None:
            app.invalidate()

    class TuiLogHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            append_line(self.format(record))

    def worker() -> None:
        root = logging.getLogger()
        old_handlers = root.handlers[:]
        old_level = root.level
        handler = TuiLogHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        root.handlers = [handler]
        root.setLevel(logging.INFO)
        returncode = 0
        try:
            target()
        except SystemExit as exc:
            returncode = int(exc.code) if isinstance(exc.code, int) else 1
            if exc.code not in (None, 0):
                append_line(f"Command exited: {exc.code}")
        except Exception as exc:
            returncode = 1
            append_line(f"Error: {exc}")
        finally:
            root.handlers = old_handlers
            root.setLevel(old_level)
        with lock:
            state["done"] = True
            state["returncode"] = returncode
        append_line(
            f"Command finished with exit code {returncode}."
            if returncode
            else "Command finished successfully."
        )

    def wrapped_lines(width: int) -> list[str]:
        wrapped: list[str] = []
        with lock:
            source = list(lines)
        for line in source:
            wrapped.extend(wrap_for_box(line, width=width))
        return wrapped

    def output_height() -> int:
        terminal_lines = shutil.get_terminal_size((100, 30)).lines
        panel_rows = min(max(12, terminal_lines - 4), terminal_lines)
        return max(3, panel_rows - 7)

    def max_scroll(width: int, height: int) -> int:
        return max(0, len(wrapped_lines(width)) - height)

    def visible_lines(width: int, height: int) -> list[str]:
        wrapped = wrapped_lines(width)
        if height <= 0:
            return []
        with lock:
            scroll["offset"] = min(scroll["offset"], max(0, len(wrapped) - height))
            offset = scroll["offset"]
        end = max(0, len(wrapped) - offset)
        start = max(0, end - height)
        return wrapped[start:end]

    def set_scroll_by(delta: int) -> None:
        width = ui_width()
        height = output_height()
        with lock:
            scroll["offset"] = max(
                0, min(scroll["offset"] + delta, max_scroll(width, height))
            )
        app = app_holder["app"]
        if app is not None:
            app.invalidate()

    def scroll_by(delta: int, event) -> None:
        set_scroll_by(delta)
        event.app.invalidate()

    def click_older(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            set_scroll_by(output_height())

    def click_newer(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            set_scroll_by(-output_height())

    def click_latest(mouse_event):
        if mouse_event.event_type == MouseEventType.MOUSE_UP:
            with lock:
                scroll["offset"] = 0
            app = app_holder["app"]
            if app is not None:
                app.invalidate()

    def fragments():
        width = ui_width()
        margin = ui_margin(width)
        terminal_lines = shutil.get_terminal_size((100, 30)).lines
        panel_rows = min(max(12, terminal_lines - 4), terminal_lines)
        height = max(3, panel_rows - 7)
        with lock:
            done = bool(state["done"])
            returncode = state["returncode"]
        result = [("class:screen", ui_top_padding(panel_rows))]
        result.extend(title_rule(title, width=width, margin=margin))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for line in visible_lines(width, height):
            result.append(("class:muted", box_line(line, width=width, margin=margin)))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        if done:
            status = (
                "Exit code: 0"
                if returncode == 0
                else f"Exit code: {returncode if returncode is not None else 'unknown'}"
            )
            result.append(
                ("class:footer", box_line(status, width=width, margin=margin))
            )
            result.append(
                (
                    "class:footer",
                    box_line(
                        "Up/PgUp: older  Down/PgDn/End: newer  Enter: back",
                        width=width,
                        margin=margin,
                    ),
                )
            )
            result.extend(
                clickable_log_controls(
                    width=width,
                    margin=margin,
                    older=click_older,
                    newer=click_newer,
                    latest=click_latest,
                )
            )
            result.extend(
                centered_box_line(
                    "<  Back  >",
                    width=width,
                    margin=margin,
                    style="class:button-focus",
                )
            )
        else:
            result.append(
                (
                    "class:footer",
                    box_line(
                        "Running... Up/PgUp: older  End: latest",
                        width=width,
                        margin=margin,
                    ),
                )
            )
            result.extend(
                clickable_log_controls(
                    width=width,
                    margin=margin,
                    older=click_older,
                    newer=click_newer,
                    latest=click_latest,
                )
            )
        result.append(
            ("class:border", box_rule(width=width, margin=margin, kind="bottom"))
        )
        return result

    control = FormattedTextControl(fragments, focusable=True)
    window = Window(control, wrap_lines=False, style="class:screen")
    bindings = KeyBindings()

    @bindings.add("enter")
    @bindings.add("escape")
    @bindings.add("q")
    @bindings.add("c-c")
    def _close_when_done(event):
        with lock:
            done = bool(state["done"])
        if done:
            event.app.exit()

    @bindings.add("up")
    @bindings.add("k")
    def _scroll_up(event):
        scroll_by(1, event)

    @bindings.add("down")
    @bindings.add("j")
    def _scroll_down(event):
        scroll_by(-1, event)

    @bindings.add(Keys.ScrollUp)
    def _mouse_scroll_up(event):
        scroll_by(3, event)

    @bindings.add(Keys.ScrollDown)
    def _mouse_scroll_down(event):
        scroll_by(-3, event)

    @bindings.add("pageup")
    @bindings.add("c-b")
    def _page_up(event):
        scroll_by(output_height(), event)

    @bindings.add("pagedown")
    @bindings.add("c-f")
    def _page_down(event):
        scroll_by(-output_height(), event)

    @bindings.add("home")
    def _home(event):
        width = ui_width()
        height = output_height()
        with lock:
            scroll["offset"] = max_scroll(width, height)
        event.app.invalidate()

    @bindings.add("end")
    def _end(event):
        with lock:
            scroll["offset"] = 0
        event.app.invalidate()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    app = Application(
        layout=Layout(HSplit([window], style="class:screen"), focused_element=window),
        key_bindings=bindings,
        style=ui_style(),
        full_screen=True,
        mouse_support=True,
    )
    app_holder["app"] = app
    app.run()
    thread.join(timeout=0.2)
    with lock:
        return int(state["returncode"] or 0)


def run_lrsa_flow(args: list[str], *, title: str, flash: bool = False) -> int:
    command_line = quote_lrsa_args(args)
    if flash and not confirm_flash(["lrsa", *args]):
        return 0

    def target() -> None:
        run_lrsa_cli(args)

    if Application is not None and sys.stdin.isatty() and sys.stdout.isatty():
        result = run_direct_view(title, command_line, target)
    else:
        get_logger(__name__).info("\nRunning:")
        get_logger(__name__).info(command_line)
        get_logger(__name__).info("")
        try:
            target()
            result = 0
        except SystemExit as exc:
            result = int(exc.code) if isinstance(exc.code, int) else 1
        except Exception as exc:
            get_logger(__name__).error("Error: %s", exc)
            result = 1
    if result != 0:
        get_logger(__name__).error("Command failed with exit code %s", result)
    return result


def run_command(
    command: list[str], *, flash: bool = False, stdin_text: str | None = None
) -> int:
    if flash:
        if not confirm_flash(command):
            return 0

    if Application is not None and sys.stdin.isatty() and sys.stdout.isatty():
        result = run_command_view(command, stdin_text=stdin_text)
        if result != 0:
            get_logger(__name__).error("Command failed with exit code %s", result)
        return result

    get_logger(__name__).info("\nRunning:")
    get_logger(__name__).info(quote_command(command))
    get_logger(__name__).info("")
    result = subprocess.run(
        command, input=stdin_text, text=stdin_text is not None
    ).returncode
    if result != 0:
        get_logger(__name__).error("Command failed with exit code %s", result)
        if sys.stdin.isatty():
            show_message(
                "Command Failed",
                f"Exit code: {result}\n\nCommand:\n{quote_command(command)}",
            )
    if sys.stdin.isatty():
        input("\nPress Enter to return to LRSA menu...")
    return result


def login_flow(state: MenuState) -> int:
    password = prompt_secret("Sudo Required", "macOS password for sudo (not stored)")
    if password is None:
        return 0
    return run_command(login_command(state), stdin_text=f"{password}\n")


def refresh_resources_impl(state: MenuState, log: Callable[[str], None]) -> dict:
    if not require_lookup_settings(state):
        raise RuntimeError("Missing device settings.")

    log(f"Reading token: {state.token_file}")
    token = extract_token_from_file(state.token_file)
    client = LRSAClient(token=token)
    if state.imei:
        log(f"Querying rescue ROM by IMEI: {state.imei}")
        result = client.get_resources_by_imei(state.imei, state.imei2)
    else:
        log(f"Querying rescue ROM by SN: model={state.model}, sn={state.sn}")
        result = client.get_rescue_rom(state.model, state.sn)

    payload = response_payload(result)
    save_json(state.work_dir / "rescue_rom_response.json", payload)
    log(f"Rescue response saved: {state.work_dir / 'rescue_rom_response.json'}")
    if not isinstance(payload, dict) or not is_success_payload(payload):
        code = payload.get("code") if isinstance(payload, dict) else None
        desc = payload.get("desc") if isinstance(payload, dict) else None
        raise RuntimeError(
            f"LRSA lookup failed: code={code or '(none)'} desc={desc or '(none)'}.\n"
            "Run Login / capture Lenovo token again if the token is invalid or expired."
        )
    resources = content_list(payload)
    if not resources:
        raise RuntimeError(
            "LRSA returned success but no firmware packages. Check Model + SN or use IMEI for phones/mobile.",
        )
    log(f"Found {len(resources)} firmware package(s).")
    return payload


def refresh_resources(state: MenuState) -> dict | None:
    try:
        return refresh_resources_impl(
            state, lambda line: get_logger(__name__).info(line)
        )
    except Exception as exc:
        show_message("Firmware Lookup", str(exc))
        return None


def has_lookup_settings(state: MenuState) -> bool:
    if state.imei:
        return True
    return bool(state.model and state.sn)


def require_lookup_settings(state: MenuState) -> bool:
    if has_lookup_settings(state):
        return True
    show_message(
        "Missing Device Settings",
        "Set either IMEI for phone/mobile lookup, or both Model and SN for tablet/laptop SN lookup.",
    )
    return False


def phone_flow(state: MenuState) -> int:
    imei = prompt_value("Phone / Mobile Flow", "IMEI", state.imei)
    if imei is None:
        return 0
    imei2 = prompt_value("Phone / Mobile Flow", "IMEI2 (optional)", state.imei2)
    if imei2 is None:
        return 0
    state.imei = imei
    state.imei2 = imei2
    save_state(state)
    return run_lrsa_flow(download_args(state), title="Download ROM")


def device_flow(state: MenuState) -> None:
    while True:
        choice = choose_item(
            "Device Identity",
            "Choose how Software Fix should match the device. Phones usually use IMEI; tablets/laptops usually use Model + SN.",
            [
                MenuItem("model", "Model", value_or_unset(state.model)),
                MenuItem("sn", "Serial number", value_or_unset(state.sn)),
                MenuItem("imei", "IMEI", value_or_unset(state.imei)),
                MenuItem("imei2", "IMEI2", value_or_unset(state.imei2)),
                MenuItem(
                    "clear_imei",
                    "Use Model + SN lookup",
                    "Clears IMEI fields and keeps model/SN mode.",
                ),
                MenuItem(
                    "clear_sn",
                    "Use IMEI lookup",
                    "Clears Model + SN fields and keeps IMEI mode.",
                ),
                MenuItem("back", "Back", "Return to the main menu."),
            ],
            "model",
        )
        if choice is None or choice == "back":
            return
        if choice == "model":
            value = prompt_value(
                "Device Identity", "Model, for example Lenovo TB390FU", state.model
            )
            if value is not None:
                state.model = value
        elif choice == "sn":
            value = prompt_value("Device Identity", "Serial number", state.sn)
            if value is not None:
                state.sn = value
        elif choice == "imei":
            value = prompt_value("Device Identity", "IMEI", state.imei)
            if value is not None:
                state.imei = value
        elif choice == "imei2":
            value = prompt_value("Device Identity", "IMEI2 (optional)", state.imei2)
            if value is not None:
                state.imei2 = value
        elif choice == "clear_imei":
            state.imei = ""
            state.imei2 = ""
        elif choice == "clear_sn":
            state.model = ""
            state.sn = ""
        save_state(state)


def load_rescue_payload(state: MenuState) -> dict | None:
    path = state.work_dir / "rescue_rom_response.json"
    if not path.exists():
        show_message(
            "Firmware Versions",
            "No rescue response exists yet. Run Dry-run matched rescue flow first, then open this picker.",
        )
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        show_message("Firmware Versions", f"Could not read {path}: {exc}")
        return None
    if not is_success_payload(payload):
        show_message(
            "Firmware Versions",
            f"Saved rescue response is not usable: code={payload.get('code')} desc={payload.get('desc')}.\n"
            "Run Login / capture Lenovo token, then Dry-run matched rescue flow again.",
        )
        return None
    return payload


def select_firmware_from_payload(state: MenuState, payload: dict) -> bool:
    resources = content_list(payload)
    if not resources:
        show_message(
            "Firmware Versions",
            "The rescue response does not contain firmware resources.",
        )
        return False

    if len(resources) == 1:
        summary = resource_summary(resources[0])
        firmware = summary.get("firmwareName") or "(unnamed firmware)"
        model = (
            summary.get("modelName")
            or summary.get("realModelName")
            or "(unknown model)"
        )
        match = summary.get("romMatchId") or "(no match id)"
        choice = choose_item(
            "Available ROMs",
            "One firmware package is available for this device.",
            [
                MenuItem("select", firmware, f"{model} - {match}"),
                MenuItem("back", "Back", "Return without selecting a package."),
            ],
            "select",
        )
        if choice != "select":
            return False
        state.firmware_index = 0
        save_state(state)
        return True

    items = []
    for index, resource in enumerate(resources):
        summary = resource_summary(resource)
        firmware = summary.get("firmwareName") or "(unnamed firmware)"
        model = (
            summary.get("modelName")
            or summary.get("realModelName")
            or "(unknown model)"
        )
        match = summary.get("romMatchId") or "(no match id)"
        items.append(MenuItem(str(index), firmware, f"{model} - {match}"))
    items.append(MenuItem("back", "Back", "Return without selecting a package."))

    default = str(state.firmware_index) if state.firmware_index is not None else "0"
    choice = choose_item(
        "Available ROMs",
        "Select the ROM package for download/extract/flash.",
        items,
        default,
    )
    if choice is None or choice == "back":
        return False
    state.firmware_index = int(choice)
    save_state(state)
    return True


def firmware_flow(state: MenuState, *, refresh: bool = False) -> bool:
    payload = refresh_resources(state) if refresh else load_rescue_payload(state)
    if not payload:
        return False
    return select_firmware_from_payload(state, payload)


def download_flow(state: MenuState) -> int:
    if not require_lookup_settings(state):
        return 0
    payload = refresh_resources(state)
    if not payload or not select_firmware_from_payload(state, payload):
        return 0
    resources = content_list(payload)
    selected = resources[state.firmware_index or 0] if resources else None
    choice = choose_item(
        "Download ROM",
        firmware_detail_text(
            selected,
            index=state.firmware_index,
            download_size=resource_known_size(selected, state.work_dir),
            work_dir=state.work_dir,
        ),
        [
            MenuItem(
                "download",
                "Download selected ROM",
                "Fetch the official ROM package into the local Software Fix cache.",
            ),
            MenuItem("back", "Back", "Return without downloading."),
        ],
        "download",
    )
    if choice != "download":
        return 0
    return run_lrsa_flow(download_args(state), title="Download ROM")


def extract_flow(state: MenuState) -> int:
    if not require_lookup_settings(state):
        return 0
    payload = refresh_resources(state)
    if not payload or not select_firmware_from_payload(state, payload):
        return 0
    resources = content_list(payload)
    selected = resources[state.firmware_index or 0] if resources else None
    choice = choose_item(
        "Extract ROM",
        firmware_detail_text(
            selected,
            index=state.firmware_index,
            download_size=resource_known_size(selected, state.work_dir),
            work_dir=state.work_dir,
        ),
        [
            MenuItem(
                "extract",
                "Extract selected ROM",
                "Extract the already downloaded official ROM for native qfil.",
            ),
            MenuItem("back", "Back", "Return without extracting."),
        ],
        "extract",
    )
    if choice != "extract":
        return 0
    return run_lrsa_flow(extract_args(state), title="Extract ROM")


def flash_flow(state: MenuState) -> int:
    candidates = local_firmware_candidates(state)
    if not candidates:
        show_message(
            "Flash Firmware",
            "No locally extracted firmware found. Run Download ROM, then Extract ROM.",
        )
        return 0
    devices = scan_connected_devices()
    if not devices:
        show_message(
            "Flash Firmware",
            "No ADB, fastboot, or Qualcomm EDL/QDLoader device detected.",
        )
        return 0
    firmware_choice = choose_item(
        "Local Firmware",
        "Select locally extracted firmware to flash.",
        [
            MenuItem(str(index), candidate["name"], candidate["path"])
            for index, candidate in enumerate(candidates)
        ]
        + [MenuItem("back", "Back", "Return without flashing.")],
        "0",
    )
    if firmware_choice is None or firmware_choice == "back":
        return 0
    candidate = candidates[int(firmware_choice)]
    device_choice = choose_item(
        "Target Device",
        local_firmware_detail_text(candidate),
        [
            MenuItem(
                str(index),
                f"{device.get('transport', '').upper()} {device.get('serial')}",
                f"{device.get('state')} {device.get('detail') or ''}".strip(),
            )
            for index, device in enumerate(devices)
        ]
        + [MenuItem("back", "Back", "Return without flashing.")],
        "0",
    )
    if device_choice is None or device_choice == "back":
        return 0
    device = devices[int(device_choice)]
    if device.get("transport") != "edl":
        show_message(
            "Flash Firmware",
            "Selected device is not Qualcomm EDL/QDLoader. Native qfil flashing requires EDL mode.",
        )
        return 0
    choice = choose_item(
        "Flash Review",
        local_firmware_detail_text(candidate, device),
        [
            MenuItem(
                "flash",
                "Continue to flash",
                "Type FLASH on the confirmation screen to start writing.",
            ),
            MenuItem("back", "Back", "Return without flashing."),
        ],
        "back",
    )
    if choice != "flash":
        return 0
    if not confirm_flash(["lrsa", "flash-local", candidate["path"]]):
        return 0
    run_local_qfil_flash(candidate, flash=True)
    return 0


def set_path(attr: str) -> Callable[[MenuState, str], None]:
    def setter(state: MenuState, value: str) -> None:
        setattr(state, attr, Path(value))

    return setter


def set_str(attr: str) -> Callable[[MenuState, str], None]:
    def setter(state: MenuState, value: str) -> None:
        setattr(state, attr, value)

    return setter


def settings_items() -> list[SettingItem]:
    return [
        SettingItem(
            "token_file",
            "Token file",
            lambda s: str(s.token_file),
            set_path("token_file"),
        ),
        SettingItem(
            "work_dir", "Work dir", lambda s: str(s.work_dir), set_path("work_dir")
        ),
        SettingItem(
            "image_dir", "Image dir", lambda s: s.image_dir, set_str("image_dir")
        ),
    ]


def configure(state: MenuState) -> None:
    items = settings_items()
    while True:
        selected = choose_item(
            "LRSA Settings",
            "Paths and runtime settings. Use Device Identity for SN/model/IMEI.",
            [
                MenuItem(item.key, item.title, item.getter(state) or "(not set)")
                for item in items
            ]
            + [MenuItem("back", "Back", "Return to the main menu.")],
            "back",
        )
        if selected in {None, "back"}:
            return
        item = next(candidate for candidate in items if candidate.key == selected)
        value = prompt_value("Edit Setting", item.title, item.getter(state))
        if value is not None:
            item.setter(state, value)
            save_state(state)


def main_items() -> list[MenuItem]:
    return [
        MenuItem(
            "login",
            "Login / capture Lenovo token",
            "Starts the local callback monitor and browser login URL.",
        ),
        MenuItem(
            "device",
            "Device identity",
            "Set Model + SN or IMEI before looking up firmware.",
        ),
        MenuItem(
            "dry_run",
            "Dry-run matched rescue flow",
            "Queries Software Fix metadata and prints the native QFIL plan.",
        ),
        MenuItem(
            "download",
            "Download ROM",
            "Looks up available firmware, shows package details, then downloads the selected official ROM.",
        ),
        MenuItem(
            "extract",
            "Extract ROM",
            "Extracts the already downloaded official ROM for native qfil.",
        ),
        MenuItem(
            "flash",
            "Flash local firmware",
            "Selects a connected device and locally extracted firmware, then runs native qfil.",
        ),
        MenuItem(
            "scan",
            "Scan connected device",
            "Detect ADB, fastboot, or Qualcomm EDL/QDLoader state.",
        ),
        MenuItem("settings", "Settings", "Edit token path, work dir, and image dir."),
        MenuItem("exit", "Exit", "Quit the interactive CLI."),
    ]


def fallback_choose(title: str, items: list[MenuItem]) -> str | None:
    get_logger(__name__).info(f"\n{title}")
    for index, item in enumerate(items, 1):
        get_logger(__name__).info(f"{index}. {item.title} - {item.description}")
    value = input("Select: ").strip()
    if not value:
        return None
    if value.isdigit() and 1 <= int(value) <= len(items):
        return items[int(value) - 1].key
    return value


def fallback_main(state: MenuState) -> None:
    show_message(
        "LRSA Python",
        "prompt_toolkit is not installed, so arrow-key navigation is unavailable.\n\n"
        "Install dependencies with: uv sync",
    )
    while True:
        choice = fallback_choose("LRSA Python", main_items())
        if choice is None or choice in {"exit", "quit"}:
            return
        handle_choice(choice, state)


def handle_choice(choice: str, state: MenuState) -> None:
    if choice == "login":
        login_flow(state)
    elif choice == "device":
        device_flow(state)
    elif choice == "dry_run":
        if require_lookup_settings(state):
            run_lrsa_flow(dry_run_args(state), title="Dry Run")
    elif choice == "download":
        download_flow(state)
    elif choice == "extract":
        extract_flow(state)
    elif choice == "flash":
        flash_flow(state)
    elif choice == "phone":
        phone_flow(state)
    elif choice == "scan":
        show_message("Connected Device", format_device_states(scan_connected_devices()))
    elif choice == "settings":
        configure(state)


class _TextualLogHandler(logging.Handler):
    def __init__(self, app: "LRSATextualApp") -> None:
        super().__init__()
        self.app = app

    def emit(self, record: logging.LogRecord) -> None:
        self.app.call_from_thread(self.app.write_log, self.format(record))


class _FirmwareLogHandler(logging.Handler):
    def __init__(self, app: "LRSATextualApp") -> None:
        super().__init__()
        self.app = app

    def emit(self, record: logging.LogRecord) -> None:
        self.app.call_from_thread(self.app.write_firmware_log, self.format(record))


class LRSATextualApp(App):
    """Textual implementation of the LRSA menu."""

    CSS = """
    Screen {
        background: #111111;
        color: #d8d8d8;
    }

    Header, Footer {
        background: #111111;
        color: #d8d8d8;
    }

    /* ── Top-level 3-column layout ── */
    #body {
        height: 1fr;
        padding: 1 1;
    }

    #sidebar {
        width: 30;
        min-width: 22;
        height: 1fr;
        border: solid #b8b8b8;
        padding: 1 2;
    }

    #workspace {
        width: 2fr;
        height: 1fr;
        border: solid #b8b8b8;
        padding: 1 2;
        margin-left: 1;
    }

    #log-panel {
        width: 2fr;
        min-width: 30;
        height: 1fr;
        border: solid #b8b8b8;
        padding: 1 1;
        margin-left: 1;
        background: #0f0f0f;
    }

    /* ── Sidebar ── */
    .title {
        color: #ff3b30;
        text-style: bold;
        margin-bottom: 1;
    }

    .section-title {
        color: #d8d8d8;
        text-style: bold;
        margin: 1 0 1 0;
    }

    #actions {
        margin-top: 1;
    }

    #actions Button {
        width: 100%;
        margin: 0 0 1 0;
    }

    /* ── Identity panel ── */
    #identity-panel {
        height: auto;
        border: solid #333333;
        padding: 1 2;
        margin-bottom: 1;
    }

    #identity-header {
        height: auto;
        margin-bottom: 1;
    }

    #identity-title {
        width: 1fr;
        color: #ff3b30;
        text-style: bold;
        content-align: left middle;
    }

    #identity-actions {
        width: auto;
        height: auto;
    }

    #identity-actions Button {
        width: 10;
        min-width: 8;
        margin: 0 0 0 1;
    }

    #identity-fields {
        layout: grid;
        grid-size: 3;
        grid-gutter: 1 2;
        height: auto;
    }

    .field {
        height: auto;
    }

    .field-label {
        color: #9a9a9a;
        margin: 0;
    }

    Input {
        height: 3;
        border: tall #444444;
        padding: 0 1;
        margin-bottom: 0;
        width: 100%;
        background: #1a1a1a;
        color: #e0e0e0;
    }

    Input:focus {
        border: tall #ff3b30;
    }

    /* ── Device panel ── */
    #device-panel {
        height: auto;
        border: solid #333333;
        padding: 1 2;
        margin-bottom: 1;
    }

    #device-header {
        height: auto;
        margin-bottom: 1;
    }

    #device-title {
        width: 1fr;
        color: #ff3b30;
        text-style: bold;
        content-align: left middle;
    }

    #scan-devices-inline {
        width: 10;
        min-width: 8;
    }

    #device-state {
        height: auto;
        color: #d8d8d8;
    }

    /* ── Firmware panel (hidden by default, replaces main workspace content) ── */
    #firmware-panel {
        display: none;
        height: auto;
        min-height: 20;
        border: solid #333333;
        padding: 1;
        background: #0f0f0f;
    }

    #firmware-actions {
        height: auto;
        margin-bottom: 1;
    }

    #firmware-title {
        width: 1fr;
        color: #ff3b30;
        text-style: bold;
        content-align: left middle;
    }

    #firmware-actions Button {
        width: 11;
        min-width: 8;
        margin-left: 1;
    }

    #firmware-table {
        height: auto;
        min-height: 10;
        margin-bottom: 1;
    }

    #target-device-title {
        display: none;
        height: auto;
        color: #ff3b30;
        text-style: bold;
        margin-top: 1;
    }

    #target-device-table {
        display: none;
        height: 5;
        margin-bottom: 1;
    }

    #firmware-detail {
        display: none;
        height: auto;
        max-height: 9;
        color: #d8d8d8;
    }

    #download-progress-label {
        display: none;
        height: auto;
        color: #c8c8c8;
        margin-top: 1;
    }

    #download-progress {
        display: none;
        height: 1;
        margin: 0 0 1 0;
    }


    /* ── Status bar ── */
    #status {
        height: auto;
        color: #c8c8c8;
        margin-bottom: 1;
    }

    /* ── Log panel ── */
    #log-header {
        height: auto;
        margin-bottom: 1;
    }

    #log-title {
        width: 1fr;
        color: #ff3b30;
        text-style: bold;
        content-align: left middle;
    }

    #log-wrap {
        width: 10;
        min-width: 8;
    }

    #log {
        height: 1fr;
        border: solid #333333;
        padding: 1;
        background: #111111;
        color: #d8d8d8;
    }
    """

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("1", "login", "Login"),
        ("2", "dry_run", "Dry run"),
        ("3", "scan_devices", "Scan"),
        ("4", "download_rom", "Download"),
        ("5", "extract_rom", "Extract"),
        ("6", "flash", "Flash"),
        ("7", "quit", "Quit"),
        ("d", "dry_run", "Dry run"),
        ("p", "download_rom", "Download"),
        ("w", "toggle_log_wrap", "Wrap log"),
    ]

    WORKFLOW_LABELS = {
        "login": ("1. Login / capture token", "1. Login"),
        "dry-run": ("2. Dry-run rescue flow", "2. Dry run"),
        "scan-devices": ("3. Scan connected device", "3. Scan"),
        "download": ("4. Download ROM", "4. Download"),
        "extract": ("5. Extract ROM", "5. Extract"),
        "flash": ("6. Flash local firmware", "6. Flash"),
        "exit": ("7. Exit", "7. Exit"),
    }

    def __init__(self, state: MenuState) -> None:
        super().__init__()
        self.state = state
        self.busy = False
        self.flash_armed = False
        self.editing_identity = False
        self.narrow_layout = False
        self.firmware_task_mode = "download"
        self.firmware_resources: list[dict] = []
        self.local_firmware_resources: list[dict[str, str]] = []
        self.connected_devices: list[dict[str, str]] = []
        self.selected_firmware_index: int | None = None
        self.selected_device_index: int | None = None
        self.firmware_size_cache: dict[int, str] = {}
        self.log_wrap = True
        self._log_lines: list[str] = []

    @property
    def identity_input_ids(self) -> tuple[str, ...]:
        return ("model", "sn", "imei", "imei2")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with VerticalScroll(id="sidebar"):
                yield Static("LRSA", classes="title")
                yield Static("Workflow Menu", classes="section-title")
                with Vertical(id="actions"):
                    yield Button("1. Login / capture token", id="login")
                    yield Button("2. Dry-run rescue flow", id="dry-run")
                    yield Button("3. Scan connected device", id="scan-devices")
                    yield Button("4. Download ROM", id="download")
                    yield Button("5. Extract ROM", id="extract")
                    yield Button("6. Flash local firmware", id="flash", variant="error")
                    yield Button("7. Exit", id="exit")
            with VerticalScroll(id="workspace"):
                with Vertical(id="identity-panel"):
                    with Horizontal(id="identity-header"):
                        yield Static("Device Identity", id="identity-title")
                        with Horizontal(id="identity-actions"):
                            yield Button("Edit", id="edit-fields", compact=True)
                            yield Button(
                                "Save",
                                id="save-fields",
                                variant="primary",
                                compact=True,
                                disabled=True,
                            )
                            yield Button(
                                "Revert",
                                id="revert-fields",
                                compact=True,
                                disabled=True,
                            )
                    with Grid(id="identity-fields"):
                        with Vertical(classes="field"):
                            yield Label("Model", classes="field-label")
                            yield Input(
                                value=self.state.model,
                                id="model",
                                placeholder="e.g. 2201123G",
                                disabled=True,
                            )
                        with Vertical(classes="field"):
                            yield Label("Serial number", classes="field-label")
                            yield Input(
                                value=self.state.sn,
                                id="sn",
                                placeholder="e.g. a1b2c3d4",
                                disabled=True,
                            )
                        with Vertical(classes="field"):
                            yield Label("IMEI", classes="field-label")
                            yield Input(
                                value=self.state.imei,
                                id="imei",
                                placeholder="15 digits",
                                disabled=True,
                            )
                        with Vertical(classes="field"):
                            yield Label("IMEI2", classes="field-label")
                            yield Input(
                                value=self.state.imei2,
                                id="imei2",
                                placeholder="15 digits",
                                disabled=True,
                            )
                        with Vertical(classes="field"):
                            yield Label(
                                "sudo password for Login", classes="field-label"
                            )
                            yield Input(password=True, id="sudo-password", placeholder="optional")
                with Vertical(id="device-panel"):
                    with Horizontal(id="device-header"):
                        yield Static("Device State", id="device-title")
                        yield Button("Scan", id="scan-devices-inline", compact=True)
                    yield Static("Scanning...", id="device-state")
                with Vertical(id="firmware-panel"):
                    with Horizontal(id="firmware-actions"):
                        yield Static("Select ROM", id="firmware-title")
                        yield Button("Refresh", id="firmware-refresh", compact=True)
                        yield Button(
                            "Download",
                            id="download-selected",
                            variant="primary",
                            compact=True,
                            disabled=True,
                        )
                        yield Button("Back", id="firmware-back", compact=True)
                    yield DataTable(id="firmware-table", zebra_stripes=True)
                    yield Static("Target Device", id="target-device-title")
                    yield DataTable(id="target-device-table", zebra_stripes=True)
                    yield Static("", id="firmware-detail")
                    yield Static("", id="download-progress-label")
                    yield ProgressBar(total=100, id="download-progress")
                yield Static("", id="status")
            with Vertical(id="log-panel"):
                with Horizontal(id="log-header"):
                    yield Static("Command Log", id="log-title")
                    yield Button("Wrap On", id="log-wrap", compact=True)
                yield TextArea(
                    id="log",
                    read_only=True,
                    soft_wrap=True,
                    show_line_numbers=False,
                    theme="monokai",
                )
        yield Footer()

    def on_mount(self) -> None:
        self.title = "LRSA"
        table = self.query_one("#firmware-table", DataTable)
        table.cursor_type = "row"
        table.add_column("#", key="index", width=4)
        table.add_column("Firmware", key="firmware", width=40)
        table.add_column("Model", key="model", width=14)
        table.add_column("Mode", key="mode", width=12)
        table.add_column("Published", key="published", width=19)
        device_table = self.query_one("#target-device-table", DataTable)
        device_table.cursor_type = "row"
        device_table.add_column("#", key="index", width=4)
        device_table.add_column("Mode", key="mode", width=10)
        device_table.add_column("Serial", key="serial", width=22)
        device_table.add_column("State", key="state", width=24)
        device_table.add_column("Detail", key="detail", width=30)
        self.apply_responsive_layout()
        self.refresh_status()
        self.refresh_device_scan()
        self.write_log(
            "Ready. Mouse wheel, scrollbar, PageUp/PageDown, Home/End work in this log."
        )

    def on_resize(self) -> None:
        self.apply_responsive_layout()
        self.refresh_status()

    def apply_responsive_layout(self) -> None:
        width, height = self.size
        narrow = width < 120
        dense = height < 32
        tiny = width < 80 or height < 24
        self.narrow_layout = narrow

        sidebar = self.query_one("#sidebar", VerticalScroll)
        sidebar.styles.width = 22 if tiny else 24 if narrow else 30

        self.query_one("#log-title", Static).update("Log" if tiny else "Command Log")
        identity_title = self.query_one("#identity-title", Static)
        identity_title.update("" if narrow else "Device Identity")
        identity_title.styles.width = 0 if narrow else "1fr"

        for button_id, labels in self.WORKFLOW_LABELS.items():
            button = self.query_one(f"#{button_id}", Button)
            button.label = labels[1] if narrow else labels[0]
            button.compact = dense or narrow
            button.styles.margin = (0, 0, 0, 0) if dense else (0, 0, 1, 0)

        for button_id in (
            "edit-fields",
            "save-fields",
            "revert-fields",
            "scan-devices-inline",
            "firmware-refresh",
            "download-selected",
            "firmware-back",
            "log-wrap",
        ):
            self.query_one(f"#{button_id}", Button).compact = dense or narrow

    def write_log(self, line: str) -> None:
        self._log_lines.append(line)
        max_lines = 5000
        if len(self._log_lines) > max_lines:
            self._log_lines = self._log_lines[-max_lines:]
        log = self.query_one("#log", TextArea)
        if log.text:
            log.insert(f"\n{line}", log.document.end)
        else:
            log.insert(line, log.document.end)
        log.scroll_end(animate=False)

    def write_firmware_log(self, line: str) -> None:
        self.write_log(line)

    def clear_log(self, title: str) -> None:
        self.query_one("#log-title", Static).update(title)
        log = self.query_one("#log", TextArea)
        log.clear()
        self._log_lines.clear()

    def toggle_log_wrap(self) -> None:
        self.log_wrap = not self.log_wrap
        log = self.query_one("#log", TextArea)
        log.soft_wrap = self.log_wrap
        self.query_one("#log-wrap", Button).label = (
            "Wrap On" if self.log_wrap else "No Wrap"
        )
        self.write_log(f"Log wrapping {'enabled' if self.log_wrap else 'disabled'}.")

    def clear_firmware_log(self) -> None:
        pass

    def refresh_status(self) -> None:
        terminal_size = f"{self.size.width}x{self.size.height}"
        if self.narrow_layout:
            status = (
                f"term={terminal_size} | work={self.state.work_dir} | "
                f"rom={self.state.firmware_index if self.state.firmware_index is not None else 'not selected'}"
            )
        else:
            status = " | ".join(
                [
                    f"Terminal: {terminal_size}",
                    f"Work: {self.state.work_dir}",
                    f"Token: {self.state.token_file.name}",
                    f"Selected ROM: {self.state.firmware_index if self.state.firmware_index is not None else 'not selected'}",
                ]
            )
        self.query_one("#status", Static).update(status)

    def refresh_device_scan(self) -> None:
        self.query_one("#device-state", Static).update(
            "Scanning connected device state..."
        )

        def worker() -> None:
            try:
                devices = scan_connected_devices()
                text = format_device_states(devices)
            except Exception as exc:
                text = f"Device scan failed: {exc}"
            self.call_from_thread(self.set_device_state_text, text)

        threading.Thread(target=worker, daemon=True).start()

    def set_device_state_text(self, text: str) -> None:
        self.query_one("#device-state", Static).update(text)

    def sync_inputs_from_state(self) -> None:
        self.query_one("#model", Input).value = self.state.model
        self.query_one("#sn", Input).value = self.state.sn
        self.query_one("#imei", Input).value = self.state.imei
        self.query_one("#imei2", Input).value = self.state.imei2

    def set_identity_editing(self, editing: bool) -> None:
        self.editing_identity = editing
        fields_disabled = self.busy or not editing
        for input_id in self.identity_input_ids:
            self.query_one(f"#{input_id}", Input).disabled = fields_disabled
        self.query_one("#sudo-password", Input).disabled = self.busy
        self.query_one("#edit-fields", Button).disabled = self.busy or editing
        self.query_one("#save-fields", Button).disabled = self.busy or not editing
        self.query_one("#revert-fields", Button).disabled = self.busy or not editing
        if editing and not self.busy:
            self.query_one("#model", Input).focus()

    def save_settings_from_inputs(self) -> None:
        self.state.model = self.query_one("#model", Input).value.strip()
        self.state.sn = self.query_one("#sn", Input).value.strip()
        self.state.imei = self.query_one("#imei", Input).value.strip()
        self.state.imei2 = self.query_one("#imei2", Input).value.strip()
        save_state(self.state)
        self.refresh_status()

    def save_identity_edits(self) -> None:
        self.save_settings_from_inputs()
        self.set_identity_editing(False)
        self.write_log("Device identity saved.")

    def revert_identity_edits(self) -> None:
        self.sync_inputs_from_state()
        self.set_identity_editing(False)
        self.write_log("Device identity reverted.")

    def focus_device_identity(self) -> None:
        if self.busy:
            return
        self.set_identity_editing(True)
        self.write_log("Device identity unlocked for editing.")

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        always_enabled = {"log-wrap"}
        for button in self.query(Button):
            if button.id in always_enabled:
                continue
            button.disabled = busy
        self.set_identity_editing(self.editing_identity)
        if self.query_one("#firmware-panel").display:
            self.update_firmware_detail()
            self.update_firmware_action_state()

    def run_lrsa_args(self, title: str, args: list[str]) -> None:
        if self.busy:
            return
        self.save_settings_from_inputs()
        self.clear_log(title)
        self.write_log(quote_lrsa_args(args))
        self.set_busy(True)

        def worker() -> None:
            root = logging.getLogger()
            old_handlers = root.handlers[:]
            old_level = root.level
            handler = _TextualLogHandler(self)
            handler.setFormatter(
                logging.Formatter("%(levelname)s:%(name)s:%(message)s")
            )
            root.handlers = [handler]
            root.setLevel(logging.INFO)
            exit_code = 0
            try:
                run_lrsa_cli(args)
            except SystemExit as exc:
                exit_code = int(exc.code) if isinstance(exc.code, int) else 1
            except Exception as exc:
                exit_code = 1
                self.call_from_thread(self.write_log, f"Error: {exc}")
            finally:
                root.handlers = old_handlers
                root.setLevel(old_level)
            self.call_from_thread(self.write_log, f"Exit code: {exit_code}")
            self.call_from_thread(self.set_busy, False)

        threading.Thread(target=worker, daemon=True).start()

    def show_main_workspace(self) -> None:
        self.flash_armed = False
        self.query_one("#firmware-panel").display = False
        self.query_one("#status").display = True

    def show_firmware_workspace(self) -> None:
        self.query_one("#firmware-panel").display = True
        self.query_one("#status").display = False

    def reset_download_progress(self) -> None:
        progress_label = self.query_one("#download-progress-label", Static)
        progress_label.update("")
        progress_label.display = False
        progress = self.query_one("#download-progress", ProgressBar)
        progress.display = False
        progress.update(total=100, progress=0)

    def set_download_progress(
        self, phase: str, completed: int, total: int | None, message: str
    ) -> None:
        label = f"{phase.title()}: {message}"
        if total:
            if phase == "download":
                label = f"{label} ({format_bytes(completed)} / {format_bytes(total)})"
            else:
                label = f"{label} ({completed} / {total})"
        progress_label = self.query_one("#download-progress-label", Static)
        progress_label.display = True
        progress_label.update(label)
        progress = self.query_one("#download-progress", ProgressBar)
        progress.display = True
        if total:
            progress.update(total=total, progress=min(completed, total))
        else:
            progress.update(total=100, progress=0)

    def open_remote_firmware_picker(self, mode: str) -> None:
        if self.busy:
            return
        if mode not in {"download", "extract"}:
            raise ValueError(f"Unsupported firmware task mode: {mode}")
        self.save_settings_from_inputs()
        self.firmware_task_mode = mode
        self.flash_armed = False
        title = "Download ROM" if mode == "download" else "Extract ROM"
        self.clear_log(title)
        self.clear_firmware_log()
        self.reset_download_progress()
        self.query_one("#target-device-title").display = False
        self.query_one("#target-device-table").display = False
        self.query_one("#firmware-title", Static).update(title)
        self.query_one("#download-selected", Button).label = (
            "Download" if mode == "download" else "Extract"
        )
        self.write_log("Looking up available firmware packages...")
        self.set_busy(True)

        def worker() -> None:
            try:
                payload = refresh_resources_impl(
                    self.state,
                    lambda line: self.call_from_thread(self.write_log, line),
                )
                self.call_from_thread(self.populate_firmware_picker, payload)
            except Exception as exc:
                self.call_from_thread(self.write_log, f"Error: {exc}")
                self.call_from_thread(self.set_busy, False)

        threading.Thread(target=worker, daemon=True).start()

    def populate_firmware_picker(self, payload: dict) -> None:
        resources = content_list(payload)
        self.firmware_resources = resources
        self.local_firmware_resources = []
        self.connected_devices = []
        self.selected_device_index = None
        self.firmware_size_cache = {
            index: size
            for index, resource in enumerate(resources)
            if (size := resource_known_size(resource, self.state.work_dir))
        }
        self.selected_firmware_index = None

        table = self.query_one("#firmware-table", DataTable)
        table.clear(columns=False)
        for index, resource in enumerate(resources):
            table.add_row(*firmware_table_row(index, resource), key=str(index))
        detail = self.query_one("#firmware-detail", Static)
        detail.update("Select a ROM package from the list.")
        detail.display = False
        self.query_one("#download-selected", Button).disabled = True
        self.show_firmware_workspace()
        self.set_busy(False)

    def open_local_flash_picker(self) -> None:
        if self.busy:
            return
        self.save_settings_from_inputs()
        self.firmware_task_mode = "flash"
        self.flash_armed = False
        self.clear_log("Flash local firmware")
        self.clear_firmware_log()
        self.reset_download_progress()
        self.write_log("Scanning local firmware and connected devices...")
        self.query_one("#firmware-title", Static).update("Flash firmware")
        self.query_one("#download-selected", Button).label = "Flash"
        self.populate_local_flash_picker()
        self.show_firmware_workspace()

    def populate_local_flash_picker(self) -> None:
        self.firmware_resources = []
        self.local_firmware_resources = local_firmware_candidates(self.state)
        self.connected_devices = scan_connected_devices()
        self.selected_firmware_index = None
        self.selected_device_index = None
        self.firmware_size_cache = {}

        firmware_table = self.query_one("#firmware-table", DataTable)
        firmware_table.clear(columns=False)
        for index, candidate in enumerate(self.local_firmware_resources):
            firmware_table.add_row(
                str(index),
                candidate.get("name") or "(unnamed)",
                candidate.get("source") or "local",
                "EDL / QFIL",
                candidate.get("qfil") or "unknown",
                key=str(index),
            )

        device_table = self.query_one("#target-device-table", DataTable)
        device_table.clear(columns=False)
        for index, device in enumerate(self.connected_devices):
            device_table.add_row(
                str(index),
                str(device.get("transport", "")).upper(),
                device.get("serial") or "",
                device.get("state") or "",
                device.get("detail") or "",
                key=str(index),
            )

        self.query_one("#target-device-title").display = True
        self.query_one("#target-device-table").display = True
        detail = self.query_one("#firmware-detail", Static)
        detail.display = True
        if not self.local_firmware_resources:
            detail.update(
                "No locally extracted firmware found. Run Download ROM, then Extract ROM."
            )
        elif not self.connected_devices:
            detail.update(
                "Select local firmware. No ADB, fastboot, or Qualcomm EDL device detected."
            )
        else:
            detail.update("Select local firmware and target device.")
        self.update_firmware_action_state()

    def selected_firmware_resource(self) -> dict | None:
        if self.selected_firmware_index is None:
            return None
        if self.selected_firmware_index < 0 or self.selected_firmware_index >= len(
            self.firmware_resources
        ):
            return None
        return self.firmware_resources[self.selected_firmware_index]

    def selected_local_firmware(self) -> dict[str, str] | None:
        if self.selected_firmware_index is None:
            return None
        if self.selected_firmware_index < 0 or self.selected_firmware_index >= len(
            self.local_firmware_resources
        ):
            return None
        return self.local_firmware_resources[self.selected_firmware_index]

    def selected_device(self) -> dict[str, str] | None:
        if self.selected_device_index is None:
            return None
        if self.selected_device_index < 0 or self.selected_device_index >= len(
            self.connected_devices
        ):
            return None
        return self.connected_devices[self.selected_device_index]

    def update_firmware_detail(self) -> None:
        if self.firmware_task_mode == "flash":
            candidate = self.selected_local_firmware()
            device = self.selected_device()
            detail = self.query_one("#firmware-detail", Static)
            detail.display = True
            detail.update(local_firmware_detail_text(candidate, device))
            self.update_firmware_action_state()
            return
        index = self.selected_firmware_index
        resource = self.selected_firmware_resource()
        if resource is None:
            self.query_one("#firmware-detail", Static).display = False
            self.query_one("#download-selected", Button).disabled = True
            return
        size = self.firmware_size_cache.get(index) if index is not None else None
        detail = self.query_one("#firmware-detail", Static)
        detail.display = True
        detail.update(
            firmware_detail_text(
                resource,
                index=index,
                download_size=size,
                work_dir=self.state.work_dir,
            )
        )
        rom_url = resource_summary(resource).get("firmwareUrl") if resource else None
        self.query_one("#download-selected", Button).disabled = self.busy or not bool(
            rom_url
        )

    def update_firmware_action_state(self) -> None:
        button = self.query_one("#download-selected", Button)
        if self.firmware_task_mode == "flash":
            button.disabled = (
                self.busy
                or self.selected_local_firmware() is None
                or self.selected_device() is None
            )
            return
        resource = self.selected_firmware_resource()
        rom_url = resource_summary(resource).get("firmwareUrl") if resource else None
        button.disabled = self.busy or not bool(rom_url)

    def set_firmware_size(self, index: int, size: str) -> None:
        self.firmware_size_cache[index] = size
        if self.selected_firmware_index == index:
            self.update_firmware_detail()

    def select_firmware_index(self, index: int) -> None:
        resources_count = (
            len(self.local_firmware_resources)
            if self.firmware_task_mode == "flash"
            else len(self.firmware_resources)
        )
        if index < 0 or index >= resources_count:
            return
        self.flash_armed = False
        self.selected_firmware_index = index
        if self.firmware_task_mode != "flash":
            self.state.firmware_index = index
            save_state(self.state)
            self.refresh_status()
        self.update_firmware_detail()

    def select_device_index(self, index: int) -> None:
        if index < 0 or index >= len(self.connected_devices):
            return
        self.flash_armed = False
        self.selected_device_index = index
        self.update_firmware_detail()

    def run_selected_firmware_task(self) -> None:
        if self.firmware_task_mode == "flash":
            self.run_selected_flash()
            return
        if self.busy or self.selected_firmware_index is None:
            return
        resource = self.selected_firmware_resource()
        if not resource:
            self.write_firmware_log("No ROM selected.")
            return
        if not is_mobile_or_tablet(resource):
            self.write_firmware_log(
                f"Unsupported category for Software Fix flow: {resource.get('category')}"
            )
            return
        self.state.firmware_index = self.selected_firmware_index
        save_state(self.state)
        selected_index = self.selected_firmware_index
        self.clear_firmware_log()
        self.reset_download_progress()
        self.set_busy(True)
        if self.firmware_task_mode == "download":
            self.write_firmware_log("Downloading selected ROM package...")
        else:
            self.write_firmware_log("Extracting selected ROM package...")

        def progress_callback(
            phase: str, completed: int, total: int | None, message: str
        ) -> None:
            self.call_from_thread(
                self.set_download_progress, phase, completed, total, message
            )

        def worker() -> None:
            root = logging.getLogger()
            old_handlers = root.handlers[:]
            old_level = root.level
            handler = _FirmwareLogHandler(self)
            handler.setFormatter(
                logging.Formatter("%(levelname)s:%(name)s:%(message)s")
            )
            root.handlers = [handler]
            root.setLevel(logging.INFO)
            try:
                manifest = prepare_artifacts(
                    resource,
                    self.state.work_dir,
                    download_rom=self.firmware_task_mode == "download",
                    extract_rom=self.firmware_task_mode == "extract",
                    progress_callback=progress_callback,
                )
                manifest_path = self.state.work_dir / "software_fix" / "manifest.json"
                save_json(manifest_path, manifest)
                size = resource_known_size(resource, self.state.work_dir)
                if size and selected_index is not None:
                    self.call_from_thread(self.set_firmware_size, selected_index, size)
                self.call_from_thread(
                    self.write_firmware_log,
                    f"Software Fix manifest saved: {manifest_path}",
                )
                if manifest.get("romDir"):
                    self.call_from_thread(
                        self.write_firmware_log, f"Extracted ROM: {manifest['romDir']}"
                    )
                self.call_from_thread(
                    self.set_download_progress,
                    "complete",
                    1,
                    1,
                    "Download complete"
                    if self.firmware_task_mode == "download"
                    else "Extract complete",
                )
            except Exception as exc:
                self.call_from_thread(self.write_firmware_log, f"Error: {exc}")
                self.call_from_thread(
                    self.set_download_progress, "error", 0, 1, str(exc)
                )
            finally:
                root.handlers = old_handlers
                root.setLevel(old_level)
                self.call_from_thread(self.set_busy, False)

        threading.Thread(target=worker, daemon=True).start()

    def run_selected_flash(self) -> None:
        if self.busy:
            return
        candidate = self.selected_local_firmware()
        device = self.selected_device()
        if not candidate:
            self.write_firmware_log("No local firmware selected.")
            return
        if not device:
            self.write_firmware_log("No target device selected.")
            return
        if device.get("transport") != "edl":
            self.write_firmware_log(
                "Selected device is not Qualcomm EDL/QDLoader. Native qfil flashing requires EDL mode."
            )
            return
        if not candidate.get("startup"):
            self.write_firmware_log(
                "Selected firmware has no Rescue.cmd or Flash.cmd. Run Extract ROM again or choose another package."
            )
            return
        if not self.flash_armed:
            self.flash_armed = True
            self.write_firmware_log(
                "Flash armed. Press Flash again to write partitions."
            )
            return

        self.flash_armed = False
        self.clear_firmware_log()
        self.reset_download_progress()
        self.set_busy(True)
        self.write_firmware_log("Executing native qfil flash from local firmware...")

        def worker() -> None:
            root = logging.getLogger()
            old_handlers = root.handlers[:]
            old_level = root.level
            handler = _FirmwareLogHandler(self)
            handler.setFormatter(
                logging.Formatter("%(levelname)s:%(name)s:%(message)s")
            )
            root.handlers = [handler]
            root.setLevel(logging.INFO)
            try:
                run_local_qfil_flash(candidate, flash=True)
                self.call_from_thread(
                    self.set_download_progress, "complete", 1, 1, "Flash complete"
                )
            except Exception as exc:
                self.call_from_thread(self.write_firmware_log, f"Error: {exc}")
                self.call_from_thread(
                    self.set_download_progress, "error", 0, 1, str(exc)
                )
            finally:
                root.handlers = old_handlers
                root.setLevel(old_level)
                self.call_from_thread(self.set_busy, False)

        threading.Thread(target=worker, daemon=True).start()


    def run_capture(self) -> None:
        if self.busy:
            return
        self.save_settings_from_inputs()
        pwd_input = self.query_one("#sudo-password", Input)
        password = pwd_input.value
        if not password:
            self.write_log("Enter sudo password before Login.")
            pwd_input.focus()
            return
        self.clear_log("Login / Capture")
        self.write_log(quote_command(login_command(self.state)))
        self.set_busy(True)

        def worker() -> None:
            exit_code = 1
            try:
                process = subprocess.Popen(
                    login_command(self.state),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                if process.stdin is not None:
                    process.stdin.write(f"{password}\n")
                    process.stdin.flush()
                    process.stdin.close()
                if process.stdout is not None:
                    for line in process.stdout:
                        self.call_from_thread(self.write_log, line.rstrip("\n"))
                exit_code = process.wait()
            except Exception as exc:
                self.call_from_thread(self.write_log, f"Error: {exc}")
            self.call_from_thread(self.write_log, f"Exit code: {exit_code}")
            self.call_from_thread(self.set_busy, False)

        threading.Thread(target=worker, daemon=True).start()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "edit-fields":
            self.show_main_workspace()
            self.focus_device_identity()
        elif button_id == "save-fields":
            self.show_main_workspace()
            self.save_identity_edits()
        elif button_id == "revert-fields":
            self.show_main_workspace()
            self.revert_identity_edits()
        elif button_id == "log-wrap":
            self.toggle_log_wrap()
        elif button_id == "dry-run":
            self.show_main_workspace()
            self.run_lrsa_args("Dry Run", dry_run_args(self.state))
        elif button_id == "download":
            self.open_remote_firmware_picker("download")
        elif button_id == "extract":
            self.open_remote_firmware_picker("extract")
        elif button_id == "login":
            self.show_main_workspace()
            self.run_capture()
        elif button_id in {"scan-devices", "scan-devices-inline"}:
            self.show_main_workspace()
            self.refresh_device_scan()
        elif button_id == "exit":
            self.exit()
        elif button_id == "flash":
            self.open_local_flash_picker()
        elif button_id == "firmware-refresh":
            if self.firmware_task_mode == "flash":
                self.populate_local_flash_picker()
            else:
                self.open_remote_firmware_picker(self.firmware_task_mode)
        elif button_id == "download-selected":
            self.run_selected_firmware_task()
        elif button_id == "firmware-back":
            self.show_main_workspace()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id not in {"firmware-table", "target-device-table"}:
            return
        try:
            index = int(str(event.row_key.value))
        except (AttributeError, TypeError, ValueError):
            index = event.cursor_row
        if event.data_table.id == "firmware-table":
            self.select_firmware_index(index)
        else:
            self.select_device_index(index)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id not in {"firmware-table", "target-device-table"}:
            return
        try:
            index = int(str(event.row_key.value))
        except (AttributeError, TypeError, ValueError):
            index = event.cursor_row
        if event.data_table.id == "firmware-table":
            self.select_firmware_index(index)
        else:
            self.select_device_index(index)

    def request_flash(self) -> None:
        self.open_local_flash_picker()

    def action_login(self) -> None:
        self.show_main_workspace()
        self.run_capture()

    def action_dry_run(self) -> None:
        self.show_main_workspace()
        self.run_lrsa_args("Dry Run", dry_run_args(self.state))

    def action_download_rom(self) -> None:
        self.open_remote_firmware_picker("download")

    def action_extract_rom(self) -> None:
        self.open_remote_firmware_picker("extract")

    def action_flash(self) -> None:
        self.request_flash()

    def action_scan_devices(self) -> None:
        self.show_main_workspace()
        self.refresh_device_scan()


    def action_toggle_log_wrap(self) -> None:
        self.toggle_log_wrap()


def main() -> None:
    state = load_state()
    if App is not None and sys.stdin.isatty() and sys.stdout.isatty():
        LRSATextualApp(state).run()
        return
    if Application is None:
        fallback_main(state)
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        get_logger(__name__).info(
            "lrsa-menu needs an interactive terminal for arrow-key navigation."
        )
        get_logger(__name__).info("Current settings:")
        get_logger(__name__).info(status_text(state))
        return

    while True:
        choice = choose_item("LRSA Python", menu_text(state), main_items(), "dry_run")
        if choice is None or choice == "exit":
            save_state(state)
            return
        handle_choice(choice, state)


if __name__ == "__main__":
    main()
