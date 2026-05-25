"""Arrow-key interactive TUI for the LRSA CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from lrsa.logging import get_logger
from lrsa.process import command_text

from .api.client import LRSAClient
from .api.firmware import response_payload
from .api.resources import content_list, is_success_payload, resource_summary
from .auth import extract_token_from_file, save_json
from .config import DEFAULT_EDL, DEFAULT_MODEL, DEFAULT_SN, DEFAULT_WORK_DIR
from .device.preflight import find_qualcomm_edl_devices, format_usb_devices
from .menu_constants import (
    BORDER,
    MIN_UI_WIDTH,
    PATH_FIELDS,
    STATE_FILE,
    STATE_VERSION,
    UI_WIDTH,
)

try:
    from prompt_toolkit.application import Application
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import HSplit, Layout
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.layout.containers import Window
    from prompt_toolkit.shortcuts import input_dialog, message_dialog
    from prompt_toolkit.styles import Style
except ImportError:  # pragma: no cover - exercised only without optional UI deps.
    Application = None
    FormattedTextControl = None
    HSplit = None
    KeyBindings = None
    Layout = None
    Window = None
    input_dialog = None
    message_dialog = None
    Style = None


@dataclass
class MenuState:
    token_file: Path = DEFAULT_WORK_DIR / "capture" / "login_session.json"
    work_dir: Path = DEFAULT_WORK_DIR
    model: str = DEFAULT_MODEL
    sn: str = DEFAULT_SN
    imei: str = ""
    imei2: str = ""
    edl: Path = DEFAULT_EDL
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


def state_to_json(state: MenuState) -> dict[str, str | int]:
    return {
        "version": STATE_VERSION,
        "token_file": str(state.token_file),
        "work_dir": str(state.work_dir),
        "model": state.model,
        "sn": state.sn,
        "imei": state.imei,
        "imei2": state.imei2,
        "edl": str(state.edl),
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
            f"Firmware:   {state.firmware_index if state.firmware_index is not None else 'auto'}",
            f"edl.py:     {state.edl}",
            f"Image dir:  {path_or_auto(state.image_dir)}",
        ]
    )


def menu_text(state: MenuState) -> str:
    return (
        f"SN: {value_or_unset(state.sn)}    IMEI: {value_or_unset(state.imei)}\n"
        f"Model: {value_or_unset(state.model)}\n"
        f"Firmware: {state.firmware_index if state.firmware_index is not None else 'auto'}\n"
        f"Token: {state.token_file}\n"
        f"Work: {state.work_dir}\n"
        f"ROM/tool cache: {state.work_dir / 'software_fix'}"
    )


def cli_base(state: MenuState) -> list[str]:
    command = [
        sys.executable,
        "-u",
        "-m",
        "lrsa.cli",
        "--token-file",
        str(state.token_file),
        "--work-dir",
        str(state.work_dir),
        "--edl",
        str(state.edl),
    ]
    if state.model:
        command.extend(["--model", state.model])
    if state.sn:
        command.extend(["--sn", state.sn])
    if state.imei:
        command.extend(["--imei", state.imei])
    if state.imei2:
        command.extend(["--imei2", state.imei2])
    if state.image_dir:
        command.extend(["--image-dir", state.image_dir])
    if state.firmware_index is not None:
        command.extend(["--firmware-index", str(state.firmware_index)])
    return command


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


def dry_run_command(state: MenuState) -> list[str]:
    command = cli_base(state)
    command.extend(["--login", "none"])
    return command


def prepare_command(state: MenuState) -> list[str]:
    command = cli_base(state)
    command.extend(["--login", "none", "--download", "--extract"])
    return command


def flash_command(state: MenuState) -> list[str]:
    command = cli_base(state)
    command.extend(["--login", "none", "--download", "--extract", "--flash"])
    return command


def verify_boot_chain_command(state: MenuState) -> list[str]:
    command = cli_base(state)
    command.extend(["--login", "none", "--verify-boot-chain"])
    return command


def ui_style():
    if Style is None:
        return None
    return Style.from_dict(
        {
            "dialog": "bg:#111111",
            "root": "bg:#111111 #e6e6e6",
            "screen": "bg:#111111 #e6e6e6",
            "dialog frame-label": "bg:#111111 #ffffff",
            "dialog.body": "bg:#111111 #e6e6e6",
            "dialog shadow": "bg:#000000",
            "button": "bg:#303030 #e6e6e6",
            "button.focused": "bg:#ffffff #111111",
            "radio": "#bbbbbb",
            "radio-checked": "#ffffff bold",
            "text-area": "bg:#202020 #ffffff",
            "title": "bg:#111111 #ffffff bold",
            "normal": "bg:#111111 #e6e6e6",
            "selected": "bg:#263238 #ffffff bold",
            "selected-detail": "bg:#151f27 #b8d7ff",
            "muted": "bg:#111111 #9e9e9e",
            "footer": "bg:#111111 #8a8f98",
            "border": "bg:#111111 #5f6872",
            "section": "bg:#111111 #cfd8dc bold",
            "shortcut": "bg:#111111 #8ab4f8",
            "progress": "bg:#111111 #7dd3fc bold",
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
        text_lines = text.splitlines()
        content_rows = 10 + len(text_lines) + len(items)
        top_padding = max(
            0, (shutil.get_terminal_size((100, 30)).lines - content_rows) // 2
        )
        selected_item = items[selected]

        result = [("class:screen", "\n" * top_padding)]
        result.append(
            ("class:border", box_rule(width=width, margin=margin, kind="top"))
        )
        result.append(
            ("class:title", box_line(f" {title} ", width=width, margin=margin))
        )
        result.append(("class:border", box_rule(width=width, margin=margin)))
        for line in text.splitlines():
            result.append(("class:muted", box_line(line, width=width, margin=margin)))
        result.append(("class:border", box_rule(width=width, margin=margin)))
        result.append(
            ("class:section", box_line(" Actions", width=width, margin=margin))
        )
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
    if message_dialog is None:
        get_logger(__name__).info(f"\n{title}\n{text}\n")
        return
    message_dialog(title=title, text=text, ok_text="Back", style=ui_style()).run()


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
        top_padding = max(0, (shutil.get_terminal_size((100, 30)).lines - rows) // 2)
        input_value = typed["value"] or ""
        cursor = " " if input_value else "_"
        result_fragments = [("class:screen", "\n" * top_padding)]
        result_fragments.append(
            ("class:border", box_rule(width=width, margin=margin, kind="top"))
        )
        result_fragments.append(
            (
                "class:title",
                box_line(" Flash Confirmation ", width=width, margin=margin),
            )
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


def run_command(
    command: list[str], *, flash: bool = False, stdin_text: str | None = None
) -> int:
    if flash:
        if not confirm_flash(command):
            return 0

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
    return run_command(prepare_command(state))


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
        if choice in {None, "back"}:
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
            "Firmware Packages",
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
        "Firmware Packages",
        "Select a package to use for download/extract/flash.",
        items,
        default,
    )
    if choice in {None, "back"}:
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
    if not firmware_flow(state, refresh=True):
        return 0
    return run_command(prepare_command(state))


def flash_flow(state: MenuState) -> int:
    if not require_lookup_settings(state):
        return 0

    payload = refresh_resources(state)
    if not payload or not select_firmware_from_payload(state, payload):
        return 0

    resources = content_list(payload)
    selected = resources[state.firmware_index or 0] if resources else {}
    summary = resource_summary(selected)
    devices = find_qualcomm_edl_devices()
    device_line = (
        format_usb_devices(devices)
        if devices
        else "No Qualcomm 9008/QDLoader device detected."
    )
    lookup_line = (
        f"IMEI: {state.imei}" if state.imei else f"Model/SN: {state.model} / {state.sn}"
    )
    firmware = summary.get("firmwareName") or "(unnamed firmware)"
    match = summary.get("romMatchId") or "(no match id)"
    model = (
        summary.get("modelName") or summary.get("realModelName") or "(unknown model)"
    )

    choice = choose_item(
        "Flash Review",
        "\n".join(
            [
                lookup_line,
                f"Selected ROM: {firmware}",
                f"Matched device: {model} / {match}",
                f"EDL device: {device_line}",
                "",
                "Next step runs Software Fix native flow with the selected ROM.",
            ]
        ),
        [
            MenuItem(
                "flash",
                "Continue to FLASH confirmation",
                "Type FLASH on the next screen to start writing.",
            ),
            MenuItem("back", "Back", "Return without flashing."),
        ],
        "back",
    )
    if choice != "flash":
        return 0
    return run_command(flash_command(state), flash=True)


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
        SettingItem("edl", "edl.py", lambda s: str(s.edl), set_path("edl")),
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
            "firmware",
            "Firmware packages",
            "Refresh and select an available firmware package for this device.",
        ),
        MenuItem(
            "dry_run",
            "Dry-run matched rescue flow",
            "Queries Software Fix metadata and prints the native QFIL plan.",
        ),
        MenuItem(
            "prepare",
            "Download + extract selected ROM",
            "Lists packages, then downloads/extracts the selected official ROM.",
        ),
        MenuItem(
            "verify_boot",
            "Verify boot chain readback",
            "Read-only EDL check for ABL/XBL/UEFI partitions against the ROM.",
        ),
        MenuItem(
            "flash",
            "Flash native qfil backend",
            "Runs the Software Fix flow through the native qfil package.",
        ),
        MenuItem(
            "settings", "Settings", "Edit token path, work dir, edl.py, and image dir."
        ),
        MenuItem("status", "Status", "Show current LRSA configuration."),
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
        if choice in {None, "exit", "quit"}:
            return
        handle_choice(choice, state)


def handle_choice(choice: str, state: MenuState) -> None:
    if choice == "login":
        login_flow(state)
    elif choice == "device":
        device_flow(state)
    elif choice == "firmware":
        firmware_flow(state, refresh=True)
    elif choice == "dry_run":
        if require_lookup_settings(state):
            run_command(dry_run_command(state))
    elif choice == "prepare":
        download_flow(state)
    elif choice == "verify_boot":
        run_command(verify_boot_chain_command(state))
    elif choice == "flash":
        flash_flow(state)
    elif choice == "phone":
        phone_flow(state)
    elif choice == "settings":
        configure(state)
    elif choice == "status":
        show_message("Current Settings", status_text(state))


def main() -> None:
    state = load_state()
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
        if choice in {None, "exit"}:
            save_state(state)
            return
        handle_choice(choice, state)


if __name__ == "__main__":
    main()
