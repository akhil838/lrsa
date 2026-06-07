"""Cross-platform PySide6 GUI for LRSA."""

from __future__ import annotations

import json
import os
import platform
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, QTimer, Qt, Signal, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QHeaderView,
    QPlainTextEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from lrsa.api.resources import (
    api_payload,
    catalog_strings,
    content_list,
    is_success_payload,
    resource_summary,
)
from lrsa.auth import (
    delete_session,
    load_session,
    logout_session,
    save_json,
    session_path,
)
from lrsa.auth.login import guest_login
from lrsa.logging import configure_logging, get_logger
from lrsa.config import DEFAULT_SN, DEFAULT_WORK_DIR
from lrsa.device.preflight import scan_connected_devices
from lrsa.flash.software_fix_flow import prepare_artifacts

DEVICE_COLUMNS = ("Transport", "Serial", "State", "Details")
RESOURCE_COLUMNS = ("ROM name",)
ARTIFACT_COLUMNS = ("Kind", "Name", "Downloaded", "Extracted", "MD5")
CATEGORY_OPTIONS = (
    ("Tablet", "tablet"),
    ("Phone", "phone"),
    ("Motorola / Smart", "smart"),
)
GUI_STATE_PATH = DEFAULT_WORK_DIR / "gui_state.json"
PAGE_TITLES = ("Devices", "Firmware", "ROM Install", "Logs")
PROGRESS_BAR_MAX = 10_000
SIDEBAR_WIDTH = 238
FORM_LABEL_WIDTH = 112
MIN_TABLE_HEIGHT = 180
LAYOUT_STATE_VERSION = 2


ROM_FILE_FILTER = (
    "ROM startup (Rescue.cmd);;ROM archives (*.zip *.tgz *.tar.gz);;All files (*)"
)


LIGHT_APP_STYLE = """
QMainWindow, QWidget {
    background: #f6f7fb;
    color: #111827;
    font-size: 13px;
}
QLabel {
    line-height: 140%;
}
QLabel#AppTitle {
    color: #111827;
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 0.4px;
}
QLabel#AppSubtitle, QLabel#FormLabel {
    color: #6b7280;
}
QLabel#FormLabel {
    font-weight: 600;
}
QGroupBox {
    background: #ffffff;
    border: 1px solid #d9dee8;
    border-radius: 12px;
    margin-top: 14px;
    padding: 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #374151;
    font-weight: 700;
}
QPushButton {
    background: #2563eb;
    color: white;
    border: 0;
    border-radius: 8px;
    padding: 9px 13px;
    min-height: 18px;
    font-weight: 700;
}
QPushButton:hover {
    background: #1d4ed8;
}
QPushButton:disabled {
    background: #9ca3af;
}
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QTableWidget {
    background: white;
    color: #111827;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 6px;
    selection-background-color: #bfdbfe;
}
QHeaderView::section {
    background: #eef2f7;
    color: #111827;
    border: 0;
    padding: 7px;
    font-weight: 700;
}
QWidget#SidebarPanel {
    background: #ffffff;
    border: 1px solid #d9dee8;
    border-radius: 12px;
}
QListWidget#Sidebar {
    background: #ffffff;
    border: 1px solid #d9dee8;
    border-radius: 10px;
    padding: 6px;
}
QListWidget#Sidebar::item {
    border-radius: 8px;
    padding: 11px 10px;
    margin: 3px;
}
QListWidget#Sidebar::item:selected {
    background: #2563eb;
    color: white;
}
"""

DARK_APP_STYLE = """
QMainWindow, QWidget {
    background: #0f172a;
    color: #e5e7eb;
    font-size: 13px;
}
QLabel {
    line-height: 140%;
}
QLabel#AppTitle {
    color: #f8fafc;
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 0.4px;
}
QLabel#AppSubtitle, QLabel#FormLabel {
    color: #94a3b8;
}
QLabel#FormLabel {
    font-weight: 600;
}
QGroupBox {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    margin-top: 14px;
    padding: 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #cbd5e1;
    font-weight: 700;
}
QPushButton {
    background: #3b82f6;
    color: white;
    border: 0;
    border-radius: 8px;
    padding: 9px 13px;
    min-height: 18px;
    font-weight: 700;
}
QPushButton:hover {
    background: #2563eb;
}
QPushButton:disabled {
    background: #475569;
    color: #94a3b8;
}
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QTableWidget {
    background: #020617;
    color: #e5e7eb;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 6px;
    selection-background-color: #1d4ed8;
}
QHeaderView::section {
    background: #1e293b;
    color: #e5e7eb;
    border: 0;
    padding: 7px;
    font-weight: 700;
}
QWidget#SidebarPanel {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
}
QListWidget#Sidebar {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 6px;
}
QListWidget#Sidebar::item {
    border-radius: 8px;
    padding: 11px 10px;
    margin: 3px;
}
QListWidget#Sidebar::item:selected {
    background: #3b82f6;
    color: white;
}
"""


def _session_token(session: dict[str, Any] | None) -> str | None:
    if not session:
        return None
    token = session.get("token")
    return token if isinstance(token, str) and token else None


def make_form_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("FormLabel")
    label.setMinimumWidth(FORM_LABEL_WIDTH)
    label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return label


def configure_grid(layout: QGridLayout) -> None:
    layout.setContentsMargins(12, 14, 12, 12)
    layout.setHorizontalSpacing(12)
    layout.setVerticalSpacing(10)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 1)


def configure_table(table: QTableWidget, *, min_height: int = MIN_TABLE_HEIGHT) -> None:
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.setMinimumHeight(min_height)
    table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(30)
    header = table.horizontalHeader()
    header.setHighlightSections(False)
    header.setStretchLastSection(True)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)


class DevicePoller(QThread):
    devices_changed = Signal(list)
    scan_failed = Signal(str)

    def __init__(self, interval_seconds: float = 1.0) -> None:
        super().__init__()
        self._interval_seconds = interval_seconds
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        last_signature: tuple[tuple[str, str, str, str], ...] | None = None
        while self._running:
            try:
                devices = scan_connected_devices()
                signature = tuple(
                    (
                        str(device.get("transport", "")),
                        str(device.get("serial", "")),
                        str(device.get("state", "")),
                        str(device.get("detail", "")),
                    )
                    for device in devices
                )
                if signature != last_signature:
                    last_signature = signature
                    self.devices_changed.emit(devices)
            except Exception as exc:
                self.scan_failed.emit(str(exc))
            deadline = time.monotonic() + self._interval_seconds
            while self._running and time.monotonic() < deadline:
                time.sleep(0.05)


class GuestLoginWorker(QThread):
    output = Signal(str)
    failed = Signal(str)
    finished_with_session = Signal(dict)

    def __init__(self, client_uuid: str | None) -> None:
        super().__init__()
        self._client_uuid = client_uuid

    def run(self) -> None:
        try:
            self.output.emit("Starting guest login...")
            self.finished_with_session.emit(guest_login(client_uuid=self._client_uuid))
        except Exception as exc:
            self.failed.emit(str(exc))


class LogoutWorker(QThread):
    finished_with_results = Signal(list)

    def __init__(self, session: dict[str, Any] | None) -> None:
        super().__init__()
        self._session = session

    def run(self) -> None:
        self.finished_with_results.emit(logout_session(self._session))


class CatalogBrowseWorker(QThread):
    output = Signal(str)
    failed = Signal(str)
    finished_with_catalog = Signal(str, list, object)

    def __init__(
        self,
        *,
        session: dict[str, Any] | None,
        category: str,
        action: str,
        market_name: str,
    ) -> None:
        super().__init__()
        self._session = session
        self._category = category
        self._action = action
        self._market_name = market_name

    def run(self) -> None:
        try:
            from lrsa.api.client import LRSAClient

            client_uuid = None
            if self._session and self._session.get("client_uuid"):
                client_uuid = str(self._session["client_uuid"])
            client = LRSAClient(
                client_uuid=client_uuid, token=_session_token(self._session)
            )

            if self._action == "markets":
                self.output.emit(f"Loading catalog markets for {self._category}...")
                if self._category == "smart":
                    result = client.get_smart_market_names()
                else:
                    result = client.get_rescue_market_names(self._category)
                keys = ("marketName", "market", "name")
            elif self._action == "models":
                if self._market_name:
                    self.output.emit(
                        f"Loading catalog models for {self._category} / {self._market_name}..."
                    )
                    result = client.get_models_by_market_name(
                        self._market_name, self._category
                    )
                else:
                    self.output.emit(
                        f"Loading full catalog model list for {self._category}..."
                    )
                    result = client.get_rescue_model_names(self._category)
                keys = ("modelName", "realModelName", "name", "model")
            else:
                raise RuntimeError(f"Unknown catalog action: {self._action}")

            api = api_payload(result)
            if not is_success_payload(api):
                code = api.get("code") if isinstance(api, dict) else None
                desc = api.get("desc") if isinstance(api, dict) else None
                raise RuntimeError(
                    f"Catalog API failed: code={code or '(none)'} desc={desc or '(none)'}"
                )
            self.finished_with_catalog.emit(
                self._action, catalog_strings(api, keys), api
            )
        except Exception as exc:
            self.failed.emit(str(exc))


class FirmwareLookupWorker(QThread):
    output = Signal(str)
    failed = Signal(str)
    finished_with_resources = Signal(list, object, object)

    def __init__(
        self,
        *,
        session: dict[str, Any] | None,
        allow_guest: bool,
        model: str,
        sn: str,
        imei: str,
        imei2: str,
        work_dir: Path,
    ) -> None:
        super().__init__()
        self._session = session
        self._allow_guest = allow_guest
        self._model = model
        self._sn = sn
        self._imei = imei
        self._imei2 = imei2
        self._work_dir = work_dir

    def _lookup(self, client: Any) -> dict[str, Any]:
        if self._imei:
            self.output.emit(f"Querying rescue ROM by IMEI: {self._imei}")
            return client.get_resources_by_imei(self._imei, self._imei2 or None)
        if not self._model or not self._sn:
            raise RuntimeError("SN lookup requires Model and SN, or use IMEI lookup.")
        self.output.emit(
            f"Querying rescue ROM by SN: model={self._model}, sn={self._sn}"
        )
        return client.get_rescue_rom(self._model, self._sn)

    def _bootstrap_guest(self, client_uuid: str | None) -> dict[str, Any]:
        self.output.emit("Bootstrapping guest session...")
        return guest_login(client_uuid=client_uuid)

    def run(self) -> None:
        try:
            from lrsa.api.client import LRSAClient
            from lrsa.api.firmware import response_payload

            active_session = (
                dict(self._session) if isinstance(self._session, dict) else None
            )
            client_uuid = None
            if active_session and active_session.get("client_uuid"):
                client_uuid = str(active_session["client_uuid"])
            token = _session_token(active_session)

            if not token and self._allow_guest:
                active_session = self._bootstrap_guest(client_uuid)
                client_uuid = str(active_session.get("client_uuid") or "") or None
                token = _session_token(active_session)

            client = LRSAClient(client_uuid=client_uuid, token=token)
            result = self._lookup(client)
            api = api_payload(result)
            if (
                not is_success_payload(api)
                and active_session
                and active_session.get("method") == "guest"
            ):
                self.output.emit("Guest session expired or rejected; renewing once...")
                active_session = self._bootstrap_guest(client.client_uuid)
                client = LRSAClient(
                    client_uuid=str(active_session.get("client_uuid") or "") or None,
                    token=_session_token(active_session),
                )
                result = self._lookup(client)
                api = api_payload(result)

            payload = response_payload(result)
            save_json(self._work_dir / "rescue_rom_response.json", payload)
            if not is_success_payload(api):
                code = api.get("code") if isinstance(api, dict) else None
                desc = api.get("desc") if isinstance(api, dict) else None
                raise RuntimeError(
                    f"LRSA resource lookup failed: code={code or '(none)'} desc={desc or '(none)'}"
                )
            resources = content_list(api)
            if not resources:
                raise RuntimeError("LRSA returned success but no firmware resources.")
            if active_session is not None and client.token:
                active_session["token"] = client.token
            self.finished_with_resources.emit(resources, payload, active_session)
        except Exception as exc:
            self.failed.emit(str(exc))


class PrepareWorker(QThread):
    progress = Signal(str, int, object, str)
    failed = Signal(str)
    finished_with_manifest = Signal(dict)

    def __init__(
        self,
        *,
        resource: dict[str, Any],
        work_dir: Path,
        downloads_dir: Path,
        download_resources: bool,
        extract_resources: bool,
        decrypt_rom: bool,
    ) -> None:
        super().__init__()
        self._resource = resource
        self._work_dir = work_dir
        self._downloads_dir = downloads_dir
        self._download_resources = download_resources
        self._extract_resources = extract_resources
        self._decrypt_rom = decrypt_rom

    def run(self) -> None:
        try:

            def progress_callback(
                stage: str, current: int, total: int | None, label: str
            ) -> None:
                self.progress.emit(stage, current, total, label)

            manifest = prepare_artifacts(
                self._resource,
                self._work_dir,
                download_rom=self._download_resources,
                extract_rom=self._extract_resources,
                decrypt_rom=self._decrypt_rom,
                downloads_dir=self._downloads_dir,
                progress_callback=progress_callback,
            )
            save_json(self._work_dir / "software_fix" / "manifest.json", manifest)
            self.finished_with_manifest.emit(manifest)
        except Exception as exc:
            self.failed.emit(str(exc))


class CommandWorker(QThread):
    output = Signal(str)
    finished_with_code = Signal(int)

    def __init__(self, command: list[str]) -> None:
        super().__init__()
        self._command = command
        self._process: subprocess.Popen[str] | None = None

    def stop(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def run(self) -> None:
        self.output.emit("$ " + " ".join(self._command))
        try:
            self._process = subprocess.Popen(
                self._command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.output.emit(f"Failed to start command: {exc}")
            self.finished_with_code.emit(1)
            return

        assert self._process.stdout is not None
        for line in self._process.stdout:
            self.output.emit(line.rstrip("\n"))
        self.finished_with_code.emit(self._process.wait())


class CaptureLoginWorker(QThread):
    output = Signal(str)
    browser_url = Signal(str)
    finished_with_code = Signal(int)

    def __init__(
        self,
        command: list[str],
        *,
        url_file: Path,
        ready_file: Path,
        needs_admin: bool,
    ) -> None:
        super().__init__()
        self._command = command
        self._url_file = url_file
        self._ready_file = ready_file
        self._needs_admin = needs_admin
        self._process: subprocess.Popen[str] | None = None

    def stop(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def _launch_command(self) -> list[str]:
        if self._needs_admin and sys.platform == "darwin":
            shell_command = " ".join(shlex.quote(part) for part in self._command)
            script = (
                f"do shell script {json.dumps(shell_command)} "
                "with administrator privileges"
            )
            return ["osascript", "-e", script]
        return self._command

    @staticmethod
    def _read_url(path: Path) -> str | None:
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return raw
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            for key in ("auth_url", "login_url", "url"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    def _capture_url(self) -> str | None:
        return self._read_url(self._ready_file) or self._read_url(self._url_file)

    def run(self) -> None:
        launch_command = self._launch_command()
        self.output.emit("$ " + " ".join(shlex.quote(part) for part in launch_command))
        if launch_command[0] == "osascript":
            self.output.emit(
                "macOS will ask for an administrator password so LRSA can bind "
                "the Lenovo callback on port 443 and restore /etc/hosts afterwards."
            )
        try:
            self._process = subprocess.Popen(
                launch_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except Exception as exc:
            self.output.emit(f"Failed to start capture login: {exc}")
            self.finished_with_code.emit(1)
            return

        opened_url = False
        while self._process.poll() is None:
            if not opened_url:
                url = self._capture_url()
                if url:
                    opened_url = True
                    self.output.emit("Opening Lenovo ID login portal...")
                    self.browser_url.emit(url)
            time.sleep(0.25)

        if not opened_url:
            url = self._capture_url()
            if url:
                self.output.emit("Opening Lenovo ID login portal...")
                self.browser_url.emit(url)

        stdout = ""
        if self._process.stdout is not None:
            stdout = self._process.stdout.read()
        for line in stdout.splitlines():
            self.output.emit(line)
        self.finished_with_code.emit(self._process.returncode or 0)


class LoginSessionWatcher(QThread):
    session_file_ready = Signal(str)
    failed = Signal(str)

    def __init__(
        self, session_file: Path, *, started_at: float, timeout_seconds: int = 600
    ) -> None:
        super().__init__()
        self._session_file = session_file
        self._started_at = started_at
        self._timeout_seconds = timeout_seconds
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        deadline = time.monotonic() + self._timeout_seconds
        while self._running and time.monotonic() < deadline:
            try:
                if (
                    self._session_file.exists()
                    and self._session_file.stat().st_mtime >= self._started_at
                ):
                    self.session_file_ready.emit(str(self._session_file))
                    return
            except OSError:
                pass
            time.sleep(0.5)
        if self._running:
            self.failed.emit("Timed out waiting for Lenovo ID login to finish.")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LRSA")
        self._gui_state = self._load_gui_state()
        self._dark_mode = bool(self._gui_state.get("dark_mode"))
        self.setMinimumSize(760, 560)
        self._resize_to_available_screen()
        self._devices: list[dict[str, Any]] = []
        self._resources: list[dict[str, Any]] = []
        self._current_session: dict[str, Any] | None = None
        self._selected_rom_base: Path | None = None
        self._selected_startup: Path | None = None
        self._session_worker: QThread | None = None
        self._catalog_worker: CatalogBrowseWorker | None = None
        self._firmware_worker: FirmwareLookupWorker | None = None
        self._prepare_worker: PrepareWorker | None = None
        self._command_worker: CommandWorker | None = None
        self._capture_worker: CaptureLoginWorker | None = None
        self._capture_watcher: LoginSessionWatcher | None = None
        self._capture_started_at = 0.0
        self._catalog_markets: list[str] = []
        self._catalog_models: list[str] = []
        self.work_dir_input = QLineEdit(
            str(self._gui_state.get("work_dir") or DEFAULT_WORK_DIR)
        )
        self.work_dir_input.setVisible(False)

        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(0)
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(14)
        content_layout.addWidget(self._build_side_panel())
        self.page_stack = QStackedWidget()
        for title, page in (
            ("Devices", self._build_devices_tab()),
            ("Firmware", self._build_firmware_tab()),
            ("ROM Install", self._build_rom_tab()),
            ("Logs", self._build_logs_tab()),
        ):
            self._add_sidebar_page(title, page)
        self.sidebar.currentRowChanged.connect(self._switch_page)
        content_layout.addWidget(self.page_stack, 1)
        main_layout.addLayout(content_layout, 1)
        self.setCentralWidget(central)

        saved_page = str(self._gui_state.get("current_page") or PAGE_TITLES[0])
        page_index = PAGE_TITLES.index(saved_page) if saved_page in PAGE_TITLES else 0
        self.sidebar.setCurrentRow(page_index)
        if self._dark_mode:
            self.dark_mode_toggle.setChecked(True)
            self._set_dark_mode(True)

        self._device_poller = DevicePoller()
        self._device_poller.devices_changed.connect(self._set_devices)
        self._device_poller.scan_failed.connect(self._append_log)
        self._device_poller.start()

        self._load_saved_session_if_present()
        self._session_status_timer = QTimer(self)
        self._session_status_timer.timeout.connect(self._refresh_session_ui)
        self._session_status_timer.start(60_000)
        QTimer.singleShot(0, self._show_initial_login_dialog)

    def _resize_to_available_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1240, 820)
            return
        available = screen.availableGeometry()
        margin = 48 if available.width() > 1000 and available.height() > 760 else 20
        width = min(1280, max(760, available.width() - margin))
        height = min(860, max(560, available.height() - margin))
        saved_window = self._gui_state.get("window")
        if self._gui_state.get("layout_version") == LAYOUT_STATE_VERSION and isinstance(
            saved_window, dict
        ):
            saved_width = saved_window.get("width")
            saved_height = saved_window.get("height")
            if isinstance(saved_width, int):
                width = min(width, max(760, saved_width))
            if isinstance(saved_height, int):
                height = min(height, max(560, saved_height))
        self.resize(width, height)
        self.move(
            available.x() + max(0, (available.width() - width) // 2),
            available.y() + max(0, (available.height() - height) // 2),
        )

    def _load_gui_state(self) -> dict[str, Any]:
        try:
            with open(GUI_STATE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            get_logger(__name__).warning("Failed to load GUI state: %s", exc)
            return {}
        return data if isinstance(data, dict) else {}

    def _save_gui_state(self) -> None:
        self._gui_state["dark_mode"] = self._dark_mode
        self._gui_state["work_dir"] = str(self._work_dir())
        try:
            save_json(GUI_STATE_PATH, self._gui_state)
        except OSError as exc:
            get_logger(__name__).warning("Failed to save GUI state: %s", exc)

    def _save_form_state(self) -> None:
        if not hasattr(self, "sn_input"):
            return
        self._gui_state["firmware"] = {
            "sn": self.sn_input.text(),
            "imei": self.imei_input.text(),
            "imei2": self.imei2_input.text(),
            "catalog_category": self._catalog_category_value()
            if hasattr(self, "catalog_category")
            else "tablet",
            "catalog_market": str(self.catalog_market.currentData() or "")
            if hasattr(self, "catalog_market")
            else "",
            "catalog_model": str(self.catalog_model.currentData() or "")
            if hasattr(self, "catalog_model")
            else "",
            "guest_fallback": self.guest_fallback_check.isChecked()
            if hasattr(self, "guest_fallback_check")
            else True,
            "download_resources": self.download_check.isChecked()
            if hasattr(self, "download_check")
            else False,
            "extract_resources": self.extract_check.isChecked()
            if hasattr(self, "extract_check")
            else True,
            "decrypt_rom": self.decrypt_check.isChecked()
            if hasattr(self, "decrypt_check")
            else True,
            "downloads_dir": self.download_dir_input.text()
            if hasattr(self, "download_dir_input")
            else str(self._work_dir() / "software_fix" / "downloads"),
        }
        if self._selected_rom_base is not None:
            self._gui_state["selected_rom_base"] = str(self._selected_rom_base)
        self._save_gui_state()

    def _add_sidebar_page(self, _title: str, page: QWidget) -> None:
        scroll = QScrollArea()
        scroll.setObjectName(f"{_title.replace(' ', '')}Page")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(page)
        self.page_stack.addWidget(scroll)

    def _switch_page(self, index: int) -> None:
        if index < 0:
            return
        self.page_stack.setCurrentIndex(index)
        if index < len(PAGE_TITLES):
            self._gui_state["current_page"] = PAGE_TITLES[index]
            self._save_gui_state()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        size = self.size()
        self._gui_state["window"] = {"width": size.width(), "height": size.height()}
        self._gui_state["layout_version"] = LAYOUT_STATE_VERSION
        self._save_form_state()
        for worker in (
            self._command_worker,
            self._capture_worker,
            self._capture_watcher,
            self._catalog_worker,
            self._firmware_worker,
            self._prepare_worker,
            self._session_worker,
        ):
            if worker is not None and worker.isRunning():
                if isinstance(
                    worker, (CommandWorker, CaptureLoginWorker, LoginSessionWatcher)
                ):
                    worker.stop()
                worker.wait(2000)
        self._device_poller.stop()
        self._device_poller.wait(2000)
        super().closeEvent(event)

    def _build_side_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("SidebarPanel")
        panel.setFixedWidth(SIDEBAR_WIDTH)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 16, 14, 14)
        layout.setSpacing(10)

        title = QLabel("LRSA")
        title.setObjectName("AppTitle")
        subtitle = QLabel("Lenovo Rescue and Smart Assistant")
        subtitle.setObjectName("AppSubtitle")
        subtitle.setWordWrap(True)
        self.session_status = QLabel("Checking for a saved login...")
        self.session_status.setWordWrap(True)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        for title_text in PAGE_TITLES:
            self.sidebar.addItem(QListWidgetItem(title_text))

        self.login_button = QPushButton("Login with Lenovo ID")
        self.login_button.clicked.connect(self._start_capture_login)
        self.guest_login_button = QPushButton("Continue as guest")
        self.guest_login_button.clicked.connect(self._start_guest_login)
        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self._logout_active_session)
        self.dark_mode_toggle = QCheckBox("Dark mode")
        self.dark_mode_toggle.toggled.connect(self._set_dark_mode)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addWidget(self.sidebar, 1)
        layout.addSpacing(8)
        layout.addWidget(self.session_status)
        layout.addWidget(self.login_button)
        layout.addWidget(self.guest_login_button)
        layout.addWidget(self.logout_button)
        layout.addWidget(self.dark_mode_toggle)
        return panel

    def _set_dark_mode(self, enabled: bool) -> None:
        self._dark_mode = enabled
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setStyleSheet(DARK_APP_STYLE if enabled else LIGHT_APP_STYLE)
        self._save_gui_state()

    def _show_initial_login_dialog(self) -> None:
        if self._current_session is not None:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Login to LRSA")
        dialog.setModal(True)
        layout = QVBoxLayout(dialog)
        message = QLabel(
            "Sign in with Lenovo ID to browse Lenovo/Motorola catalogs and download ROMs. "
            "Guest mode may have limited access."
        )
        message.setWordWrap(True)
        layout.addWidget(message)
        actions = QHBoxLayout()
        login = QPushButton("Login with Lenovo ID")
        guest = QPushButton("Continue as guest")
        login.clicked.connect(dialog.accept)
        login.clicked.connect(self._start_capture_login)
        guest.clicked.connect(dialog.accept)
        guest.clicked.connect(self._start_guest_login)
        actions.addWidget(login)
        actions.addWidget(guest)
        layout.addLayout(actions)
        dialog.exec()

    def _build_devices_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)

        self.device_status = QLabel(
            "Scanning for ADB, fastboot, and Qualcomm EDL devices..."
        )
        layout.addWidget(self.device_status)

        self.device_table = QTableWidget(0, len(DEVICE_COLUMNS))
        self.device_table.setHorizontalHeaderLabels(DEVICE_COLUMNS)
        configure_table(self.device_table, min_height=220)
        self.device_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.device_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.device_table.itemSelectionChanged.connect(
            self._show_selected_device_details
        )
        layout.addWidget(self.device_table)

        details_group = QGroupBox("Selected device details")
        details_layout = QVBoxLayout(details_group)
        self.device_details = QPlainTextEdit()
        self.device_details.setMinimumHeight(150)
        self.device_details.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.device_details.setReadOnly(True)
        self.device_details.setPlainText("Select a device to inspect details.")
        details_layout.addWidget(self.device_details)
        layout.addWidget(details_group)

        refresh = QPushButton("Refresh now")
        refresh.clicked.connect(self._refresh_devices_once)
        layout.addWidget(refresh, alignment=Qt.AlignmentFlag.AlignRight)
        return page

    def _build_firmware_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)

        lookup_group = QGroupBox("Firmware lookup")
        lookup_layout = QGridLayout(lookup_group)
        configure_grid(lookup_layout)
        self.sn_input = QLineEdit(DEFAULT_SN)
        self.imei_input = QLineEdit()
        self.imei2_input = QLineEdit()
        self.sn_input.setPlaceholderText("Serial number")
        self.imei_input.setPlaceholderText("IMEI")
        self.imei2_input.setPlaceholderText("Optional second IMEI")
        self.guest_fallback_check = QCheckBox("Use guest login if no session is loaded")
        self.guest_fallback_check.setChecked(True)
        self.lookup_button = QPushButton("List ROMs")
        self.lookup_button.clicked.connect(self._lookup_firmware)
        self.catalog_category = QComboBox()
        for label, value in CATEGORY_OPTIONS:
            self.catalog_category.addItem(label, value)
        self.catalog_category.currentIndexChanged.connect(
            self._catalog_category_changed
        )
        self.catalog_market = QComboBox()
        self.catalog_market.currentIndexChanged.connect(self._catalog_market_changed)
        self.catalog_model = QComboBox()
        self.catalog_model.currentIndexChanged.connect(self._catalog_model_changed)
        self._populate_combo(self.catalog_market, ["(all markets)"], [""])
        self._populate_combo(
            self.catalog_model,
            ["(select a market to load models)"],
            [""],
        )
        self.load_markets_button = QPushButton("Load markets")
        self.load_markets_button.clicked.connect(self._load_catalog_markets)

        lookup_layout.addWidget(make_form_label("Device type"), 0, 0)
        lookup_layout.addWidget(self.catalog_category, 0, 1)
        lookup_layout.addWidget(self.load_markets_button, 0, 2)
        lookup_layout.addWidget(make_form_label("Market"), 1, 0)
        lookup_layout.addWidget(self.catalog_market, 1, 1, 1, 2)
        lookup_layout.addWidget(make_form_label("Model"), 2, 0)
        lookup_layout.addWidget(self.catalog_model, 2, 1, 1, 2)
        lookup_layout.addWidget(make_form_label("SN"), 3, 0)
        lookup_layout.addWidget(self.sn_input, 3, 1, 1, 2)
        lookup_layout.addWidget(make_form_label("IMEI"), 4, 0)
        lookup_layout.addWidget(self.imei_input, 4, 1, 1, 2)
        lookup_layout.addWidget(make_form_label("IMEI2"), 5, 0)
        lookup_layout.addWidget(self.imei2_input, 5, 1, 1, 2)
        lookup_layout.addWidget(self.guest_fallback_check, 6, 1, 1, 2)
        lookup_layout.addWidget(self.lookup_button, 7, 2)
        lookup_layout.setColumnStretch(1, 1)
        lookup_layout.setColumnStretch(2, 0)
        layout.addWidget(lookup_group)

        results_layout = QHBoxLayout()
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(12)

        rom_list_group = QGroupBox("Available ROMs")
        rom_list_layout = QVBoxLayout(rom_list_group)
        self.resource_table = QTableWidget(0, len(RESOURCE_COLUMNS))
        self.resource_table.setHorizontalHeaderLabels(RESOURCE_COLUMNS)
        configure_table(self.resource_table, min_height=240)
        self.resource_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.resource_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.resource_table.itemSelectionChanged.connect(
            self._show_selected_resource_details
        )
        rom_list_layout.addWidget(self.resource_table)
        rom_list_group.setMinimumWidth(270)
        results_layout.addWidget(rom_list_group, 2)

        resource_details_group = QGroupBox("Selected ROM")
        resource_details_layout = QVBoxLayout(resource_details_group)
        self.resource_details = QPlainTextEdit()
        self.resource_details.setMinimumHeight(240)
        self.resource_details.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.resource_details.setReadOnly(True)
        self.resource_details.setPlainText("Run List ROMs, then select a ROM.")
        resource_details_layout.addWidget(self.resource_details)
        resource_details_group.setMinimumWidth(180)
        results_layout.addWidget(resource_details_group, 2)
        layout.addLayout(results_layout)

        prepare_group = QGroupBox("Download / prepare")
        prepare_layout = QGridLayout(prepare_group)
        configure_grid(prepare_layout)
        self.download_check = QCheckBox("Download matched resources")
        self.extract_check = QCheckBox("Extract ZIP resources")
        self.extract_check.setChecked(True)
        self.decrypt_check = QCheckBox("Decrypt ROM helper files")
        self.decrypt_check.setChecked(True)
        self.download_dir_input = QLineEdit(
            str(self._work_dir() / "software_fix" / "downloads")
        )
        self.download_dir_input.setReadOnly(True)
        self.download_dir_input.setPlaceholderText(
            "Choose where firmware archives are saved"
        )
        self.download_dir_button = QPushButton("Choose")
        self.download_dir_button.clicked.connect(self._pick_download_dir)

        firmware_state = self._gui_state.get("firmware")
        if isinstance(firmware_state, dict):
            self.sn_input.setText(str(firmware_state.get("sn") or DEFAULT_SN))
            self.imei_input.setText(str(firmware_state.get("imei") or ""))
            self.imei2_input.setText(str(firmware_state.get("imei2") or ""))
            category = str(firmware_state.get("catalog_category") or "tablet")
            category_index = self.catalog_category.findData(category)
            if category_index >= 0:
                self.catalog_category.setCurrentIndex(category_index)
            saved_market = str(firmware_state.get("catalog_market") or "")
            if saved_market:
                self._populate_combo(
                    self.catalog_market, [saved_market], [saved_market]
                )
            saved_model = str(firmware_state.get("catalog_model") or "")
            if saved_model:
                self._populate_combo(self.catalog_model, [saved_model], [saved_model])
            self.guest_fallback_check.setChecked(
                bool(firmware_state.get("guest_fallback", True))
            )
            self.download_check.setChecked(
                bool(firmware_state.get("download_resources", False))
            )
            self.extract_check.setChecked(
                bool(firmware_state.get("extract_resources", True))
            )
            self.decrypt_check.setChecked(bool(firmware_state.get("decrypt_rom", True)))
            self.download_dir_input.setText(
                str(
                    firmware_state.get("downloads_dir")
                    or self._work_dir() / "software_fix" / "downloads"
                )
            )

        for field in (
            self.sn_input,
            self.imei_input,
            self.imei2_input,
            self.download_dir_input,
        ):
            field.textChanged.connect(self._save_form_state)
        for toggle in (
            self.guest_fallback_check,
            self.download_check,
            self.extract_check,
            self.decrypt_check,
        ):
            toggle.toggled.connect(self._save_form_state)
        self.prepare_button = QPushButton("Prepare selected ROM")
        self.prepare_button.clicked.connect(self._prepare_selected_resource)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_label = QLabel("Idle")
        self.artifact_table = QTableWidget(0, len(ARTIFACT_COLUMNS))
        self.artifact_table.setHorizontalHeaderLabels(ARTIFACT_COLUMNS)
        configure_table(self.artifact_table, min_height=150)
        self.artifact_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.artifact_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        prepare_layout.addWidget(make_form_label("Download location"), 0, 0)
        prepare_layout.addWidget(self.download_dir_input, 0, 1)
        prepare_layout.addWidget(self.download_dir_button, 0, 2)
        prepare_layout.addWidget(self.download_check, 1, 1, 1, 2)
        prepare_layout.addWidget(self.extract_check, 2, 1, 1, 2)
        prepare_layout.addWidget(self.decrypt_check, 3, 1, 1, 2)
        prepare_layout.addWidget(self.prepare_button, 4, 2)
        prepare_layout.addWidget(self.progress_bar, 5, 1)
        prepare_layout.addWidget(self.progress_label, 5, 2)
        prepare_layout.addWidget(self.artifact_table, 6, 0, 1, 3)
        prepare_layout.setColumnStretch(1, 1)
        prepare_layout.setColumnStretch(2, 0)
        layout.addWidget(prepare_group)
        return page

    def _build_rom_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)

        picker_group = QGroupBox("ROM source")
        picker_layout = QGridLayout(picker_group)
        configure_grid(picker_layout)
        self.rom_path = QLineEdit()
        self.rom_path.setReadOnly(True)
        self.rom_path.setPlaceholderText("No ROM selected")
        picker_layout.addWidget(make_form_label("Selected ROM"), 0, 0)
        picker_layout.addWidget(self.rom_path, 0, 1, 1, 3)
        selected_rom_path = self._gui_state.get("selected_rom_path")
        if selected_rom_path:
            self.rom_path.setText(str(selected_rom_path))

        folder_button = QPushButton("Select extracted ROM folder")
        folder_button.clicked.connect(self._pick_rom_folder)
        file_button = QPushButton("Select Rescue.cmd / archive")
        file_button.clicked.connect(self._pick_rom_file)
        picker_layout.addWidget(folder_button, 1, 2)
        picker_layout.addWidget(file_button, 1, 3)
        layout.addWidget(picker_group)

        validation_group = QGroupBox("Validation")
        validation_layout = QVBoxLayout(validation_group)
        self.rom_validation = QLabel(
            "Select an extracted ROM folder or Rescue.cmd to validate flashing files."
        )
        self.rom_validation.setWordWrap(True)
        validation_layout.addWidget(self.rom_validation)
        layout.addWidget(validation_group)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.preview_button = QPushButton("Preview flash plan")
        self.preview_button.setEnabled(False)
        self.preview_button.clicked.connect(self._preview_flash_plan)
        self.install_button = QPushButton("Install ROM")
        self.install_button.setEnabled(False)
        self.install_button.clicked.connect(self._install_rom)
        actions.addStretch(1)
        actions.addWidget(self.preview_button)
        actions.addWidget(self.install_button)
        layout.addLayout(actions)
        layout.addStretch(1)
        return page

    def _build_logs_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setMinimumHeight(420)
        self.logs.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.logs)
        clear = QPushButton("Clear logs")
        clear.clicked.connect(self.logs.clear)
        layout.addWidget(clear, alignment=Qt.AlignmentFlag.AlignRight)
        return page

    def _downloads_dir(self) -> Path:
        if hasattr(self, "download_dir_input"):
            value = self.download_dir_input.text().strip()
            if value:
                return Path(value)
        return self._work_dir() / "software_fix" / "downloads"

    def _pick_download_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self,
            "Choose download location",
            str(self._downloads_dir()),
        )
        if folder:
            self.download_dir_input.setText(folder)
            self._save_form_state()

    def _work_dir(self) -> Path:
        return Path(self.work_dir_input.text().strip() or DEFAULT_WORK_DIR)

    def _session_file(self) -> Path:
        return session_path(self._work_dir())

    def _session_candidates(self) -> list[Path]:
        work_dir = self._work_dir()
        return [
            session_path(work_dir),
            work_dir / "capture" / "login_session.json",
        ]

    def _latest_session_file(self) -> Path | None:
        existing = [path for path in self._session_candidates() if path.exists()]
        if not existing:
            return None
        return max(existing, key=lambda path: path.stat().st_mtime)

    def _client_uuid_hint(self) -> str | None:
        if self._current_session and self._current_session.get("client_uuid"):
            return str(self._current_session["client_uuid"])
        return None

    def _set_active_session(
        self, session: dict[str, Any] | None, persist: bool = True
    ) -> None:
        self._current_session = session
        if session is not None:
            session["auto_login"] = True
            session.setdefault("saved_at_unix", int(time.time()))
            self._gui_state["session"] = {
                "method": session.get("method"),
                "client_uuid": session.get("client_uuid"),
                "fullName": session.get("fullName"),
                "saved_at_unix": session.get("saved_at_unix"),
            }
            if persist:
                save_json(self._session_file(), session)
        else:
            self._gui_state.pop("session", None)
            if persist:
                delete_session(self._session_file())
        self._save_gui_state()
        self._refresh_session_ui()

    def _session_expiry_text(self) -> str:
        if not self._current_session:
            return ""
        token_response = self._current_session.get("token_response")
        if isinstance(token_response, dict):
            oauth_token = token_response.get("oauth_token")
            if isinstance(oauth_token, dict):
                expires_in = oauth_token.get("expires_in")
                saved_at = self._current_session.get("saved_at_unix")
                if isinstance(expires_in, int) and isinstance(saved_at, int):
                    remaining = saved_at + expires_in - int(time.time())
                    if remaining > 0:
                        return f"expires in {remaining // 60} min"
                    return "expired by OAuth timer"
        saved_at = self._current_session.get("saved_at_unix")
        if isinstance(saved_at, int):
            age_seconds = max(0, int(time.time()) - saved_at)
            return f"age {age_seconds // 60} min; no expiry provided"
        return "no expiry provided"

    def _refresh_session_ui(self) -> None:
        if not self._current_session:
            self.session_status.setText(
                "Not logged in. Use Lenovo ID for catalog browsing and ROM downloads, "
                "or continue as guest for limited access."
            )
            self.logout_button.setEnabled(False)
            return
        method = str(self._current_session.get("method") or "")
        label = (
            "Guest session active" if method == "guest" else "Logged in with Lenovo ID"
        )
        self.session_status.setText(f"{label} — {self._session_expiry_text()}")
        self.logout_button.setEnabled(True)

    def _load_saved_session_if_present(self) -> None:
        path = self._latest_session_file()
        if path is None:
            self._current_session = None
            self._refresh_session_ui()
            return
        try:
            loaded = load_session(path)
        except Exception as exc:
            self._current_session = None
            self._append_log(f"Failed to load saved session: {exc}")
            self._refresh_session_ui()
            return
        if loaded and loaded.get("auto_login", True):
            loaded.setdefault("saved_at_unix", int(path.stat().st_mtime))
            self._set_active_session(loaded, persist=path != self._session_file())
            self._append_log(f"Loaded session: {path}")
        else:
            self._current_session = None
            self._refresh_session_ui()

    def _run_session_worker(self, worker: QThread) -> None:
        if self._session_worker is not None and self._session_worker.isRunning():
            QMessageBox.information(
                self,
                "LRSA",
                "Another login/session action is already running.",
            )
            return
        self._session_worker = worker
        worker.start()

    def _start_guest_login(self) -> None:
        worker = GuestLoginWorker(self._client_uuid_hint())
        worker.output.connect(self._append_log)
        worker.failed.connect(
            lambda message: QMessageBox.warning(self, "Guest login failed", message)
        )
        worker.failed.connect(
            lambda message: self._append_log(f"Guest login failed: {message}")
        )
        worker.finished_with_session.connect(self._guest_login_finished)
        self._run_session_worker(worker)

    def _guest_login_finished(self, session: dict[str, Any]) -> None:
        session["auto_login"] = False
        self._set_active_session(session, persist=True)
        self._append_log("Guest login completed.")

    def _start_capture_login(self) -> None:
        busy_workers = (
            self._command_worker,
            self._capture_worker,
            self._capture_watcher,
        )
        if any(worker is not None and worker.isRunning() for worker in busy_workers):
            QMessageBox.information(self, "LRSA", "A command is already running.")
            return

        out_dir = (self._work_dir() / "capture").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        url_file = out_dir / "login_url.json"
        ready_file = out_dir / "capture_ready.json"
        session_file = out_dir / "login_session.json"
        self._capture_started_at = time.time()
        for stale_file in (url_file, ready_file, session_file):
            try:
                stale_file.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                self._append_log(
                    f"Could not remove stale login file {stale_file}: {exc}"
                )

        base_command = [
            sys.executable,
            "-m",
            "lrsa.servers.capture",
            "--out-dir",
            str(out_dir),
            "--url-file",
            str(url_file),
            "--ready-file",
            str(ready_file),
            "--login-url-mode",
            "software-fix-api",
        ]
        needs_admin = bool(getattr(os, "geteuid", lambda: 0)() != 0)
        self._append_log("")
        self._append_log(
            "Starting Lenovo ID login capture. The login portal will open "
            "automatically after the local callback listener is ready."
        )
        self.login_button.setEnabled(False)
        if needs_admin and platform.system() == "Darwin":
            self._start_macos_terminal_capture(base_command, session_file)
            return
        if needs_admin:
            self._append_log(
                "This platform must run LRSA with administrator/root privileges "
                "to bind port 443 and update the hosts file."
            )
        command = [*base_command, "--no-browser"]
        self._capture_worker = CaptureLoginWorker(
            command,
            url_file=url_file,
            ready_file=ready_file,
            needs_admin=False,
        )
        self._capture_worker.output.connect(self._append_log)
        self._capture_worker.browser_url.connect(self._open_capture_login_url)
        self._capture_worker.finished_with_code.connect(self._capture_login_finished)
        self._capture_worker.start()

    def _start_macos_terminal_capture(
        self, command: list[str], session_file: Path
    ) -> None:
        shell_command = " ".join(shlex.quote(part) for part in command)
        repo_dir = shlex.quote(str(Path.cwd()))
        terminal_command = (
            f"cd {repo_dir} && sudo {shell_command}; "
            "printf '\\nLRSA Lenovo ID login capture finished. "
            "You can close this Terminal window.\\n'"
        )
        script = (
            'tell application "Terminal"\n'
            "activate\n"
            f"do script {json.dumps(terminal_command)}\n"
            "end tell"
        )
        self._append_log(
            "Opening Terminal for the administrator step. Enter your macOS "
            "password there; the Lenovo login portal will then open automatically."
        )
        try:
            subprocess.Popen(["osascript", "-e", script])
        except Exception as exc:
            self.login_button.setEnabled(True)
            self._append_log(f"Failed to open Terminal for login capture: {exc}")
            QMessageBox.warning(self, "Lenovo ID login failed", str(exc))
            return

        self._capture_watcher = LoginSessionWatcher(
            session_file,
            started_at=self._capture_started_at,
        )
        self._capture_watcher.session_file_ready.connect(self._capture_session_ready)
        self._capture_watcher.failed.connect(self._capture_session_wait_failed)
        self._capture_watcher.start()

    def _open_capture_login_url(self, url: str) -> None:
        if not QDesktopServices.openUrl(QUrl(url)):
            self._append_log(f"Could not open browser automatically. Login URL: {url}")
            QMessageBox.warning(
                self,
                "Open Lenovo ID Login",
                "Could not open the browser automatically. Copy the login URL from Logs.",
            )

    def _capture_login_finished(self, returncode: int) -> None:
        self._append_log(f"Capture login finished with exit code {returncode}.")
        self.login_button.setEnabled(True)
        session_file = (self._work_dir() / "capture" / "login_session.json").resolve()
        if returncode != 0:
            self._append_log(
                "Login capture failed; ignoring any older saved capture session."
            )
            QMessageBox.warning(
                self,
                "Lenovo ID login failed",
                "Login capture did not complete. See Logs for details.",
            )
            return
        self._import_capture_session(session_file)

    def _capture_session_ready(self, session_file: str) -> None:
        self.login_button.setEnabled(True)
        self._append_log("Lenovo ID login capture produced a fresh session.")
        self._import_capture_session(Path(session_file))

    def _capture_session_wait_failed(self, message: str) -> None:
        self.login_button.setEnabled(True)
        self._append_log(message)
        QMessageBox.warning(self, "Lenovo ID login timed out", message)

    def _import_capture_session(self, session_file: Path) -> None:
        if not session_file.exists():
            self._append_log(f"No captured session found at {session_file}.")
            return
        try:
            if session_file.stat().st_mtime < self._capture_started_at:
                self._append_log(
                    "Captured session file is older than this login attempt; ignoring it."
                )
                return
        except OSError as exc:
            self._append_log(f"Could not inspect captured session file: {exc}")
            return
        try:
            session = load_session(session_file)
        except Exception as exc:
            self._append_log(f"Failed to load captured session: {exc}")
            QMessageBox.warning(self, "Capture login failed", str(exc))
            return
        if not session:
            self._append_log("Captured session file was empty.")
            return
        self._set_active_session(session, persist=True)
        self._append_log(f"Imported captured Lenovo ID session from {session_file}.")

    def _logout_active_session(self) -> None:
        if not self._current_session:
            QMessageBox.information(self, "LRSA", "No active session.")
            return
        worker = LogoutWorker(self._current_session)
        worker.finished_with_results.connect(self._logout_finished)
        self._run_session_worker(worker)

    def _logout_finished(self, results: list[dict[str, Any]]) -> None:
        for item in results:
            self._append_log(f"logout.{item.get('step')}: {item}")
        self._set_active_session(None, persist=True)
        self._append_log("Session cleared.")

    def _refresh_devices_once(self) -> None:
        try:
            self._set_devices(scan_connected_devices())
        except Exception as exc:
            self._append_log(f"Device scan failed: {exc}")

    def _set_devices(self, devices: list[dict[str, Any]]) -> None:
        self._devices = devices
        self.device_table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            values = [
                str(device.get("transport", "")).upper(),
                str(device.get("serial", "")),
                str(device.get("state", "")),
                str(device.get("detail", "")),
            ]
            for column, value in enumerate(values):
                self.device_table.setItem(row, column, QTableWidgetItem(value))
        if devices:
            self.device_status.setText(f"Detected {len(devices)} device(s).")
        else:
            self.device_status.setText(
                "No ADB, fastboot, or Qualcomm EDL device detected."
            )
        self._show_selected_device_details()

    def _show_selected_device_details(self) -> None:
        row = self.device_table.currentRow()
        if row < 0 or row >= len(self._devices):
            self.device_details.setPlainText("Select a device to inspect details.")
            return
        device = self._devices[row]
        self.device_details.setPlainText(
            "\n".join(f"{key}: {value}" for key, value in device.items())
        )

    def _catalog_category_value(self) -> str:
        data = self.catalog_category.currentData()
        return str(data or "tablet")

    def _selected_catalog_model(self) -> str:
        return str(self.catalog_model.currentData() or "").strip()

    def _catalog_category_changed(self) -> None:
        self._catalog_markets = []
        self._catalog_models = []
        self._populate_combo(self.catalog_market, ["(all markets)"], [""])
        self._populate_combo(
            self.catalog_model,
            ["(select a market to load models)"],
            [""],
        )
        self._save_form_state()

    def _catalog_market_changed(self) -> None:
        self._save_form_state()
        if not self.catalog_market.signalsBlocked():
            self._load_catalog_models()

    def _catalog_model_changed(self) -> None:
        self._save_form_state()

    def _populate_combo(
        self,
        combo: QComboBox,
        labels: list[str],
        placeholder_data: list[str] | None = None,
    ) -> None:
        was_blocked = combo.blockSignals(True)
        combo.clear()
        if placeholder_data is None:
            placeholder_data = labels
        for label, data in zip(labels, placeholder_data, strict=False):
            combo.addItem(label, data)
        combo.blockSignals(was_blocked)

    def _run_catalog_worker(self, action: str, market_name: str = "") -> None:
        if self._catalog_worker is not None and self._catalog_worker.isRunning():
            QMessageBox.information(
                self, "LRSA", "A catalog request is already running."
            )
            return
        worker = CatalogBrowseWorker(
            session=self._current_session,
            category=self._catalog_category_value(),
            action=action,
            market_name=market_name,
        )
        worker.output.connect(self._append_log)
        worker.failed.connect(self._catalog_failed)
        worker.finished_with_catalog.connect(self._catalog_loaded)
        self._catalog_worker = worker
        worker.start()

    def _load_catalog_markets(self) -> None:
        self._run_catalog_worker("markets")

    def _load_catalog_models(self) -> None:
        market_name = str(self.catalog_market.currentData() or "")
        self._run_catalog_worker("models", market_name=market_name)

    def _catalog_failed(self, message: str) -> None:
        self._append_log(f"Catalog load failed: {message}")
        QMessageBox.warning(self, "Catalog load failed", message)

    def _catalog_loaded(self, action: str, items: list[Any], payload: object) -> None:
        del payload
        strings = [str(item) for item in items if str(item).strip()]
        if action == "markets":
            self._catalog_markets = strings
            labels = ["(all markets)", *strings] if strings else ["(all markets)"]
            data = ["", *strings] if strings else [""]
            self._populate_combo(self.catalog_market, labels, data)
            self._append_log(f"Loaded {len(strings)} catalog market(s).")
        else:
            self._catalog_models = strings
            labels = ["(select model)", *strings] if strings else ["(no models found)"]
            data = ["", *strings] if strings else [""]
            self._populate_combo(self.catalog_model, labels, data)
            self._append_log(f"Loaded {len(strings)} catalog model(s).")
        self._save_form_state()

    def _lookup_firmware(self) -> None:
        if self._firmware_worker is not None and self._firmware_worker.isRunning():
            QMessageBox.information(self, "LRSA", "Firmware lookup is already running.")
            return
        model = self._selected_catalog_model()
        imei = self.imei_input.text().strip()
        sn = self.sn_input.text().strip()
        if not model and not imei:
            QMessageBox.information(
                self,
                "LRSA",
                "Select a catalog model first, or enter an IMEI.",
            )
            return
        if model and not sn and not imei:
            QMessageBox.information(
                self,
                "LRSA",
                "Lenovo requires SN/IMEI or device readback properties for matched ROM lookup. "
                "Enter SN/IMEI before listing matched ROMs.",
            )
            return
        self.resource_table.setRowCount(0)
        self.artifact_table.setRowCount(0)
        self._resources = []
        self.resource_details.setPlainText("Looking up ROMs...")
        self._save_form_state()
        self._firmware_worker = FirmwareLookupWorker(
            session=self._current_session,
            allow_guest=self.guest_fallback_check.isChecked(),
            model=model,
            sn=sn,
            imei=imei,
            imei2=self.imei2_input.text().strip(),
            work_dir=self._work_dir(),
        )
        self._firmware_worker.output.connect(self._append_log)
        self._firmware_worker.failed.connect(self._lookup_failed)
        self._firmware_worker.finished_with_resources.connect(self._set_resources)
        self._firmware_worker.start()

    def _lookup_failed(self, message: str) -> None:
        self._append_log(f"Firmware lookup failed: {message}")
        self.resource_details.setPlainText(message)
        QMessageBox.warning(self, "Firmware lookup failed", message)

    def _set_resources(
        self, resources: list[dict[str, Any]], payload: object, session_update: object
    ) -> None:
        if isinstance(session_update, dict):
            self._set_active_session(session_update, persist=True)
        self._resources = resources
        self.resource_table.setRowCount(len(resources))
        for row, resource in enumerate(resources):
            summary = resource_summary(resource)
            rom_name = str(
                summary.get("firmwareName") or resource.get("modelName") or ""
            )
            self.resource_table.setItem(row, 0, QTableWidgetItem(rom_name))
        self._append_log(f"Listed {len(resources)} ROM resource(s).")
        self._append_log(f"Response saved under {self._work_dir()}.")
        if resources:
            self.resource_table.selectRow(0)
        else:
            self.resource_details.setPlainText(str(payload))

    def _selected_resource(self) -> dict[str, Any] | None:
        row = self.resource_table.currentRow()
        if row < 0 or row >= len(self._resources):
            return None
        return self._resources[row]

    def _show_selected_resource_details(self) -> None:
        resource = self._selected_resource()
        if resource is None:
            self.resource_details.setPlainText("Select a ROM to inspect details.")
            return
        summary = resource_summary(resource)
        lines = [f"{key}: {value}" for key, value in summary.items()]
        for prefix, key in (
            ("rom", "romResource"),
            ("tool", "toolResource"),
            ("country", "countryCodeResource"),
        ):
            value = resource.get(key)
            if isinstance(value, dict):
                lines.extend(
                    f"{prefix}.{item_key}: {item_value}"
                    for item_key, item_value in value.items()
                )
        self.resource_details.setPlainText("\n".join(lines))

    def _prepare_selected_resource(self) -> None:
        resource = self._selected_resource()
        if resource is None:
            QMessageBox.information(self, "LRSA", "Select a ROM first.")
            return
        if self._prepare_worker is not None and self._prepare_worker.isRunning():
            QMessageBox.information(self, "LRSA", "ROM preparation is already running.")
            return
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Preparing ROM...")
        self._prepare_worker = PrepareWorker(
            resource=resource,
            work_dir=self._work_dir(),
            downloads_dir=self._downloads_dir(),
            download_resources=self.download_check.isChecked(),
            extract_resources=self.extract_check.isChecked(),
            decrypt_rom=self.decrypt_check.isChecked(),
        )
        self._prepare_worker.progress.connect(self._update_prepare_progress)
        self._prepare_worker.failed.connect(self._prepare_failed)
        self._prepare_worker.finished_with_manifest.connect(self._prepare_finished)
        self._prepare_worker.start()

    @staticmethod
    def _format_progress_amount(current: int, total: int, stage: str) -> str:
        if stage == "download":

            def format_bytes(value: int) -> str:
                amount = float(max(0, value))
                for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
                    if amount < 1024 or unit == "TiB":
                        if unit == "B":
                            return f"{int(amount)} {unit}"
                        return f"{amount:.1f} {unit}"
                    amount /= 1024
                return f"{amount:.1f} TiB"

            return f"{format_bytes(current)} / {format_bytes(total)}"
        return f"{current}/{total}"

    def _update_prepare_progress(
        self, stage: str, current: int, total: object, label: str
    ) -> None:
        if isinstance(total, int) and not isinstance(total, bool) and total > 0:
            bounded_current = max(0, min(current, total))
            if total <= PROGRESS_BAR_MAX:
                self.progress_bar.setRange(0, total)
                self.progress_bar.setValue(bounded_current)
            else:
                self.progress_bar.setRange(0, PROGRESS_BAR_MAX)
                self.progress_bar.setValue(
                    int(bounded_current * PROGRESS_BAR_MAX / total)
                )
            self.progress_label.setText(
                f"{stage}: {label} "
                f"({self._format_progress_amount(current, total, stage)})"
            )
        else:
            self.progress_bar.setRange(0, 0)
            self.progress_label.setText(f"{stage}: {label}")

    def _prepare_failed(self, message: str) -> None:
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Failed")
        self._append_log(f"ROM preparation failed: {message}")
        QMessageBox.warning(self, "ROM preparation failed", message)

    def _prepare_finished(self, manifest: dict[str, Any]) -> None:
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.progress_label.setText("Done")
        self._populate_artifacts(manifest.get("resourceArtifacts"))
        for key, value in manifest.items():
            self._append_log(f"manifest.{key}: {value}")
        startup = manifest.get("startupFile")
        rom_dir = manifest.get("romDir")
        if startup:
            self._validate_rom_selection(Path(str(startup)))
        elif rom_dir:
            self._validate_rom_selection(Path(str(rom_dir)))

    def _populate_artifacts(self, artifacts: object) -> None:
        items = artifacts if isinstance(artifacts, list) else []
        self.artifact_table.setRowCount(len(items))
        for row, artifact in enumerate(items):
            if not isinstance(artifact, dict):
                continue
            md5_status = artifact.get("archiveMd5")
            md5_text = ""
            if isinstance(md5_status, dict):
                if md5_status.get("skipped"):
                    md5_text = "skipped"
                elif md5_status.get("verified") is True:
                    md5_text = "verified"
                elif md5_status.get("verified") is False:
                    md5_text = "mismatch"
            values = [
                str(artifact.get("kind") or ""),
                str(artifact.get("name") or ""),
                "yes" if artifact.get("archive") else "no",
                "yes" if artifact.get("extractedDir") else "no",
                md5_text,
            ]
            for column, value in enumerate(values):
                self.artifact_table.setItem(row, column, QTableWidgetItem(value))

    def _pick_rom_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select extracted ROM folder")
        if folder:
            self._validate_rom_selection(Path(folder))

    def _pick_rom_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Rescue.cmd or ROM archive",
            "",
            ROM_FILE_FILTER,
        )
        if filename:
            self._validate_rom_selection(Path(filename))

    def _validate_rom_selection(self, selected: Path) -> None:
        self._selected_rom_base = None
        self._selected_startup = None
        self.preview_button.setEnabled(False)
        self.install_button.setEnabled(False)
        self.rom_path.setText(str(selected))
        self._gui_state["selected_rom_path"] = str(selected)
        self._save_gui_state()

        if selected.is_file() and selected.name.lower() != "rescue.cmd":
            self.rom_validation.setText(
                "Archive selected. Extract the ROM first, then select the extracted folder or Rescue.cmd."
            )
            return

        base_dir = selected.parent if selected.is_file() else selected
        startup = selected if selected.is_file() else self._find_rescue_cmd(base_dir)
        if startup is None:
            self.rom_validation.setText(f"No Rescue.cmd found under {base_dir}.")
            return

        try:
            from lrsa.flash.qfil import resolve_qfil_image_dir
            from qfil import parse_rescue_cmd, summarize_plan

            image_dir = resolve_qfil_image_dir(base_dir, startup)
            plan = parse_rescue_cmd(startup, image_dir)
            summary = "\n".join(summarize_plan(plan))
        except Exception as exc:
            self.rom_validation.setText(f"ROM validation failed: {exc}")
            return

        self._selected_rom_base = base_dir
        self._selected_startup = startup
        self.preview_button.setEnabled(True)
        self.install_button.setEnabled(True)
        self.rom_validation.setText(
            f"Ready: {startup}\n\n{summary}" if summary else f"Ready: {startup}"
        )

    @staticmethod
    def _find_rescue_cmd(root: Path) -> Path | None:
        for path in root.rglob("*"):
            if path.is_file() and path.name.lower() == "rescue.cmd":
                return path
        return None

    def _preview_flash_plan(self) -> None:
        if self._selected_rom_base is None:
            return
        self._run_lrsa_command(
            [
                "--skip-api",
                "--image-dir",
                str(self._selected_rom_base),
            ]
        )

    def _install_rom(self) -> None:
        if self._selected_rom_base is None:
            return
        has_edl = any(
            str(device.get("transport", "")).lower() == "edl"
            for device in self._devices
        )
        message = "This will flash the selected ROM to the connected device. Continue?"
        if not has_edl:
            message += (
                "\n\nNo Qualcomm EDL device is currently detected; the backend preflight will block "
                "flashing unless one appears."
            )
        if (
            QMessageBox.warning(
                self,
                "Install ROM",
                message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._run_lrsa_command(
            [
                "--skip-api",
                "--image-dir",
                str(self._selected_rom_base),
                "--flash",
            ]
        )

    def _run_lrsa_command(self, args: list[str]) -> None:
        if self._command_worker is not None and self._command_worker.isRunning():
            QMessageBox.information(self, "LRSA", "A command is already running.")
            return
        command = [sys.executable, "-m", "lrsa.cli", *args]
        self._append_log("")
        self._command_worker = CommandWorker(command)
        self._command_worker.output.connect(self._append_log)
        self._command_worker.finished_with_code.connect(self._command_finished)
        self._command_worker.start()

    def _append_log(self, text: str) -> None:
        self.logs.append(text)

    def _command_finished(self, returncode: int) -> None:
        self._append_log(f"Command finished with exit code {returncode}.")


def main() -> None:
    configure_logging()
    app = QApplication(sys.argv)
    app.setStyleSheet(LIGHT_APP_STYLE)
    window = MainWindow()
    window.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
