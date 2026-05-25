"""Interactive menu constants."""

from __future__ import annotations

from .config import DEFAULT_WORK_DIR

STATE_FILE = DEFAULT_WORK_DIR / "menu_state.json"
STATE_VERSION = 1
PATH_FIELDS = {"token_file", "work_dir"}
UI_WIDTH = 88
MIN_UI_WIDTH = 56
BORDER = {
    "top": ("┌", "┐"),
    "mid": ("├", "┤"),
    "bottom": ("└", "┘"),
}
