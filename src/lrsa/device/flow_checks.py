"""Software Fix recipe validation preflights."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .constants import FASTBOOT_CHECK_STEPS
from .preflight import run_fastboot_getvar_all_with_warning


def flow_step_names(flow: dict[str, Any]) -> list[str]:
    return [
        str(step.get("Step") or "")
        for step in flow.get("Steps", [])
        if isinstance(step, dict)
    ]


def required_fastboot_steps(flow: dict[str, Any]) -> list[str]:
    return [name for name in flow_step_names(flow) if name in FASTBOOT_CHECK_STEPS]


def validate_fastboot_recipe_checks(
    flow: dict[str, Any],
    resource: dict[str, Any],
    image_dir: Path | None = None,
    fastboot: str | Path | None = None,
    require: bool = False,
) -> dict[str, Any]:
    steps = required_fastboot_steps(flow)
    result: dict[str, Any] = {
        "requiredSteps": steps,
        "checked": False,
        "properties": {},
    }
    if not steps:
        return result

    fastboot_path = str(fastboot or shutil.which("fastboot") or "")
    if not fastboot_path:
        if require:
            raise RuntimeError(
                "Software Fix recipe requires fastboot validation, but no native fastboot binary was found."
            )
        result["warning"] = (
            "fastboot validation required by recipe but fastboot was not found"
        )
        return result

    props, warning = run_fastboot_getvar_all_with_warning(fastboot_path)
    result["checked"] = True
    result["properties"] = props
    if warning:
        result["warning"] = warning

    expected = (
        str(resource.get("realModelName") or resource.get("modelName") or "")
        .strip()
        .lower()
    )
    if expected:
        candidates = [
            props.get("modelname", ""),
            props.get("product", ""),
            props.get("sku", ""),
            props.get("serialno", ""),
            props.get("ro.product.model", ""),
        ]
        if not any(expected in str(value).lower() for value in candidates):
            raise RuntimeError(
                f"Fastboot model validation failed: expected {expected}, got "
                + ", ".join(value for value in candidates if value)
            )

    if "BatFileVersionCheck" in steps and image_dir:
        signing_files = [
            Path(image_dir) / "signing-info.txt",
            Path(image_dir) / "sign_info.txt",
        ]
        if not any(path.exists() for path in signing_files):
            raise RuntimeError(
                "Recipe requests rollback/version check, but no signing-info file was found."
            )

    return result
