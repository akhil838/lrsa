"""Resource matching helpers for Software Fix firmware responses."""

from __future__ import annotations

from typing import Any


def api_payload(result: dict[str, Any]) -> dict[str, Any] | None:
    payload = result.get("json")
    return payload if isinstance(payload, dict) else None


def is_success_payload(payload: dict[str, Any] | None) -> bool:
    return bool(payload and payload.get("code") == "0000")


def content_list(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    content = payload.get("content") if payload else None
    if not isinstance(content, list):
        return []
    return [item for item in content if isinstance(item, dict)]


def first_resource(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    resources = content_list(payload)
    return resources[0] if resources else None


def resource_at(
    payload: dict[str, Any] | None, index: int | None = None
) -> dict[str, Any] | None:
    resources = content_list(payload)
    if not resources:
        return None
    if index is None:
        return resources[0]
    if index < 0 or index >= len(resources):
        raise IndexError(
            f"Firmware index {index} is out of range; {len(resources)} resource(s) available."
        )
    return resources[index]


def resource_summary(resource: dict[str, Any] | None) -> dict[str, Any]:
    if not resource:
        return {}
    rom = (
        resource.get("romResource")
        if isinstance(resource.get("romResource"), dict)
        else {}
    )
    tool = (
        resource.get("toolResource")
        if isinstance(resource.get("toolResource"), dict)
        else {}
    )
    return {
        "brand": resource.get("brand"),
        "category": resource.get("category"),
        "modelName": resource.get("modelName"),
        "realModelName": resource.get("realModelName"),
        "marketName": resource.get("marketName"),
        "romMatchId": resource.get("romMatchId"),
        "platform": resource.get("platform"),
        "firmwareName": rom.get("name"),
        "firmwareUrl": rom.get("uri"),
        "firmwareMd5": rom.get("md5"),
        "toolName": tool.get("name"),
        "toolUrl": tool.get("uri"),
        "flashFlow": resource.get("flashFlow"),
    }
