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


def _text_value(value: object) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _catalog_items(content: object) -> list[object]:
    if isinstance(content, dict):
        models = content.get("models")
        if isinstance(models, list):
            return models
        return list(content.values())
    if isinstance(content, list):
        items: list[object] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("marketNames"), list):
                items.extend(item["marketNames"])
            else:
                items.append(item)
        return items
    return []


def catalog_strings(
    payload: dict[str, Any] | None, preferred_keys: tuple[str, ...] = ()
) -> list[str]:
    if not payload:
        return []
    values: list[str] = []
    seen: set[str] = set()
    for item in _catalog_items(payload.get("content")):
        candidates: list[str | None] = []
        if isinstance(item, dict):
            for key in preferred_keys:
                candidates.append(_text_value(item.get(key)))
            if not preferred_keys:
                for value in item.values():
                    candidates.append(_text_value(value))
        else:
            candidates.append(_text_value(item))
        for candidate in candidates:
            if candidate and candidate not in seen:
                seen.add(candidate)
                values.append(candidate)
                break
    return values


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
    rom_resource = resource.get("romResource")
    rom: dict[str, Any] = rom_resource if isinstance(rom_resource, dict) else {}
    tool_resource = resource.get("toolResource")
    tool: dict[str, Any] = tool_resource if isinstance(tool_resource, dict) else {}
    country_resource = resource.get("countryCodeResource")
    country: dict[str, Any] = (
        country_resource if isinstance(country_resource, dict) else {}
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
        "countryCodeName": country.get("name"),
        "countryCodeUrl": country.get("uri"),
        "flashFlow": resource.get("flashFlow"),
    }
