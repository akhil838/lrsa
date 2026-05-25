"""Firmware response, download, and extraction helpers."""

import json
import hashlib
import shutil
import urllib.parse
import zipfile
from pathlib import Path

import requests
from tqdm.auto import tqdm

from lrsa.logging import get_logger
from lrsa.process import run_process


def file_md5(path):
    digest = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_md5(path, expected):
    expected = str(expected or "").strip().lower()
    if not expected:
        return {"expected": expected, "actual": None, "verified": None, "skipped": True}
    actual = file_md5(path).lower()
    verified = actual == expected
    return {
        "expected": expected,
        "actual": actual,
        "verified": verified,
        "skipped": False,
    }


def archive_looks_readable(path):
    suffixes = "".join(Path(path).suffixes).lower()
    if suffixes.endswith(".zip"):
        try:
            with zipfile.ZipFile(path) as zf:
                zf.infolist()
        except zipfile.BadZipFile:
            return False
    return True


def quarantine_download(path, reason):
    path = Path(path)
    target = path.with_name(f"{path.name}.bad")
    index = 1
    while target.exists():
        target = path.with_name(f"{path.name}.bad{index}")
        index += 1
    path.replace(target)
    get_logger(__name__).warning(
        "Cached download is not usable (%s); moved to: %s", reason, target
    )


def recursive_find_urls(value):
    urls = []
    if isinstance(value, dict):
        for item in value.values():
            urls.extend(recursive_find_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(recursive_find_urls(item))
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith(("http://", "https://")):
            urls.append(text)
    return urls


def pick_firmware_url(response, resource_index=None):
    resource_url = pick_rom_resource_url(response, resource_index=resource_index)
    if resource_url:
        return resource_url

    urls = recursive_find_urls(response)
    preferred_exts = (".zip", ".7z", ".tgz", ".tar.gz", ".tar", ".xml")
    for url in urls:
        lowered = urllib.parse.urlparse(url).path.lower()
        if lowered.endswith(preferred_exts):
            return url
    return urls[0] if urls else None


def pick_tool_url(response):
    resource = first_resource(response)
    tool = resource.get("toolResource") if resource else None
    if isinstance(tool, dict) and isinstance(tool.get("uri"), str):
        return tool["uri"]
    return None


def pick_flash_flow_url(response):
    resource = first_resource(response)
    if resource and isinstance(resource.get("flashFlow"), str):
        return resource["flashFlow"]
    return None


def first_resource(value):
    if isinstance(value, dict):
        content = value.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    return item
        if "romResource" in value or "toolResource" in value:
            return value
    return None


def pick_rom_resource_url(value, resource_index=None):
    if isinstance(value, dict):
        rom = value.get("romResource")
        if isinstance(rom, dict) and isinstance(rom.get("uri"), str):
            return rom["uri"]
        content = value.get("content")
        if isinstance(content, list):
            if resource_index is not None:
                if resource_index < 0 or resource_index >= len(content):
                    raise IndexError(
                        f"Firmware index {resource_index} is out of range; {len(content)} resource(s) available."
                    )
                return pick_rom_resource_url(content[resource_index])
            for item in content:
                url = pick_rom_resource_url(item)
                if url:
                    return url
        return None
    if isinstance(value, list):
        if resource_index is not None:
            if resource_index < 0 or resource_index >= len(value):
                raise IndexError(
                    f"Firmware index {resource_index} is out of range; {len(value)} resource(s) available."
                )
            return pick_rom_resource_url(value[resource_index])
        for item in value:
            url = pick_rom_resource_url(item)
            if url:
                return url
    return None


def response_payload(result):
    if result.get("json") is not None:
        return result["json"]
    if result.get("decrypted"):
        try:
            return json.loads(result["decrypted"])
        except ValueError:
            return result["decrypted"]
    raw = result.get("raw") or ""
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def download_file(url, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    name = (
        Path(urllib.parse.unquote(urllib.parse.urlparse(url).path)).name
        or "firmware.bin"
    )
    output = output_dir / name
    if output.exists() and output.stat().st_size > 0:
        if archive_looks_readable(output):
            get_logger(__name__).info("Using existing download: %s", output)
            return output
        quarantine_download(output, "invalid archive")

    get_logger(__name__).info("Downloading firmware: %s", url)
    partial = output.with_name(f"{output.name}.part")
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length") or 0)
        progress = tqdm(
            total=total or None,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=name,
        )
        with open(partial, "wb") as f, progress:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    progress.update(len(chunk))
    partial.replace(output)
    if not archive_looks_readable(output):
        quarantine_download(output, "downloaded file is not a valid archive")
        raise RuntimeError(f"Downloaded file is not a valid archive: {output}")
    get_logger(__name__).info("Saved firmware archive: %s", output)
    return output


def download_json(url, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    get_logger(__name__).info("Downloading JSON: %s", url)
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    data = r.json()
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    get_logger(__name__).info("Saved JSON: %s", output)
    return output


def extract_archive(archive, output_dir):
    archive = Path(archive)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    suffixes = "".join(archive.suffixes).lower()
    if suffixes.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            members = zf.infolist()
            get_logger(__name__).info(
                "Extracting archive: %s -> %s", archive, output_dir
            )
            for member in tqdm(members, desc=f"Extract {archive.name}", unit="file"):
                zf.extract(member, output_dir)
        return output_dir

    seven_zip = shutil.which("7z")
    if seven_zip:
        run_process(
            [seven_zip, "x", str(archive), f"-o{output_dir}", "-y"],
            label="7z extract",
            logger=get_logger(__name__),
        )
        return output_dir

    raise RuntimeError(
        f"Do not know how to extract {archive}; install 7z or extract it manually"
    )
