#!/usr/bin/env python3
"""
Extract .NET IL metadata, method signatures, and string literals from LRSA DLLs.
Focus on auth flow: RSA key exchange → token init → session management.
"""

from lrsa.logging import get_logger

import argparse
import dnfile
import os

from .constants import DEFAULT_LRSA_DIR


def extract_user_strings(filepath):
    """Extract #US (User Strings) heap from .NET assembly — contains all string literals."""
    with open(filepath, "rb") as f:
        data = f.read()

    strings = []
    # Find UTF-16LE strings (how .NET stores user strings)
    # Look for readable sequences
    i = 0
    while i < len(data) - 4:
        # Try to decode as UTF-16LE pairs
        chunk = data[i : i + 200]
        try:
            # Look for printable UTF-16LE
            decoded = chunk.decode("utf-16-le", errors="strict")
            if len(decoded) > 3 and all(
                c.isprintable() or c in "\r\n\t" for c in decoded[:20]
            ):
                # Find end of string
                end = decoded.find("\x00")
                if end > 3:
                    s = decoded[:end].strip()
                    if len(s) > 3 and not s.startswith("\x00"):
                        strings.append(s)
                        i += end * 2
                        continue
        except Exception:
            pass
        i += 2

    return list(set(strings))


def analyze_dll(filepath):
    """Parse .NET metadata tables for type/method info."""
    try:
        dn = dnfile.dnPE(filepath)
    except Exception:
        return None

    info = {
        "types": [],
        "methods": [],
        "strings": [],
    }

    net = getattr(dn, "net", None)
    mdtables = getattr(net, "mdtables", None)
    if mdtables:
        td = getattr(mdtables, "TypeDef", None)
        if td:
            for row in td.rows:
                name = str(row.TypeName) if row.TypeName else ""
                ns = str(row.TypeNamespace) if row.TypeNamespace else ""
                if name and not name.startswith("<"):
                    info["types"].append(f"{ns}.{name}" if ns else name)

        md = getattr(mdtables, "MethodDef", None)
        if md:
            for row in md.rows:
                name = str(row.Name) if row.Name else ""
                if name and not name.startswith(".") and not name.startswith("<"):
                    info["methods"].append(name)

        # Get MemberRef for external method calls
        mr = getattr(mdtables, "MemberRef", None)
        if mr:
            for row in mr.rows:
                name = str(row.Name) if row.Name else ""
                if name:
                    info["methods"].append(f"[ref]{name}")

    info["strings"].extend(extract_user_strings(filepath))

    return info


def main():
    parser = argparse.ArgumentParser(description="Inspect LRSA .NET assemblies")
    parser.add_argument("--lrsa-dir", default=DEFAULT_LRSA_DIR)
    args = parser.parse_args()

    target_dlls = [
        "lenovo.mbg.service.common.webservices.dll",
        "lenovo.mbg.service.framework.smartbase.dll",
        "lenovo.mbg.service.framework.updateversion.dll",
        "lenovo.mbg.service.framework.smartdevice.dll",
        "lenovo.mbg.service.framework.devicemgt.dll",
        "lenovo.mbg.service.framework.services.dll",
        "lenovo.mbg.service.framework.hostcontroller.dll",
        "plugins/8ab04aa975e34f1ca4f9dc3a81374e2c/lenovo.mbg.service.lmsa.flash.dll",
        "Software Fix.exe",
        "LmsaWindowsService.exe",
    ]

    for dll_rel in target_dlls:
        filepath = os.path.join(args.lrsa_dir, dll_rel)
        if not os.path.exists(filepath):
            continue

        name = os.path.basename(dll_rel)
        get_logger(__name__).info(f"\n{'=' * 70}")
        get_logger(__name__).info(f"Analyzing: {name}")
        get_logger(__name__).info(f"{'=' * 70}")

        info = analyze_dll(filepath)
        if not info:
            get_logger(__name__).info("  Failed to parse")
            continue

        # Show types related to auth/API
        auth_types = [
            t
            for t in info["types"]
            if any(
                k in t.lower()
                for k in [
                    "api",
                    "auth",
                    "token",
                    "login",
                    "session",
                    "rsa",
                    "encrypt",
                    "request",
                    "web",
                    "http",
                    "service",
                    "rescue",
                    "rom",
                    "firmware",
                    "flash",
                    "download",
                    "context",
                    "config",
                    "init",
                    "connect",
                ]
            )
        ]
        if auth_types:
            get_logger(__name__).info(f"\n  Key Types ({len(auth_types)}):")
            for t in sorted(set(auth_types)):
                get_logger(__name__).info(f"    {t}")

        # Show methods related to auth
        auth_methods = [
            m
            for m in info["methods"]
            if any(
                k in m.lower()
                for k in [
                    "token",
                    "login",
                    "auth",
                    "rsa",
                    "encrypt",
                    "decrypt",
                    "init",
                    "request",
                    "header",
                    "session",
                    "connect",
                    "api",
                    "rescue",
                    "rom",
                    "firmware",
                    "download",
                    "match",
                    "getrom",
                    "getnew",
                ]
            )
        ]
        if auth_methods:
            get_logger(__name__).info(f"\n  Key Methods ({len(auth_methods)}):")
            for m in sorted(set(auth_methods)):
                get_logger(__name__).info(f"    {m}")

        # Show all string literals (these are the goldmine)
        if info["strings"]:
            relevant = [
                s
                for s in info["strings"]
                if any(
                    k in s.lower()
                    for k in [
                        "http",
                        "url",
                        "api",
                        "token",
                        "auth",
                        "login",
                        "key",
                        "encrypt",
                        "header",
                        "session",
                        "connection",
                        "jhtml",
                        "rescue",
                        "rom",
                        "firmware",
                        "model",
                        "imei",
                        "serial",
                        "device",
                        "json",
                        "content-type",
                        "bearer",
                        "authorization",
                    ]
                )
            ]
            if relevant:
                get_logger(__name__).info(
                    f"\n  Relevant String Literals ({len(relevant)}):"
                )
                for s in sorted(set(relevant)):
                    get_logger(__name__).info(f'    "{s}"')

            # Also show ALL strings for small DLLs
            if len(info["strings"]) < 100:
                get_logger(__name__).info(
                    f"\n  ALL String Literals ({len(info['strings'])}):"
                )
                for s in sorted(set(info["strings"])):
                    if len(s) > 2:
                        get_logger(__name__).info(f'    "{s}"')


if __name__ == "__main__":
    main()
