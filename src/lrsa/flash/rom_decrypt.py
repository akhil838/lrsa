"""Decrypt Software Fix encrypted ROM helper files."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .constants import DEFAULT_DECRYPT_PASSWORD, ROM_DECRYPT_MAGIC


def password_derive_bytes_sha256(
    password: str, salt: bytes, length: int, iterations: int = 1000
) -> bytes:
    """Match .NET PasswordDeriveBytes(password, salt, "SHA256", iterations)."""
    base = hashlib.sha256(password.encode("utf-8") + salt).digest()
    for _ in range(iterations - 1):
        base = hashlib.sha256(base).digest()

    output = bytearray()
    prefix = 0
    while len(output) < length:
        if prefix == 0:
            block = base
        else:
            block = hashlib.sha256(str(prefix).encode("ascii") + base).digest()
        output.extend(block)
        prefix += 1
    return bytes(output[:length])


def decrypted_path_for(path: Path) -> Path:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".t":
        return Path(str(path) + "xt")
    if suffix == ".x":
        return Path(str(path) + "ml")
    raise ValueError(f"Unsupported encrypted ROM file suffix: {path.suffix}")


def decrypt_file(
    source: Path, output: Path | None = None, password: str = DEFAULT_DECRYPT_PASSWORD
) -> Path:
    source = Path(source)
    output = Path(output) if output else decrypted_path_for(source)
    data = source.read_bytes()
    if len(data) < 48:
        raise ValueError(f"Encrypted file is too small: {source}")

    iv = data[:16]
    salt = data[16:32]
    encrypted = data[32:]
    key = password_derive_bytes_sha256(password, salt, 32)
    payload = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted), AES.block_size)

    if len(payload) < 48:
        raise ValueError(f"Decrypted payload is too small: {source}")
    size = struct.unpack_from("<q", payload, 0)[0]
    magic = struct.unpack_from("<Q", payload, 8)[0]
    if magic != ROM_DECRYPT_MAGIC:
        raise ValueError(f"Encrypted file magic mismatch: {source}")

    start = 16
    end = start + size
    plaintext = payload[start:end]
    expected_hash = payload[end : end + hashlib.sha256().digest_size]
    if len(plaintext) != size:
        raise ValueError(f"Encrypted file size mismatch: {source}")
    if hashlib.sha256(plaintext).digest() != expected_hash:
        raise ValueError(f"Encrypted file hash mismatch: {source}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)
    return output


def decrypt_rom_files(
    rom_dir: Path,
    file_types: str = "*.t|*.x",
    password: str = DEFAULT_DECRYPT_PASSWORD,
    overwrite: bool = False,
) -> list[Path]:
    rom_dir = Path(rom_dir)
    outputs: list[Path] = []
    for pattern in [part.strip() for part in file_types.split("|") if part.strip()]:
        for source in sorted(rom_dir.rglob(pattern)):
            output = decrypted_path_for(source)
            if output.exists() and not overwrite:
                outputs.append(output)
                continue
            outputs.append(decrypt_file(source, output, password))
    return outputs
