# lrsa

Native Python Lenovo Software Fix / LRSA rescue workflow.

## Setup

Install `uv`, then clone and sync:

```bash
git clone https://github.com/akhil838/lrsa.git
cd lrsa
uv sync
```

This project depends on `qfil` from:

```text
https://github.com/akhil838/qfil.git
```

If the repository is private, make sure GitHub HTTPS credentials are available before running `uv sync`.

## Usage

Run the CLI:

```bash
uv run lrsa --help
```

Run the menu:

```bash
uv run lrsa-menu
```

Python import:

```python
import lrsa
```

## Source Layout

The package source lives under `src/lrsa`:

- `api/`: LRSA API client, endpoints, resource parsing, and downloads
- `auth/`: Lenovo ID, Passport, token capture, and login helpers
- `core/`: shared primitives such as crypto
- `device/`: USB and fastboot preflight checks
- `flash/`: Software Fix flow, QFIL integration, boot-chain checks, and ROM decrypt helpers
- `diagnostics/`: static analysis and unlock research utilities
- `servers/`: local capture and relay server entrypoints
