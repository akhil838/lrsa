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

Run the desktop GUI:

```bash
uv run lrsa-gui
```

Capture a fresh Lenovo ID session for catalog/API verification:

```bash
sudo uv run lrsa-capture-login --login-url-mode software-fix-api --test-token
```

This starts the local HTTPS callback capture used by the original Software Fix flow, saves artifacts under `lrsa_work/capture/`, and writes a fresh `login_session.json` you can import in the GUI.

The GUI provides:

- Lenovo ID and guest login, session save/load, and logout
- automatic ADB, fastboot, and Qualcomm EDL device detection
- device detail inspection
- Lenovo rescue ROM lookup by Model/SN or IMEI
- ROM listing and selected-ROM detail view
- matched resource preparation for ROM, tool, and country-code packages
- firmware download, extraction, and ROM helper decrypt preparation
- local ROM folder / `Rescue.cmd` picker
- flash-plan preview and guarded ROM install
Typical GUI flow:
1. Open **Login** and start **Guest login** or **Lenovo ID** login.
2. Open **Firmware** and list ROMs by Model/SN or IMEI.
3. Select a ROM and click **Prepare selected ROM**.
4. Open **ROM Install** to validate the prepared package and flash it.

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
