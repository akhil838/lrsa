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

The package source lives under `src/lrsa`.
