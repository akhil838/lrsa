#!/usr/bin/env python3
"""Compatibility wrapper for the standalone LRSA CLI."""

from .cli import main


if __name__ == "__main__":
    print("lrsa.standalone is deprecated; use python3 -m lrsa.cli instead.")
    main()
