#!/usr/bin/env python3
"""Compatibility shim: the implementation lives in the `hexstrike_mcp/` package."""
from hexstrike_mcp import *  # noqa: F401,F403

if __name__ == '__main__':
    from hexstrike_mcp.main import main
    main()
