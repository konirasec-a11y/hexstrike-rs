#!/usr/bin/env python3
"""Compatibility shim: the implementation lives in the `hexstrike_server/` package.

This file is kept so existing commands keep working:
    python hexstrike_server.py            # runs the server
    from hexstrike_server import app      # library-style imports
"""
from hexstrike_server import *  # noqa: F401,F403
from hexstrike_server.main import main

if __name__ == '__main__':
    main()
