"""HexStrike AI MCP Client (modular package, extracted 1:1)."""

import importlib as _importlib

from . import _compat_imports  # noqa: F401  (monolith header)
from ._state import set_global  # noqa: F401
from .config import (HexStrikeColors, Colors, ColoredFormatter, logger,
                     DEFAULT_HEXSTRIKE_SERVER, DEFAULT_REQUEST_TIMEOUT,
                     MAX_RETRIES)  # noqa: F401
from .client import HexStrikeClient  # noqa: F401
from .server import setup_mcp_server  # noqa: F401
from .main import main, parse_args  # noqa: F401

# import-binding re-exports (monolith namespace compat)
for _n in [
    'Any',
    'Dict',
    'FastMCP',
    'Optional',
    'argparse',
    'datetime',
    'handler',
    'logging',
    'os',
    'requests',
    'sys',
    'time',
]:
    for _mn in ("hexstrike_mcp._compat_imports", "hexstrike_mcp.config",
                "hexstrike_mcp.client", "hexstrike_mcp.mcp_instance",
                "hexstrike_mcp.server", "hexstrike_mcp.main"):
        try:
            _m = _importlib.import_module(_mn)
        except ImportError:
            continue
        if hasattr(_m, _n):
            globals()[_n] = getattr(_m, _n)
            break

__all__ = ['HexStrikeColors', 'Colors', 'ColoredFormatter', 'logger',
           'DEFAULT_HEXSTRIKE_SERVER', 'DEFAULT_REQUEST_TIMEOUT',
           'MAX_RETRIES', 'HexStrikeClient', 'setup_mcp_server',
           'parse_args', 'main', 'set_global'] + [
    'Any',
    'Dict',
    'FastMCP',
    'Optional',
    'argparse',
    'datetime',
    'handler',
    'logging',
    'os',
    'requests',
    'sys',
    'time',
]
