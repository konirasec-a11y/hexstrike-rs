"""HexStrike MCP - shared FastMCP instance.

Originally created inside setup_mcp_server(); now a package singleton
so the extracted tool modules can register against it.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('hexstrike-ai-mcp')
