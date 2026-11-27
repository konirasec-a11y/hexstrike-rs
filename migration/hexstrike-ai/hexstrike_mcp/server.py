"""HexStrike MCP - server setup (extracted 1:1)."""

from ._state import set_global as _set_global


def setup_mcp_server(hexstrike_client):
    """Set up the MCP server with all enhanced tool functions

Args:
    hexstrike_client: Initialized HexStrikeClient

Returns:
    Configured FastMCP instance"""
    _set_global('hexstrike_client', hexstrike_client)
    # tool registration happens in the ORIGINAL definition order:
    from .tools import (
        recon,
        cloud,
        files_env,
        network,
        binary,
        web_discovery,
        ai_api,
        api_forensics,
        server_admin,
        threat_intel,
        reporting,
        ai_intelligence,
        bugbounty,
        http_framework,
        error_handling,
    )
    from .mcp_instance import mcp
    return mcp
