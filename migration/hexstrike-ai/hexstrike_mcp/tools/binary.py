"""HexStrike MCP tools - binary domain (extracted 1:1)."""

from ..mcp_instance import mcp  # noqa: F401
from ..client import hexstrike_client  # noqa: F401
from typing import Any, Dict
from ..config import logger


@mcp.tool()
def volatility_analyze(memory_file: str, plugin: str, profile: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Volatility for memory forensics analysis with enhanced logging.

    Args:
        memory_file: Path to memory dump file
        plugin: Volatility plugin to use
        profile: Memory profile to use
        additional_args: Additional Volatility arguments

    Returns:
        Memory forensics analysis results
    """
    data = {
        "memory_file": memory_file,
        "plugin": plugin,
        "profile": profile,
        "additional_args": additional_args
    }
    logger.info(f"🧠 Starting Volatility analysis: {plugin}")
    result = hexstrike_client.safe_post("api/tools/volatility", data)
    if result.get("success"):
        logger.info(f"✅ Volatility analysis completed")
    else:
        logger.error(f"❌ Volatility analysis failed")
    return result


@mcp.tool()
def msfvenom_generate(payload: str, format_type: str = "", output_file: str = "", encoder: str = "", iterations: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute MSFVenom for payload generation with enhanced logging.

    Args:
        payload: The payload to generate
        format_type: Output format (exe, elf, raw, etc.)
        output_file: Output file path
        encoder: Encoder to use
        iterations: Number of encoding iterations
        additional_args: Additional MSFVenom arguments

    Returns:
        Payload generation results
    """
    data = {
        "payload": payload,
        "format": format_type,
        "output_file": output_file,
        "encoder": encoder,
        "iterations": iterations,
        "additional_args": additional_args
    }
    logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
    result = hexstrike_client.safe_post("api/tools/msfvenom", data)
    if result.get("success"):
        logger.info(f"✅ MSFVenom payload generated")
    else:
        logger.error(f"❌ MSFVenom payload generation failed")
    return result


@mcp.tool()
def gdb_analyze(binary: str, commands: str = "", script_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute GDB for binary analysis and debugging with enhanced logging.

    Args:
        binary: Path to the binary file
        commands: GDB commands to execute
        script_file: Path to GDB script file
        additional_args: Additional GDB arguments

    Returns:
        Binary analysis results
    """
    data = {
        "binary": binary,
        "commands": commands,
        "script_file": script_file,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting GDB analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/gdb", data)
    if result.get("success"):
        logger.info(f"✅ GDB analysis completed for {binary}")
    else:
        logger.error(f"❌ GDB analysis failed for {binary}")
    return result


@mcp.tool()
def radare2_analyze(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Radare2 for binary analysis and reverse engineering with enhanced logging.

    Args:
        binary: Path to the binary file
        commands: Radare2 commands to execute
        additional_args: Additional Radare2 arguments

    Returns:
        Binary analysis results
    """
    data = {
        "binary": binary,
        "commands": commands,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Radare2 analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/radare2", data)
    if result.get("success"):
        logger.info(f"✅ Radare2 analysis completed for {binary}")
    else:
        logger.error(f"❌ Radare2 analysis failed for {binary}")
    return result


@mcp.tool()
def binwalk_analyze(file_path: str, extract: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Binwalk for firmware and file analysis with enhanced logging.

    Args:
        file_path: Path to the file to analyze
        extract: Whether to extract discovered files
        additional_args: Additional Binwalk arguments

    Returns:
        Firmware analysis results
    """
    data = {
        "file_path": file_path,
        "extract": extract,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
    result = hexstrike_client.safe_post("api/tools/binwalk", data)
    if result.get("success"):
        logger.info(f"✅ Binwalk analysis completed for {file_path}")
    else:
        logger.error(f"❌ Binwalk analysis failed for {file_path}")
    return result


@mcp.tool()
def ropgadget_search(binary: str, gadget_type: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Search for ROP gadgets in a binary using ROPgadget with enhanced logging.

    Args:
        binary: Path to the binary file
        gadget_type: Type of gadgets to search for
        additional_args: Additional ROPgadget arguments

    Returns:
        ROP gadget search results
    """
    data = {
        "binary": binary,
        "gadget_type": gadget_type,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting ROPgadget search: {binary}")
    result = hexstrike_client.safe_post("api/tools/ropgadget", data)
    if result.get("success"):
        logger.info(f"✅ ROPgadget search completed for {binary}")
    else:
        logger.error(f"❌ ROPgadget search failed for {binary}")
    return result


@mcp.tool()
def checksec_analyze(binary: str) -> Dict[str, Any]:
    """
    Check security features of a binary with enhanced logging.

    Args:
        binary: Path to the binary file

    Returns:
        Security features analysis results
    """
    data = {
        "binary": binary
    }
    logger.info(f"🔧 Starting Checksec analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/checksec", data)
    if result.get("success"):
        logger.info(f"✅ Checksec analysis completed for {binary}")
    else:
        logger.error(f"❌ Checksec analysis failed for {binary}")
    return result


@mcp.tool()
def xxd_hexdump(file_path: str, offset: str = "0", length: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Create a hex dump of a file using xxd with enhanced logging.

    Args:
        file_path: Path to the file
        offset: Offset to start reading from
        length: Number of bytes to read
        additional_args: Additional xxd arguments

    Returns:
        Hex dump results
    """
    data = {
        "file_path": file_path,
        "offset": offset,
        "length": length,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting XXD hex dump: {file_path}")
    result = hexstrike_client.safe_post("api/tools/xxd", data)
    if result.get("success"):
        logger.info(f"✅ XXD hex dump completed for {file_path}")
    else:
        logger.error(f"❌ XXD hex dump failed for {file_path}")
    return result


@mcp.tool()
def strings_extract(file_path: str, min_len: int = 4, additional_args: str = "") -> Dict[str, Any]:
    """
    Extract strings from a binary file with enhanced logging.

    Args:
        file_path: Path to the file
        min_len: Minimum string length
        additional_args: Additional strings arguments

    Returns:
        String extraction results
    """
    data = {
        "file_path": file_path,
        "min_len": min_len,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Strings extraction: {file_path}")
    result = hexstrike_client.safe_post("api/tools/strings", data)
    if result.get("success"):
        logger.info(f"✅ Strings extraction completed for {file_path}")
    else:
        logger.error(f"❌ Strings extraction failed for {file_path}")
    return result


@mcp.tool()
def objdump_analyze(binary: str, disassemble: bool = True, additional_args: str = "") -> Dict[str, Any]:
    """
    Analyze a binary using objdump with enhanced logging.

    Args:
        binary: Path to the binary file
        disassemble: Whether to disassemble the binary
        additional_args: Additional objdump arguments

    Returns:
        Binary analysis results
    """
    data = {
        "binary": binary,
        "disassemble": disassemble,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Objdump analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/objdump", data)
    if result.get("success"):
        logger.info(f"✅ Objdump analysis completed for {binary}")
    else:
        logger.error(f"❌ Objdump analysis failed for {binary}")
    return result


@mcp.tool()
def ghidra_analysis(binary: str, project_name: str = "hexstrike_analysis",
                   script_file: str = "", analysis_timeout: int = 300,
                   output_format: str = "xml", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Ghidra for advanced binary analysis and reverse engineering.

    Args:
        binary: Path to the binary file
        project_name: Ghidra project name
        script_file: Custom Ghidra script to run
        analysis_timeout: Analysis timeout in seconds
        output_format: Output format (xml, json)
        additional_args: Additional Ghidra arguments

    Returns:
        Advanced binary analysis results from Ghidra
    """
    data = {
        "binary": binary,
        "project_name": project_name,
        "script_file": script_file,
        "analysis_timeout": analysis_timeout,
        "output_format": output_format,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Ghidra analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/ghidra", data)
    if result.get("success"):
        logger.info(f"✅ Ghidra analysis completed for {binary}")
    else:
        logger.error(f"❌ Ghidra analysis failed for {binary}")
    return result


@mcp.tool()
def pwntools_exploit(script_content: str = "", target_binary: str = "",
                    target_host: str = "", target_port: int = 0,
                    exploit_type: str = "local", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Pwntools for exploit development and automation.

    Args:
        script_content: Python script content using pwntools
        target_binary: Local binary to exploit
        target_host: Remote host to connect to
        target_port: Remote port to connect to
        exploit_type: Type of exploit (local, remote, format_string, rop)
        additional_args: Additional arguments

    Returns:
        Exploit execution results
    """
    data = {
        "script_content": script_content,
        "target_binary": target_binary,
        "target_host": target_host,
        "target_port": target_port,
        "exploit_type": exploit_type,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
    result = hexstrike_client.safe_post("api/tools/pwntools", data)
    if result.get("success"):
        logger.info(f"✅ Pwntools exploit completed")
    else:
        logger.error(f"❌ Pwntools exploit failed")
    return result


@mcp.tool()
def one_gadget_search(libc_path: str, level: int = 1, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute one_gadget to find one-shot RCE gadgets in libc.

    Args:
        libc_path: Path to libc binary
        level: Constraint level (0, 1, 2)
        additional_args: Additional one_gadget arguments

    Returns:
        One-shot RCE gadget search results
    """
    data = {
        "libc_path": libc_path,
        "level": level,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
    result = hexstrike_client.safe_post("api/tools/one-gadget", data)
    if result.get("success"):
        logger.info(f"✅ one_gadget analysis completed")
    else:
        logger.error(f"❌ one_gadget analysis failed")
    return result


@mcp.tool()
def libc_database_lookup(action: str = "find", symbols: str = "",
                        libc_id: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute libc-database for libc identification and offset lookup.

    Args:
        action: Action to perform (find, dump, download)
        symbols: Symbols with offsets for find action (format: "symbol1:offset1 symbol2:offset2")
        libc_id: Libc ID for dump/download actions
        additional_args: Additional arguments

    Returns:
        Libc database lookup results
    """
    data = {
        "action": action,
        "symbols": symbols,
        "libc_id": libc_id,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
    result = hexstrike_client.safe_post("api/tools/libc-database", data)
    if result.get("success"):
        logger.info(f"✅ libc-database {action} completed")
    else:
        logger.error(f"❌ libc-database {action} failed")
    return result


@mcp.tool()
def gdb_peda_debug(binary: str = "", commands: str = "", attach_pid: int = 0,
                  core_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute GDB with PEDA for enhanced debugging and exploitation.

    Args:
        binary: Binary to debug
        commands: GDB commands to execute
        attach_pid: Process ID to attach to
        core_file: Core dump file to analyze
        additional_args: Additional GDB arguments

    Returns:
        Enhanced debugging results with PEDA
    """
    data = {
        "binary": binary,
        "commands": commands,
        "attach_pid": attach_pid,
        "core_file": core_file,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting GDB-PEDA analysis: {binary or f'PID {attach_pid}' or core_file}")
    result = hexstrike_client.safe_post("api/tools/gdb-peda", data)
    if result.get("success"):
        logger.info(f"✅ GDB-PEDA analysis completed")
    else:
        logger.error(f"❌ GDB-PEDA analysis failed")
    return result


@mcp.tool()
def angr_symbolic_execution(binary: str, script_content: str = "",
                           find_address: str = "", avoid_addresses: str = "",
                           analysis_type: str = "symbolic", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute angr for symbolic execution and binary analysis.

    Args:
        binary: Binary to analyze
        script_content: Custom angr script content
        find_address: Address to find during symbolic execution
        avoid_addresses: Comma-separated addresses to avoid
        analysis_type: Type of analysis (symbolic, cfg, static)
        additional_args: Additional arguments

    Returns:
        Symbolic execution and binary analysis results
    """
    data = {
        "binary": binary,
        "script_content": script_content,
        "find_address": find_address,
        "avoid_addresses": avoid_addresses,
        "analysis_type": analysis_type,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting angr analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/angr", data)
    if result.get("success"):
        logger.info(f"✅ angr analysis completed")
    else:
        logger.error(f"❌ angr analysis failed")
    return result


@mcp.tool()
def ropper_gadget_search(binary: str, gadget_type: str = "rop", quality: int = 1,
                        arch: str = "", search_string: str = "",
                        additional_args: str = "") -> Dict[str, Any]:
    """
    Execute ropper for advanced ROP/JOP gadget searching.

    Args:
        binary: Binary to search for gadgets
        gadget_type: Type of gadgets (rop, jop, sys, all)
        quality: Gadget quality level (1-5)
        arch: Target architecture (x86, x86_64, arm, etc.)
        search_string: Specific gadget pattern to search for
        additional_args: Additional ropper arguments

    Returns:
        Advanced ROP/JOP gadget search results
    """
    data = {
        "binary": binary,
        "gadget_type": gadget_type,
        "quality": quality,
        "arch": arch,
        "search_string": search_string,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting ropper analysis: {binary}")
    result = hexstrike_client.safe_post("api/tools/ropper", data)
    if result.get("success"):
        logger.info(f"✅ ropper analysis completed")
    else:
        logger.error(f"❌ ropper analysis failed")
    return result


@mcp.tool()
def pwninit_setup(binary: str, libc: str = "", ld: str = "",
                 template_type: str = "python", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute pwninit for CTF binary exploitation setup.

    Args:
        binary: Binary file to set up
        libc: Libc file to use
        ld: Loader file to use
        template_type: Template type (python, c)
        additional_args: Additional pwninit arguments

    Returns:
        CTF binary exploitation setup results
    """
    data = {
        "binary": binary,
        "libc": libc,
        "ld": ld,
        "template_type": template_type,
        "additional_args": additional_args
    }
    logger.info(f"🔧 Starting pwninit setup: {binary}")
    result = hexstrike_client.safe_post("api/tools/pwninit", data)
    if result.get("success"):
        logger.info(f"✅ pwninit setup completed")
    else:
        logger.error(f"❌ pwninit setup failed")
    return result
