"""HexStrike MCP tools - network domain (extracted 1:1)."""

from ..mcp_instance import mcp  # noqa: F401
from ..client import hexstrike_client  # noqa: F401
from typing import Any, Dict
from ..config import logger


@mcp.tool()
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Dirb for directory brute forcing with enhanced logging.

    Args:
        url: The target URL
        wordlist: Path to wordlist file
        additional_args: Additional Dirb arguments

    Returns:
        Scan results with enhanced telemetry
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "additional_args": additional_args
    }
    logger.info(f"📁 Starting Dirb scan: {url}")
    result = hexstrike_client.safe_post("api/tools/dirb", data)
    if result.get("success"):
        logger.info(f"✅ Dirb scan completed for {url}")
    else:
        logger.error(f"❌ Dirb scan failed for {url}")
    return result


@mcp.tool()
def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Nikto web vulnerability scanner with enhanced logging.

    Args:
        target: The target URL or IP
        additional_args: Additional Nikto arguments

    Returns:
        Scan results with discovered vulnerabilities
    """
    data = {
        "target": target,
        "additional_args": additional_args
    }
    logger.info(f"🔬 Starting Nikto scan: {target}")
    result = hexstrike_client.safe_post("api/tools/nikto", data)
    if result.get("success"):
        logger.info(f"✅ Nikto scan completed for {target}")
    else:
        logger.error(f"❌ Nikto scan failed for {target}")
    return result


@mcp.tool()
def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute SQLMap for SQL injection testing with enhanced logging.

    Args:
        url: The target URL
        data: POST data for testing
        additional_args: Additional SQLMap arguments

    Returns:
        SQL injection test results
    """
    data_payload = {
        "url": url,
        "data": data,
        "additional_args": additional_args
    }
    logger.info(f"💉 Starting SQLMap scan: {url}")
    result = hexstrike_client.safe_post("api/tools/sqlmap", data_payload)
    if result.get("success"):
        logger.info(f"✅ SQLMap scan completed for {url}")
    else:
        logger.error(f"❌ SQLMap scan failed for {url}")
    return result


@mcp.tool()
def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
    """
    Execute a Metasploit module with enhanced logging.

    Args:
        module: The Metasploit module to use
        options: Dictionary of module options

    Returns:
        Metasploit execution results
    """
    data = {
        "module": module,
        "options": options
    }
    logger.info(f"🚀 Starting Metasploit module: {module}")
    result = hexstrike_client.safe_post("api/tools/metasploit", data)
    if result.get("success"):
        logger.info(f"✅ Metasploit module completed: {module}")
    else:
        logger.error(f"❌ Metasploit module failed: {module}")
    return result


@mcp.tool()
def hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    Execute Hydra for password brute forcing with enhanced logging.

    Args:
        target: The target IP or hostname
        service: The service to attack (ssh, ftp, http, etc.)
        username: Single username to test
        username_file: File containing usernames
        password: Single password to test
        password_file: File containing passwords
        additional_args: Additional Hydra arguments

    Returns:
        Brute force attack results
    """
    data = {
        "target": target,
        "service": service,
        "username": username,
        "username_file": username_file,
        "password": password,
        "password_file": password_file,
        "additional_args": additional_args
    }
    logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
    result = hexstrike_client.safe_post("api/tools/hydra", data)
    if result.get("success"):
        logger.info(f"✅ Hydra attack completed for {target}")
    else:
        logger.error(f"❌ Hydra attack failed for {target}")
    return result


@mcp.tool()
def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format_type: str = "",
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    Execute John the Ripper for password cracking with enhanced logging.

    Args:
        hash_file: File containing password hashes
        wordlist: Wordlist file to use
        format_type: Hash format type
        additional_args: Additional John arguments

    Returns:
        Password cracking results
    """
    data = {
        "hash_file": hash_file,
        "wordlist": wordlist,
        "format": format_type,
        "additional_args": additional_args
    }
    logger.info(f"🔐 Starting John the Ripper: {hash_file}")
    result = hexstrike_client.safe_post("api/tools/john", data)
    if result.get("success"):
        logger.info(f"✅ John the Ripper completed")
    else:
        logger.error(f"❌ John the Ripper failed")
    return result


@mcp.tool()
def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute WPScan for WordPress vulnerability scanning with enhanced logging.

    Args:
        url: The WordPress site URL
        additional_args: Additional WPScan arguments

    Returns:
        WordPress vulnerability scan results
    """
    data = {
        "url": url,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting WPScan: {url}")
    result = hexstrike_client.safe_post("api/tools/wpscan", data)
    if result.get("success"):
        logger.info(f"✅ WPScan completed for {url}")
    else:
        logger.error(f"❌ WPScan failed for {url}")
    return result


@mcp.tool()
def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
    """
    Execute Enum4linux for SMB enumeration with enhanced logging.

    Args:
        target: The target IP address
        additional_args: Additional Enum4linux arguments

    Returns:
        SMB enumeration results
    """
    data = {
        "target": target,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Enum4linux: {target}")
    result = hexstrike_client.safe_post("api/tools/enum4linux", data)
    if result.get("success"):
        logger.info(f"✅ Enum4linux completed for {target}")
    else:
        logger.error(f"❌ Enum4linux failed for {target}")
    return result


@mcp.tool()
def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "directory", match_codes: str = "200,204,301,302,307,401,403", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute FFuf for web fuzzing with enhanced logging.

    Args:
        url: The target URL
        wordlist: Wordlist file to use
        mode: Fuzzing mode (directory, vhost, parameter)
        match_codes: HTTP status codes to match
        additional_args: Additional FFuf arguments

    Returns:
        Web fuzzing results
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "mode": mode,
        "match_codes": match_codes,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
    result = hexstrike_client.safe_post("api/tools/ffuf", data)
    if result.get("success"):
        logger.info(f"✅ FFuf fuzzing completed for {url}")
    else:
        logger.error(f"❌ FFuf fuzzing failed for {url}")
    return result


@mcp.tool()
def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "", hash_value: str = "", module: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute NetExec (formerly CrackMapExec) for network enumeration with enhanced logging.

    Args:
        target: The target IP or network
        protocol: Protocol to use (smb, ssh, winrm, etc.)
        username: Username for authentication
        password: Password for authentication
        hash_value: Hash for pass-the-hash attacks
        module: NetExec module to execute
        additional_args: Additional NetExec arguments

    Returns:
        Network enumeration results
    """
    data = {
        "target": target,
        "protocol": protocol,
        "username": username,
        "password": password,
        "hash": hash_value,
        "module": module,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting NetExec {protocol} scan: {target}")
    result = hexstrike_client.safe_post("api/tools/netexec", data)
    if result.get("success"):
        logger.info(f"✅ NetExec scan completed for {target}")
    else:
        logger.error(f"❌ NetExec scan failed for {target}")
    return result


@mcp.tool()
def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Amass for subdomain enumeration with enhanced logging.

    Args:
        domain: The target domain
        mode: Amass mode (enum, intel, viz)
        additional_args: Additional Amass arguments

    Returns:
        Subdomain enumeration results
    """
    data = {
        "domain": domain,
        "mode": mode,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Amass {mode}: {domain}")
    result = hexstrike_client.safe_post("api/tools/amass", data)
    if result.get("success"):
        logger.info(f"✅ Amass completed for {domain}")
    else:
        logger.error(f"❌ Amass failed for {domain}")
    return result


@mcp.tool()
def hashcat_crack(hash_file: str, hash_type: str, attack_mode: str = "0", wordlist: str = "/usr/share/wordlists/rockyou.txt", mask: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Hashcat for advanced password cracking with enhanced logging.

    Args:
        hash_file: File containing password hashes
        hash_type: Hash type number for Hashcat
        attack_mode: Attack mode (0=dict, 1=combo, 3=mask, etc.)
        wordlist: Wordlist file for dictionary attacks
        mask: Mask for mask attacks
        additional_args: Additional Hashcat arguments

    Returns:
        Password cracking results
    """
    data = {
        "hash_file": hash_file,
        "hash_type": hash_type,
        "attack_mode": attack_mode,
        "wordlist": wordlist,
        "mask": mask,
        "additional_args": additional_args
    }
    logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
    result = hexstrike_client.safe_post("api/tools/hashcat", data)
    if result.get("success"):
        logger.info(f"✅ Hashcat attack completed")
    else:
        logger.error(f"❌ Hashcat attack failed")
    return result


@mcp.tool()
def subfinder_scan(domain: str, silent: bool = True, all_sources: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Subfinder for passive subdomain enumeration with enhanced logging.

    Args:
        domain: The target domain
        silent: Run in silent mode
        all_sources: Use all sources
        additional_args: Additional Subfinder arguments

    Returns:
        Passive subdomain enumeration results
    """
    data = {
        "domain": domain,
        "silent": silent,
        "all_sources": all_sources,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Subfinder: {domain}")
    result = hexstrike_client.safe_post("api/tools/subfinder", data)
    if result.get("success"):
        logger.info(f"✅ Subfinder completed for {domain}")
    else:
        logger.error(f"❌ Subfinder failed for {domain}")
    return result


@mcp.tool()
def smbmap_scan(target: str, username: str = "", password: str = "", domain: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute SMBMap for SMB share enumeration with enhanced logging.

    Args:
        target: The target IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain for authentication
        additional_args: Additional SMBMap arguments

    Returns:
        SMB share enumeration results
    """
    data = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting SMBMap: {target}")
    result = hexstrike_client.safe_post("api/tools/smbmap", data)
    if result.get("success"):
        logger.info(f"✅ SMBMap completed for {target}")
    else:
        logger.error(f"❌ SMBMap failed for {target}")
    return result


@mcp.tool()
def rustscan_fast_scan(target: str, ports: str = "", ulimit: int = 5000,
                      batch_size: int = 4500, timeout: int = 1500,
                      scripts: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Rustscan for ultra-fast port scanning with enhanced logging.

    Args:
        target: The target IP address or hostname
        ports: Specific ports to scan (e.g., "22,80,443")
        ulimit: File descriptor limit
        batch_size: Batch size for scanning
        timeout: Timeout in milliseconds
        scripts: Run Nmap scripts on discovered ports
        additional_args: Additional Rustscan arguments

    Returns:
        Ultra-fast port scanning results
    """
    data = {
        "target": target,
        "ports": ports,
        "ulimit": ulimit,
        "batch_size": batch_size,
        "timeout": timeout,
        "scripts": scripts,
        "additional_args": additional_args
    }
    logger.info(f"⚡ Starting Rustscan: {target}")
    result = hexstrike_client.safe_post("api/tools/rustscan", data)
    if result.get("success"):
        logger.info(f"✅ Rustscan completed for {target}")
    else:
        logger.error(f"❌ Rustscan failed for {target}")
    return result


@mcp.tool()
def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000,
                      interface: str = "", router_mac: str = "", source_ip: str = "",
                      banners: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting.

    Args:
        target: The target IP address or CIDR range
        ports: Port range to scan
        rate: Packets per second rate
        interface: Network interface to use
        router_mac: Router MAC address
        source_ip: Source IP address
        banners: Enable banner grabbing
        additional_args: Additional Masscan arguments

    Returns:
        High-speed port scanning results with intelligent rate limiting
    """
    data = {
        "target": target,
        "ports": ports,
        "rate": rate,
        "interface": interface,
        "router_mac": router_mac,
        "source_ip": source_ip,
        "banners": banners,
        "additional_args": additional_args
    }
    logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
    result = hexstrike_client.safe_post("api/tools/masscan", data)
    if result.get("success"):
        logger.info(f"✅ Masscan completed for {target}")
    else:
        logger.error(f"❌ Masscan failed for {target}")
    return result


@mcp.tool()
def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                      timing: str = "T4", nse_scripts: str = "", os_detection: bool = False,
                      version_detection: bool = False, aggressive: bool = False,
                      stealth: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute advanced Nmap scans with custom NSE scripts and optimized timing.

    Args:
        target: The target IP address or hostname
        scan_type: Nmap scan type (e.g., -sS, -sT, -sU)
        ports: Specific ports to scan
        timing: Timing template (T0-T5)
        nse_scripts: Custom NSE scripts to run
        os_detection: Enable OS detection
        version_detection: Enable version detection
        aggressive: Enable aggressive scanning
        stealth: Enable stealth mode
        additional_args: Additional Nmap arguments

    Returns:
        Advanced Nmap scanning results with custom NSE scripts
    """
    data = {
        "target": target,
        "scan_type": scan_type,
        "ports": ports,
        "timing": timing,
        "nse_scripts": nse_scripts,
        "os_detection": os_detection,
        "version_detection": version_detection,
        "aggressive": aggressive,
        "stealth": stealth,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Advanced Nmap: {target}")
    result = hexstrike_client.safe_post("api/tools/nmap-advanced", data)
    if result.get("success"):
        logger.info(f"✅ Advanced Nmap completed for {target}")
    else:
        logger.error(f"❌ Advanced Nmap failed for {target}")
    return result


@mcp.tool()
def autorecon_comprehensive(target: str, output_dir: str = "/tmp/autorecon",
                           port_scans: str = "top-100-ports", service_scans: str = "default",
                           heartbeat: int = 60, timeout: int = 300,
                           additional_args: str = "") -> Dict[str, Any]:
    """
    Execute AutoRecon for comprehensive automated reconnaissance.

    Args:
        target: The target IP address or hostname
        output_dir: Output directory for results
        port_scans: Port scan configuration
        service_scans: Service scan configuration
        heartbeat: Heartbeat interval in seconds
        timeout: Timeout for individual scans
        additional_args: Additional AutoRecon arguments

    Returns:
        Comprehensive automated reconnaissance results
    """
    data = {
        "target": target,
        "output_dir": output_dir,
        "port_scans": port_scans,
        "service_scans": service_scans,
        "heartbeat": heartbeat,
        "timeout": timeout,
        "additional_args": additional_args
    }
    logger.info(f"🔄 Starting AutoRecon: {target}")
    result = hexstrike_client.safe_post("api/tools/autorecon", data)
    if result.get("success"):
        logger.info(f"✅ AutoRecon completed for {target}")
    else:
        logger.error(f"❌ AutoRecon failed for {target}")
    return result


@mcp.tool()
def enum4linux_ng_advanced(target: str, username: str = "", password: str = "",
                           domain: str = "", shares: bool = True, users: bool = True,
                           groups: bool = True, policy: bool = True,
                           additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging.

    Args:
        target: The target IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain for authentication
        shares: Enumerate shares
        users: Enumerate users
        groups: Enumerate groups
        policy: Enumerate policies
        additional_args: Additional Enum4linux-ng arguments

    Returns:
        Advanced SMB enumeration results
    """
    data = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "shares": shares,
        "users": users,
        "groups": groups,
        "policy": policy,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Enum4linux-ng: {target}")
    result = hexstrike_client.safe_post("api/tools/enum4linux-ng", data)
    if result.get("success"):
        logger.info(f"✅ Enum4linux-ng completed for {target}")
    else:
        logger.error(f"❌ Enum4linux-ng failed for {target}")
    return result


@mcp.tool()
def rpcclient_enumeration(target: str, username: str = "", password: str = "",
                         domain: str = "", commands: str = "enumdomusers;enumdomgroups;querydominfo",
                         additional_args: str = "") -> Dict[str, Any]:
    """
    Execute rpcclient for RPC enumeration with enhanced logging.

    Args:
        target: The target IP address
        username: Username for authentication
        password: Password for authentication
        domain: Domain for authentication
        commands: Semicolon-separated RPC commands
        additional_args: Additional rpcclient arguments

    Returns:
        RPC enumeration results
    """
    data = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "commands": commands,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting rpcclient: {target}")
    result = hexstrike_client.safe_post("api/tools/rpcclient", data)
    if result.get("success"):
        logger.info(f"✅ rpcclient completed for {target}")
    else:
        logger.error(f"❌ rpcclient failed for {target}")
    return result


@mcp.tool()
def nbtscan_netbios(target: str, verbose: bool = False, timeout: int = 2,
                   additional_args: str = "") -> Dict[str, Any]:
    """
    Execute nbtscan for NetBIOS name scanning with enhanced logging.

    Args:
        target: The target IP address or range
        verbose: Enable verbose output
        timeout: Timeout in seconds
        additional_args: Additional nbtscan arguments

    Returns:
        NetBIOS name scanning results
    """
    data = {
        "target": target,
        "verbose": verbose,
        "timeout": timeout,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting nbtscan: {target}")
    result = hexstrike_client.safe_post("api/tools/nbtscan", data)
    if result.get("success"):
        logger.info(f"✅ nbtscan completed for {target}")
    else:
        logger.error(f"❌ nbtscan failed for {target}")
    return result


@mcp.tool()
def arp_scan_discovery(target: str = "", interface: str = "", local_network: bool = False,
                      timeout: int = 500, retry: int = 3, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute arp-scan for network discovery with enhanced logging.

    Args:
        target: The target IP range (if not using local_network)
        interface: Network interface to use
        local_network: Scan local network
        timeout: Timeout in milliseconds
        retry: Number of retries
        additional_args: Additional arp-scan arguments

    Returns:
        Network discovery results via ARP scanning
    """
    data = {
        "target": target,
        "interface": interface,
        "local_network": local_network,
        "timeout": timeout,
        "retry": retry,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
    result = hexstrike_client.safe_post("api/tools/arp-scan", data)
    if result.get("success"):
        logger.info(f"✅ arp-scan completed")
    else:
        logger.error(f"❌ arp-scan failed")
    return result


@mcp.tool()
def responder_credential_harvest(interface: str = "eth0", analyze: bool = False,
                               wpad: bool = True, force_wpad_auth: bool = False,
                               fingerprint: bool = False, duration: int = 300,
                               additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Responder for credential harvesting with enhanced logging.

    Args:
        interface: Network interface to use
        analyze: Analyze mode only
        wpad: Enable WPAD rogue proxy
        force_wpad_auth: Force WPAD authentication
        fingerprint: Fingerprint mode
        duration: Duration to run in seconds
        additional_args: Additional Responder arguments

    Returns:
        Credential harvesting results
    """
    data = {
        "interface": interface,
        "analyze": analyze,
        "wpad": wpad,
        "force_wpad_auth": force_wpad_auth,
        "fingerprint": fingerprint,
        "duration": duration,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Responder on interface: {interface}")
    result = hexstrike_client.safe_post("api/tools/responder", data)
    if result.get("success"):
        logger.info(f"✅ Responder completed")
    else:
        logger.error(f"❌ Responder failed")
    return result
