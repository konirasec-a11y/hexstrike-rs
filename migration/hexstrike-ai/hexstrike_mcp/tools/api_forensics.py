"""HexStrike MCP tools - api_forensics domain (extracted 1:1)."""

from ..mcp_instance import mcp  # noqa: F401
from ..client import hexstrike_client  # noqa: F401
from typing import Any, Dict
import time
from ..config import logger


@mcp.tool()
def api_schema_analyzer(schema_url: str, schema_type: str = "openapi") -> Dict[str, Any]:
    """
    Analyze API schemas and identify potential security issues.

    Args:
        schema_url: URL to the API schema (OpenAPI/Swagger/GraphQL)
        schema_type: Type of schema (openapi, swagger, graphql)

    Returns:
        Schema analysis results with security issues and recommendations
    """
    data = {
        "schema_url": schema_url,
        "schema_type": schema_type
    }

    logger.info(f"🔍 Starting API schema analysis: {schema_url}")
    result = hexstrike_client.safe_post("api/tools/api_schema_analyzer", data)

    if result.get("success"):
        analysis = result.get("schema_analysis_results", {})
        endpoint_count = len(analysis.get("endpoints_found", []))
        issue_count = len(analysis.get("security_issues", []))

        logger.info(f"✅ Schema analysis completed: {endpoint_count} endpoints, {issue_count} issues")

        if issue_count > 0:
            logger.warning(f"⚠️  Found {issue_count} security issues in schema!")
            for issue in analysis.get("security_issues", [])[:3]:  # Show first 3
                severity = issue.get("severity", "UNKNOWN")
                issue_type = issue.get("issue", "unknown")
                logger.warning(f"   ├─ [{severity}] {issue_type}")

        if endpoint_count > 0:
            logger.info(f"📊 Discovered endpoints:")
            for endpoint in analysis.get("endpoints_found", [])[:5]:  # Show first 5
                method = endpoint.get("method", "GET")
                path = endpoint.get("path", "/")
                logger.info(f"   ├─ {method} {path}")
    else:
        logger.error("❌ Schema analysis failed")

    return result


@mcp.tool()
def comprehensive_api_audit(base_url: str, schema_url: str = "", jwt_token: str = "", graphql_endpoint: str = "") -> Dict[str, Any]:
    """
    Comprehensive API security audit combining multiple testing techniques.

    Args:
        base_url: Base URL of the API
        schema_url: Optional API schema URL
        jwt_token: Optional JWT token for analysis
        graphql_endpoint: Optional GraphQL endpoint

    Returns:
        Comprehensive audit results with all API security tests
    """
    audit_results = {
        "base_url": base_url,
        "audit_timestamp": time.time(),
        "tests_performed": [],
        "total_vulnerabilities": 0,
        "summary": {},
        "recommendations": []
    }

    logger.info(f"🚀 Starting comprehensive API security audit: {base_url}")

    # 1. API Endpoint Fuzzing
    logger.info("🔍 Phase 1: API endpoint discovery and fuzzing")
    fuzz_result = self.api_fuzzer(base_url)
    if fuzz_result.get("success"):
        audit_results["tests_performed"].append("api_fuzzing")
        audit_results["api_fuzzing"] = fuzz_result

    # 2. Schema Analysis (if provided)
    if schema_url:
        logger.info("🔍 Phase 2: API schema analysis")
        schema_result = self.api_schema_analyzer(schema_url)
        if schema_result.get("success"):
            audit_results["tests_performed"].append("schema_analysis")
            audit_results["schema_analysis"] = schema_result

            schema_data = schema_result.get("schema_analysis_results", {})
            audit_results["total_vulnerabilities"] += len(schema_data.get("security_issues", []))

    # 3. JWT Analysis (if provided)
    if jwt_token:
        logger.info("🔍 Phase 3: JWT token analysis")
        jwt_result = self.jwt_analyzer(jwt_token, base_url)
        if jwt_result.get("success"):
            audit_results["tests_performed"].append("jwt_analysis")
            audit_results["jwt_analysis"] = jwt_result

            jwt_data = jwt_result.get("jwt_analysis_results", {})
            audit_results["total_vulnerabilities"] += len(jwt_data.get("vulnerabilities", []))

    # 4. GraphQL Testing (if provided)
    if graphql_endpoint:
        logger.info("🔍 Phase 4: GraphQL security scanning")
        graphql_result = self.graphql_scanner(graphql_endpoint)
        if graphql_result.get("success"):
            audit_results["tests_performed"].append("graphql_scanning")
            audit_results["graphql_scanning"] = graphql_result

            graphql_data = graphql_result.get("graphql_scan_results", {})
            audit_results["total_vulnerabilities"] += len(graphql_data.get("vulnerabilities", []))

    # Generate comprehensive recommendations
    audit_results["recommendations"] = [
        "Implement proper authentication and authorization",
        "Use HTTPS for all API communications",
        "Validate and sanitize all input parameters",
        "Implement rate limiting and request throttling",
        "Add comprehensive logging and monitoring",
        "Regular security testing and code reviews",
        "Keep API documentation updated and secure",
        "Implement proper error handling"
    ]

    # Summary
    audit_results["summary"] = {
        "tests_performed": len(audit_results["tests_performed"]),
        "total_vulnerabilities": audit_results["total_vulnerabilities"],
        "audit_coverage": "comprehensive" if len(audit_results["tests_performed"]) >= 3 else "partial"
    }

    logger.info(f"✅ Comprehensive API audit completed:")
    logger.info(f"   ├─ Tests performed: {audit_results['summary']['tests_performed']}")
    logger.info(f"   ├─ Total vulnerabilities: {audit_results['summary']['total_vulnerabilities']}")
    logger.info(f"   └─ Coverage: {audit_results['summary']['audit_coverage']}")

    return {
        "success": True,
        "comprehensive_audit": audit_results
    }


@mcp.tool()
def volatility3_analyze(memory_file: str, plugin: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Volatility3 for advanced memory forensics with enhanced logging.

    Args:
        memory_file: Path to memory dump file
        plugin: Volatility3 plugin to execute
        output_file: Output file path
        additional_args: Additional Volatility3 arguments

    Returns:
        Advanced memory forensics results
    """
    data = {
        "memory_file": memory_file,
        "plugin": plugin,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
    result = hexstrike_client.safe_post("api/tools/volatility3", data)
    if result.get("success"):
        logger.info(f"✅ Volatility3 analysis completed")
    else:
        logger.error(f"❌ Volatility3 analysis failed")
    return result


@mcp.tool()
def foremost_carving(input_file: str, output_dir: str = "/tmp/foremost_output", file_types: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Foremost for file carving with enhanced logging.

    Args:
        input_file: Input file or device to carve
        output_dir: Output directory for carved files
        file_types: File types to carve (jpg,gif,png,etc.)
        additional_args: Additional Foremost arguments

    Returns:
        File carving results
    """
    data = {
        "input_file": input_file,
        "output_dir": output_dir,
        "file_types": file_types,
        "additional_args": additional_args
    }
    logger.info(f"📁 Starting Foremost file carving: {input_file}")
    result = hexstrike_client.safe_post("api/tools/foremost", data)
    if result.get("success"):
        logger.info(f"✅ Foremost carving completed")
    else:
        logger.error(f"❌ Foremost carving failed")
    return result


@mcp.tool()
def steghide_analysis(action: str, cover_file: str, embed_file: str = "", passphrase: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Steghide for steganography analysis with enhanced logging.

    Args:
        action: Action to perform (extract, embed, info)
        cover_file: Cover file for steganography
        embed_file: File to embed (for embed action)
        passphrase: Passphrase for steganography
        output_file: Output file path
        additional_args: Additional Steghide arguments

    Returns:
        Steganography analysis results
    """
    data = {
        "action": action,
        "cover_file": cover_file,
        "embed_file": embed_file,
        "passphrase": passphrase,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🖼️ Starting Steghide {action}: {cover_file}")
    result = hexstrike_client.safe_post("api/tools/steghide", data)
    if result.get("success"):
        logger.info(f"✅ Steghide {action} completed")
    else:
        logger.error(f"❌ Steghide {action} failed")
    return result


@mcp.tool()
def exiftool_extract(file_path: str, output_format: str = "", tags: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute ExifTool for metadata extraction with enhanced logging.

    Args:
        file_path: Path to file for metadata extraction
        output_format: Output format (json, xml, csv)
        tags: Specific tags to extract
        additional_args: Additional ExifTool arguments

    Returns:
        Metadata extraction results
    """
    data = {
        "file_path": file_path,
        "output_format": output_format,
        "tags": tags,
        "additional_args": additional_args
    }
    logger.info(f"📷 Starting ExifTool analysis: {file_path}")
    result = hexstrike_client.safe_post("api/tools/exiftool", data)
    if result.get("success"):
        logger.info(f"✅ ExifTool analysis completed")
    else:
        logger.error(f"❌ ExifTool analysis failed")
    return result


@mcp.tool()
def hashpump_attack(signature: str, data: str, key_length: str, append_data: str, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute HashPump for hash length extension attacks with enhanced logging.

    Args:
        signature: Original hash signature
        data: Original data
        key_length: Length of secret key
        append_data: Data to append
        additional_args: Additional HashPump arguments

    Returns:
        Hash length extension attack results
    """
    data = {
        "signature": signature,
        "data": data,
        "key_length": key_length,
        "append_data": append_data,
        "additional_args": additional_args
    }
    logger.info(f"🔐 Starting HashPump attack")
    result = hexstrike_client.safe_post("api/tools/hashpump", data)
    if result.get("success"):
        logger.info(f"✅ HashPump attack completed")
    else:
        logger.error(f"❌ HashPump attack failed")
    return result


@mcp.tool()
def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Hakrawler for web endpoint discovery with enhanced logging.

    Note: Uses standard Kali Linux hakrawler (hakluke/hakrawler) with parameter mapping:
    - url: Piped via echo to stdin (not -url flag)
    - depth: Mapped to -d flag (not -depth)
    - forms: Mapped to -s flag for showing sources
    - robots/sitemap/wayback: Mapped to -subs for subdomain inclusion
    - Always includes -u for unique URLs

    Args:
        url: Target URL to crawl
        depth: Crawling depth (mapped to -d)
        forms: Include forms in crawling (mapped to -s)
        robots: Check robots.txt (mapped to -subs)
        sitemap: Check sitemap.xml (mapped to -subs)
        wayback: Use Wayback Machine (mapped to -subs)
        additional_args: Additional Hakrawler arguments

    Returns:
        Web endpoint discovery results
    """
    data = {
        "url": url,
        "depth": depth,
        "forms": forms,
        "robots": robots,
        "sitemap": sitemap,
        "wayback": wayback,
        "additional_args": additional_args
    }
    logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
    result = hexstrike_client.safe_post("api/tools/hakrawler", data)
    if result.get("success"):
        logger.info(f"✅ Hakrawler crawling completed")
    else:
        logger.error(f"❌ Hakrawler crawling failed")
    return result


@mcp.tool()
def httpx_probe(targets: str = "", target_file: str = "", ports: str = "", methods: str = "GET", status_code: str = "", content_length: bool = False, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute HTTPx for HTTP probing with enhanced logging.

    Args:
        targets: Target URLs or IPs
        target_file: File containing targets
        ports: Ports to probe
        methods: HTTP methods to use
        status_code: Filter by status code
        content_length: Show content length
        output_file: Output file path
        additional_args: Additional HTTPx arguments

    Returns:
        HTTP probing results
    """
    data = {
        "targets": targets,
        "target_file": target_file,
        "ports": ports,
        "methods": methods,
        "status_code": status_code,
        "content_length": content_length,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🌐 Starting HTTPx probing")
    result = hexstrike_client.safe_post("api/tools/httpx", data)
    if result.get("success"):
        logger.info(f"✅ HTTPx probing completed")
    else:
        logger.error(f"❌ HTTPx probing failed")
    return result


@mcp.tool()
def paramspider_discovery(domain: str, exclude: str = "", output_file: str = "", level: int = 2, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute ParamSpider for parameter discovery with enhanced logging.

    Args:
        domain: Target domain
        exclude: Extensions to exclude
        output_file: Output file path
        level: Crawling level
        additional_args: Additional ParamSpider arguments

    Returns:
        Parameter discovery results
    """
    data = {
        "domain": domain,
        "exclude": exclude,
        "output_file": output_file,
        "level": level,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting ParamSpider discovery: {domain}")
    result = hexstrike_client.safe_post("api/tools/paramspider", data)
    if result.get("success"):
        logger.info(f"✅ ParamSpider discovery completed")
    else:
        logger.error(f"❌ ParamSpider discovery failed")
    return result


@mcp.tool()
def burpsuite_scan(project_file: str = "", config_file: str = "", target: str = "", headless: bool = False, scan_type: str = "", scan_config: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Burp Suite with enhanced logging.

    Args:
        project_file: Burp project file path
        config_file: Burp configuration file path
        target: Target URL
        headless: Run in headless mode
        scan_type: Type of scan to perform
        scan_config: Scan configuration
        output_file: Output file path
        additional_args: Additional Burp Suite arguments

    Returns:
        Burp Suite scan results
    """
    data = {
        "project_file": project_file,
        "config_file": config_file,
        "target": target,
        "headless": headless,
        "scan_type": scan_type,
        "scan_config": scan_config,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Burp Suite scan")
    result = hexstrike_client.safe_post("api/tools/burpsuite", data)
    if result.get("success"):
        logger.info(f"✅ Burp Suite scan completed")
    else:
        logger.error(f"❌ Burp Suite scan failed")
    return result


@mcp.tool()
def zap_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format_type: str = "xml", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute OWASP ZAP with enhanced logging.

    Args:
        target: Target URL
        scan_type: Type of scan (baseline, full, api)
        api_key: ZAP API key
        daemon: Run in daemon mode
        port: Port for ZAP daemon
        host: Host for ZAP daemon
        format_type: Output format (xml, json, html)
        output_file: Output file path
        additional_args: Additional ZAP arguments

    Returns:
        ZAP scan results
    """
    data = {
        "target": target,
        "scan_type": scan_type,
        "api_key": api_key,
        "daemon": daemon,
        "port": port,
        "host": host,
        "format": format_type,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting ZAP scan: {target}")
    result = hexstrike_client.safe_post("api/tools/zap", data)
    if result.get("success"):
        logger.info(f"✅ ZAP scan completed for {target}")
    else:
        logger.error(f"❌ ZAP scan failed for {target}")
    return result


@mcp.tool()
def arjun_scan(url: str, method: str = "GET", data: str = "", headers: str = "", timeout: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Arjun for parameter discovery with enhanced logging.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        data: POST data for testing
        headers: Custom headers
        timeout: Request timeout
        output_file: Output file path
        additional_args: Additional Arjun arguments

    Returns:
        Parameter discovery results
    """
    data = {
        "url": url,
        "method": method,
        "data": data,
        "headers": headers,
        "timeout": timeout,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Arjun parameter discovery: {url}")
    result = hexstrike_client.safe_post("api/tools/arjun", data)
    if result.get("success"):
        logger.info(f"✅ Arjun completed for {url}")
    else:
        logger.error(f"❌ Arjun failed for {url}")
    return result


@mcp.tool()
def wafw00f_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute wafw00f to identify and fingerprint WAF products with enhanced logging.

    Args:
        target: Target URL or IP
        additional_args: Additional wafw00f arguments

    Returns:
        WAF detection results
    """
    data = {
        "target": target,
        "additional_args": additional_args
    }
    logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
    result = hexstrike_client.safe_post("api/tools/wafw00f", data)
    if result.get("success"):
        logger.info(f"✅ Wafw00f completed for {target}")
    else:
        logger.error(f"❌ Wafw00f failed for {target}")
    return result


@mcp.tool()
def fierce_scan(domain: str, dns_server: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute fierce for DNS reconnaissance with enhanced logging.

    Args:
        domain: Target domain
        dns_server: DNS server to use
        additional_args: Additional fierce arguments

    Returns:
        DNS reconnaissance results
    """
    data = {
        "domain": domain,
        "dns_server": dns_server,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
    result = hexstrike_client.safe_post("api/tools/fierce", data)
    if result.get("success"):
        logger.info(f"✅ Fierce completed for {domain}")
    else:
        logger.error(f"❌ Fierce failed for {domain}")
    return result


@mcp.tool()
def dnsenum_scan(domain: str, dns_server: str = "", wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute dnsenum for DNS enumeration with enhanced logging.

    Args:
        domain: Target domain
        dns_server: DNS server to use
        wordlist: Wordlist for brute forcing
        additional_args: Additional dnsenum arguments

    Returns:
        DNS enumeration results
    """
    data = {
        "domain": domain,
        "dns_server": dns_server,
        "wordlist": wordlist,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting DNSenum: {domain}")
    result = hexstrike_client.safe_post("api/tools/dnsenum", data)
    if result.get("success"):
        logger.info(f"✅ DNSenum completed for {domain}")
    else:
        logger.error(f"❌ DNSenum failed for {domain}")
    return result


@mcp.tool()
def autorecon_scan(
    target: str = "",
    target_file: str = "",
    ports: str = "",
    output_dir: str = "",
    max_scans: str = "",
    max_port_scans: str = "",
    heartbeat: str = "",
    timeout: str = "",
    target_timeout: str = "",
    config_file: str = "",
    global_file: str = "",
    plugins_dir: str = "",
    add_plugins_dir: str = "",
    tags: str = "",
    exclude_tags: str = "",
    port_scans: str = "",
    service_scans: str = "",
    reports: str = "",
    single_target: bool = False,
    only_scans_dir: bool = False,
    no_port_dirs: bool = False,
    nmap: str = "",
    nmap_append: str = "",
    proxychains: bool = False,
    disable_sanity_checks: bool = False,
    disable_keyboard_control: bool = False,
    force_services: str = "",
    accessible: bool = False,
    verbose: int = 0,
    curl_path: str = "",
    dirbuster_tool: str = "",
    dirbuster_wordlist: str = "",
    dirbuster_threads: str = "",
    dirbuster_ext: str = "",
    onesixtyone_community_strings: str = "",
    global_username_wordlist: str = "",
    global_password_wordlist: str = "",
    global_domain: str = "",
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    Execute AutoRecon for comprehensive target enumeration with full parameter support.

    Args:
        target: Single target to scan
        target_file: File containing multiple targets
        ports: Specific ports to scan
        output_dir: Output directory
        max_scans: Maximum number of concurrent scans
        max_port_scans: Maximum number of concurrent port scans
        heartbeat: Heartbeat interval
        timeout: Global timeout
        target_timeout: Per-target timeout
        config_file: Configuration file path
        global_file: Global configuration file
        plugins_dir: Plugins directory
        add_plugins_dir: Additional plugins directory
        tags: Plugin tags to include
        exclude_tags: Plugin tags to exclude
        port_scans: Port scan plugins to run
        service_scans: Service scan plugins to run
        reports: Report plugins to run
        single_target: Use single target directory structure
        only_scans_dir: Only create scans directory
        no_port_dirs: Don't create port directories
        nmap: Custom nmap command
        nmap_append: Arguments to append to nmap
        proxychains: Use proxychains
        disable_sanity_checks: Disable sanity checks
        disable_keyboard_control: Disable keyboard control
        force_services: Force service detection
        accessible: Enable accessible output
        verbose: Verbosity level (0-3)
        curl_path: Custom curl path
        dirbuster_tool: Directory busting tool
        dirbuster_wordlist: Directory busting wordlist
        dirbuster_threads: Directory busting threads
        dirbuster_ext: Directory busting extensions
        onesixtyone_community_strings: SNMP community strings
        global_username_wordlist: Global username wordlist
        global_password_wordlist: Global password wordlist
        global_domain: Global domain
        additional_args: Additional AutoRecon arguments

    Returns:
        Comprehensive enumeration results with full configurability
    """
    data = {
        "target": target,
        "target_file": target_file,
        "ports": ports,
        "output_dir": output_dir,
        "max_scans": max_scans,
        "max_port_scans": max_port_scans,
        "heartbeat": heartbeat,
        "timeout": timeout,
        "target_timeout": target_timeout,
        "config_file": config_file,
        "global_file": global_file,
        "plugins_dir": plugins_dir,
        "add_plugins_dir": add_plugins_dir,
        "tags": tags,
        "exclude_tags": exclude_tags,
        "port_scans": port_scans,
        "service_scans": service_scans,
        "reports": reports,
        "single_target": single_target,
        "only_scans_dir": only_scans_dir,
        "no_port_dirs": no_port_dirs,
        "nmap": nmap,
        "nmap_append": nmap_append,
        "proxychains": proxychains,
        "disable_sanity_checks": disable_sanity_checks,
        "disable_keyboard_control": disable_keyboard_control,
        "force_services": force_services,
        "accessible": accessible,
        "verbose": verbose,
        "curl_path": curl_path,
        "dirbuster_tool": dirbuster_tool,
        "dirbuster_wordlist": dirbuster_wordlist,
        "dirbuster_threads": dirbuster_threads,
        "dirbuster_ext": dirbuster_ext,
        "onesixtyone_community_strings": onesixtyone_community_strings,
        "global_username_wordlist": global_username_wordlist,
        "global_password_wordlist": global_password_wordlist,
        "global_domain": global_domain,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting AutoRecon comprehensive enumeration: {target}")
    result = hexstrike_client.safe_post("api/tools/autorecon", data)
    if result.get("success"):
        logger.info(f"✅ AutoRecon comprehensive enumeration completed for {target}")
    else:
        logger.error(f"❌ AutoRecon failed for {target}")
    return result
