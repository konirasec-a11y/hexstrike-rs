"""HexStrike MCP tools - ai_api domain (extracted 1:1)."""

from ..mcp_instance import mcp  # noqa: F401
from ..client import hexstrike_client  # noqa: F401
from typing import Any, Dict
import time
from ..config import logger


@mcp.tool()
def ai_generate_payload(attack_type: str, complexity: str = "basic", technology: str = "", url: str = "") -> Dict[str, Any]:
    """
    Generate AI-powered contextual payloads for security testing.

    Args:
        attack_type: Type of attack (xss, sqli, lfi, cmd_injection, ssti, xxe)
        complexity: Complexity level (basic, advanced, bypass)
        technology: Target technology (php, asp, jsp, python, nodejs)
        url: Target URL for context

    Returns:
        Contextual payloads with risk assessment and test cases
    """
    data = {
        "attack_type": attack_type,
        "complexity": complexity,
        "technology": technology,
        "url": url
    }
    logger.info(f"🤖 Generating AI payloads for {attack_type} attack")
    result = hexstrike_client.safe_post("api/ai/generate_payload", data)

    if result.get("success"):
        payload_data = result.get("ai_payload_generation", {})
        count = payload_data.get("payload_count", 0)
        logger.info(f"✅ Generated {count} contextual {attack_type} payloads")

        # Log some example payloads for user awareness
        payloads = payload_data.get("payloads", [])
        if payloads:
            logger.info("🎯 Sample payloads generated:")
            for i, payload_info in enumerate(payloads[:3]):  # Show first 3
                risk = payload_info.get("risk_level", "UNKNOWN")
                context = payload_info.get("context", "basic")
                logger.info(f"   ├─ [{risk}] {context}: {payload_info['payload'][:50]}...")
    else:
        logger.error("❌ AI payload generation failed")

    return result


@mcp.tool()
def ai_test_payload(payload: str, target_url: str, method: str = "GET") -> Dict[str, Any]:
    """
    Test generated payload against target with AI analysis.

    Args:
        payload: The payload to test
        target_url: Target URL to test against
        method: HTTP method (GET, POST)

    Returns:
        Test results with AI analysis and vulnerability assessment
    """
    data = {
        "payload": payload,
        "target_url": target_url,
        "method": method
    }
    logger.info(f"🧪 Testing AI payload against {target_url}")
    result = hexstrike_client.safe_post("api/ai/test_payload", data)

    if result.get("success"):
        analysis = result.get("ai_analysis", {})
        potential_vuln = analysis.get("potential_vulnerability", False)
        logger.info(f"🔍 Payload test completed | Vulnerability detected: {potential_vuln}")

        if potential_vuln:
            logger.warning("⚠️  Potential vulnerability found! Review the response carefully.")
        else:
            logger.info("✅ No obvious vulnerability indicators detected")
    else:
        logger.error("❌ Payload testing failed")

    return result


@mcp.tool()
def ai_generate_attack_suite(target_url: str, attack_types: str = "xss,sqli,lfi") -> Dict[str, Any]:
    """
    Generate comprehensive attack suite with multiple payload types.

    Args:
        target_url: Target URL for testing
        attack_types: Comma-separated list of attack types

    Returns:
        Comprehensive attack suite with multiple payload types
    """
    attack_list = [attack.strip() for attack in attack_types.split(",")]
    results = {
        "target_url": target_url,
        "attack_types": attack_list,
        "payload_suites": {},
        "summary": {
            "total_payloads": 0,
            "high_risk_payloads": 0,
            "test_cases": 0
        }
    }

    logger.info(f"🚀 Generating comprehensive attack suite for {target_url}")
    logger.info(f"🎯 Attack types: {', '.join(attack_list)}")

    for attack_type in attack_list:
        logger.info(f"🤖 Generating {attack_type} payloads...")

        # Generate payloads for this attack type
        payload_result = self.ai_generate_payload(attack_type, "advanced", "", target_url)

        if payload_result.get("success"):
            payload_data = payload_result.get("ai_payload_generation", {})
            results["payload_suites"][attack_type] = payload_data

            # Update summary
            results["summary"]["total_payloads"] += payload_data.get("payload_count", 0)
            results["summary"]["test_cases"] += len(payload_data.get("test_cases", []))

            # Count high-risk payloads
            for payload_info in payload_data.get("payloads", []):
                if payload_info.get("risk_level") == "HIGH":
                    results["summary"]["high_risk_payloads"] += 1

    logger.info(f"✅ Attack suite generated:")
    logger.info(f"   ├─ Total payloads: {results['summary']['total_payloads']}")
    logger.info(f"   ├─ High-risk payloads: {results['summary']['high_risk_payloads']}")
    logger.info(f"   └─ Test cases: {results['summary']['test_cases']}")

    return {
        "success": True,
        "attack_suite": results,
        "timestamp": time.time()
    }


@mcp.tool()
def api_fuzzer(base_url: str, endpoints: str = "", methods: str = "GET,POST,PUT,DELETE", wordlist: str = "/usr/share/wordlists/api/api-endpoints.txt") -> Dict[str, Any]:
    """
    Advanced API endpoint fuzzing with intelligent parameter discovery.

    Args:
        base_url: Base URL of the API
        endpoints: Comma-separated list of specific endpoints to test
        methods: HTTP methods to test (comma-separated)
        wordlist: Wordlist for endpoint discovery

    Returns:
        API fuzzing results with endpoint discovery and vulnerability assessment
    """
    data = {
        "base_url": base_url,
        "endpoints": [e.strip() for e in endpoints.split(",") if e.strip()] if endpoints else [],
        "methods": [m.strip() for m in methods.split(",")],
        "wordlist": wordlist
    }

    logger.info(f"🔍 Starting API fuzzing: {base_url}")
    result = hexstrike_client.safe_post("api/tools/api_fuzzer", data)

    if result.get("success"):
        fuzzing_type = result.get("fuzzing_type", "unknown")
        if fuzzing_type == "endpoint_testing":
            endpoint_count = len(result.get("results", []))
            logger.info(f"✅ API endpoint testing completed: {endpoint_count} endpoints tested")
        else:
            logger.info(f"✅ API endpoint discovery completed")
    else:
        logger.error("❌ API fuzzing failed")

    return result


@mcp.tool()
def graphql_scanner(endpoint: str, introspection: bool = True, query_depth: int = 10, test_mutations: bool = True) -> Dict[str, Any]:
    """
    Advanced GraphQL security scanning and introspection.

    Args:
        endpoint: GraphQL endpoint URL
        introspection: Test introspection queries
        query_depth: Maximum query depth to test
        test_mutations: Test mutation operations

    Returns:
        GraphQL security scan results with vulnerability assessment
    """
    data = {
        "endpoint": endpoint,
        "introspection": introspection,
        "query_depth": query_depth,
        "test_mutations": test_mutations
    }

    logger.info(f"🔍 Starting GraphQL security scan: {endpoint}")
    result = hexstrike_client.safe_post("api/tools/graphql_scanner", data)

    if result.get("success"):
        scan_results = result.get("graphql_scan_results", {})
        vuln_count = len(scan_results.get("vulnerabilities", []))
        tests_count = len(scan_results.get("tests_performed", []))

        logger.info(f"✅ GraphQL scan completed: {tests_count} tests, {vuln_count} vulnerabilities")

        if vuln_count > 0:
            logger.warning(f"⚠️  Found {vuln_count} GraphQL vulnerabilities!")
            for vuln in scan_results.get("vulnerabilities", [])[:3]:  # Show first 3
                severity = vuln.get("severity", "UNKNOWN")
                vuln_type = vuln.get("type", "unknown")
                logger.warning(f"   ├─ [{severity}] {vuln_type}")
    else:
        logger.error("❌ GraphQL scanning failed")

    return result


@mcp.tool()
def jwt_analyzer(jwt_token: str, target_url: str = "") -> Dict[str, Any]:
    """
    Advanced JWT token analysis and vulnerability testing.

    Args:
        jwt_token: JWT token to analyze
        target_url: Optional target URL for testing token manipulation

    Returns:
        JWT analysis results with vulnerability assessment and attack vectors
    """
    data = {
        "jwt_token": jwt_token,
        "target_url": target_url
    }

    logger.info(f"🔍 Starting JWT security analysis")
    result = hexstrike_client.safe_post("api/tools/jwt_analyzer", data)

    if result.get("success"):
        analysis = result.get("jwt_analysis_results", {})
        vuln_count = len(analysis.get("vulnerabilities", []))
        algorithm = analysis.get("token_info", {}).get("algorithm", "unknown")

        logger.info(f"✅ JWT analysis completed: {vuln_count} vulnerabilities found")
        logger.info(f"🔐 Token algorithm: {algorithm}")

        if vuln_count > 0:
            logger.warning(f"⚠️  Found {vuln_count} JWT vulnerabilities!")
            for vuln in analysis.get("vulnerabilities", [])[:3]:  # Show first 3
                severity = vuln.get("severity", "UNKNOWN")
                vuln_type = vuln.get("type", "unknown")
                logger.warning(f"   ├─ [{severity}] {vuln_type}")
    else:
        logger.error("❌ JWT analysis failed")

    return result
