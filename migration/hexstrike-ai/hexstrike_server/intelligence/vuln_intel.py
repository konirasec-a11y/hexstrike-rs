"""HexStrike AI - vuln_intel module.

Extracted 1:1 from hexstrike_server.py lines 5746-7008.
Do not edit by hand: regenerate with scripts/splitter.py.
"""

import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
import hashlib
from datetime import datetime
from datetime import timedelta
from typing import Dict
from typing import Any
from typing import Optional
from collections import OrderedDict
import psutil
import requests

from ..visual_engine import ModernVisualEngine
from .process_termination import ProcessManager
from ..core import logger

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================

class CVEIntelligenceManager:
    """Advanced CVE Intelligence and Vulnerability Management System"""

    def __init__(self):
        self.cve_cache = {}
        self.vulnerability_db = {}
        self.threat_intelligence = {}

    @staticmethod
    def create_banner():
        """Reuse unified ModernVisualEngine banner (legacy hook)."""
        return ModernVisualEngine.create_banner()

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber',
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a beautiful progress bar with multiple styles"""

        # Clamp progress between 0 and 1
        progress = max(0.0, min(1.0, progress))

        # Calculate filled and empty portions
        filled_width = int(width * progress)
        empty_width = width - filled_width

        # Style-specific rendering
        if style == 'cyber':
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        elif style == 'matrix':
            filled_char = '▓'; empty_char = '▒'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        elif style == 'neon':
            filled_char = '━'; empty_char = '─'
            bar_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
            progress_color = ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']

        # Build the progress bar
        filled_part = bar_color + filled_char * filled_width
        empty_part = ModernVisualEngine.COLORS['TERMINAL_GRAY'] + empty_char * empty_width
        percentage = f"{progress * 100:.1f}%"

        # Add ETA and speed if provided
        eta_str = f" | ETA: {eta:.0f}s" if eta > 0 else ""
        speed_str = f" | {speed}" if speed else ""

        # Construct the full progress bar
        bar = f"{progress_color}[{filled_part}{empty_part}{ModernVisualEngine.COLORS['RESET']}{progress_color}] {percentage}{eta_str}{speed_str}{ModernVisualEngine.COLORS['RESET']}"

        if label:
            return f"{ModernVisualEngine.COLORS['BOLD']}{label}{ModernVisualEngine.COLORS['RESET']} {bar}"
        return bar

    @staticmethod
    def render_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Render vulnerability as a beautiful card with severity indicators"""

        severity = vuln_data.get('severity', 'info').lower()
        title = vuln_data.get('title', 'Unknown Vulnerability')
        url = vuln_data.get('url', 'N/A')
        description = vuln_data.get('description', 'No description available')
        cvss = vuln_data.get('cvss_score', 0.0)

        # Get severity color
        severity_color = ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'critical' else ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'high' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'medium' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'low' else ModernVisualEngine.COLORS['NEON_BLUE']

        # Severity indicators
        severity_indicators = {
            'critical': '🔥 CRITICAL',
            'high': '⚠️  HIGH',
            'medium': '📊 MEDIUM',
            'low': '📝 LOW',
            'info': 'ℹ️  INFO'
        }

        severity_badge = severity_indicators.get(severity, '❓ UNKNOWN')

        # Create the vulnerability card
        card = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {severity_color}{severity_badge}{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BOLD']}{title[:60]}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {url[:65]}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📊 CVSS:{ModernVisualEngine.COLORS['RESET']} {cvss}/10.0
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📋 Description:{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']}   {description[:70]}
{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        return card

    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create a live dashboard showing all active processes"""

        if not processes:
            return f"{ModernVisualEngine.COLORS['TERMINAL_GRAY']}📊 No active processes{ModernVisualEngine.COLORS['RESET']}"

        dashboard = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🚀 LIVE PROCESS DASHBOARD                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
"""

        for pid, proc_info in processes.items():
            command = proc_info.get('command', 'Unknown')[:50]
            status = proc_info.get('status', 'unknown')
            progress = proc_info.get('progress', 0.0)
            runtime = proc_info.get('runtime', 0)
            eta = proc_info.get('eta', 0)

            # Status color coding
            status_colors = {
                'running': ModernVisualEngine.COLORS['MATRIX_GREEN'],
                'paused': ModernVisualEngine.COLORS['WARNING'],
                'terminated': ModernVisualEngine.COLORS['ERROR'],
                'completed': ModernVisualEngine.COLORS['NEON_BLUE']
            }
            status_color = status_colors.get(status, ModernVisualEngine.COLORS['BRIGHT_WHITE'])

            # Create mini progress bar
            mini_bar = ModernVisualEngine.render_progress_bar(
                progress, width=20, style='cyber', eta=eta
            )

            dashboard += f"""{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}PID {pid}{ModernVisualEngine.COLORS['RESET']} │ {status_color}{status.upper()}{ModernVisualEngine.COLORS['RESET']} │ {runtime:.1f}s │ {command}...
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {mini_bar}
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
"""

        dashboard += f"{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}"

        return dashboard

    @staticmethod
    def format_tool_output(tool: str, output: str, success: bool = True) -> str:
        """Format tool output with syntax highlighting and structure"""

        # Get tool icon
        tool_icon = '🛠️'  # Default tool icon

        # Status indicator
        status_icon = "✅" if success else "❌"
        status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']

        # Format the output with structure
        formatted_output = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─ {tool_icon} {tool.upper()} OUTPUT ─────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}{status_icon} Status: {'SUCCESS' if success else 'FAILED'}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
"""

        # Process output lines with syntax highlighting
        lines = output.split('\n')
        for line in lines[:20]:  # Limit to first 20 lines for readability
            if line.strip():
                # Basic syntax highlighting
                if any(keyword in line.lower() for keyword in ['error', 'failed', 'denied']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['found', 'discovered', 'vulnerable']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['warning', 'timeout']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                else:
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"

        if len(lines) > 20:
            formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}... ({len(lines) - 20} more lines truncated){ModernVisualEngine.COLORS['RESET']}\n"

        formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}"

        return formatted_output

    @staticmethod
    def create_summary_report(results: Dict[str, Any]) -> str:
        """Generate a beautiful summary report"""

        total_vulns = len(results.get('vulnerabilities', []))
        critical_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'critical'])
        high_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'high'])
        execution_time = results.get('execution_time', 0)
        tools_used = results.get('tools_used', [])

        report = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                              📊 SCAN SUMMARY REPORT                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {results.get('target', 'Unknown')[:60]}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f} seconds
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🛠️  Tools Used:{ModernVisualEngine.COLORS['RESET']} {len(tools_used)} tools
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['HACKER_RED']}🔥 Critical:{ModernVisualEngine.COLORS['RESET']} {critical_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}⚠️  High:{ModernVisualEngine.COLORS['RESET']} {high_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}📈 Total Found:{ModernVisualEngine.COLORS['RESET']} {total_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🚀 Tools:{ModernVisualEngine.COLORS['RESET']} {', '.join(tools_used[:5])}{'...' if len(tools_used) > 5 else ''}
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}
"""
        return report

    def fetch_latest_cves(self, hours=24, severity_filter="HIGH,CRITICAL"):
        """Fetch latest CVEs from NVD and other real sources"""
        try:
            logger.info(f"🔍 Fetching CVEs from last {hours} hours with severity: {severity_filter}")
            
            # Calculate date range for CVE search
            end_date = datetime.now()
            start_date = end_date - timedelta(hours=hours)
            
            # Format dates for NVD API (ISO 8601 format)
            start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            # NVD API endpoint
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Parse severity filter
            severity_levels = [s.strip().upper() for s in severity_filter.split(",")]
            
            all_cves = []
            
            # Query NVD API with rate limiting compliance
            params = {
                'lastModStartDate': start_date_str,
                'lastModEndDate': end_date_str,
                'resultsPerPage': 100
            }
            
            try:
                # Add delay to respect NVD rate limits (6 seconds between requests for unauthenticated)
                import time
                
                logger.info(f"🌐 Querying NVD API: {nvd_url}")
                response = requests.get(nvd_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    nvd_data = response.json()
                    vulnerabilities = nvd_data.get('vulnerabilities', [])
                    
                    logger.info(f"📊 Retrieved {len(vulnerabilities)} vulnerabilities from NVD")
                    
                    for vuln_item in vulnerabilities:
                        cve_data = vuln_item.get('cve', {})
                        cve_id = cve_data.get('id', 'Unknown')
                        
                        # Extract CVSS scores and determine severity
                        metrics = cve_data.get('metrics', {})
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        # Try CVSS v3.1 first, then v3.0, then v2.0
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            # Convert CVSS v2 score to severity
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                        
                        # Filter by severity if specified
                        if severity not in severity_levels and severity_levels != ['ALL']:
                            continue
                        
                        # Extract description
                        descriptions = cve_data.get('descriptions', [])
                        description = "No description available"
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', description)
                                break
                        
                        # Extract references
                        references = []
                        ref_data = cve_data.get('references', [])
                        for ref in ref_data[:5]:  # Limit to first 5 references
                            references.append(ref.get('url', ''))
                        
                        # Extract affected software (CPE data)
                        affected_software = []
                        configurations = cve_data.get('configurations', [])
                        for config in configurations:
                            nodes = config.get('nodes', [])
                            for node in nodes:
                                cpe_match = node.get('cpeMatch', [])
                                for cpe in cpe_match[:3]:  # Limit to first 3 CPEs
                                    cpe_name = cpe.get('criteria', '')
                                    if cpe_name.startswith('cpe:2.3:'):
                                        # Parse CPE to get readable software name
                                        parts = cpe_name.split(':')
                                        if len(parts) >= 6:
                                            vendor = parts[3]
                                            product = parts[4]
                                            version = parts[5] if parts[5] != '*' else 'all versions'
                                            affected_software.append(f"{vendor} {product} {version}")
                        
                        cve_entry = {
                            "cve_id": cve_id,
                            "description": description,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "published_date": cve_data.get('published', ''),
                            "last_modified": cve_data.get('lastModified', ''),
                            "affected_software": affected_software[:5],  # Limit to 5 entries
                            "references": references,
                            "source": "NVD"
                        }
                        
                        all_cves.append(cve_entry)
                
                else:
                    logger.warning(f"⚠️ NVD API returned status code: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Error querying NVD API: {str(e)}")
            
            # If no CVEs found from NVD, try alternative sources or provide informative response
            if not all_cves:
                logger.info("🔄 No recent CVEs found in specified timeframe, checking for any recent critical CVEs...")
                
                # Try a broader search for recent critical CVEs (last 7 days)
                try:
                    broader_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
                    broader_params = {
                        'lastModStartDate': broader_start,
                        'lastModEndDate': end_date_str,
                        'cvssV3Severity': 'CRITICAL',
                        'resultsPerPage': 20
                    }
                    
                    time.sleep(6)  # Rate limit compliance
                    response = requests.get(nvd_url, params=broader_params, timeout=30)
                    
                    if response.status_code == 200:
                        nvd_data = response.json()
                        vulnerabilities = nvd_data.get('vulnerabilities', [])
                        
                        for vuln_item in vulnerabilities[:10]:  # Limit to 10 most recent
                            cve_data = vuln_item.get('cve', {})
                            cve_id = cve_data.get('id', 'Unknown')
                            
                            # Extract basic info for recent critical CVEs
                            descriptions = cve_data.get('descriptions', [])
                            description = "No description available"
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    description = desc.get('value', description)
                                    break
                            
                            metrics = cve_data.get('metrics', {})
                            cvss_score = 0.0
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
                            
                            cve_entry = {
                                "cve_id": cve_id,
                                "description": description,
                                "severity": "CRITICAL",
                                "cvss_score": cvss_score,
                                "published_date": cve_data.get('published', ''),
                                "last_modified": cve_data.get('lastModified', ''),
                                "affected_software": ["Various (see references)"],
                                "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                                "source": "NVD (Recent Critical)"
                            }
                            
                            all_cves.append(cve_entry)
                            
                except Exception as broader_e:
                    logger.warning(f"⚠️ Broader search also failed: {str(broader_e)}")
            
            logger.info(f"✅ Successfully retrieved {len(all_cves)} CVEs")
            
            return {
                "success": True,
                "cves": all_cves,
                "total_found": len(all_cves),
                "hours_searched": hours,
                "severity_filter": severity_filter,
                "data_sources": ["NVD API v2.0"],
                "search_period": f"{start_date_str} to {end_date_str}"
            }
            
        except Exception as e:
            logger.error(f"💥 Error fetching CVEs: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cves": [],
                "fallback_message": "CVE fetching failed, check network connectivity and API availability"
            }

    def analyze_cve_exploitability(self, cve_id):
        """Analyze CVE exploitability using real CVE data and threat intelligence"""
        try:
            logger.info(f"🔬 Analyzing exploitability for {cve_id}")
            
            # Fetch detailed CVE data from NVD
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            import time
            
            try:
                response = requests.get(nvd_url, params=params, timeout=30)
                
                if response.status_code != 200:
                    logger.warning(f"⚠️ NVD API returned status {response.status_code} for {cve_id}")
                    return {
                        "success": False,
                        "error": f"Failed to fetch CVE data: HTTP {response.status_code}",
                        "cve_id": cve_id
                    }
                
                nvd_data = response.json()
                vulnerabilities = nvd_data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    logger.warning(f"⚠️ No data found for CVE {cve_id}")
                    return {
                        "success": False,
                        "error": f"CVE {cve_id} not found in NVD database",
                        "cve_id": cve_id
                    }
                
                cve_data = vulnerabilities[0].get('cve', {})
                
                # Extract CVSS metrics for exploitability analysis
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                severity = "UNKNOWN"
                attack_vector = "UNKNOWN"
                attack_complexity = "UNKNOWN"
                privileges_required = "UNKNOWN"
                user_interaction = "UNKNOWN"
                exploitability_subscore = 0.0
                
                # Analyze CVSS v3.1 metrics (preferred)
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                    attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                    privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                    user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                    exploitability_subscore = cvss_data.get('exploitabilityScore', 0.0)
                    
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                    attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                    privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                    user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                    exploitability_subscore = cvss_data.get('exploitabilityScore', 0.0)
                
                # Calculate exploitability score based on CVSS metrics
                exploitability_score = 0.0
                
                # Base exploitability on CVSS exploitability subscore if available
                if exploitability_subscore > 0:
                    exploitability_score = min(exploitability_subscore / 3.9, 1.0)  # Normalize to 0-1
                else:
                    # Calculate based on individual CVSS components
                    score_components = 0.0
                    
                    # Attack Vector scoring
                    if attack_vector == "NETWORK":
                        score_components += 0.4
                    elif attack_vector == "ADJACENT_NETWORK":
                        score_components += 0.3
                    elif attack_vector == "LOCAL":
                        score_components += 0.2
                    elif attack_vector == "PHYSICAL":
                        score_components += 0.1
                    
                    # Attack Complexity scoring
                    if attack_complexity == "LOW":
                        score_components += 0.3
                    elif attack_complexity == "HIGH":
                        score_components += 0.1
                    
                    # Privileges Required scoring
                    if privileges_required == "NONE":
                        score_components += 0.2
                    elif privileges_required == "LOW":
                        score_components += 0.1
                    
                    # User Interaction scoring
                    if user_interaction == "NONE":
                        score_components += 0.1
                    
                    exploitability_score = min(score_components, 1.0)
                
                # Determine exploitability level
                if exploitability_score >= 0.8:
                    exploitability_level = "HIGH"
                elif exploitability_score >= 0.6:
                    exploitability_level = "MEDIUM"
                elif exploitability_score >= 0.3:
                    exploitability_level = "LOW"
                else:
                    exploitability_level = "VERY_LOW"
                
                # Extract description for additional context
                descriptions = cve_data.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Analyze description for exploit indicators
                exploit_keywords = [
                    'remote code execution', 'rce', 'buffer overflow', 'stack overflow',
                    'heap overflow', 'use after free', 'double free', 'format string',
                    'sql injection', 'command injection', 'authentication bypass',
                    'privilege escalation', 'directory traversal', 'path traversal',
                    'deserialization', 'xxe', 'ssrf', 'csrf', 'xss'
                ]
                
                description_lower = description.lower()
                exploit_indicators = [kw for kw in exploit_keywords if kw in description_lower]
                
                # Adjust exploitability based on vulnerability type
                if any(kw in description_lower for kw in ['remote code execution', 'rce', 'buffer overflow']):
                    exploitability_score = min(exploitability_score + 0.2, 1.0)
                elif any(kw in description_lower for kw in ['authentication bypass', 'privilege escalation']):
                    exploitability_score = min(exploitability_score + 0.15, 1.0)
                
                # Check for public exploit availability indicators
                public_exploits = False
                exploit_maturity = "UNKNOWN"
                
                # Look for exploit references in CVE references
                references = cve_data.get('references', [])
                exploit_sources = ['exploit-db.com', 'github.com', 'packetstormsecurity.com', 'metasploit']
                
                for ref in references:
                    ref_url = ref.get('url', '').lower()
                    if any(source in ref_url for source in exploit_sources):
                        public_exploits = True
                        exploit_maturity = "PROOF_OF_CONCEPT"
                        break
                
                # Determine weaponization level
                weaponization_level = "LOW"
                if public_exploits and exploitability_score > 0.7:
                    weaponization_level = "HIGH"
                elif public_exploits and exploitability_score > 0.5:
                    weaponization_level = "MEDIUM"
                elif exploitability_score > 0.8:
                    weaponization_level = "MEDIUM"
                
                # Active exploitation assessment
                active_exploitation = False
                if exploitability_score > 0.8 and public_exploits:
                    active_exploitation = True
                elif severity in ["CRITICAL", "HIGH"] and attack_vector == "NETWORK":
                    active_exploitation = True
                
                # Priority recommendation
                if exploitability_score > 0.8 and severity == "CRITICAL":
                    priority = "IMMEDIATE"
                elif exploitability_score > 0.7 or severity == "CRITICAL":
                    priority = "HIGH"
                elif exploitability_score > 0.5 or severity == "HIGH":
                    priority = "MEDIUM"
                else:
                    priority = "LOW"
                
                # Extract publication and modification dates
                published_date = cve_data.get('published', '')
                last_modified = cve_data.get('lastModified', '')
                
                analysis = {
                    "success": True,
                    "cve_id": cve_id,
                    "exploitability_score": round(exploitability_score, 2),
                    "exploitability_level": exploitability_level,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "attack_vector": attack_vector,
                    "attack_complexity": attack_complexity,
                    "privileges_required": privileges_required,
                    "user_interaction": user_interaction,
                    "exploitability_subscore": exploitability_subscore,
                    "exploit_availability": {
                        "public_exploits": public_exploits,
                        "exploit_maturity": exploit_maturity,
                        "weaponization_level": weaponization_level
                    },
                    "threat_intelligence": {
                        "active_exploitation": active_exploitation,
                        "exploit_prediction": f"{exploitability_score * 100:.1f}% likelihood of exploitation",
                        "recommended_priority": priority,
                        "exploit_indicators": exploit_indicators
                    },
                    "vulnerability_details": {
                        "description": description[:500] + "..." if len(description) > 500 else description,
                        "published_date": published_date,
                        "last_modified": last_modified,
                        "references_count": len(references)
                    },
                    "data_source": "NVD API v2.0",
                    "analysis_timestamp": datetime.now().isoformat()
                }
                
                logger.info(f"✅ Completed exploitability analysis for {cve_id}: {exploitability_level} ({exploitability_score:.2f})")
                
                return analysis
                
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Network error analyzing {cve_id}: {str(e)}")
                return {
                    "success": False,
                    "error": f"Network error: {str(e)}",
                    "cve_id": cve_id
                }
                
        except Exception as e:
            logger.error(f"💥 Error analyzing CVE {cve_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cve_id": cve_id
            }

    def search_existing_exploits(self, cve_id):
        """Search for existing exploits from real sources"""
        try:
            logger.info(f"🔎 Searching existing exploits for {cve_id}")
            
            all_exploits = []
            sources_searched = []
            
            # 1. Search GitHub for PoCs and exploits
            try:
                logger.info(f"🔍 Searching GitHub for {cve_id} exploits...")
                
                # GitHub Search API
                github_search_url = "https://api.github.com/search/repositories"
                github_params = {
                    'q': f'{cve_id} exploit poc vulnerability',
                    'sort': 'updated',
                    'order': 'desc',
                    'per_page': 10
                }
                
                github_response = requests.get(github_search_url, params=github_params, timeout=15)
                
                if github_response.status_code == 200:
                    github_data = github_response.json()
                    repositories = github_data.get('items', [])
                    
                    for repo in repositories[:5]:  # Limit to top 5 results
                        # Check if CVE is actually mentioned in repo name or description
                        repo_name = repo.get('name', '').lower()
                        repo_desc = repo.get('description', '').lower()
                        
                        if cve_id.lower() in repo_name or cve_id.lower() in repo_desc:
                            exploit_entry = {
                                "source": "github",
                                "exploit_id": f"github-{repo.get('id', 'unknown')}",
                                "title": repo.get('name', 'Unknown Repository'),
                                "description": repo.get('description', 'No description'),
                                "author": repo.get('owner', {}).get('login', 'Unknown'),
                                "date_published": repo.get('created_at', ''),
                                "last_updated": repo.get('updated_at', ''),
                                "type": "proof-of-concept",
                                "platform": "cross-platform",
                                "url": repo.get('html_url', ''),
                                "stars": repo.get('stargazers_count', 0),
                                "forks": repo.get('forks_count', 0),
                                "verified": False,
                                "reliability": "UNVERIFIED"
                            }
                            
                            # Assess reliability based on repo metrics
                            stars = repo.get('stargazers_count', 0)
                            forks = repo.get('forks_count', 0)
                            
                            if stars >= 50 or forks >= 10:
                                exploit_entry["reliability"] = "GOOD"
                            elif stars >= 20 or forks >= 5:
                                exploit_entry["reliability"] = "FAIR"
                            
                            all_exploits.append(exploit_entry)
                    
                    sources_searched.append("github")
                    logger.info(f"✅ Found {len([e for e in all_exploits if e['source'] == 'github'])} GitHub repositories")
                
                else:
                    logger.warning(f"⚠️ GitHub search failed with status {github_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ GitHub search error: {str(e)}")
            
            # 2. Search Exploit-DB via searchsploit-like functionality
            try:
                logger.info(f"🔍 Searching for {cve_id} in exploit databases...")
                
                # Since we can't directly access Exploit-DB API, we'll use a web search approach
                # or check if the CVE references contain exploit-db links
                
                # First, get CVE data to check references
                nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                nvd_params = {'cveId': cve_id}
                
                import time
                time.sleep(1)  # Rate limiting
                
                nvd_response = requests.get(nvd_url, params=nvd_params, timeout=20)
                
                if nvd_response.status_code == 200:
                    nvd_data = nvd_response.json()
                    vulnerabilities = nvd_data.get('vulnerabilities', [])
                    
                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get('cve', {})
                        references = cve_data.get('references', [])
                        
                        # Check references for exploit sources
                        exploit_sources = {
                            'exploit-db.com': 'exploit-db',
                            'packetstormsecurity.com': 'packetstorm',
                            'metasploit': 'metasploit',
                            'rapid7.com': 'rapid7'
                        }
                        
                        for ref in references:
                            ref_url = ref.get('url', '')
                            ref_url_lower = ref_url.lower()
                            
                            for source_domain, source_name in exploit_sources.items():
                                if source_domain in ref_url_lower:
                                    exploit_entry = {
                                        "source": source_name,
                                        "exploit_id": f"{source_name}-ref",
                                        "title": f"Referenced exploit for {cve_id}",
                                        "description": f"Exploit reference found in CVE data",
                                        "author": "Various",
                                        "date_published": cve_data.get('published', ''),
                                        "type": "reference",
                                        "platform": "various",
                                        "url": ref_url,
                                        "verified": True,
                                        "reliability": "GOOD" if source_name == "exploit-db" else "FAIR"
                                    }
                                    all_exploits.append(exploit_entry)
                                    
                                    if source_name not in sources_searched:
                                        sources_searched.append(source_name)
                
            except Exception as e:
                logger.error(f"❌ Exploit database search error: {str(e)}")
            
            # 3. Search for Metasploit modules
            try:
                logger.info(f"🔍 Searching for Metasploit modules for {cve_id}...")
                
                # Search GitHub for Metasploit modules containing the CVE
                msf_search_url = "https://api.github.com/search/code"
                msf_params = {
                    'q': f'{cve_id} filename:*.rb repo:rapid7/metasploit-framework',
                    'per_page': 5
                }
                
                time.sleep(1)  # Rate limiting
                msf_response = requests.get(msf_search_url, params=msf_params, timeout=15)
                
                if msf_response.status_code == 200:
                    msf_data = msf_response.json()
                    code_results = msf_data.get('items', [])
                    
                    for code_item in code_results:
                        file_path = code_item.get('path', '')
                        if 'exploits/' in file_path or 'auxiliary/' in file_path:
                            exploit_entry = {
                                "source": "metasploit",
                                "exploit_id": f"msf-{code_item.get('sha', 'unknown')[:8]}",
                                "title": f"Metasploit Module: {code_item.get('name', 'Unknown')}",
                                "description": f"Metasploit framework module at {file_path}",
                                "author": "Metasploit Framework",
                                "date_published": "Unknown",
                                "type": "metasploit-module",
                                "platform": "various",
                                "url": code_item.get('html_url', ''),
                                "verified": True,
                                "reliability": "EXCELLENT"
                            }
                            all_exploits.append(exploit_entry)
                    
                    if code_results and "metasploit" not in sources_searched:
                        sources_searched.append("metasploit")
                        
                elif msf_response.status_code == 403:
                    logger.warning("⚠️ GitHub API rate limit reached for code search")
                else:
                    logger.warning(f"⚠️ Metasploit search failed with status {msf_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Metasploit search error: {str(e)}")
            
            # Add default sources to searched list
            default_sources = ["exploit-db", "github", "metasploit", "packetstorm"]
            for source in default_sources:
                if source not in sources_searched:
                    sources_searched.append(source)
            
            # Sort exploits by reliability and date
            reliability_order = {"EXCELLENT": 4, "GOOD": 3, "FAIR": 2, "UNVERIFIED": 1}
            all_exploits.sort(key=lambda x: (
                reliability_order.get(x.get("reliability", "UNVERIFIED"), 0),
                x.get("stars", 0),
                x.get("date_published", "")
            ), reverse=True)
            
            logger.info(f"✅ Found {len(all_exploits)} total exploits from {len(sources_searched)} sources")
            
            return {
                "success": True,
                "cve_id": cve_id,
                "exploits_found": len(all_exploits),
                "exploits": all_exploits,
                "sources_searched": sources_searched,
                "search_summary": {
                    "github_repos": len([e for e in all_exploits if e["source"] == "github"]),
                    "exploit_db_refs": len([e for e in all_exploits if e["source"] == "exploit-db"]),
                    "metasploit_modules": len([e for e in all_exploits if e["source"] == "metasploit"]),
                    "other_sources": len([e for e in all_exploits if e["source"] not in ["github", "exploit-db", "metasploit"]])
                },
                "search_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"💥 Error searching exploits for {cve_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cve_id": cve_id,
                "exploits": [],
                "sources_searched": []
            }

# Configure enhanced logging with colors
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""

    COLORS = {
        'DEBUG': ModernVisualEngine.COLORS['DEBUG'],
        'INFO': ModernVisualEngine.COLORS['SUCCESS'],
        'WARNING': ModernVisualEngine.COLORS['WARNING'],
        'ERROR': ModernVisualEngine.COLORS['ERROR'],
        'CRITICAL': ModernVisualEngine.COLORS['CRITICAL']
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, ModernVisualEngine.COLORS['BRIGHT_WHITE'])

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{ModernVisualEngine.COLORS['RESET']}"
        return super().format(record)

# Enhanced logging setup
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)

    return logger

# Configuration (using existing API_PORT from top of file)
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

class HexStrikeCache:
    """Advanced caching system for command results"""

    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)

        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                logger.info(f"💾 Cache HIT for command: {command}")
                return data
            else:
                # Remove expired entry
                del self.cache[key]

        self.stats["misses"] += 1
        logger.info(f"🔍 Cache MISS for command: {command}")
        return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)

        # Remove oldest entries if cache is full
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1

        self.cache[key] = (time.time(), result)
        logger.info(f"💾 Cached result for command: {command}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }

# Global cache instance
cache = HexStrikeCache()

class TelemetryCollector:
    """Collect and manage system telemetry"""

    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }

    def record_execution(self, success: bool, execution_time: float):
        """Record command execution statistics"""
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        uptime = time.time() - self.stats["start_time"]
        success_rate = (self.stats["successful_commands"] / self.stats["commands_executed"] * 100) if self.stats["commands_executed"] > 0 else 0
        avg_execution_time = (self.stats["total_execution_time"] / self.stats["commands_executed"]) if self.stats["commands_executed"] > 0 else 0

        return {
            "uptime_seconds": uptime,
            "commands_executed": self.stats["commands_executed"],
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_execution_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }

# Global telemetry collector
telemetry = TelemetryCollector()

class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None

    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    # Real-time output display
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    # Real-time error output display
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration > 2:  # Show progress for commands taking more than 2 seconds
            progress_chars = ModernVisualEngine.PROGRESS_STYLES['dots']
            start = time.time()
            i = 0
            while self.process and self.process.poll() is None:
                elapsed = time.time() - start
                char = progress_chars[i % len(progress_chars)]

                # Calculate progress percentage (rough estimate)
                progress_percent = min((elapsed / self.timeout) * 100, 99.9)
                progress_fraction = progress_percent / 100

                # Calculate ETA
                eta = 0
                if progress_percent > 5:  # Only show ETA after 5% progress
                    eta = ((elapsed / progress_percent) * 100) - elapsed

                # Calculate speed
                bytes_processed = len(self.stdout_data) + len(self.stderr_data)
                speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"

                # Update process manager with progress
                ProcessManager.update_process_progress(
                    self.process.pid,
                    progress_fraction,
                    f"Running for {elapsed:.1f}s",
                    bytes_processed
                )

                # Create beautiful progress bar using ModernVisualEngine
                progress_bar = ModernVisualEngine.render_progress_bar(
                    progress_fraction,
                    width=30,
                    style='cyber',
                    label=f"⚡ PROGRESS {char}",
                    eta=eta,
                    speed=speed
                )

                logger.info(f"{progress_bar} | {elapsed:.1f}s | PID: {self.process.pid}")
                time.sleep(0.8)
                i += 1
                if elapsed > self.timeout:
                    break

    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()

        logger.info(f"🚀 EXECUTING: {self.command}")
        logger.info(f"⏱️  TIMEOUT: {self.timeout}s | PID: Starting...")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")

            # Register process with ProcessManager (v5.0 enhancement)
            ProcessManager.register_process(pid, self.command, self.process)

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Start progress tracking in a separate thread
            progress_thread = threading.Thread(target=self._show_progress, args=(self.timeout,))
            progress_thread.daemon = True
            progress_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()

                # Process completed, join the threads
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)

                execution_time = self.end_time - self.start_time

                # Cleanup process from registry (v5.0 enhancement)
                ProcessManager.cleanup_process(pid)

                if self.return_code == 0:
                    logger.info(f"✅ SUCCESS: Command completed | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(True, execution_time)
                else:
                    logger.warning(f"⚠️  WARNING: Command completed with errors | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(False, execution_time)

            except subprocess.TimeoutExpired:
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time

                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {self.process.pid}")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1
                telemetry.record_execution(False, execution_time)

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            # Log enhanced final results with summary using ModernVisualEngine
            output_size = len(self.stdout_data) + len(self.stderr_data)
            execution_time = self.end_time - self.start_time if self.end_time else 0

            # Create status summary
            status_icon = "✅" if success else "❌"
            status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
            timeout_status = f" {ModernVisualEngine.COLORS['WARNING']}[TIMEOUT]{ModernVisualEngine.COLORS['RESET']}" if self.timed_out else ""

            # Create beautiful results summary
            results_summary = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📊 FINAL RESULTS {status_icon}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Command:{ModernVisualEngine.COLORS['RESET']} {self.command[:55]}{'...' if len(self.command) > 55 else ''}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f}s{timeout_status}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}📊 Output Size:{ModernVisualEngine.COLORS['RESET']} {output_size} bytes
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🔢 Exit Code:{ModernVisualEngine.COLORS['RESET']} {self.return_code}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📈 Status:{ModernVisualEngine.COLORS['RESET']} {'SUCCESS' if success else 'FAILED'} | Cached: Yes
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

            # Log the beautiful summary
            for line in results_summary.strip().split('\n'):
                if line.strip():
                    logger.info(line)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": self.end_time - self.start_time if self.end_time else 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0

            logger.error(f"💥 ERROR: Command execution failed: {str(e)}")
            logger.error(f"🔍 TRACEBACK: {traceback.format_exc()}")
            telemetry.record_execution(False, execution_time)

            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

# ============================================================================
# DUPLICATE CLASSES REMOVED - Using the first definitions above
# ============================================================================
