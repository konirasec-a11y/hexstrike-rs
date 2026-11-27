"""HexStrike AI - web_security module.

Extracted 1:1 from hexstrike_server.py lines 12673-12802.
Do not edit by hand: regenerate with scripts/splitter.py.
"""

from flask import request
from flask import jsonify

from ..core import app, logger
from ..intelligence.exploit_gen import execute_command

# ============================================================================
# ADDITIONAL WEB SECURITY TOOLS
# ============================================================================

@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Feroxbuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"feroxbuster -u {url} -w {wordlist} -t {threads}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Feroxbuster scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dotdotpwn", methods=["POST"])
def dotdotpwn():
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        module = params.get("module", "http")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 DotDotPwn called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"dotdotpwn -m {module} -h {target}"

        if additional_args:
            command += f" {additional_args}"

        command += " -b"

        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 DotDotPwn scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dotdotpwn endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/xsser", methods=["POST"])
def xsser():
    """Execute XSSer for XSS vulnerability testing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        params_str = params.get("params", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 XSSer called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"xsser --url '{url}'"

        if params_str:
            command += f" --param='{params_str}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 XSSer scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xsser endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Wfuzz called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wfuzz -w {wordlist} '{url}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Wfuzz scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wfuzz endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
