"""HexStrike AI - cloud_security module.

Extracted 1:1 from hexstrike_server.py lines 10485-10576.
Do not edit by hand: regenerate with scripts/splitter.py.
"""

from pathlib import Path
from flask import request
from flask import jsonify

from ..core import app, logger
from ..intelligence.exploit_gen import execute_command

# ============================================================================
# CLOUD SECURITY TOOLS
# ============================================================================

@app.route("/api/tools/prowler", methods=["POST"])
def prowler():
    """Execute Prowler for AWS security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")
        profile = params.get("profile", "default")
        region = params.get("region", "")
        checks = params.get("checks", "")
        output_dir = params.get("output_dir", "/tmp/prowler_output")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"prowler {provider}"

        if profile:
            command += f" --profile {profile}"

        if region:
            command += f" --region {region}"

        if checks:
            command += f" --checks {checks}"

        command += f" --output-directory {output_dir}"
        command += f" --output-format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Prowler assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in prowler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "image")  # image, fs, repo
        target = params.get("target", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Trivy called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"trivy {scan_type} {target}"

        if output_format:
            command += f" --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if output_file:
            command += f" --output {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = execute_command(command)
        if output_file:
            result["output_file"] = output_file
        logger.info(f"📊 Trivy scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in trivy endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
