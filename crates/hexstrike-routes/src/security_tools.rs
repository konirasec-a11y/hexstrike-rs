//! Port 1:1 de `hexstrike_server/routes/security_tools.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  def nmap
//!    68  def gobuster
//!   120  def nuclei
//! ```
//!
//! Rotas (`@app.route`) deste módulo (3):
//!
//! ```text
//!    17  nmap("/api/tools/nmap", methods=["POST"])
//!    67  gobuster("/api/tools/gobuster", methods=["POST"])
//!   119  nuclei("/api/tools/nuclei", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use hexstrike_intelligence::exploit_gen::{execute_command, execute_command_with_recovery};

/// `jsonify(x)` (200) vs `jsonify(x), <status>` (≠200). O `Result` do axum
/// devolve o status só no ramo de erro, então o ramo 200 continua sendo
/// `Json<Value>`.
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// `@app.route("/api/tools/nmap", methods=["POST"])` — `def nmap()`.
pub async fn nmap(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let scan_type = params
        .get("scan_type")
        .and_then(Value::as_str)
        .unwrap_or("-sCV");
    let ports = params.get("ports").and_then(Value::as_str).unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("-T4 -Pn");
    let use_recovery = params
        .get("use_recovery")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if target.is_empty() {
        warn!("🎯 Nmap called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("nmap {scan_type}");

    if !ports.is_empty() {
        command.push_str(&format!(" -p {ports}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    command.push_str(&format!(" {target}"));

    info!("🔍 Starting Nmap scan: {target}");

    // Use intelligent error handling if enabled
    let result = if use_recovery {
        let mut tool_params = Map::new();
        tool_params.insert("target".to_string(), json!(target));
        tool_params.insert("scan_type".to_string(), json!(scan_type));
        tool_params.insert("ports".to_string(), json!(ports));
        tool_params.insert("additional_args".to_string(), json!(additional_args));
        execute_command_with_recovery(
        "nmap",
        &command,
        Some(&tool_params),
        true,
        3,
    )
    .await
    } else {
        execute_command(&command, true).await
    };

    info!("📊 Nmap scan completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/gobuster", methods=["POST"])` — `def gobuster()`.
pub async fn gobuster(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let mode = params.get("mode").and_then(Value::as_str).unwrap_or("dir");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");
    let use_recovery = params
        .get("use_recovery")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if url.is_empty() {
        warn!("🌐 Gobuster called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    // Validate mode
    if !matches!(mode, "dir" | "dns" | "fuzz" | "vhost") {
        warn!("❌ Invalid gobuster mode: {mode}");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost")
            })),
        ));
    }

    let mut command = format!("gobuster {mode} -u {url} -w {wordlist}");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("📁 Starting Gobuster {mode} scan: {url}");

    // Use intelligent error handling if enabled
    let result = if use_recovery {
        let mut tool_params = Map::new();
        tool_params.insert("target".to_string(), json!(url));
        tool_params.insert("mode".to_string(), json!(mode));
        tool_params.insert("wordlist".to_string(), json!(wordlist));
        tool_params.insert("additional_args".to_string(), json!(additional_args));
        execute_command_with_recovery(
        "gobuster",
        &command,
        Some(&tool_params),
        true,
        3,
    )
    .await
    } else {
        execute_command(&command, true).await
    };

    info!("📊 Gobuster scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/nuclei", methods=["POST"])` — `def nuclei()`.
pub async fn nuclei(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let severity = params
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tags = params.get("tags").and_then(Value::as_str).unwrap_or("");
    let template = params
        .get("template")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");
    let use_recovery = params
        .get("use_recovery")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if target.is_empty() {
        warn!("🎯 Nuclei called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("nuclei -u {target}");

    if !severity.is_empty() {
        command.push_str(&format!(" -severity {severity}"));
    }

    if !tags.is_empty() {
        command.push_str(&format!(" -tags {tags}"));
    }

    if !template.is_empty() {
        command.push_str(&format!(" -t {template}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔬 Starting Nuclei vulnerability scan: {target}");

    // Use intelligent error handling if enabled
    let result = if use_recovery {
        let mut tool_params = Map::new();
        tool_params.insert("target".to_string(), json!(target));
        tool_params.insert("severity".to_string(), json!(severity));
        tool_params.insert("tags".to_string(), json!(tags));
        tool_params.insert("template".to_string(), json!(template));
        tool_params.insert("additional_args".to_string(), json!(additional_args));
        execute_command_with_recovery(
        "nuclei",
        &command,
        Some(&tool_params),
        true,
        3,
    )
    .await
    } else {
        execute_command(&command, true).await
    };

    info!("📊 Nuclei scan completed for {target}");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/nmap", post(nmap))
        .route("/api/tools/gobuster", post(gobuster))
        .route("/api/tools/nuclei", post(nuclei))
}
