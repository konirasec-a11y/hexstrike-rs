//! Port 1:1 de `hexstrike_server/routes/web_security.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  def feroxbuster
//!    49  def dotdotpwn
//!    81  def xsser
//!   114  def wfuzz
//! ```
//!
//! Rotas (`@app.route`) deste módulo (4):
//!
//! ```text
//!    17  feroxbuster("/api/tools/feroxbuster", methods=["POST"])
//!    48  dotdotpwn("/api/tools/dotdotpwn", methods=["POST"])
//!    80  xsser("/api/tools/xsser", methods=["POST"])
//!   113  wfuzz("/api/tools/wfuzz", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::{info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

/// `jsonify(x)` (200) vs `jsonify(x), <status>` (≠200). O `Result` do axum
/// devolve o status só no ramo de erro, então o ramo 200 continua sendo
/// `Json<Value>`.
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// `@app.route("/api/tools/feroxbuster", methods=["POST"])` — `def feroxbuster()`.
pub async fn feroxbuster(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let threads = params.get("threads").and_then(Value::as_i64).unwrap_or(10);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Feroxbuster called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("feroxbuster -u {url} -w {wordlist} -t {threads}");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting Feroxbuster scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Feroxbuster scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/dotdotpwn", methods=["POST"])` — `def dotdotpwn()`.
pub async fn dotdotpwn(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let module = params
        .get("module")
        .and_then(Value::as_str)
        .unwrap_or("http");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if target.is_empty() {
        warn!("🎯 DotDotPwn called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("dotdotpwn -m {module} -h {target}");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    // O `-b` do Python vem DEPOIS dos additional_args.
    command.push_str(" -b");

    info!("🔍 Starting DotDotPwn scan: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 DotDotPwn scan completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/xsser", methods=["POST"])` — `def xsser()`.
pub async fn xsser(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let params_str = params
        .get("params")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 XSSer called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("xsser --url '{url}'");

    if !params_str.is_empty() {
        command.push_str(&format!(" --param='{params_str}'"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting XSSer scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 XSSer scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/wfuzz", methods=["POST"])` — `def wfuzz()`.
pub async fn wfuzz(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Wfuzz called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("wfuzz -w {wordlist} '{url}'");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting Wfuzz scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Wfuzz scan completed for {url}");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/feroxbuster", post(feroxbuster))
        .route("/api/tools/dotdotpwn", post(dotdotpwn))
        .route("/api/tools/xsser", post(xsser))
        .route("/api/tools/wfuzz", post(wfuzz))
}
