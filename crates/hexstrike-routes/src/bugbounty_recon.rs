//! Port 1:1 de `hexstrike_server/routes/bugbounty_recon.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W7.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  def hakrawler
//! ```
//!
//! Rotas (`@app.route`) deste módulo (1):
//!
//! ```text
//!    17  hakrawler("/api/tools/hakrawler", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::{info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

/// `@app.route("/api/tools/hakrawler", methods=["POST"])`
///
/// ```text
/// Execute Hakrawler for web endpoint discovery with enhanced logging
///
/// Note: This implementation uses the standard Kali Linux hakrawler (hakluke/hakrawler)
/// command line arguments, NOT the Elsfa7-110 fork. The standard version uses:
/// - echo URL | hakrawler (stdin input)
/// - -d for depth (not -depth)
/// - -s for showing sources (not -forms)
/// - -u for unique URLs
/// - -subs for subdomain inclusion
/// ```
///
/// O `try/except Exception -> 500` do Python (`{"error": f"Server error: {str(e)}"}`
/// e `logger.error(f"💥 Error in hakrawler endpoint: {str(e)}")`) é inalcançável
/// em Rust por construção e fica documentado em vez de inventado.
pub async fn hakrawler(Json(params): Json<Value>) -> (StatusCode, Json<Value>) {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let depth = params.get("depth").and_then(Value::as_i64).unwrap_or(2);
    let forms = params
        .get("forms")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let robots = params
        .get("robots")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let sitemap = params
        .get("sitemap")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let wayback = params
        .get("wayback")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🕷️ Hakrawler called without URL parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        );
    }

    // Build command for standard Kali Linux hakrawler (hakluke version)
    let mut command = format!("echo '{url}' | hakrawler -d {depth}");

    if forms {
        // Show sources (includes forms)
        command += " -s";
    }
    if robots || sitemap || wayback {
        // Include subdomains for better coverage
        command += " -subs";
    }

    // Add unique URLs flag for cleaner output
    command += " -u";

    if !additional_args.is_empty() {
        command += &format!(" {additional_args}");
    }

    info!("🕷️ Starting Hakrawler crawling: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Hakrawler crawling completed");
    (StatusCode::OK, Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new().route("/api/tools/hakrawler", post(hakrawler))
}
