//! Port 1:1 de `hexstrike_server/routes/cloud_security.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W8.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    19  def prowler
//!    63  def trivy
//! ```
//!
//! Rotas (`@app.route`) deste módulo (2):
//!
//! ```text
//!    18  prowler("/api/tools/prowler", methods=["POST"])
//!    62  trivy("/api/tools/trivy", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

// ---------------------------------------------------------------------------
// Auxiliares: o Python repete estes trechos em cada handler.
// `params = request.json` é `Json<Value>`; corpo que não seja objeto vira
// dict vazio (o Python levantaria AttributeError -> 500; divergência
// documentada, o harness sempre envia `{}`).
// ---------------------------------------------------------------------------

/// Truthiness do Python (`if valor:`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Valor JSON como o f-string do Python o formata (`str()`).
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        // `repr` de float sempre traz o `.0` (5000.0), como no Python.
        Value::Number(n) if n.is_f64() => {
            format!("{:?}", n.as_f64().unwrap_or(0.0))
        }
        Value::Number(n) => n.to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// `params.get(chave, padrao)` — valor usado no comando sem condição.
fn p_str(params: &Map<String, Value>, key: &str, default: &str) -> String {
    params.get(key).map(py_str).unwrap_or_else(|| default.to_string())
}

/// `valor = params.get(chave, padrao)` seguido do `if valor:` do Python.
/// `None` significa que o Python não entra no `if` (valor falso).
fn p_if(params: &Map<String, Value>, key: &str, default: Value) -> Option<String> {
    let v = params.get(key).cloned().unwrap_or(default);
    if truthy(&v) {
        Some(py_str(&v))
    } else {
        None
    }
}

/// `@app.route("/api/tools/prowler", methods=["POST"])` — `def prowler()`.
pub async fn prowler(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let provider = p_str(&params, "provider", "aws");
    let profile = p_if(&params, "profile", json!("default"));
    let region = p_if(&params, "region", json!(""));
    let checks = p_if(&params, "checks", json!(""));
    let output_dir = p_str(&params, "output_dir", "/tmp/prowler_output");
    let output_format = p_str(&params, "output_format", "json");
    let additional_args = p_if(&params, "additional_args", json!(""));

    // Path(output_dir).mkdir(parents=True, exist_ok=True)
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        error!("💥 Error in prowler endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    let mut command = format!("prowler {provider}");

    if let Some(profile) = &profile {
        command += &format!(" --profile {profile}");
    }

    if let Some(region) = &region {
        command += &format!(" --region {region}");
    }

    if let Some(checks) = &checks {
        command += &format!(" --checks {checks}");
    }

    command += &format!(" --output-directory {output_dir}");
    command += &format!(" --output-format {output_format}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting Prowler {provider} security assessment");
    let mut result = execute_command(&command, true).await;
    // result["output_directory"] = output_dir
    if let Some(obj) = result.as_object_mut() {
        obj.insert("output_directory".to_string(), json!(output_dir));
    }
    info!("📊 Prowler assessment completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/trivy", methods=["POST"])` — `def trivy()`.
pub async fn trivy(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let scan_type = p_str(&params, "scan_type", "image");
    let target = p_str(&params, "target", "");
    let output_format = p_if(&params, "output_format", json!("json"));
    let severity = p_if(&params, "severity", json!(""));
    let output_file = p_if(&params, "output_file", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if target.is_empty() {
        warn!("🎯 Trivy called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("trivy {scan_type} {target}");

    if let Some(output_format) = &output_format {
        command += &format!(" --format {output_format}");
    }

    if let Some(severity) = &severity {
        command += &format!(" --severity {severity}");
    }

    if let Some(output_file) = &output_file {
        command += &format!(" --output {output_file}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting Trivy {scan_type} scan: {target}");
    let mut result = execute_command(&command, true).await;
    // if output_file: result["output_file"] = output_file
    if let Some(output_file) = &output_file {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("output_file".to_string(), json!(output_file));
        }
    }
    info!("📊 Trivy scan completed for {target}");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/prowler", post(prowler))
        .route("/api/tools/trivy", post(trivy))
}
