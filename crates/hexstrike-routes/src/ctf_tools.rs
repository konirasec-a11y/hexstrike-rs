//! Port 1:1 de `hexstrike_server/routes/ctf_tools.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W6.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    19  def volatility3
//!    59  def foremost
//!    99  def steghide
//!   148  def exiftool
//!   187  def hashpump
//! ```
//!
//! Rotas (`@app.route`) deste módulo (5):
//!
//! ```text
//!    18  volatility3("/api/tools/volatility3", methods=["POST"])
//!    58  foremost("/api/tools/foremost", methods=["POST"])
//!    98  steghide("/api/tools/steghide", methods=["POST"])
//!   147  exiftool("/api/tools/exiftool", methods=["POST"])
//!   186  hashpump("/api/tools/hashpump", methods=["POST"])
//! ```

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

/// `params = request.json` + o helper `params.get(key, default)` do Python.
///
/// O corpo destas rotas é `try: ... except Exception as e: 500`. Em Rust nada
/// levanta, exceto o único caso que sobra: corpo JSON que não é objeto
/// (`null`/lista/str) — o `params.get` do Python levanta AttributeError.
/// [`request_json`] reproduz esse caminho e [`get_str`] é o
/// `params.get(key, "")`.
///
/// Corpo sem `Content-Type: application/json` ou com JSON inválido nem chega
/// aqui: o extrator `Json` do axum recusa (415/400 em texto puro) antes do
/// handler, enquanto o Flask devolve 500 com a mensagem do erro dele. É a
/// única divergência do `except Exception` que não tem equivalente em Rust.
fn request_json<'a>(body: &'a Value, log: &str) -> Result<&'a Value, (StatusCode, Json<Value>)> {
    if body.is_object() {
        return Ok(body);
    }

    let python_type = match body {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    };
    let message = format!("'{python_type}' object has no attribute 'get'");
    error!("{log}: {message}");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    ))
}

/// `params.get(key, default)` — o default só vale quando a chave não existe.
/// Valor não-string cai em `""` (o Python usaria `str(valor)` no comando).
fn get_str(params: &Value, key: &str, default: &str) -> String {
    match params.get(key) {
        None => default.to_string(),
        Some(value) => value.as_str().unwrap_or_default().to_string(),
    }
}

/// Execute Volatility3 for advanced memory forensics with enhanced logging
pub async fn volatility3(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in volatility3 endpoint") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let memory_file = get_str(params, "memory_file", "");
    let plugin = get_str(params, "plugin", "");
    let output_file = get_str(params, "output_file", "");
    let additional_args = get_str(params, "additional_args", "");

    if memory_file.is_empty() {
        warn!("🧠 Volatility3 called without memory_file parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Memory file parameter is required"})),
        );
    }

    if plugin.is_empty() {
        warn!("🧠 Volatility3 called without plugin parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Plugin parameter is required"})),
        );
    }

    let mut command = format!("vol.py -f {memory_file} {plugin}");

    if !output_file.is_empty() {
        command.push_str(&format!(" -o {output_file}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🧠 Starting Volatility3 analysis: {plugin}");
    let result = execute_command(&command, true).await;
    info!("📊 Volatility3 analysis completed");
    (StatusCode::OK, Json(result))
}

/// Execute Foremost for file carving with enhanced logging
pub async fn foremost(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in foremost endpoint") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let input_file = get_str(params, "input_file", "");
    let output_dir = get_str(params, "output_dir", "/tmp/foremost_output");
    let file_types = get_str(params, "file_types", "");
    let additional_args = get_str(params, "additional_args", "");

    if input_file.is_empty() {
        warn!("📁 Foremost called without input_file parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Input file parameter is required"})),
        );
    }

    // Ensure output directory exists
    if let Err(error) = std::fs::create_dir_all(&output_dir) {
        let message = py_os_error(&output_dir, &error);
        error!("💥 Error in foremost endpoint: {message}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {message}")})),
        );
    }

    let mut command = format!("foremost -o {output_dir}");

    if !file_types.is_empty() {
        command.push_str(&format!(" -t {file_types}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    command.push_str(&format!(" {input_file}"));

    info!("📁 Starting Foremost file carving: {input_file}");
    let mut result = execute_command(&command, true).await;
    result["output_directory"] = json!(output_dir);
    info!("📊 Foremost carving completed");
    (StatusCode::OK, Json(result))
}

/// Execute Steghide for steganography analysis with enhanced logging
pub async fn steghide(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in steghide endpoint") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let action = get_str(params, "action", "extract"); // extract, embed, info
    let cover_file = get_str(params, "cover_file", "");
    let embed_file = get_str(params, "embed_file", "");
    let passphrase = get_str(params, "passphrase", "");
    let output_file = get_str(params, "output_file", "");
    let additional_args = get_str(params, "additional_args", "");

    if cover_file.is_empty() {
        warn!("🖼️ Steghide called without cover_file parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cover file parameter is required"})),
        );
    }

    let mut command = if action == "extract" {
        let mut command = format!("steghide extract -sf {cover_file}");
        if !output_file.is_empty() {
            command.push_str(&format!(" -xf {output_file}"));
        }
        command
    } else if action == "embed" {
        if embed_file.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Embed file required for embed action"})),
            );
        }
        format!("steghide embed -cf {cover_file} -ef {embed_file}")
    } else if action == "info" {
        format!("steghide info {cover_file}")
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid action. Use: extract, embed, info"})),
        );
    };

    if !passphrase.is_empty() {
        command.push_str(&format!(" -p {passphrase}"));
    } else {
        command.push_str(" -p ''"); // Empty passphrase
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🖼️ Starting Steghide {action}: {cover_file}");
    let result = execute_command(&command, true).await;
    info!("📊 Steghide {action} completed");
    (StatusCode::OK, Json(result))
}

/// Execute ExifTool for metadata extraction with enhanced logging
pub async fn exiftool(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in exiftool endpoint") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let file_path = get_str(params, "file_path", "");
    let output_format = get_str(params, "output_format", ""); // json, xml, csv
    let tags = get_str(params, "tags", "");
    let additional_args = get_str(params, "additional_args", "");

    if file_path.is_empty() {
        warn!("📷 ExifTool called without file_path parameter");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "File path parameter is required"})),
        );
    }

    let mut command = "exiftool".to_string();

    if !output_format.is_empty() {
        command.push_str(&format!(" -{output_format}"));
    }

    if !tags.is_empty() {
        command.push_str(&format!(" -{tags}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    command.push_str(&format!(" {file_path}"));

    info!("📷 Starting ExifTool analysis: {file_path}");
    let result = execute_command(&command, true).await;
    info!("📊 ExifTool analysis completed");
    (StatusCode::OK, Json(result))
}

/// Execute HashPump for hash length extension attacks with enhanced logging
pub async fn hashpump(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in hashpump endpoint") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let signature = get_str(params, "signature", "");
    let data = get_str(params, "data", "");
    let key_length = get_str(params, "key_length", "");
    let append_data = get_str(params, "append_data", "");
    let additional_args = get_str(params, "additional_args", "");

    if signature.is_empty() || data.is_empty() || key_length.is_empty() || append_data.is_empty() {
        warn!("🔐 HashPump called without required parameters");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Signature, data, key_length, and append_data parameters are required"
            })),
        );
    }

    let mut command =
        format!("hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔐 Starting HashPump attack");
    let result = execute_command(&command, true).await;
    info!("📊 HashPump attack completed");
    (StatusCode::OK, Json(result))
}

/// `str(exceção)` do Python para `Path(...).mkdir(parents=True)`: o nome no
/// fim é o do caminho (`[Errno 13] Permission denied: '/tmp/x'`).
fn py_os_error(path: &str, error: &std::io::Error) -> String {
    let errno = error.raw_os_error().unwrap_or(0);
    let description = error.to_string();
    let description = description.split(" (os error").next().unwrap_or(&description);
    format!("[Errno {errno}] {description}: '{path}'")
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/volatility3", post(volatility3))
        .route("/api/tools/foremost", post(foremost))
        .route("/api/tools/steghide", post(steghide))
        .route("/api/tools/exiftool", post(exiftool))
        .route("/api/tools/hashpump", post(hashpump))
}
