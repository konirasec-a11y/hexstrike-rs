//! Port 1:1 de `hexstrike_server/routes/binary_analysis.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W8.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    19  def gdb
//!    68  def radare2
//!   111  def binwalk
//!   146  def ropgadget
//!   179  def checksec
//!   204  def xxd
//!   240  def strings
//!   272  def objdump
//! ```
//!
//! Rotas (`@app.route`) deste módulo (8):
//!
//! ```text
//!    18  gdb("/api/tools/gdb", methods=["POST"])
//!    67  radare2("/api/tools/radare2", methods=["POST"])
//!   110  binwalk("/api/tools/binwalk", methods=["POST"])
//!   145  ropgadget("/api/tools/ropgadget", methods=["POST"])
//!   178  checksec("/api/tools/checksec", methods=["POST"])
//!   203  xxd("/api/tools/xxd", methods=["POST"])
//!   239  strings("/api/tools/strings", methods=["POST"])
//!   271  objdump("/api/tools/objdump", methods=["POST"])
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

/// `flag = params.get(chave, padrao)` usado como booleano (Python truthiness).
fn p_bool(params: &Map<String, Value>, key: &str, default: bool) -> bool {
    params.get(key).map(truthy).unwrap_or(default)
}

/// `@app.route("/api/tools/gdb", methods=["POST"])` — `def gdb()`.
pub async fn gdb(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let commands = p_if(&params, "commands", json!(""));
    let script_file = p_if(&params, "script_file", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 GDB called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command = format!("gdb {binary}");

    if let Some(script_file) = &script_file {
        command += &format!(" -x {script_file}");
    }

    if let Some(commands) = &commands {
        let temp_script = "/tmp/gdb_commands.txt";
        if let Err(e) = std::fs::write(temp_script, commands) {
            error!("💥 Error in gdb endpoint: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {e}")})),
            ));
        }
        command += &format!(" -x {temp_script}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += " -batch";

    info!("🔧 Starting GDB analysis: {binary}");
    let result = execute_command(&command, true).await;

    // if commands and os.path.exists("/tmp/gdb_commands.txt"): os.remove(...)
    //   except: pass
    if commands.is_some() {
        let _ = std::fs::remove_file("/tmp/gdb_commands.txt");
    }

    info!("📊 GDB analysis completed for {binary}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/radare2", methods=["POST"])` — `def radare2()`.
pub async fn radare2(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let commands = p_if(&params, "commands", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 Radare2 called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command;
    if let Some(commands) = &commands {
        let temp_script = "/tmp/r2_commands.txt";
        if let Err(e) = std::fs::write(temp_script, commands) {
            error!("💥 Error in radare2 endpoint: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {e}")})),
            ));
        }
        command = format!("r2 -i {temp_script} -q {binary}");
    } else {
        command = format!("r2 -q {binary}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting Radare2 analysis: {binary}");
    let result = execute_command(&command, true).await;

    // if commands and os.path.exists("/tmp/r2_commands.txt"): os.remove(...)
    //   except: pass
    if commands.is_some() {
        let _ = std::fs::remove_file("/tmp/r2_commands.txt");
    }

    info!("📊 Radare2 analysis completed for {binary}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/binwalk", methods=["POST"])` — `def binwalk()`.
pub async fn binwalk(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let file_path = p_str(&params, "file_path", "");
    let extract = p_bool(&params, "extract", false);
    let additional_args = p_if(&params, "additional_args", json!(""));

    if file_path.is_empty() {
        warn!("🔧 Binwalk called without file_path parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "File path parameter is required"})),
        ));
    }

    let mut command = "binwalk".to_string();

    if extract {
        command += " -e";
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {file_path}");

    info!("🔧 Starting Binwalk analysis: {file_path}");
    let result = execute_command(&command, true).await;
    info!("📊 Binwalk analysis completed for {file_path}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/ropgadget", methods=["POST"])` — `def ropgadget()`.
pub async fn ropgadget(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let gadget_type = p_if(&params, "gadget_type", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 ROPgadget called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command = format!("ROPgadget --binary {binary}");

    if let Some(gadget_type) = &gadget_type {
        command += &format!(" --only '{gadget_type}'");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting ROPgadget search: {binary}");
    let result = execute_command(&command, true).await;
    info!("📊 ROPgadget search completed for {binary}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/checksec", methods=["POST"])` — `def checksec()`.
pub async fn checksec(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");

    if binary.is_empty() {
        warn!("🔧 Checksec called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let command = format!("checksec --file={binary}");

    info!("🔧 Starting Checksec analysis: {binary}");
    let result = execute_command(&command, true).await;
    info!("📊 Checksec analysis completed for {binary}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/xxd", methods=["POST"])` — `def xxd()`.
pub async fn xxd(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let file_path = p_str(&params, "file_path", "");
    let offset = p_str(&params, "offset", "0");
    let length = p_if(&params, "length", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if file_path.is_empty() {
        warn!("🔧 XXD called without file_path parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "File path parameter is required"})),
        ));
    }

    let mut command = format!("xxd -s {offset}");

    if let Some(length) = &length {
        command += &format!(" -l {length}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {file_path}");

    info!("🔧 Starting XXD hex dump: {file_path}");
    let result = execute_command(&command, true).await;
    info!("📊 XXD hex dump completed for {file_path}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/strings", methods=["POST"])` — `def strings()`.
pub async fn strings(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let file_path = p_str(&params, "file_path", "");
    let min_len = p_str(&params, "min_len", "4");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if file_path.is_empty() {
        warn!("🔧 Strings called without file_path parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "File path parameter is required"})),
        ));
    }

    let mut command = format!("strings -n {min_len}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {file_path}");

    info!("🔧 Starting Strings extraction: {file_path}");
    let result = execute_command(&command, true).await;
    info!("📊 Strings extraction completed for {file_path}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/objdump", methods=["POST"])` — `def objdump()`.
pub async fn objdump(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let disassemble = p_bool(&params, "disassemble", true);
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 Objdump called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command = "objdump".to_string();

    if disassemble {
        command += " -d";
    } else {
        command += " -x";
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {binary}");

    info!("🔧 Starting Objdump analysis: {binary}");
    let result = execute_command(&command, true).await;
    info!("📊 Objdump analysis completed for {binary}");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/gdb", post(gdb))
        .route("/api/tools/radare2", post(radare2))
        .route("/api/tools/binwalk", post(binwalk))
        .route("/api/tools/ropgadget", post(ropgadget))
        .route("/api/tools/checksec", post(checksec))
        .route("/api/tools/xxd", post(xxd))
        .route("/api/tools/strings", post(strings))
        .route("/api/tools/objdump", post(objdump))
}
