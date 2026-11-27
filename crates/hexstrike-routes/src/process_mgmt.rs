//! Port 1:1 de `hexstrike_server/routes/process_mgmt.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W5.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    22  def list_processes
//!    48  def get_process_status
//!    79  def terminate_process
//!   101  def pause_process
//!   123  def resume_process
//!   145  def process_dashboard
//!   198  def create_vulnerability_card
//!   219  def create_summary_report
//!   241  def format_tool_output
//! ```
//!
//! Rotas (`@app.route`) deste módulo (9):
//!
//! ```text
//!    21  list_processes("/api/processes/list", methods=["GET"])
//!    47  get_process_status("/api/processes/status/<int:pid>", methods=["GET"])
//!    78  terminate_process("/api/processes/terminate/<int:pid>", methods=["POST"])
//!   100  pause_process("/api/processes/pause/<int:pid>", methods=["POST"])
//!   122  resume_process("/api/processes/resume/<int:pid>", methods=["POST"])
//!   144  process_dashboard("/api/processes/dashboard", methods=["GET"])
//!   197  create_vulnerability_card("/api/visual/vulnerability-card", methods=["POST"])
//!   218  create_summary_report("/api/visual/summary-report", methods=["POST"])
//!    240  format_tool_output("/api/visual/tool-output", methods=["POST"])
//! ```
//!
//! Observações de port:
//!
//! - `<int:pid>`: o converter do Werkzeug exige `\d+`. No axum o segmento casa
//!   sempre, então a conversão é feita no handler ([`int_pid`]) e um segmento
//!   que não converge recebe a MESMA página 404 do Flask ([`not_found`]), que é
//!   o que o harness vê ao chamar a regra literal.
//! - `try/except Exception` -> 500 `{"error": "Server error: ..."}`: só existe
//!   onde o port tem operação falível (leitura de `/proc/net/*` no dashboard);
//!   nas demais o corpo não tem nada que possa levantar no Rust.
//! - As 3 rotas `/api/visual/*` chamam métodos que NÃO existem em
//!   `visual_engine.py` (`render_vulnerability_card`, `create_summary_report`,
//!   `format_tool_output` — lá o método é `format_vulnerability_card`): o Python
//!   levanta `AttributeError` e cai no `except` -> 500. O port reproduz o 500.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::{error, info};

use hexstrike_intelligence::param_optimizer::{cpu_percent_interval_1, memory_percent};
use hexstrike_intelligence::process_termination::ProcessManager;
use hexstrike_core::visual_engine::{ModernVisualEngine, ProcessRow, py_truncate};
use hexstrike_intelligence::vuln_intel::iso_now;

/// `time.time()`
fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// `datetime.now().isoformat()`

/// `if not data:` do Python.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Página 404 padrão do Flask/Werkzeug, byte-a-byte.
pub const FLASK_404_PAGE: &str = "<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n";

/// `<int:pid>`: `\d+` (converter do Werkzeug) convertido a inteiro.
pub fn int_pid(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// Resposta de rota inexistente do Flask (ver [`int_pid`]).
pub fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        FLASK_404_PAGE,
    )
        .into_response()
}

/// `len(psutil.net_connections())` (`kind="inet"`): uma linha por socket em
/// `/proc/net/{tcp,tcp6,udp,udp6}`, fora o cabeçalho.
fn net_connections_count() -> std::io::Result<usize> {
    let mut total = 0;
    for path in [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        let raw = std::fs::read_to_string(path)?;
        total += raw.lines().skip(1).filter(|line| !line.trim().is_empty()).count();
    }
    Ok(total)
}

/// Campos calculados que `list_processes`/`get_process_status` acrescentam a
/// cada `info` (`runtime_formatted` e `eta_formatted`).
fn add_calculated_fields(process_info: &mut Value, current_time: f64) {
    let Some(info) = process_info.as_object_mut() else {
        return;
    };
    let start_time = info
        .get("start_time")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let runtime = current_time - start_time;
    info.insert(
        "runtime_formatted".to_string(),
        json!(format!("{runtime:.1}s")),
    );

    let progress = info
        .get("progress")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if progress > 0.0 {
        let eta = (runtime / progress) * (1.0 - progress);
        info.insert("eta_formatted".to_string(), json!(format!("{eta:.1}s")));
    } else {
        info.insert("eta_formatted".to_string(), json!("Unknown"));
    }
}

// ============================================================================
// PROCESS MANAGEMENT API ENDPOINTS (v5.0 ENHANCEMENT)
// ============================================================================

/// `@app.route("/api/processes/list", methods=["GET"])` —
/// `def list_processes()`: lista os processos ativos.
pub async fn list_processes() -> (StatusCode, Json<Value>) {
    let mut processes = ProcessManager::list_active_processes();
    let current_time = now_secs();

    // Add calculated fields for each process
    if let Some(map) = processes.as_object_mut() {
        for info in map.values_mut() {
            add_calculated_fields(info, current_time);
        }
    }

    let total_count = processes.as_object().map(|m| m.len()).unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "active_processes": processes,
            "total_count": total_count,
        })),
    )
}

/// `@app.route("/api/processes/status/<int:pid>", methods=["GET"])` —
/// `def get_process_status(pid)`: status de um processo.
pub async fn get_process_status(Path(pid): Path<String>) -> Response {
    let Some(pid) = int_pid(&pid) else {
        return not_found();
    };

    let Some(mut process_info) = ProcessManager::get_process_status(pid) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": format!("Process {pid} not found"),
            })),
        )
            .into_response();
    };

    // Add calculated fields
    add_calculated_fields(&mut process_info, now_secs());

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "process": process_info,
        })),
    )
        .into_response()
}

/// `@app.route("/api/processes/terminate/<int:pid>", methods=["POST"])` —
/// `def terminate_process(pid)`.
pub async fn terminate_process(Path(pid): Path<String>) -> Response {
    let Some(pid) = int_pid(&pid) else {
        return not_found();
    };

    let success = ProcessManager::terminate_process(pid);

    if success {
        info!("🛑 Process {pid} terminated successfully");
        return (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": format!("Process {pid} terminated successfully"),
            })),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "success": false,
            "error": format!("Failed to terminate process {pid} or process not found"),
        })),
    )
        .into_response()
}

/// `@app.route("/api/processes/pause/<int:pid>", methods=["POST"])` —
/// `def pause_process(pid)`.
pub async fn pause_process(Path(pid): Path<String>) -> Response {
    let Some(pid) = int_pid(&pid) else {
        return not_found();
    };

    let success = ProcessManager::pause_process(pid);

    if success {
        info!("⏸️ Process {pid} paused successfully");
        return (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": format!("Process {pid} paused successfully"),
            })),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "success": false,
            "error": format!("Failed to pause process {pid} or process not found"),
        })),
    )
        .into_response()
}

/// `@app.route("/api/processes/resume/<int:pid>", methods=["POST"])` —
/// `def resume_process(pid)`.
pub async fn resume_process(Path(pid): Path<String>) -> Response {
    let Some(pid) = int_pid(&pid) else {
        return not_found();
    };

    let success = ProcessManager::resume_process(pid);

    if success {
        info!("▶️ Process {pid} resumed successfully");
        return (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": format!("Process {pid} resumed successfully"),
            })),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "success": false,
            "error": format!("Failed to resume process {pid} or process not found"),
        })),
    )
        .into_response()
}

/// `@app.route("/api/processes/dashboard", methods=["GET"])` —
/// `def process_dashboard()`: dashboard visual (ModernVisualEngine).
pub async fn process_dashboard() -> Response {
    let processes = ProcessManager::list_active_processes();
    let current_time = now_secs();

    let rows: Vec<ProcessRow> = processes
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(pid, info)| ProcessRow {
                    pid: pid.parse().unwrap_or(0),
                    status: info
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    command: info
                        .get("command")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    duration: info
                        .get("duration")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0),
                })
                .collect()
        })
        .unwrap_or_default();

    // Create beautiful dashboard using ModernVisualEngine
    let dashboard_visual = ModernVisualEngine::create_live_dashboard(&rows);
    let active_connections = match net_connections_count() {
        Ok(count) => count,
        Err(e) => {
            error!("💥 Error getting process dashboard: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {e}")})),
            )
                .into_response();
        }
    };

    let mut process_list: Vec<Value> = Vec::new();
    if let Some(map) = processes.as_object() {
        for (pid, info) in map {
            let start_time = info
                .get("start_time")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let runtime = current_time - start_time;
            let progress_fraction = info
                .get("progress")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let command = info.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let eta = info.get("eta").and_then(|v| v.as_f64()).unwrap_or(0.0);

            // Create beautiful progress bar using ModernVisualEngine
            let progress_bar = ModernVisualEngine::render_progress_bar(
                progress_fraction,
                25,
                "cyber",
                "",
                eta,
                "",
            );

            let command_display = if command.chars().count() > 60 {
                format!("{}...", py_truncate(command, 60))
            } else {
                command.to_string()
            };

            process_list.push(json!({
                "pid": pid.parse::<u32>().unwrap_or(0),
                "command": command_display,
                "status": info.get("status").cloned().unwrap_or(json!("")),
                "runtime": format!("{runtime:.1}s"),
                "progress_percent": format!("{:.1}%", progress_fraction * 100.0),
                "progress_bar": progress_bar,
                "eta": if eta > 0.0 { format!("{eta:.0}s") } else { "Calculating...".to_string() },
                "bytes_processed": info.get("bytes_processed").cloned().unwrap_or(json!(0)),
                "last_output": py_truncate(
                    info.get("last_output").and_then(|v| v.as_str()).unwrap_or(""),
                    100
                ),
            }));
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "timestamp": iso_now(),
            "total_processes": processes.as_object().map(|m| m.len()).unwrap_or(0),
            "visual_dashboard": dashboard_visual,
            "processes": process_list,
            "system_load": {
                "cpu_percent": cpu_percent_interval_1(),
                "memory_percent": memory_percent(),
                "active_connections": active_connections,
            },
        })),
    )
        .into_response()
}

/// `@app.route("/api/visual/vulnerability-card", methods=["POST"])` —
/// `def create_vulnerability_card()`.
pub async fn create_vulnerability_card(Json(data): Json<Value>) -> Response {
    if !py_truthy(&data) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No data provided"})),
        )
            .into_response();
    }

    // `ModernVisualEngine.render_vulnerability_card(data)`: o método não existe
    // em `visual_engine.py` -> AttributeError -> `except` -> 500.
    let message = "type object 'ModernVisualEngine' has no attribute 'render_vulnerability_card'";
    error!("💥 Error creating vulnerability card: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    )
        .into_response()
}

/// `@app.route("/api/visual/summary-report", methods=["POST"])` —
/// `def create_summary_report()`.
pub async fn create_summary_report(Json(data): Json<Value>) -> Response {
    if !py_truthy(&data) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No data provided"})),
        )
            .into_response();
    }

    // `ModernVisualEngine().create_summary_report(data)`: não existe -> 500.
    let message = "'ModernVisualEngine' object has no attribute 'create_summary_report'";
    error!("💥 Error creating summary report: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    )
        .into_response()
}

/// `@app.route("/api/visual/tool-output", methods=["POST"])` —
/// `def format_tool_output()`.
pub async fn format_tool_output(Json(data): Json<Value>) -> Response {
    if !py_truthy(&data) || data.get("tool").is_none() || data.get("output").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Tool and output data required"})),
        )
            .into_response();
    }

    // `ModernVisualEngine.format_tool_output(tool, output, success)`: não existe
    // -> AttributeError -> `except` -> 500.
    let message = "type object 'ModernVisualEngine' has no attribute 'format_tool_output'";
    error!("💥 Error formatting tool output: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    )
        .into_response()
}

/// Rotas deste módulo, na ordem do arquivo Python.
pub fn routes() -> Router {
    Router::new()
        .route("/api/processes/list", get(list_processes))
        .route("/api/processes/status/{pid}", get(get_process_status))
        .route("/api/processes/terminate/{pid}", post(terminate_process))
        .route("/api/processes/pause/{pid}", post(pause_process))
        .route("/api/processes/resume/{pid}", post(resume_process))
        .route("/api/processes/dashboard", get(process_dashboard))
        .route("/api/visual/vulnerability-card", post(create_vulnerability_card))
        .route("/api/visual/summary-report", post(create_summary_report))
        .route("/api/visual/tool-output", post(format_tool_output))
}
