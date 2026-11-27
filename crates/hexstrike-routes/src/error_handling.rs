//! Port 1:1 de `hexstrike_server/routes/error_handling.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W2.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    25  def get_error_statistics
//!    39  def test_error_recovery
//!    85  def get_fallback_chains
//!   113  def execute_with_recovery_endpoint
//!   146  def classify_error_endpoint
//!   178  def get_parameter_adjustments
//!   211  def get_alternative_tools
//!   234  BANNER = ModernVisualEngine.create_banner()
//! ```
//!
//! Rotas (`@app.route`) deste módulo (7):
//!
//! ```text
//!    24  get_error_statistics("/api/error-handling/statistics", methods=["GET"])
//!    38  test_error_recovery("/api/error-handling/test-recovery", methods=["POST"])
//!    84  get_fallback_chains("/api/error-handling/fallback-chains", methods=["GET"])
//!   112  execute_with_recovery_endpoint("/api/error-handling/execute-with-recovery", methods=["POST"])
//!   145  classify_error_endpoint("/api/error-handling/classify-error", methods=["POST"])
//!   177  get_parameter_adjustments("/api/error-handling/parameter-adjustments", methods=["POST"])
//!   210  get_alternative_tools("/api/error-handling/alternative-tools", methods=["GET"])
//! ```
//!
//! O `try/except Exception -> 500` de cada rota não tem caminho equivalente
//! aqui: os helpers portados não levantam exceção, então só os `400` do Python
//! (validação de entrada) viram `(StatusCode, Json<Value>)`.

use std::sync::LazyLock;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use hexstrike_intelligence::error_recovery::{
    degradation_manager, error_handler, ErrorType, Exception,
};
use hexstrike_intelligence::exploit_gen::execute_command_with_recovery;
use hexstrike_core::visual_engine::ModernVisualEngine;
use hexstrike_intelligence::vuln_intel::iso_now;

/// `get_error_statistics()` — `stats = error_handler.get_error_statistics()`.
pub async fn get_error_statistics() -> Json<Value> {
    let stats = error_handler.lock().unwrap().get_error_statistics();
    Json(json!({
        "success": true,
        "statistics": stats,
        "timestamp": iso_now(),
    }))
}

/// `test_error_recovery()` — simula uma falha e pede a estratégia ao handler.
pub async fn test_error_recovery(Json(data): Json<Value>) -> Json<Value> {
    let tool_name = data
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("nmap")
        .to_string();
    let error_type = data
        .get("error_type")
        .and_then(|v| v.as_str())
        .unwrap_or("timeout")
        .to_string();
    let target = data
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("example.com")
        .to_string();

    // Simulate an error for testing
    let exception = match error_type.as_str() {
        "timeout" => Exception::TimeoutError("Simulated timeout error".to_string()),
        "permission_denied" => Exception::PermissionError("Simulated permission error".to_string()),
        "network_unreachable" => Exception::ConnectionError("Simulated network error".to_string()),
        other => Exception::Exception(format!("Simulated {other} error")),
    };

    let context = json!({
        "target": target,
        "parameters": data.get("parameters").cloned().unwrap_or_else(|| json!({})),
        "attempt_count": 1,
    });

    // Get recovery strategy
    let mut handler = error_handler.lock().unwrap();
    let recovery_strategy = handler.handle_tool_failure(&tool_name, &exception, &context);
    let error_classification = handler
        .classify_error(exception.message(), Some(&exception))
        .value();
    let alternative_tools: Vec<&'static str> = handler
        .tool_alternatives
        .get(tool_name.as_str())
        .map(|alternatives| alternatives.to_vec())
        .unwrap_or_default();

    Json(json!({
        "success": true,
        "recovery_strategy": {
            "action": recovery_strategy.action.value(),
            "parameters": recovery_strategy.parameters,
            "max_attempts": recovery_strategy.max_attempts,
            "success_probability": recovery_strategy.success_probability,
            "estimated_time": recovery_strategy.estimated_time,
        },
        "error_classification": error_classification,
        "alternative_tools": alternative_tools,
        "timestamp": iso_now(),
    }))
}

/// `get_fallback_chains()` — cadeias de fallback por operação.
pub async fn get_fallback_chains(Query(query): Query<Vec<(String, String)>>) -> Json<Value> {
    let operation = query_arg(&query, "operation").to_string();
    let failed_tools = query_getlist(&query, "failed_tools");

    let manager = degradation_manager.lock().unwrap();
    if !operation.is_empty() {
        let fallback_chain = manager.create_fallback_chain(&operation, &failed_tools);
        Json(json!({
            "success": true,
            "operation": operation,
            "fallback_chain": fallback_chain,
            "is_critical": manager.is_critical_operation(&operation),
            "timestamp": iso_now(),
        }))
    } else {
        // `list(fallback_chains.keys())` / `list(critical_operations)`
        let available_operations: Vec<&'static str> =
            manager.fallback_chains.iter().map(|(name, _)| *name).collect();
        let critical_operations = manager.critical_operations.clone();
        Json(json!({
            "success": true,
            "available_operations": available_operations,
            "critical_operations": critical_operations,
            "timestamp": iso_now(),
        }))
    }
}

/// `execute_with_recovery_endpoint()` — executa com recuperação inteligente.
///
/// Dependência de outro shard: `execute_command_with_recovery` mora em
/// `intelligence/exploit_gen.py` (ainda não portada).
pub async fn execute_with_recovery_endpoint(
    Json(data): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tool_name = data
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let command = data
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let parameters = data.get("parameters").cloned().unwrap_or_else(|| json!({}));
    let max_attempts = data
        .get("max_attempts")
        .and_then(|v| v.as_u64())
        .unwrap_or(3) as u32;
    let use_cache = data.get("use_cache").and_then(|v| v.as_bool()).unwrap_or(true);

    if tool_name.is_empty() || command.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "tool_name and command are required"})),
        ));
    }

    // Execute command with recovery
    let result = execute_command_with_recovery(
        &tool_name,
        &command,
        parameters.as_object(),
        use_cache,
        max_attempts,
    )
    .await;

    let success = result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(Json(json!({
        "success": success,
        "result": result,
        "timestamp": iso_now(),
    })))
}

/// `classify_error_endpoint()` — classifica uma mensagem de erro.
pub async fn classify_error_endpoint(
    Json(data): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let error_message = data
        .get("error_message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if error_message.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "error_message is required"})),
        ));
    }

    let handler = error_handler.lock().unwrap();
    let error_type = handler.classify_error(&error_message, None);
    let recovery_strategies: Vec<Value> = handler
        .recovery_strategies
        .get(&error_type)
        .map(|strategies| {
            strategies
                .iter()
                .map(|strategy| {
                    json!({
                        "action": strategy.action.value(),
                        "parameters": strategy.parameters,
                        "success_probability": strategy.success_probability,
                        "estimated_time": strategy.estimated_time,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(json!({
        "success": true,
        "error_type": error_type.value(),
        "recovery_strategies": recovery_strategies,
        "timestamp": iso_now(),
    })))
}

/// `get_parameter_adjustments()` — ajustes de parâmetro por ferramenta/erro.
pub async fn get_parameter_adjustments(
    Json(data): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tool_name = data
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let error_type_str = data
        .get("error_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let original_params = data.get("original_params").cloned().unwrap_or_else(|| json!({}));

    if tool_name.is_empty() || error_type_str.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "tool_name and error_type are required"})),
        ));
    }

    // Convert string to ErrorType enum (`except ValueError`)
    let Some(error_type) = ErrorType::from_value(&error_type_str) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Invalid error_type: {error_type_str}")})),
        ));
    };

    let adjusted_params = error_handler.lock().unwrap().auto_adjust_parameters(
        &tool_name,
        error_type,
        &original_params,
    );

    Ok(Json(json!({
        "success": true,
        "tool_name": tool_name,
        "error_type": error_type.value(),
        "original_params": original_params,
        "adjusted_params": adjusted_params,
        "timestamp": iso_now(),
    })))
}

/// `get_alternative_tools()` — ferramentas alternativas para uma ferramenta.
pub async fn get_alternative_tools(
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tool_name = query_arg(&query, "tool_name").to_string();

    if tool_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "tool_name parameter is required"})),
        ));
    }

    let alternatives: Vec<&'static str> = error_handler
        .lock()
        .unwrap()
        .tool_alternatives
        .get(tool_name.as_str())
        .map(|alternatives| alternatives.to_vec())
        .unwrap_or_default();
    let has_alternatives = !alternatives.is_empty();

    Ok(Json(json!({
        "success": true,
        "tool_name": tool_name,
        "alternatives": alternatives,
        "has_alternatives": has_alternatives,
        "timestamp": iso_now(),
    })))
}

/// `request.args.get(nome, "")` — primeiro valor.
fn query_arg<'a>(query: &'a [(String, String)], name: &str) -> &'a str {
    query
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or("")
}

/// `request.args.getlist(nome)` — todos os valores, na ordem.
fn query_getlist(query: &[(String, String)], name: &str) -> Vec<String> {
    query
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .collect()
}

/// `BANNER = ModernVisualEngine.create_banner()` — o `main.py` imprime.
pub static BANNER: LazyLock<String> = LazyLock::new(ModernVisualEngine::create_banner);

/// As 7 rotas deste módulo, na ordem dos `@app.route` do Python.
pub fn routes() -> Router {
    Router::new()
        .route("/api/error-handling/statistics", get(get_error_statistics))
        .route("/api/error-handling/test-recovery", post(test_error_recovery))
        .route("/api/error-handling/fallback-chains", get(get_fallback_chains))
        .route(
            "/api/error-handling/execute-with-recovery",
            post(execute_with_recovery_endpoint),
        )
        .route("/api/error-handling/classify-error", post(classify_error_endpoint))
        .route(
            "/api/error-handling/parameter-adjustments",
            post(get_parameter_adjustments),
        )
        .route("/api/error-handling/alternative-tools", get(get_alternative_tools))
}
