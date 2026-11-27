//! Port 1:1 de `hexstrike_server/routes/decision_engine.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W1.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    21  def analyze_target
//!    48  def select_optimal_tools
//!    83  def optimize_tool_parameters
//!   119  def create_attack_chain
//!   154  def intelligent_smart_scan
//!   306  def execute_nmap_scan
//!   325  def execute_gobuster_scan
//!   340  def execute_nuclei_scan
//!   359  def execute_nikto_scan
//!   371  def execute_sqlmap_scan
//!   383  def execute_ffuf_scan
//!   401  def execute_feroxbuster_scan
//!   415  def execute_katana_scan
//!   427  def execute_httpx_scan
//!   438  def execute_wpscan_scan
//!   450  def execute_dirsearch_scan
//!   462  def execute_arjun_scan
//!   474  def execute_paramspider_scan
//!   486  def execute_dalfox_scan
//!   498  def execute_amass_scan
//!   510  def execute_subfinder_scan
//!   523  def detect_technologies
//! ```
//!
//! Rotas (`@app.route`) deste módulo (6):
//!
//! ```text
//!    20  analyze_target("/api/intelligence/analyze-target", methods=["POST"])
//!    47  select_optimal_tools("/api/intelligence/select-tools", methods=["POST"])
//!    82  optimize_tool_parameters("/api/intelligence/optimize-parameters", methods=["POST"])
//!   118  create_attack_chain("/api/intelligence/create-attack-chain", methods=["POST"])
//!   153  intelligent_smart_scan("/api/intelligence/smart-scan", methods=["POST"])
//!    523  detect_technologies("/api/intelligence/technology-detection", methods=["POST"])
//! ```
//!
//! ## Notas de paridade
//!
//! - `decision_engine.optimize_parameters` é o único ponto onde o Python do
//!   split estoura (`NameError: name 'parameter_optimizer' is not defined` — ver
//!   a nota em `intelligence/decision_engine.rs`). O `Result` de lá vira o 500
//!   `"Server error: ..."` que o `except Exception as e` destas rotas devolve.
//! - O corpo é lido com `Json<Value>` (o `request.get_json()` do Flask). Um
//!   corpo que não seja JSON é recusado pelo extractor do axum (400) antes do
//!   handler; o Flask responderia 415/500 nesse caso. E `data` que não seja
//!   objeto JSON cai no 400 "Target is required" (com `["target"]` o Python
//!   passaria da checagem e estouraria `TypeError` no `data['target']`).
//! - `ThreadPoolExecutor` da `smart-scan` vira `tokio::spawn` com um semáforo de
//!   `min(len(selected_tools), 5)` permissões, e os resultados são coletados na
//!   ordem de submissão (o `for future in future_to_tool` do Python), não na de
//!   conclusão.

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use hexstrike_intelligence::decision_engine::{decision_engine, TargetProfile, TechnologyStack};
use hexstrike_intelligence::exploit_gen::execute_command;
use hexstrike_intelligence::vuln_intel::iso_now;

/// `datetime.now().isoformat()` — hora local com microssegundos.

/// `if x:` do Python — None/False/0/""/[]/{} são falsos.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Nome de tipo do Python, para as mensagens de `AttributeError`.
fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// `target = data['target']` usado como string.
///
/// No Python o primeiro uso é `target.startswith(...)` DENTRO de
/// `decision_engine.analyze_target`, então um valor que não seja string estoura
/// `AttributeError` e o `except Exception as e` da rota devolve 500
/// `"Server error: ..."`. `log` é a linha de erro de cada rota
/// (`💥 Error analyzing target`, ...).
fn target_as_str<'a>(target: &'a Value, log: &str) -> Result<&'a str, (StatusCode, Json<Value>)> {
    match target.as_str() {
        Some(target) => Ok(target),
        None => {
            let message = format!("'{}' object has no attribute 'startswith'", py_type_name(target));
            error!("{log}: {message}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {message}")})),
            ))
        }
    }
}

/// `@app.route("/api/intelligence/analyze-target", methods=["POST"])`
pub async fn analyze_target(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    // data = request.get_json()
    // if not data or 'target' not in data: -> 400
    let Some(target_value) = data.get("target") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Target is required"})));
    };
    let target = match target_as_str(target_value, "💥 Error analyzing target") {
        Ok(target) => target,
        Err(response) => return response,
    };

    info!("🧠 Analyzing target: {target}");

    // Use the decision engine to analyze the target
    let profile = decision_engine.analyze_target(target);

    info!("✅ Target analysis completed for {target}");
    info!("📊 Target type: {}, Risk level: {}", profile.target_type.value(), profile.risk_level);

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "target_profile": profile.to_dict(),
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/intelligence/select-tools", methods=["POST"])`
pub async fn select_optimal_tools(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(target_value) = data.get("target") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Target is required"})));
    };
    let target = match target_as_str(target_value, "💥 Error selecting tools") {
        Ok(target) => target,
        Err(response) => return response,
    };

    // objective = data.get('objective', 'comprehensive')  # comprehensive, quick, stealth
    let objective = data.get("objective").cloned().unwrap_or_else(|| json!("comprehensive"));
    let objective_str = objective.as_str().unwrap_or_default();

    info!("🎯 Selecting optimal tools for {target} with objective: {objective_str}");

    // Analyze target first
    let profile = decision_engine.analyze_target(target);

    // Select optimal tools
    let selected_tools = decision_engine.select_optimal_tools(&profile, objective_str);

    info!("✅ Selected {} tools for {target}", selected_tools.len());

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "selected_tools": selected_tools,
            "tool_count": selected_tools.len(),
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/intelligence/optimize-parameters", methods=["POST"])`
pub async fn optimize_tool_parameters(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    // if not data or 'target' not in data or 'tool' not in data: -> 400
    let (Some(target_value), Some(tool)) = (data.get("target"), data.get("tool")) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target and tool are required"})),
        );
    };
    let target = match target_as_str(target_value, "💥 Error optimizing parameters") {
        Ok(target) => target,
        Err(response) => return response,
    };

    // context = data.get('context', {}) — `None` também vira `{}` dentro do
    // `optimize_parameters`.
    let context = data.get("context").cloned().unwrap_or_else(|| json!({}));
    let tool_str = tool.as_str().unwrap_or_default();

    info!("⚙️  Optimizing parameters for {tool_str} against {target}");

    // Analyze target first
    let profile = decision_engine.analyze_target(target);

    // Optimize parameters
    let optimized_params = match decision_engine.optimize_parameters(tool_str, &profile, context.as_object()) {
        Ok(params) => params,
        Err(message) => {
            error!("💥 Error optimizing parameters: {message}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {message}")})),
            );
        }
    };

    info!("✅ Parameters optimized for {tool_str}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "target": target,
            "tool": tool,
            "context": context,
            "target_profile": profile.to_dict(),
            "optimized_parameters": optimized_params,
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/intelligence/create-attack-chain", methods=["POST"])`
pub async fn create_attack_chain(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(target_value) = data.get("target") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Target is required"})));
    };
    let target = match target_as_str(target_value, "💥 Error creating attack chain") {
        Ok(target) => target,
        Err(response) => return response,
    };

    let objective = data.get("objective").cloned().unwrap_or_else(|| json!("comprehensive"));
    let objective_str = objective.as_str().unwrap_or_default();

    info!("⚔️  Creating attack chain for {target} with objective: {objective_str}");

    // Analyze target first
    let profile = decision_engine.analyze_target(target);

    // Create attack chain
    let attack_chain = match decision_engine.create_attack_chain(&profile, objective_str) {
        Ok(chain) => chain,
        Err(message) => {
            error!("💥 Error creating attack chain: {message}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {message}")})),
            );
        }
    };

    info!("✅ Attack chain created with {} steps", attack_chain.steps.len());
    info!(
        "📊 Success probability: {:.2}, Estimated time: {}s",
        attack_chain.success_probability, attack_chain.estimated_time
    );

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "attack_chain": attack_chain.to_dict(),
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/intelligence/smart-scan", methods=["POST"])`
pub async fn intelligent_smart_scan(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(target_value) = data.get("target") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Target is required"})));
    };
    let target = match target_as_str(target_value, "💥 Error in intelligent smart scan") {
        Ok(target) => target,
        Err(response) => return response,
    };

    let objective = data.get("objective").cloned().unwrap_or_else(|| json!("comprehensive"));
    let objective_str = objective.as_str().unwrap_or_default();

    // max_tools = data.get('max_tools', 5)
    // (`max_tools: null` no JSON é `[:None]` no Python: a lista inteira)
    let max_tools: Option<i64> = match data.get("max_tools") {
        None => Some(5),
        Some(Value::Null) => None,
        Some(value) => match value.as_i64() {
            Some(max_tools) => Some(max_tools),
            // `selected_tools[:max_tools]` com índice não-inteiro -> TypeError
            None => {
                let message = "slice indices must be integers or None or have an __index__ method";
                error!("💥 Error in intelligent smart scan: {message}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Server error: {message}"), "success": false})),
                );
            }
        },
    };

    info!("🚀 Starting intelligent smart scan for {target}");

    // Analyze target
    let profile = decision_engine.analyze_target(target);

    // Select optimal tools — `select_optimal_tools(profile, objective)[:max_tools]`
    let all_tools = decision_engine.select_optimal_tools(&profile, objective_str);
    let end = match max_tools {
        None => all_tools.len(),
        Some(max_tools) if max_tools < 0 => (all_tools.len() as i64 + max_tools).max(0) as usize,
        Some(max_tools) => (max_tools as usize).min(all_tools.len()),
    };
    let selected_tools: Vec<&'static str> = all_tools[..end].to_vec();

    // Execute tools in parallel with real tool execution
    let mut scan_results: Map<String, Value> = Map::new();
    scan_results.insert("target".to_string(), json!(target));
    scan_results.insert("target_profile".to_string(), profile.to_dict());
    scan_results.insert("tools_executed".to_string(), json!([]));
    scan_results.insert("total_vulnerabilities".to_string(), json!(0));
    scan_results.insert("execution_summary".to_string(), json!({}));
    scan_results.insert("combined_output".to_string(), json!(""));

    // Execute tools in parallel using ThreadPoolExecutor
    let max_workers = selected_tools.len().min(5);
    if max_workers == 0 {
        // `ThreadPoolExecutor(max_workers=0)` -> ValueError
        let message = "max_workers must be greater than 0";
        error!("💥 Error in intelligent smart scan: {message}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {message}"), "success": false})),
        );
    }

    let limiter = Arc::new(Semaphore::new(max_workers));
    let mut handles = Vec::with_capacity(selected_tools.len());
    for tool in &selected_tools {
        let limiter = limiter.clone();
        let target = target.to_string();
        let profile = profile.clone();
        let tool: &'static str = *tool;
        handles.push(tokio::spawn(async move {
            let _permit = limiter.acquire().await;
            execute_single_tool(tool, &target, &profile).await
        }));
    }

    let mut tools_executed: Vec<Value> = Vec::new();
    let mut total_vulnerabilities = 0i64;
    let mut combined_output = String::new();
    let mut total_execution_time = 0.0f64;
    let mut total_execution_time_is_float = false;

    // Collect results as they complete (a ordem de coleta é a de submissão)
    for handle in handles {
        let tool_result = handle.await.unwrap_or_else(|_| json!({}));

        // Accumulate vulnerability count
        if tool_result.get("vulnerabilities_found").is_some_and(truthy) {
            total_vulnerabilities +=
                tool_result["vulnerabilities_found"].as_i64().unwrap_or(0);
        }

        // Combine outputs
        if tool_result.get("stdout").is_some_and(truthy) {
            let tool_name = tool_result["tool"].as_str().unwrap_or_default().to_uppercase();
            combined_output += &format!("\n=== {tool_name} OUTPUT ===\n");
            combined_output += tool_result["stdout"].as_str().unwrap_or_default();
            combined_output += &format!("\n{}\n", "=".repeat(50));
        }

        // `sum(t.get("execution_time", 0) ...)` — o default é o int 0
        if let Some(execution_time) = tool_result.get("execution_time") {
            total_execution_time += execution_time.as_f64().unwrap_or(0.0);
            if execution_time.is_f64() {
                total_execution_time_is_float = true;
            }
        }

        tools_executed.push(tool_result);
    }

    // Create execution summary
    let successful_tools: Vec<&Value> =
        tools_executed.iter().filter(|tool| tool.get("success").is_some_and(truthy)).collect();
    let failed_tools: Vec<&Value> =
        tools_executed.iter().filter(|tool| !tool.get("success").is_some_and(truthy)).collect();

    let success_rate = if selected_tools.is_empty() {
        json!(0)
    } else {
        json!(successful_tools.len() as f64 / selected_tools.len() as f64 * 100.0)
    };
    let total_execution_time = if total_execution_time_is_float {
        json!(total_execution_time)
    } else {
        json!(total_execution_time as i64)
    };
    let tools_used: Vec<Value> =
        successful_tools.iter().map(|tool| tool["tool"].clone()).collect();
    let successful_tools_count = successful_tools.len();
    let failed_tools_count = failed_tools.len();

    scan_results.insert("tools_executed".to_string(), Value::Array(tools_executed));
    scan_results.insert("total_vulnerabilities".to_string(), json!(total_vulnerabilities));
    scan_results.insert("combined_output".to_string(), json!(combined_output));
    scan_results.insert(
        "execution_summary".to_string(),
        json!({
            "total_tools": selected_tools.len(),
            "successful_tools": successful_tools_count,
            "failed_tools": failed_tools_count,
            "success_rate": success_rate,
            "total_execution_time": total_execution_time,
            "tools_used": tools_used,
        }),
    );

    info!("✅ Intelligent smart scan completed for {target}");
    info!(
        "📊 Results: {}/{} tools successful, {} vulnerabilities found",
        successful_tools_count, selected_tools.len(), total_vulnerabilities
    );

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "scan_results": Value::Object(scan_results),
            "timestamp": iso_now(),
        })),
    )
}

/// `def execute_single_tool(tool_name, target, profile)` — a função aninhada de
/// `intelligent_smart_scan` (o `try/except Exception as e` dela).
async fn execute_single_tool(tool_name: &str, target: &str, profile: &TargetProfile) -> Value {
    // try:
    info!("🔧 Executing {tool_name} with optimized parameters");

    // Get optimized parameters for this tool
    let optimized_params = match decision_engine.optimize_parameters(tool_name, profile, None) {
        Ok(params) => params,
        Err(message) => {
            // except Exception as e:
            error!("❌ Error executing {tool_name}: {message}");
            return json!({
                "tool": tool_name,
                "status": "failed",
                "timestamp": iso_now(),
                "error": message,
                "success": false,
            });
        }
    };

    // Map tool names to their actual execution functions
    let result = match tool_name {
        "nmap" => Some(execute_nmap_scan(target, &optimized_params).await),
        "gobuster" => Some(execute_gobuster_scan(target, &optimized_params).await),
        "nuclei" => Some(execute_nuclei_scan(target, &optimized_params).await),
        "nikto" => Some(execute_nikto_scan(target, &optimized_params).await),
        "sqlmap" => Some(execute_sqlmap_scan(target, &optimized_params).await),
        "ffuf" => Some(execute_ffuf_scan(target, &optimized_params).await),
        "feroxbuster" => Some(execute_feroxbuster_scan(target, &optimized_params).await),
        "katana" => Some(execute_katana_scan(target, &optimized_params).await),
        "httpx" => Some(execute_httpx_scan(target, &optimized_params).await),
        "wpscan" => Some(execute_wpscan_scan(target, &optimized_params).await),
        "dirsearch" => Some(execute_dirsearch_scan(target, &optimized_params).await),
        "arjun" => Some(execute_arjun_scan(target, &optimized_params).await),
        "paramspider" => Some(execute_paramspider_scan(target, &optimized_params).await),
        "dalfox" => Some(execute_dalfox_scan(target, &optimized_params).await),
        "amass" => Some(execute_amass_scan(target, &optimized_params).await),
        "subfinder" => Some(execute_subfinder_scan(target, &optimized_params).await),
        _ => None,
    };

    // Execute the tool if we have a mapping for it
    let Some(result) = result else {
        warn!("⚠️ No execution mapping found for tool: {tool_name}");
        return json!({
            "tool": tool_name,
            "parameters": optimized_params,
            "status": "skipped",
            "timestamp": iso_now(),
            "error": format!("Tool {tool_name} not implemented in execution map"),
            "success": false,
        });
    };

    // Extract vulnerability count from result
    let mut vuln_count = 0i64;
    if result.get("success").is_some_and(truthy) && result.get("stdout").is_some_and(truthy) {
        // Simple vulnerability detection based on common patterns
        let output = result.get("stdout").and_then(Value::as_str).unwrap_or_default().to_lowercase();
        let vuln_indicators = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "VULNERABILITY",
            "EXPLOIT",
            "SQL injection",
            "XSS",
            "CSRF",
        ];
        vuln_count = vuln_indicators.iter().filter(|indicator| output.contains(&indicator.to_lowercase())).count()
            as i64;
    }

    json!({
        "tool": tool_name,
        "parameters": optimized_params,
        "status": if result.get("success").is_some_and(truthy) { "success" } else { "failed" },
        "timestamp": iso_now(),
        "execution_time": result.get("execution_time").cloned().unwrap_or_else(|| json!(0)),
        "stdout": result.get("stdout").cloned().unwrap_or_else(|| json!("")),
        "stderr": result.get("stderr").cloned().unwrap_or_else(|| json!("")),
        "vulnerabilities_found": vuln_count,
        "command": result.get("command").cloned().unwrap_or_else(|| json!("")),
        "success": result.get("success").cloned().unwrap_or_else(|| json!(false)),
    })
}

// Helper functions for intelligent smart scan tool execution
//
// O `try/except Exception as e -> {"success": False, "error": str(e)}` do
// Python só dispara no `' '.join(...)` com item não-str; aqui os parâmetros são
// lidos com `as_str()` (valor de tipo inesperado cai no default do `params.get`).

/// `def execute_nmap_scan(target, params)`
async fn execute_nmap_scan(target: &str, params: &Value) -> Value {
    let scan_type = params.get("scan_type").and_then(Value::as_str).unwrap_or("-sV");
    let ports = params.get("ports").and_then(Value::as_str).unwrap_or("");
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    // Build nmap command
    let mut cmd_parts = vec!["nmap".to_string(), scan_type.to_string()];
    if !ports.is_empty() {
        cmd_parts.extend(["-p".to_string(), ports.to_string()]);
    }
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }
    cmd_parts.push(target.to_string());

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_gobuster_scan(target, params)`
async fn execute_gobuster_scan(target: &str, params: &Value) -> Value {
    let mode = params.get("mode").and_then(Value::as_str).unwrap_or("dir");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec![
        "gobuster".to_string(),
        mode.to_string(),
        "-u".to_string(),
        target.to_string(),
        "-w".to_string(),
        wordlist.to_string(),
    ];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_nuclei_scan(target, params)`
async fn execute_nuclei_scan(target: &str, params: &Value) -> Value {
    let severity = params.get("severity").and_then(Value::as_str).unwrap_or("");
    let tags = params.get("tags").and_then(Value::as_str).unwrap_or("");
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["nuclei".to_string(), "-u".to_string(), target.to_string()];
    if !severity.is_empty() {
        cmd_parts.extend(["-severity".to_string(), severity.to_string()]);
    }
    if !tags.is_empty() {
        cmd_parts.extend(["-tags".to_string(), tags.to_string()]);
    }
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_nikto_scan(target, params)`
async fn execute_nikto_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["nikto".to_string(), "-h".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_sqlmap_scan(target, params)`
async fn execute_sqlmap_scan(target: &str, params: &Value) -> Value {
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("--batch --random-agent");

    let mut cmd_parts = vec!["sqlmap".to_string(), "-u".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_ffuf_scan(target, params)`
async fn execute_ffuf_scan(target: &str, params: &Value) -> Value {
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    // Ensure target has FUZZ placeholder
    let fuzz_target = if target.contains("FUZZ") {
        target.to_string()
    } else {
        format!("{}/FUZZ", target.trim_end_matches('/'))
    };

    let mut cmd_parts = vec![
        "ffuf".to_string(),
        "-u".to_string(),
        fuzz_target,
        "-w".to_string(),
        wordlist.to_string(),
    ];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_feroxbuster_scan(target, params)`
async fn execute_feroxbuster_scan(target: &str, params: &Value) -> Value {
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirb/common.txt");
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec![
        "feroxbuster".to_string(),
        "-u".to_string(),
        target.to_string(),
        "-w".to_string(),
        wordlist.to_string(),
    ];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_katana_scan(target, params)`
async fn execute_katana_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["katana".to_string(), "-u".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_httpx_scan(target, params)`
async fn execute_httpx_scan(target: &str, params: &Value) -> Value {
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("-tech-detect -status-code");

    // Use shell command with pipe for httpx
    let cmd = format!("echo {target} | httpx {additional_args}");

    execute_command(&cmd, true).await
}

/// `def execute_wpscan_scan(target, params)`
async fn execute_wpscan_scan(target: &str, params: &Value) -> Value {
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("--enumerate p,t,u");

    let mut cmd_parts = vec!["wpscan".to_string(), "--url".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_dirsearch_scan(target, params)`
async fn execute_dirsearch_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["dirsearch".to_string(), "-u".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_arjun_scan(target, params)`
async fn execute_arjun_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["arjun".to_string(), "-u".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_paramspider_scan(target, params)`
async fn execute_paramspider_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["paramspider".to_string(), "-d".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_dalfox_scan(target, params)`
async fn execute_dalfox_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["dalfox".to_string(), "url".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_amass_scan(target, params)`
async fn execute_amass_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec![
        "amass".to_string(),
        "enum".to_string(),
        "-d".to_string(),
        target.to_string(),
    ];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `def execute_subfinder_scan(target, params)`
async fn execute_subfinder_scan(target: &str, params: &Value) -> Value {
    let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");

    let mut cmd_parts = vec!["subfinder".to_string(), "-d".to_string(), target.to_string()];
    if !additional_args.is_empty() {
        cmd_parts.extend(additional_args.split_whitespace().map(str::to_string));
    }

    execute_command(&cmd_parts.join(" "), true).await
}

/// `@app.route("/api/intelligence/technology-detection", methods=["POST"])`
pub async fn detect_technologies(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(target_value) = data.get("target") else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Target is required"})));
    };
    let target = match target_as_str(target_value, "💥 Error in technology detection") {
        Ok(target) => target,
        Err(response) => return response,
    };

    info!("🔍 Detecting technologies for {target}");

    // Analyze target
    let profile = decision_engine.analyze_target(target);

    // Get technology-specific recommendations
    let mut tech_recommendations: Map<String, Value> = Map::new();
    for tech in &profile.technologies {
        if *tech == TechnologyStack::WORDPRESS {
            tech_recommendations.insert(
                "WordPress".to_string(),
                json!({
                    "tools": ["wpscan", "nuclei"],
                    "focus_areas": ["plugin vulnerabilities", "theme issues", "user enumeration"],
                    "priority": "high",
                }),
            );
        } else if *tech == TechnologyStack::PHP {
            tech_recommendations.insert(
                "PHP".to_string(),
                json!({
                    "tools": ["nikto", "sqlmap", "ffuf"],
                    "focus_areas": ["code injection", "file inclusion", "SQL injection"],
                    "priority": "high",
                }),
            );
        } else if *tech == TechnologyStack::NODEJS {
            tech_recommendations.insert(
                "Node.js".to_string(),
                json!({
                    "tools": ["nuclei", "ffuf"],
                    "focus_areas": ["prototype pollution", "dependency vulnerabilities"],
                    "priority": "medium",
                }),
            );
        }
    }

    info!("✅ Technology detection completed for {target}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "target": target,
            "detected_technologies": profile.technologies.iter().map(|tech| tech.value()).collect::<Vec<_>>(),
            "cms_type": profile.cms_type,
            "technology_recommendations": Value::Object(tech_recommendations),
            "target_profile": profile.to_dict(),
            "timestamp": iso_now(),
        })),
    )
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/intelligence/analyze-target", post(analyze_target))
        .route("/api/intelligence/select-tools", post(select_optimal_tools))
        .route("/api/intelligence/optimize-parameters", post(optimize_tool_parameters))
        .route("/api/intelligence/create-attack-chain", post(create_attack_chain))
        .route("/api/intelligence/smart-scan", post(intelligent_smart_scan))
        .route("/api/intelligence/technology-detection", post(detect_technologies))
}
