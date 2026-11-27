//! Port 1:1 de `hexstrike_server/routes/api_testing.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  def api_fuzzer
//!    77  def graphql_scanner
//!   184  def jwt_analyzer
//!   302  def api_schema_analyzer
//! ```
//!
//! Rotas (`@app.route`) deste módulo (4):
//!
//! ```text
//!    19  api_fuzzer("/api/tools/api_fuzzer", methods=["POST"])
//!    76  graphql_scanner("/api/tools/graphql_scanner", methods=["POST"])
//!   183  jwt_analyzer("/api/tools/jwt_analyzer", methods=["POST"])
//!   301  api_schema_analyzer("/api/tools/api_schema_analyzer", methods=["POST"])
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

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `base64.b64decode(s)` (validate=False): descarta chars fora do alfabeto e
/// exige grupo de 4 (mensagens de erro 1:1 do `binascii`).
fn b64decode(input: &str) -> Result<Vec<u8>, String> {
    // Os '=' são contados só no fim; o resto do padding é ignorado, como o
    // `a2b_base64` não-estrito.
    let symbols: Vec<u8> = input
        .bytes()
        .filter(|b| B64_ALPHABET.contains(b))
        .collect();
    let trailing_pad = input.chars().rev().take_while(|c| *c == '=').count();

    let leftover = symbols.len() % 4;
    if leftover == 1 {
        return Err(format!(
            "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4",
            symbols.len()
        ));
    }
    if leftover != 0 && trailing_pad != 4 - leftover {
        return Err("Incorrect padding".to_string());
    }

    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for chunk in symbols.chunks(4) {
        let mut buf = 0u32;
        for (i, sym) in chunk.iter().enumerate() {
            let val = B64_ALPHABET
                .iter()
                .position(|c| c == sym)
                .unwrap_or(0) as u32;
            buf |= val << (18 - 6 * i);
        }
        // 4 símbolos -> 3 bytes; 3 -> 2; 2 -> 1.
        for i in 0..chunk.len().saturating_sub(1) {
            out.push((buf >> (16 - 8 * i)) as u8);
        }
    }

    Ok(out)
}

/// `base64.b64encode(data).decode().rstrip('=')`
fn b64encode_no_pad(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buf = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            buf |= (*byte as u32) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            let idx = (buf >> (18 - 6 * i)) & 0x3f;
            out.push(B64_ALPHABET[idx as usize] as char);
        }
    }
    out
}

/// `@app.route("/api/tools/api_fuzzer", methods=["POST"])` — `def api_fuzzer()`.
pub async fn api_fuzzer(Json(params): Json<Value>) -> ApiResult {
    let base_url = params
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or("");
    let endpoints: Vec<Value> = params
        .get("endpoints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let methods: Vec<Value> = params
        .get("methods")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            ["GET", "POST", "PUT", "DELETE"]
                .iter()
                .map(|m| json!(m))
                .collect()
        });
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/api/api-endpoints.txt");

    if base_url.is_empty() {
        warn!("🌐 API Fuzzer called without base_url parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Base URL parameter is required"})),
        ));
    }

    // Create comprehensive API fuzzing command
    if !endpoints.is_empty() {
        // Test specific endpoints
        let mut results: Vec<Value> = Vec::new();
        for endpoint in &endpoints {
            for method in &methods {
                let endpoint_str = match endpoint.as_str() {
                    Some(s) => s.to_string(),
                    None => endpoint.to_string(),
                };
                let method_str = match method.as_str() {
                    Some(s) => s.to_string(),
                    None => method.to_string(),
                };
                let test_url = format!(
                    "{}/{}",
                    base_url.trim_end_matches('/'),
                    endpoint_str.trim_start_matches('/')
                );
                let command = format!(
                    "curl -s -X {method_str} -w '%{{http_code}}|%{{size_download}}' '{test_url}'"
                );
                let result = execute_command(&command, false).await;
                results.push(json!({
                    "endpoint": endpoint,
                    "method": method,
                    "result": result,
                }));
            }
        }

        info!(
            "🔍 API endpoint testing completed for {} endpoints",
            endpoints.len()
        );
        Ok(Json(json!({
            "success": true,
            "fuzzing_type": "endpoint_testing",
            "results": results,
        })))
    } else {
        // Discover endpoints using wordlist
        let command = format!(
            "ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,201,202,204,301,302,307,401,403,405 -t 50"
        );

        info!("🔍 Starting API endpoint discovery: {base_url}");
        let result = execute_command(&command, true).await;
        info!("📊 API endpoint discovery completed");

        Ok(Json(json!({
            "success": true,
            "fuzzing_type": "endpoint_discovery",
            "result": result,
        })))
    }
}

/// `@app.route("/api/tools/graphql_scanner", methods=["POST"])` —
/// `def graphql_scanner()`.
pub async fn graphql_scanner(Json(params): Json<Value>) -> ApiResult {
    let endpoint = params
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or("");
    let introspection = params
        .get("introspection")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let query_depth = params
        .get("query_depth")
        .and_then(Value::as_i64)
        .unwrap_or(10);
    // `test_mutations` só é lido no Python; nenhum teste o usa.
    let _mutations = params
        .get("test_mutations")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if endpoint.is_empty() {
        warn!("🌐 GraphQL Scanner called without endpoint parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "GraphQL endpoint parameter is required"})),
        ));
    }

    info!("🔍 Starting GraphQL security scan: {endpoint}");

    let mut tests_performed: Vec<Value> = Vec::new();
    let mut vulnerabilities: Vec<Value> = Vec::new();
    let mut recommendations: Vec<Value> = Vec::new();

    // Test 1: Introspection query
    if introspection {
        let introspection_query = "\n            {\n                __schema {\n                    types {\n                        name\n                        fields {\n                            name\n                            type {\n                                name\n                            }\n                        }\n                    }\n                }\n            }\n            ";

        let clean_query = introspection_query
            .replace('\n', " ")
            .replace("  ", " ")
            .trim()
            .to_string();
        let command = format!(
            "curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
        );
        let result = execute_command(&command, false).await;

        tests_performed.push(json!("introspection_query"));

        if result
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("data")
        {
            vulnerabilities.push(json!({
                "type": "introspection_enabled",
                "severity": "MEDIUM",
                "description": "GraphQL introspection is enabled",
            }));
        }
    }

    // Test 2: Query depth analysis
    let depth = query_depth.max(0) as usize;
    let deep_query = format!("{}{}{}", "{ ".repeat(depth), "field", " }".repeat(depth));
    let command = format!(
        "curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{deep_query}\"}}' {endpoint}"
    );
    let depth_result = execute_command(&command, false).await;

    tests_performed.push(json!("query_depth_analysis"));

    if !depth_result
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase()
        .contains("error")
    {
        vulnerabilities.push(json!({
            "type": "no_query_depth_limit",
            "severity": "HIGH",
            "description": format!("No query depth limiting detected (tested depth: {query_depth})"),
        }));
    }

    // Test 3: Batch query testing
    let batch_query = format!(
        "[{}]",
        ["{\"query\":\"{field}\"}"; 10].join(",")
    );
    let command = format!(
        "curl -s -X POST -H 'Content-Type: application/json' -d '{batch_query}' {endpoint}"
    );
    let batch_result = execute_command(&command, false).await;

    tests_performed.push(json!("batch_query_testing"));

    if batch_result
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or("")
        .contains("data")
        && batch_result
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        vulnerabilities.push(json!({
            "type": "batch_queries_allowed",
            "severity": "MEDIUM",
            "description": "Batch queries are allowed without rate limiting",
        }));
    }

    // Generate recommendations
    if !vulnerabilities.is_empty() {
        recommendations = [
            "Disable introspection in production",
            "Implement query depth limiting",
            "Add rate limiting for batch queries",
            "Implement query complexity analysis",
            "Add authentication for sensitive operations",
        ]
        .iter()
        .map(|r| json!(r))
        .collect();
    }

    info!(
        "📊 GraphQL scan completed | Vulnerabilities found: {}",
        vulnerabilities.len()
    );

    Ok(Json(json!({
        "success": true,
        "graphql_scan_results": {
            "endpoint": endpoint,
            "tests_performed": tests_performed,
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations,
        },
    })))
}

/// `@app.route("/api/tools/jwt_analyzer", methods=["POST"])` — `def jwt_analyzer()`.
pub async fn jwt_analyzer(Json(params): Json<Value>) -> ApiResult {
    let jwt_token = params
        .get("jwt_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    let target_url = params
        .get("target_url")
        .and_then(Value::as_str)
        .unwrap_or("");

    if jwt_token.is_empty() {
        warn!("🔐 JWT Analyzer called without jwt_token parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "JWT token parameter is required"})),
        ));
    }

    info!("🔍 Starting JWT security analysis");

    // `token`: primeiros 50 chars + "..." quando maior.
    let token_repr = if jwt_token.chars().count() > 50 {
        format!("{}...", jwt_token.chars().take(50).collect::<String>())
    } else {
        jwt_token.to_string()
    };

    let mut vulnerabilities: Vec<Value> = Vec::new();
    let mut attack_vectors: Vec<Value> = Vec::new();
    let mut token_info = json!({});

    // Decode JWT header and payload (basic analysis)
    let parts: Vec<&str> = jwt_token.split('.').collect();
    if parts.len() >= 2 {
        // Add padding if needed — o `4 - len % 4` do Python dá 4 quando já é
        // múltiplo de 4 (bug preservado 1:1).
        let header_b64 = format!(
            "{}{}",
            parts[0],
            "=".repeat(4 - parts[0].chars().count() % 4)
        );
        let payload_b64 = format!(
            "{}{}",
            parts[1],
            "=".repeat(4 - parts[1].chars().count() % 4)
        );

        match decode_jwt_part(&header_b64).and_then(|h| {
            decode_jwt_part(&payload_b64).map(|p| (h, p))
        }) {
            Ok((header, payload)) => {
                let algorithm = header.get("alg").cloned().unwrap_or(json!("unknown"));
                token_info = json!({
                    "header": header,
                    "payload": payload,
                    "algorithm": algorithm,
                });

                // Check for vulnerabilities
                let algorithm_lower = header
                    .get("alg")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();

                if algorithm_lower == "none" {
                    vulnerabilities.push(json!({
                        "type": "none_algorithm",
                        "severity": "CRITICAL",
                        "description": "JWT uses 'none' algorithm - no signature verification",
                    }));
                }

                if matches!(algorithm_lower.as_str(), "hs256" | "hs384" | "hs512") {
                    attack_vectors.push(json!("hmac_key_confusion"));
                    vulnerabilities.push(json!({
                        "type": "hmac_algorithm",
                        "severity": "MEDIUM",
                        "description": "HMAC algorithm detected - vulnerable to key confusion attacks",
                    }));
                }

                // Check token expiration
                let has_exp = payload.get("exp").map(|v| !json_falsy(v)).unwrap_or(false);
                if !has_exp {
                    vulnerabilities.push(json!({
                        "type": "no_expiration",
                        "severity": "HIGH",
                        "description": "JWT token has no expiration time",
                    }));
                }
            }
            Err(decode_error) => {
                vulnerabilities.push(json!({
                    "type": "malformed_token",
                    "severity": "HIGH",
                    "description": format!("Token decoding failed: {decode_error}"),
                }));
            }
        }
    }

    // Test token manipulation if target URL provided
    if !target_url.is_empty() {
        let none_token_parts: Vec<&str> = jwt_token.split('.').collect();
        if none_token_parts.len() >= 2 {
            let none_header = b64encode_no_pad(br#"{"alg":"none","typ":"JWT"}"#);
            let none_token = format!("{}.{}.", none_header, none_token_parts[1]);

            let command = format!("curl -s -H 'Authorization: Bearer {none_token}' '{target_url}'");
            let none_result = execute_command(&command, false).await;

            let stdout = none_result
                .get("stdout")
                .and_then(Value::as_str)
                .unwrap_or("");
            if stdout.contains("200") || stdout.to_lowercase().contains("success") {
                vulnerabilities.push(json!({
                    "type": "none_algorithm_accepted",
                    "severity": "CRITICAL",
                    "description": "Server accepts tokens with 'none' algorithm",
                }));
            }
        }
    }

    info!(
        "📊 JWT analysis completed | Vulnerabilities found: {}",
        vulnerabilities.len()
    );

    Ok(Json(json!({
        "success": true,
        "jwt_analysis_results": {
            "token": token_repr,
            "vulnerabilities": vulnerabilities,
            "token_info": token_info,
            "attack_vectors": attack_vectors,
        },
    })))
}

/// `json.loads(base64.b64decode(part))` do bloco de decode do JWT.
fn decode_jwt_part(part_b64: &str) -> Result<Value, String> {
    let raw = b64decode(part_b64)?;
    let text = String::from_utf8(raw).map_err(|e| {
        // Python: UnicodeDecodeError do `json.loads(bytes)`.
        format!("'utf-8' codec can't decode bytes: {e}")
    })?;
    serde_json::from_str(&text).map_err(|e| {
        // Python: JSONDecodeError (`Expecting value: line 1 column 1 (char 0)`).
        e.to_string()
    })
}

/// Truthiness do Python para os valores que o JSON representa.
fn json_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// `@app.route("/api/tools/api_schema_analyzer", methods=["POST"])` —
/// `def api_schema_analyzer()`.
pub async fn api_schema_analyzer(Json(params): Json<Value>) -> ApiResult {
    let schema_url = params
        .get("schema_url")
        .and_then(Value::as_str)
        .unwrap_or("");
    let schema_type = params
        .get("schema_type")
        .and_then(Value::as_str)
        .unwrap_or("openapi");

    if schema_url.is_empty() {
        warn!("📋 API Schema Analyzer called without schema_url parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Schema URL parameter is required"})),
        ));
    }

    info!("🔍 Starting API schema analysis: {schema_url}");

    // Fetch schema
    let command = format!("curl -s '{schema_url}'");
    let result = execute_command(&command, true).await;

    if !result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Failed to fetch API schema"})),
        ));
    }

    let schema_content = result.get("stdout").and_then(Value::as_str).unwrap_or("");

    let mut endpoints_found: Vec<Value> = Vec::new();
    let mut security_issues: Vec<Value> = Vec::new();
    let mut recommendations: Vec<Value> = Vec::new();

    // Parse schema based on type
    match serde_json::from_str::<Value>(schema_content) {
        Ok(schema_data) => {
            if matches!(schema_type.to_lowercase().as_str(), "openapi" | "swagger") {
                // OpenAPI/Swagger analysis — `paths.items()` do Python preserva
                // a ordem do documento; aqui o Map do serde_json é um BTreeMap
                // (ordem alfabética). Divergência conhecida do port.
                let paths = schema_data
                    .get("paths")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();

                for (path, methods) in &paths {
                    for (method, details) in methods.as_object().into_iter().flatten() {
                        if !details.is_object() {
                            continue;
                        }
                        let parameters = details
                            .get("parameters")
                            .cloned()
                            .unwrap_or_else(|| json!([]));
                        let security = details
                            .get("security")
                            .cloned()
                            .unwrap_or_else(|| json!([]));
                        let endpoint_info = json!({
                            "path": path,
                            "method": method.to_uppercase(),
                            "summary": details.get("summary").cloned().unwrap_or(json!("")),
                            "parameters": parameters,
                            "security": security,
                        });

                        // Check for security issues
                        if json_falsy(&security) {
                            security_issues.push(json!({
                                "endpoint": format!("{} {path}", method.to_uppercase()),
                                "issue": "no_authentication",
                                "severity": "MEDIUM",
                                "description": "Endpoint has no authentication requirements",
                            }));
                        }

                        // Check for sensitive data in parameters
                        for param in parameters.as_array().into_iter().flatten() {
                            let param_name = param
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_lowercase();
                            if ["password", "token", "key", "secret"]
                                .iter()
                                .any(|s| param_name.contains(s))
                            {
                                security_issues.push(json!({
                                    "endpoint": format!("{} {path}", method.to_uppercase()),
                                    "issue": "sensitive_parameter",
                                    "severity": "HIGH",
                                    "description": format!("Sensitive parameter detected: {param_name}"),
                                }));
                            }
                        }

                        endpoints_found.push(endpoint_info);
                    }
                }
            }

            // Generate recommendations
            if !security_issues.is_empty() {
                recommendations = [
                    "Implement authentication for all endpoints",
                    "Use HTTPS for all API communications",
                    "Validate and sanitize all input parameters",
                    "Implement rate limiting",
                    "Add proper error handling",
                    "Use secure headers (CORS, CSP, etc.)",
                ]
                .iter()
                .map(|r| json!(r))
                .collect();
            }
        }
        Err(_) => {
            // except json.JSONDecodeError
            security_issues.push(json!({
                "endpoint": "schema",
                "issue": "invalid_json",
                "severity": "HIGH",
                "description": "Schema is not valid JSON",
            }));
        }
    }

    info!(
        "📊 Schema analysis completed | Issues found: {}",
        security_issues.len()
    );

    Ok(Json(json!({
        "success": true,
        "schema_analysis_results": {
            "schema_url": schema_url,
            "schema_type": schema_type,
            "endpoints_found": endpoints_found,
            "security_issues": security_issues,
            "recommendations": recommendations,
        },
    })))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/api_fuzzer", post(api_fuzzer))
        .route("/api/tools/graphql_scanner", post(graphql_scanner))
        .route("/api/tools/jwt_analyzer", post(jwt_analyzer))
        .route("/api/tools/api_schema_analyzer", post(api_schema_analyzer))
}

