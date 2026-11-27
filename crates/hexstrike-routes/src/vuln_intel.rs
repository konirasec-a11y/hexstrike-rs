//! Port 1:1 de `hexstrike_server/routes/vuln_intel.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W3.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  def cve_monitor                      -> porta (POST /api/vuln-intel/cve-monitor)
//!    74  def exploit_generate                 -> PENDENTE: precisa de `exploit_generator`
//!                                                (AIExploitGenerator, exploit_gen.py)
//!   147  def discover_attack_chains           -> PENDENTE: precisa de `vulnerability_correlator`
//!                                                (VulnerabilityCorrelator, exploit_gen.py)
//!   224  def threat_intelligence_feeds         -> porta (POST /api/vuln-intel/threat-feeds)
//!   359  def zero_day_research                 -> porta (POST /api/vuln-intel/zero-day-research)
//!   498  def advanced_payload_generation       -> PENDENTE: precisa de `ai_payload_generator`
//!                                                (AIPayloadGenerator, routes/payloads.py)
//! ```
//!
//! Rotas (`@app.route`) deste módulo (6) — só as 3 primeiras estão registradas:
//!
//! ```text
//!    19  cve_monitor("/api/vuln-intel/cve-monitor", methods=["POST"])
//!    73  exploit_generate("/api/vuln-intel/exploit-generate", methods=["POST"])
//!   146  discover_attack_chains("/api/vuln-intel/attack-chains", methods=["POST"])
//!   223  threat_intelligence_feeds("/api/vuln-intel/threat-feeds", methods=["POST"])
//!   358  zero_day_research("/api/vuln-intel/zero-day-research", methods=["POST"])
//!   497  advanced_payload_generation("/api/ai/advanced-payload-generation", methods=["POST"])
//! ```

use axum::routing::post;
use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use hexstrike_intelligence::vuln_intel::{cve_intelligence, iso_now};

/// `params = request.json` — o corpo que o harness manda é `{}`.
/// (O Python estoura 500 se o corpo não for um dict; aqui um corpo não-objeto
/// equivale a `{}`.)
fn params_of(body: Value) -> Map<String, Value> {
    body.as_object().cloned().unwrap_or_default()
}

/// `if valor:` do Python.
fn py_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// `params.get(key, default)` para strings.
fn pget_str(params: &Map<String, Value>, key: &str, default: &str) -> String {
    params.get(key).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| default.to_string())
}

/// `@app.route("/api/vuln-intel/cve-monitor", methods=["POST"])`
async fn cve_monitor(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let hours = params.get("hours").and_then(Value::as_i64).unwrap_or(24);
    let severity_filter = pget_str(&params, "severity_filter", "HIGH,CRITICAL");
    let keywords = pget_str(&params, "keywords", "");

    info!("🔍 Monitoring CVE feeds for last {hours} hours with severity filter: {severity_filter}");

    // Fetch latest CVEs
    let mut cve_results = cve_intelligence.fetch_latest_cves(hours, &severity_filter).await;

    // Filter by keywords if provided
    if !keywords.is_empty()
        && cve_results.get("success").and_then(Value::as_bool).unwrap_or(false)
    {
        let keyword_list: Vec<String> =
            keywords.split(',').map(|k| k.trim().to_lowercase()).collect();

        let filtered_cves: Vec<Value> = cve_results
            .get("cves")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|cve| {
                let description =
                    cve.get("description").and_then(Value::as_str).unwrap_or("").to_lowercase();
                keyword_list.iter().any(|keyword| description.contains(keyword))
            })
            .collect();

        if let Some(result) = cve_results.as_object_mut() {
            result.insert("cves".to_string(), Value::Array(filtered_cves.clone()));
            result.insert("filtered_by_keywords".to_string(), json!(keywords));
            result.insert("total_after_filter".to_string(), json!(filtered_cves.len()));
        }
    }

    // Analyze exploitability for top CVEs
    let mut exploitability_analysis: Vec<Value> = Vec::new();
    let top_cves: Vec<Value> = cve_results
        .get("cves")
        .and_then(Value::as_array)
        .map(|cves| cves.iter().take(5).cloned().collect())
        .unwrap_or_default();

    for cve in top_cves {
        let cve_id = cve.get("cve_id").and_then(Value::as_str).unwrap_or("").to_string();
        if !cve_id.is_empty() {
            let analysis = cve_intelligence.analyze_cve_exploitability(&cve_id).await;
            if analysis.get("success").and_then(Value::as_bool).unwrap_or(false) {
                exploitability_analysis.push(analysis);
            }
        }
    }

    let found = cve_results.get("cves").and_then(Value::as_array).map(|cves| cves.len()).unwrap_or(0);
    let result = json!({
        "success": true,
        "cve_monitoring": cve_results,
        "exploitability_analysis": exploitability_analysis,
        "timestamp": iso_now(),
    });

    info!("📊 CVE monitoring completed | Found: {found} CVEs");
    (StatusCode::OK, Json(result))
}

/// `@app.route("/api/vuln-intel/threat-feeds", methods=["POST"])`
async fn threat_intelligence_feeds(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let indicators: Vec<String> = match params.get("indicators") {
        Some(Value::String(text)) => text.split(',').map(|i| i.trim().to_string()).collect(),
        Some(Value::Array(items)) => {
            items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    };
    let timeframe = pget_str(&params, "timeframe", "30d");
    let sources = pget_str(&params, "sources", "all");

    if indicators.is_empty() {
        warn!("🧠 Threat intelligence called without indicators");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "Indicators parameter is required"})),
        );
    }

    info!("🧠 Correlating threat intelligence for {} indicators", indicators.len());

    let mut correlations: Vec<Value> = Vec::new();
    let mut threat_score = 0.0f64;

    // Analyze each indicator
    let cve_indicators: Vec<String> =
        indicators.iter().filter(|i| i.starts_with("CVE-")).cloned().collect();
    let ip_indicators: Vec<String> = indicators
        .iter()
        .filter(|i| {
            let digits = i.replace('.', "");
            !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
        })
        .cloned()
        .collect();
    let hash_indicators: Vec<String> = indicators
        .iter()
        .filter(|i| {
            matches!(i.chars().count(), 32 | 40 | 64) && i
                .to_lowercase()
                .chars()
                .all(|c| "0123456789abcdef".contains(c))
        })
        .cloned()
        .collect();

    // Process CVE indicators
    for cve_id in &cve_indicators {
        let cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id).await;
        if cve_analysis.get("success").and_then(Value::as_bool).unwrap_or(false) {
            let threat_level = cve_analysis
                .get("exploitability_level")
                .cloned()
                .unwrap_or_else(|| json!("UNKNOWN"));
            let exploit_score =
                cve_analysis.get("exploitability_score").and_then(Value::as_f64).unwrap_or(0.0);
            // Add to threat score
            threat_score += exploit_score.min(100.0);

            correlations.push(json!({
                "indicator": cve_id,
                "type": "cve",
                "analysis": cve_analysis,
                "threat_level": threat_level,
            }));
        }

        // Search for existing exploits. O Python lê `total_exploits`, chave que
        // `search_existing_exploits` NÃO devolve (ele devolve `exploits_found`),
        // então este bloco nunca entra — reproduzido de propósito.
        let exploits = cve_intelligence.search_existing_exploits(cve_id).await;
        if exploits.get("success").and_then(Value::as_bool).unwrap_or(false)
            && exploits.get("total_exploits").and_then(Value::as_i64).unwrap_or(0) > 0
        {
            correlations.push(json!({
                "indicator": cve_id,
                "type": "exploit_availability",
                "exploits_found": exploits.get("total_exploits").cloned().unwrap_or_else(|| json!(0)),
                "threat_level": "HIGH",
            }));
            threat_score += 25.0;
        }
    }

    // Process IP indicators (basic reputation check simulation)
    for ip in &ip_indicators {
        // Simulate threat intelligence lookup
        correlations.push(json!({
            "indicator": ip,
            "type": "ip_reputation",
            "analysis": {
                "reputation": "unknown",
                "geolocation": "unknown",
                "associated_threats": [],
            },
            // Default for unknown IPs
            "threat_level": "MEDIUM",
        }));
    }

    // Process hash indicators
    for hash_val in &hash_indicators {
        correlations.push(json!({
            "indicator": hash_val,
            "type": "file_hash",
            "analysis": {
                "hash_type": format!("hash{}", hash_val.chars().count()),
                "malware_family": "unknown",
                "detection_rate": "unknown",
            },
            "threat_level": "MEDIUM",
        }));
    }

    // Calculate overall threat score and generate recommendations
    let total_indicators = indicators.len();
    let mut score = 0.0f64;
    let mut recommendations: Vec<&str> = Vec::new();

    if total_indicators > 0 {
        score = (threat_score / total_indicators as f64).min(100.0);

        recommendations = if score >= 75.0 {
            vec![
                "Immediate threat response required",
                "Block identified indicators",
                "Enhance monitoring for related IOCs",
                "Implement emergency patches for identified CVEs",
            ]
        } else if score >= 50.0 {
            vec![
                "Elevated threat level detected",
                "Increase monitoring for identified indicators",
                "Plan patching for identified vulnerabilities",
                "Review security controls",
            ]
        } else {
            vec![
                "Low to medium threat level",
                "Continue standard monitoring",
                "Plan routine patching",
                "Consider additional threat intelligence sources",
            ]
        };
    }

    let result = json!({
        "success": true,
        "threat_intelligence": {
            "indicators_analyzed": indicators,
            "timeframe": timeframe,
            "sources": sources,
            "correlations": correlations,
            "threat_score": score,
            "recommendations": recommendations,
        },
        "timestamp": iso_now(),
    });

    info!("🎯 Threat intelligence correlation completed | Threat Score: {score:.1}");
    (StatusCode::OK, Json(result))
}

/// `@app.route("/api/vuln-intel/zero-day-research", methods=["POST"])`
async fn zero_day_research(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let target_software = pget_str(&params, "target_software", "");
    let analysis_depth = pget_str(&params, "analysis_depth", "standard");
    let source_code_url = pget_str(&params, "source_code_url", "");

    if target_software.is_empty() {
        warn!("🔬 Zero-day research called without target software");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "Target software parameter is required"})),
        );
    }

    info!("🔬 Starting zero-day research for {target_software} | Depth: {analysis_depth}");

    // Define research areas based on software type
    let common_research_areas = [
        "Input validation vulnerabilities",
        "Memory corruption issues",
        "Authentication bypasses",
        "Authorization flaws",
        "Cryptographic weaknesses",
        "Race conditions",
        "Logic flaws",
    ];

    // Software-specific research areas
    let web_research_areas = [
        "Cross-site scripting (XSS)",
        "SQL injection",
        "Server-side request forgery (SSRF)",
        "Insecure deserialization",
        "Template injection",
    ];

    let system_research_areas = [
        "Buffer overflows",
        "Privilege escalation",
        "Kernel vulnerabilities",
        "Service exploitation",
        "Configuration weaknesses",
    ];

    // Determine research areas based on target
    let target_lower = target_software.to_lowercase();
    let research_areas: Vec<&str> =
        if ["apache", "nginx", "tomcat", "php", "node", "django"]
            .iter()
            .any(|web_tech| target_lower.contains(web_tech))
        {
            common_research_areas.iter().chain(web_research_areas.iter()).copied().collect()
        } else if ["windows", "linux", "kernel", "driver"]
            .iter()
            .any(|sys_tech| target_lower.contains(sys_tech))
        {
            common_research_areas.iter().chain(system_research_areas.iter()).copied().collect()
        } else {
            common_research_areas.to_vec()
        };

    // Simulate vulnerability discovery based on analysis depth
    let vuln_count = match analysis_depth.as_str() {
        "quick" => 2,
        "standard" => 4,
        "comprehensive" => 6,
        _ => 4,
    };

    let mut potential_vulnerabilities: Vec<Value> = Vec::new();
    // `["LOW", "MEDIUM", "HIGH", "CRITICAL"]` e `["LOW", "MEDIUM", "HIGH"]`
    // ciclados por `i` no Python.
    const SEVERITIES: [&str; 4] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const CONFIDENCES: [&str; 3] = ["LOW", "MEDIUM", "HIGH"];
    for i in 0..vuln_count {
        let category = research_areas[i % research_areas.len()];
        potential_vulnerabilities.push(json!({
            "id": format!("RESEARCH-{}-{:03}", target_software.to_uppercase(), i + 1),
            "category": category,
            "severity": SEVERITIES[i % 4],
            "confidence": CONFIDENCES[i % 3],
            "description": format!("Potential {} in {target_software}", category.to_lowercase()),
            "attack_vector": "To be determined through further analysis",
            "impact": "To be assessed",
            "proof_of_concept": "Research phase - PoC development needed",
        }));
    }

    // Risk assessment
    let high_risk_count = potential_vulnerabilities
        .iter()
        .filter(|v| {
            matches!(v.get("severity").and_then(Value::as_str), Some("HIGH" | "CRITICAL"))
        })
        .count();
    let total_vulns = potential_vulnerabilities.len();
    let risk_score = (high_risk_count as i64 * 25 + (total_vulns - high_risk_count) as i64 * 10).min(100);

    // Generate recommendations
    let recommendations: Vec<&str> = if high_risk_count > 0 {
        vec![
            "Prioritize security testing in identified high-risk areas",
            "Conduct focused penetration testing",
            "Implement additional security controls",
            "Consider bug bounty program for target software",
            "Perform code review in identified areas",
        ]
    } else {
        vec![
            "Continue standard security testing",
            "Monitor for new vulnerability research",
            "Implement defense-in-depth strategies",
            "Regular security assessments recommended",
        ]
    };

    let mut research_results = json!({
        "target_software": target_software,
        "analysis_depth": analysis_depth,
        "research_areas": research_areas,
        "potential_vulnerabilities": potential_vulnerabilities,
        "risk_assessment": {
            "total_areas_analyzed": research_areas.len(),
            "potential_vulnerabilities_found": total_vulns,
            "high_risk_findings": high_risk_count,
            "risk_score": risk_score,
            "research_confidence": analysis_depth,
        },
        "recommendations": recommendations,
    });

    // Source code analysis simulation
    if !source_code_url.is_empty() {
        research_results["source_code_analysis"] = json!({
            "repository_url": source_code_url,
            "analysis_status": "simulated",
            "findings": [
                "Static analysis patterns identified",
                "Potential code quality issues detected",
                "Security-relevant functions located",
            ],
            "recommendation": "Manual code review recommended for identified areas",
        });
    }

    let result = json!({
        "success": true,
        "zero_day_research": research_results,
        "disclaimer": "This is simulated research for demonstration. Real zero-day research requires extensive manual analysis.",
        "timestamp": iso_now(),
    });

    info!("🎯 Zero-day research completed | Risk Score: {risk_score}");
    (StatusCode::OK, Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
///
/// Pendentes (não registradas — `MISSING` no harness até os módulos
/// dependentes serem portados, o que é honesto: o handler sem a dependência
/// responderia diferente do Python):
/// - `/api/vuln-intel/exploit-generate`   -> `exploit_generator.generate_exploit_from_cve`
/// - `/api/vuln-intel/attack-chains`      -> `vulnerability_correlator.find_attack_chains`
/// - `/api/ai/advanced-payload-generation` -> `ai_payload_generator.generate_contextual_payload`
/// `@app.route("/api/vuln-intel/exploit-generate", methods=["POST"])`
async fn exploit_generate(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let cve_id = pget_str(&params, "cve_id", "");
    let target_os = pget_str(&params, "target_os", "");
    let target_arch = pget_str(&params, "target_arch", "x64");
    let exploit_type = pget_str(&params, "exploit_type", "poc");
    let evasion_level = pget_str(&params, "evasion_level", "none");

    // Additional target context
    let target_info = json!({
        "target_os": target_os,
        "target_arch": target_arch,
        "exploit_type": exploit_type,
        "evasion_level": evasion_level,
        "target_ip": pget_str(&params, "target_ip", "192.168.1.100"),
        "target_port": params.get("target_port").cloned().unwrap_or_else(|| json!(80)),
        "description": pget_str(&params, "target_description", &format!("Target for {cve_id}")),
    });

    if cve_id.is_empty() {
        warn!("🤖 Exploit generation called without CVE ID");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "CVE ID parameter is required"})),
        );
    }

    info!("🤖 Generating exploit for {cve_id} | Target: {target_os} {target_arch}");

    // First analyze the CVE for context
    let cve_analysis = cve_intelligence.analyze_cve_exploitability(&cve_id).await;

    if !py_truthy(cve_analysis.get("success")) {
        let err = cve_analysis
            .get("error")
            .map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
            .unwrap_or_else(|| "Unknown error".to_string());
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": format!("Failed to analyze CVE {cve_id}: {err}")})),
        );
    }

    // Prepare CVE data for exploit generation
    let cve_data = json!({
        "cve_id": cve_id,
        "description": format!("Vulnerability analysis for {cve_id}"),
        "exploitability_level": cve_analysis.get("exploitability_level").cloned()
            .unwrap_or_else(|| json!("UNKNOWN")),
        "exploitability_score": cve_analysis.get("exploitability_score").cloned()
            .unwrap_or_else(|| json!(0)),
    });

    // Generate exploit
    let exploit_result =
        hexstrike_intelligence::exploit_gen::exploit_generator.generate_exploit_from_cve(&cve_data, &target_info);

    // Search for existing exploits for reference
    let existing_exploits = cve_intelligence.search_existing_exploits(&cve_id).await;

    info!("🎯 Exploit generation completed for {cve_id}");
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "cve_analysis": cve_analysis,
            "exploit_generation": exploit_result,
            "existing_exploits": existing_exploits,
            "target_info": target_info,
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/vuln-intel/attack-chains", methods=["POST"])`
async fn discover_attack_chains(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let target_software = pget_str(&params, "target_software", "");
    let attack_depth = params.get("attack_depth").and_then(Value::as_i64).unwrap_or(3);
    let include_zero_days = py_truthy(params.get("include_zero_days"));

    if target_software.is_empty() {
        warn!("🔗 Attack chain discovery called without target software");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "Target software parameter is required"})),
        );
    }

    info!("🔗 Discovering attack chains for {target_software} | Depth: {attack_depth}");

    // Discover attack chains
    let mut chain_results = hexstrike_intelligence::exploit_gen::vulnerability_correlator
        .find_attack_chains(&target_software, attack_depth as u32);

    // Enhance with exploit generation for viable chains
    if py_truthy(chain_results.get("success")) {
        if let Some(chains) = chain_results.get("attack_chains").and_then(Value::as_array).cloned() {
            let mut enhanced_chains: Vec<Value> = Vec::new();
            for chain in chains.iter().take(2) {
                // Enhance top 2 chains
                let mut enhanced_chain = chain.clone();
                let mut enhanced_stages: Vec<Value> = Vec::new();
                for stage in chain.get("stages").and_then(Value::as_array).cloned().unwrap_or_default() {
                    let mut enhanced_stage = stage.clone();
                    let vuln = stage.get("vulnerability").cloned().unwrap_or_else(|| json!({}));
                    let cve_id = pget_str(
                        &vuln.as_object().cloned().unwrap_or_default(),
                        "cve_id",
                        "",
                    );
                    if !cve_id.is_empty() {
                        // `try/except: exploit_available = False`
                        let cve_data = json!({
                            "cve_id": cve_id,
                            "description": vuln.get("description").cloned().unwrap_or_else(|| json!("")),
                        });
                        let target_info =
                            json!({"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"});
                        let exploit_result = hexstrike_intelligence::exploit_gen::exploit_generator
                            .generate_exploit_from_cve(&cve_data, &target_info);
                        enhanced_stage["exploit_available"] = json!(py_truthy(exploit_result.get("success")));
                        if py_truthy(exploit_result.get("success")) {
                            let code = exploit_result
                                .get("exploit_code")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let truncated: String = code.chars().take(500).collect();
                            enhanced_stage["exploit_code"] = json!(format!("{truncated}..."));
                        }
                    }
                    enhanced_stages.push(enhanced_stage);
                }
                enhanced_chain["stages"] = Value::Array(enhanced_stages);
                enhanced_chains.push(enhanced_chain);
            }
            chain_results["enhanced_chains"] = Value::Array(enhanced_chains);
        }
    }

    let found = chain_results
        .get("attack_chains")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    info!("🎯 Attack chain discovery completed | Found: {found} chains");
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "attack_chain_discovery": chain_results,
            "parameters": {
                "target_software": target_software,
                "attack_depth": attack_depth,
                "include_zero_days": include_zero_days,
            },
            "timestamp": iso_now(),
        })),
    )
}

/// `@app.route("/api/ai/advanced-payload-generation", methods=["POST"])`
async fn advanced_payload_generation(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = params_of(body);
    let attack_type = pget_str(&params, "attack_type", "rce");
    let target_context = pget_str(&params, "target_context", "");
    let evasion_level = pget_str(&params, "evasion_level", "standard");
    let custom_constraints = pget_str(&params, "custom_constraints", "");

    if attack_type.is_empty() {
        warn!("🎯 Advanced payload generation called without attack type");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "Attack type parameter is required"})),
        );
    }

    info!("🎯 Generating advanced {attack_type} payload with {evasion_level} evasion");

    // `ai_payload_generator.generate_contextual_payload(target_info)` — o
    // `complexity` do target_info é "advanced" e `technology` é o target_context.
    let base_result = crate::payloads::AIPayloadGenerator::generate_contextual_payload(
        &attack_type,
        "advanced",
        &target_context,
    );

    let mut advanced_payloads: Vec<Value> = Vec::new();
    let base_payloads = base_result
        .get("payloads")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for payload_info in base_payloads.iter().take(10) {
        // Limit to 10 advanced payloads
        let payload_str = payload_info
            .get("payload")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut evasion_techniques: Vec<Value> = Vec::new();

        // Apply evasion techniques based on level
        if evasion_level == "advanced" || evasion_level == "nation-state" {
            // Advanced encoding techniques
            let double_url = payload_str.replace('%', "%25").replace(' ', "%2520");
            let unicode_norm = payload_str.replace("script", "scr\u{0131}pt");
            let case_variation: String = payload_str
                .chars()
                .enumerate()
                .map(|(i, c)| if i % 2 == 0 { c.to_lowercase().collect::<String>() } else { c.to_uppercase().collect::<String>() })
                .collect();
            evasion_techniques.push(json!({"technique": "Double URL Encoding", "payload": double_url}));
            evasion_techniques.push(json!({"technique": "Unicode Normalization", "payload": unicode_norm}));
            evasion_techniques.push(json!({"technique": "Case Variation", "payload": case_variation}));
        }

        if evasion_level == "nation-state" {
            // Nation-state level techniques
            evasion_techniques.push(json!({
                "technique": "Polyglot Payload",
                "payload": format!("/*{payload_str}*/ OR {payload_str}"),
            }));
            evasion_techniques.push(json!({
                "technique": "Time-delayed Execution",
                "payload": format!("setTimeout(function(){{{payload_str}}}, 1000)"),
            }));
            evasion_techniques.push(json!({
                "technique": "Environmental Keying",
                "payload": format!("if(navigator.userAgent.includes('specific')){{ {payload_str} }}"),
            }));
        }

        advanced_payloads.push(json!({
            "payload": payload_str,
            "original_context": payload_info.get("context").cloned().unwrap_or_else(|| json!("")),
            "risk_level": payload_info.get("risk_level").cloned().unwrap_or_else(|| json!("")),
            "evasion_techniques": evasion_techniques,
            "deployment_methods": [
                "Direct injection",
                "Parameter pollution",
                "Header injection",
                "Cookie manipulation",
                "Fragment-based delivery",
            ],
        }));
    }

    // Generate deployment instructions
    let deployment_guide = json!({
        "pre_deployment": [
            "Reconnaissance of target environment",
            "Identification of input validation mechanisms",
            "Analysis of security controls (WAF, IDS, etc.)",
            "Selection of appropriate evasion techniques",
        ],
        "deployment": [
            "Start with least detectable payloads",
            "Monitor for defensive responses",
            "Escalate evasion techniques as needed",
            "Document successful techniques for future use",
        ],
        "post_deployment": [
            "Monitor for payload execution",
            "Clean up traces if necessary",
            "Document findings",
            "Report vulnerabilities responsibly",
        ],
    });

    let custom = if custom_constraints.is_empty() { "none".to_string() } else { custom_constraints.clone() };
    info!("🎯 Advanced payload generation completed | Generated: {} payloads", advanced_payloads.len());
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "advanced_payload_generation": {
                "attack_type": attack_type,
                "evasion_level": evasion_level,
                "target_context": target_context,
                "payload_count": advanced_payloads.len(),
                "advanced_payloads": advanced_payloads,
                "deployment_guide": deployment_guide,
                "custom_constraints_applied": custom,
            },
            "disclaimer": "These payloads are for authorized security testing only. Ensure proper authorization before use.",
            "timestamp": iso_now(),
        })),
    )
}

pub fn routes() -> Router {
    Router::new()
        .route("/api/vuln-intel/cve-monitor", post(cve_monitor))
        .route("/api/vuln-intel/exploit-generate", post(exploit_generate))
        .route("/api/vuln-intel/attack-chains", post(discover_attack_chains))
        .route("/api/vuln-intel/threat-feeds", post(threat_intelligence_feeds))
        .route("/api/ai/advanced-payload-generation", post(advanced_payload_generation))
        .route("/api/vuln-intel/zero-day-research", post(zero_day_research))
}
