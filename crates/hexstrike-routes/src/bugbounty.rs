//! Port 1:1 de `hexstrike_server/routes/bugbounty.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W7.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    19  def create_reconnaissance_workflow
//!    57  def create_vulnerability_hunting_workflow
//!    93  def create_business_logic_workflow
//!   124  def create_osint_workflow
//!   154  def create_file_upload_testing
//!   185  def create_comprehensive_bugbounty_assessment
//! ```
//!
//! Rotas (`@app.route`) deste módulo (6):
//!
//! ```text
//!    18  create_reconnaissance_workflow("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
//!    56  create_vulnerability_hunting_workflow("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])
//!    92  create_business_logic_workflow("/api/bugbounty/business-logic-workflow", methods=["POST"])
//!   123  create_osint_workflow("/api/bugbounty/osint-workflow", methods=["POST"])
//!   153  create_file_upload_testing("/api/bugbounty/file-upload-testing", methods=["POST"])
//!   184  create_comprehensive_bugbounty_assessment("/api/bugbounty/comprehensive-assessment", methods=["POST"])
//! ```
//!
//! Os seis handlers são `try/except Exception -> 500` no Python. Em Rust não há
//! exceção: o braço `return jsonify({"error": f"Server error: {str(e)}"}), 500`
//! e o `logger.error(f"💥 Error ...")` de cada rota são inalcançáveis por
//! construção (o Python só os alcança com corpo fora das anotações de tipo) e
//! ficam documentados aqui em vez de inventados. Corpo que não é JSON é
//! recusado pelo extractor do axum, antes do handler.

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::info;
use hexstrike_intelligence::vuln_intel::iso_now;

use hexstrike_intelligence::bugbounty::{
    bugbounty_manager, fileupload_framework, BugBountyTarget,
};

/// `datetime.now().isoformat()` — usado no `"timestamp"` de todas as respostas.
///
/// Duplicado de `intelligence::vuln_intel::iso_now` (que é privado); quando o
/// dono daquele arquivo o tornar `pub`, este sai.

/// `data.get(key, [])` das anotações `List[str]` do Python (que não valida o
/// tipo do corpo).
fn str_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `data.get("priority_vulns", ["rce", "sqli", "xss", "idor", "ssrf"])` — o
/// default mora em `BugBountyTarget`.
fn priority_vulns_of(data: &Value) -> Vec<String> {
    match data.get("priority_vulns") {
        Some(value) => str_list(Some(value)),
        None => BugBountyTarget::default().priority_vulns,
    }
}

/// `@app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])`
pub async fn create_reconnaissance_workflow(
    Json(data): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(domain) = data.get("domain").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain is required"})),
        );
    };
    let scope = str_list(data.get("scope"));
    let out_of_scope = str_list(data.get("out_of_scope"));
    let program_type = data
        .get("program_type")
        .and_then(Value::as_str)
        .unwrap_or("web");

    info!("🎯 Creating reconnaissance workflow for {domain}");

    // Create bug bounty target
    let target = BugBountyTarget {
        domain: domain.to_string(),
        scope,
        out_of_scope,
        program_type: program_type.to_string(),
        ..Default::default()
    };

    // Generate reconnaissance workflow
    let workflow = bugbounty_manager.create_reconnaissance_workflow(&target);

    info!("✅ Reconnaissance workflow created for {domain}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "workflow": workflow,
            "timestamp": iso_now()
        })),
    )
}

/// `@app.route("/api/bugbounty/vulnerability-hunting-workflow",
/// methods=["POST"])`
pub async fn create_vulnerability_hunting_workflow(
    Json(data): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(domain) = data.get("domain").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain is required"})),
        );
    };
    let priority_vulns = priority_vulns_of(&data);
    let bounty_range = data
        .get("bounty_range")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    info!("🎯 Creating vulnerability hunting workflow for {domain}");

    // Create bug bounty target
    let target = BugBountyTarget {
        domain: domain.to_string(),
        priority_vulns,
        bounty_range: bounty_range.to_string(),
        ..Default::default()
    };

    // Generate vulnerability hunting workflow
    let workflow = bugbounty_manager.create_vulnerability_hunting_workflow(&target);

    info!("✅ Vulnerability hunting workflow created for {domain}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "workflow": workflow,
            "timestamp": iso_now()
        })),
    )
}

/// `@app.route("/api/bugbounty/business-logic-workflow", methods=["POST"])`
pub async fn create_business_logic_workflow(
    Json(data): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(domain) = data.get("domain").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain is required"})),
        );
    };
    let program_type = data
        .get("program_type")
        .and_then(Value::as_str)
        .unwrap_or("web");

    info!("🎯 Creating business logic testing workflow for {domain}");

    // Create bug bounty target
    let target = BugBountyTarget {
        domain: domain.to_string(),
        program_type: program_type.to_string(),
        ..Default::default()
    };

    // Generate business logic testing workflow
    let workflow = bugbounty_manager.create_business_logic_testing_workflow(&target);

    info!("✅ Business logic testing workflow created for {domain}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "workflow": workflow,
            "timestamp": iso_now()
        })),
    )
}

/// `@app.route("/api/bugbounty/osint-workflow", methods=["POST"])`
pub async fn create_osint_workflow(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(domain) = data.get("domain").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain is required"})),
        );
    };

    info!("🎯 Creating OSINT workflow for {domain}");

    // Create bug bounty target
    let target = BugBountyTarget {
        domain: domain.to_string(),
        ..Default::default()
    };

    // Generate OSINT workflow
    let workflow = bugbounty_manager.create_osint_workflow(&target);

    info!("✅ OSINT workflow created for {domain}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "workflow": workflow,
            "timestamp": iso_now()
        })),
    )
}

/// `@app.route("/api/bugbounty/file-upload-testing", methods=["POST"])`
pub async fn create_file_upload_testing(Json(data): Json<Value>) -> (StatusCode, Json<Value>) {
    let Some(target_url) = data.get("target_url").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target URL is required"})),
        );
    };

    info!("🎯 Creating file upload testing workflow for {target_url}");

    // Generate file upload testing workflow
    let mut workflow = fileupload_framework.create_upload_testing_workflow(target_url);

    // Generate test files
    let test_files = fileupload_framework.generate_test_files();
    workflow["test_files"] = test_files;

    info!("✅ File upload testing workflow created for {target_url}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "workflow": workflow,
            "timestamp": iso_now()
        })),
    )
}

/// `@app.route("/api/bugbounty/comprehensive-assessment", methods=["POST"])`
pub async fn create_comprehensive_bugbounty_assessment(
    Json(data): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(domain) = data.get("domain").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain is required"})),
        );
    };
    let scope = str_list(data.get("scope"));
    let priority_vulns = priority_vulns_of(&data);
    let include_osint = data
        .get("include_osint")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_business_logic = data
        .get("include_business_logic")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    info!("🎯 Creating comprehensive bug bounty assessment for {domain}");

    // Create bug bounty target
    let target = BugBountyTarget {
        domain: domain.to_string(),
        scope,
        priority_vulns,
        ..Default::default()
    };

    // Generate all workflows
    let mut assessment = json!({
        "target": domain,
        "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(&target),
        "vulnerability_hunting": bugbounty_manager.create_vulnerability_hunting_workflow(&target)
    });

    if include_osint {
        assessment["osint"] = bugbounty_manager.create_osint_workflow(&target);
    }

    if include_business_logic {
        assessment["business_logic"] = bugbounty_manager.create_business_logic_testing_workflow(&target);
    }

    // Calculate total estimates (só os workflows: dicts com estimated_time /
    // tools_count; `target` é string e não entra).
    let (mut total_time, mut total_tools) = (0i64, 0usize);
    if let Some(workflows) = assessment.as_object() {
        for workflow in workflows.values() {
            total_time += workflow
                .get("estimated_time")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            total_tools += workflow
                .get("tools_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
        }
    }

    let workflow_count = assessment
        .as_object()
        .map(|workflows| workflows.keys().filter(|key| *key != "target").count())
        .unwrap_or(0);
    let priority_score = assessment
        .get("vulnerability_hunting")
        .and_then(|workflow| workflow.get("priority_score"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    assessment["summary"] = json!({
        "total_estimated_time": total_time,
        "total_tools": total_tools,
        "workflow_count": workflow_count,
        "priority_score": priority_score
    });

    info!("✅ Comprehensive bug bounty assessment created for {domain}");

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "assessment": assessment,
            "timestamp": iso_now()
        })),
    )
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route(
            "/api/bugbounty/reconnaissance-workflow",
            post(create_reconnaissance_workflow),
        )
        .route(
            "/api/bugbounty/vulnerability-hunting-workflow",
            post(create_vulnerability_hunting_workflow),
        )
        .route(
            "/api/bugbounty/business-logic-workflow",
            post(create_business_logic_workflow),
        )
        .route("/api/bugbounty/osint-workflow", post(create_osint_workflow))
        .route(
            "/api/bugbounty/file-upload-testing",
            post(create_file_upload_testing),
        )
        .route(
            "/api/bugbounty/comprehensive-assessment",
            post(create_comprehensive_bugbounty_assessment),
        )
}
