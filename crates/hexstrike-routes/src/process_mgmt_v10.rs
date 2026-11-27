//! Port 1:1 de `hexstrike_server/routes/process_mgmt_v10.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W5.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  def execute_command_async
//!    47  def get_async_task_result
//!    68  def get_process_pool_stats
//!    85  def get_cache_stats
//!   102  def clear_process_cache
//!   119  def get_resource_usage
//!   138  def get_performance_dashboard
//!   171  def terminate_process_gracefully
//!   200  def configure_auto_scaling
//!   226  def manual_scale_pool
//!   270  def process_health_check
//! ```
//!
//! Rotas (`@app.route`) deste módulo (11):
//!
//! ```text
//!    19  execute_command_async("/api/process/execute-async", methods=["POST"])
//!    46  get_async_task_result("/api/process/get-task-result/<task_id>", methods=["GET"])
//!    67  get_process_pool_stats("/api/process/pool-stats", methods=["GET"])
//!    84  get_cache_stats("/api/process/cache-stats", methods=["GET"])
//!   101  clear_process_cache("/api/process/clear-cache", methods=["POST"])
//!   118  get_resource_usage("/api/process/resource-usage", methods=["GET"])
//!   137  get_performance_dashboard("/api/process/performance-dashboard", methods=["GET"])
//!   170  terminate_process_gracefully("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])
//!   199  configure_auto_scaling("/api/process/auto-scaling", methods=["POST"])
//!   225  manual_scale_pool("/api/process/scale-pool", methods=["POST"])
//!   269  process_health_check("/api/process/health-check", methods=["GET"])
//! ```
//!
//! Observações de port: iguais às de `routes/process_mgmt.rs` (`<int:pid>`,
//! `try/except` -> 500). Todos os endpoints aqui leem/escrevem o singleton
//! `enhanced_process_manager` (`intelligence/process_manager.rs`).

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::info;

use hexstrike_intelligence::process_manager::enhanced_process_manager;
use crate::process_mgmt::{int_pid, not_found};
use hexstrike_intelligence::vuln_intel::iso_now;

/// `datetime.now().isoformat()`

/// `if not value:` do Python.
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

/// `f"{value:.1f}"` para um número JSON (`cache_stats['hit_rate']`).
fn fmt_f64(value: &Value) -> String {
    format!("{:.1}", value.as_f64().unwrap_or(0.0))
}

// ============================================================================
// ADVANCED PROCESS MANAGEMENT API ENDPOINTS (v10.0 ENHANCEMENT)
// ============================================================================

/// `@app.route("/api/process/execute-async", methods=["POST"])` —
/// `def execute_command_async()`.
pub async fn execute_command_async(Json(params): Json<Value>) -> Response {
    let command = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let context = params.get("context").cloned().unwrap_or(json!({}));

    if command.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Command parameter is required"})),
        )
            .into_response();
    }

    // Execute command asynchronously
    let task_id = enhanced_process_manager.execute_command_async(command, &context);

    info!(
        "🚀 Async command execution started | Task ID: {}",
        task_id
    );
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "task_id": task_id,
            "command": command,
            "status": "submitted",
            "timestamp": iso_now(),
        })),
    )
        .into_response()
}

/// `@app.route("/api/process/get-task-result/<task_id>", methods=["GET"])` —
/// `def get_async_task_result(task_id)`.
pub async fn get_async_task_result(Path(task_id): Path<String>) -> Response {
    let result = enhanced_process_manager.get_task_result(&task_id);

    if result.get("status").and_then(|v| v.as_str()) == Some("not_found") {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Task not found"})),
        )
            .into_response();
    }

    info!(
        "📋 Task result retrieved | Task ID: {task_id} | Status: {}",
        result.get("status").and_then(|v| v.as_str()).unwrap_or("")
    );
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "task_id": task_id,
            "result": result,
            "timestamp": iso_now(),
        })),
    )
        .into_response()
}

/// `@app.route("/api/process/pool-stats", methods=["GET"])` —
/// `def get_process_pool_stats()`.
pub async fn get_process_pool_stats() -> Json<Value> {
    let stats = enhanced_process_manager.get_comprehensive_stats();

    info!(
        "📊 Process pool stats retrieved | Active workers: {}",
        stats
            .get("process_pool")
            .and_then(|v| v.get("active_workers"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    );
    Json(json!({
        "success": true,
        "stats": stats,
        "timestamp": iso_now(),
    }))
}

/// `@app.route("/api/process/cache-stats", methods=["GET"])` —
/// `def get_cache_stats()`.
pub async fn get_cache_stats() -> Json<Value> {
    let cache_stats = enhanced_process_manager.cache.get_stats();

    info!(
        "💾 Cache stats retrieved | Hit rate: {}%",
        fmt_f64(cache_stats.get("hit_rate").unwrap_or(&json!(0)))
    );
    Json(json!({
        "success": true,
        "cache_stats": cache_stats,
        "timestamp": iso_now(),
    }))
}

/// `@app.route("/api/process/clear-cache", methods=["POST"])` —
/// `def clear_process_cache()`.
pub async fn clear_process_cache() -> Json<Value> {
    enhanced_process_manager.cache.clear();

    info!("🧹 Process cache cleared");
    Json(json!({
        "success": true,
        "message": "Cache cleared successfully",
        "timestamp": iso_now(),
    }))
}

/// `@app.route("/api/process/resource-usage", methods=["GET"])` —
/// `def get_resource_usage()`.
pub async fn get_resource_usage() -> Json<Value> {
    let current_usage = enhanced_process_manager.resource_monitor.get_current_usage();
    let usage_trends = enhanced_process_manager.resource_monitor.get_usage_trends();

    info!(
        "📈 Resource usage retrieved | CPU: {}% | Memory: {}%",
        fmt_f64(current_usage.get("cpu_percent").unwrap_or(&json!(0))),
        fmt_f64(current_usage.get("memory_percent").unwrap_or(&json!(0)))
    );
    Json(json!({
        "success": true,
        "current_usage": current_usage,
        "usage_trends": usage_trends,
        "timestamp": iso_now(),
    }))
}

/// `@app.route("/api/process/performance-dashboard", methods=["GET"])` —
/// `def get_performance_dashboard()`.
pub async fn get_performance_dashboard() -> Json<Value> {
    let dashboard_data = enhanced_process_manager.performance_dashboard.get_summary();
    let pool_stats = enhanced_process_manager.process_pool.get_pool_stats();
    let resource_usage = enhanced_process_manager.resource_monitor.get_current_usage();

    let cpu_percent = resource_usage
        .get("cpu_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let memory_percent = resource_usage
        .get("memory_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let disk_percent = resource_usage
        .get("disk_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let health = |value: f64, warn: f64, critical: f64| -> &'static str {
        if value < warn {
            "healthy"
        } else if value < critical {
            "warning"
        } else {
            "critical"
        }
    };

    // Create comprehensive dashboard
    let dashboard = json!({
        "performance_summary": dashboard_data,
        "process_pool": pool_stats,
        "resource_usage": resource_usage,
        "cache_stats": enhanced_process_manager.cache.get_stats(),
        "auto_scaling_status": enhanced_process_manager
            .auto_scaling_enabled
            .load(std::sync::atomic::Ordering::SeqCst),
        "system_health": {
            "cpu_status": health(cpu_percent, 80.0, 95.0),
            "memory_status": health(memory_percent, 85.0, 95.0),
            "disk_status": health(disk_percent, 90.0, 98.0),
        },
    });

    info!(
        "📊 Performance dashboard retrieved | Success rate: {}%",
        fmt_f64(dashboard_data.get("success_rate").unwrap_or(&json!(0)))
    );
    Json(json!({
        "success": true,
        "dashboard": dashboard,
        "timestamp": iso_now(),
    }))
}

/// `@app.route("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])`
/// — `def terminate_process_gracefully(pid)`.
pub async fn terminate_process_gracefully(
    Path(pid): Path<String>,
    Json(params): Json<Value>,
) -> Response {
    let Some(pid) = int_pid(&pid) else {
        return not_found();
    };
    let timeout = params.get("timeout").and_then(|v| v.as_u64()).unwrap_or(30);

    let success = enhanced_process_manager.terminate_process_gracefully(pid, timeout);

    if success {
        info!("✅ Process {pid} terminated gracefully");
        return (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": format!("Process {pid} terminated successfully"),
                "pid": pid,
                "timestamp": iso_now(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": format!("Failed to terminate process {pid}"),
            "pid": pid,
            "timestamp": iso_now(),
        })),
    )
        .into_response()
}

/// `@app.route("/api/process/auto-scaling", methods=["POST"])` —
/// `def configure_auto_scaling()`.
pub async fn configure_auto_scaling(Json(params): Json<Value>) -> Response {
    let enabled = params.get("enabled").cloned().unwrap_or(Value::Bool(true));
    let thresholds = params.get("thresholds").cloned().unwrap_or(json!({}));

    // Update auto-scaling configuration
    enhanced_process_manager
        .auto_scaling_enabled
        .store(py_truthy(&enabled), std::sync::atomic::Ordering::SeqCst);

    if py_truthy(&thresholds) {
        if let Some(thresholds) = thresholds.as_object() {
            let mut resource_thresholds = enhanced_process_manager
                .resource_thresholds
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for (key, value) in thresholds {
                resource_thresholds.insert(key.clone(), value.clone());
            }
        }
    }

    info!("⚙️ Auto-scaling configured | Enabled: {enabled}");
    let resource_thresholds = Value::Object(
        enhanced_process_manager
            .resource_thresholds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
    );
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "auto_scaling_enabled": enabled,
            "resource_thresholds": resource_thresholds,
            "timestamp": iso_now(),
        })),
    )
        .into_response()
}

/// `@app.route("/api/process/scale-pool", methods=["POST"])` —
/// `def manual_scale_pool()`.
pub async fn manual_scale_pool(Json(params): Json<Value>) -> Response {
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let count = params.get("count").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

    if action != "up" && action != "down" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Action must be 'up' or 'down'"})),
        )
            .into_response();
    }

    let current_stats = enhanced_process_manager.process_pool.get_pool_stats();
    let current_workers = current_stats
        .get("active_workers")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let new_workers;
    let message;
    if action == "up" {
        let max_workers = enhanced_process_manager.process_pool.max_workers;
        if current_workers + count <= max_workers {
            enhanced_process_manager.process_pool._scale_up(count);
            new_workers = current_workers + count;
            message = format!("Scaled up by {count} workers");
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Cannot scale up: would exceed max workers ({max_workers})"),
                })),
            )
                .into_response();
        }
    } else {
        // down
        let min_workers = enhanced_process_manager.process_pool.min_workers;
        if current_workers >= count && current_workers - count >= min_workers {
            enhanced_process_manager.process_pool._scale_down(count);
            new_workers = current_workers - count;
            message = format!("Scaled down by {count} workers");
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Cannot scale down: would go below min workers ({min_workers})"),
                })),
            )
                .into_response();
        }
    }

    info!("📏 Manual scaling | {message} | Workers: {current_workers} → {new_workers}");
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": message,
            "previous_workers": current_workers,
            "current_workers": new_workers,
            "timestamp": iso_now(),
        })),
    )
        .into_response()
}

/// `@app.route("/api/process/health-check", methods=["GET"])` —
/// `def process_health_check()`.
pub async fn process_health_check() -> Json<Value> {
    // Get all system stats
    let comprehensive_stats = enhanced_process_manager.get_comprehensive_stats();

    // Determine overall health
    let empty = json!({});
    let resource_usage = comprehensive_stats.get("resource_usage").unwrap_or(&empty);
    let pool_stats = comprehensive_stats.get("process_pool").unwrap_or(&empty);
    let cache_stats = comprehensive_stats.get("cache").unwrap_or(&empty);

    let cpu_percent = resource_usage
        .get("cpu_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let memory_percent = resource_usage
        .get("memory_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let disk_percent = resource_usage
        .get("disk_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let queue_size = pool_stats.get("queue_size").and_then(|v| v.as_i64()).unwrap_or(0);
    let hit_rate = cache_stats.get("hit_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);

    let mut health_score: i64 = 100;
    let mut issues: Vec<&'static str> = Vec::new();

    // CPU health
    if cpu_percent > 95.0 {
        health_score -= 30;
        issues.push("Critical CPU usage");
    } else if cpu_percent > 80.0 {
        health_score -= 15;
        issues.push("High CPU usage");
    }

    // Memory health
    if memory_percent > 95.0 {
        health_score -= 25;
        issues.push("Critical memory usage");
    } else if memory_percent > 85.0 {
        health_score -= 10;
        issues.push("High memory usage");
    }

    // Disk health
    if disk_percent > 98.0 {
        health_score -= 20;
        issues.push("Critical disk usage");
    } else if disk_percent > 90.0 {
        health_score -= 5;
        issues.push("High disk usage");
    }

    // Process pool health
    if queue_size > 50 {
        health_score -= 15;
        issues.push("High task queue backlog");
    }

    // Cache health
    if hit_rate < 30.0 {
        health_score -= 10;
        issues.push("Low cache hit rate");
    }

    health_score = health_score.max(0);

    // Determine status
    let status = if health_score >= 90 {
        "excellent"
    } else if health_score >= 75 {
        "good"
    } else if health_score >= 50 {
        "fair"
    } else if health_score >= 25 {
        "poor"
    } else {
        "critical"
    };

    // Add recommendations based on issues
    let mut recommendations: Vec<&'static str> = Vec::new();
    if issues.contains(&"High CPU usage") {
        recommendations.push("Consider reducing concurrent processes or upgrading CPU");
    }
    if issues.contains(&"High memory usage") {
        recommendations.push("Clear caches or increase available memory");
    }
    if issues.contains(&"High task queue backlog") {
        recommendations.push("Scale up process pool or optimize task processing");
    }
    if issues.contains(&"Low cache hit rate") {
        recommendations.push("Review cache TTL settings or increase cache size");
    }

    let health_report = json!({
        "overall_status": status,
        "health_score": health_score,
        "issues": issues,
        "system_stats": comprehensive_stats,
        "recommendations": recommendations,
    });

    info!("🏥 Health check completed | Status: {status} | Score: {health_score}/100");
    Json(json!({
        "success": true,
        "health_report": health_report,
        "timestamp": iso_now(),
    }))
}

/// Rotas deste módulo, na ordem do arquivo Python.
pub fn routes() -> Router {
    Router::new()
        .route("/api/process/execute-async", post(execute_command_async))
        .route(
            "/api/process/get-task-result/{task_id}",
            get(get_async_task_result),
        )
        .route("/api/process/pool-stats", get(get_process_pool_stats))
        .route("/api/process/cache-stats", get(get_cache_stats))
        .route("/api/process/clear-cache", post(clear_process_cache))
        .route("/api/process/resource-usage", get(get_resource_usage))
        .route(
            "/api/process/performance-dashboard",
            get(get_performance_dashboard),
        )
        .route(
            "/api/process/terminate-gracefully/{pid}",
            post(terminate_process_gracefully),
        )
        .route("/api/process/auto-scaling", post(configure_auto_scaling))
        .route("/api/process/scale-pool", post(manual_scale_pool))
        .route("/api/process/health-check", get(process_health_check))
}
