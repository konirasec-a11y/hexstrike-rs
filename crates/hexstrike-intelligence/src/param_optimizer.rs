//! Port 1:1 de `hexstrike_server/intelligence/param_optimizer.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W5.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    22  class TechnologyDetector:
//!   143  class RateLimitDetector:
//!   248  class FailureRecoverySystem:
//!   343  class PerformanceMonitor:
//!   434  class ParameterOptimizer:
//! ```
//!
//! Observações de port:
//!
//! - Os `dict` do Python são [`Value`] (regra do contrato). Listas de
//!   categorias/ferramentas cuja ORDEM é observável ficam em `&[..]` estáticos
//!   (mesma ordem de inserção do literal Python).
//! - `ParameterOptimizer::optimize_parameters_advanced` e
//!   `ParameterOptimizer::_get_base_parameters` recebem
//!   `TargetProfile` (`intelligence/decision_engine.py`), que no crate ainda é
//!   stub do shard W1 — as duas ficam `todo!()` até lá.
//! - `psutil` -> `sysinfo`/leitura de `/proc`, como em `vuln_intel.rs`.

use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Map, Value};
use sysinfo::System;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// `str(float)` do Python (`1.0` -> `"1.0"`, `0.5` -> `"0.5"`), usado dentro
/// das f-strings que montam `additional_args`/mensagens de otimização.
fn py_float(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e16 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

/// `str(x)` de um valor JSON numérico (o `{x}` das f-strings do Python).
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() => py_float(f),
            _ => n.to_string(),
        },
        other => other.to_string(),
    }
}

/// `self.detection_patterns` — a ORDEM é a do literal Python (a ordem dos
/// arrays devolvidos por `detect_technologies` depende dela).
pub type DetectionPatterns =
    &'static [(&'static str, &'static [(&'static str, &'static [&'static str])])];

const DETECTION_PATTERNS: DetectionPatterns = &[
    (
        "web_servers",
        &[
            ("apache", &["Apache", "apache", "httpd"]),
            ("nginx", &["nginx", "Nginx"]),
            ("iis", &["Microsoft-IIS", "IIS"]),
            ("tomcat", &["Tomcat", "Apache-Coyote"]),
            ("jetty", &["Jetty"]),
            ("lighttpd", &["lighttpd"]),
        ],
    ),
    (
        "frameworks",
        &[
            ("django", &["Django", "django", "csrftoken"]),
            ("flask", &["Flask", "Werkzeug"]),
            ("express", &["Express", "X-Powered-By: Express"]),
            ("laravel", &["Laravel", "laravel_session"]),
            ("symfony", &["Symfony", "symfony"]),
            ("rails", &["Ruby on Rails", "rails", "_session_id"]),
            ("spring", &["Spring", "JSESSIONID"]),
            ("struts", &["Struts", "struts"]),
        ],
    ),
    (
        "cms",
        &[
            (
                "wordpress",
                &["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
            ),
            (
                "drupal",
                &["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
            ),
            (
                "joomla",
                &["Joomla", "joomla", "/administrator/", "com_content"],
            ),
            ("magento", &["Magento", "magento", "Mage.Cookies"]),
            ("prestashop", &["PrestaShop", "prestashop"]),
            ("opencart", &["OpenCart", "opencart"]),
        ],
    ),
    (
        "databases",
        &[
            ("mysql", &["MySQL", "mysql", "phpMyAdmin"]),
            ("postgresql", &["PostgreSQL", "postgres"]),
            ("mssql", &["Microsoft SQL Server", "MSSQL"]),
            ("oracle", &["Oracle", "oracle"]),
            ("mongodb", &["MongoDB", "mongo"]),
            ("redis", &["Redis", "redis"]),
        ],
    ),
    (
        "languages",
        &[
            ("php", &["PHP", "php", ".php", "X-Powered-By: PHP"]),
            ("python", &["Python", "python", ".py"]),
            ("java", &["Java", "java", ".jsp", ".do"]),
            ("dotnet", &["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"]),
            ("nodejs", &["Node.js", "node", ".js"]),
            ("ruby", &["Ruby", "ruby", ".rb"]),
            ("go", &["Go", "golang"]),
            ("rust", &["Rust", "rust"]),
        ],
    ),
    (
        "security",
        &[
            (
                "waf",
                &[
                    "cloudflare",
                    "CloudFlare",
                    "X-CF-Ray",
                    "incapsula",
                    "Incapsula",
                    "sucuri",
                    "Sucuri",
                ],
            ),
            (
                "load_balancer",
                &["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
            ),
            (
                "cdn",
                &["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"],
            ),
        ],
    ),
];

/// As 7 chaves de `detected`, na ordem do literal Python.
const DETECTED_CATEGORIES: [&str; 7] = [
    "web_servers",
    "frameworks",
    "cms",
    "databases",
    "languages",
    "security",
    "services",
];

type Detected = [(&'static str, Vec<String>); 7];

fn detected_new() -> Detected {
    DETECTED_CATEGORIES.map(|c| (c, Vec::new()))
}

fn detected_push(detected: &mut Detected, category: &str, tech: &str) {
    for (name, bucket) in detected.iter_mut() {
        if *name == category {
            // `if tech not in detected[category]`
            if !bucket.iter().any(|t| t == tech) {
                bucket.push(tech.to_string());
            }
            return;
        }
    }
}

fn detected_to_json(detected: Detected) -> Value {
    let mut map = Map::new();
    for (name, items) in detected {
        map.insert(
            name.to_string(),
            Value::Array(items.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(map)
}

/// `class TechnologyDetector:` — detecção de tecnologias para otimização
/// sensível a contexto.
pub struct TechnologyDetector {
    pub detection_patterns: DetectionPatterns,
    pub port_services: Map<String, Value>,
}

impl TechnologyDetector {
    pub fn new() -> Self {
        let mut port_services = Map::new();
        for (port, service) in [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (143, "imap"),
            (443, "https"),
            (993, "imaps"),
            (995, "pop3s"),
            (1433, "mssql"),
            (3306, "mysql"),
            (5432, "postgresql"),
            (6379, "redis"),
            (27017, "mongodb"),
            (8080, "http-alt"),
            (8443, "https-alt"),
            (9200, "elasticsearch"),
            (11211, "memcached"),
        ] {
            port_services.insert(port.to_string(), Value::String(service.to_string()));
        }
        Self {
            detection_patterns: DETECTION_PATTERNS,
            port_services,
        }
    }

    /// `detect_technologies(target, headers=None, content="", ports=None)` —
    /// `target` não é usado no corpo do Python (mantido por paridade de
    /// assinatura).
    pub fn detect_technologies(
        &self,
        _target: &str,
        headers: Option<&Map<String, Value>>,
        content: &str,
        ports: Option<&[i64]>,
    ) -> Value {
        let mut detected = detected_new();

        // Header-based detection
        if let Some(headers) = headers {
            for (category, tech_patterns) in self.detection_patterns {
                for (tech, patterns) in *tech_patterns {
                    for (header_name, header_value) in headers {
                        let header_name = header_name.to_lowercase();
                        let header_value = header_value.as_str().unwrap_or("").to_lowercase();
                        for pattern in *patterns {
                            let pattern = pattern.to_lowercase();
                            if header_value.contains(&pattern) || header_name.contains(&pattern) {
                                detected_push(&mut detected, category, tech);
                            }
                        }
                    }
                }
            }
        }

        // Content-based detection
        if !content.is_empty() {
            let content_lower = content.to_lowercase();
            for (category, tech_patterns) in self.detection_patterns {
                for (tech, patterns) in *tech_patterns {
                    for pattern in *patterns {
                        if content_lower.contains(&pattern.to_lowercase()) {
                            detected_push(&mut detected, category, tech);
                        }
                    }
                }
            }
        }

        // Port-based service detection
        if let Some(ports) = ports {
            for port in ports {
                if let Some(service) = self.port_services.get(&port.to_string()) {
                    let service = service.as_str().unwrap_or("");
                    let already = detected
                        .iter()
                        .any(|(_, b)| b.iter().any(|s| s == service));
                    if !already {
                        detected_push(&mut detected, "services", service);
                    }
                }
            }
        }

        detected_to_json(detected)
    }
}

impl Default for TechnologyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// `self.timing_profiles[profile]` — os 4 perfis do literal Python.
#[derive(Clone, Copy)]
struct Timing {
    delay: f64,
    threads: i64,
    timeout: i64,
}

fn timing_profile(profile: &str) -> Timing {
    match profile {
        "aggressive" => Timing {
            delay: 0.1,
            threads: 50,
            timeout: 5,
        },
        "conservative" => Timing {
            delay: 1.0,
            threads: 10,
            timeout: 15,
        },
        "stealth" => Timing {
            delay: 2.0,
            threads: 5,
            timeout: 30,
        },
        // `self.timing_profiles["normal"]` (default do `.get`)
        _ => Timing {
            delay: 0.5,
            threads: 20,
            timeout: 10,
        },
    }
}

/// `class RateLimitDetector:` — detecção de rate limiting e ajuste de timing.
pub struct RateLimitDetector {
    pub rate_limit_indicators: Vec<&'static str>,
}

impl RateLimitDetector {
    pub fn new() -> Self {
        Self {
            rate_limit_indicators: vec![
                "rate limit",
                "too many requests",
                "429",
                "throttle",
                "slow down",
                "retry after",
                "quota exceeded",
                "api limit",
                "request limit",
            ],
        }
    }

    /// `detect_rate_limiting(response_text, status_code, headers=None)`
    pub fn detect_rate_limiting(
        &self,
        response_text: &str,
        status_code: i64,
        headers: Option<&Map<String, Value>>,
    ) -> Value {
        let mut rate_limit_detected = false;
        let mut confidence = 0.0f64;
        let mut indicators_found: Vec<String> = Vec::new();

        // Status code check
        if status_code == 429 {
            rate_limit_detected = true;
            confidence += 0.8;
            indicators_found.push("HTTP 429 status".to_string());
        }

        // Response text check
        let response_lower = response_text.to_lowercase();
        for indicator in &self.rate_limit_indicators {
            if response_lower.contains(indicator) {
                rate_limit_detected = true;
                confidence += 0.2;
                indicators_found.push(format!("Text: '{indicator}'"));
            }
        }

        // Header check
        if let Some(headers) = headers {
            let rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"];
            for header_name in headers.keys() {
                let name_lower = header_name.to_lowercase();
                for rl_header in rate_limit_headers {
                    if name_lower.contains(rl_header) {
                        rate_limit_detected = true;
                        confidence += 0.3;
                        indicators_found.push(format!("Header: {header_name}"));
                    }
                }
            }
        }

        let confidence = confidence.min(1.0);

        json!({
            "detected": rate_limit_detected,
            "confidence": confidence,
            "indicators": indicators_found,
            "recommended_profile": self._recommend_timing_profile(confidence),
        })
    }

    /// `_recommend_timing_profile(confidence)`
    fn _recommend_timing_profile(&self, confidence: f64) -> &'static str {
        if confidence >= 0.8 {
            "stealth"
        } else if confidence >= 0.5 {
            "conservative"
        } else if confidence >= 0.2 {
            "normal"
        } else {
            "aggressive"
        }
    }

    /// `adjust_timing(current_params, profile)`
    pub fn adjust_timing(&self, current_params: &Map<String, Value>, profile: &str) -> Value {
        let timing = timing_profile(profile);
        let mut adjusted_params = current_params.clone();

        // Adjust common parameters
        if adjusted_params.contains_key("threads") {
            adjusted_params.insert("threads".to_string(), json!(timing.threads));
        }
        if adjusted_params.contains_key("delay") {
            adjusted_params.insert("delay".to_string(), json!(timing.delay));
        }
        if adjusted_params.contains_key("timeout") {
            adjusted_params.insert("timeout".to_string(), json!(timing.timeout));
        }

        // Tool-specific adjustments
        if let Some(args) = adjusted_params.get("additional_args").and_then(|v| v.as_str()) {
            let mut args = args.to_string();

            // Remove existing timing arguments
            for pattern in [r"-t\s+\d+", r"--threads\s+\d+", r"--delay\s+[\d.]+"] {
                args = Regex::new(pattern).unwrap().replace_all(&args, "").to_string();
            }

            // Add new timing arguments
            args.push_str(&format!(" -t {}", timing.threads));
            if timing.delay > 0.0 {
                args.push_str(&format!(" --delay {}", py_float(timing.delay)));
            }

            adjusted_params.insert("additional_args".to_string(), Value::String(args.trim().to_string()));
        }

        Value::Object(adjusted_params)
    }
}

impl Default for RateLimitDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// `self.tool_alternatives` — ordem de inserção do literal Python
/// (`_extract_tool_name` devolve a PRIMEIRA chave presente na saída).
const TOOL_ALTERNATIVES: &[(&str, &[&str])] = &[
    ("nmap", &["rustscan", "masscan", "zmap"]),
    ("gobuster", &["dirsearch", "feroxbuster", "dirb"]),
    ("sqlmap", &["sqlninja", "bbqsql", "jsql-injection"]),
    ("nuclei", &["nikto", "w3af", "skipfish"]),
    ("hydra", &["medusa", "ncrack", "patator"]),
    ("hashcat", &["john", "ophcrack", "rainbowcrack"]),
    ("amass", &["subfinder", "sublist3r", "assetfinder"]),
    ("ffuf", &["wfuzz", "gobuster", "dirb"]),
];

/// `self.failure_patterns` — ordem de inserção do literal Python.
const FAILURE_PATTERNS: &[(&str, &[&str])] = &[
    ("timeout", &["timeout", "timed out", "connection timeout"]),
    (
        "permission_denied",
        &["permission denied", "access denied", "forbidden"],
    ),
    (
        "not_found",
        &["not found", "command not found", "no such file"],
    ),
    (
        "network_error",
        &[
            "network unreachable",
            "connection refused",
            "host unreachable",
        ],
    ),
    (
        "rate_limited",
        &["rate limit", "too many requests", "throttled"],
    ),
    (
        "authentication_required",
        &["authentication required", "unauthorized", "login required"],
    ),
];

/// `class FailureRecoverySystem:` — recuperação com ferramenta alternativa.
pub struct FailureRecoverySystem {
    pub tool_alternatives: &'static [(&'static str, &'static [&'static str])],
    pub failure_patterns: &'static [(&'static str, &'static [&'static str])],
}

impl FailureRecoverySystem {
    pub fn new() -> Self {
        Self {
            tool_alternatives: TOOL_ALTERNATIVES,
            failure_patterns: FAILURE_PATTERNS,
        }
    }

    /// `analyze_failure(error_output, exit_code)`
    pub fn analyze_failure(&self, error_output: &str, exit_code: i64) -> Value {
        let mut failure_type = "unknown";
        let mut confidence = 0.0f64;
        let mut recovery_strategies: Vec<&'static str> = Vec::new();

        let error_lower = error_output.to_lowercase();

        // Identify failure type
        for (failure, patterns) in self.failure_patterns {
            for pattern in *patterns {
                if error_lower.contains(pattern) {
                    failure_type = failure;
                    confidence += 0.3;
                    break;
                }
            }
        }

        // Exit code analysis
        if exit_code == 1 {
            confidence += 0.1;
        } else if exit_code == 124 {
            // timeout
            failure_type = "timeout";
            confidence += 0.5;
        } else if exit_code == 126 {
            // permission denied
            failure_type = "permission_denied";
            confidence += 0.5;
        }

        let confidence = confidence.min(1.0);

        // Generate recovery strategies
        match failure_type {
            "timeout" => recovery_strategies = vec![
                "Increase timeout values",
                "Reduce thread count",
                "Use alternative faster tool",
                "Split target into smaller chunks",
            ],
            "permission_denied" => recovery_strategies = vec![
                "Run with elevated privileges",
                "Check file permissions",
                "Use alternative tool with different approach",
            ],
            "rate_limited" => recovery_strategies = vec![
                "Implement delays between requests",
                "Reduce thread count",
                "Use stealth timing profile",
                "Rotate IP addresses if possible",
            ],
            "network_error" => recovery_strategies = vec![
                "Check network connectivity",
                "Try alternative network routes",
                "Use proxy or VPN",
                "Verify target is accessible",
            ],
            _ => {}
        }

        let tool = self._extract_tool_name(error_output);
        let alternative_tools: Vec<String> = self
            .tool_alternatives
            .iter()
            .find(|(name, _)| *name == tool)
            .map(|(_, tools)| tools.iter().map(|t| t.to_string()).collect())
            .unwrap_or_default();

        json!({
            "failure_type": failure_type,
            "confidence": confidence,
            "recovery_strategies": recovery_strategies,
            "alternative_tools": alternative_tools,
        })
    }

    /// `_extract_tool_name(error_output)`
    fn _extract_tool_name(&self, error_output: &str) -> String {
        let error_lower = error_output.to_lowercase();
        for (tool, _) in self.tool_alternatives {
            if error_lower.contains(tool) {
                return (*tool).to_string();
            }
        }
        "unknown".to_string()
    }
}

impl Default for FailureRecoverySystem {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// psutil -> sysinfo // /proc
// ============================================================================
// Shim compartilhado pelas chamadas `psutil` dos módulos desta cadeia
// (`param_optimizer.py`, `process_manager.py` e `routes/process_mgmt.py`), na
// mesma linha do que `vuln_intel.rs` já faz localmente.

/// `psutil.cpu_percent(interval=1)`
pub fn cpu_percent_interval_1() -> f64 {
    let Ok(mut system) = System::new() else {
        return 0.0;
    };
    system.refresh_cpu_usage();
    sleep(Duration::from_secs(1));
    system.refresh_cpu_usage();
    system.global_cpu_usage() as f64
}

/// `psutil.virtual_memory().percent`
pub fn memory_percent() -> f64 {
    let Ok(mut system) = System::new() else {
        return 0.0;
    };
    system.refresh_memory();
    let total = system.total_memory() as f64;
    if total > 0.0 {
        system.used_memory() as f64 / total * 100.0
    } else {
        0.0
    }
}

/// `psutil.virtual_memory().available` em GB
pub(crate) fn memory_available_gb() -> f64 {
    let Ok(mut system) = System::new() else {
        return 0.0;
    };
    system.refresh_memory();
    system.available_memory() as f64 / 1024f64.powi(3)
}

/// Memória total em bytes (para `memory_percent` por processo).
pub(crate) fn total_memory_bytes() -> u64 {
    let Ok(mut system) = System::new() else {
        return 0;
    };
    system.refresh_memory();
    system.total_memory()
}

/// Espelho de `psutil.net_io_counters()` (sem `pernic`): soma de todas as
/// interfaces em `/proc/net/dev` — `(bytes_sent, bytes_recv)`.
pub(crate) fn net_io_counters() -> (u64, u64) {
    let mut bytes_sent = 0u64;
    let mut bytes_recv = 0u64;
    let Ok(raw) = std::fs::read_to_string("/proc/net/dev") else {
        return (bytes_sent, bytes_recv);
    };
    for line in raw.lines() {
        let Some((_iface, rest)) = line.split_once(':') else {
            continue;
        };
        let cols: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|c| c.parse().ok())
            .collect();
        if cols.len() < 16 {
            continue;
        }
        bytes_recv += cols[0];
        bytes_sent += cols[8];
    }
    (bytes_sent, bytes_recv)
}

/// `psutil.disk_usage('/')` — `(percent, free_bytes)`.
///
/// O `percent` do psutil 7 é `used / (used + f_bavail)` com
/// `used = total - f_bfree`, e o `sysinfo` só expõe `f_bavail`; por isso os
/// dois contadores do `statvfs` vêm de `stat -f` (coreutils). Sem `stat`, cai no
/// cálculo do `sysinfo`, que ignora os blocos reservados ao root.
pub(crate) fn disk_usage_root() -> (f64, f64) {
    if let Ok(output) = std::process::Command::new("stat")
        .args(["-f", "-c", "%b %f %a %S", "/"])
        .output()
    {
        if output.status.success() {
            let raw = String::from_utf8_lossy(&output.stdout);
            let cols: Vec<u64> = raw.split_whitespace().filter_map(|c| c.parse().ok()).collect();
            if cols.len() >= 4 {
                let (blocks, bfree, bavail, frsize) = (cols[0], cols[1], cols[2], cols[3]);
                let total = blocks as f64 * frsize as f64;
                let avail_to_root = bfree as f64 * frsize as f64;
                let avail_to_user = bavail as f64 * frsize as f64;
                let used = total - avail_to_root;
                let total_user = used + avail_to_user;
                let percent = if total_user > 0.0 {
                    py_round(used / total_user * 100.0, 1)
                } else {
                    0.0
                };
                return (percent, avail_to_user);
            }
        }
    }

    use sysinfo::Disks;
    let Ok(disks) = Disks::new_with_refreshed_list() else {
        return (0.0, 0.0);
    };
    match disks
        .iter()
        .find(|d| d.mount_point().to_string_lossy() == "/")
    {
        Some(d) => {
            let total = d.total_space() as f64;
            let free = d.available_space() as f64;
            let percent = if total > 0.0 {
                py_round((total - free) / total * 100.0, 1)
            } else {
                0.0
            };
            (percent, free)
        }
        None => (0.0, 0.0),
    }
}

/// `round(x, digits)` do Python (`usage_percent(..., round_=1)` do psutil).
fn py_round(value: f64, digits: i32) -> f64 {
    let factor = 10f64.powi(digits);
    (value * factor).round() / factor
}

/// `class PerformanceMonitor:` — monitor de performance com alocação
/// automática de recursos.
pub struct PerformanceMonitor {
    /// Declarado no `__init__` do Python e nunca escrito/lido no módulo.
    pub performance_metrics: Mutex<Value>,
    pub resource_thresholds: Value,
    pub optimization_rules: Value,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            performance_metrics: Mutex::new(json!({})),
            resource_thresholds: json!({
                "cpu_high": 80.0,
                "memory_high": 85.0,
                "disk_high": 90.0,
                "network_high": 80.0,
            }),
            optimization_rules: json!({
                "high_cpu": {
                    "reduce_threads": 0.5,
                    "increase_delay": 2.0,
                    "enable_nice": true,
                },
                "high_memory": {
                    "reduce_batch_size": 0.6,
                    "enable_streaming": true,
                    "clear_cache": true,
                },
                "high_disk": {
                    "reduce_output_verbosity": true,
                    "enable_compression": true,
                    "cleanup_temp_files": true,
                },
                "high_network": {
                    "reduce_concurrent_connections": 0.7,
                    "increase_timeout": 1.5,
                    "enable_connection_pooling": true,
                },
            }),
        }
    }

    /// `self.resource_thresholds[key]`
    fn threshold(&self, key: &str) -> f64 {
        self.resource_thresholds
            .get(key)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    }

    /// `self.optimization_rules[group][key]`
    fn rule(&self, group: &str, key: &str) -> f64 {
        self.optimization_rules
            .get(group)
            .and_then(|g| g.get(key))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    }

    /// `monitor_system_resources()` — `psutil` -> `sysinfo`/`/proc`.
    pub fn monitor_system_resources(&self) -> Value {
        let cpu_percent = cpu_percent_interval_1();
        let memory_percent = memory_percent();
        let (disk_percent, _) = disk_usage_root();
        let (bytes_sent, bytes_recv) = net_io_counters();

        json!({
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
            "network_bytes_sent": bytes_sent,
            "network_bytes_recv": bytes_recv,
            "timestamp": now_secs(),
        })
    }

    /// `optimize_based_on_resources(current_params, resource_usage)`
    pub fn optimize_based_on_resources(
        &self,
        current_params: &Map<String, Value>,
        resource_usage: &Value,
    ) -> Value {
        let mut optimized_params = current_params.clone();
        let mut optimizations_applied: Vec<String> = Vec::new();

        // CPU optimization
        if resource_usage.get("cpu_percent").and_then(|v| v.as_f64()).unwrap_or(0.0)
            > self.threshold("cpu_high")
        {
            if let Some(original_threads) = optimized_params.get("threads").cloned() {
                let scaled = (original_threads.as_f64().unwrap_or(0.0)
                    * self.rule("high_cpu", "reduce_threads")) as i64;
                let threads = scaled.max(1);
                optimized_params.insert("threads".to_string(), json!(threads));
                optimizations_applied.push(format!(
                    "Reduced threads from {} to {threads}",
                    py_str(&original_threads)
                ));
            }

            if let Some(original_delay) = optimized_params.get("delay").cloned() {
                let delay =
                    original_delay.as_f64().unwrap_or(0.0) * self.rule("high_cpu", "increase_delay");
                optimized_params.insert("delay".to_string(), json!(delay));
                optimizations_applied.push(format!("Increased delay to {}", py_float(delay)));
            }
        }

        // Memory optimization
        if resource_usage
            .get("memory_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
            > self.threshold("memory_high")
        {
            if let Some(original_batch) = optimized_params.get("batch_size").cloned() {
                let scaled = (original_batch.as_f64().unwrap_or(0.0)
                    * self.rule("high_memory", "reduce_batch_size")) as i64;
                let batch_size = scaled.max(1);
                optimized_params.insert("batch_size".to_string(), json!(batch_size));
                optimizations_applied.push(format!(
                    "Reduced batch size from {} to {batch_size}",
                    py_str(&original_batch)
                ));
            }
        }

        // Network optimization
        if resource_usage.get("network_bytes_sent").is_some() {
            // Simple heuristic for high network usage
            if resource_usage
                .get("network_bytes_sent")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                > 1000000.0
            {
                if let Some(original_conn) = optimized_params.get("concurrent_connections").cloned()
                {
                    let scaled = (original_conn.as_f64().unwrap_or(0.0)
                        * self.rule("high_network", "reduce_concurrent_connections"))
                        as i64;
                    let concurrent_connections = scaled.max(1);
                    optimized_params
                        .insert("concurrent_connections".to_string(), json!(concurrent_connections));
                    optimizations_applied.push(format!(
                        "Reduced concurrent connections to {concurrent_connections}"
                    ));
                }
            }
        }

        optimized_params.insert(
            "_optimizations_applied".to_string(),
            Value::Array(optimizations_applied.into_iter().map(Value::String).collect()),
        );
        Value::Object(optimized_params)
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// `class ParameterOptimizer:` — otimização de parâmetros sensível a contexto.
pub struct ParameterOptimizer {
    pub tech_detector: TechnologyDetector,
    pub rate_limiter: RateLimitDetector,
    pub failure_recovery: FailureRecoverySystem,
    pub performance_monitor: PerformanceMonitor,
    pub optimization_profiles: Value,
}

impl ParameterOptimizer {
    pub fn new() -> Self {
        Self {
            tech_detector: TechnologyDetector::new(),
            rate_limiter: RateLimitDetector::new(),
            failure_recovery: FailureRecoverySystem::new(),
            performance_monitor: PerformanceMonitor::new(),
            optimization_profiles: json!({
                "nmap": {
                    "stealth": {
                        "scan_type": "-sS",
                        "timing": "-T2",
                        "additional_args": "--max-retries 1 --host-timeout 300s",
                    },
                    "normal": {
                        "scan_type": "-sS -sV",
                        "timing": "-T4",
                        "additional_args": "--max-retries 2",
                    },
                    "aggressive": {
                        "scan_type": "-sS -sV -sC -O",
                        "timing": "-T5",
                        "additional_args": "--max-retries 3 --min-rate 1000",
                    },
                },
                "gobuster": {
                    "stealth": {
                        "threads": 5,
                        "delay": "1s",
                        "timeout": "30s",
                    },
                    "normal": {
                        "threads": 20,
                        "delay": "0s",
                        "timeout": "10s",
                    },
                    "aggressive": {
                        "threads": 50,
                        "delay": "0s",
                        "timeout": "5s",
                    },
                },
                "sqlmap": {
                    "stealth": {
                        "level": 1,
                        "risk": 1,
                        "threads": 1,
                        "delay": 1,
                    },
                    "normal": {
                        "level": 2,
                        "risk": 2,
                        "threads": 5,
                        "delay": 0,
                    },
                    "aggressive": {
                        "level": 3,
                        "risk": 3,
                        "threads": 10,
                        "delay": 0,
                    },
                },
            }),
        }
    }

    /// `optimize_parameters_advanced(tool, target_profile, context=None)`
    ///
    /// BLOQUEADO pelo shard W1: a assinatura recebe
    /// `intelligence/decision_engine.py::TargetProfile` (usa `target` e
    /// `open_ports`), que ainda não existe em `intelligence/decision_engine.rs`.
    pub fn optimize_parameters_advanced(
        &self,
        _tool: &str,
        _target_profile: &Value,
        _context: Option<&Map<String, Value>>,
    ) -> Value {
        todo!("optimize_parameters_advanced: aguarda decision_engine::TargetProfile (shard W1)")
    }

    /// `_get_base_parameters(tool, profile)` — mesma dependência de
    /// `TargetProfile` (`profile.target`).
    fn _get_base_parameters(&self, _tool: &str, _profile: &Value) -> Value {
        todo!("_get_base_parameters: aguarda decision_engine::TargetProfile (shard W1)")
    }

    /// `_apply_technology_optimizations(tool, params, detected_tech)`
    fn _apply_technology_optimizations(
        &self,
        tool: &str,
        params: &Map<String, Value>,
        detected_tech: &Value,
    ) -> Value {
        let mut optimized_params = params.clone();

        /// `x in detected_tech.get(category, [])`
        fn has(detected_tech: &Value, category: &str, item: &str) -> bool {
            detected_tech
                .get(category)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().any(|v| v.as_str() == Some(item)))
                .unwrap_or(false)
        }

        // Web server optimizations
        if has(detected_tech, "web_servers", "apache") {
            if tool == "gobuster" {
                optimized_params.insert(
                    "extensions".to_string(),
                    Value::String("php,html,txt,xml,conf".to_string()),
                );
            } else if tool == "nuclei" {
                let tags = optimized_params
                    .get("tags")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                optimized_params.insert("tags".to_string(), json!(format!("{tags},apache")));
            }
        } else if has(detected_tech, "web_servers", "nginx") {
            if tool == "gobuster" {
                optimized_params.insert(
                    "extensions".to_string(),
                    Value::String("php,html,txt,json,conf".to_string()),
                );
            } else if tool == "nuclei" {
                let tags = optimized_params
                    .get("tags")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                optimized_params.insert("tags".to_string(), json!(format!("{tags},nginx")));
            }
        }

        // CMS optimizations
        if has(detected_tech, "cms", "wordpress") {
            if tool == "gobuster" {
                optimized_params.insert(
                    "extensions".to_string(),
                    Value::String("php,html,txt,xml".to_string()),
                );
                optimized_params.insert(
                    "additional_paths".to_string(),
                    Value::String("/wp-content/,/wp-admin/,/wp-includes/".to_string()),
                );
            } else if tool == "nuclei" {
                let tags = optimized_params
                    .get("tags")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                optimized_params.insert("tags".to_string(), json!(format!("{tags},wordpress")));
            } else if tool == "wpscan" {
                optimized_params
                    .insert("enumerate".to_string(), Value::String("ap,at,cb,dbe".to_string()));
            }
        }

        // Language-specific optimizations
        if has(detected_tech, "languages", "php") {
            if tool == "gobuster" {
                optimized_params.insert(
                    "extensions".to_string(),
                    Value::String("php,php3,php4,php5,phtml,html".to_string()),
                );
            } else if tool == "sqlmap" {
                optimized_params.insert("dbms".to_string(), Value::String("mysql".to_string()));
            }
        } else if has(detected_tech, "languages", "dotnet") {
            if tool == "gobuster" {
                optimized_params.insert(
                    "extensions".to_string(),
                    Value::String("aspx,asp,html,txt".to_string()),
                );
            } else if tool == "sqlmap" {
                optimized_params.insert("dbms".to_string(), Value::String("mssql".to_string()));
            }
        }

        // Security feature adaptations
        let security = detected_tech
            .get("security")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !security.is_empty() {
            // WAF detected - use stealth mode
            let waf = ["cloudflare", "incapsula", "sucuri"]
                .iter()
                .any(|w| security.iter().any(|v| v.as_str() == Some(*w)));
            if waf {
                optimized_params.insert("_stealth_mode".to_string(), Value::Bool(true));
                if tool == "gobuster" {
                    let threads = optimized_params
                        .get("threads")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(20)
                        .min(5);
                    optimized_params.insert("threads".to_string(), json!(threads));
                    optimized_params.insert("delay".to_string(), Value::String("2s".to_string()));
                } else if tool == "sqlmap" {
                    optimized_params.insert("delay".to_string(), json!(2));
                    optimized_params.insert("randomize".to_string(), Value::Bool(true));
                }
            }
        }

        Value::Object(optimized_params)
    }

    /// `_apply_profile_optimizations(tool, params, profile)`
    fn _apply_profile_optimizations(
        &self,
        tool: &str,
        params: &Map<String, Value>,
        profile: &str,
    ) -> Value {
        let Some(tool_profiles) = self.optimization_profiles.get(tool) else {
            return Value::Object(params.clone());
        };

        let profile_settings = tool_profiles
            .get(profile)
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let mut optimized_params = params.clone();

        // Apply profile-specific settings
        for (key, value) in profile_settings {
            optimized_params.insert(key, value);
        }

        // Handle stealth mode flag
        if params
            .get("_stealth_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            && profile != "stealth"
        {
            // Force stealth settings even if different profile requested
            if let Some(stealth_settings) = tool_profiles.get("stealth").and_then(|v| v.as_object()) {
                for (key, value) in stealth_settings {
                    optimized_params.insert(key.clone(), value.clone());
                }
            }
        }

        Value::Object(optimized_params)
    }

    /// `handle_tool_failure(tool, error_output, exit_code, current_params)`
    pub fn handle_tool_failure(
        &self,
        tool: &str,
        error_output: &str,
        exit_code: i64,
        current_params: &Map<String, Value>,
    ) -> Value {
        let failure_analysis = self.failure_recovery.analyze_failure(error_output, exit_code);
        let failure_type = failure_analysis
            .get("failure_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut adjusted_parameters = current_params.clone();
        let mut recovery_actions: Vec<&'static str> = Vec::new();

        // Apply automatic parameter adjustments based on failure type
        if failure_type == "timeout" {
            if let Some(timeout) = adjusted_parameters.get("timeout").and_then(|v| v.as_f64()) {
                let doubled = match adjusted_parameters.get("timeout") {
                    Some(Value::Number(n)) if !n.is_f64() => json!((timeout as i64) * 2),
                    _ => json!(timeout * 2.0),
                };
                adjusted_parameters.insert("timeout".to_string(), doubled);
            }
            if let Some(threads) = adjusted_parameters.get("threads").and_then(|v| v.as_i64()) {
                adjusted_parameters.insert("threads".to_string(), json!(threads.div_euclid(2).max(1)));
            }
            recovery_actions.push("Increased timeout and reduced threads");
        } else if failure_type == "rate_limited" {
            let timing_profile = self
                .rate_limiter
                .adjust_timing(&adjusted_parameters, "stealth");
            if let Some(map) = timing_profile.as_object() {
                for (key, value) in map {
                    adjusted_parameters.insert(key.clone(), value.clone());
                }
            }
            recovery_actions.push("Applied stealth timing profile");
        }

        json!({
            "original_tool": tool,
            "failure_analysis": failure_analysis,
            "recovery_actions": recovery_actions,
            "alternative_tools": failure_analysis.get("alternative_tools").cloned().unwrap_or(json!([])),
            "adjusted_parameters": Value::Object(adjusted_parameters),
        })
    }
}

impl Default for ParameterOptimizer {
    fn default() -> Self {
        Self::new()
    }
}
