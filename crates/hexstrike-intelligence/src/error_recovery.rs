//! Port 1:1 de `hexstrike_server/intelligence/error_recovery.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W2.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    35  class ErrorType
//!    49  class RecoveryAction
//!    60  class ErrorContext:
//!    74  class RecoveryStrategy:
//!    83  class IntelligentErrorHandler:
//!   678  class GracefulDegradation:
//!   906  error_handler = IntelligentErrorHandler()
//!   907  degradation_manager = GracefulDegradation()
//! ```
//!
//! Modelagem: as classes viram `struct`/`enum` com o MESMO nome e os membros
//! dos enums mantêm o SCREAMING_CASE do Python (`ErrorType.TIMEOUT`). Os dois
//! singletons do módulo viram `static` com o MESMO nome, atrás de `Mutex`
//! porque o `error_history` é mutável (`_add_to_history`), igual a
//! `_state::cache` / `_state::telemetry`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};
use sysinfo::{Disks, ProcessesToUpdate, System};
use time::OffsetDateTime;
use tracing::{error, info, warn};

use hexstrike_core::visual_engine::ModernVisualEngine;
use crate::vuln_intel::iso_now;

/// `ErrorType(Enum)` — enumeração dos tipos de erro.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorType {
    TIMEOUT,
    PERMISSION_DENIED,
    NETWORK_UNREACHABLE,
    RATE_LIMITED,
    TOOL_NOT_FOUND,
    INVALID_PARAMETERS,
    RESOURCE_EXHAUSTED,
    AUTHENTICATION_FAILED,
    TARGET_UNREACHABLE,
    PARSING_ERROR,
    UNKNOWN,
}

impl ErrorType {
    /// `.value` do enum Python.
    pub fn value(self) -> &'static str {
        match self {
            Self::TIMEOUT => "timeout",
            Self::PERMISSION_DENIED => "permission_denied",
            Self::NETWORK_UNREACHABLE => "network_unreachable",
            Self::RATE_LIMITED => "rate_limited",
            Self::TOOL_NOT_FOUND => "tool_not_found",
            Self::INVALID_PARAMETERS => "invalid_parameters",
            Self::RESOURCE_EXHAUSTED => "resource_exhausted",
            Self::AUTHENTICATION_FAILED => "authentication_failed",
            Self::TARGET_UNREACHABLE => "target_unreachable",
            Self::PARSING_ERROR => "parsing_error",
            Self::UNKNOWN => "unknown",
        }
    }

    /// `ErrorType(valor)` do Python: `None` é o `ValueError` que a rota
    /// `/api/error-handling/parameter-adjustments` traduz em HTTP 400.
    pub fn from_value(value: &str) -> Option<Self> {
        match value {
            "timeout" => Some(Self::TIMEOUT),
            "permission_denied" => Some(Self::PERMISSION_DENIED),
            "network_unreachable" => Some(Self::NETWORK_UNREACHABLE),
            "rate_limited" => Some(Self::RATE_LIMITED),
            "tool_not_found" => Some(Self::TOOL_NOT_FOUND),
            "invalid_parameters" => Some(Self::INVALID_PARAMETERS),
            "resource_exhausted" => Some(Self::RESOURCE_EXHAUSTED),
            "authentication_failed" => Some(Self::AUTHENTICATION_FAILED),
            "target_unreachable" => Some(Self::TARGET_UNREACHABLE),
            "parsing_error" => Some(Self::PARSING_ERROR),
            "unknown" => Some(Self::UNKNOWN),
            _ => None,
        }
    }
}

/// `RecoveryAction(Enum)` — tipos de ação de recuperação.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryAction {
    RETRY_WITH_BACKOFF,
    RETRY_WITH_REDUCED_SCOPE,
    SWITCH_TO_ALTERNATIVE_TOOL,
    ADJUST_PARAMETERS,
    ESCALATE_TO_HUMAN,
    GRACEFUL_DEGRADATION,
    ABORT_OPERATION,
}

impl RecoveryAction {
    /// `.value` do enum Python.
    pub fn value(self) -> &'static str {
        match self {
            Self::RETRY_WITH_BACKOFF => "retry_with_backoff",
            Self::RETRY_WITH_REDUCED_SCOPE => "retry_with_reduced_scope",
            Self::SWITCH_TO_ALTERNATIVE_TOOL => "switch_to_alternative_tool",
            Self::ADJUST_PARAMETERS => "adjust_parameters",
            Self::ESCALATE_TO_HUMAN => "escalate_to_human",
            Self::GRACEFUL_DEGRADATION => "graceful_degradation",
            Self::ABORT_OPERATION => "abort_operation",
        }
    }
}

/// Equivalente do argumento `exception: Exception` do Python: as quatro
/// classes que `classify_error` testa com `isinstance` (`TimeoutError`,
/// `PermissionError`, `ConnectionError`, `FileNotFoundError`) mais o
/// `Exception(msg)` genérico usado por `exploit_gen.execute_command_with_recovery`.
#[derive(Debug, Clone)]
pub enum Exception {
    TimeoutError(String),
    PermissionError(String),
    ConnectionError(String),
    FileNotFoundError(String),
    Exception(String),
}

impl Exception {
    /// `str(exception)`.
    pub fn message(&self) -> &str {
        match self {
            Self::TimeoutError(m)
            | Self::PermissionError(m)
            | Self::ConnectionError(m)
            | Self::FileNotFoundError(m)
            | Self::Exception(m) => m,
        }
    }
}

/// `@dataclass ErrorContext` — contexto para as decisões de recuperação.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub tool_name: String,
    pub target: String,
    /// `Dict[str, Any]`
    pub parameters: Value,
    pub error_type: ErrorType,
    pub error_message: String,
    pub attempt_count: usize,
    pub timestamp: OffsetDateTime,
    pub stack_trace: String,
    /// `Dict[str, Any]`
    pub system_resources: Value,
    /// `previous_errors: List['ErrorContext'] = field(default_factory=list)`
    pub previous_errors: Vec<ErrorContext>,
}

/// `@dataclass RecoveryStrategy` — estratégia de recuperação configurada.
#[derive(Debug, Clone)]
pub struct RecoveryStrategy {
    pub action: RecoveryAction,
    /// `Dict[str, Any]`
    pub parameters: Value,
    pub max_attempts: usize,
    pub backoff_multiplier: f64,
    pub success_probability: f64,
    /// segundos
    pub estimated_time: u32,
}

impl RecoveryStrategy {
    /// Construtor na ordem dos campos do dataclass (nada de `..Default`).
    fn new(
        action: RecoveryAction,
        parameters: Value,
        max_attempts: usize,
        backoff_multiplier: f64,
        success_probability: f64,
        estimated_time: u32,
    ) -> Self {
        Self { action, parameters, max_attempts, backoff_multiplier, success_probability, estimated_time }
    }
}

/// `class IntelligentErrorHandler` — tratamento de erro com recuperação
/// automática.
pub struct IntelligentErrorHandler {
    /// `error_patterns: Dict[str, ErrorType]`. A ordem do dict Python é
    /// significativa: `classify_error` devolve o PRIMEIRO padrão que casa.
    pub error_patterns: Vec<(Regex, ErrorType)>,
    pub recovery_strategies: HashMap<ErrorType, Vec<RecoveryStrategy>>,
    pub tool_alternatives: HashMap<&'static str, &'static [&'static str]>,
    /// `Dict[str, Dict[ErrorType, Dict[str, Any]]]`
    pub parameter_adjustments: HashMap<&'static str, Vec<(ErrorType, Value)>>,
    pub error_history: Vec<ErrorContext>,
    pub max_history_size: usize,
}

impl Default for IntelligentErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl IntelligentErrorHandler {
    /// `__init__`
    pub fn new() -> Self {
        Self {
            error_patterns: Self::_initialize_error_patterns(),
            recovery_strategies: Self::_initialize_recovery_strategies(),
            tool_alternatives: Self::_initialize_tool_alternatives(),
            parameter_adjustments: Self::_initialize_parameter_adjustments(),
            error_history: Vec::new(),
            max_history_size: 1000,
        }
    }

    /// `_initialize_error_patterns` — `re.IGNORECASE` + `re.search` viram
    /// `(?i)` + `is_match` (busca em qualquer posição).
    fn _initialize_error_patterns() -> Vec<(Regex, ErrorType)> {
        [
            // Timeout patterns
            (r"timeout|timed out|connection timeout|read timeout", ErrorType::TIMEOUT),
            (r"operation timed out|command timeout", ErrorType::TIMEOUT),
            // Permission patterns
            (r"permission denied|access denied|forbidden|not authorized", ErrorType::PERMISSION_DENIED),
            (r"sudo required|root required|insufficient privileges", ErrorType::PERMISSION_DENIED),
            // Network patterns
            (r"network unreachable|host unreachable|no route to host", ErrorType::NETWORK_UNREACHABLE),
            (r"connection refused|connection reset|network error", ErrorType::NETWORK_UNREACHABLE),
            // Rate limiting patterns
            (r"rate limit|too many requests|throttled|429", ErrorType::RATE_LIMITED),
            (r"request limit exceeded|quota exceeded", ErrorType::RATE_LIMITED),
            // Tool not found patterns
            (r"command not found|no such file or directory|not found", ErrorType::TOOL_NOT_FOUND),
            (r"executable not found|binary not found", ErrorType::TOOL_NOT_FOUND),
            // Parameter patterns
            (r"invalid argument|invalid option|unknown option", ErrorType::INVALID_PARAMETERS),
            (r"bad parameter|invalid parameter|syntax error", ErrorType::INVALID_PARAMETERS),
            // Resource patterns
            (r"out of memory|memory error|disk full|no space left", ErrorType::RESOURCE_EXHAUSTED),
            (r"resource temporarily unavailable|too many open files", ErrorType::RESOURCE_EXHAUSTED),
            // Authentication patterns
            (r"authentication failed|login failed|invalid credentials", ErrorType::AUTHENTICATION_FAILED),
            (r"unauthorized|invalid token|expired token", ErrorType::AUTHENTICATION_FAILED),
            // Target patterns
            (r"target unreachable|target not responding|target down", ErrorType::TARGET_UNREACHABLE),
            (r"host not found|dns resolution failed", ErrorType::TARGET_UNREACHABLE),
            // Parsing patterns
            (r"parse error|parsing failed|invalid format|malformed", ErrorType::PARSING_ERROR),
            (r"json decode error|xml parse error|invalid json", ErrorType::PARSING_ERROR),
        ]
        .into_iter()
        .map(|(pattern, error_type)| {
            let regex = Regex::new(&format!("(?i){pattern}"))
                .expect("error_patterns: regex invalida no monólito");
            (regex, error_type)
        })
        .collect()
    }

    /// `_initialize_recovery_strategies`
    fn _initialize_recovery_strategies() -> HashMap<ErrorType, Vec<RecoveryStrategy>> {
        use ErrorType::*;
        use RecoveryAction::*;
        let strategies: Vec<(ErrorType, Vec<RecoveryStrategy>)> = vec![
            (
                TIMEOUT,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 5, "max_delay": 60}),
                        3,
                        2.0,
                        0.7,
                        30,
                    ),
                    RecoveryStrategy::new(
                        RETRY_WITH_REDUCED_SCOPE,
                        json!({"reduce_threads": true, "reduce_timeout": true}),
                        2,
                        1.0,
                        0.8,
                        45,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"prefer_faster_tools": true}),
                        1,
                        1.0,
                        0.6,
                        60,
                    ),
                ],
            ),
            (
                PERMISSION_DENIED,
                vec![
                    RecoveryStrategy::new(
                        ESCALATE_TO_HUMAN,
                        json!({"message": "Privilege escalation required", "urgency": "medium"}),
                        1,
                        1.0,
                        0.9,
                        300,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"require_no_privileges": true}),
                        1,
                        1.0,
                        0.5,
                        30,
                    ),
                ],
            ),
            (
                NETWORK_UNREACHABLE,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 10, "max_delay": 120}),
                        3,
                        2.0,
                        0.6,
                        60,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"prefer_offline_tools": true}),
                        1,
                        1.0,
                        0.4,
                        30,
                    ),
                ],
            ),
            (
                RATE_LIMITED,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 30, "max_delay": 300}),
                        5,
                        1.5,
                        0.9,
                        180,
                    ),
                    RecoveryStrategy::new(
                        ADJUST_PARAMETERS,
                        json!({"reduce_rate": true, "increase_delays": true}),
                        2,
                        1.0,
                        0.8,
                        120,
                    ),
                ],
            ),
            (
                TOOL_NOT_FOUND,
                vec![
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"find_equivalent": true}),
                        1,
                        1.0,
                        0.7,
                        15,
                    ),
                    RecoveryStrategy::new(
                        ESCALATE_TO_HUMAN,
                        json!({"message": "Tool installation required", "urgency": "low"}),
                        1,
                        1.0,
                        0.9,
                        600,
                    ),
                ],
            ),
            (
                INVALID_PARAMETERS,
                vec![
                    RecoveryStrategy::new(
                        ADJUST_PARAMETERS,
                        json!({"use_defaults": true, "remove_invalid": true}),
                        3,
                        1.0,
                        0.8,
                        10,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"simpler_interface": true}),
                        1,
                        1.0,
                        0.6,
                        30,
                    ),
                ],
            ),
            (
                RESOURCE_EXHAUSTED,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_REDUCED_SCOPE,
                        json!({"reduce_memory": true, "reduce_threads": true}),
                        2,
                        1.0,
                        0.7,
                        60,
                    ),
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 60, "max_delay": 300}),
                        2,
                        2.0,
                        0.5,
                        180,
                    ),
                ],
            ),
            (
                AUTHENTICATION_FAILED,
                vec![
                    RecoveryStrategy::new(
                        ESCALATE_TO_HUMAN,
                        json!({"message": "Authentication credentials required", "urgency": "high"}),
                        1,
                        1.0,
                        0.9,
                        300,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"no_auth_required": true}),
                        1,
                        1.0,
                        0.4,
                        30,
                    ),
                ],
            ),
            (
                TARGET_UNREACHABLE,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 15, "max_delay": 180}),
                        3,
                        2.0,
                        0.6,
                        90,
                    ),
                    RecoveryStrategy::new(
                        GRACEFUL_DEGRADATION,
                        json!({"skip_target": true, "continue_with_others": true}),
                        1,
                        1.0,
                        1.0,
                        5,
                    ),
                ],
            ),
            (
                PARSING_ERROR,
                vec![
                    RecoveryStrategy::new(
                        ADJUST_PARAMETERS,
                        json!({"change_output_format": true, "add_parsing_flags": true}),
                        2,
                        1.0,
                        0.7,
                        20,
                    ),
                    RecoveryStrategy::new(
                        SWITCH_TO_ALTERNATIVE_TOOL,
                        json!({"better_output_format": true}),
                        1,
                        1.0,
                        0.6,
                        30,
                    ),
                ],
            ),
            (
                UNKNOWN,
                vec![
                    RecoveryStrategy::new(
                        RETRY_WITH_BACKOFF,
                        json!({"initial_delay": 5, "max_delay": 30}),
                        2,
                        2.0,
                        0.3,
                        45,
                    ),
                    RecoveryStrategy::new(
                        ESCALATE_TO_HUMAN,
                        json!({"message": "Unknown error encountered", "urgency": "medium"}),
                        1,
                        1.0,
                        0.9,
                        300,
                    ),
                ],
            ),
        ];
        strategies.into_iter().collect()
    }

    /// `_initialize_tool_alternatives`
    fn _initialize_tool_alternatives() -> HashMap<&'static str, &'static [&'static str]> {
        [
            // Network scanning alternatives
            ("nmap", &["rustscan", "masscan", "zmap"][..]),
            ("rustscan", &["nmap", "masscan"][..]),
            ("masscan", &["nmap", "rustscan", "zmap"][..]),
            // Directory/file discovery alternatives
            ("gobuster", &["feroxbuster", "dirsearch", "ffuf", "dirb"][..]),
            ("feroxbuster", &["gobuster", "dirsearch", "ffuf"][..]),
            ("dirsearch", &["gobuster", "feroxbuster", "ffuf"][..]),
            ("ffuf", &["gobuster", "feroxbuster", "dirsearch"][..]),
            // Vulnerability scanning alternatives
            ("nuclei", &["jaeles", "nikto", "w3af"][..]),
            ("jaeles", &["nuclei", "nikto"][..]),
            ("nikto", &["nuclei", "jaeles", "w3af"][..]),
            // Web crawling alternatives
            ("katana", &["gau", "waybackurls", "hakrawler"][..]),
            ("gau", &["katana", "waybackurls", "hakrawler"][..]),
            ("waybackurls", &["gau", "katana", "hakrawler"][..]),
            // Parameter discovery alternatives
            ("arjun", &["paramspider", "x8", "ffuf"][..]),
            ("paramspider", &["arjun", "x8"][..]),
            ("x8", &["arjun", "paramspider"][..]),
            // SQL injection alternatives
            ("sqlmap", &["sqlninja", "jsql-injection"][..]),
            // XSS testing alternatives
            ("dalfox", &["xsser", "xsstrike"][..]),
            // Subdomain enumeration alternatives
            ("subfinder", &["amass", "assetfinder", "findomain"][..]),
            ("amass", &["subfinder", "assetfinder", "findomain"][..]),
            ("assetfinder", &["subfinder", "amass", "findomain"][..]),
            // Cloud security alternatives
            ("prowler", &["scout-suite", "cloudmapper"][..]),
            ("scout-suite", &["prowler", "cloudmapper"][..]),
            // Container security alternatives
            ("trivy", &["clair", "docker-bench-security"][..]),
            ("clair", &["trivy", "docker-bench-security"][..]),
            // Binary analysis alternatives
            ("ghidra", &["radare2", "ida", "binary-ninja"][..]),
            ("radare2", &["ghidra", "objdump", "gdb"][..]),
            ("gdb", &["radare2", "lldb"][..]),
            // Exploitation alternatives
            ("pwntools", &["ropper", "ropgadget"][..]),
            ("ropper", &["ropgadget", "pwntools"][..]),
            ("ropgadget", &["ropper", "pwntools"][..]),
        ]
        .into_iter()
        .collect()
    }

    /// `_initialize_parameter_adjustments`
    fn _initialize_parameter_adjustments() -> HashMap<&'static str, Vec<(ErrorType, Value)>> {
        use ErrorType::*;
        [
            (
                "nmap",
                vec![
                    (TIMEOUT, json!({"timing": "-T2", "reduce_ports": true})),
                    (RATE_LIMITED, json!({"timing": "-T1", "delay": "1000ms"})),
                    (RESOURCE_EXHAUSTED, json!({"max_parallelism": "10"})),
                ],
            ),
            (
                "gobuster",
                vec![
                    (TIMEOUT, json!({"threads": "10", "timeout": "30s"})),
                    (RATE_LIMITED, json!({"threads": "5", "delay": "1s"})),
                    (RESOURCE_EXHAUSTED, json!({"threads": "5"})),
                ],
            ),
            (
                "nuclei",
                vec![
                    (TIMEOUT, json!({"concurrency": "10", "timeout": "30"})),
                    (RATE_LIMITED, json!({"rate-limit": "10", "concurrency": "5"})),
                    (RESOURCE_EXHAUSTED, json!({"concurrency": "5"})),
                ],
            ),
            (
                "feroxbuster",
                vec![
                    (TIMEOUT, json!({"threads": "10", "timeout": "30"})),
                    (RATE_LIMITED, json!({"threads": "5", "rate-limit": "10"})),
                    (RESOURCE_EXHAUSTED, json!({"threads": "5"})),
                ],
            ),
            (
                "ffuf",
                vec![
                    (TIMEOUT, json!({"threads": "10", "timeout": "30"})),
                    (RATE_LIMITED, json!({"threads": "5", "rate": "10"})),
                    (RESOURCE_EXHAUSTED, json!({"threads": "5"})),
                ],
            ),
        ]
        .into_iter()
        .collect()
    }

    /// `classify_error(error_message, exception=None)`
    pub fn classify_error(&self, error_message: &str, exception: Option<&Exception>) -> ErrorType {
        let error_text = error_message.to_lowercase();

        // Check exception type first
        if let Some(exception) = exception {
            match exception {
                Exception::TimeoutError(_) => return ErrorType::TIMEOUT,
                Exception::PermissionError(_) => return ErrorType::PERMISSION_DENIED,
                Exception::ConnectionError(_) => return ErrorType::NETWORK_UNREACHABLE,
                Exception::FileNotFoundError(_) => return ErrorType::TOOL_NOT_FOUND,
                Exception::Exception(_) => {}
            }
        }

        // Check error patterns
        for (pattern, error_type) in &self.error_patterns {
            if pattern.is_match(&error_text) {
                return *error_type;
            }
        }

        ErrorType::UNKNOWN
    }

    /// `handle_tool_failure(tool, error, context)` — ponto de entrada de
    /// `exploit_gen.execute_command_with_recovery` e das rotas
    /// `/api/error-handling/test-recovery`.
    pub fn handle_tool_failure(
        &mut self,
        tool: &str,
        error: &Exception,
        context: &Value,
    ) -> RecoveryStrategy {
        let error_message = error.message().to_string();
        let error_type = self.classify_error(&error_message, Some(error));

        // Create error context
        let error_context = ErrorContext {
            tool_name: tool.to_string(),
            target: context
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            parameters: context.get("parameters").cloned().unwrap_or_else(|| json!({})),
            error_type,
            error_message: error_message.clone(),
            attempt_count: context
                .get("attempt_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as usize,
            timestamp: now_local(),
            // `traceback.format_exc()` fora de um `except` devolve
            // exatamente esta string.
            stack_trace: "NoneType: None\n".to_string(),
            system_resources: self._get_system_resources(),
            previous_errors: Vec::new(),
        };

        // Add to error history
        self._add_to_history(error_context.clone());

        // Get recovery strategies for this error type
        let strategies = self
            .recovery_strategies
            .get(&error_type)
            .cloned()
            .unwrap_or_else(|| {
                self.recovery_strategies
                    .get(&ErrorType::UNKNOWN)
                    .cloned()
                    .unwrap_or_default()
            });

        // Select best strategy based on context
        let best_strategy = self._select_best_strategy(&strategies, &error_context);

        let error_message =
            format!("{} - Applying {}", error_type.value(), best_strategy.action.value());
        warn!(
            "{}",
            ModernVisualEngine::format_error_card("RECOVERY", tool, &error_message, "")
        );

        best_strategy
    }

    /// `_select_best_strategy(strategies, context)`
    fn _select_best_strategy(
        &self,
        strategies: &[RecoveryStrategy],
        context: &ErrorContext,
    ) -> RecoveryStrategy {
        // Filter strategies based on attempt count
        let viable_strategies: Vec<&RecoveryStrategy> = strategies
            .iter()
            .filter(|s| context.attempt_count <= s.max_attempts)
            .collect();

        if viable_strategies.is_empty() {
            // If all strategies exhausted, escalate to human
            return RecoveryStrategy::new(
                RecoveryAction::ESCALATE_TO_HUMAN,
                json!({
                    "message": format!("All recovery strategies exhausted for {}", context.tool_name),
                    "urgency": "high",
                }),
                1,
                1.0,
                0.9,
                300,
            );
        }

        // Score strategies based on success probability and estimated time
        let mut scored_strategies: Vec<(f64, &RecoveryStrategy)> = viable_strategies
            .into_iter()
            .map(|strategy| {
                // Adjust success probability based on previous failures
                let adjusted_probability = strategy.success_probability
                    * 0.9_f64.powi(context.attempt_count as i32 - 1);

                // Prefer strategies with higher success probability and lower time
                let score = adjusted_probability - (strategy.estimated_time as f64 / 1000.0);
                (score, strategy)
            })
            .collect();

        // Return strategy with highest score (sort estável, como o `reverse=True`)
        scored_strategies.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored_strategies[0].1.clone()
    }

    /// `auto_adjust_parameters(tool, error_type, original_params)`
    pub fn auto_adjust_parameters(
        &self,
        tool: &str,
        error_type: ErrorType,
        original_params: &Value,
    ) -> Value {
        let mut adjustments = self
            .parameter_adjustments
            .get(tool)
            .and_then(|table| table.iter().find(|(t, _)| *t == error_type))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| json!({}));

        if !py_truthy(&adjustments) {
            // Generic adjustments based on error type
            adjustments = match error_type {
                ErrorType::TIMEOUT => json!({"timeout": "60", "threads": "5"}),
                ErrorType::RATE_LIMITED => json!({"delay": "2s", "threads": "3"}),
                ErrorType::RESOURCE_EXHAUSTED => json!({"threads": "3", "memory_limit": "1G"}),
                _ => adjustments,
            };
        }

        // Apply adjustments to original parameters
        let mut adjusted_params: Map<String, Value> = original_params
            .as_object()
            .cloned()
            .unwrap_or_default();
        if let Some(adjustments) = adjustments.as_object() {
            for (key, value) in adjustments {
                adjusted_params.insert(key.clone(), value.clone());
            }
        }

        let adjustment_info = format!("Parameters adjusted: {}", py_repr(&adjustments));
        info!(
            "{}",
            ModernVisualEngine::format_tool_status(tool, "RECOVERY", &adjustment_info, 0.0)
        );

        Value::Object(adjusted_params)
    }

    /// `get_alternative_tool(failed_tool, context)`
    pub fn get_alternative_tool(
        &self,
        failed_tool: &str,
        context: &Value,
    ) -> Option<&'static str> {
        let alternatives = self.tool_alternatives.get(failed_tool)?;

        if alternatives.is_empty() {
            return None;
        }

        // Filter alternatives based on context requirements
        let mut filtered_alternatives: Vec<&'static str> = Vec::new();
        for alt in *alternatives {
            if py_truthy(context.get("require_no_privileges").unwrap_or(&Value::Null))
                && ["nmap", "masscan"].contains(alt)
            {
                continue; // Skip tools that typically require privileges
            }
            if py_truthy(context.get("prefer_faster_tools").unwrap_or(&Value::Null))
                && ["amass", "w3af"].contains(alt)
            {
                continue; // Skip slower tools
            }
            filtered_alternatives.push(alt);
        }

        // Return first available alternative (ordem do Python preservada;
        // se o filtro esvaziar a lista, vale a lista original)
        filtered_alternatives
            .first()
            .or_else(|| alternatives.first())
            .copied()
    }

    /// `escalate_to_human(context, urgency="medium")`
    pub fn escalate_to_human(&self, context: &ErrorContext, urgency: &str) -> Value {
        let escalation_data = json!({
            "timestamp": py_isoformat(context.timestamp),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value(),
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self._get_human_suggestions(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": context
                    .previous_errors
                    .iter()
                    .rev()
                    .take(5)
                    .rev()
                    .map(|e| e.error_message.clone())
                    .collect::<Vec<String>>(),
            },
        });

        // Log escalation with enhanced formatting
        error!(
            "{}",
            ModernVisualEngine::format_error_card(
                "CRITICAL",
                &context.tool_name,
                &context.error_message,
                "HUMAN ESCALATION REQUIRED"
            )
        );
        error!(
            "{}",
            ModernVisualEngine::format_highlighted_text("ESCALATION DETAILS", "RED")
        );
        error!(
            "{}",
            serde_json::to_string_pretty(&escalation_data).unwrap_or_default()
        );

        escalation_data
    }

    /// `_get_human_suggestions(context)`
    fn _get_human_suggestions(&self, context: &ErrorContext) -> Vec<String> {
        let mut suggestions: Vec<String> = Vec::new();

        match context.error_type {
            ErrorType::PERMISSION_DENIED => suggestions.extend(
                [
                    "Run the command with sudo privileges",
                    "Check file/directory permissions",
                    "Verify user is in required groups",
                ]
                .map(String::from),
            ),
            ErrorType::TOOL_NOT_FOUND => suggestions.extend(
                [
                    format!("Install {} using package manager", context.tool_name),
                    "Check if tool is in PATH".to_string(),
                    "Verify tool installation".to_string(),
                ],
            ),
            ErrorType::NETWORK_UNREACHABLE => suggestions.extend(
                [
                    "Check network connectivity",
                    "Verify target is accessible",
                    "Check firewall rules",
                ]
                .map(String::from),
            ),
            ErrorType::RATE_LIMITED => suggestions.extend(
                [
                    "Wait before retrying",
                    "Use slower scan rates",
                    "Check API rate limits",
                ]
                .map(String::from),
            ),
            _ => suggestions.push("Review error details and logs".to_string()),
        }

        suggestions
    }

    /// `_get_system_resources()` — psutil vira sysinfo (mesmo mapeamento de
    /// `vuln_intel.TelemetryCollector::get_system_metrics`).
    pub fn _get_system_resources(&self) -> Value {
        // `try/except -> {"error": "Unable to get system resources"}`
        let mut system = match System::new() {
            Ok(system) => system,
            Err(_) => return json!({"error": "Unable to get system resources"}),
        };
        system.refresh_memory();
        system.refresh_cpu_usage();

        let total_memory = system.total_memory() as f64;
        let memory_percent = if total_memory > 0.0 {
            system.used_memory() as f64 / total_memory * 100.0
        } else {
            0.0
        };

        let disk_percent = match Disks::new_with_refreshed_list() {
            Ok(disks) => disks
                .iter()
                .find(|d| d.mount_point().to_string_lossy() == "/")
                .map(|d| {
                    let total = d.total_space() as f64;
                    if total > 0.0 {
                        (total - d.available_space() as f64) / total * 100.0
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0),
            Err(_) => return json!({"error": "Unable to get system resources"}),
        };

        // `os.getloadavg() if hasattr(os, 'getloadavg') else None`
        let load_average = match System::load_average() {
            Ok(load) => json!([load.one, load.five, load.fifteen]),
            Err(_) => Value::Null,
        };

        // `len(psutil.pids())`
        system.refresh_processes(ProcessesToUpdate::All, true);
        let active_processes = system.processes().len();

        json!({
            "cpu_percent": system.global_cpu_usage() as f64,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
            "load_average": load_average,
            "active_processes": active_processes,
        })
    }

    /// `_add_to_history(error_context)`
    fn _add_to_history(&mut self, error_context: ErrorContext) {
        self.error_history.push(error_context);

        // Maintain history size limit
        if self.error_history.len() > self.max_history_size {
            let excess = self.error_history.len() - self.max_history_size;
            self.error_history.drain(..excess);
        }
    }

    /// `get_error_statistics()`
    pub fn get_error_statistics(&self) -> Value {
        if self.error_history.is_empty() {
            return json!({"total_errors": 0});
        }

        let mut error_counts: Map<String, Value> = Map::new();
        let mut tool_errors: Map<String, Value> = Map::new();
        let mut recent_errors: Vec<Value> = Vec::new();

        // Count errors by type and tool
        for error in &self.error_history {
            let error_type = error.error_type.value();
            let tool = error.tool_name.as_str();

            let count = error_counts.get(error_type).and_then(|v| v.as_u64()).unwrap_or(0);
            error_counts.insert(error_type.to_string(), json!(count + 1));

            let count = tool_errors.get(tool).and_then(|v| v.as_u64()).unwrap_or(0);
            tool_errors.insert(tool.to_string(), json!(count + 1));

            // Recent errors (last hour)
            if (now_local() - error.timestamp).as_seconds_f64() < 3600.0 {
                recent_errors.push(json!({
                    "tool": tool,
                    "error_type": error_type,
                    "timestamp": py_isoformat(error.timestamp),
                }));
            }
        }

        json!({
            "total_errors": self.error_history.len(),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": recent_errors.len(),
            // Last 10 recent errors
            "recent_errors": recent_errors[recent_errors.len().saturating_sub(10)..].to_vec(),
        })
    }
}

/// `class GracefulDegradation` — mantém o sistema operando mesmo com
/// falhas parciais de ferramentas.
pub struct GracefulDegradation {
    /// `fallback_chains: Dict[str, List[List[str]]]` — a ordem é significativa
    /// (`available_operations = list(fallback_chains.keys())`).
    pub fallback_chains: Vec<(&'static str, Vec<Vec<&'static str>>)>,
    /// `critical_operations: Set[str]`. O `set` do Python não tem ordem
    /// estável entre processos (PYTHONHASHSEED); aqui vale a ordem de
    /// declaração do literal.
    pub critical_operations: Vec<&'static str>,
}

impl Default for GracefulDegradation {
    fn default() -> Self {
        Self::new()
    }
}

impl GracefulDegradation {
    /// `__init__`
    pub fn new() -> Self {
        Self {
            fallback_chains: Self::_initialize_fallback_chains(),
            critical_operations: Self::_initialize_critical_operations(),
        }
    }

    /// `_initialize_fallback_chains`
    fn _initialize_fallback_chains() -> Vec<(&'static str, Vec<Vec<&'static str>>)> {
        vec![
            (
                "network_discovery",
                vec![
                    vec!["nmap", "rustscan", "masscan"],
                    vec!["rustscan", "nmap"],
                    vec!["ping", "telnet"], // Basic fallback
                ],
            ),
            (
                "web_discovery",
                vec![
                    vec!["gobuster", "feroxbuster", "dirsearch"],
                    vec!["feroxbuster", "ffuf"],
                    vec!["curl", "wget"], // Basic fallback
                ],
            ),
            (
                "vulnerability_scanning",
                vec![
                    vec!["nuclei", "jaeles", "nikto"],
                    vec!["nikto", "w3af"],
                    vec!["curl"], // Basic manual testing
                ],
            ),
            (
                "subdomain_enumeration",
                vec![
                    vec!["subfinder", "amass", "assetfinder"],
                    vec!["amass", "findomain"],
                    vec!["dig", "nslookup"], // Basic DNS tools
                ],
            ),
            (
                "parameter_discovery",
                vec![
                    vec!["arjun", "paramspider", "x8"],
                    vec!["ffuf", "wfuzz"],
                    vec!["manual_testing"], // Manual parameter testing
                ],
            ),
        ]
    }

    /// `_initialize_critical_operations`
    fn _initialize_critical_operations() -> Vec<&'static str> {
        vec![
            "network_discovery",
            "web_discovery",
            "vulnerability_scanning",
            "subdomain_enumeration",
        ]
    }

    /// `create_fallback_chain(operation, failed_tools=None)`
    pub fn create_fallback_chain(&self, operation: &str, failed_tools: &[String]) -> Vec<String> {
        let chains = self
            .fallback_chains
            .iter()
            .find(|(name, _)| *name == operation)
            .map(|(_, chains)| chains)
            .cloned()
            .unwrap_or_default();

        // Find first chain that doesn't contain failed tools
        for chain in &chains {
            let viable_chain: Vec<String> = chain
                .iter()
                .filter(|tool| !failed_tools.iter().any(|failed| failed == *tool))
                .map(|tool| (*tool).to_string())
                .collect();
            if !viable_chain.is_empty() {
                info!("🔄 Fallback chain for {operation}: {}", py_repr(&json!(viable_chain)));
                return viable_chain;
            }
        }

        // If no viable chain found, return basic fallback
        let basic_fallbacks: [(&str, &[&str]); 4] = [
            ("network_discovery", &["ping"]),
            ("web_discovery", &["curl"]),
            ("vulnerability_scanning", &["curl"]),
            ("subdomain_enumeration", &["dig"]),
        ];

        let fallback: Vec<String> = basic_fallbacks
            .iter()
            .find(|(name, _)| *name == operation)
            .map(|(_, tools)| tools.iter().map(|tool| (*tool).to_string()).collect())
            .unwrap_or_else(|| vec!["manual_testing".to_string()]);
        warn!(
            "⚠️  Using basic fallback for {operation}: {}",
            py_repr(&json!(fallback))
        );
        fallback
    }

    /// `handle_partial_failure(operation, partial_results, failed_components)`
    pub fn handle_partial_failure(
        &self,
        operation: &str,
        partial_results: &Value,
        failed_components: &[String],
    ) -> Value {
        let mut enhanced_results: Map<String, Value> = partial_results
            .as_object()
            .cloned()
            .unwrap_or_default();
        enhanced_results.insert(
            "degradation_info".to_string(),
            json!({
                "operation": operation,
                "failed_components": failed_components,
                "partial_success": true,
                "fallback_applied": true,
                "timestamp": iso_now(),
            }),
        );

        let target = partial_results.get("target").cloned().unwrap_or(Value::Null);
        let target = target.as_str().unwrap_or("").to_string();

        // Try to fill gaps based on operation type
        if operation == "network_discovery" && partial_results.get("open_ports").is_none() {
            // Try basic port check if full scan failed
            enhanced_results.insert("open_ports".to_string(), json!(self._basic_port_check(&target)));
        } else if operation == "web_discovery" && partial_results.get("directories").is_none() {
            // Try basic directory check
            enhanced_results.insert(
                "directories".to_string(),
                json!(self._basic_directory_check(&target)),
            );
        } else if operation == "vulnerability_scanning" && partial_results.get("vulnerabilities").is_none() {
            // Provide basic security headers check
            enhanced_results.insert(
                "vulnerabilities".to_string(),
                self._basic_security_check(&target),
            );
        }

        // Add recommendations for manual follow-up
        enhanced_results.insert(
            "manual_recommendations".to_string(),
            json!(self._get_manual_recommendations(operation, failed_components)),
        );

        info!("🛡️  Graceful degradation applied for {operation}");
        Value::Object(enhanced_results)
    }

    /// `_basic_port_check(target)` — `socket.connect_ex` vira
    /// `TcpStream::connect_timeout` (mesmo `settimeout(2)`).
    fn _basic_port_check(&self, target: &str) -> Vec<u16> {
        if target.is_empty() {
            return Vec::new();
        }

        let common_ports: [u16; 11] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
        let mut open_ports: Vec<u16> = Vec::new();

        for port in common_ports {
            let address = format!("{target}:{port}");
            let Ok(mut resolved) = address.to_socket_addrs() else {
                continue;
            };
            // `result = sock.connect_ex((target, port)); if result == 0`
            let reachable = resolved.any(|socket_addr| {
                TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).is_ok()
            });
            if reachable {
                open_ports.push(port);
            }
        }

        open_ports
    }

    /// `_basic_directory_check(target)` — `requests.head(url, timeout=5,
    /// allow_redirects=True)`.
    fn _basic_directory_check(&self, target: &str) -> Vec<String> {
        if target.is_empty() {
            return Vec::new();
        }

        let common_dirs = ["/admin", "/login", "/api", "/wp-admin", "/phpmyadmin", "/robots.txt"];
        let mut found_dirs: Vec<String> = Vec::new();

        for directory in common_dirs {
            let url = format!("{}{}", target.trim_end_matches('/'), directory);
            if let Ok(response) = http_request(&url, "HEAD", Duration::from_secs(5)) {
                if [200, 301, 302, 403].contains(&response.status) {
                    found_dirs.push(directory.to_string());
                }
            }
        }

        found_dirs
    }

    /// `_basic_security_check(target)` — `requests.get(target, timeout=10)`.
    fn _basic_security_check(&self, target: &str) -> Value {
        if target.is_empty() {
            return json!([]);
        }

        let mut vulnerabilities: Vec<Value> = Vec::new();

        match http_request(target, "GET", Duration::from_secs(10)) {
            Ok(response) => {
                let headers: Vec<String> =
                    response.headers.iter().map(|(name, _)| name.to_lowercase()).collect();

                // Check for missing security headers
                let security_headers = [
                    ("X-Frame-Options", "Clickjacking protection missing"),
                    ("X-Content-Type-Options", "MIME type sniffing protection missing"),
                    ("X-XSS-Protection", "XSS protection missing"),
                    ("Strict-Transport-Security", "HTTPS enforcement missing"),
                    ("Content-Security-Policy", "Content Security Policy missing"),
                ];

                for (header, description) in security_headers {
                    // `if header not in headers` (requests compara sem caixa)
                    if !headers.contains(&header.to_lowercase()) {
                        vulnerabilities.push(json!({
                            "type": "missing_security_header",
                            "severity": "medium",
                            "description": description,
                            "header": header,
                        }));
                    }
                }
            }
            Err(e) => vulnerabilities.push(json!({
                "type": "connection_error",
                "severity": "info",
                "description": format!("Could not perform basic security check: {e}"),
            })),
        }

        json!(vulnerabilities)
    }

    /// `_get_manual_recommendations(operation, failed_components)`
    fn _get_manual_recommendations(
        &self,
        operation: &str,
        failed_components: &[String],
    ) -> Vec<String> {
        let mut recommendations: Vec<String> = Vec::new();

        let base_recommendations: [(&str, &[&str]); 4] = [
            (
                "network_discovery",
                &[
                    "Manually test common ports using telnet or nc",
                    "Check for service banners manually",
                    "Use online port scanners as alternative",
                ],
            ),
            (
                "web_discovery",
                &[
                    "Manually browse common directories",
                    "Check robots.txt and sitemap.xml",
                    "Use browser developer tools for endpoint discovery",
                ],
            ),
            (
                "vulnerability_scanning",
                &[
                    "Manually test for common vulnerabilities",
                    "Check security headers using browser tools",
                    "Perform manual input validation testing",
                ],
            ),
            (
                "subdomain_enumeration",
                &[
                    "Use online subdomain discovery tools",
                    "Check certificate transparency logs",
                    "Perform manual DNS queries",
                ],
            ),
        ];

        recommendations.extend(
            base_recommendations
                .iter()
                .find(|(name, _)| *name == operation)
                .map(|(_, lines)| lines.iter().map(|line| (*line).to_string()))
                .into_iter()
                .flatten(),
        );

        // Add specific recommendations based on failed components
        for component in failed_components {
            if component == "nmap" {
                recommendations.push("Consider using online port scanners".to_string());
            } else if component == "gobuster" {
                recommendations.push("Try manual directory browsing".to_string());
            } else if component == "nuclei" {
                recommendations.push("Perform manual vulnerability testing".to_string());
            }
        }

        recommendations
    }

    /// `is_critical_operation(operation)`
    pub fn is_critical_operation(&self, operation: &str) -> bool {
        self.critical_operations.contains(&operation)
    }
}

/// Resposta mínima de `requests.head`/`requests.get`: status e cabeçalhos.
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

/// Cliente HTTP/1.0 mínimo sobre TCP: o crate não carrega cliente HTTP (o
/// Python usa `requests`). Consequências documentadas: `https://` cai no
/// `except Exception` do Python (sem TLS no `std`) e redirecionamentos não são
/// seguidos — `_basic_directory_check` já aceita 301/302 como achado.
fn http_request(url: &str, method: &str, timeout: Duration) -> Result<HttpResponse, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        let scheme = url.split_once("://").map(|(scheme, _)| scheme).unwrap_or("");
        format!("no HTTP client for scheme '{scheme}'")
    })?;

    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let host = authority.split_once(':').map(|(host, _)| host).unwrap_or(authority);
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let socket_addr = address
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("no address for {host}"))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: {authority}\r\nUser-Agent: HexStrike\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;

    let mut raw: Vec<u8> = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let raw = String::from_utf8_lossy(&raw);

    let mut lines = raw.lines();
    let status_line = lines.next().ok_or_else(|| "empty response".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid status line: {status_line}"))?;
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    Ok(HttpResponse { status, headers })
}

/// `repr()` do Python para dicts/listas/escalares — usado só nos logs
/// (`f'Parameters adjusted: {adjustments}'`). Sem `preserve_order` no
/// `serde_json`, a ordem das chaves de um dict sai alfabética.
fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => format!("'{string}'"),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<String>>().join(", ")
        ),
        Value::Object(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(key, item)| format!("'{key}': {}", py_repr(item)))
                .collect::<Vec<String>>()
                .join(", ")
        ),
    }
}

/// Veracidade do Python (`if x:`) sobre um `serde_json::Value`.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|number| number != 0.0).unwrap_or(true),
        Value::String(string) => !string.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(entries) => !entries.is_empty(),
    }
}

/// `datetime.now()` (hora local, como o Python).
fn now_local() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

/// `datetime.isoformat()`.
fn py_isoformat(timestamp: OffsetDateTime) -> String {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]"
    );
    timestamp.format(&format).unwrap_or_default()
}

/// `datetime.now().isoformat()` — mesma função privada de `vuln_intel.rs`
/// (lá ela não é `pub`, então o helper é repetido com o mesmo formato).
/// `pub(crate)` porque as rotas de `error_handling` usam o mesmo
/// `datetime.now().isoformat()` no `timestamp` de cada resposta.

/// `error_handler = IntelligentErrorHandler()`
#[allow(non_upper_case_globals)]
pub static error_handler: LazyLock<Mutex<IntelligentErrorHandler>> =
    LazyLock::new(|| Mutex::new(IntelligentErrorHandler::new()));

/// `degradation_manager = GracefulDegradation()`
#[allow(non_upper_case_globals)]
pub static degradation_manager: LazyLock<Mutex<GracefulDegradation>> =
    LazyLock::new(|| Mutex::new(GracefulDegradation::new()));

