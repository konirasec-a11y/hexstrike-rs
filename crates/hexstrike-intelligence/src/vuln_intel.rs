//! Port 1:1 de `hexstrike_server/intelligence/vuln_intel.py`.
//!
//! Inventário Python (ordem de definição) — o que o `_registry.py` atribui a
//! este módulo, e só isso:
//!
//! ```text
//!    33  class CVEIntelligenceManager
//!   898  class ColoredFormatter
//!   926  def setup_logging
//!   946  DEBUG_MODE = ...
//!   947  COMMAND_TIMEOUT = 300
//!   948  CACHE_SIZE = 1000
//!   949  CACHE_TTL = 3600
//!   951  class HexStrikeCache
//!  1017  cache = HexStrikeCache()
//!  1019  class TelemetryCollector
//!  1064  telemetry = TelemetryCollector()
//!  1066  class EnhancedCommandExecutor
//! ```
//!
//! `execute_command` NÃO mora aqui: é de `exploit_gen.py`. Os globais `cache` e
//! `telemetry` moram em `_state.rs` (o `_state.py` do split) e são reexportados
//! no fim deste arquivo para preservar a superfície do módulo Python.
//!
//! Sem stack TLS nas dependências: `requests.get` é feito pelo `curl(1)` do
//! sistema — mesmo padrão do `kill(1)` usado em [`EnhancedCommandExecutor::execute`].

use hexstrike_core::visual_engine::color;
use linked_hash_map::LinkedHashMap;
use md5::{Digest, Md5};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Disks, System};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
// --- constantes de ambiente (vuln_intel.py) ---
pub const COMMAND_TIMEOUT: u64 = 300;
pub const CACHE_SIZE: usize = 1000;
pub const CACHE_TTL: u64 = 3600;

pub struct HexStrikeCache {
    cache: LinkedHashMap<String, (f64, Value)>,
    max_size: usize,
    ttl: f64,
    stats: Stats,
}

#[derive(Default)]
struct Stats {
    hits: u64,
    misses: u64,
    evictions: u64,
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

impl HexStrikeCache {
    pub fn new(max_size: usize, ttl: u64) -> Self {
        Self {
            cache: LinkedHashMap::new(),
            max_size,
            ttl: ttl as f64,
            stats: Stats::default(),
        }
    }

    /// `_generate_key(command, params)`
    fn generate_key(&self, command: &str, params: &Map<String, Value>) -> String {
        let sorted = json_sorted(params);
        let key_data = format!("{command}:{sorted}");
        let mut hasher = Md5::new();
        hasher.update(key_data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// `_is_expired(timestamp)`
    fn is_expired(&self, timestamp: f64) -> bool {
        now_secs() - timestamp > self.ttl
    }

    /// `get(command, params) -> Optional[Dict]`
    pub fn get(&mut self, command: &str, params: &Map<String, Value>) -> Option<Value> {
        let key = self.generate_key(command, params);

        if let Some((timestamp, data)) = self.cache.get(&key).cloned() {
            if !self.is_expired(timestamp) {
                // Move to end (most recently used)
                self.cache.get_refresh(&key);
                self.stats.hits += 1;
                info!("💾 Cache HIT for command: {command}");
                return Some(data);
            } else {
                // Remove expired entry
                self.cache.remove(&key);
            }
        }

        self.stats.misses += 1;
        info!("🔍 Cache MISS for command: {command}");
        None
    }

    /// `set(command, params, result)`
    pub fn set(&mut self, command: &str, params: &Map<String, Value>, result: Value) {
        let key = self.generate_key(command, params);

        // Remove oldest entries if cache is full
        while self.cache.len() >= self.max_size {
            let oldest_key = self.cache.keys().next().cloned();
            match oldest_key {
                Some(k) => {
                    self.cache.remove(&k);
                    self.stats.evictions += 1;
                }
                None => break,
            }
        }

        self.cache.insert(key, (now_secs(), result));
        info!("💾 Cached result for command: {command}");
    }

    /// `get_stats()` — MESMAS chaves/valores do dict Python
    pub fn get_stats(&self) -> Value {
        let total_requests = self.stats.hits + self.stats.misses;
        let hit_rate =
            if total_requests > 0 { self.stats.hits as f64 / total_requests as f64 * 100.0 } else { 0.0 };

        json!({
            "size": self.cache.len(),
            "max_size": self.max_size,
            "hit_rate": format!("{hit_rate:.1}%"),
            "hits": self.stats.hits,
            "misses": self.stats.misses,
            "evictions": self.stats.evictions,
        })
    }
}

/// Serializa um objeto JSON com chaves ordenadas (equivalente a
/// `json.dumps(params, sort_keys=True)` para geração de chave).
fn json_sorted(v: &Map<String, Value>) -> String {
    let mut keys: Vec<&String> = v.keys().collect();
    keys.sort();
    let inner: Vec<String> =
        keys.iter().map(|k| format!("{:?}:{}", k, json_sorted_value(&v[*k]))).collect();
    format!("{{{}}}", inner.join(","))
}

fn json_sorted_value(v: &Value) -> String {
    match v {
        Value::Object(map) => json_sorted(map),
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(json_sorted_value).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Conveniência: params vazios `{}` (o caso dominante — `cache.get(command, {})`).
pub fn empty_params() -> Map<String, Value> {
    Map::new()
}

/// `len(self.cache)` usado por get_stats — mantido público para o health.
impl HexStrikeCache {
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    pub fn stats_counts(&self) -> HashMap<&'static str, u64> {
        HashMap::from([
            ("hits", self.stats.hits),
            ("misses", self.stats.misses),
            ("evictions", self.stats.evictions),
        ])
    }

    /// `cache.cache.clear()` + `cache.stats = {"hits": 0, "misses": 0,
    /// "evictions": 0}` — rota `/api/cache/clear` (exploit_gen.py:2290).
    pub fn clear(&mut self) {
        self.cache.clear();
        self.stats = Stats::default();
    }
}

pub struct TelemetryCollector {
    commands_executed: u64,
    successful_commands: u64,
    failed_commands: u64,
    total_execution_time: f64,
    start_time: f64,
    system: System,
}

/// Espelho de `psutil.net_io_counters()` (sem `pernic`): soma de todas as
/// interfaces em `/proc/net/dev`. Campos na ordem do namedtuple do psutil.
#[derive(Default)]
struct NetIoCounters {
    bytes_sent: u64,
    bytes_recv: u64,
    packets_sent: u64,
    packets_recv: u64,
    errin: u64,
    errout: u64,
    dropin: u64,
    dropout: u64,
}

fn net_io_counters() -> NetIoCounters {
    let mut acc = NetIoCounters::default();
    let Ok(raw) = std::fs::read_to_string("/proc/net/dev") else {
        return acc;
    };
    for line in raw.lines() {
        // linhas de dados têm o formato "<iface>: <8 colunas rx> <8 colunas tx>"
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
        // rx: bytes packets errs drop | tx: bytes packets errs drop
        acc.bytes_recv += cols[0];
        acc.packets_recv += cols[1];
        acc.errin += cols[2];
        acc.dropin += cols[3];
        acc.bytes_sent += cols[8];
        acc.packets_sent += cols[9];
        acc.errout += cols[10];
        acc.dropout += cols[11];
    }
    acc
}

impl TelemetryCollector {
    pub fn new() -> Self {
        // sysinfo precisa de um refresh inicial para métricas de CPU/memória
        // (em 0.40 os construtores viraram fallible)
        let mut system = System::new().expect("sysinfo: falha ao inicializar System");
        system.refresh_memory();
        system.refresh_cpu_usage();
        Self {
            commands_executed: 0,
            successful_commands: 0,
            failed_commands: 0,
            total_execution_time: 0.0,
            start_time: now_secs(),
            system,
        }
    }

    /// `record_execution(success, execution_time)`
    pub fn record_execution(&mut self, success: bool, execution_time: f64) {
        self.commands_executed += 1;
        if success {
            self.successful_commands += 1;
        } else {
            self.failed_commands += 1;
        }
        self.total_execution_time += execution_time;
    }

    /// `get_system_metrics()` — via sysinfo (psutil em Python)
    pub fn get_system_metrics(&mut self) -> Value {
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        self.system.refresh_cpu_all();

        let total_mem = self.system.total_memory() as f64;
        let used_mem = self.system.used_memory() as f64;
        let memory_percent = if total_mem > 0.0 { used_mem / total_mem * 100.0 } else { 0.0 };

        let cpu_percent = self.system.global_cpu_usage() as f64;

        let disks = Disks::new_with_refreshed_list()
            .expect("sysinfo: falha ao listar discos");
        let disk_usage = disks
            .iter()
            .find(|d| d.mount_point().to_string_lossy() == "/")
            .map(|d| {
                let total = d.total_space() as f64;
                let available = d.available_space() as f64;
                if total > 0.0 { (total - available) / total * 100.0 } else { 0.0 }
            })
            .unwrap_or(0.0);

        let net = net_io_counters();

        json!({
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_usage": disk_usage,
            "network_io": {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
                "errin": net.errin,
                "errout": net.errout,
                "dropin": net.dropin,
                "dropout": net.dropout,
            },
        })
    }

    /// Uptime bruto (usado pela rota /health: `time.time() - telemetry.stats["start_time"]`)
    pub fn uptime_seconds(&self) -> f64 {
        now_secs() - self.start_time
    }

    /// `get_stats()` — MESMAS chaves do dict Python
    pub fn get_stats(&mut self) -> Value {
        let uptime = self.uptime_seconds();
        let success_rate = if self.commands_executed > 0 {
            self.successful_commands as f64 / self.commands_executed as f64 * 100.0
        } else {
            0.0
        };
        let avg_execution_time = if self.commands_executed > 0 {
            self.total_execution_time / self.commands_executed as f64
        } else {
            0.0
        };

        let system_metrics = self.get_system_metrics();

        json!({
            "uptime_seconds": uptime,
            "commands_executed": self.commands_executed,
            "success_rate": format!("{success_rate:.1}%"),
            "average_execution_time": format!("{avg_execution_time:.2}s"),
            "system_metrics": system_metrics,
        })
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Log de telemetria (mantém o logger vivo como no Python, que loga via logger).
pub fn log_telemetry_stats(stats: &Value) {
    info!("📈 Telemetry stats: {stats}");
}

/// Ponto de inversão do ciclo executor -> process_manager detectado no
/// ranking de acoplamento. A camada 4 (process_manager) implementará este
/// trait para receber eventos; até lá, `NoopHook` mantém o comportamento.
pub trait ProgressHook: Send + Sync {
    fn register_process(&self, pid: u32, command: &str);
    fn update_progress(&self, pid: u32, progress: f64, message: &str, bytes_processed: usize);
    fn cleanup_process(&self, pid: u32);
}

/// No-op até a camada 4 (process_manager) ser portada.
pub struct NoopHook;
impl ProgressHook for NoopHook {
    fn register_process(&self, _pid: u32, _command: &str) {}
    fn update_progress(&self, _pid: u32, _progress: f64, _message: &str, _bytes: usize) {}
    fn cleanup_process(&self, _pid: u32) {}
}

/// Timestamp no formato `datetime.now().isoformat()`.
pub fn iso_now() -> String {
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]"
    );
    let now = time::OffsetDateTime::now_local()
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    now.format(&fmt).unwrap_or_default()
}

pub struct EnhancedCommandExecutor {
    command: String,
    timeout: Duration,
    hook: Arc<dyn ProgressHook>,
}

impl EnhancedCommandExecutor {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            timeout: Duration::from_secs(COMMAND_TIMEOUT),
            // `ProcessManager.register_process/update_process_progress/
            // cleanup_process` do Python: o hook real (o trait foi criado para
            // inverter o ciclo executor -> process_manager; com os dois no mesmo
            // crate, o default pode ser o de verdade).
            hook: crate::process_termination::progress_hook(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_hook(mut self, hook: Arc<dyn ProgressHook>) -> Self {
        self.hook = hook;
        self
    }

    /// `execute()` — 1:1, incluindo mensagens de log e shape do resultado.
    pub async fn execute(&self) -> Value {
        let start_time = Instant::now();
        let timeout_secs = self.timeout.as_secs_f64();

        info!("🚀 EXECUTING: {}", self.command);
        info!("⏱️  TIMEOUT: {}s | PID: Starting...", timeout_secs);

        let mut child = match Command::new("/bin/sh")
            .arg("-c")
            .arg(&self.command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                // Variante de erro do except do Python
                let execution_time = start_time.elapsed().as_secs_f64();
                error!("💥 ERROR: Command execution failed: {e}");
                error!("🔍 TRACEBACK: {}", std::backtrace::Backtrace::capture());
                crate::_state::telemetry.lock().unwrap().record_execution(false, execution_time);
                return json!({
                    "stdout": "",
                    "stderr": format!("Error executing command: {e}\n"),
                    "return_code": -1,
                    "success": false,
                    "timed_out": false,
                    "partial_results": false,
                    "execution_time": execution_time,
                    "timestamp": iso_now(),
                });
            }
        };

        let pid = child.id().unwrap_or(0);
        info!("🆔 PROCESS: PID {pid} started");

        // ProcessManager.register_process (v5.0) -> hook (no-op por ora)
        self.hook.register_process(pid, &self.command);

        let stdout_buf = Arc::new(Mutex::new(String::new()));
        let stderr_buf = Arc::new(Mutex::new(String::new()));

        // Threads de leitura contínua (1:1 com _read_stdout/_read_stderr)
        let mut reader_tasks = Vec::new();
        if let Some(out) = child.stdout.take() {
            let buf = stdout_buf.clone();
            reader_tasks.push(tokio::spawn(async move {
                let mut lines = BufReader::new(out).lines();
                // `except Exception as e: logger.error(f"Error reading stdout: {e}")`
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            info!("📤 STDOUT: {line}");
                            let mut b = buf.lock().await;
                            b.push_str(&line);
                            b.push('\n');
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("Error reading stdout: {e}");
                            break;
                        }
                    }
                }
            }));
        }
        if let Some(err) = child.stderr.take() {
            let buf = stderr_buf.clone();
            reader_tasks.push(tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                // `except Exception as e: logger.error(f"Error reading stderr: {e}")`
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            warn!("📥 STDERR: {line}");
                            let mut b = buf.lock().await;
                            b.push_str(&line);
                            b.push('\n');
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("Error reading stderr: {e}");
                            break;
                        }
                    }
                }
            }));
        }

        // _show_progress: só para comandos > 2s, ciclo de 0.8s (1:1)
        let progress_handle = {
            let stdout_buf = stdout_buf.clone();
            let stderr_buf = stderr_buf.clone();
            let hook = self.hook.clone();
            let command_len_timeout = self.timeout;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let progress_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let start = Instant::now();
                let mut i = 0usize;
                loop {
                    let elapsed = start.elapsed().as_secs_f64();
                    let ch = progress_chars[i % progress_chars.len()];
                    let progress_percent = ((elapsed / command_len_timeout.as_secs_f64()) * 100.0).min(99.9);
                    let progress_fraction = progress_percent / 100.0;
                    let eta =
                        if progress_percent > 5.0 { (elapsed / progress_percent) * 100.0 - elapsed } else { 0.0 };
                    let bytes = {
                        let s = stdout_buf.lock().await;
                        let e = stderr_buf.lock().await;
                        s.len() + e.len()
                    };
                    let speed = if elapsed > 0.0 { format!("{:.0} B/s", bytes as f64 / elapsed) } else { "0 B/s".to_string() };

                    hook.update_progress(pid, progress_fraction, &format!("Running for {elapsed:.1}s"), bytes);

                    let bar = hexstrike_core::visual_engine::ModernVisualEngine::render_progress_bar(
                        progress_fraction, 30, "cyber",
                        &format!("⚡ PROGRESS {ch}"), eta, &speed,
                    );
                    info!("{bar} | {elapsed:.1}s | PID: {pid}");
                    tokio::time::sleep(Duration::from_millis(800)).await;
                    i += 1;
                    if elapsed > command_len_timeout.as_secs_f64() {
                        break;
                    }
                }
            })
        };

        // wait(timeout=...) — 1:1
        let wait = tokio::time::timeout(self.timeout, child.wait()).await;
        let return_code: i32;
        let mut timed_out = false;

        match wait {
            Ok(Ok(status)) => {
                return_code = status.code().unwrap_or(-1);
                let execution_time = start_time.elapsed().as_secs_f64();
                for t in reader_tasks.drain(..) {
                    let _ = t.await;
                }
                progress_handle.abort();

                // ProcessManager.cleanup_process (v5.0) -> hook
                self.hook.cleanup_process(pid);

                if return_code == 0 {
                    info!("✅ SUCCESS: Command completed | Exit Code: {return_code} | Duration: {execution_time:.2}s");
                    crate::_state::telemetry.lock().unwrap().record_execution(true, execution_time);
                } else {
                    warn!("⚠️  WARNING: Command completed with errors | Exit Code: {return_code} | Duration: {execution_time:.2}s");
                    crate::_state::telemetry.lock().unwrap().record_execution(false, execution_time);
                }
            }
            Ok(Err(e)) => {
                // erro de espera — tratado como except do Python
                let execution_time = start_time.elapsed().as_secs_f64();
                error!("💥 ERROR: Command execution failed: {e}");
                error!("🔍 TRACEBACK: {}", std::backtrace::Backtrace::capture());
                crate::_state::telemetry.lock().unwrap().record_execution(false, execution_time);
                progress_handle.abort();
                let stdout_data = stdout_buf.lock().await.clone();
                let stderr_data = stderr_buf.lock().await.clone();
                return json!({
                    "stdout": stdout_data,
                    "stderr": format!("Error executing command: {e}\n{stderr_data}"),
                    "return_code": -1,
                    "success": false,
                    "timed_out": false,
                    "partial_results": !stdout_data.is_empty() || !stderr_data.is_empty(),
                    "execution_time": execution_time,
                    "timestamp": iso_now(),
                });
            }
            Err(_elapsed) => {
                // subprocess.TimeoutExpired — 1:1
                let execution_time = start_time.elapsed().as_secs_f64();
                timed_out = true;
                warn!("⏰ TIMEOUT: Command timed out after {timeout_secs}s | Terminating PID {pid}");

                // terminate() = SIGTERM; espera 5s; kill() = SIGKILL
                // (libc 1.0 ainda é alpha; SIGTERM via kill(1) do sistema —
                //  mesmo efeito observável do terminate() do Python)
                let _ = Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;
                match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(_) => {}
                    Err(_) => {
                        error!("🔪 FORCE KILL: Process {pid} not responding to termination");
                        let _ = child.kill().await;
                    }
                }
                return_code = -1;
                crate::_state::telemetry.lock().unwrap().record_execution(false, execution_time);
                for t in reader_tasks.drain(..) {
                    t.abort();
                }
                progress_handle.abort();
            }
        }

        // "Always consider it a success if we have output, even with timeout"
        let stdout_data = stdout_buf.lock().await.clone();
        let stderr_data = stderr_buf.lock().await.clone();
        let execution_time = start_time.elapsed().as_secs_f64();
        let success =
            if timed_out && (!stdout_data.is_empty() || !stderr_data.is_empty()) { true } else { return_code == 0 };

        let output_size = stdout_data.len() + stderr_data.len();

        // Results summary (1:1 com o box do Python)
        let status_icon = if success { "✅" } else { "❌" };
        let status_color = if success { color("MATRIX_GREEN") } else { color("HACKER_RED") };
        let timeout_status =
            if timed_out { format!(" {}[TIMEOUT]{}", color("WARNING"), color("RESET")) } else { String::new() };
        let cmd = hexstrike_core::visual_engine::py_truncate(&self.command, 55);
        let cmd_ellipsis = if self.command.chars().count() > 55 { "..." } else { "" };
        let summary = format!(
            "
{}{}╭─────────────────────────────────────────────────────────────────────────────╮{}
{}│{} {}📊 FINAL RESULTS {status_icon}{}
{}├─────────────────────────────────────────────────────────────────────────────┤{}
{}│{} {}🚀 Command:{} {cmd}{cmd_ellipsis}
{}│{} {}⏱️  Duration:{} {execution_time:.2}s{timeout_status}
{}│{} {}📊 Output Size:{} {output_size} bytes
{}│{} {}🔢 Exit Code:{} {return_code}
{}│{} {}📈 Status:{} {} | Cached: Yes
{}{}╰─────────────────────────────────────────────────────────────────────────────╯{}",
            color("MATRIX_GREEN"), color("BOLD"), color("RESET"),
            color("BOLD"), color("RESET"), status_color, color("RESET"),
            color("BOLD"), color("RESET"),
            color("BOLD"), color("RESET"), color("NEON_BLUE"), color("RESET"),
            color("BOLD"), color("RESET"), color("CYBER_ORANGE"), color("RESET"),
            color("BOLD"), color("RESET"), color("WARNING"), color("RESET"),
            color("BOLD"), color("RESET"), color("ELECTRIC_PURPLE"), color("RESET"),
            color("BOLD"), color("RESET"), status_color, color("RESET"),
            if success { "SUCCESS" } else { "FAILED" },
            color("MATRIX_GREEN"), color("BOLD"), color("RESET"),
        );
        for line in summary.trim().split('\n') {
            if !line.trim().is_empty() {
                info!("{line}");
            }
        }

        json!({
            "stdout": stdout_data,
            "stderr": stderr_data,
            "return_code": return_code,
            "success": success,
            "timed_out": timed_out,
            "partial_results": timed_out && (!stdout_data.is_empty() || !stderr_data.is_empty()),
            "execution_time": execution_time,
            "timestamp": iso_now(),
        })
    }
}

// ============================================================================
// ADVANCED VULNERABILITY INTELLIGENCE SYSTEM (v6.0 ENHANCEMENT)
// ============================================================================

/// `datetime.now()` local (fallback UTC) — a origem dos timestamps do Python.
fn now_local() -> time::OffsetDateTime {
    time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

/// `dt.strftime('%Y-%m-%dT%H:%M:%S.000')`
fn nvd_timestamp(dt: time::OffsetDateTime) -> String {
    let fmt =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].000");
    dt.format(&fmt).unwrap_or_default()
}

/// `round(x, 2)` — mesmo arredondamento (half-to-even) do `round` do Python,
/// que é o do `format`.
fn py_round2(v: f64) -> f64 {
    format!("{v:.2}").parse().unwrap_or(v)
}

/// `f"{x}"` de um float do Python: `0.0` sai `"0.0"`, não `"0"`.
fn py_float(v: f64) -> String {
    if v.is_finite() && v == v.trunc() { format!("{v:.1}") } else { format!("{v}") }
}

/// `str(value)` para os campos que o Python interpola em f-string.
fn py_str(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `obj.get(key, default)` para strings.
fn jget_str(v: &Value, key: &str, default: &str) -> String {
    v.get(key).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| default.to_string())
}

/// `obj.get(key, default)` para números.
fn jget_f64(v: &Value, key: &str, default: f64) -> f64 {
    v.get(key).and_then(Value::as_f64).unwrap_or(default)
}

/// `obj.get(key, 0)` preservando o tipo JSON do número (o harness compara
/// `0` e `0.0` como coisas diferentes).
fn jget_num(v: &Value, key: &str) -> Value {
    v.get(key).filter(|n| n.is_number()).cloned().unwrap_or_else(|| json!(0.0))
}

/// `obj.get(key, [])`
fn jget_arr(v: &Value, key: &str) -> Vec<Value> {
    v.get(key).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Resposta de `requests.get(...)`: código HTTP + corpo cru.
struct Response {
    status_code: i64,
    text: String,
}

impl Response {
    /// `response.json()`
    fn json(&self) -> Result<Value, String> {
        serde_json::from_str(&self.text).map_err(|e| format!("JSON decode error: {e}"))
    }
}

/// `requests.get(url, params=params, timeout=timeout)` via `curl(1)`.
/// `Err` é o equivalente de `requests.exceptions.RequestException`.
async fn requests_get(
    url: &str,
    params: &[(&str, String)],
    timeout_secs: u64,
) -> Result<Response, String> {
    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("-L").arg("--max-time").arg(timeout_secs.to_string()).arg("-G").arg(url);
    for (key, value) in params {
        cmd.arg("--data-urlencode").arg(format!("{key}={value}"));
    }
    cmd.arg("-w").arg("\n%{http_code}");

    let out = cmd.output().await.map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("curl exit status {}", out.status)
        } else {
            stderr
        });
    }

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = match stdout.rsplit_once('\n') {
        Some((body, code)) => (body.to_string(), code.trim().parse::<i64>().unwrap_or(0)),
        None => (String::new(), stdout.trim().parse::<i64>().unwrap_or(0)),
    };
    Ok(Response { status_code: code, text: body })
}

/// `class CVEIntelligenceManager` — inteligência de CVE e gestão de
/// vulnerabilidades.
pub struct CVEIntelligenceManager {
    pub cve_cache: HashMap<String, Value>,
    pub vulnerability_db: HashMap<String, Value>,
    pub threat_intelligence: HashMap<String, Value>,
}

impl CVEIntelligenceManager {
    pub fn new() -> Self {
        Self {
            cve_cache: HashMap::new(),
            vulnerability_db: HashMap::new(),
            threat_intelligence: HashMap::new(),
        }
    }

    /// `create_banner()` — reaproveita o banner unificado do visual engine.
    pub fn create_banner() -> String {
        hexstrike_core::visual_engine::ModernVisualEngine::create_banner()
    }

    /// `render_progress_bar(progress, width=40, style='cyber', label="", eta=0, speed="")`
    pub fn render_progress_bar(
        progress: f64,
        width: usize,
        style: &str,
        label: &str,
        eta: f64,
        speed: &str,
    ) -> String {
        let progress = progress.clamp(0.0, 1.0);
        let filled_width = (width as f64 * progress) as usize;
        let empty_width = width - filled_width;

        let (filled_char, empty_char, bar_color, progress_color) = match style {
            "cyber" => ("█", "░", color("ACCENT_LINE"), color("PRIMARY_BORDER")),
            "matrix" => ("▓", "▒", color("ACCENT_LINE"), color("ACCENT_GRADIENT")),
            "neon" => ("━", "─", color("PRIMARY_BORDER"), color("CYBER_ORANGE")),
            _ => ("█", "░", color("ACCENT_LINE"), color("PRIMARY_BORDER")),
        };

        let filled_part = format!("{bar_color}{}", filled_char.repeat(filled_width));
        let empty_part = format!("{}{}", color("TERMINAL_GRAY"), empty_char.repeat(empty_width));
        let percentage = format!("{:.1}%", progress * 100.0);

        let eta_str = if eta > 0.0 { format!(" | ETA: {eta:.0}s") } else { String::new() };
        let speed_str = if speed.is_empty() { String::new() } else { format!(" | {speed}") };

        let bar = format!(
            "{progress_color}[{filled_part}{empty_part}{}{progress_color}] {percentage}{eta_str}{speed_str}{}",
            color("RESET"),
            color("RESET"),
        );

        if label.is_empty() {
            bar
        } else {
            format!("{}{label}{} {bar}", color("BOLD"), color("RESET"))
        }
    }

    /// `render_vulnerability_card(vuln_data)`
    pub fn render_vulnerability_card(vuln_data: &Map<String, Value>) -> String {
        let data = Value::Object(vuln_data.clone());
        let severity = jget_str(&data, "severity", "info").to_lowercase();
        let title = jget_str(&data, "title", "Unknown Vulnerability");
        let url = jget_str(&data, "url", "N/A");
        let description = jget_str(&data, "description", "No description available");
        let cvss = jget_f64(&data, "cvss_score", 0.0);

        let severity_color = match severity.as_str() {
            "critical" | "high" => color("HACKER_RED"),
            "medium" | "low" => color("CYBER_ORANGE"),
            _ => color("NEON_BLUE"),
        };
        let severity_badge = match severity.as_str() {
            "critical" => "🔥 CRITICAL",
            "high" => "⚠️  HIGH",
            "medium" => "📊 MEDIUM",
            "low" => "📝 LOW",
            "info" => "ℹ️  INFO",
            _ => "❓ UNKNOWN",
        };

        let bold = color("BOLD");
        let reset = color("RESET");
        let top = "╭─────────────────────────────────────────────────────────────────────────────╮";
        let middle = "├─────────────────────────────────────────────────────────────────────────────┤";
        let bottom = "╰─────────────────────────────────────────────────────────────────────────────╯";

        let mut card = String::from("\n");
        card.push_str(&format!("{bold}{top}{reset}\n"));
        card.push_str(&format!(
            "{bold}│{reset} {severity_color}{severity_badge}{reset} {bold}{}{reset}\n",
            hexstrike_core::visual_engine::py_truncate(&title, 60)
        ));
        card.push_str(&format!("{bold}{middle}{reset}\n"));
        card.push_str(&format!(
            "{bold}│{reset} {}🎯 Target:{reset} {}\n",
            color("NEON_BLUE"),
            hexstrike_core::visual_engine::py_truncate(&url, 65)
        ));
        card.push_str(&format!(
            "{bold}│{reset} {}📊 CVSS:{reset} {}/10.0\n",
            color("CYBER_ORANGE"),
            py_float(cvss)
        ));
        card.push_str(&format!(
            "{bold}│{reset} {}📋 Description:{reset}\n",
            color("CYBER_ORANGE")
        ));
        card.push_str(&format!(
            "{bold}│{reset}   {}\n",
            hexstrike_core::visual_engine::py_truncate(&description, 70)
        ));
        card.push_str(&format!("{bold}{bottom}{reset}\n"));

        card
    }

    /// `create_live_dashboard(processes)` — `processes` é o dict
    /// `pid -> proc_info` do ProcessManager (chaves viram strings na serialização).
    pub fn create_live_dashboard(processes: &Map<String, Value>) -> String {
        if processes.is_empty() {
            return format!("{}📊 No active processes{}", color("TERMINAL_GRAY"), color("RESET"));
        }

        let mut dashboard = format!(
            "
{}{}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🚀 LIVE PROCESS DASHBOARD                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{}
",
            color("MATRIX_GREEN"),
            color("BOLD"),
            color("RESET"),
        );

        for (pid, proc_info) in processes {
            let command = jget_str(proc_info, "command", "Unknown");
            let status = jget_str(proc_info, "status", "unknown");
            let progress = jget_f64(proc_info, "progress", 0.0);
            let runtime = jget_f64(proc_info, "runtime", 0.0);
            let eta = jget_f64(proc_info, "eta", 0.0);

            let status_color = match status.as_str() {
                "running" => color("MATRIX_GREEN"),
                "paused" => color("WARNING"),
                "terminated" => color("ERROR"),
                "completed" => color("NEON_BLUE"),
                _ => color("BRIGHT_WHITE"),
            };

            let mini_bar =
                hexstrike_core::visual_engine::ModernVisualEngine::render_progress_bar(progress, 20, "cyber", "", eta, "");

            dashboard.push_str(&format!(
                "{}║{} {}PID {}{} │ {}{}{} │ {runtime:.1}s │ {}...
{}║{} {mini_bar}
{}╠──────────────────────────────────────────────────────────────────────────────╣{}
",
                color("BOLD"),
                color("RESET"),
                color("NEON_BLUE"),
                pid,
                color("RESET"),
                status_color,
                status.to_uppercase(),
                color("RESET"),
                hexstrike_core::visual_engine::py_truncate(&command, 50),
                color("BOLD"),
                color("RESET"),
                color("BOLD"),
                color("RESET"),
            ));
        }

        dashboard.push_str(&format!(
            "{}{}╚══════════════════════════════════════════════════════════════════════════════╝{}",
            color("MATRIX_GREEN"),
            color("BOLD"),
            color("RESET"),
        ));

        dashboard
    }

    /// `format_tool_output(tool, output, success=True)`
    pub fn format_tool_output(tool: &str, output: &str, success: bool) -> String {
        let tool_icon = "🛠️";
        let status_icon = if success { "✅" } else { "❌" };
        let status_color = if success { color("MATRIX_GREEN") } else { color("HACKER_RED") };

        let mut formatted_output = format!(
            "
{}╭─ {tool_icon} {} OUTPUT ─────────────────────────────────────────────╮{}
{}│{} {}{} Status: {}{}
{}├─────────────────────────────────────────────────────────────────────────────┤{}
",
            color("BOLD"),
            tool.to_uppercase(),
            color("RESET"),
            color("BOLD"),
            color("RESET"),
            status_color,
            status_icon,
            if success { "SUCCESS" } else { "FAILED" },
            color("RESET"),
            color("BOLD"),
            color("RESET"),
        );

        let lines: Vec<&str> = output.split('\n').collect();
        for line in lines.iter().take(20) {
            if line.trim().is_empty() {
                continue;
            }
            let lower = line.to_lowercase();
            let line_color = if ["error", "failed", "denied"].iter().any(|k| lower.contains(k)) {
                color("ERROR")
            } else if ["found", "discovered", "vulnerable"].iter().any(|k| lower.contains(k)) {
                color("MATRIX_GREEN")
            } else if ["warning", "timeout"].iter().any(|k| lower.contains(k)) {
                color("WARNING")
            } else {
                color("BRIGHT_WHITE")
            };
            formatted_output.push_str(&format!(
                "{}│{} {}{}{}\n",
                color("BOLD"),
                color("RESET"),
                line_color,
                hexstrike_core::visual_engine::py_truncate(line, 75),
                color("RESET"),
            ));
        }

        if lines.len() > 20 {
            formatted_output.push_str(&format!(
                "{}│{} {}... ({} more lines truncated){}\n",
                color("BOLD"),
                color("RESET"),
                color("TERMINAL_GRAY"),
                lines.len() - 20,
                color("RESET"),
            ));
        }

        formatted_output.push_str(&format!(
            "{}╰─────────────────────────────────────────────────────────────────────────────╯{}",
            color("BOLD"),
            color("RESET"),
        ));

        formatted_output
    }

    /// `create_summary_report(results)`
    pub fn create_summary_report(results: &Value) -> String {
        let vulnerabilities = jget_arr(results, "vulnerabilities");
        let total_vulns = vulnerabilities.len();
        let critical_vulns = vulnerabilities
            .iter()
            .filter(|v| v.get("severity").and_then(Value::as_str) == Some("critical"))
            .count();
        let high_vulns = vulnerabilities
            .iter()
            .filter(|v| v.get("severity").and_then(Value::as_str) == Some("high"))
            .count();
        let execution_time = jget_f64(results, "execution_time", 0.0);
        let tools_used: Vec<String> = jget_arr(results, "tools_used")
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();

        let tools_list = tools_used.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
        let tools_ellipsis = if tools_used.len() > 5 { "..." } else { "" };
        let target = hexstrike_core::visual_engine::py_truncate(&jget_str(results, "target", "Unknown"), 60);

        let bold = color("BOLD");
        let reset = color("RESET");
        let rule = "─".repeat(78);
        let mut report = format!(
            "\n{}{}╔══════════════════════════════════════════════════════════════════════════════╗\n║                              📊 SCAN SUMMARY REPORT                          ║\n╠══════════════════════════════════════════════════════════════════════════════╣{reset}",
            color("MATRIX_GREEN"),
            bold,
        );
        report.push_str(&format!(
            "\n{bold}║{reset} {}🎯 Target:{reset} {target}",
            color("NEON_BLUE")
        ));
        report.push_str(&format!(
            "\n{bold}║{reset} {}⏱️  Duration:{reset} {execution_time:.2}s seconds",
            color("CYBER_ORANGE")
        ));
        report.push_str(&format!(
            "\n{bold}║{reset} {}🛠️  Tools Used:{reset} {} tools",
            color("WARNING"),
            tools_used.len()
        ));
        report.push_str(&format!("\n{bold}╠{rule}╣{reset}"));
        report.push_str(&format!(
            "\n{bold}║{reset} {}🔥 Critical:{reset} {critical_vulns} vulnerabilities",
            color("HACKER_RED")
        ));
        report.push_str(&format!(
            "\n{bold}║{reset} {}⚠️  High:{reset} {high_vulns} vulnerabilities",
            color("ERROR")
        ));
        report.push_str(&format!(
            "\n{bold}║{reset} {}📈 Total Found:{reset} {total_vulns} vulnerabilities",
            color("MATRIX_GREEN")
        ));
        report.push_str(&format!("\n{bold}╠{rule}╣{reset}"));
        report.push_str(&format!(
            "\n{bold}║{reset} {}🚀 Tools:{reset} {tools_list}{tools_ellipsis}",
            color("ELECTRIC_PURPLE")
        ));
        report.push_str(&format!(
            "\n{}{}╚══════════════════════════════════════════════════════════════════════════════╝{reset}\n",
            color("MATRIX_GREEN"),
            bold,
        ));

        report
    }
}

impl Default for CVEIntelligenceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// `metrics['cvssMetricVXY'][0]['cvssData']` — só quando a lista é não vazia.
fn first_cvss_data(metrics: &Value, key: &str) -> Option<Value> {
    metrics
        .get(key)
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|entry| entry.get("cvssData"))
        .cloned()
}

impl CVEIntelligenceManager {
    /// `fetch_latest_cves(hours=24, severity_filter="HIGH,CRITICAL")`
    pub async fn fetch_latest_cves(&self, hours: i64, severity_filter: &str) -> Value {
        info!("🔍 Fetching CVEs from last {hours} hours with severity: {severity_filter}");

        // Calculate date range for CVE search
        let end_date = now_local();
        let start_date = end_date - time::Duration::hours(hours);
        let start_date_str = nvd_timestamp(start_date);
        let end_date_str = nvd_timestamp(end_date);

        // NVD API endpoint
        let nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        let severity_levels: Vec<String> =
            severity_filter.split(',').map(|s| s.trim().to_uppercase()).collect();

        let mut all_cves: Vec<Value> = Vec::new();

        let params = vec![
            ("lastModStartDate", start_date_str.clone()),
            ("lastModEndDate", end_date_str.clone()),
            ("resultsPerPage", "100".to_string()),
        ];

        info!("🌐 Querying NVD API: {nvd_url}");
        match requests_get(nvd_url, &params, 30).await {
            Ok(response) => {
                if response.status_code == 200 {
                    let nvd_data = match response.json() {
                        Ok(data) => data,
                        Err(e) => {
                            // JSONDecodeError não é RequestException: cai no except externo
                            return fetch_cves_error(&e);
                        }
                    };
                    let vulnerabilities = jget_arr(&nvd_data, "vulnerabilities");

                    info!("📊 Retrieved {} vulnerabilities from NVD", vulnerabilities.len());

                    for vuln_item in &vulnerabilities {
                        let cve_data = vuln_item.get("cve").cloned().unwrap_or_else(|| json!({}));
                        let cve_id = jget_str(&cve_data, "id", "Unknown");

                        // Extract CVSS scores and determine severity
                        let metrics = cve_data.get("metrics").cloned().unwrap_or_else(|| json!({}));
                        let mut cvss_value = json!(0.0);
                        let mut severity = "UNKNOWN".to_string();

                        // Try CVSS v3.1 first, then v3.0, then v2.0
                        if let Some(cvss_data) = first_cvss_data(&metrics, "cvssMetricV31") {
                            cvss_value = jget_num(&cvss_data, "baseScore");
                            severity = jget_str(&cvss_data, "baseSeverity", "UNKNOWN").to_uppercase();
                        } else if let Some(cvss_data) = first_cvss_data(&metrics, "cvssMetricV30") {
                            cvss_value = jget_num(&cvss_data, "baseScore");
                            severity = jget_str(&cvss_data, "baseSeverity", "UNKNOWN").to_uppercase();
                        } else if let Some(cvss_data) = first_cvss_data(&metrics, "cvssMetricV2") {
                            cvss_value = jget_num(&cvss_data, "baseScore");
                            // Convert CVSS v2 score to severity
                            let score = cvss_value.as_f64().unwrap_or(0.0);
                            severity = if score >= 9.0 {
                                "CRITICAL"
                            } else if score >= 7.0 {
                                "HIGH"
                            } else if score >= 4.0 {
                                "MEDIUM"
                            } else {
                                "LOW"
                            }
                            .to_string();
                        }

                        // Filter by severity if specified
                        if !severity_levels.contains(&severity)
                            && severity_levels != vec!["ALL".to_string()]
                        {
                            continue;
                        }

                        // Extract description
                        let mut description = "No description available".to_string();
                        for desc in jget_arr(&cve_data, "descriptions") {
                            if desc.get("lang").and_then(Value::as_str) == Some("en") {
                                description = jget_str(&desc, "value", &description);
                                break;
                            }
                        }

                        // Extract references
                        let references: Vec<Value> = jget_arr(&cve_data, "references")
                            .iter()
                            .take(5)
                            .map(|r| json!(jget_str(r, "url", "")))
                            .collect();

                        // Extract affected software (CPE data)
                        let mut affected_software: Vec<String> = Vec::new();
                        for config in jget_arr(&cve_data, "configurations") {
                            for node in jget_arr(&config, "nodes") {
                                for cpe in jget_arr(&node, "cpeMatch").iter().take(3) {
                                    let cpe_name = jget_str(cpe, "criteria", "");
                                    if cpe_name.starts_with("cpe:2.3:") {
                                        // Parse CPE to get readable software name
                                        let parts: Vec<&str> = cpe_name.split(':').collect();
                                        if parts.len() >= 6 {
                                            let vendor = parts[3];
                                            let product = parts[4];
                                            let version = if parts[5] != "*" {
                                                parts[5].to_string()
                                            } else {
                                                "all versions".to_string()
                                            };
                                            affected_software
                                                .push(format!("{vendor} {product} {version}"));
                                        }
                                    }
                                }
                            }
                        }

                        all_cves.push(json!({
                            "cve_id": cve_id,
                            "description": description,
                            "severity": severity,
                            "cvss_score": cvss_value,
                            "published_date": jget_str(&cve_data, "published", ""),
                            "last_modified": jget_str(&cve_data, "lastModified", ""),
                            // Limit to 5 entries
                            "affected_software": affected_software.iter().take(5).collect::<Vec<_>>(),
                            "references": references,
                            "source": "NVD",
                        }));
                    }
                } else {
                    warn!("⚠️ NVD API returned status code: {}", response.status_code);
                }
            }
            Err(e) => error!("❌ Error querying NVD API: {e}"),
        }

        // If no CVEs found from NVD, try alternative sources or provide
        // informative response
        if all_cves.is_empty() {
            info!("🔄 No recent CVEs found in specified timeframe, checking for any recent critical CVEs...");

            // Try a broader search for recent critical CVEs (last 7 days)
            let broader_start = nvd_timestamp(now_local() - time::Duration::days(7));
            let broader_params = vec![
                ("lastModStartDate", broader_start),
                ("lastModEndDate", end_date_str.clone()),
                ("cvssV3Severity", "CRITICAL".to_string()),
                ("resultsPerPage", "20".to_string()),
            ];

            // Rate limit compliance
            tokio::time::sleep(Duration::from_secs(6)).await;

            match requests_get(nvd_url, &broader_params, 30).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        match response.json() {
                            Ok(nvd_data) => {
                                let vulnerabilities = jget_arr(&nvd_data, "vulnerabilities");

                                // Limit to 10 most recent
                                for vuln_item in vulnerabilities.iter().take(10) {
                                    let cve_data =
                                        vuln_item.get("cve").cloned().unwrap_or_else(|| json!({}));
                                    let cve_id = jget_str(&cve_data, "id", "Unknown");

                                    // Extract basic info for recent critical CVEs
                                    let mut description = "No description available".to_string();
                                    for desc in jget_arr(&cve_data, "descriptions") {
                                        if desc.get("lang").and_then(Value::as_str) == Some("en") {
                                            description = jget_str(&desc, "value", &description);
                                            break;
                                        }
                                    }

                                    let metrics =
                                        cve_data.get("metrics").cloned().unwrap_or_else(|| json!({}));
                                    let mut cvss_value = json!(0.0);
                                    if let Some(cvss_data) =
                                        first_cvss_data(&metrics, "cvssMetricV31")
                                    {
                                        cvss_value = jget_num(&cvss_data, "baseScore");
                                    }

                                    all_cves.push(json!({
                                        "cve_id": cve_id,
                                        "description": description,
                                        "severity": "CRITICAL",
                                        "cvss_score": cvss_value,
                                        "published_date": jget_str(&cve_data, "published", ""),
                                        "last_modified": jget_str(&cve_data, "lastModified", ""),
                                        "affected_software": ["Various (see references)"],
                                        "references": [format!("https://nvd.nist.gov/vuln/detail/{cve_id}")],
                                        "source": "NVD (Recent Critical)",
                                    }));
                                }
                            }
                            Err(e) => warn!("⚠️ Broader search also failed: {e}"),
                        }
                    }
                }
                Err(e) => warn!("⚠️ Broader search also failed: {e}"),
            }
        }

        info!("✅ Successfully retrieved {} CVEs", all_cves.len());

        let total_found = all_cves.len();
        json!({
            "success": true,
            "cves": all_cves,
            "total_found": total_found,
            "hours_searched": hours,
            "severity_filter": severity_filter,
            "data_sources": ["NVD API v2.0"],
            "search_period": format!("{start_date_str} to {end_date_str}"),
        })
    }

    /// `analyze_cve_exploitability(cve_id)`
    pub async fn analyze_cve_exploitability(&self, cve_id: &str) -> Value {
        info!("🔬 Analyzing exploitability for {cve_id}");

        // Fetch detailed CVE data from NVD
        let nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        let params = vec![("cveId", cve_id.to_string())];

        let response = match requests_get(nvd_url, &params, 30).await {
            Ok(response) => response,
            Err(e) => {
                error!("❌ Network error analyzing {cve_id}: {e}");
                return json!({
                    "success": false,
                    "error": format!("Network error: {e}"),
                    "cve_id": cve_id,
                });
            }
        };

        if response.status_code != 200 {
            warn!("⚠️ NVD API returned status {} for {cve_id}", response.status_code);
            return json!({
                "success": false,
                "error": format!("Failed to fetch CVE data: HTTP {}", response.status_code),
                "cve_id": cve_id,
            });
        }

        let nvd_data = match response.json() {
            Ok(data) => data,
            Err(e) => {
                error!("💥 Error analyzing CVE {cve_id}: {e}");
                return json!({"success": false, "error": e, "cve_id": cve_id});
            }
        };
        let vulnerabilities = jget_arr(&nvd_data, "vulnerabilities");

        if vulnerabilities.is_empty() {
            warn!("⚠️ No data found for CVE {cve_id}");
            return json!({
                "success": false,
                "error": format!("CVE {cve_id} not found in NVD database"),
                "cve_id": cve_id,
            });
        }

        let cve_data = vulnerabilities[0].get("cve").cloned().unwrap_or_else(|| json!({}));

        // Extract CVSS metrics for exploitability analysis
        let metrics = cve_data.get("metrics").cloned().unwrap_or_else(|| json!({}));
        let mut cvss_value = json!(0.0);
        let mut severity = "UNKNOWN".to_string();
        let mut attack_vector = "UNKNOWN".to_string();
        let mut attack_complexity = "UNKNOWN".to_string();
        let mut privileges_required = "UNKNOWN".to_string();
        let mut user_interaction = "UNKNOWN".to_string();
        let mut exploitability_subscore = json!(0.0);

        // Analyze CVSS v3.1 metrics (preferred)
        if let Some(cvss_data) = first_cvss_data(&metrics, "cvssMetricV31") {
            cvss_value = jget_num(&cvss_data, "baseScore");
            severity = jget_str(&cvss_data, "baseSeverity", "UNKNOWN").to_uppercase();
            attack_vector = jget_str(&cvss_data, "attackVector", "UNKNOWN");
            attack_complexity = jget_str(&cvss_data, "attackComplexity", "UNKNOWN");
            privileges_required = jget_str(&cvss_data, "privilegesRequired", "UNKNOWN");
            user_interaction = jget_str(&cvss_data, "userInteraction", "UNKNOWN");
            exploitability_subscore = jget_num(&cvss_data, "exploitabilityScore");
        } else if let Some(cvss_data) = first_cvss_data(&metrics, "cvssMetricV30") {
            cvss_value = jget_num(&cvss_data, "baseScore");
            severity = jget_str(&cvss_data, "baseSeverity", "UNKNOWN").to_uppercase();
            attack_vector = jget_str(&cvss_data, "attackVector", "UNKNOWN");
            attack_complexity = jget_str(&cvss_data, "attackComplexity", "UNKNOWN");
            privileges_required = jget_str(&cvss_data, "privilegesRequired", "UNKNOWN");
            user_interaction = jget_str(&cvss_data, "userInteraction", "UNKNOWN");
            exploitability_subscore = jget_num(&cvss_data, "exploitabilityScore");
        }

        // Calculate exploitability score based on CVSS metrics
        let subscore = exploitability_subscore.as_f64().unwrap_or(0.0);
        let mut exploitability_score;

        // Base exploitability on CVSS exploitability subscore if available
        if subscore > 0.0 {
            // Normalize to 0-1
            exploitability_score = (subscore / 3.9).min(1.0);
        } else {
            // Calculate based on individual CVSS components
            let mut score_components = 0.0f64;

            // Attack Vector scoring
            match attack_vector.as_str() {
                "NETWORK" => score_components += 0.4,
                "ADJACENT_NETWORK" => score_components += 0.3,
                "LOCAL" => score_components += 0.2,
                "PHYSICAL" => score_components += 0.1,
                _ => {}
            }

            // Attack Complexity scoring
            match attack_complexity.as_str() {
                "LOW" => score_components += 0.3,
                "HIGH" => score_components += 0.1,
                _ => {}
            }

            // Privileges Required scoring
            match privileges_required.as_str() {
                "NONE" => score_components += 0.2,
                "LOW" => score_components += 0.1,
                _ => {}
            }

            // User Interaction scoring
            if user_interaction == "NONE" {
                score_components += 0.1;
            }

            exploitability_score = score_components.min(1.0);
        }

        // Determine exploitability level. O Python decide o rótulo ANTES do
        // ajuste por tipo de falha logo abaixo — o rótulo pode, por isso,
        // discordar do score final. Reproduzido de propósito.
        let exploitability_level = if exploitability_score >= 0.8 {
            "HIGH"
        } else if exploitability_score >= 0.6 {
            "MEDIUM"
        } else if exploitability_score >= 0.3 {
            "LOW"
        } else {
            "VERY_LOW"
        };

        // Extract description for additional context
        let mut description = String::new();
        for desc in jget_arr(&cve_data, "descriptions") {
            if desc.get("lang").and_then(Value::as_str) == Some("en") {
                description = jget_str(&desc, "value", "");
                break;
            }
        }

        // Analyze description for exploit indicators
        let exploit_keywords = [
            "remote code execution",
            "rce",
            "buffer overflow",
            "stack overflow",
            "heap overflow",
            "use after free",
            "double free",
            "format string",
            "sql injection",
            "command injection",
            "authentication bypass",
            "privilege escalation",
            "directory traversal",
            "path traversal",
            "deserialization",
            "xxe",
            "ssrf",
            "csrf",
            "xss",
        ];

        let description_lower = description.to_lowercase();
        let exploit_indicators: Vec<&str> =
            exploit_keywords.iter().copied().filter(|kw| description_lower.contains(kw)).collect();

        // Adjust exploitability based on vulnerability type
        if ["remote code execution", "rce", "buffer overflow"]
            .iter()
            .any(|kw| description_lower.contains(kw))
        {
            exploitability_score = (exploitability_score + 0.2).min(1.0);
        } else if ["authentication bypass", "privilege escalation"]
            .iter()
            .any(|kw| description_lower.contains(kw))
        {
            exploitability_score = (exploitability_score + 0.15).min(1.0);
        }

        // Check for public exploit availability indicators
        let mut public_exploits = false;
        let mut exploit_maturity = "UNKNOWN";

        // Look for exploit references in CVE references
        let references = jget_arr(&cve_data, "references");
        let exploit_sources =
            ["exploit-db.com", "github.com", "packetstormsecurity.com", "metasploit"];

        for reference in &references {
            let ref_url = jget_str(reference, "url", "").to_lowercase();
            if exploit_sources.iter().any(|source| ref_url.contains(source)) {
                public_exploits = true;
                exploit_maturity = "PROOF_OF_CONCEPT";
                break;
            }
        }

        // Determine weaponization level
        let mut weaponization_level = "LOW";
        if public_exploits && exploitability_score > 0.7 {
            weaponization_level = "HIGH";
        } else if public_exploits && exploitability_score > 0.5 {
            weaponization_level = "MEDIUM";
        } else if exploitability_score > 0.8 {
            weaponization_level = "MEDIUM";
        }

        // Active exploitation assessment
        let active_exploitation = (exploitability_score > 0.8 && public_exploits)
            || ((severity == "CRITICAL" || severity == "HIGH") && attack_vector == "NETWORK");

        // Priority recommendation
        let priority = if exploitability_score > 0.8 && severity == "CRITICAL" {
            "IMMEDIATE"
        } else if exploitability_score > 0.7 || severity == "CRITICAL" {
            "HIGH"
        } else if exploitability_score > 0.5 || severity == "HIGH" {
            "MEDIUM"
        } else {
            "LOW"
        };

        let truncated_description = if description.chars().count() > 500 {
            format!("{}...", hexstrike_core::visual_engine::py_truncate(&description, 500))
        } else {
            description
        };

        info!(
            "✅ Completed exploitability analysis for {cve_id}: {exploitability_level} ({:.2})",
            exploitability_score
        );

        json!({
            "success": true,
            "cve_id": cve_id,
            "exploitability_score": py_round2(exploitability_score),
            "exploitability_level": exploitability_level,
            "cvss_score": cvss_value,
            "severity": severity,
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "exploitability_subscore": exploitability_subscore,
            "exploit_availability": {
                "public_exploits": public_exploits,
                "exploit_maturity": exploit_maturity,
                "weaponization_level": weaponization_level,
            },
            "threat_intelligence": {
                "active_exploitation": active_exploitation,
                "exploit_prediction": format!(
                    "{:.1}% likelihood of exploitation",
                    exploitability_score * 100.0
                ),
                "recommended_priority": priority,
                "exploit_indicators": exploit_indicators,
            },
            "vulnerability_details": {
                "description": truncated_description,
                "published_date": jget_str(&cve_data, "published", ""),
                "last_modified": jget_str(&cve_data, "lastModified", ""),
                "references_count": references.len(),
            },
            "data_source": "NVD API v2.0",
            "analysis_timestamp": iso_now(),
        })
    }
}

/// `except Exception` de `fetch_latest_cves`.
fn fetch_cves_error(e: &str) -> Value {
    error!("💥 Error fetching CVEs: {e}");
    json!({
        "success": false,
        "error": e,
        "cves": [],
        "fallback_message": "CVE fetching failed, check network connectivity and API availability",
    })
}

/// Posição de `reliability` na ordenação de `search_existing_exploits`.
fn reliability_rank(exploit: &Value) -> i64 {
    match exploit.get("reliability").and_then(Value::as_str).unwrap_or("UNVERIFIED") {
        "EXCELLENT" => 4,
        "GOOD" => 3,
        "FAIR" => 2,
        "UNVERIFIED" => 1,
        _ => 0,
    }
}

/// `len([e for e in exploits if e["source"] == source])`
fn count_source(exploits: &[Value], source: &str) -> usize {
    exploits.iter().filter(|e| e.get("source").and_then(Value::as_str) == Some(source)).count()
}

impl CVEIntelligenceManager {
    /// `search_existing_exploits(cve_id)`
    pub async fn search_existing_exploits(&self, cve_id: &str) -> Value {
        info!("🔎 Searching existing exploits for {cve_id}");

        let mut all_exploits: Vec<Value> = Vec::new();
        let mut sources_searched: Vec<String> = Vec::new();
        let cve_id_lower = cve_id.to_lowercase();

        // 1. Search GitHub for PoCs and exploits
        info!("🔍 Searching GitHub for {cve_id} exploits...");

        // GitHub Search API
        let github_search_url = "https://api.github.com/search/repositories";
        let github_params = vec![
            ("q", format!("{cve_id} exploit poc vulnerability")),
            ("sort", "updated".to_string()),
            ("order", "desc".to_string()),
            ("per_page", "10".to_string()),
        ];

        match requests_get(github_search_url, &github_params, 15).await {
            Ok(response) => {
                if response.status_code == 200 {
                    let github_data = match response.json() {
                        Ok(data) => data,
                        Err(e) => return search_exploits_error(cve_id, &e),
                    };
                    let repositories = jget_arr(&github_data, "items");

                    // Limit to top 5 results
                    for repo in repositories.iter().take(5) {
                        // Check if CVE is actually mentioned in repo name or description.
                        // (No Python, `repo.get('description', '').lower()` estoura
                        // AttributeError quando a descrição vem null; o port trata
                        // null como string vazia.)
                        let repo_name = jget_str(repo, "name", "").to_lowercase();
                        let repo_desc = jget_str(repo, "description", "").to_lowercase();

                        if repo_name.contains(&cve_id_lower) || repo_desc.contains(&cve_id_lower) {
                            let mut entry = json!({
                                "source": "github",
                                "exploit_id": format!(
                                    "github-{}",
                                    py_str(repo.get("id")).unwrap_or_else(|| "unknown".to_string())
                                ),
                                "title": jget_str(repo, "name", "Unknown Repository"),
                                "description": jget_str(repo, "description", "No description"),
                                "author": repo
                                    .get("owner")
                                    .and_then(|owner| owner.get("login"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("Unknown"),
                                "date_published": jget_str(repo, "created_at", ""),
                                "last_updated": jget_str(repo, "updated_at", ""),
                                "type": "proof-of-concept",
                                "platform": "cross-platform",
                                "url": jget_str(repo, "html_url", ""),
                                "stars": repo
                                    .get("stargazers_count")
                                    .cloned()
                                    .unwrap_or_else(|| json!(0)),
                                "forks": repo.get("forks_count").cloned().unwrap_or_else(|| json!(0)),
                                "verified": false,
                                "reliability": "UNVERIFIED",
                            });

                            // Assess reliability based on repo metrics
                            let stars = jget_f64(repo, "stargazers_count", 0.0);
                            let forks = jget_f64(repo, "forks_count", 0.0);

                            if stars >= 50.0 || forks >= 10.0 {
                                entry["reliability"] = json!("GOOD");
                            } else if stars >= 20.0 || forks >= 5.0 {
                                entry["reliability"] = json!("FAIR");
                            }

                            all_exploits.push(entry);
                        }
                    }

                    sources_searched.push("github".to_string());
                    info!("✅ Found {} GitHub repositories", count_source(&all_exploits, "github"));
                } else {
                    warn!("⚠️ GitHub search failed with status {}", response.status_code);
                }
            }
            Err(e) => error!("❌ GitHub search error: {e}"),
        }

        // 2. Search Exploit-DB via searchsploit-like functionality
        info!("🔍 Searching for {cve_id} in exploit databases...");

        // First, get CVE data to check references
        let nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        let nvd_params = vec![("cveId", cve_id.to_string())];

        // Rate limiting
        tokio::time::sleep(Duration::from_secs(1)).await;

        match requests_get(nvd_url, &nvd_params, 20).await {
            Ok(response) => {
                if response.status_code == 200 {
                    match response.json() {
                        Ok(nvd_data) => {
                            let vulnerabilities = jget_arr(&nvd_data, "vulnerabilities");

                            if !vulnerabilities.is_empty() {
                                let cve_data = vulnerabilities[0]
                                    .get("cve")
                                    .cloned()
                                    .unwrap_or_else(|| json!({}));
                                let references = jget_arr(&cve_data, "references");

                                // Check references for exploit sources
                                let exploit_sources = [
                                    ("exploit-db.com", "exploit-db"),
                                    ("packetstormsecurity.com", "packetstorm"),
                                    ("metasploit", "metasploit"),
                                    ("rapid7.com", "rapid7"),
                                ];

                                for reference in &references {
                                    let ref_url = jget_str(reference, "url", "");
                                    let ref_url_lower = ref_url.to_lowercase();

                                    for (source_domain, source_name) in exploit_sources {
                                        if ref_url_lower.contains(source_domain) {
                                            all_exploits.push(json!({
                                                "source": source_name,
                                                "exploit_id": format!("{source_name}-ref"),
                                                "title": format!("Referenced exploit for {cve_id}"),
                                                "description": "Exploit reference found in CVE data",
                                                "author": "Various",
                                                "date_published": jget_str(&cve_data, "published", ""),
                                                "type": "reference",
                                                "platform": "various",
                                                "url": ref_url,
                                                "verified": true,
                                                "reliability": if source_name == "exploit-db" {
                                                    "GOOD"
                                                } else {
                                                    "FAIR"
                                                },
                                            }));

                                            if !sources_searched.iter().any(|s| s == source_name) {
                                                sources_searched.push(source_name.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => error!("❌ Exploit database search error: {e}"),
                    }
                }
            }
            Err(e) => error!("❌ Exploit database search error: {e}"),
        }

        // 3. Search for Metasploit modules
        info!("🔍 Searching for Metasploit modules for {cve_id}...");

        // Search GitHub for Metasploit modules containing the CVE
        let msf_search_url = "https://api.github.com/search/code";
        let msf_params = vec![
            ("q", format!("{cve_id} filename:*.rb repo:rapid7/metasploit-framework")),
            ("per_page", "5".to_string()),
        ];

        // Rate limiting
        tokio::time::sleep(Duration::from_secs(1)).await;

        match requests_get(msf_search_url, &msf_params, 15).await {
            Ok(response) => {
                if response.status_code == 200 {
                    let msf_data = match response.json() {
                        Ok(data) => data,
                        Err(e) => return search_exploits_error(cve_id, &e),
                    };
                    let code_results = jget_arr(&msf_data, "items");

                    for code_item in &code_results {
                        let file_path = jget_str(code_item, "path", "");
                        if file_path.contains("exploits/") || file_path.contains("auxiliary/") {
                            let sha = jget_str(code_item, "sha", "unknown");
                            all_exploits.push(json!({
                                "source": "metasploit",
                                "exploit_id": format!(
                                    "msf-{}",
                                    hexstrike_core::visual_engine::py_truncate(&sha, 8)
                                ),
                                "title": format!(
                                    "Metasploit Module: {}",
                                    jget_str(code_item, "name", "Unknown")
                                ),
                                "description": format!("Metasploit framework module at {file_path}"),
                                "author": "Metasploit Framework",
                                "date_published": "Unknown",
                                "type": "metasploit-module",
                                "platform": "various",
                                "url": jget_str(code_item, "html_url", ""),
                                "verified": true,
                                "reliability": "EXCELLENT",
                            }));
                        }
                    }

                    if !code_results.is_empty()
                        && !sources_searched.iter().any(|s| s == "metasploit")
                    {
                        sources_searched.push("metasploit".to_string());
                    }
                } else if response.status_code == 403 {
                    warn!("⚠️ GitHub API rate limit reached for code search");
                } else {
                    warn!("⚠️ Metasploit search failed with status {}", response.status_code);
                }
            }
            Err(e) => error!("❌ Metasploit search error: {e}"),
        }

        // Add default sources to searched list
        for source in ["exploit-db", "github", "metasploit", "packetstorm"] {
            if !sources_searched.iter().any(|s| s == source) {
                sources_searched.push(source.to_string());
            }
        }

        // Sort exploits by reliability and date
        all_exploits.sort_by(|a, b| {
            let key = |exploit: &Value| {
                (
                    reliability_rank(exploit),
                    exploit.get("stars").and_then(Value::as_i64).unwrap_or(0),
                    jget_str(exploit, "date_published", ""),
                )
            };
            key(b).cmp(&key(a))
        });

        info!(
            "✅ Found {} total exploits from {} sources",
            all_exploits.len(),
            sources_searched.len()
        );

        let exploits_found = all_exploits.len();
        let github_repos = count_source(&all_exploits, "github");
        let exploit_db_refs = count_source(&all_exploits, "exploit-db");
        let metasploit_modules = count_source(&all_exploits, "metasploit");
        let other_sources = all_exploits
            .iter()
            .filter(|e| {
                !matches!(
                    e.get("source").and_then(Value::as_str),
                    Some("github" | "exploit-db" | "metasploit")
                )
            })
            .count();

        json!({
            "success": true,
            "cve_id": cve_id,
            "exploits_found": exploits_found,
            "exploits": all_exploits,
            "sources_searched": sources_searched,
            "search_summary": {
                "github_repos": github_repos,
                "exploit_db_refs": exploit_db_refs,
                "metasploit_modules": metasploit_modules,
                "other_sources": other_sources,
            },
            "search_timestamp": iso_now(),
        })
    }
}

/// `except Exception` de `search_existing_exploits`.
fn search_exploits_error(cve_id: &str, e: &str) -> Value {
    error!("💥 Error searching exploits for {cve_id}: {e}");
    json!({
        "success": false,
        "error": e,
        "cve_id": cve_id,
        "exploits": [],
        "sources_searched": [],
    })
}

// ============================================================================
// LOGGING COM CORES (ColoredFormatter / setup_logging)
// ============================================================================

/// `class ColoredFormatter(logging.Formatter)` — cores e emojis por nível.
pub struct ColoredFormatter;

impl ColoredFormatter {
    /// `COLORS` do Python — cada nível aponta para uma chave do
    /// `ModernVisualEngine.COLORS`.
    pub fn colors(levelname: &str) -> &'static str {
        match levelname {
            "DEBUG" => color("DEBUG"),
            "INFO" => color("SUCCESS"),
            "WARNING" => color("WARNING"),
            "ERROR" => color("ERROR"),
            "CRITICAL" => color("CRITICAL"),
            _ => color("BRIGHT_WHITE"),
        }
    }

    /// `EMOJIS` do Python
    pub fn emojis(levelname: &str) -> &'static str {
        match levelname {
            "DEBUG" => "🔍",
            "INFO" => "✅",
            "WARNING" => "⚠️",
            "ERROR" => "❌",
            "CRITICAL" => "🔥",
            _ => "📝",
        }
    }

    /// `format(record)` — `record.msg = f"{color}{emoji} {msg}{RESET}"`.
    pub fn format(levelname: &str, message: &str) -> String {
        format!(
            "{}{} {message}{}",
            Self::colors(levelname),
            Self::emojis(levelname),
            color("RESET")
        )
    }
}

/// `record.msg` visto pelo `ColoredFormatter`.
#[derive(Default)]
struct RecordMessage(String);

impl tracing::field::Visit for RecordMessage {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// `%(asctime)s` do `setup_logging`, com `datefmt="%Y-%m-%d %H:%M:%S"`.
#[derive(Clone, Copy, Default)]
struct AsctimeSeconds;

impl tracing_subscriber::fmt::time::FormatTime for AsctimeSeconds {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let fmt = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
        write!(w, "{}", now_local().format(&fmt).unwrap_or_default())
    }
}

/// `"[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s"`
struct ColoredEventFormat;

impl<S, N> FormatEvent<S, N> for ColoredEventFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let levelname = match *event.metadata().level() {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARNING",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "DEBUG",
        };

        let mut record = RecordMessage::default();
        event.record(&mut record);

        write!(writer, "[🔥 HexStrike AI] ")?;
        AsctimeSeconds.format_time(&mut writer)?;
        writeln!(writer, " [{}] {}", levelname, ColoredFormatter::format(levelname, &record.0))
    }
}

/// `setup_logging()` — logger raiz em INFO, saída no stdout com cores.
///
/// O `logger` global do Python vira o subscriber do `tracing`, que o
/// `core::init()` já instalou ("MUST BE FIRST"); `try_init` não troca um
/// subscriber existente — é o limite do `tracing` para o
/// `logger.removeHandler`/`addHandler` do Python.
pub fn setup_logging() {
    let filter = tracing_subscriber::EnvFilter::new("info");
    let console_layer = tracing_subscriber::fmt::layer()
        .event_format(ColoredEventFormat)
        .with_writer(std::io::stdout);
    let _ = tracing_subscriber::registry().with(filter).with(console_layer).try_init();
}

// ============================================================================
// CONFIGURAÇÃO E GLOBAIS
// ============================================================================

/// `DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1","true","yes","y")`
/// — o valor vivo (com `--debug`) mora em [`hexstrike_core::debug_mode`].
pub static DEBUG_MODE: LazyLock<bool> = LazyLock::new(hexstrike_core::debug_mode);

/// `cve_intelligence = CVEIntelligenceManager()`.
///
/// No split Python o singleton é instanciado em
/// `intelligence/exploit_gen.py` (o `_registry.py` o atribui lá) e as rotas o
/// importam de lá; como a classe é deste módulo, a instância vive aqui para
/// não depender de `exploit_gen.rs`. Quem portar `exploit_gen.py` deve
/// reexportá-la (`pub use ...::cve_intelligence;`) em vez de criar outra.
#[allow(non_upper_case_globals)]
pub static cve_intelligence: LazyLock<CVEIntelligenceManager> =
    LazyLock::new(CVEIntelligenceManager::new);

/// Globais do módulo Python (`cache = HexStrikeCache()` e
/// `telemetry = TelemetryCollector()`): moram em `_state.rs` (o `_state.py` do
/// split) e são reexportados aqui para preservar a superfície do módulo.
pub use crate::_state::{cache, telemetry};


