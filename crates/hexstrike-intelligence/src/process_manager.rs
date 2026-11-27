//! Port 1:1 de `hexstrike_server/intelligence/process_manager.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W5.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    25  class ProcessPool:
//!   233  class AdvancedCache:
//!   356  class EnhancedProcessManager:
//!   571  class ResourceMonitor:
//!   651  class PerformanceDashboard:
//! ```
//!
//! Globais do módulo (`_registry.py`): `tech_detector`, `rate_limiter`,
//! `failure_recovery`, `performance_monitor`, `parameter_optimizer`,
//! `enhanced_process_manager`, `ctf_manager`, `ctf_tools`, `ctf_automator`,
//! `ctf_coordinator`.
//!
//! Observações de port:
//!
//! - `ctf_manager`/`ctf_tools` (`intelligence/ctf.py`) e
//!   `ctf_automator`/`ctf_coordinator` (`intelligence/ctf_automation.py`)
//!   NÃO estão aqui: os dois módulos são stubs do shard W6 e as classes
//!   (`CTFWorkflowManager`, `CTFToolManager`, `CTFChallengeAutomator`,
//!   `CTFTeamCoordinator`) ainda não existem no crate. As 4 linhas finais do
//!   `process_manager.py` entram quando o W6 chegar.
//! - Onde o Python usa um `threading.Lock`/`RLock` por objeto, o port usa um
//!   `Mutex` que já contém o estado protegido (mesma granularidade: os campos
//!   mutáveis `self.process_pool`, `self.cache`, etc. são `&self`).
//! - `psutil` -> `sysinfo`/`/proc` (mesmo critério de `vuln_intel.rs`).
//! - `subprocess.Popen(..., shell=True)` -> `sh -c` com `std::process::Command`
//!   (threads do pool são threads de SO, como no Python). `preexec_fn=os.setsid`
//!   não tem equivalente sem `libc`.
//! - `hash(str)` do Python é salteado por processo (`PYTHONHASHSEED`): a chave
//!   de cache e o sufixo do `task_id` são hashes do Rust — só a IDENTIDADE
//!   (mesma string -> mesma chave) é observável, e o `task_id` é volátil por
//!   construção (`int(time.time() * 1000)`).

use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sysinfo::System;
use tracing::{debug, error, info, warn};

use crate::ctf::{CTFToolManager, CTFWorkflowManager};
use crate::ctf_automation::{CTFChallengeAutomator, CTFTeamCoordinator};

use super::param_optimizer::{
    FailureRecoverySystem, ParameterOptimizer, PerformanceMonitor, RateLimitDetector,
    TechnologyDetector,
};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// `hash(command)` — identidade estável por string (ver nota do cabeçalho).
fn py_hash(command: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);
    hasher.finish()
}

/// `if not value:` do Python (usado em `context`/`use_cache`).
fn py_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Leitura de `/proc/<pid>` (equivalente de `psutil.Process`).
fn proc_stat(pid: u32) -> Option<(u64, u64, char)> {
    // (rss_pages, num_threads, state)
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // o `comm` pode conter espaços/parenteses: parse a partir do último ')'
    let rest = &raw[raw.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state; fields[17] = num_threads; fields[21] = rss
    let state = fields.first()?.chars().next()?;
    let num_threads = fields.get(17)?.parse().ok()?;
    let rss = fields.get(21)?.parse().ok()?;
    Some((rss, num_threads, state))
}

fn page_size() -> u64 {
    // `sysconf(_SC_PAGESIZE)` == 4096 nas plataformas do harness
    4096
}

/// `psutil.Process.status()` a partir do estado de `/proc/<pid>/stat`.
fn proc_status_name(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk-sleep",
        'T' => "stopped",
        't' => "tracing-stop",
        'Z' => "zombie",
        'X' | 'x' => "dead",
        'W' => "waking",
        'K' => "wake-kill",
        'P' => "parked",
        'I' => "idle",
        _ => "?",
    }
}

/// Envia um sinal via `kill(1)`.
fn send_signal(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// `psutil.cpu_percent()` sem intervalo, com o `System` do laço (uso desde o
/// refresh anterior).
fn cpu_usage_since_last_refresh(system: &mut System) -> f64 {
    system.refresh_cpu_usage();
    system.global_cpu_usage() as f64
}

/// `psutil.virtual_memory().percent`, com o `System` do laço.
fn mem_usage(system: &mut System) -> f64 {
    system.refresh_memory();
    let total = system.total_memory() as f64;
    if total > 0.0 {
        system.used_memory() as f64 / total * 100.0
    } else {
        0.0
    }
}

// ============================================================================
// ADVANCED PROCESS MANAGEMENT AND MONITORING (v10.0 ENHANCEMENT)
// ============================================================================

/// Tarefa do pool. No Python `submit_task(task_id, func, *args, **kwargs)`
/// carrega o callable; o único call site é
/// `EnhancedProcessManager.execute_command_async`, que passa sempre
/// `self._execute_command_internal(command, context or {})` — então o port
/// guarda só os argumentos.
struct Task {
    id: String,
    command: String,
    context: Value,
    submitted_at: f64,
    status: String,
}

/// O estado protegido por `self.pool_lock` no Python.
struct PoolState {
    workers: Vec<std::thread::JoinHandle<()>>,
    results: HashMap<String, Value>,
    active_tasks: HashMap<String, Value>,
    performance_metrics: Value,
}

struct PoolInner {
    /// `self.pool_lock`
    pool_lock: Mutex<PoolState>,
    /// `self.task_queue` (`queue.Queue`); `None` = sinal de shutdown.
    task_queue: Mutex<VecDeque<Option<Task>>>,
    task_queue_ready: Condvar,
}

/// `class ProcessPool:` — pool de processos com auto-scaling.
#[derive(Clone)]
pub struct ProcessPool {
    pub min_workers: usize,
    pub max_workers: usize,
    scale_threshold: f64,
    inner: Arc<PoolInner>,
}

impl ProcessPool {
    pub fn new(min_workers: usize, max_workers: usize, scale_threshold: f64) -> Self {
        let pool = Self {
            min_workers,
            max_workers,
            scale_threshold,
            inner: Arc::new(PoolInner {
                pool_lock: Mutex::new(PoolState {
                    workers: Vec::new(),
                    results: HashMap::new(),
                    active_tasks: HashMap::new(),
                    performance_metrics: json!({
                        "tasks_completed": 0,
                        "tasks_failed": 0,
                        "avg_task_time": 0.0,
                        "cpu_usage": 0.0,
                        "memory_usage": 0.0,
                    }),
                }),
                task_queue: Mutex::new(VecDeque::new()),
                task_queue_ready: Condvar::new(),
            }),
        };

        // Initialize minimum workers
        pool._scale_up(pool.min_workers);

        // Start monitoring thread
        let monitor = pool.clone();
        std::thread::spawn(move || monitor._monitor_performance());

        pool
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.inner.pool_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `self.task_queue.qsize()`
    fn queue_size(&self) -> usize {
        self.inner
            .task_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// `submit_task(task_id, func, *args, **kwargs)`
    pub fn submit_task(&self, task_id: &str, command: &str, context: &Value) -> String {
        let submitted_at = now_secs();
        let task = Task {
            id: task_id.to_string(),
            command: command.to_string(),
            context: context.clone(),
            submitted_at,
            status: "queued".to_string(),
        };

        {
            let mut state = self.lock();
            state.active_tasks.insert(
                task_id.to_string(),
                json!({
                    "id": &task.id,
                    "command": &task.command,
                    "context": &task.context,
                    "submitted_at": task.submitted_at,
                    "status": &task.status,
                }),
            );
            let mut queue = self
                .inner
                .task_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            queue.push_back(Some(task));
        }
        self.inner.task_queue_ready.notify_one();

        info!("📋 Task submitted to pool: {task_id}");
        task_id.to_string()
    }

    /// `get_task_result(task_id)`
    pub fn get_task_result(&self, task_id: &str) -> Value {
        let state = self.lock();
        if let Some(result) = state.results.get(task_id) {
            return result.clone();
        }
        if let Some(task) = state.active_tasks.get(task_id) {
            return json!({
                "status": task.get("status").cloned().unwrap_or(json!("unknown")),
                "result": Value::Null,
            });
        }
        json!({"status": "not_found", "result": Value::Null})
    }

    /// `_worker_thread(worker_id)` — thread de SO, como no Python.
    fn _worker_thread(inner: Arc<PoolInner>, worker_id: usize) {
        info!("🔧 Process pool worker {worker_id} started");

        loop {
            // `task = self.task_queue.get(timeout=30)`
            let popped: Option<Option<Task>> = {
                let mut queue = inner.task_queue.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if let Some(item) = queue.pop_front() {
                        break Some(item);
                    }
                    let (guard, wait) = inner
                        .task_queue_ready
                        .wait_timeout(queue, Duration::from_secs(30))
                        .unwrap_or_else(|e| e.into_inner());
                    queue = guard;
                    if wait.timed_out() {
                        // queue.Empty: no tasks available, continue waiting
                        break None;
                    }
                }
            };

            let task = match popped {
                None => continue,
                Some(None) => break, // shutdown signal
                Some(Some(task)) => task,
            };

            let task_id = task.id.clone();
            let start_time = now_secs();

            // Update task status
            {
                let mut state = inner.pool_lock.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(active) = state
                    .active_tasks
                    .get_mut(&task_id)
                    .and_then(|v| v.as_object_mut())
                {
                    active.insert("status".to_string(), json!("running"));
                    active.insert("worker_id".to_string(), json!(worker_id));
                    active.insert("started_at".to_string(), json!(start_time));
                }
            }

            // Execute task (`self._execute_command_internal`) — nunca levanta:
            // o `except Exception` do worker é inalcançável no Python também.
            let result = enhanced_process_manager._execute_command_internal(&task.command, &task.context);

            // Store result
            let execution_time = now_secs() - start_time;
            {
                let mut state = inner.pool_lock.lock().unwrap_or_else(|e| e.into_inner());
                state.results.insert(
                    task_id.clone(),
                    json!({
                        "status": "completed",
                        "result": result,
                        "execution_time": execution_time,
                        "worker_id": worker_id,
                        "completed_at": now_secs(),
                    }),
                );

                // Update performance metrics
                if let Some(metrics) = state.performance_metrics.as_object_mut() {
                    let tasks_completed = metrics
                        .get("tasks_completed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        + 1;
                    let avg_task_time = metrics
                        .get("avg_task_time")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    metrics.insert("tasks_completed".to_string(), json!(tasks_completed));
                    metrics.insert(
                        "avg_task_time".to_string(),
                        json!(
                            (avg_task_time * (tasks_completed - 1) as f64 + execution_time)
                                / tasks_completed as f64
                        ),
                    );
                }

                // Remove from active tasks
                state.active_tasks.remove(&task_id);
            }

            info!("✅ Task completed: {task_id} in {execution_time:.2}s");
            // `self.task_queue.task_done()`: só faz sentido com `join()`, que
            // ninguém chama no Python.
        }
    }

    /// `_monitor_performance()` — monitora e faz auto-scaling a cada 10s.
    fn _monitor_performance(&self) {
        // No Python cada iteração faz `try/except`: um erro de `psutil` só loga.
        // Aqui o `System` é único (precisa do refresh anterior para a medição
        // de CPU); se ele não subir, o monitor para.
        let mut system = match System::new() {
            Ok(s) => s,
            Err(e) => {
                error!("💥 Pool monitor error: {e}");
                return;
            }
        };

        loop {
            std::thread::sleep(Duration::from_secs(10)); // Monitor every 10 seconds

            let (queue_size, active_workers, active_tasks_count) = {
                let state = self.lock();
                let active_workers = state.workers.iter().filter(|w| !w.is_finished()).count();
                (self.queue_size(), active_workers, state.active_tasks.len())
            };

            // Calculate load metrics
            let load_ratio = if active_workers > 0 {
                (active_tasks_count + queue_size) as f64 / active_workers as f64
            } else {
                f64::INFINITY
            };

            // Auto-scaling logic
            if load_ratio > self.scale_threshold && active_workers < self.max_workers {
                // Scale up
                let new_workers = 2.min(self.max_workers - active_workers);
                self._scale_up(new_workers);
                info!(
                    "📈 Scaled up process pool: +{new_workers} workers (total: {})",
                    active_workers + new_workers
                );
            } else if load_ratio < 0.3 && active_workers > self.min_workers {
                // Scale down
                let workers_to_remove = 1.min(active_workers - self.min_workers);
                self._scale_down(workers_to_remove);
                info!(
                    "📉 Scaled down process pool: -{workers_to_remove} workers (total: {})",
                    active_workers - workers_to_remove
                );
            }

            // Update performance metrics
            let cpu_percent = cpu_usage_since_last_refresh(&mut system);
            let memory_usage = mem_usage(&mut system);

            let mut state = self.lock();
            if let Some(metrics) = state.performance_metrics.as_object_mut() {
                metrics.insert("cpu_usage".to_string(), json!(cpu_percent));
                metrics.insert("memory_usage".to_string(), json!(memory_usage));
            }
        }
    }

    /// `_scale_up(count)`
    pub fn _scale_up(&self, count: usize) {
        let mut state = self.lock();
        for _ in 0..count {
            let worker_id = state.workers.len();
            let inner = self.inner.clone();
            let worker = std::thread::spawn(move || ProcessPool::_worker_thread(inner, worker_id));
            state.workers.push(worker);
        }
    }

    /// `_scale_down(count)`
    pub fn _scale_down(&self, count: usize) {
        let mut state = self.lock();
        for _ in 0..count {
            if state.workers.len() > self.min_workers {
                // Signal worker to shutdown by putting None in queue
                self.inner
                    .task_queue
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push_back(None);
                self.inner.task_queue_ready.notify_one();
                // Remove from workers list (worker will exit naturally)
                state.workers.pop();
            }
        }
    }

    /// `get_pool_stats()`
    pub fn get_pool_stats(&self) -> Value {
        let state = self.lock();
        let active_workers = state.workers.iter().filter(|w| !w.is_finished()).count();
        json!({
            "active_workers": active_workers,
            "queue_size": self.queue_size(),
            "active_tasks": state.active_tasks.len(),
            "performance_metrics": state.performance_metrics.clone(),
            "min_workers": self.min_workers,
            "max_workers": self.max_workers,
        })
    }
}

// ============================================================================
// ADVANCED CACHE
// ============================================================================

struct CacheState {
    cache: HashMap<String, Value>,
    access_times: HashMap<String, f64>,
    ttl_times: HashMap<String, f64>,
    hit_count: u64,
    miss_count: u64,
}

/// `_remove_key(key)`
fn remove_key(state: &mut CacheState, key: &str) {
    state.cache.remove(key);
    state.access_times.remove(key);
    state.ttl_times.remove(key);
}

/// `_evict_lru()` — `min(access_times, key=...)` (primeiro mínimo em caso de
/// empate, como no Python).
fn evict_lru(state: &mut CacheState) {
    let Some(lru_key) = state
        .access_times
        .iter()
        .fold(None::<(&String, &f64)>, |acc, (k, v)| match acc {
            Some((_, best)) if *best <= *v => acc,
            _ => Some((k, v)),
        })
        .map(|(k, _)| k.clone())
    else {
        return;
    };

    remove_key(state, &lru_key);
    debug!("🗑️ Evicted LRU cache entry: {lru_key}");
}

/// `_cleanup_expired()` — thread de limpeza (1 minuto).
fn cleanup_expired(inner: Arc<Mutex<CacheState>>) {
    loop {
        std::thread::sleep(Duration::from_secs(60)); // Cleanup every minute
        let current_time = now_secs();
        let mut expired_keys: Vec<String> = Vec::new();

        {
            let state = inner.lock().unwrap_or_else(|e| e.into_inner());
            for (key, expiry_time) in state.ttl_times.iter() {
                if *expiry_time <= current_time {
                    expired_keys.push(key.clone());
                }
            }
        }

        {
            let mut state = inner.lock().unwrap_or_else(|e| e.into_inner());
            for key in &expired_keys {
                remove_key(&mut state, key);
            }
        }

        if !expired_keys.is_empty() {
            debug!(
                "🧹 Cleaned up {} expired cache entries",
                expired_keys.len()
            );
        }
    }
}

/// `class AdvancedCache:` — cache com TTL inteligente e evicção LRU.
#[derive(Clone)]
pub struct AdvancedCache {
    pub max_size: usize,
    pub default_ttl: i64,
    inner: Arc<Mutex<CacheState>>,
}

impl AdvancedCache {
    pub fn new(max_size: usize, default_ttl: i64) -> Self {
        let cache = Self {
            max_size,
            default_ttl,
            inner: Arc::new(Mutex::new(CacheState {
                cache: HashMap::new(),
                access_times: HashMap::new(),
                ttl_times: HashMap::new(),
                hit_count: 0,
                miss_count: 0,
            })),
        };

        // Start cleanup thread
        let inner = cache.inner.clone();
        std::thread::spawn(move || cleanup_expired(inner));

        cache
    }

    fn lock(&self) -> MutexGuard<'_, CacheState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `get(key)`
    pub fn get(&self, key: &str) -> Option<Value> {
        let mut state = self.lock();
        let current_time = now_secs();

        let not_expired = match state.ttl_times.get(key) {
            None => true,
            Some(expiry) => *expiry > current_time,
        };

        // Check if key exists and is not expired
        if state.cache.contains_key(key) && not_expired {
            // Update access time for LRU
            state.access_times.insert(key.to_string(), current_time);
            state.hit_count += 1;
            return state.cache.get(key).cloned();
        }

        // Cache miss or expired
        if state.cache.contains_key(key) {
            // Remove expired entry
            remove_key(&mut state, key);
        }

        state.miss_count += 1;
        None
    }

    /// `set(key, value, ttl=None)`
    pub fn set(&self, key: &str, value: Value, ttl: Option<i64>) {
        let mut state = self.lock();
        let current_time = now_secs();

        // Use default TTL if not specified
        let ttl = ttl.unwrap_or(self.default_ttl);

        // Check if we need to evict entries
        if state.cache.len() >= self.max_size && !state.cache.contains_key(key) {
            evict_lru(&mut state);
        }

        // Set the value
        state.cache.insert(key.to_string(), value);
        state.access_times.insert(key.to_string(), current_time);
        state.ttl_times.insert(key.to_string(), current_time + ttl as f64);
    }

    /// `delete(key)`
    pub fn delete(&self, key: &str) -> bool {
        let mut state = self.lock();
        if state.cache.contains_key(key) {
            remove_key(&mut state, key);
            return true;
        }
        false
    }

    /// `clear()`
    pub fn clear(&self) {
        let mut state = self.lock();
        state.cache.clear();
        state.access_times.clear();
        state.ttl_times.clear();
    }

    /// `get_stats()` — MESMOS tipos do dict Python (`hit_rate` é `int` quando
    /// não houve requisições).
    pub fn get_stats(&self) -> Value {
        let state = self.lock();
        let total_requests = state.hit_count + state.miss_count;
        let hit_rate = if total_requests > 0 {
            json!(state.hit_count as f64 / total_requests as f64 * 100.0)
        } else {
            json!(0)
        };

        json!({
            "size": state.cache.len(),
            "max_size": self.max_size,
            "hit_count": state.hit_count,
            "miss_count": state.miss_count,
            "hit_rate": hit_rate,
            "utilization": state.cache.len() as f64 / self.max_size as f64 * 100.0,
        })
    }
}

// ============================================================================
// ENHANCED PROCESS MANAGER
// ============================================================================

/// Entrada de `self.process_registry` (o `Popen` do Python não cabe no JSON e
/// os sinais vão por `kill(1)` no pid).
pub struct ProcessRegistryEntry {
    pub command: String,
    pub start_time: f64,
    pub context: Value,
    pub status: String,
}

/// `class EnhancedProcessManager:` — gerenciamento avançado com alocação
/// inteligente de recursos.
pub struct EnhancedProcessManager {
    pub process_pool: ProcessPool,
    pub cache: AdvancedCache,
    pub resource_monitor: ResourceMonitor,
    /// `self.process_registry` + `self.registry_lock` (Mutex já contém o dict).
    process_registry: Mutex<HashMap<u32, ProcessRegistryEntry>>,
    pub performance_dashboard: PerformanceDashboard,
    /// Declarados no `__init__` do Python e nunca usados no módulo.
    pub termination_handlers: Mutex<Value>,
    pub recovery_strategies: Mutex<Value>,
    /// `self.auto_scaling_enabled` (a rota `/api/process/auto-scaling` escreve).
    pub auto_scaling_enabled: AtomicBool,
    /// `self.resource_thresholds` (a mesma rota faz `.update(thresholds)`).
    pub resource_thresholds: Mutex<Map<String, Value>>,
}

impl EnhancedProcessManager {
    pub fn new() -> Self {
        let manager = Self {
            process_pool: ProcessPool::new(4, 32, 0.8),
            cache: AdvancedCache::new(2000, 1800), // 30 minutes default TTL
            resource_monitor: ResourceMonitor::new(100),
            process_registry: Mutex::new(HashMap::new()),
            performance_dashboard: PerformanceDashboard::new(),
            termination_handlers: Mutex::new(json!({})),
            recovery_strategies: Mutex::new(json!({})),
            auto_scaling_enabled: AtomicBool::new(true),
            resource_thresholds: Mutex::new(Map::from_iter([
                ("cpu_high".to_string(), json!(85.0)),
                ("memory_high".to_string(), json!(90.0)),
                ("disk_high".to_string(), json!(95.0)),
                ("load_high".to_string(), json!(0.8)),
            ])),
        };

        // Start background monitoring
        std::thread::spawn(EnhancedProcessManager::_monitor_system);

        manager
    }

    fn threshold(&self, key: &str) -> f64 {
        self.resource_thresholds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
    }

    /// `execute_command_async(command, context=None)` — devolve o `task_id`
    /// (ou o RESULTADO cacheado, como o Python, que é `Union[str, dict]`).
    pub fn execute_command_async(&self, command: &str, context: &Value) -> Value {
        let task_id = format!(
            "cmd_{}_{}",
            (now_secs() * 1000.0) as u64,
            py_hash(command) % 10000
        );

        // Check cache first
        let cache_key = format!("cmd_result_{}", py_hash(command));
        let cached_result = self.cache.get(&cache_key);
        if let Some(cached_result) = cached_result {
            let use_cache = match context.get("use_cache") {
                None => true,
                other => py_truthy(other),
            };
            if py_truthy(Some(context)) && use_cache {
                info!(
                    "📋 Using cached result for command: {}...",
                    hexstrike_core::visual_engine::py_truncate(command, 50)
                );
                return cached_result;
            }
        }

        // Submit to process pool (`context or {}`)
        let context = if py_truthy(Some(context)) {
            context.clone()
        } else {
            json!({})
        };
        self.process_pool.submit_task(&task_id, command, &context);

        json!(task_id)
    }

    /// `_execute_command_internal(command, context)`
    pub fn _execute_command_internal(&self, command: &str, context: &Value) -> Value {
        let start_time = now_secs();
        let mut command = command.to_string();

        // Resource-aware execution
        let resource_usage = self.resource_monitor.get_current_usage();

        // Adjust command based on resource availability
        if resource_usage
            .get("cpu_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
            > self.threshold("cpu_high")
        {
            // Add nice priority for CPU-intensive commands
            if !command.starts_with("nice") {
                command = format!("nice -n 10 {command}");
            }
        }

        // Execute command (`subprocess.Popen(..., shell=True)`)
        let child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let child = match child {
            Ok(child) => child,
            // `except Exception as e`
            Err(e) => return self.execution_error(&command, &e.to_string(), start_time),
        };
        let pid = child.id();

        // Register process
        self.process_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                pid,
                ProcessRegistryEntry {
                    command: command.clone(),
                    start_time,
                    context: context.clone(),
                    status: "running".to_string(),
                },
            );

        // Monitor process execution (`process.communicate()`)
        let result = match child.wait_with_output() {
            Ok(output) => {
                let execution_time = now_secs() - start_time;
                let return_code = output.status.code().unwrap_or(-1);
                json!({
                    "success": return_code == 0,
                    "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
                    "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
                    "return_code": return_code,
                    "execution_time": execution_time,
                    "pid": pid,
                    "resource_usage": self.resource_monitor.get_process_usage(pid),
                })
            }
            Err(e) => self.execution_error(&command, &e.to_string(), start_time),
        };

        // Cache successful results
        let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let cache_result = match context.get("cache_result") {
            None => true,
            other => py_truthy(other),
        };
        if success && cache_result {
            let cache_key = format!("cmd_result_{}", py_hash(&command));
            // 30 minutes default
            let cache_ttl = context
                .get("cache_ttl")
                .and_then(|v| v.as_i64())
                .unwrap_or(1800);
            self.cache.set(&cache_key, result.clone(), Some(cache_ttl));
        }

        // Update performance metrics
        self.performance_dashboard.record_execution(&command, &result);

        // `finally:` — Cleanup process registry
        self.process_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&pid);

        result
    }

    /// Corpo do `except Exception as e:` de `_execute_command_internal`.
    fn execution_error(&self, command: &str, message: &str, start_time: f64) -> Value {
        let execution_time = now_secs() - start_time;
        let error_result = json!({
            "success": false,
            "stdout": "",
            "stderr": message,
            "return_code": -1,
            "execution_time": execution_time,
            "error": message,
        });

        self.performance_dashboard.record_execution(command, &error_result);
        error_result
    }

    /// `get_task_result(task_id)`
    pub fn get_task_result(&self, task_id: &str) -> Value {
        self.process_pool.get_task_result(task_id)
    }

    /// `terminate_process_gracefully(pid, timeout=30)`
    pub fn terminate_process_gracefully(&self, pid: u32, timeout: u64) -> bool {
        let mut registry = self.process_registry.lock().unwrap_or_else(|e| e.into_inner());
        let Some(process_info) = registry.get_mut(&pid) else {
            return false;
        };

        // Try graceful termination first (`process.terminate()`)
        send_signal(pid, "TERM");

        // Wait for graceful termination (`process.wait(timeout=timeout)`)
        let deadline = Instant::now() + Duration::from_secs(timeout);
        loop {
            if !process_alive(pid) {
                process_info.status = "terminated_gracefully".to_string();
                info!("✅ Process {pid} terminated gracefully");
                return true;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Force kill if graceful termination fails (`subprocess.TimeoutExpired`)
        send_signal(pid, "KILL");
        process_info.status = "force_killed".to_string();
        warn!("⚠️ Process {pid} force killed after timeout");
        true
    }

    /// `_monitor_system()` — monitora recursos e faz auto-scaling a cada 15s.
    /// O Python amarra o thread ao `self`; aqui ele lê o singleton do módulo
    /// (o `LazyLock` já está inicializado quando o primeiro `sleep` termina).
    fn _monitor_system() {
        loop {
            std::thread::sleep(Duration::from_secs(15)); // Monitor every 15 seconds

            let manager = &*enhanced_process_manager;

            // Get current resource usage
            let resource_usage = manager.resource_monitor.get_current_usage();

            // Auto-scaling based on resource usage
            if manager.auto_scaling_enabled.load(Ordering::SeqCst) {
                manager._auto_scale_based_on_resources(&resource_usage);
            }

            // Update performance dashboard
            manager.performance_dashboard.update_system_metrics(&resource_usage);
        }
    }

    /// `_auto_scale_based_on_resources(resource_usage)`
    fn _auto_scale_based_on_resources(&self, resource_usage: &Value) {
        let pool_stats = self.process_pool.get_pool_stats();
        let current_workers = pool_stats
            .get("active_workers")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let cpu_percent = resource_usage
            .get("cpu_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let memory_percent = resource_usage
            .get("memory_percent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        // Scale down if resources are constrained
        if cpu_percent > self.threshold("cpu_high") || memory_percent > self.threshold("memory_high") {
            if current_workers > self.process_pool.min_workers {
                self.process_pool._scale_down(1);
                info!(
                    "📉 Auto-scaled down due to high resource usage: CPU {cpu_percent:.1}%, Memory {memory_percent:.1}%"
                );
            }
        } else if cpu_percent < 60.0
            && memory_percent < 70.0
            && pool_stats
                .get("queue_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 2
        {
            // Scale up if resources are available and there's demand
            if current_workers < self.process_pool.max_workers {
                self.process_pool._scale_up(1);
                info!("📈 Auto-scaled up due to available resources and demand");
            }
        }
    }

    /// `get_comprehensive_stats()`
    pub fn get_comprehensive_stats(&self) -> Value {
        json!({
            "process_pool": self.process_pool.get_pool_stats(),
            "cache": self.cache.get_stats(),
            "resource_usage": self.resource_monitor.get_current_usage(),
            "active_processes": self
                .process_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            "performance_dashboard": self.performance_dashboard.get_summary(),
            "auto_scaling_enabled": self.auto_scaling_enabled.load(Ordering::SeqCst),
            "resource_thresholds": Value::Object(
                self.resource_thresholds
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            ),
        })
    }
}

impl Default for EnhancedProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RESOURCE MONITOR
// ============================================================================

/// `class ResourceMonitor:` — monitoramento com histórico.
pub struct ResourceMonitor {
    pub history_size: usize,
    usage_history: Mutex<Vec<Value>>,
}

impl ResourceMonitor {
    pub fn new(history_size: usize) -> Self {
        Self {
            history_size,
            usage_history: Mutex::new(Vec::new()),
        }
    }

    /// `get_current_usage()`
    ///
    /// O `except Exception` do Python devolve zeros: as leituras do port
    /// (`sysinfo`/`/proc`) devolvem 0 no pior caso em vez de levantar.
    pub fn get_current_usage(&self) -> Value {
        let cpu_percent = super::param_optimizer::cpu_percent_interval_1();
        let memory_percent = super::param_optimizer::memory_percent();
        let memory_available_gb = super::param_optimizer::memory_available_gb();
        let (disk_percent, free_bytes) = super::param_optimizer::disk_usage_root();
        let disk_free_gb = free_bytes / 1024f64.powi(3);
        let (bytes_sent, bytes_recv) = super::param_optimizer::net_io_counters();

        let usage = json!({
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "memory_available_gb": memory_available_gb,
            "disk_percent": disk_percent,
            "disk_free_gb": disk_free_gb,
            "network_bytes_sent": bytes_sent,
            "network_bytes_recv": bytes_recv,
            "timestamp": now_secs(),
        });

        // Add to history
        {
            let mut history = self.usage_history.lock().unwrap_or_else(|e| e.into_inner());
            history.push(usage.clone());
            if history.len() > self.history_size {
                history.remove(0);
            }
        }

        usage
    }

    /// `get_process_usage(pid)`
    pub fn get_process_usage(&self, pid: u32) -> Value {
        let Some((rss_pages, num_threads, state)) = proc_stat(pid) else {
            // `except (psutil.NoSuchProcess, psutil.AccessDenied): return {}`
            return json!({});
        };

        let total_mem = super::param_optimizer::total_memory_bytes() as f64;
        let rss = (rss_pages * page_size()) as f64;

        json!({
            // `psutil.Process.cpu_percent()` sem intervalo == primeira chamada
            // (0.0) — não há estado por processo no port.
            "cpu_percent": 0.0,
            "memory_percent": if total_mem > 0.0 { rss / total_mem * 100.0 } else { 0.0 },
            "memory_rss_mb": rss / 1024f64.powi(2),
            "num_threads": num_threads,
            "status": proc_status_name(state),
        })
    }

    /// `get_usage_trends()`
    pub fn get_usage_trends(&self) -> Value {
        let history = self.usage_history.lock().unwrap_or_else(|e| e.into_inner());
        if history.len() < 2 {
            return json!({});
        }

        let recent = &history[history.len().saturating_sub(10)..]; // Last 10 measurements

        let cpu_trend = recent
            .iter()
            .map(|u| u.get("cpu_percent").and_then(|v| v.as_f64()).unwrap_or(0.0))
            .sum::<f64>()
            / recent.len() as f64;
        let memory_trend = recent
            .iter()
            .map(|u| u.get("memory_percent").and_then(|v| v.as_f64()).unwrap_or(0.0))
            .sum::<f64>()
            / recent.len() as f64;

        json!({
            "cpu_avg_10": cpu_trend,
            "memory_avg_10": memory_trend,
            "measurements": history.len(),
            // 15 second intervals
            "trend_period_minutes": recent.len() as f64 * 15.0 / 60.0,
        })
    }
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new(100)
    }
}

// ============================================================================
// PERFORMANCE DASHBOARD
// ============================================================================

struct DashState {
    execution_history: Vec<Value>,
    system_metrics: Vec<Value>,
}

/// `class PerformanceDashboard:` — dashboard de performance em tempo real.
pub struct PerformanceDashboard {
    inner: Mutex<DashState>,
    pub max_history: usize,
}

impl PerformanceDashboard {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DashState {
                execution_history: Vec::new(),
                system_metrics: Vec::new(),
            }),
            max_history: 1000,
        }
    }

    /// `record_execution(command, result)`
    pub fn record_execution(&self, command: &str, result: &Value) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let execution_record = json!({
            // Truncate long commands
            "command": hexstrike_core::visual_engine::py_truncate(command, 100),
            "success": result.get("success").cloned().unwrap_or(json!(false)),
            "execution_time": result.get("execution_time").cloned().unwrap_or(json!(0)),
            "return_code": result.get("return_code").cloned().unwrap_or(json!(-1)),
            "timestamp": now_secs(),
        });

        state.execution_history.push(execution_record);
        if state.execution_history.len() > self.max_history {
            state.execution_history.remove(0);
        }
    }

    /// `update_system_metrics(metrics)`
    pub fn update_system_metrics(&self, metrics: &Value) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.system_metrics.push(metrics.clone());
        if state.system_metrics.len() > self.max_history {
            state.system_metrics.remove(0);
        }
    }

    /// `get_summary()`
    pub fn get_summary(&self) -> Value {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.execution_history.is_empty() {
            return json!({"executions": 0});
        }

        let recent_executions = &state.execution_history[state.execution_history.len().saturating_sub(100)..];

        let total_executions = recent_executions.len();
        let successful_executions = recent_executions
            .iter()
            .filter(|e| e.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();
        let avg_execution_time = recent_executions
            .iter()
            .map(|e| e.get("execution_time").and_then(|v| v.as_f64()).unwrap_or(0.0))
            .sum::<f64>()
            / total_executions as f64;

        json!({
            "total_executions": state.execution_history.len(),
            "recent_executions": total_executions,
            "success_rate": successful_executions as f64 / total_executions as f64 * 100.0,
            "avg_execution_time": avg_execution_time,
            "system_metrics_count": state.system_metrics.len(),
        })
    }
}

impl Default for PerformanceDashboard {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global instances
// ============================================================================

#[allow(non_upper_case_globals)]
pub static tech_detector: LazyLock<TechnologyDetector> = LazyLock::new(TechnologyDetector::new);

#[allow(non_upper_case_globals)]
pub static rate_limiter: LazyLock<RateLimitDetector> = LazyLock::new(RateLimitDetector::new);

#[allow(non_upper_case_globals)]
pub static failure_recovery: LazyLock<FailureRecoverySystem> =
    LazyLock::new(FailureRecoverySystem::new);

#[allow(non_upper_case_globals)]
pub static performance_monitor: LazyLock<PerformanceMonitor> =
    LazyLock::new(PerformanceMonitor::new);

#[allow(non_upper_case_globals)]
pub static parameter_optimizer: LazyLock<ParameterOptimizer> =
    LazyLock::new(ParameterOptimizer::new);

#[allow(non_upper_case_globals)]
pub static enhanced_process_manager: LazyLock<EnhancedProcessManager> =
    LazyLock::new(EnhancedProcessManager::new);

// ---------------------------------------------------------------------------
// Global CTF framework instances (`process_manager.py:711-714`)
//
// O `_registry.py` atribui estes quatro singletons a ESTE módulo; as classes
// moram em `intelligence/ctf.rs` e `intelligence/ctf_automation.rs` (shard
// W6). Sem `Mutex` porque nenhum método dos managers muda o objeto (só
// `&self`) — diferente de `cache`/`telemetry`, que mutam.
// ---------------------------------------------------------------------------


#[allow(non_upper_case_globals)]
pub static ctf_manager: LazyLock<CTFWorkflowManager> = LazyLock::new(CTFWorkflowManager::new);

#[allow(non_upper_case_globals)]
pub static ctf_tools: LazyLock<CTFToolManager> = LazyLock::new(CTFToolManager::new);

#[allow(non_upper_case_globals)]
pub static ctf_automator: LazyLock<CTFChallengeAutomator> = LazyLock::new(CTFChallengeAutomator::new);

#[allow(non_upper_case_globals)]
pub static ctf_coordinator: LazyLock<CTFTeamCoordinator> = LazyLock::new(CTFTeamCoordinator::new);
