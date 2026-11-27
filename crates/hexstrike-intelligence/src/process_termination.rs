//! Port 1:1 de `hexstrike_server/intelligence/process_termination.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W5.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    25  class ProcessManager:
//!   154  class PythonEnvironmentManager:
//! ```
//!
//! Globais do módulo (`_registry.py`): `active_processes`, `process_lock`,
//! `ProcessManager`, `PythonEnvironmentManager`, `env_manager`.
//!
//! Observações de port:
//!
//! - `active_processes` é um `Mutex<HashMap>`: em Rust o lock mora junto do
//!   dado, então `process_lock` (o `threading.Lock` do Python) não é um global
//!   à parte — [`process_lock`] devolve o guard do dict, e os `with
//!   process_lock:` do Python viram `let mut procs = process_lock();`.
//! - O valor `"process"` de cada entrada guarda o `Popen` do Python, que não é
//!   serializável: no port é um [`std::process::Child`] e NÃO entra no JSON
//!   ([`ActiveProcess::to_json`]). Com o registro vazio (o caso real), a
//!   resposta é idêntica ao Python; com processo registrado o Python
//!   respondería 500 (`jsonify` de um `Popen`).
//! - `SIGSTOP`/`SIGCONT`/`SIGTERM`/`SIGKILL` via `kill(1)`, mesmo critério já
//!   usado em `vuln_intel.rs`.
//! - `venv.create(..., with_pip=True)` -> `python3 -m venv <path>`;
//!   `install_package`/`get_python_path`/`create_venv` são `async` (rodam
//!   subprocesso) — no Python são bloqueantes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use crate::vuln_intel::ProgressHook;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// `active_processes = {}`  # pid -> process info
#[allow(non_upper_case_globals)]
pub static active_processes: LazyLock<Mutex<HashMap<u32, ActiveProcess>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `process_lock = threading.Lock()` — o guard do dict `active_processes`
/// (ver nota do cabeçalho).
pub fn process_lock() -> MutexGuard<'static, HashMap<u32, ActiveProcess>> {
    active_processes.lock().unwrap_or_else(|e| e.into_inner())
}

/// Uma entrada de `active_processes` (o dict por pid do Python).
pub struct ActiveProcess {
    pub pid: u32,
    pub command: String,
    pub process: Option<std::process::Child>,
    pub start_time: f64,
    pub status: String,
    pub progress: f64,
    pub last_output: String,
    pub bytes_processed: usize,
    /// `runtime` existe depois do primeiro `update_process_progress`.
    pub runtime: Option<f64>,
    /// `eta` idem.
    pub eta: Option<f64>,
}

impl ActiveProcess {
    /// A parte serializável da entrada (o `Popen` do Python não sobrevive ao
    /// `jsonify`).
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("pid".to_string(), json!(self.pid));
        map.insert("command".to_string(), Value::String(self.command.clone()));
        map.insert("start_time".to_string(), json!(self.start_time));
        map.insert("status".to_string(), Value::String(self.status.clone()));
        map.insert("progress".to_string(), json!(self.progress));
        map.insert(
            "last_output".to_string(),
            Value::String(self.last_output.clone()),
        );
        map.insert("bytes_processed".to_string(), json!(self.bytes_processed));
        if let Some(runtime) = self.runtime {
            map.insert("runtime".to_string(), json!(runtime));
        }
        if let Some(eta) = self.eta {
            map.insert("eta".to_string(), json!(eta));
        }
        Value::Object(map)
    }
}

/// Envia um sinal via `kill(1)` (equivalente de `os.kill`/`Popen.terminate`).
fn send_signal(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// `class ProcessManager:` — gerenciamento de processos para terminação e
/// monitoramento (v5.0). Os métodos são `staticmethod` no Python.
pub struct ProcessManager;

impl ProcessManager {
    // Cores de `ModernVisualEngine` que, no split, ficaram como ATRIBUTOS DA
    // CLASSE (bloco indentado depois de `return False`, ver o cabeçalho de
    // `process_termination.py`). Mantidas aqui pelo mesmo motivo: pertencem a
    // `ProcessManager`.
    pub const BG_GREEN: &'static str = "\u{1b}[42m";
    pub const BG_YELLOW: &'static str = "\u{1b}[43m";
    pub const BG_BLUE: &'static str = "\u{1b}[44m";
    pub const BG_MAGENTA: &'static str = "\u{1b}[45m";
    pub const BG_CYAN: &'static str = "\u{1b}[46m";
    pub const BG_WHITE: &'static str = "\u{1b}[47m";
    pub const DIM: &'static str = "\u{1b}[2m";
    pub const UNDERLINE: &'static str = "\u{1b}[4m";
    pub const BLINK: &'static str = "\u{1b}[5m";
    pub const REVERSE: &'static str = "\u{1b}[7m";
    pub const STRIKETHROUGH: &'static str = "\u{1b}[9m";

    /// `register_process(pid, command, process_obj)`
    pub fn register_process(pid: u32, command: &str, process_obj: Option<std::process::Child>) {
        let mut procs = process_lock();
        procs.insert(
            pid,
            ActiveProcess {
                pid,
                command: command.to_string(),
                process: process_obj,
                start_time: now_secs(),
                status: "running".to_string(),
                progress: 0.0,
                last_output: String::new(),
                bytes_processed: 0,
                runtime: None,
                eta: None,
            },
        );
        info!(
            "🆔 REGISTERED: Process {pid} - {}...",
            hexstrike_core::visual_engine::py_truncate(command, 50)
        );
    }

    /// `update_process_progress(pid, progress, last_output="",
    /// bytes_processed=0)`
    pub fn update_process_progress(
        pid: u32,
        progress: f64,
        last_output: &str,
        bytes_processed: usize,
    ) {
        let mut procs = process_lock();
        if let Some(process_info) = procs.get_mut(&pid) {
            process_info.progress = progress;
            process_info.last_output = last_output.to_string();
            process_info.bytes_processed = bytes_processed;
            let runtime = now_secs() - process_info.start_time;

            // Calculate ETA if progress > 0
            let mut eta = 0.0;
            if progress > 0.0 {
                eta = (runtime / progress) * (1.0 - progress);
            }

            process_info.runtime = Some(runtime);
            process_info.eta = Some(eta);
        }
    }

    /// `terminate_process(pid)`
    pub fn terminate_process(pid: u32) -> bool {
        let mut procs = process_lock();
        if let Some(process_info) = procs.get_mut(&pid) {
            let running = matches!(
                process_info.process.as_mut().map(|p| p.try_wait()),
                Some(Ok(None))
            );
            if running {
                send_signal(pid, "TERM");
                std::thread::sleep(Duration::from_secs(1));
                // Force kill if still running
                if matches!(process_info.process.as_mut().map(|p| p.try_wait()), Some(Ok(None))) {
                    if let Some(child) = process_info.process.as_mut() {
                        let _ = child.kill();
                    }
                }

                process_info.status = "terminated".to_string();
                warn!(
                    "🛑 TERMINATED: Process {pid} - {}...",
                    hexstrike_core::visual_engine::py_truncate(&process_info.command, 50)
                );
                return true;
            }
            return false;
        }
        false
    }

    /// `cleanup_process(pid)`
    pub fn cleanup_process(pid: u32) -> Option<ActiveProcess> {
        let mut procs = process_lock();
        let process_info = procs.remove(&pid);
        if process_info.is_some() {
            info!("🧹 CLEANUP: Process {pid} removed from registry");
        }
        process_info
    }

    /// `get_process_status(pid)`
    pub fn get_process_status(pid: u32) -> Option<Value> {
        let procs = process_lock();
        procs.get(&pid).map(|info| info.to_json())
    }

    /// `list_active_processes()`
    pub fn list_active_processes() -> Value {
        let procs = process_lock();
        let mut map = Map::new();
        for (pid, info) in procs.iter() {
            map.insert(pid.to_string(), info.to_json());
        }
        Value::Object(map)
    }

    /// `pause_process(pid)` — (SIGSTOP)
    pub fn pause_process(pid: u32) -> bool {
        let mut procs = process_lock();
        if let Some(process_info) = procs.get_mut(&pid) {
            if matches!(process_info.process.as_mut().map(|p| p.try_wait()), Some(Ok(None))) {
                send_signal(pid, "STOP");
                process_info.status = "paused".to_string();
                info!("⏸️  PAUSED: Process {pid}");
                return true;
            }
        }
        false
    }

    /// `resume_process(pid)` — (SIGCONT)
    pub fn resume_process(pid: u32) -> bool {
        let mut procs = process_lock();
        if let Some(process_info) = procs.get_mut(&pid) {
            if matches!(process_info.process.as_mut().map(|p| p.try_wait()), Some(Ok(None))) {
                send_signal(pid, "CONT");
                process_info.status = "running".to_string();
                info!("▶️  RESUMED: Process {pid}");
                return true;
            }
        }
        false
    }
}

/// Hook real do `EnhancedCommandExecutor` (substitui `NoopHook`): o executor
/// do Python chama `ProcessManager.register_process` /
/// `update_process_progress` / `cleanup_process` — exatamente os três eventos
/// de [`ProgressHook`]. O `process_obj` do Python não atravessa o trait
/// (registra `None`).
impl ProgressHook for ProcessManager {
    fn register_process(&self, pid: u32, command: &str) {
        ProcessManager::register_process(pid, command, None);
    }

    fn update_progress(&self, pid: u32, progress: f64, message: &str, bytes_processed: usize) {
        ProcessManager::update_process_progress(pid, progress, message, bytes_processed);
    }

    fn cleanup_process(&self, pid: u32) {
        ProcessManager::cleanup_process(pid);
    }
}

/// `Arc<dyn ProgressHook>` pronto para o `EnhancedCommandExecutor::with_hook`
/// (`exploit_gen::execute_command` ainda constrói com `NoopHook`: o call site
/// é de outro shard).
pub fn progress_hook() -> std::sync::Arc<dyn ProgressHook> {
    std::sync::Arc::new(ProcessManager)
}

/// `class PythonEnvironmentManager:` — venvs e dependências.
pub struct PythonEnvironmentManager {
    pub base_dir: PathBuf,
}

impl PythonEnvironmentManager {
    pub fn new(base_dir: &str) -> Self {
        let base_dir = PathBuf::from(base_dir);
        // `self.base_dir.mkdir(exist_ok=True)` — no Python não há log/except:
        // um erro aqui levanta na importação do módulo.
        let _ = std::fs::create_dir_all(&base_dir);
        Self { base_dir }
    }

    /// `create_venv(env_name)`
    pub async fn create_venv(&self, env_name: &str) -> PathBuf {
        let env_path = self.base_dir.join(env_name);
        if !env_path.exists() {
            info!("🐍 Creating virtual environment: {env_name}");
            // `venv.create(env_path, with_pip=True)`
            let _ = tokio::process::Command::new("python3")
                .arg("-m")
                .arg("venv")
                .arg(&env_path)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
        env_path
    }

    /// `install_package(env_name, package)`
    pub async fn install_package(&self, env_name: &str, package: &str) -> bool {
        let env_path = self.create_venv(env_name).await;
        let pip_path = env_path.join("bin").join("pip");

        let child = tokio::process::Command::new(&pip_path)
            .arg("install")
            .arg(package)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let result = match child {
            Ok(child) => {
                match tokio::time::timeout(Duration::from_secs(300), child.wait_with_output()).await {
                    Ok(Ok(output)) => Some(output),
                    Ok(Err(e)) => {
                        error!("💥 Error installing package {package}: {e}");
                        return false;
                    }
                    Err(_elapsed) => {
                        // `subprocess.TimeoutExpired` -> `except Exception`
                        error!(
                            "💥 Error installing package {package}: Command '{}' timed out after 300 seconds",
                            pip_path.display()
                        );
                        return false;
                    }
                }
            }
            Err(e) => {
                error!("💥 Error installing package {package}: {e}");
                return false;
            }
        };

        let Some(output) = result else {
            return false;
        };
        if output.status.code() == Some(0) {
            info!("📦 Installed package {package} in {env_name}");
            true
        } else {
            error!(
                "❌ Failed to install {package}: {}",
                String::from_utf8_lossy(&output.stderr).trim_end()
            );
            false
        }
    }

    /// `get_python_path(env_name)`
    pub async fn get_python_path(&self, env_name: &str) -> String {
        let env_path = self.create_venv(env_name).await;
        env_path.join("bin").join("python").display().to_string()
    }
}

impl Default for PythonEnvironmentManager {
    fn default() -> Self {
        Self::new("/tmp/hexstrike_envs")
    }
}

/// `env_manager = PythonEnvironmentManager()`
#[allow(non_upper_case_globals)]
pub static env_manager: LazyLock<PythonEnvironmentManager> =
    LazyLock::new(|| PythonEnvironmentManager::new("/tmp/hexstrike_envs"));
