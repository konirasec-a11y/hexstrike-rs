//! Port 1:1 de `hexstrike_server/core.py`.
//!
//! - `logging.basicConfig(...)` (stdout + hexstrike.log com fallback) -> [`init`]
//! - `logger` global -> macros `tracing`
//! - `app = Flask(__name__)` -> [`app`] (axum; ordem de montagem em `routes`)
//! - `API_PORT` / `API_HOST` -> statics; `set_global` do `_state.py` -> [`RuntimeConfig`]
//!
//! `COMMAND_TIMEOUT`, `CACHE_SIZE` e `CACHE_TTL` NÃO moram aqui: o
//! `_registry.py` do split os atribui a `intelligence/vuln_intel.py`.

use std::fmt;
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex};
use std::sync::{LazyLock, RwLock};
use time::OffsetDateTime;
use tracing::Level;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::{Layer as _, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// Timestamp no formato `%(asctime)s` do Python: `2026-11-26 17:52:03,123`
/// (hora local; fallback UTC se o tz database não estiver disponível).
#[derive(Clone, Copy, Default)]
pub struct PyAsctime;

impl FormatTime for PyAsctime {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let fmt = time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second],[subsecond digits:3]"
        );
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        write!(w, "{}", now.format(&fmt).unwrap_or_default())
    }
}

/// Formato `%(asctime)s - %(name)s - %(levelname)s - %(message)s`.
struct PyLogFormat;

impl<S, N> FormatEvent<S, N> for PyLogFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        PyAsctime.format_time(&mut writer)?;
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        let name = meta.module_path().unwrap_or("hexstrike");
        write!(writer, " - {name} - {level} - ")?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Writer para o arquivo de log (equivalente do `FileHandler('hexstrike.log')`).
struct FileMakeWriter(Arc<Mutex<File>>);

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for FileMakeWriter {
    type Writer = FileGuard;

    fn make_writer(&self) -> Self::Writer {
        FileGuard(self.0.clone())
    }
}

struct FileGuard(Arc<Mutex<File>>);

impl io::Write for FileGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

/// Inicializa o logging global. Chamar ANTES de qualquer outro código
/// ("MUST BE FIRST", igual ao monólito).
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // FileHandler('hexstrike.log') com fallback console-only (PermissionError)
    match File::options().create(true).append(true).open("hexstrike.log") {
        Ok(file) => {
            let stdout_layer = tracing_subscriber::fmt::layer()
                .event_format(PyLogFormat)
                .with_writer(std::io::stdout)
                .boxed();
            let file_layer = tracing_subscriber::fmt::layer()
                .event_format(PyLogFormat)
                .with_writer(FileMakeWriter(Arc::new(Mutex::new(file))))
                .boxed();
            tracing_subscriber::registry().with(filter).with(stdout_layer).with(file_layer).init();
        }
        Err(_) => {
            // Fallback 1:1 do `except PermissionError`
            let stdout_layer = tracing_subscriber::fmt::layer()
                .event_format(PyLogFormat)
                .with_writer(std::io::stdout)
                .boxed();
            tracing_subscriber::registry().with(filter).with(stdout_layer).init();
        }
    }
}

/// `API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))`
pub static API_PORT: LazyLock<u16> = LazyLock::new(|| {
    std::env::var("HEXSTRIKE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8888)
});

/// `API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')`
pub static API_HOST: LazyLock<&'static str> = LazyLock::new(|| {
    std::env::var("HEXSTRIKE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()).leak()
});

/// `DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")`
fn env_debug_mode() -> bool {
    matches!(
        std::env::var("DEBUG_MODE").unwrap_or_else(|_| "0".to_string()).to_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

/// `COMMAND_TIMEOUT = 300`
/// Estado mutável global — equivalente 1:1 do `_state.set_global(name, value)`,
/// que no split Python rebindava `DEBUG_MODE`/`API_PORT` em todos os módulos
/// (semântica de global do monólito original).
pub struct RuntimeConfig {
    debug_mode: RwLock<bool>,
    api_port: RwLock<u16>,
}

impl RuntimeConfig {
    fn new() -> Self {
        Self { debug_mode: RwLock::new(env_debug_mode()), api_port: RwLock::new(*API_PORT) }
    }

    /// `set_global('DEBUG_MODE', True)` (main.py: `if args.debug:`)
    pub fn set_debug_mode(&self, value: bool) {
        *self.debug_mode.write().unwrap() = value;
        info!("DEBUG_MODE set to {}", value);
    }

    /// `set_global('API_PORT', args.port)` (main.py: `if args.port != API_PORT:`)
    pub fn set_api_port(&self, port: u16) {
        *self.api_port.write().unwrap() = port;
        info!("API_PORT set to {}", port);
    }

    pub fn debug_mode(&self) -> bool {
        *self.debug_mode.read().unwrap()
    }

    pub fn api_port(&self) -> u16 {
        *self.api_port.read().unwrap()
    }
}

static RUNTIME: LazyLock<RuntimeConfig> = LazyLock::new(RuntimeConfig::new);

/// Acesso ao estado runtime global (equivalente dos globals do monólito).
pub fn runtime() -> &'static RuntimeConfig {
    &RUNTIME
}

/// `API_HOST` atual (equivalente do acesso direto ao global).
pub fn api_host() -> &'static str {
    *API_HOST
}

/// `DEBUG_MODE` atual (respeita `--debug` em runtime).
pub fn debug_mode() -> bool {
    runtime().debug_mode()
}

/// `API_PORT` atual (respeita `--port` em runtime).
pub fn api_port() -> u16 {
    runtime().api_port()
}

