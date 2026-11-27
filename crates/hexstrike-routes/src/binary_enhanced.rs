//! Port 1:1 de `hexstrike_server/routes/binary_enhanced.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W8.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    19  def ghidra
//!    59  def pwntools
//!   134  def one_gadget
//!   160  def libc_database
//!   201  def gdb_peda
//!   263  def angr
//!   354  def ropper
//!   401  def pwninit
//! ```
//!
//! Rotas (`@app.route`) deste módulo (8):
//!
//! ```text
//!    18  ghidra("/api/tools/ghidra", methods=["POST"])
//!    58  pwntools("/api/tools/pwntools", methods=["POST"])
//!   133  one_gadget("/api/tools/one-gadget", methods=["POST"])
//!   159  libc_database("/api/tools/libc-database", methods=["POST"])
//!   200  gdb_peda("/api/tools/gdb-peda", methods=["POST"])
//!   262  angr("/api/tools/angr", methods=["POST"])
//!   353  ropper("/api/tools/ropper", methods=["POST"])
//!   400  pwninit("/api/tools/pwninit", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

// ---------------------------------------------------------------------------
// Auxiliares: o Python repete estes trechos em cada handler.
// `params = request.json` é `Json<Value>`; corpo que não seja objeto vira
// dict vazio (o Python levantaria AttributeError -> 500; divergência
// documentada, o harness sempre envia `{}`).
// ---------------------------------------------------------------------------

/// Truthiness do Python (`if valor:`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Valor JSON como o f-string do Python o formata (`str()`).
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        // `repr` de float sempre traz o `.0` (5000.0), como no Python.
        Value::Number(n) if n.is_f64() => {
            format!("{:?}", n.as_f64().unwrap_or(0.0))
        }
        Value::Number(n) => n.to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

/// `params.get(chave, padrao)` — valor usado no comando sem condição.
fn p_str(params: &Map<String, Value>, key: &str, default: &str) -> String {
    params.get(key).map(py_str).unwrap_or_else(|| default.to_string())
}

/// `valor = params.get(chave, padrao)` seguido do `if valor:` do Python.
/// `None` significa que o Python não entra no `if` (valor falso).
fn p_if(params: &Map<String, Value>, key: &str, default: Value) -> Option<String> {
    let v = params.get(key).cloned().unwrap_or(default);
    if truthy(&v) {
        Some(py_str(&v))
    } else {
        None
    }
}

/// `@app.route("/api/tools/ghidra", methods=["POST"])` — `def ghidra()`.
pub async fn ghidra(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let project_name = p_str(&params, "project_name", "hexstrike_analysis");

    if binary.is_empty() {
        warn!("🔧 Ghidra called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    // Create Ghidra project directory
    let project_dir = format!("/tmp/ghidra_projects/{project_name}");
    if let Err(e) = std::fs::create_dir_all(&project_dir) {
        error!("💥 Error in ghidra endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    // O Python monta `analyzeHeadless ...` e chama
    // `execute_command(command, timeout=analysis_timeout)`, mas
    // `execute_command` só aceita `(command, use_cache)` — o `timeout=`
    // levantou TypeError antes de qualquer execução, e o `except` converte
    // isso no 500 abaixo. Reproduzido 1:1 (ver relatório do shard W8).
    let mensagem =
        "execute_command() got an unexpected keyword argument 'timeout'";
    info!("🔧 Starting Ghidra analysis: {binary}");
    error!("💥 Error in ghidra endpoint: {mensagem}");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {mensagem}")})),
    ))
}

/// `@app.route("/api/tools/pwntools", methods=["POST"])` — `def pwntools()`.
pub async fn pwntools(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let script_content = p_if(&params, "script_content", json!(""));
    let target_binary = p_str(&params, "target_binary", "");
    let target_host = p_str(&params, "target_host", "");
    let target_port = p_str(&params, "target_port", "0");
    let exploit_type = p_str(&params, "exploit_type", "local");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if script_content.is_none() && target_binary.is_empty() {
        warn!("🔧 Pwntools called without script content or target binary");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Script content or target binary is required"})),
        ));
    }

    // Create temporary Python script
    let script_file = "/tmp/pwntools_exploit.py";

    let conteudo = match &script_content {
        // Use provided script content
        Some(script_content) => script_content.clone(),
        // Generate basic exploit template
        None => format!(
"#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f\"Started local process: {{binary}}\")
elif host and port:
    p = remote(host, port)
    log.info(f\"Connected to {{host}}:{{port}}\")
else:
    log.error(\"No target specified\")
    exit(1)

# Basic interaction
p.interactive()
"
        ),
    };

    if let Err(e) = std::fs::write(script_file, conteudo) {
        error!("💥 Error in pwntools endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    let mut command = format!("python3 {script_file}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting Pwntools exploit: {exploit_type}");
    let result = execute_command(&command, true).await;

    // Cleanup
    let _ = std::fs::remove_file(script_file);

    info!("📊 Pwntools exploit completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/one-gadget", methods=["POST"])` — `def one_gadget()`.
pub async fn one_gadget(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let libc_path = p_str(&params, "libc_path", "");
    let level = p_str(&params, "level", "1");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if libc_path.is_empty() {
        warn!("🔧 one_gadget called without libc_path parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "libc_path parameter is required"})),
        ));
    }

    let mut command = format!("one_gadget {libc_path} --level {level}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting one_gadget analysis: {libc_path}");
    let result = execute_command(&command, true).await;
    info!("📊 one_gadget analysis completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/libc-database", methods=["POST"])`.
pub async fn libc_database(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let action = p_str(&params, "action", "find");
    let symbols = p_if(&params, "symbols", json!(""));
    let libc_id = p_if(&params, "libc_id", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if action == "find" && symbols.is_none() {
        warn!("🔧 libc-database find called without symbols");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Symbols parameter is required for find action"})),
        ));
    }

    if matches!(action.as_str(), "dump" | "download") && libc_id.is_none() {
        warn!("🔧 libc-database called without libc_id for dump/download");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "libc_id parameter is required for dump/download actions"})),
        ));
    }

    // Navigate to libc-database directory (assuming it's installed)
    let base_command = "cd /opt/libc-database 2>/dev/null || \
cd ~/libc-database 2>/dev/null || echo 'libc-database not found'";

    let mut command = match action.as_str() {
        "find" => format!(
            "{base_command} && ./find {}",
            symbols.as_deref().unwrap_or("")
        ),
        "dump" => format!(
            "{base_command} && ./dump {}",
            libc_id.as_deref().unwrap_or("")
        ),
        "download" => format!(
            "{base_command} && ./download {}",
            libc_id.as_deref().unwrap_or("")
        ),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid action: {action}")})),
            ));
        }
    };

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    // f"... {action}: {symbols or libc_id}" — `or` do Python
    let alvo = symbols.as_deref().or(libc_id.as_deref()).unwrap_or("None");
    info!("🔧 Starting libc-database {action}: {alvo}");
    let result = execute_command(&command, true).await;
    info!("📊 libc-database {action} completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/gdb-peda", methods=["POST"])` — `def gdb_peda()`.
pub async fn gdb_peda(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let commands = p_if(&params, "commands", json!(""));
    // `attach_pid` sem default (0) para o `target_info`; e com a truthiness
    // do Python para o `if attach_pid:` que emite ` -p {attach_pid}`.
    let attach_pid_raw = p_str(&params, "attach_pid", "0");
    let attach_pid = p_if(&params, "attach_pid", json!(0));
    let core_file = p_if(&params, "core_file", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() && attach_pid.is_none() && core_file.is_none() {
        warn!("🔧 GDB-PEDA called without binary, PID, or core file");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary, PID, or core file parameter is required"})),
        ));
    }

    // Base GDB command with PEDA
    let mut command = "gdb -q".to_string();

    if !binary.is_empty() {
        command += &format!(" {binary}");
    }

    if let Some(core_file) = &core_file {
        command += &format!(" {core_file}");
    }

    if let Some(attach_pid) = &attach_pid {
        command += &format!(" -p {attach_pid}");
    }

    // Create command script
    if let Some(commands) = &commands {
        let temp_script = "/tmp/gdb_peda_commands.txt";
        let peda_commands =
            format!("\nsource ~/peda/peda.py\n{commands}\nquit\n");
        if let Err(e) = std::fs::write(temp_script, peda_commands) {
            error!("💥 Error in gdb-peda endpoint: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Server error: {e}")})),
            ));
        }
        command += &format!(" -x {temp_script}");
    } else {
        // Default PEDA initialization
        command += " -ex 'source ~/peda/peda.py' -ex 'quit'";
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    // `binary or f'PID {attach_pid}' or core_file` — o f-string é sempre
    // verdadeiro, então `core_file` nunca vence (mantido 1:1).
    let target_info = if binary.is_empty() {
        format!("PID {attach_pid_raw}")
    } else {
        binary.clone()
    };

    info!("🔧 Starting GDB-PEDA analysis: {target_info}");
    let result = execute_command(&command, true).await;

    // Cleanup
    if commands.is_some() {
        let _ = std::fs::remove_file("/tmp/gdb_peda_commands.txt");
    }

    info!("📊 GDB-PEDA analysis completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/angr", methods=["POST"])` — `def angr()`.
pub async fn angr(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let script_content = p_if(&params, "script_content", json!(""));
    let find_address = p_str(&params, "find_address", "");
    let avoid_addresses = p_str(&params, "avoid_addresses", "");
    let analysis_type = p_str(&params, "analysis_type", "symbolic");

    if binary.is_empty() {
        warn!("🔧 angr called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    // Create angr script
    let script_file = "/tmp/angr_analysis.py";

    let conteudo = match &script_content {
        Some(script_content) => script_content.clone(),
        // Generate basic angr template
        None => {
            let mut template = format!(
"#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f\"Loaded binary: {binary}\")
print(f\"Architecture: {{project.arch}}\")
print(f\"Entry point: {{hex(project.entry)}}\")

"
            );
            if analysis_type == "symbolic" {
                // f-string do Python: os `{{ }}` viram `{ }` literais.
                let find_addr = if find_address.is_empty() {
                    "None".to_string()
                } else {
                    find_address.clone()
                };
                let avoid_addrs = if avoid_addresses.is_empty() {
                    "[]".to_string()
                } else {
                    // `avoid_addresses.split(',')` -> repr da lista do Python
                    let itens: Vec<String> = avoid_addresses
                        .split(',')
                        .map(|item| format!("'{item}'"))
                        .collect();
                    format!("[{}]", itens.join(", "))
                };
                // O `f"""` do Python começa com uma linha vazia ("\n").
                template += &format!(
"
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_addr}
avoid_addrs = {avoid_addrs}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print(\"Found solution!\")
        solution_state = simgr.found[0]
        print(f\"Input: {{solution_state.posix.dumps(0)}}\")
    else:
        print(\"No solution found\")
else:
    print(\"No find address specified, running basic analysis\")
"
                );
            } else if analysis_type == "cfg" {
                // Bloco sem f-string no Python: chaves ficam literais.
                template += "\n# Control Flow Graph analysis\n\
cfg = project.analyses.CFGFast()\n\
print(f\"CFG nodes: {len(cfg.graph.nodes())}\")\n\
print(f\"CFG edges: {len(cfg.graph.edges())}\")\n\
\n\
# Function analysis\n\
for func_addr, func in cfg.functions.items():\n\
    print(f\"Function: {func.name} at {hex(func_addr)}\")\n";
            }
            template
        }
    };

    if let Err(e) = std::fs::write(script_file, conteudo) {
        error!("💥 Error in angr endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    // O Python chama `execute_command(command, timeout=600)`; `execute_command`
    // não aceita `timeout=`, então o TypeError vira 500 antes de executar —
    // inclusive antes do `os.remove(script_file)` do finally. Reproduzido 1:1.
    let mensagem =
        "execute_command() got an unexpected keyword argument 'timeout'";
    info!("🔧 Starting angr analysis: {binary}");
    error!("💥 Error in angr endpoint: {mensagem}");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {mensagem}")})),
    ))
}

/// `@app.route("/api/tools/ropper", methods=["POST"])` — `def ropper()`.
pub async fn ropper(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let gadget_type = p_str(&params, "gadget_type", "rop");
    let quality = params.get("quality").cloned().unwrap_or(json!(1));
    let arch = p_if(&params, "arch", json!(""));
    let search_string = p_if(&params, "search_string", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 ropper called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command = format!("ropper --file {binary}");

    match gadget_type.as_str() {
        "rop" => command += " --rop",
        "jop" => command += " --jop",
        "sys" => command += " --sys",
        "all" => command += " --all",
        _ => {}
    }

    // `if quality > 1:` — comparação numérica (valor não numérico seria
    // TypeError -> 500 no Python; aqui conta como falso, ver relatório).
    if quality.as_f64().map(|q| q > 1.0).unwrap_or(false) {
        command += &format!(" --quality {}", py_str(&quality));
    }

    if let Some(arch) = &arch {
        command += &format!(" --arch {arch}");
    }

    if let Some(search_string) = &search_string {
        command += &format!(" --search '{search_string}'");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting ropper analysis: {binary}");
    let result = execute_command(&command, true).await;
    info!("📊 ropper analysis completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/pwninit", methods=["POST"])` — `def pwninit()`.
pub async fn pwninit(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let binary = p_str(&params, "binary", "");
    let libc = p_if(&params, "libc", json!(""));
    let ld = p_if(&params, "ld", json!(""));
    let template_type = p_if(&params, "template_type", json!("python"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if binary.is_empty() {
        warn!("🔧 pwninit called without binary parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary parameter is required"})),
        ));
    }

    let mut command = format!("pwninit --bin {binary}");

    if let Some(libc) = &libc {
        command += &format!(" --libc {libc}");
    }

    if let Some(ld) = &ld {
        command += &format!(" --ld {ld}");
    }

    if let Some(template_type) = &template_type {
        command += &format!(" --template {template_type}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔧 Starting pwninit setup: {binary}");
    let result = execute_command(&command, true).await;
    info!("📊 pwninit setup completed");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/ghidra", post(ghidra))
        .route("/api/tools/pwntools", post(pwntools))
        .route("/api/tools/one-gadget", post(one_gadget))
        .route("/api/tools/libc-database", post(libc_database))
        .route("/api/tools/gdb-peda", post(gdb_peda))
        .route("/api/tools/angr", post(angr))
        .route("/api/tools/ropper", post(ropper))
        .route("/api/tools/pwninit", post(pwninit))
}
