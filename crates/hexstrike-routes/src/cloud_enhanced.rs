//! Port 1:1 de `hexstrike_server/routes/cloud_enhanced.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W8.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  def scout_suite
//!    60  def cloudmapper
//!    93  def pacu
//!   145  def kube_hunter
//!   189  def kube_bench
//!   225  def docker_bench_security
//!   258  def clair
//!   292  def falco
//!   325  def checkov
//!   362  def terrascan
//!   396  def dirb
//!   426  def nikto
//!   455  def sqlmap
//!   488  def metasploit
//!   532  def hydra
//!   584  def john
//!   623  def wpscan
//!   652  def enum4linux
//!   678  def ffuf
//!   721  def netexec
//!   767  def amass
//!   802  def hashcat
//!   846  def subfinder
//!   883  def smbmap
//! ```
//!
//! Rotas (`@app.route`) deste módulo (24):
//!
//! ```text
//!    19  scout_suite("/api/tools/scout-suite", methods=["POST"])
//!    59  cloudmapper("/api/tools/cloudmapper", methods=["POST"])
//!    92  pacu("/api/tools/pacu", methods=["POST"])
//!   144  kube_hunter("/api/tools/kube-hunter", methods=["POST"])
//!   188  kube_bench("/api/tools/kube-bench", methods=["POST"])
//!   224  docker_bench_security("/api/tools/docker-bench-security", methods=["POST"])
//!   257  clair("/api/tools/clair", methods=["POST"])
//!   291  falco("/api/tools/falco", methods=["POST"])
//!   324  checkov("/api/tools/checkov", methods=["POST"])
//!   361  terrascan("/api/tools/terrascan", methods=["POST"])
//!   395  dirb("/api/tools/dirb", methods=["POST"])
//!   425  nikto("/api/tools/nikto", methods=["POST"])
//!   454  sqlmap("/api/tools/sqlmap", methods=["POST"])
//!   487  metasploit("/api/tools/metasploit", methods=["POST"])
//!   531  hydra("/api/tools/hydra", methods=["POST"])
//!   583  john("/api/tools/john", methods=["POST"])
//!   622  wpscan("/api/tools/wpscan", methods=["POST"])
//!   651  enum4linux("/api/tools/enum4linux", methods=["POST"])
//!   677  ffuf("/api/tools/ffuf", methods=["POST"])
//!   720  netexec("/api/tools/netexec", methods=["POST"])
//!   766  amass("/api/tools/amass", methods=["POST"])
//!   801  hashcat("/api/tools/hashcat", methods=["POST"])
//!   845  subfinder("/api/tools/subfinder", methods=["POST"])
//!   882  smbmap("/api/tools/smbmap", methods=["POST"])
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

/// `flag = params.get(chave, padrao)` usado como booleano (Python truthiness).
fn p_bool(params: &Map<String, Value>, key: &str, default: bool) -> bool {
    params.get(key).map(truthy).unwrap_or(default)
}

/// `@app.route("/api/tools/scout-suite", methods=["POST"])`.
pub async fn scout_suite(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let provider = p_str(&params, "provider", "aws");
    let profile = p_if(&params, "profile", json!("default"));
    let report_dir = p_str(&params, "report_dir", "/tmp/scout-suite");
    let services = p_if(&params, "services", json!(""));
    let exceptions = p_if(&params, "exceptions", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    // Ensure report directory exists
    if let Err(e) = std::fs::create_dir_all(&report_dir) {
        error!("💥 Error in scout-suite endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    let mut command = format!("scout {provider}");

    // if profile and provider == "aws":
    if let Some(profile) = &profile {
        if provider == "aws" {
            command += &format!(" --profile {profile}");
        }
    }

    if let Some(services) = &services {
        command += &format!(" --services {services}");
    }

    if let Some(exceptions) = &exceptions {
        command += &format!(" --exceptions {exceptions}");
    }

    command += &format!(" --report-dir {report_dir}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting Scout Suite {provider} assessment");
    let mut result = execute_command(&command, true).await;
    // result["report_directory"] = report_dir
    if let Some(obj) = result.as_object_mut() {
        obj.insert("report_directory".to_string(), json!(report_dir));
    }
    info!("📊 Scout Suite assessment completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/cloudmapper", methods=["POST"])`.
pub async fn cloudmapper(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let action = p_str(&params, "action", "collect");
    let account = p_if(&params, "account", json!(""));
    let config = p_if(&params, "config", json!("config.json"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if account.is_none() && action != "webserver" {
        warn!("☁️  CloudMapper called without account parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Account parameter is required for most actions"})),
        ));
    }

    let mut command = format!("cloudmapper {action}");

    if let Some(account) = &account {
        command += &format!(" --account {account}");
    }

    if let Some(config) = &config {
        command += &format!(" --config {config}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting CloudMapper {action}");
    let result = execute_command(&command, true).await;
    info!("📊 CloudMapper {action} completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/pacu", methods=["POST"])` — `def pacu()`.
pub async fn pacu(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let session_name = p_str(&params, "session_name", "hexstrike_session");
    let modules = p_if(&params, "modules", json!(""));
    let data_services = p_if(&params, "data_services", json!(""));
    let regions = p_if(&params, "regions", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    // Create Pacu command sequence
    let mut commands: Vec<String> = vec![format!("set_session {session_name}")];

    if let Some(data_services) = &data_services {
        commands.push(format!("data {data_services}"));
    }

    if let Some(regions) = &regions {
        commands.push(format!("set_regions {regions}"));
    }

    if let Some(modules) = &modules {
        for module in modules.split(',') {
            commands.push(format!("run {}", module.trim()));
        }
    }

    commands.push("exit".to_string());

    // Create command file
    let command_file = "/tmp/pacu_commands.txt";
    if let Err(e) = std::fs::write(command_file, commands.join("\n")) {
        error!("💥 Error in pacu endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    let mut command = format!("pacu < {command_file}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting Pacu AWS exploitation");
    let result = execute_command(&command, true).await;

    // Cleanup
    let _ = std::fs::remove_file(command_file);

    info!("📊 Pacu exploitation completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/kube-hunter", methods=["POST"])`.
pub async fn kube_hunter(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_if(&params, "target", json!(""));
    let remote = p_if(&params, "remote", json!(""));
    let cidr = p_if(&params, "cidr", json!(""));
    let interface = p_if(&params, "interface", json!(""));
    let active = p_bool(&params, "active", false);
    let report = p_if(&params, "report", json!("json"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = "kube-hunter".to_string();

    if let Some(target) = &target {
        command += &format!(" --remote {target}");
    } else if let Some(remote) = &remote {
        command += &format!(" --remote {remote}");
    } else if let Some(cidr) = &cidr {
        command += &format!(" --cidr {cidr}");
    } else if let Some(interface) = &interface {
        command += &format!(" --interface {interface}");
    } else {
        // Default to pod scanning
        command += " --pod";
    }

    if active {
        command += " --active";
    }

    if let Some(report) = &report {
        command += &format!(" --report {report}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting kube-hunter Kubernetes scan");
    let result = execute_command(&command, true).await;
    info!("📊 kube-hunter scan completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/kube-bench", methods=["POST"])`.
pub async fn kube_bench(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let targets = p_if(&params, "targets", json!(""));
    let version = p_if(&params, "version", json!(""));
    let config_dir = p_if(&params, "config_dir", json!(""));
    let output_format = p_if(&params, "output_format", json!("json"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = "kube-bench".to_string();

    if let Some(targets) = &targets {
        command += &format!(" --targets {targets}");
    }

    if let Some(version) = &version {
        command += &format!(" --version {version}");
    }

    if let Some(config_dir) = &config_dir {
        command += &format!(" --config-dir {config_dir}");
    }

    if let Some(output_format) = &output_format {
        command += &format!(
            " --outputfile /tmp/kube-bench-results.{output_format} --json"
        );
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("☁️  Starting kube-bench CIS benchmark");
    let result = execute_command(&command, true).await;
    info!("📊 kube-bench benchmark completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/docker-bench-security", methods=["POST"])`.
pub async fn docker_bench_security(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let checks = p_if(&params, "checks", json!(""));
    let exclude = p_if(&params, "exclude", json!(""));
    let output_file =
        p_str(&params, "output_file", "/tmp/docker-bench-results.json");
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = "docker-bench-security".to_string();

    if let Some(checks) = &checks {
        command += &format!(" -c {checks}");
    }

    if let Some(exclude) = &exclude {
        command += &format!(" -e {exclude}");
    }

    // `if output_file:` — o default é verdadeiro, então só um `""` explícito
    // do cliente remove o `-l`.
    if !output_file.is_empty() {
        command += &format!(" -l {output_file}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🐳 Starting Docker Bench Security assessment");
    let mut result = execute_command(&command, true).await;
    // result["output_file"] = output_file (incondicional no Python)
    if let Some(obj) = result.as_object_mut() {
        obj.insert("output_file".to_string(), json!(output_file));
    }
    info!("📊 Docker Bench Security completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/clair", methods=["POST"])` — `def clair()`.
pub async fn clair(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let image = p_str(&params, "image", "");
    let config = p_if(&params, "config", json!("/etc/clair/config.yaml"));
    let output_format = p_if(&params, "output_format", json!("json"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if image.is_empty() {
        warn!("🐳 Clair called without image parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Image parameter is required"})),
        ));
    }

    // Use clairctl for scanning
    let mut command = format!("clairctl analyze {image}");

    if let Some(config) = &config {
        command += &format!(" --config {config}");
    }

    if let Some(output_format) = &output_format {
        command += &format!(" --format {output_format}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🐳 Starting Clair vulnerability scan: {image}");
    let result = execute_command(&command, true).await;
    info!("📊 Clair scan completed for {image}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/falco", methods=["POST"])` — `def falco()`.
pub async fn falco(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let config_file = p_if(&params, "config_file", json!("/etc/falco/falco.yaml"));
    let rules_file = p_if(&params, "rules_file", json!(""));
    let output_format = p_if(&params, "output_format", json!("json"));
    let duration = p_str(&params, "duration", "60");
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = format!("timeout {duration} falco");

    if let Some(config_file) = &config_file {
        command += &format!(" --config {config_file}");
    }

    if let Some(rules_file) = &rules_file {
        command += &format!(" --rules {rules_file}");
    }

    if output_format.as_deref() == Some("json") {
        command += " --json";
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🛡️  Starting Falco runtime monitoring for {duration}s");
    let result = execute_command(&command, true).await;
    info!("📊 Falco monitoring completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/checkov", methods=["POST"])` — `def checkov()`.
pub async fn checkov(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let directory = p_str(&params, "directory", ".");
    let framework = p_if(&params, "framework", json!(""));
    let check = p_if(&params, "check", json!(""));
    let skip_check = p_if(&params, "skip_check", json!(""));
    let output_format = p_if(&params, "output_format", json!("json"));
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = format!("checkov -d {directory}");

    if let Some(framework) = &framework {
        command += &format!(" --framework {framework}");
    }

    if let Some(check) = &check {
        command += &format!(" --check {check}");
    }

    if let Some(skip_check) = &skip_check {
        command += &format!(" --skip-check {skip_check}");
    }

    if let Some(output_format) = &output_format {
        command += &format!(" --output {output_format}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting Checkov IaC scan: {directory}");
    let result = execute_command(&command, true).await;
    info!("📊 Checkov scan completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/terrascan", methods=["POST"])` — `def terrascan()`.
pub async fn terrascan(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let scan_type = p_str(&params, "scan_type", "all");
    let iac_dir = p_str(&params, "iac_dir", ".");
    let policy_type = p_if(&params, "policy_type", json!(""));
    let output_format = p_if(&params, "output_format", json!("json"));
    let severity = p_if(&params, "severity", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    let mut command = format!("terrascan scan -t {scan_type} -d {iac_dir}");

    if let Some(policy_type) = &policy_type {
        command += &format!(" -p {policy_type}");
    }

    if let Some(output_format) = &output_format {
        command += &format!(" -o {output_format}");
    }

    if let Some(severity) = &severity {
        command += &format!(" --severity {severity}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting Terrascan IaC scan: {iac_dir}");
    let result = execute_command(&command, true).await;
    info!("📊 Terrascan scan completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/dirb", methods=["POST"])` — `def dirb()`.
pub async fn dirb(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let url = p_str(&params, "url", "");
    let wordlist =
        p_str(&params, "wordlist", "/usr/share/wordlists/dirb/common.txt");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if url.is_empty() {
        warn!("🌐 Dirb called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("dirb {url} {wordlist}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("📁 Starting Dirb scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Dirb scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/nikto", methods=["POST"])` — `def nikto()`.
pub async fn nikto(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_str(&params, "target", "");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if target.is_empty() {
        warn!("🎯 Nikto called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("nikto -h {target}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔬 Starting Nikto scan: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 Nikto scan completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/sqlmap", methods=["POST"])` — `def sqlmap()`.
pub async fn sqlmap(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let url = p_str(&params, "url", "");
    let data = p_if(&params, "data", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if url.is_empty() {
        warn!("🎯 SQLMap called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("sqlmap -u {url} --batch");

    if let Some(data) = &data {
        command += &format!(" --data=\"{data}\"");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("💉 Starting SQLMap scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 SQLMap scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/metasploit", methods=["POST"])` — `def metasploit()`.
pub async fn metasploit(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let module = p_str(&params, "module", "");
    let options = params.get("options").cloned().unwrap_or_else(|| json!({}));

    if module.is_empty() {
        warn!("🚀 Metasploit called without module parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Module parameter is required"})),
        ));
    }

    // Create an MSF resource script
    let mut resource_content = format!("use {module}\n");
    // `for key, value in options.items()` — aqui a ordem das chaves é a do
    // BTreeMap (JSON ordenado); o Python usa a ordem de inserção do dict.
    // Corpo não-objeto é ignorado (o Python levantaria AttributeError -> 500).
    for (key, value) in options.as_object().into_iter().flatten() {
        resource_content += &format!("set {key} {}\n", py_str(value));
    }
    resource_content += "exploit\n";

    // Save resource script to a temporary file
    let resource_file = "/tmp/mcp_msf_resource.rc";
    if let Err(e) = std::fs::write(resource_file, resource_content) {
        error!("💥 Error in metasploit endpoint: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Server error: {e}")})),
        ));
    }

    let command = format!("msfconsole -q -r {resource_file}");

    info!("🚀 Starting Metasploit module: {module}");
    let result = execute_command(&command, true).await;

    // Clean up the temporary file
    if let Err(e) = std::fs::remove_file(resource_file) {
        warn!("Error removing temporary resource file: {e}");
    }

    info!("📊 Metasploit module completed: {module}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/hydra", methods=["POST"])` — `def hydra()`.
pub async fn hydra(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_str(&params, "target", "");
    let service = p_str(&params, "service", "");
    let username = p_if(&params, "username", json!(""));
    let username_file = p_if(&params, "username_file", json!(""));
    let password = p_if(&params, "password", json!(""));
    let password_file = p_if(&params, "password_file", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if target.is_empty() || service.is_empty() {
        warn!("🎯 Hydra called without target or service parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target and service parameters are required"})),
        ));
    }

    if (username.is_none() && username_file.is_none())
        || (password.is_none() && password_file.is_none())
    {
        warn!("🔑 Hydra called without username/password parameters");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Username/username_file and password/password_file are required"
            })),
        ));
    }

    let mut command = "hydra -t 4".to_string();

    if let Some(username) = &username {
        command += &format!(" -l {username}");
    } else if let Some(username_file) = &username_file {
        command += &format!(" -L {username_file}");
    }

    if let Some(password) = &password {
        command += &format!(" -p {password}");
    } else if let Some(password_file) = &password_file {
        command += &format!(" -P {password_file}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {target} {service}");

    info!("🔑 Starting Hydra attack: {target}:{service}");
    let result = execute_command(&command, true).await;
    info!("📊 Hydra attack completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/john", methods=["POST"])` — `def john()`.
pub async fn john(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let hash_file = p_str(&params, "hash_file", "");
    let wordlist =
        p_str(&params, "wordlist", "/usr/share/wordlists/rockyou.txt");
    let format_type = p_if(&params, "format", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if hash_file.is_empty() {
        warn!("🔐 John called without hash_file parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Hash file parameter is required"})),
        ));
    }

    let mut command = "john".to_string();

    if let Some(format_type) = &format_type {
        command += &format!(" --format={format_type}");
    }

    if !wordlist.is_empty() {
        command += &format!(" --wordlist={wordlist}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    command += &format!(" {hash_file}");

    info!("🔐 Starting John the Ripper: {hash_file}");
    let result = execute_command(&command, true).await;
    info!("📊 John the Ripper completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/wpscan", methods=["POST"])` — `def wpscan()`.
pub async fn wpscan(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let url = p_str(&params, "url", "");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if url.is_empty() {
        warn!("🌐 WPScan called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("wpscan --url {url}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting WPScan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 WPScan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/enum4linux", methods=["POST"])`.
pub async fn enum4linux(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_str(&params, "target", "");
    // Aqui o default é "-a" e entra no comando SEMPRE (sem `if`).
    let additional_args = p_str(&params, "additional_args", "-a");

    if target.is_empty() {
        warn!("🎯 Enum4linux called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let command = format!("enum4linux {additional_args} {target}");

    info!("🔍 Starting Enum4linux: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 Enum4linux completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/ffuf", methods=["POST"])` — `def ffuf()`.
pub async fn ffuf(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let url = p_str(&params, "url", "");
    let wordlist =
        p_str(&params, "wordlist", "/usr/share/wordlists/dirb/common.txt");
    let mode = p_str(&params, "mode", "directory");
    let match_codes =
        p_str(&params, "match_codes", "200,204,301,302,307,401,403");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if url.is_empty() {
        warn!("🌐 FFuf called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = "ffuf".to_string();

    match mode.as_str() {
        "directory" => command += &format!(" -u {url}/FUZZ -w {wordlist}"),
        "vhost" => {
            command += &format!(" -u {url} -H 'Host: FUZZ' -w {wordlist}")
        }
        "parameter" => {
            command += &format!(" -u {url}?FUZZ=value -w {wordlist}")
        }
        _ => command += &format!(" -u {url} -w {wordlist}"),
    }

    command += &format!(" -mc {match_codes}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting FFuf {mode} fuzzing: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 FFuf fuzzing completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/netexec", methods=["POST"])` — `def netexec()`.
pub async fn netexec(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_str(&params, "target", "");
    let protocol = p_str(&params, "protocol", "smb");
    let username = p_if(&params, "username", json!(""));
    let password = p_if(&params, "password", json!(""));
    let hash_value = p_if(&params, "hash", json!(""));
    let module = p_if(&params, "module", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if target.is_empty() {
        warn!("🎯 NetExec called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("nxc {protocol} {target}");

    if let Some(username) = &username {
        command += &format!(" -u {username}");
    }

    if let Some(password) = &password {
        command += &format!(" -p {password}");
    }

    if let Some(hash_value) = &hash_value {
        command += &format!(" -H {hash_value}");
    }

    if let Some(module) = &module {
        command += &format!(" -M {module}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting NetExec {protocol} scan: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 NetExec scan completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/amass", methods=["POST"])` — `def amass()`.
pub async fn amass(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let domain = p_str(&params, "domain", "");
    let mode = p_str(&params, "mode", "enum");
    let additional_args = p_if(&params, "additional_args", json!(""));

    if domain.is_empty() {
        warn!("🌐 Amass called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("amass {mode}");

    // Os dois ramos do Python (`enum` e `else`) emitem a mesma string:
    //   command += f" -d {domain}"
    command += &format!(" -d {domain}");

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting Amass {mode}: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 Amass completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/hashcat", methods=["POST"])` — `def hashcat()`.
pub async fn hashcat(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let hash_file = p_str(&params, "hash_file", "");
    let hash_type = p_str(&params, "hash_type", "");
    let attack_mode = p_str(&params, "attack_mode", "0");
    let wordlist =
        p_str(&params, "wordlist", "/usr/share/wordlists/rockyou.txt");
    let mask = p_if(&params, "mask", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if hash_file.is_empty() {
        warn!("🔐 Hashcat called without hash_file parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Hash file parameter is required"})),
        ));
    }

    if hash_type.is_empty() {
        warn!("🔐 Hashcat called without hash_type parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Hash type parameter is required"})),
        ));
    }

    let mut command =
        format!("hashcat -m {hash_type} -a {attack_mode} {hash_file}");

    if attack_mode == "0" && !wordlist.is_empty() {
        command += &format!(" {wordlist}");
    } else if attack_mode == "3" {
        if let Some(mask) = &mask {
            command += &format!(" {mask}");
        }
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔐 Starting Hashcat attack: mode {attack_mode}");
    let result = execute_command(&command, true).await;
    info!("📊 Hashcat attack completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/subfinder", methods=["POST"])`.
pub async fn subfinder(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let domain = p_str(&params, "domain", "");
    let silent = p_bool(&params, "silent", true);
    let all_sources = p_bool(&params, "all_sources", false);
    let additional_args = p_if(&params, "additional_args", json!(""));

    if domain.is_empty() {
        warn!("🌐 Subfinder called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("subfinder -d {domain}");

    if silent {
        command += " -silent";
    }

    if all_sources {
        command += " -all";
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting Subfinder: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 Subfinder completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/smbmap", methods=["POST"])` — `def smbmap()`.
pub async fn smbmap(
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let params = body.as_object().cloned().unwrap_or_default();
    let target = p_str(&params, "target", "");
    let username = p_if(&params, "username", json!(""));
    let password = p_if(&params, "password", json!(""));
    let domain = p_if(&params, "domain", json!(""));
    let additional_args = p_if(&params, "additional_args", json!(""));

    if target.is_empty() {
        warn!("🎯 SMBMap called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("smbmap -H {target}");

    if let Some(username) = &username {
        command += &format!(" -u {username}");
    }

    if let Some(password) = &password {
        command += &format!(" -p {password}");
    }

    if let Some(domain) = &domain {
        command += &format!(" -d {domain}");
    }

    if let Some(additional_args) = &additional_args {
        command += &format!(" {additional_args}");
    }

    info!("🔍 Starting SMBMap: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 SMBMap completed for {target}");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/scout-suite", post(scout_suite))
        .route("/api/tools/cloudmapper", post(cloudmapper))
        .route("/api/tools/pacu", post(pacu))
        .route("/api/tools/kube-hunter", post(kube_hunter))
        .route("/api/tools/kube-bench", post(kube_bench))
        .route("/api/tools/docker-bench-security", post(docker_bench_security))
        .route("/api/tools/clair", post(clair))
        .route("/api/tools/falco", post(falco))
        .route("/api/tools/checkov", post(checkov))
        .route("/api/tools/terrascan", post(terrascan))
        .route("/api/tools/dirb", post(dirb))
        .route("/api/tools/nikto", post(nikto))
        .route("/api/tools/sqlmap", post(sqlmap))
        .route("/api/tools/metasploit", post(metasploit))
        .route("/api/tools/hydra", post(hydra))
        .route("/api/tools/john", post(john))
        .route("/api/tools/wpscan", post(wpscan))
        .route("/api/tools/enum4linux", post(enum4linux))
        .route("/api/tools/ffuf", post(ffuf))
        .route("/api/tools/netexec", post(netexec))
        .route("/api/tools/amass", post(amass))
        .route("/api/tools/hashcat", post(hashcat))
        .route("/api/tools/subfinder", post(subfinder))
        .route("/api/tools/smbmap", post(smbmap))
}
