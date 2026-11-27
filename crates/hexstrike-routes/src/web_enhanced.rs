//! Port 1:1 de `hexstrike_server/routes/web_enhanced.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  def dirsearch
//!    50  def katana
//!    88  def gau
//!   125  def waybackurls
//!   158  def arjun
//!   197  def paramspider
//!   231  def x8
//!   266  def jaeles
//!   301  def dalfox
//!   346  def httpx
//!   396  def anew
//!   425  def qsreplace
//!   451  def uro
//! ```
//!
//! Rotas (`@app.route`) deste módulo (13):
//!
//! ```text
//!    17  dirsearch("/api/tools/dirsearch", methods=["POST"])
//!    49  katana("/api/tools/katana", methods=["POST"])
//!    87  gau("/api/tools/gau", methods=["POST"])
//!   124  waybackurls("/api/tools/waybackurls", methods=["POST"])
//!   157  arjun("/api/tools/arjun", methods=["POST"])
//!   196  paramspider("/api/tools/paramspider", methods=["POST"])
//!   230  x8("/api/tools/x8", methods=["POST"])
//!   265  jaeles("/api/tools/jaeles", methods=["POST"])
//!   300  dalfox("/api/tools/dalfox", methods=["POST"])
//!   345  httpx("/api/tools/httpx", methods=["POST"])
//!   395  anew("/api/tools/anew", methods=["POST"])
//!   424  qsreplace("/api/tools/qsreplace", methods=["POST"])
//!   450  uro("/api/tools/uro", methods=["POST"])
//! ```

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tracing::{info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;

/// `jsonify(x)` (200) vs `jsonify(x), <status>` (≠200). O `Result` do axum
/// devolve o status só no ramo de erro, então o ramo 200 continua sendo
/// `Json<Value>`.
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// `@app.route("/api/tools/dirsearch", methods=["POST"])` — `def dirsearch()`.
pub async fn dirsearch(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let extensions = params
        .get("extensions")
        .and_then(Value::as_str)
        .unwrap_or("php,html,js,txt,xml,json");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/dirsearch/common.txt");
    let threads = params.get("threads").and_then(Value::as_i64).unwrap_or(30);
    let recursive = params
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Dirsearch called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("dirsearch -u {url} -e {extensions} -w {wordlist} -t {threads}");

    if recursive {
        command.push_str(" -r");
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("📁 Starting Dirsearch scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Dirsearch scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/katana", methods=["POST"])` — `def katana()`.
pub async fn katana(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let depth = params.get("depth").and_then(Value::as_i64).unwrap_or(3);
    let js_crawl = params
        .get("js_crawl")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let form_extraction = params
        .get("form_extraction")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let output_format = params
        .get("output_format")
        .and_then(Value::as_str)
        .unwrap_or("json");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Katana called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("katana -u {url} -d {depth}");

    if js_crawl {
        command.push_str(" -jc");
    }

    if form_extraction {
        command.push_str(" -fx");
    }

    if output_format == "json" {
        command.push_str(" -jsonl");
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("⚔️  Starting Katana crawl: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Katana crawl completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/gau", methods=["POST"])` — `def gau()`.
pub async fn gau(Json(params): Json<Value>) -> ApiResult {
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("");
    let providers = params
        .get("providers")
        .and_then(Value::as_str)
        .unwrap_or("wayback,commoncrawl,otx,urlscan");
    let include_subs = params
        .get("include_subs")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let blacklist = params
        .get("blacklist")
        .and_then(Value::as_str)
        .unwrap_or("png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if domain.is_empty() {
        warn!("🌐 Gau called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("gau {domain}");

    if providers != "wayback,commoncrawl,otx,urlscan" {
        command.push_str(&format!(" --providers {providers}"));
    }

    if include_subs {
        command.push_str(" --subs");
    }

    if !blacklist.is_empty() {
        command.push_str(&format!(" --blacklist {blacklist}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("📡 Starting Gau URL discovery: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 Gau URL discovery completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/waybackurls", methods=["POST"])` — `def waybackurls()`.
pub async fn waybackurls(Json(params): Json<Value>) -> ApiResult {
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("");
    let get_versions = params
        .get("get_versions")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let no_subs = params
        .get("no_subs")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if domain.is_empty() {
        warn!("🌐 Waybackurls called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("waybackurls {domain}");

    if get_versions {
        command.push_str(" --get-versions");
    }

    if no_subs {
        command.push_str(" --no-subs");
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🕰️  Starting Waybackurls discovery: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 Waybackurls discovery completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/arjun", methods=["POST"])` — `def arjun()`.
pub async fn arjun(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("");
    let delay = params.get("delay").and_then(Value::as_i64).unwrap_or(0);
    let threads = params.get("threads").and_then(Value::as_i64).unwrap_or(25);
    let stable = params
        .get("stable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Arjun called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("arjun -u {url} -m {method} -t {threads}");

    if !wordlist.is_empty() {
        command.push_str(&format!(" -w {wordlist}"));
    }

    if delay > 0 {
        command.push_str(&format!(" -d {delay}"));
    }

    if stable {
        command.push_str(" --stable");
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🎯 Starting Arjun parameter discovery: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Arjun parameter discovery completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/paramspider", methods=["POST"])` — `def paramspider()`.
pub async fn paramspider(Json(params): Json<Value>) -> ApiResult {
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("");
    let level = params.get("level").and_then(Value::as_i64).unwrap_or(2);
    let exclude = params
        .get("exclude")
        .and_then(Value::as_str)
        .unwrap_or("png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico");
    let output = params
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if domain.is_empty() {
        warn!("🌐 ParamSpider called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("paramspider -d {domain} -l {level}");

    if !exclude.is_empty() {
        command.push_str(&format!(" --exclude {exclude}"));
    }

    if !output.is_empty() {
        command.push_str(&format!(" -o {output}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🕷️  Starting ParamSpider mining: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 ParamSpider mining completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/x8", methods=["POST"])` — `def x8()`.
pub async fn x8(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("/usr/share/wordlists/x8/params.txt");
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let body = params.get("body").and_then(Value::as_str).unwrap_or("");
    let headers = params
        .get("headers")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 x8 called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("x8 -u {url} -w {wordlist} -X {method}");

    if !body.is_empty() {
        command.push_str(&format!(" -b '{body}'"));
    }

    if !headers.is_empty() {
        command.push_str(&format!(" -H '{headers}'"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting x8 parameter discovery: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 x8 parameter discovery completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/jaeles", methods=["POST"])` — `def jaeles()`.
pub async fn jaeles(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let signatures = params
        .get("signatures")
        .and_then(Value::as_str)
        .unwrap_or("");
    let config = params
        .get("config")
        .and_then(Value::as_str)
        .unwrap_or("");
    let threads = params.get("threads").and_then(Value::as_i64).unwrap_or(20);
    let timeout = params.get("timeout").and_then(Value::as_i64).unwrap_or(20);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() {
        warn!("🌐 Jaeles called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = format!("jaeles scan -u {url} -c {threads} --timeout {timeout}");

    if !signatures.is_empty() {
        command.push_str(&format!(" -s {signatures}"));
    }

    if !config.is_empty() {
        command.push_str(&format!(" --config {config}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔬 Starting Jaeles vulnerability scan: {url}");
    let result = execute_command(&command, true).await;
    info!("📊 Jaeles vulnerability scan completed for {url}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/dalfox", methods=["POST"])` — `def dalfox()`.
pub async fn dalfox(Json(params): Json<Value>) -> ApiResult {
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let pipe_mode = params
        .get("pipe_mode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let blind = params
        .get("blind")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mining_dom = params
        .get("mining_dom")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mining_dict = params
        .get("mining_dict")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let custom_payload = params
        .get("custom_payload")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if url.is_empty() && !pipe_mode {
        warn!("🌐 Dalfox called without URL parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL parameter is required"})),
        ));
    }

    let mut command = if pipe_mode {
        "dalfox pipe".to_string()
    } else {
        format!("dalfox url {url}")
    };

    if blind {
        command.push_str(" --blind");
    }

    if mining_dom {
        command.push_str(" --mining-dom");
    }

    if mining_dict {
        command.push_str(" --mining-dict");
    }

    if !custom_payload.is_empty() {
        command.push_str(&format!(" --custom-payload '{custom_payload}'"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    // `{url if url else 'pipe mode'}`
    let target_label = if url.is_empty() { "pipe mode" } else { url };
    info!("🎯 Starting Dalfox XSS scan: {target_label}");
    let result = execute_command(&command, true).await;
    info!("📊 Dalfox XSS scan completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/httpx", methods=["POST"])` — `def httpx()`.
pub async fn httpx(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let probe = params
        .get("probe")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let tech_detect = params
        .get("tech_detect")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status_code = params
        .get("status_code")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content_length = params
        .get("content_length")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let title = params
        .get("title")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let web_server = params
        .get("web_server")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let threads = params.get("threads").and_then(Value::as_i64).unwrap_or(50);
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if target.is_empty() {
        warn!("🌐 httpx called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("httpx -l {target} -t {threads}");

    if probe {
        command.push_str(" -probe");
    }

    if tech_detect {
        command.push_str(" -tech-detect");
    }

    if status_code {
        command.push_str(" -sc");
    }

    if content_length {
        command.push_str(" -cl");
    }

    if title {
        command.push_str(" -title");
    }

    if web_server {
        command.push_str(" -server");
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🌍 Starting httpx probe: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 httpx probe completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/anew", methods=["POST"])` — `def anew()`.
pub async fn anew(Json(params): Json<Value>) -> ApiResult {
    let input_data = params
        .get("input_data")
        .and_then(Value::as_str)
        .unwrap_or("");
    let output_file = params
        .get("output_file")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if input_data.is_empty() {
        warn!("📝 Anew called without input data");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Input data is required"})),
        ));
    }

    let mut command = if !output_file.is_empty() {
        format!("echo '{input_data}' | anew {output_file}")
    } else {
        format!("echo '{input_data}' | anew")
    };

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("📝 Starting anew data processing");
    let result = execute_command(&command, true).await;
    info!("📊 anew data processing completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/qsreplace", methods=["POST"])` — `def qsreplace()`.
pub async fn qsreplace(Json(params): Json<Value>) -> ApiResult {
    let urls = params.get("urls").and_then(Value::as_str).unwrap_or("");
    let replacement = params
        .get("replacement")
        .and_then(Value::as_str)
        .unwrap_or("FUZZ");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if urls.is_empty() {
        warn!("🌐 qsreplace called without URLs");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URLs parameter is required"})),
        ));
    }

    let mut command = format!("echo '{urls}' | qsreplace '{replacement}'");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔄 Starting qsreplace parameter replacement");
    let result = execute_command(&command, true).await;
    info!("📊 qsreplace parameter replacement completed");
    Ok(Json(result))
}

/// `@app.route("/api/tools/uro", methods=["POST"])` — `def uro()`.
pub async fn uro(Json(params): Json<Value>) -> ApiResult {
    let urls = params.get("urls").and_then(Value::as_str).unwrap_or("");
    let whitelist = params
        .get("whitelist")
        .and_then(Value::as_str)
        .unwrap_or("");
    let blacklist = params
        .get("blacklist")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if urls.is_empty() {
        warn!("🌐 uro called without URLs");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URLs parameter is required"})),
        ));
    }

    let mut command = format!("echo '{urls}' | uro");

    if !whitelist.is_empty() {
        command.push_str(&format!(" --whitelist {whitelist}"));
    }

    if !blacklist.is_empty() {
        command.push_str(&format!(" --blacklist {blacklist}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting uro URL filtering");
    let result = execute_command(&command, true).await;
    info!("📊 uro URL filtering completed");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/dirsearch", post(dirsearch))
        .route("/api/tools/katana", post(katana))
        .route("/api/tools/gau", post(gau))
        .route("/api/tools/waybackurls", post(waybackurls))
        .route("/api/tools/arjun", post(arjun))
        .route("/api/tools/paramspider", post(paramspider))
        .route("/api/tools/x8", post(x8))
        .route("/api/tools/jaeles", post(jaeles))
        .route("/api/tools/dalfox", post(dalfox))
        .route("/api/tools/httpx", post(httpx))
        .route("/api/tools/anew", post(anew))
        .route("/api/tools/qsreplace", post(qsreplace))
        .route("/api/tools/uro", post(uro))
}
