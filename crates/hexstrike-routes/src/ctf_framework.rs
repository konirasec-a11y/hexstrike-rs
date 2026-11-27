//! Port 1:1 de `hexstrike_server/routes/ctf_framework.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W6.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    22  def create_ctf_challenge_workflow
//!    62  def auto_solve_ctf_challenge
//!   102  def create_ctf_team_strategy
//!   142  def suggest_ctf_tools
//!   179  def ctf_cryptography_solver
//!   277  def ctf_forensics_analyzer
//!   420  def ctf_binary_analyzer
//! ```
//!
//! Rotas (`@app.route`) deste módulo (7):
//!
//! ```text
//!    21  create_ctf_challenge_workflow("/api/ctf/create-challenge-workflow", methods=["POST"])
//!    61  auto_solve_ctf_challenge("/api/ctf/auto-solve-challenge", methods=["POST"])
//!   101  create_ctf_team_strategy("/api/ctf/team-strategy", methods=["POST"])
//!   141  suggest_ctf_tools("/api/ctf/suggest-tools", methods=["POST"])
//!   178  ctf_cryptography_solver("/api/ctf/cryptography-solver", methods=["POST"])
//!   276  ctf_forensics_analyzer("/api/ctf/forensics-analyzer", methods=["POST"])
//!   419  ctf_binary_analyzer("/api/ctf/binary-analyzer", methods=["POST"])
//! ```

use std::collections::HashSet;
use std::sync::LazyLock;

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use regex::Regex;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{error, info};

use hexstrike_intelligence::ctf::TARGET_KWARG_TYPE_ERROR;
use hexstrike_intelligence::process_manager::ctf_tools;

// ============================================================================
// CTF COMPETITION EXCELLENCE FRAMEWORK API ENDPOINTS (v8.0 ENHANCEMENT)
// ============================================================================

/// `re.match(r'^[0-9a-fA-F]+$', …)`
static HEX_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").expect("regex do Python válido"));

/// `re.match(r'^[A-Za-z0-9+/]+=*$', …)`
static BASE64_ONLY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]+=*$").expect("regex do Python válido"));

/// `params = request.json` + o helper `params.get(key, default)` do Python.
///
/// O corpo destas rotas é `try: ... except Exception as e: 500`. Em Rust nada
/// levanta, exceto o único caso que sobra: corpo JSON que não é objeto
/// (`null`/lista/str) — o `params.get` do Python levanta AttributeError.
/// [`request_json`] reproduz esse caminho e [`get_str`] é o
/// `params.get(key, default)`.
///
/// Corpo sem `Content-Type: application/json` ou com JSON inválido nem chega
/// aqui: o extrator `Json` do axum recusa (415/400 em texto puro) antes do
/// handler, enquanto o Flask devolve 500 com a mensagem do erro dele. É a
/// única divergência do `except Exception` que não tem equivalente em Rust.
/// Nome do tipo do Python, para a mensagem do AttributeError.
fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn request_json<'a>(body: &'a Value, log: &str) -> Result<&'a Value, (StatusCode, Json<Value>)> {
    if body.is_object() {
        return Ok(body);
    }

    let message = format!("'{}' object has no attribute 'get'", py_type_name(body));
    error!("{log}: {message}");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    ))
}

/// `params.get(key, default)` — o default só vale quando a chave não existe.
/// Valor não-string cai em `""` (o Python usaria `str(valor)` no comando).
fn get_str(params: &Value, key: &str, default: &str) -> String {
    match params.get(key) {
        None => default.to_string(),
        Some(value) => value.as_str().unwrap_or_default().to_string(),
    }
}

/// `bool(valor)` do Python.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|number| number != 0.0).unwrap_or(true),
        Value::String(string) => !string.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(entries) => !entries.is_empty(),
    }
}

/// `len(set(texto))` — nº de caracteres distintos.
fn distinct_chars(text: &str) -> usize {
    text.chars().collect::<HashSet<char>>().len()
}

/// `datetime.now().isoformat()`
fn isoformat_now() -> String {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]"
    );
    now.format(&format).unwrap_or_default()
}

/// `str(['file', '/tmp/x'])` do Python → `['file', '/tmp/x']`
fn py_list_repr(argv: &[&str]) -> String {
    format!(
        "[{}]",
        argv.iter().map(|arg| format!("'{arg}'")).collect::<Vec<String>>().join(", ")
    )
}

/// `str(exceção)` do Python para falha de `subprocess.run`:
/// `[Errno 2] No such file or directory: 'binwalk'`.
fn py_os_error(program: &str, error: &std::io::Error) -> String {
    let errno = error.raw_os_error().unwrap_or(0);
    let description = error.to_string();
    let description = description.split(" (os error").next().unwrap_or(&description);
    format!("[Errno {errno}] {description}: '{program}'")
}

/// `subprocess.run(argv, capture_output=True, text=True, timeout=…)` —
/// devolve `(returncode, stdout)` ou a mensagem que o `except Exception`
/// colocaria no JSON da resposta.
async fn subprocess_run(argv: &[&str], timeout_secs: u64) -> Result<(i32, String), String> {
    let program = argv.first().copied().unwrap_or_default();
    let output = timeout(
        Duration::from_secs(timeout_secs),
        Command::new(program).args(&argv[1..]).output(),
    )
    .await;

    match output {
        Ok(Ok(completed)) => Ok((
            completed.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&completed.stdout).to_string(),
        )),
        Ok(Err(error)) => Err(py_os_error(program, &error)),
        Err(_) => Err(format!(
            "Command '{}' timed out after {timeout_secs} seconds",
            py_list_repr(argv)
        )),
    }
}

/// Create specialized workflow for CTF challenge
///
/// Divergência herdada do Python (reproduzida 1:1): o dataclass
/// `CTFChallenge` não tem campo `target`, então
/// `CTFChallenge(…, target=target)` levanta TypeError, o `except Exception`
/// devolve 500 e o resto do corpo (workflow, `challenge.to_dict()` — que
/// também não existe) é inalcançável. Preserva a string e o `logger.error`.
pub async fn create_ctf_challenge_workflow(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error creating CTF workflow") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let challenge_name = get_str(params, "name", "");

    if challenge_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Challenge name is required"})),
        );
    }

    error!("💥 Error creating CTF workflow: {TARGET_KWARG_TYPE_ERROR}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {TARGET_KWARG_TYPE_ERROR}")})),
    )
}

/// Attempt to automatically solve a CTF challenge
///
/// Mesma divergência de [`create_ctf_challenge_workflow`]: o corpo morre na
/// construção do `CTFChallenge` e nunca chega em
/// `ctf_automator.auto_solve_challenge`.
pub async fn auto_solve_ctf_challenge(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in CTF auto-solve") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let challenge_name = get_str(params, "name", "");

    if challenge_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Challenge name is required"})),
        );
    }

    error!("💥 Error in CTF auto-solve: {TARGET_KWARG_TYPE_ERROR}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {TARGET_KWARG_TYPE_ERROR}")})),
    )
}

/// Create optimal team strategy for CTF competition
///
/// Mesma divergência: o `for challenge_data in challenges_data` monta
/// `CTFChallenge(…, target=target)`, então
/// `ctf_coordinator.optimize_team_strategy` nunca é chamado.
pub async fn create_ctf_team_strategy(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error creating CTF team strategy") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let challenges_data = params.get("challenges").cloned().unwrap_or(json!([]));

    if !truthy(&challenges_data) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Challenges data is required"})),
        );
    }

    // O `for challenge_data in challenges_data` do Python chama
    // `challenge_data.get(...)` (AttributeError se o elemento não for dict) e
    // depois monta `CTFChallenge(…, target=target)` (TypeError) — o primeiro
    // elemento decide e nada chega em `optimize_team_strategy`.
    let message = match challenges_data.as_array().and_then(|items| items.first()) {
        Some(first) if !first.is_object() => {
            format!("'{}' object has no attribute 'get'", py_type_name(first))
        }
        _ => TARGET_KWARG_TYPE_ERROR.to_string(),
    };

    error!("💥 Error creating CTF team strategy: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("Server error: {message}")})),
    )
}

/// Suggest optimal tools for CTF challenge based on description and category
pub async fn suggest_ctf_tools(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error suggesting CTF tools") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let description = get_str(params, "description", "");
    let category = get_str(params, "category", "misc");

    if description.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Challenge description is required"})),
        );
    }

    // Get tool suggestions
    let suggested_tools = ctf_tools.suggest_tools_for_challenge(&description, &category);
    let category_tools = ctf_tools.get_category_tools(&format!("{category}_recon"));

    // Get tool commands (`try/except` do Python: `get_tool_command` não levanta)
    let mut tool_commands = Map::new();
    for tool in &suggested_tools {
        tool_commands.insert(tool.clone(), json!(ctf_tools.get_tool_command(tool, "TARGET", "")));
    }

    info!(
        "🔧 CTF tools suggested | Category: {category} | Tools: {}",
        suggested_tools.len()
    );
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "suggested_tools": suggested_tools,
            "category_tools": category_tools,
            "tool_commands": Value::Object(tool_commands),
            "category": category,
            "timestamp": isoformat_now()
        })),
    )
}

/// Advanced cryptography challenge solver with multiple attack methods
pub async fn ctf_cryptography_solver(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in CTF crypto solver") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let cipher_text = get_str(params, "cipher_text", "");
    let cipher_type = get_str(params, "cipher_type", "unknown");
    // `key_hint` e `known_plaintext` são lidos pelo Python e nunca usados.
    let additional_info = get_str(params, "additional_info", "");

    if cipher_text.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cipher text is required"})),
        );
    }

    let mut analysis_results: Vec<String> = Vec::new();
    let potential_solutions: Vec<String> = Vec::new(); // nunca preenchido
    let mut recommended_tools: Vec<String> = Vec::new();
    let mut next_steps: Vec<String> = Vec::new();

    // Cipher type identification
    if cipher_type == "unknown" {
        // Basic cipher identification heuristics
        let without_spaces = cipher_text.replace(' ', "");
        if HEX_ONLY.is_match(&without_spaces) {
            analysis_results.push("Possible hexadecimal encoding".to_string());
            recommended_tools.extend(["hex".to_string(), "xxd".to_string()]);
        }

        if BASE64_ONLY.is_match(&without_spaces) {
            analysis_results.push("Possible Base64 encoding".to_string());
            recommended_tools.push("base64".to_string());
        }

        if distinct_chars(&cipher_text.to_uppercase().replace(' ', "")) <= 26 {
            analysis_results.push("Possible substitution cipher".to_string());
            recommended_tools.extend(["frequency-analysis".to_string(), "substitution-solver".to_string()]);
        }
    }

    // Hash identification
    let clean_text = cipher_text.replace(' ', "").replace('\n', "");
    let hash_type = match clean_text.chars().count() {
        32 => Some("MD5"),
        40 => Some("SHA1"),
        64 => Some("SHA256"),
        128 => Some("SHA512"),
        _ => None,
    };
    if let Some(hash_type) = hash_type {
        if HEX_ONLY.is_match(&clean_text) {
            analysis_results.push(format!("Possible {hash_type} hash"));
            recommended_tools.extend([
                "hashcat".to_string(),
                "john".to_string(),
                "hash-identifier".to_string(),
            ]);
        }
    }

    // Frequency analysis for substitution ciphers
    // (`"substitution" in results["analysis_results"]` do Python: `in` em
    // lista é igualdade, então nunca casa — reproduzido.)
    if cipher_type == "substitution"
        || cipher_type == "caesar"
        || cipher_type == "vigenere"
        || analysis_results.iter().any(|result| result == "substitution")
    {
        // Ordem de primeira aparição (dict do Python, não hash).
        let mut char_freq: Vec<(char, usize)> = Vec::new();
        for character in cipher_text.to_uppercase().chars() {
            if character.is_alphabetic() {
                match char_freq.iter_mut().find(|(known, _)| *known == character) {
                    Some((_, count)) => *count += 1,
                    None => char_freq.push((character, 1)),
                }
            }
        }

        if let Some(first) = char_freq.first() {
            // `max(char_freq, key=char_freq.get)` = o primeiro de maior contagem
            let mut most_common = *first;
            for entry in &char_freq[1..] {
                if entry.1 > most_common.1 {
                    most_common = *entry;
                }
            }

            analysis_results.push(format!(
                "Most frequent character: {} ({} occurrences)",
                most_common.0, most_common.1
            ));
            next_steps.push("Try substituting most frequent character with 'E'".to_string());
        }
    }

    // ROT/Caesar cipher detection
    if cipher_type == "caesar" || distinct_chars(&cipher_text.to_uppercase().replace(' ', "")) <= 26 {
        recommended_tools.push("rot13".to_string());
        next_steps.push("Try all ROT values (1-25)".to_string());
    }

    // RSA-specific analysis
    if cipher_type == "rsa" || additional_info.to_lowercase().contains("rsa") {
        recommended_tools.extend(["rsatool".to_string(), "factordb".to_string(), "yafu".to_string()]);
        next_steps.extend(
            [
                "Check if modulus can be factored",
                "Look for small public exponent attacks",
                "Check for common modulus attacks",
            ]
            .map(str::to_string),
        );
    }

    // Vigenère cipher analysis
    if cipher_type == "vigenere" || additional_info.to_lowercase().contains("vigenere") {
        recommended_tools.push("vigenere-solver".to_string());
        next_steps.extend(
            [
                "Perform Kasiski examination for key length",
                "Use index of coincidence analysis",
                "Try common key words",
            ]
            .map(str::to_string),
        );
    }

    info!(
        "🔐 CTF crypto analysis completed | Type: {cipher_type} | Tools: {}",
        recommended_tools.len()
    );
    let analysis = json!({
        "cipher_text": cipher_text,
        "cipher_type": cipher_type,
        "analysis_results": analysis_results,
        "potential_solutions": potential_solutions,
        "recommended_tools": recommended_tools,
        "next_steps": next_steps
    });

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "analysis": analysis,
            "timestamp": isoformat_now()
        })),
    )
}

/// Advanced forensics challenge analyzer with multiple investigation techniques
pub async fn ctf_forensics_analyzer(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in CTF forensics analyzer") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let file_path = get_str(params, "file_path", "");
    let analysis_type = get_str(params, "analysis_type", "comprehensive");
    let extract_hidden = params.get("extract_hidden").map(truthy).unwrap_or(true);
    let check_steganography = params.get("check_steganography").map(truthy).unwrap_or(true);

    if file_path.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "File path is required"})),
        );
    }

    let mut file_info = Map::new();
    let mut metadata = Map::new();
    let mut hidden_data: Vec<Value> = Vec::new();
    let mut steganography_results: Vec<Value> = Vec::new();
    let mut recommended_tools: Vec<String> = Vec::new();
    let mut next_steps: Vec<String> = Vec::new();

    // Basic file analysis
    match subprocess_run(&["file", &file_path], 30).await {
        Ok((returncode, stdout)) => {
            if returncode == 0 {
                file_info.insert("type".to_string(), json!(stdout.trim()));

                // Determine file category and suggest tools
                let file_type = stdout.to_lowercase();
                if file_type.contains("image") {
                    recommended_tools.extend(["exiftool", "steghide", "stegsolve", "zsteg"].map(str::to_string));
                    next_steps.extend(
                        [
                            "Extract EXIF metadata",
                            "Check for steganographic content",
                            "Analyze color channels separately",
                        ]
                        .map(str::to_string),
                    );
                } else if file_type.contains("audio") {
                    recommended_tools.extend(["audacity", "sonic-visualizer", "spectrum-analyzer"].map(str::to_string));
                    next_steps.extend(
                        [
                            "Analyze audio spectrum",
                            "Check for hidden data in audio channels",
                            "Look for DTMF tones or morse code",
                        ]
                        .map(str::to_string),
                    );
                } else if file_type.contains("pdf") {
                    recommended_tools.extend(["pdfinfo", "pdftotext", "binwalk"].map(str::to_string));
                    next_steps.extend(
                        [
                            "Extract text and metadata",
                            "Check for embedded files",
                            "Analyze PDF structure",
                        ]
                        .map(str::to_string),
                    );
                } else if file_type.contains("zip") || file_type.contains("archive") {
                    recommended_tools.extend(["unzip", "7zip", "binwalk"].map(str::to_string));
                    next_steps.extend(
                        [
                            "Extract archive contents",
                            "Check for password protection",
                            "Look for hidden files",
                        ]
                        .map(str::to_string),
                    );
                }
            }
        }
        Err(error) => {
            file_info.insert("error".to_string(), json!(error));
        }
    }

    // Metadata extraction
    match subprocess_run(&["exiftool", &file_path], 30).await {
        Ok((returncode, stdout)) => {
            if returncode == 0 {
                metadata.insert("exif".to_string(), json!(stdout));
            }
        }
        Err(error) => {
            metadata.insert("exif_error".to_string(), json!(error));
        }
    }

    // Binwalk analysis for hidden files
    if extract_hidden {
        match subprocess_run(&["binwalk", "-e", &file_path], 60).await {
            Ok((returncode, stdout)) => {
                if returncode == 0 {
                    hidden_data.push(json!({"tool": "binwalk", "output": stdout}));
                }
            }
            Err(error) => {
                hidden_data.push(json!({"tool": "binwalk", "error": error}));
            }
        }
    }

    // Steganography checks
    if check_steganography {
        // Check for common steganography tools
        for tool in ["steghide", "zsteg", "outguess"] {
            let argv: Vec<&str> = match tool {
                "steghide" => vec![tool, "info", &file_path],
                "zsteg" => vec![tool, "-a", &file_path],
                _ => vec![tool, "-r", &file_path, "/tmp/outguess_output"],
            };

            match subprocess_run(&argv, 30).await {
                Ok((returncode, stdout)) => {
                    if returncode == 0 && !stdout.trim().is_empty() {
                        steganography_results.push(json!({"tool": tool, "output": stdout}));
                    }
                }
                Err(error) => {
                    steganography_results.push(json!({"tool": tool, "error": error}));
                }
            }
        }
    }

    // Strings analysis
    match subprocess_run(&["strings", &file_path], 30).await {
        Ok((returncode, stdout)) => {
            if returncode == 0 {
                // Look for interesting strings (flags, URLs, etc.)
                let mut interesting_strings: Vec<String> = Vec::new();
                for line in stdout.split('\n') {
                    if ["flag", "password", "key", "secret", "http", "ftp"]
                        .iter()
                        .any(|keyword| line.to_lowercase().contains(keyword))
                    {
                        interesting_strings.push(line.trim().to_string());
                    }
                }

                if !interesting_strings.is_empty() {
                    // Limit to first 20
                    hidden_data.push(json!({
                        "tool": "strings",
                        "interesting_strings": interesting_strings.into_iter().take(20).collect::<Vec<String>>()
                    }));
                }
            }
        }
        Err(error) => {
            hidden_data.push(json!({"tool": "strings", "error": error}));
        }
    }

    info!(
        "🔍 CTF forensics analysis completed | File: {file_path} | Tools used: {}",
        recommended_tools.len()
    );
    let analysis = json!({
        "file_path": file_path,
        "analysis_type": analysis_type,
        "file_info": Value::Object(file_info),
        "metadata": Value::Object(metadata),
        "hidden_data": hidden_data,
        "steganography_results": steganography_results,
        "recommended_tools": recommended_tools,
        "next_steps": next_steps
    });

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "analysis": analysis,
            "timestamp": isoformat_now()
        })),
    )
}

/// Advanced binary analysis for reverse engineering and pwn challenges
pub async fn ctf_binary_analyzer(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let params = match request_json(&body, "💥 Error in CTF binary analyzer") {
        Ok(params) => params,
        Err(response) => return response,
    };

    let binary_path = get_str(params, "binary_path", "");
    let analysis_depth = get_str(params, "analysis_depth", "comprehensive"); // basic, comprehensive, deep
    let check_protections = params.get("check_protections").map(truthy).unwrap_or(true);
    let find_gadgets = params.get("find_gadgets").map(truthy).unwrap_or(true);

    if binary_path.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Binary path is required"})),
        );
    }

    let mut file_info = Map::new();
    let mut security_protections = Map::new();
    let mut interesting_functions: Vec<Value> = Vec::new();
    let mut strings_analysis = json!({});
    let mut gadgets: Vec<Value> = Vec::new();
    let mut recommended_tools: Vec<String> = Vec::new();
    let mut exploitation_hints: Vec<String> = Vec::new();

    // Basic file information
    match subprocess_run(&["file", &binary_path], 30).await {
        Ok((returncode, stdout)) => {
            if returncode == 0 {
                file_info.insert("type".to_string(), json!(stdout.trim()));

                // Determine architecture and suggest tools
                let file_output = stdout.to_lowercase();
                if file_output.contains("x86-64") || file_output.contains("x86_64") {
                    file_info.insert("architecture".to_string(), json!("x86_64"));
                } else if file_output.contains("i386") || file_output.contains("80386") {
                    file_info.insert("architecture".to_string(), json!("i386"));
                } else if file_output.contains("arm") {
                    file_info.insert("architecture".to_string(), json!("ARM"));
                }

                recommended_tools.extend(["gdb-peda", "radare2", "ghidra"].map(str::to_string));
            }
        }
        Err(error) => {
            file_info.insert("error".to_string(), json!(error));
        }
    }

    // Security protections check
    if check_protections {
        match subprocess_run(&["checksec", "--file", &binary_path], 30).await {
            Ok((returncode, stdout)) => {
                if returncode == 0 {
                    security_protections.insert("checksec".to_string(), json!(stdout));

                    // Parse protections and provide exploitation hints
                    let output = stdout.to_lowercase();
                    if output.contains("no canary found") {
                        exploitation_hints.push("Stack canary disabled - buffer overflow exploitation possible".to_string());
                    }
                    if output.contains("nx disabled") {
                        exploitation_hints.push("NX disabled - shellcode execution on stack possible".to_string());
                    }
                    if output.contains("no pie") {
                        exploitation_hints.push("PIE disabled - fixed addresses, ROP/ret2libc easier".to_string());
                    }
                    if output.contains("no relro") {
                        exploitation_hints.push("RELRO disabled - GOT overwrite attacks possible".to_string());
                    }
                }
            }
            Err(error) => {
                security_protections.insert("error".to_string(), json!(error));
            }
        }
    }

    // Strings analysis
    match subprocess_run(&["strings", &binary_path], 30).await {
        Ok((returncode, stdout)) => {
            if returncode == 0 {
                let strings_output = stdout.split('\n');

                // Categorize interesting strings
                let mut functions: Vec<String> = Vec::new();
                let mut format_strings: Vec<String> = Vec::new();
                let mut file_paths: Vec<String> = Vec::new();
                let mut potential_flags: Vec<String> = Vec::new();
                let mut system_calls: Vec<String> = Vec::new();

                for string in strings_output {
                    let string = string.trim();
                    if string.is_empty() {
                        continue;
                    }

                    // Look for function names
                    if ["printf", "scanf", "gets", "strcpy", "system", "execve"]
                        .iter()
                        .any(|function| string.contains(function))
                    {
                        functions.push(string.to_string());
                    }

                    // Look for format strings
                    if string.contains('%')
                        && ["%s", "%d", "%x", "%n"].iter().any(|format| string.contains(format))
                    {
                        format_strings.push(string.to_string());
                    }

                    // Look for file paths
                    if string.starts_with('/') || string.contains('\\') {
                        file_paths.push(string.to_string());
                    }

                    // Look for potential flags
                    if ["flag", "ctf", "key", "password"]
                        .iter()
                        .any(|keyword| string.to_lowercase().contains(keyword))
                    {
                        potential_flags.push(string.to_string());
                    }

                    // Look for system calls
                    if ["sh", "bash", "/bin/sh", "/bin/bash", "cmd.exe"].contains(&string) {
                        system_calls.push(string.to_string());
                    }
                }

                strings_analysis = json!({
                    "functions": functions,
                    "format_strings": format_strings,
                    "file_paths": file_paths,
                    "potential_flags": potential_flags,
                    "system_calls": system_calls
                });

                // Add exploitation hints based on strings
                if !functions.is_empty() {
                    let dangerous_funcs = ["gets", "strcpy", "sprintf", "scanf"];
                    let found_dangerous: Vec<&str> = dangerous_funcs
                        .iter()
                        .filter(|function| functions.iter().any(|string| string.contains(**function)))
                        .copied()
                        .collect();

                    if !found_dangerous.is_empty() {
                        exploitation_hints.push(format!(
                            "Dangerous functions found: {} - potential buffer overflow",
                            found_dangerous.join(", ")
                        ));
                    }
                }

                if !format_strings.is_empty() {
                    if format_strings.iter().any(|string| string.contains("%n")) {
                        exploitation_hints
                            .push("Format string with %n found - potential format string vulnerability".to_string());
                    }
                }
            }
        }
        Err(error) => {
            strings_analysis["error"] = json!(error);
        }
    }

    // ROP gadgets search
    if find_gadgets && matches!(analysis_depth.as_str(), "comprehensive" | "deep") {
        match subprocess_run(&["ROPgadget", "--binary", &binary_path, "--only", "pop|ret"], 60).await {
            Ok((returncode, stdout)) => {
                if returncode == 0 {
                    let gadget_lines = stdout.split('\n');
                    let mut useful_gadgets: Vec<String> = Vec::new();

                    for line in gadget_lines {
                        if line.contains("pop") && line.contains("ret") {
                            useful_gadgets.push(line.trim().to_string());
                        }
                    }

                    // Limit to first 20 gadgets
                    gadgets = useful_gadgets.iter().take(20).map(|gadget| json!(gadget)).collect();

                    if !useful_gadgets.is_empty() {
                        exploitation_hints.push(format!(
                            "Found {} ROP gadgets - ROP chain exploitation possible",
                            useful_gadgets.len()
                        ));
                        recommended_tools.push("ropper".to_string());
                    }
                }
            }
            Err(error) => {
                gadgets = vec![json!(format!("Error finding gadgets: {error}"))];
            }
        }
    }

    // Function analysis with objdump
    if matches!(analysis_depth.as_str(), "comprehensive" | "deep") {
        match subprocess_run(&["objdump", "-t", &binary_path], 30).await {
            Ok((returncode, stdout)) => {
                if returncode == 0 {
                    let mut functions: Vec<String> = Vec::new();
                    for line in stdout.split('\n') {
                        if line.contains("F .text") {
                            // Function in text section
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 6 {
                                if let Some(function) = parts.last() {
                                    functions.push((*function).to_string());
                                }
                            }
                        }
                    }

                    // Limit to first 50 functions
                    interesting_functions = functions.iter().take(50).map(|function| json!(function)).collect();
                }
            }
            Err(error) => {
                interesting_functions = vec![json!(format!("Error analyzing functions: {error}"))];
            }
        }
    }

    // Add tool recommendations based on findings
    if !exploitation_hints.is_empty() {
        recommended_tools.extend(["pwntools", "gdb-peda", "one-gadget"].map(str::to_string));
    }

    if exploitation_hints
        .iter()
        .any(|hint| hint.to_lowercase().contains("format string"))
    {
        recommended_tools.push("format-string-exploiter".to_string());
    }

    info!(
        "🔬 CTF binary analysis completed | Binary: {binary_path} | Hints: {}",
        exploitation_hints.len()
    );
    let analysis = json!({
        "binary_path": binary_path,
        "analysis_depth": analysis_depth,
        "file_info": Value::Object(file_info),
        "security_protections": Value::Object(security_protections),
        "interesting_functions": interesting_functions,
        "strings_analysis": strings_analysis,
        "gadgets": gadgets,
        "recommended_tools": recommended_tools,
        "exploitation_hints": exploitation_hints
    });

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "analysis": analysis,
            "timestamp": isoformat_now()
        })),
    )
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/ctf/create-challenge-workflow", post(create_ctf_challenge_workflow))
        .route("/api/ctf/auto-solve-challenge", post(auto_solve_ctf_challenge))
        .route("/api/ctf/team-strategy", post(create_ctf_team_strategy))
        .route("/api/ctf/suggest-tools", post(suggest_ctf_tools))
        .route("/api/ctf/cryptography-solver", post(ctf_cryptography_solver))
        .route("/api/ctf/forensics-analyzer", post(ctf_forensics_analyzer))
        .route("/api/ctf/binary-analyzer", post(ctf_binary_analyzer))
}
