//! Port 1:1 de `hexstrike_server/routes/http_testing.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W9.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    30  class HTTPTestingFramework:
//!   372  class BrowserAgent:
//!   789  def http_framework_endpoint
//!   885  def browser_agent_endpoint
//!   974  def burpsuite_alternative
//!  1068  def zap
//!  1118  def wafw00f
//!  1147  def fierce
//!  1180  def dnsenum
//!  1218  def install_python_package
//!  1248  def execute_python_script
//! ```
//!
//! Rotas (`@app.route`) deste módulo (9):
//!
//! ```text
//!   788  http_framework_endpoint("/api/tools/http-framework", methods=["POST"])
//!   884  browser_agent_endpoint("/api/tools/browser-agent", methods=["POST"])
//!   973  burpsuite_alternative("/api/tools/burpsuite-alternative", methods=["POST"])
//!  1067  zap("/api/tools/zap", methods=["POST"])
//!  1117  wafw00f("/api/tools/wafw00f", methods=["POST"])
//!  1146  fierce("/api/tools/fierce", methods=["POST"])
//!  1179  dnsenum("/api/tools/dnsenum", methods=["POST"])
//!  1217  install_python_package("/api/python/install", methods=["POST"])
//!  1247  execute_python_script("/api/python/execute", methods=["POST"])
//! ```

//! ## O que NÃO tem port (e por quê)
//!
//! `HTTPTestingFramework` e `BrowserAgent` falam HTTP com `requests` e dirigem
//! o Chrome com `selenium`; o workspace não tem cliente HTTP nem driver de
//! browser nas dependências. O seam é uma função só — [`session_request`] —
//! que devolve o erro do ramo `except Exception` do Python. Consequências:
//!
//! * `intercept_request` / `send_custom_request` / `intruder_sniper` e a
//!   inspeção de página devolvem `{'success': False, 'error': ...}`, que é o
//!   que o Python devolve quando o `requests` falha.
//! * `spider_website` devolve `success: True` com resultados vazios, que é o
//!   caminho do Python quando o `GET` de cada URL levanta (o `except` interno
//!   loga `Error spidering ...` e continua a fila).
//! * `BrowserAgent.setup_browser` é sempre o ramo de falha, então
//!   `navigate_and_inspect` devolve `{'success': False, 'error': 'Failed to
//!   setup browser'}` — exatamente o que o Python devolve sem Chrome no PATH.
//!   Os helpers que só existem sobre um `driver` (`_get_local_storage`,
//!   `_get_session_storage`, `_extract_forms`, `_extract_links`,
//!   `_extract_inputs`, `_extract_scripts`, `_get_network_logs`,
//!   `_get_console_errors`, `_analyze_cookies`, `_analyze_security_headers`,
//!   `_detect_mixed_content`, `_extended_passive_analysis`,
//!   `_analyze_page_security`) não foram portados.
//! * `self.session.cookies` (cookie jar do requests) não tem equivalente.
//! * `/api/python/*` dependem de `env_manager` (process_termination.py, ainda
//!   stub) e `file_manager` (exploit_gen.py, ainda stub); os stand-ins no fim
//!   deste arquivo são 1:1 com os métodos que as rotas usam.
//! * `self.driver.get_log(...)`/`execute_script(...)` e a extração de
//!   links/formulários com BeautifulSoup: sem port.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use regex::Regex;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use hexstrike_intelligence::exploit_gen::execute_command;
use hexstrike_core::visual_engine::ModernVisualEngine;
use hexstrike_intelligence::vuln_intel::iso_now;

/// `jsonify(x)` (200) vs `jsonify(x), <status>` (≠200). O `Result` do axum
/// devolve o status só no ramo de erro, então o ramo 200 continua sendo
/// `Json<Value>`.
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// `datetime.now().isoformat()` — microssegundos com 6 dígitos, hora local.
/// (O `timestamp` é volátil no harness de paridade; o formato existe para o
/// corpo da resposta ficar igual ao do Python.)

/// `bool(x)` do Python para os valores que o JSON representa.
fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str(v)` do Python para os valores que o JSON representa.
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// `urlparse(url).hostname` — host em minúsculas, sem userinfo/porta.
fn urlparse_hostname(url: &str) -> String {
    let mut rest = url;
    if let Some(idx) = url.find("://") {
        let scheme = &url[..idx];
        let valid = !scheme.is_empty()
            && scheme
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            rest = &url[idx + 3..];
        }
    } else if let Some(after) = url.strip_prefix("//") {
        rest = after;
    } else {
        // Sem scheme e sem `//` o urlparse não tem netloc.
        return String::new();
    }

    let netloc = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string();
    let host_port = match netloc.rsplit_once('@') {
        Some((_, host)) => host,
        None => &netloc,
    };
    let host = match host_port.rsplit_once(':') {
        Some((host, _port)) => host,
        None => host_port,
    };
    host.to_lowercase()
}

/// `urlparse(url)` reduzido aos campos que `_apply_match_replace` usa:
/// (scheme, netloc, path, query, fragment).
fn url_split(url: &str) -> (String, String, String, String, String) {
    let mut rest = url;
    let mut scheme = String::new();

    if let Some(idx) = url.find("://") {
        let candidate = &url[..idx];
        let valid = !candidate.is_empty()
            && candidate
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            scheme = candidate.to_string();
            rest = &url[idx + 3..];
        }
    }

    // Netloc: só o que vem depois de `//` (com ou sem scheme).
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let (loc, tail) = match after.find(['/', '?', '#']) {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        netloc = loc.to_string();
        rest = tail;
    }

    let mut fragment = String::new();
    if let Some(idx) = rest.find('#') {
        fragment = rest[idx + 1..].to_string();
        rest = &rest[..idx];
    }
    let mut query = String::new();
    if let Some(idx) = rest.find('?') {
        query = rest[idx + 1..].to_string();
        rest = &rest[..idx];
    }

    (
        scheme,
        netloc,
        rest.to_string(),
        query,
        fragment,
    )
}

/// `urlunparse((scheme, netloc, path, params, query, fragment))` (params vazio).
fn url_unparse(scheme: &str, netloc: &str, path: &str, query: &str, fragment: &str) -> String {
    let mut url = path.to_string();
    if !netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url = format!("/{url}");
        }
        url = format!("//{netloc}{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !fragment.is_empty() {
        url = format!("{url}#{fragment}");
    }
    url
}

/// `quote_plus(s, safe='')`
fn quote_plus(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// `unquote_plus(s)`
fn unquote_plus(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// `parse_qsl(query, keep_blank_values=True)`
fn parse_qsl(query: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (name, value) = match segment.split_once('=') {
            Some((name, value)) => (name, value),
            None => (segment, ""),
        };
        pairs.push((unquote_plus(name), unquote_plus(value)));
    }
    pairs
}

/// `urlencode(pairs)` — `quote_via=quote_plus`.
fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", quote_plus(name), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `d[key] = value` sobre a lista de pares do `parse_qsl` (ordem de inserção,
/// substituindo o valor quando a chave já existe).
fn pairs_set(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = pairs.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value.to_string();
    } else {
        pairs.push((key.to_string(), value.to_string()));
    }
}

/// `re.sub(pattern, replacement, text)` — o replacement do Python usa `\1`
/// para retro-referência; o do Rust usa `${1}`.
fn py_re_sub(pattern: &str, replacement: &str, text: &str) -> Option<String> {
    let re = Regex::new(pattern).ok()?;
    let rust_replacement = py_replacement_to_rust(replacement);
    Some(re.replace_all(text, rust_replacement.as_str()).to_string())
}

fn py_replacement_to_rust(replacement: &str) -> String {
    let mut out = String::new();
    let mut chars = replacement.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some(d) if d.is_ascii_digit() => {
                    out.push_str(&format!("${{{d}}}"));
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                _ => out.push('\\'),
            },
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out
}

/// O que o port usa de `requests.Response`.
struct HttpResponse {
    status_code: i64,
    headers: BTreeMap<String, String>,
    request_headers: BTreeMap<String, String>,
    text: String,
    size: usize,
    elapsed: f64,
}

/// `self.session.get/post/put/delete/request(...)` — transporte HTTP do
/// `requests`, que o port não tem (ver cabeçalho). Por isso o ramo executado é
/// sempre o `except Exception` do Python, com `error` nesta mensagem.
fn session_request(
    _url: &str,
    _method: &str,
    _data: &Value,
    _headers: &BTreeMap<String, String>,
) -> Result<HttpResponse, String> {
    Err("HTTP transport unavailable in this port (requests not ported)".to_string())
}

/// `class HTTPTestingFramework` — "Advanced HTTP testing framework as Burp
/// Suite alternative".
pub struct HTTPTestingFramework {
    /// `self.session.headers`
    session_headers: BTreeMap<String, String>,
    /// `self.proxy_history`
    pub proxy_history: Vec<Value>,
    /// `self.vulnerabilities`
    pub vulnerabilities: Vec<Value>,
    /// `self.match_replace_rules`
    match_replace_rules: Vec<Value>,
    /// `self.scope` — `{'host': ..., 'include_subdomains': ...}`
    pub scope: Option<Value>,
    /// `self._req_id`
    req_id: i64,
}

impl HTTPTestingFramework {
    pub fn new() -> Self {
        let mut session_headers = BTreeMap::new();
        session_headers.insert(
            "User-Agent".to_string(),
            "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)".to_string(),
        );
        Self {
            session_headers,
            proxy_history: Vec::new(),
            vulnerabilities: Vec::new(),
            match_replace_rules: Vec::new(),
            scope: None,
            req_id: 0,
        }
    }

    /// `set_match_replace_rules(rules)` — `rules or []`
    pub fn set_match_replace_rules(&mut self, rules: &Value) {
        self.match_replace_rules = match rules.as_array() {
            Some(rules) => rules.clone(),
            None => Vec::new(),
        };
    }

    /// `set_scope(host, include_subdomains=True)`
    pub fn set_scope(&mut self, host: &str, include_subdomains: bool) {
        self.scope = Some(json!({
            "host": host,
            "include_subdomains": include_subdomains,
        }));
    }

    /// `_in_scope(url)`
    pub fn in_scope(&self, url: &str) -> bool {
        let Some(scope) = &self.scope else {
            return true;
        };
        let host = urlparse_hostname(url);
        let target = scope.get("host").and_then(Value::as_str).unwrap_or("");
        if host.is_empty() || target.is_empty() {
            return true;
        }
        if host == target {
            return true;
        }
        if json_truthy(scope.get("include_subdomains").unwrap_or(&Value::Null))
            && host.ends_with(&format!(".{target}"))
        {
            return true;
        }
        false
    }

    /// `_apply_match_replace(url, data, headers)`
    pub fn apply_match_replace(
        &self,
        url: &str,
        data: &Value,
        headers: &BTreeMap<String, String>,
    ) -> (String, Value, BTreeMap<String, String>) {
        let original_url = url.to_string();
        let mut url = url.to_string();
        let mut out_headers = headers.clone();
        let mut out_data = data.clone();

        for rule in &self.match_replace_rules {
            // `where = (rule.get('where') or 'url').lower()`
            let where_raw = rule.get("where").and_then(Value::as_str).unwrap_or("");
            let where_ = if where_raw.is_empty() {
                "url".to_string()
            } else {
                where_raw.to_lowercase()
            };
            let pattern = rule.get("pattern").and_then(Value::as_str).unwrap_or("");
            let repl = rule
                .get("replacement")
                .and_then(Value::as_str)
                .unwrap_or("");

            // `except Exception: continue` — regex inválida pula a regra.
            match where_.as_str() {
                "url" => {
                    if let Some(substituted) = py_re_sub(pattern, repl, &url) {
                        url = substituted;
                    }
                }
                "query" => {
                    let (scheme, netloc, path, query, fragment) = url_split(&url);
                    let qs = parse_qsl(&query);
                    let mut new_qs: Vec<(String, String)> = Vec::with_capacity(qs.len());
                    let mut ok = true;
                    for (k, v) in qs {
                        match (py_re_sub(pattern, repl, &k), py_re_sub(pattern, repl, &v)) {
                            (Some(new_k), Some(new_v)) => new_qs.push((new_k, new_v)),
                            _ => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        url = url_unparse(&scheme, &netloc, &path, &urlencode(&new_qs), &fragment);
                    }
                }
                "headers" => {
                    let mut rebuilt: BTreeMap<String, String> = BTreeMap::new();
                    let mut failed = false;
                    for (k, v) in &out_headers {
                        match (py_re_sub(pattern, repl, k), py_re_sub(pattern, repl, v)) {
                            (Some(new_k), Some(new_v)) => {
                                rebuilt.insert(new_k, new_v);
                            }
                            _ => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if !failed {
                        out_headers = rebuilt;
                    }
                }
                "body" => match &out_data {
                    Value::Object(body) => {
                        let mut rebuilt = serde_json::Map::new();
                        let mut failed = false;
                        for (k, v) in body {
                            let (Some(new_k), Some(new_v)) = (
                                py_re_sub(pattern, repl, k),
                                py_re_sub(pattern, repl, &py_str(v)),
                            ) else {
                                failed = true;
                                break;
                            };
                            rebuilt.insert(new_k, Value::String(new_v));
                        }
                        if !failed {
                            out_data = Value::Object(rebuilt);
                        }
                    }
                    Value::String(body) => {
                        if let Some(substituted) = py_re_sub(pattern, repl, body) {
                            out_data = Value::String(substituted);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Ensure scope restriction
        if !self.in_scope(&url) {
            warn!(
                "{}",
                ModernVisualEngine::format_tool_status(
                    "HTTP-Framework",
                    "SKIPPED",
                    &format!("Out of scope: {url}"),
                    0.0
                )
            );
            return (original_url, data.clone(), headers.clone());
        }

        (url, out_data, out_headers)
    }

    /// `_get_recent_vulns(limit=10)`
    pub fn get_recent_vulns(&self, limit: usize) -> Vec<Value> {
        let len = self.vulnerabilities.len();
        self.vulnerabilities[len.saturating_sub(limit)..].to_vec()
    }

    /// `_analyze_response_for_vulns(url, response)`
    fn analyze_response_for_vulns(&mut self, url: &str, response: &HttpResponse) {
        let mut vulns: Vec<Value> = Vec::new();

        // Check for missing security headers
        let security_headers = [
            ("X-Frame-Options", "Clickjacking protection missing"),
            (
                "X-Content-Type-Options",
                "MIME type sniffing protection missing",
            ),
            ("X-XSS-Protection", "XSS protection missing"),
            ("Strict-Transport-Security", "HTTPS enforcement missing"),
            ("Content-Security-Policy", "Content Security Policy missing"),
        ];

        for (header, description) in security_headers {
            if !response.headers.contains_key(header) {
                vulns.push(json!({
                    "type": "missing_security_header",
                    "severity": "medium",
                    "description": description,
                    "url": url,
                    "header": header,
                }));
            }
        }

        // Check for sensitive information disclosure
        let sensitive_patterns = [
            (r#"password\s*[:=]\s*["']?([^"'\s]+)"#, "Password disclosure"),
            (r#"api[_-]?key\s*[:=]\s*["']?([^"'\s]+)"#, "API key disclosure"),
            (r#"secret\s*[:=]\s*["']?([^"'\s]+)"#, "Secret disclosure"),
            (r#"token\s*[:=]\s*["']?([^"'\s]+)"#, "Token disclosure"),
        ];

        for (pattern, description) in sensitive_patterns {
            let Ok(re) = Regex::new(&format!("(?i){pattern}")) else {
                continue;
            };
            let matches: Vec<Value> = re
                .captures_iter(&response.text)
                .filter_map(|c| c.get(1))
                .map(|m| json!(m.as_str()))
                .take(5)
                .collect();
            if !matches.is_empty() {
                vulns.push(json!({
                    "type": "information_disclosure",
                    "severity": "high",
                    "description": description,
                    "url": url,
                    "matches": matches,
                }));
            }
        }

        // Check for SQL injection indicators
        let sql_errors = [
            "SQL syntax error",
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider",
            "PostgreSQL query failed",
        ];

        let text_lower = response.text.to_lowercase();
        for sql_error in sql_errors {
            if text_lower.contains(&sql_error.to_lowercase()) {
                vulns.push(json!({
                    "type": "sql_injection_indicator",
                    "severity": "high",
                    "description": format!("Potential SQL injection: {sql_error}"),
                    "url": url,
                }));
            }
        }

        self.vulnerabilities.extend(vulns);
    }

    /// `intercept_request(url, method='GET', data=None, headers=None,
    /// cookies=None)`
    pub fn intercept_request(
        &mut self,
        url: &str,
        method: &str,
        data: &Value,
        headers: &Value,
        _cookies: &Value,
    ) -> Value {
        if json_truthy(headers) {
            if let Some(headers) = headers.as_object() {
                for (k, v) in headers {
                    self.session_headers.insert(k.clone(), py_str(v));
                }
            }
        }
        // `self.session.cookies.update(cookies)` — cookie jar do requests,
        // sem equivalente no port.

        // Apply match/replace rules prior to sending
        let (url, data, mut send_headers) =
            self.apply_match_replace(url, data, &self.session_headers.clone());
        if json_truthy(headers) {
            if let Some(headers) = headers.as_object() {
                for (k, v) in headers {
                    send_headers.insert(k.clone(), py_str(v));
                }
            }
        }

        let response = match session_request(&url, method, &data, &send_headers) {
            Ok(response) => response,
            Err(e) => {
                error!(
                    "{}",
                    ModernVisualEngine::format_error_card("ERROR", "HTTP-Framework", &e, "")
                );
                return json!({"success": false, "error": e});
            }
        };

        // Store request/response in history
        self.req_id += 1;
        let request_data = json!({
            "id": self.req_id,
            "url": url,
            "method": method,
            "headers": response.request_headers,
            "data": data,
            "timestamp": iso_now(),
        });

        let response_data = json!({
            "status_code": response.status_code,
            "headers": response.headers,
            "content": response.text.chars().take(10000).collect::<String>(),
            "size": response.size,
            "time": response.elapsed,
        });

        self.proxy_history.push(json!({
            "request": request_data.clone(),
            "response": response_data.clone(),
        }));

        // Analyze for vulnerabilities
        self.analyze_response_for_vulns(&url, &response);

        json!({
            "success": true,
            "request": request_data,
            "response": response_data,
            "vulnerabilities": self.get_recent_vulns(10),
        })
    }

    /// `send_custom_request(request_spec)`
    pub fn send_custom_request(&mut self, request_spec: &Value) -> Value {
        let url = request_spec.get("url").and_then(Value::as_str).unwrap_or("");
        let method = request_spec
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET");
        let headers = request_spec.get("headers").cloned().unwrap_or(json!({}));
        let headers = if json_truthy(&headers) { headers } else { json!({}) };
        let cookies = request_spec.get("cookies").cloned().unwrap_or(json!({}));
        let cookies = if json_truthy(&cookies) { cookies } else { json!({}) };
        let data = request_spec.get("data").cloned().unwrap_or(Value::Null);
        self.intercept_request(url, method, &data, &headers, &cookies)
    }

    /// `intruder_sniper(url, method='GET', location='query', params=None,
    /// payloads=None, base_data=None, max_requests=100)`
    #[allow(clippy::too_many_arguments)]
    pub fn intruder_sniper(
        &mut self,
        url: &str,
        method: &str,
        location: &str,
        params: &Value,
        payloads: &Value,
        base_data: &Value,
        max_requests: i64,
    ) -> Value {
        let params = match params.as_array() {
            Some(params) => params.clone(),
            None => Vec::new(),
        };
        let payloads = match payloads.as_array() {
            Some(payloads) if !payloads.is_empty() => payloads.clone(),
            _ => vec![json!("'\"<>`, ${7*7}")],
        };
        let m_base_data = match base_data.as_object() {
            Some(_) => base_data.clone(),
            None => json!({}),
        };

        let mut interesting: Vec<Value> = Vec::new();
        let mut total = 0i64;

        let baseline = self.intercept_request(url, method, &m_base_data, &json!({}), &json!({}));
        let (base_status, base_len) = if json_truthy(baseline.get("success").unwrap_or(&Value::Null)) {
            let response = baseline.get("response").cloned().unwrap_or(json!({}));
            (
                response.get("status_code").and_then(Value::as_i64),
                response
                    .get("size")
                    .and_then(Value::as_i64),
            )
        } else {
            (None, None)
        };

        for p in &params {
            let p = py_str(p);
            for pay in &payloads {
                let pay = py_str(pay);
                if total >= max_requests {
                    break;
                }
                let mut m_url = url.to_string();
                let mut m_data = m_base_data.clone();
                let mut m_headers: BTreeMap<String, String> = BTreeMap::new();
                match location {
                    "query" => {
                        let (scheme, netloc, path, query, fragment) = url_split(url);
                        let mut q = parse_qsl(&query);
                        pairs_set(&mut q, &p, &pay);
                        m_url = url_unparse(&scheme, &netloc, &path, &urlencode(&q), &fragment);
                    }
                    "body" => {
                        if let Value::Object(body) = &mut m_data {
                            body.insert(p.clone(), json!(pay));
                        }
                    }
                    "headers" => {
                        m_headers.insert(p.clone(), pay.clone());
                    }
                    "cookie" => {
                        // `self.session.cookies.set(p, pay)` — jar do requests.
                    }
                    _ => {}
                }
                let m_headers_value = json!(m_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v)))
                    .collect::<serde_json::Map<String, Value>>());
                let resp = self.intercept_request(&m_url, method, &m_data, &m_headers_value, &json!({}));
                total += 1;
                if !json_truthy(resp.get("success").unwrap_or(&Value::Null)) {
                    continue;
                }
                let r = resp.get("response").cloned().unwrap_or(json!({}));
                let status_code = r.get("status_code").and_then(Value::as_i64);
                let size = r.get("size").and_then(Value::as_i64).unwrap_or(0);
                let changed = (base_status.is_some() && status_code != base_status)
                    || (base_len.is_some()
                        && base_len.map(|len| (size - len).abs() > 150).unwrap_or(false));
                let content = r.get("content").and_then(Value::as_str).unwrap_or("");
                let reflected = content.contains(&pay);
                if changed || reflected {
                    interesting.push(json!({
                        "param": p,
                        "payload": pay,
                        "status_code": status_code,
                        "size": size,
                        "reflected": reflected,
                    }));
                }
            }
        }

        let interesting: Vec<Value> = interesting.into_iter().take(50).collect();
        json!({
            "success": true,
            "tested": total,
            "interesting": interesting,
        })
    }

    /// `spider_website(base_url, max_depth=3, max_pages=100)`
    pub fn spider_website(&mut self, base_url: &str, max_depth: i64, max_pages: usize) -> Value {
        // `discovered_urls` é um `set` no Python: `list(...)` não tem ordem
        // definida. Aqui é um Vec na ordem de descoberta.
        let mut discovered_urls: Vec<String> = Vec::new();
        let mut to_visit: Vec<(String, i64)> = vec![(base_url.to_string(), 0)];
        let mut visited: Vec<String> = Vec::new();

        while !to_visit.is_empty() && discovered_urls.len() < max_pages {
            let (current_url, depth) = to_visit.remove(0);

            if visited.contains(&current_url) || depth > max_depth {
                continue;
            }

            visited.push(current_url.clone());

            match session_request(&current_url, "GET", &Value::Null, &BTreeMap::new()) {
                Ok(response) => {
                    if response.status_code == 200 {
                        discovered_urls.push(current_url.clone());
                        // Parse HTML for links and forms (BeautifulSoup): sem
                        // port — ver cabeçalho.
                    }
                }
                Err(e) => {
                    warn!("Error spidering {current_url}: {e}");
                    continue;
                }
            }
        }

        json!({
            "success": true,
            "discovered_urls": discovered_urls,
            "forms": Vec::<Value>::new(),
            "total_pages": discovered_urls.len(),
            "vulnerabilities": self.get_recent_vulns(10),
        })
    }
}

impl Default for HTTPTestingFramework {
    fn default() -> Self {
        Self::new()
    }
}

/// `class BrowserAgent` — "AI-powered browser agent for web application testing
/// and inspection".
pub struct BrowserAgent {
    /// `self.driver` do Python. Sem `selenium` no port nunca há driver, então
    /// `setup_browser` é sempre o ramo de falha.
    driver: Option<()>,
    /// `self.screenshots`
    screenshots: Vec<String>,
    /// `self.page_sources`
    page_sources: Vec<Value>,
}

impl BrowserAgent {
    pub fn new() -> Self {
        Self {
            driver: None,
            screenshots: Vec::new(),
            page_sources: Vec::new(),
        }
    }

    /// `setup_browser(headless=True, proxy_port=None) -> bool`
    pub fn setup_browser(&mut self, _headless: bool, _proxy_port: Option<i64>) -> bool {
        // `webdriver.Chrome(...)`: sem driver de browser no port, o `except`
        // do Python é sempre o caminho.
        error!(
            "{}",
            ModernVisualEngine::format_error_card(
                "ERROR",
                "BrowserAgent",
                "selenium/Chrome driver unavailable in this port",
                ""
            )
        );
        false
    }

    /// `navigate_and_inspect(url, wait_time=5)`
    pub fn navigate_and_inspect(&mut self, _url: &str, _wait_time: i64) -> Value {
        if self.driver.is_none() && !self.setup_browser(true, None) {
            return json!({"success": false, "error": "Failed to setup browser"});
        }

        // O restante do Python (screenshot, page_source, `_extract_*`,
        // `_analyze_page_security`) só roda com um `driver` vivo.
        json!({"success": false, "error": "Failed to setup browser"})
    }

    /// `run_active_tests(page_info, payload='<hexstrikeXSSTest123>')`
    pub fn run_active_tests(&mut self, page_info: &Value, payload: &str) -> Value {
        let mut findings: Vec<Value> = Vec::new();
        let mut tested = 0;

        let forms = page_info
            .get("forms")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for form in &forms {
            if form
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_uppercase()
                != "GET"
            {
                continue;
            }
            let mut params: Vec<String> = Vec::new();
            for input in form
                .get("inputs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(3)
            {
                let kind = input.get("type").and_then(Value::as_str).unwrap_or("text");
                if matches!(kind, "text" | "search") {
                    let name = input.get("name").and_then(Value::as_str).unwrap_or("param");
                    params.push(format!("{name}={payload}"));
                }
            }
            if params.is_empty() {
                continue;
            }
            let mut action = form
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if action.is_empty() {
                action = page_info
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
            if action.starts_with('/') {
                let base = page_info.get("url").and_then(Value::as_str).unwrap_or("");
                let (scheme, netloc, _, _, _) = url_split(base);
                action = url_unparse(
                    &scheme,
                    &netloc,
                    &format!("{}{action}", url_split(base).2),
                    "",
                    "",
                );
            }
            let separator = if action.contains('?') { '&' } else { '?' };
            let test_url = format!("{action}{separator}{}", params.join("&"));

            match session_request(&test_url, "GET", &Value::Null, &BTreeMap::new()) {
                Ok(response) => {
                    tested += 1;
                    if response.text.contains(payload) {
                        findings.push(json!({
                            "type": "reflected_xss",
                            "severity": "high",
                            "description": "Payload reflected in response",
                            "url": test_url,
                        }));
                    }
                }
                Err(_) => continue,
            }
            if tested >= 5 {
                break;
            }
        }

        json!({"active_findings": findings, "tested_forms": tested})
    }

    /// `close_browser()`
    pub fn close_browser(&mut self) {
        if self.driver.is_some() {
            self.driver = None;
            info!(
                "{}",
                ModernVisualEngine::format_tool_status(
                    "BrowserAgent",
                    "SUCCESS",
                    "Browser Closed",
                    0.0
                )
            );
        }
    }
}

impl Default for BrowserAgent {
    fn default() -> Self {
        Self::new()
    }
}

/// `http_framework = HTTPTestingFramework()`
#[allow(non_upper_case_globals)]
pub static http_framework: LazyLock<Mutex<HTTPTestingFramework>> =
    LazyLock::new(|| Mutex::new(HTTPTestingFramework::new()));

/// `browser_agent = BrowserAgent()`
#[allow(non_upper_case_globals)]
pub static browser_agent: LazyLock<Mutex<BrowserAgent>> =
    LazyLock::new(|| Mutex::new(BrowserAgent::new()));

// ---------------------------------------------------------------------------
// Delegação aos módulos de verdade: estas rotas usam `file_manager`
// (`intelligence/exploit_gen.py`) e `env_manager`
// (`intelligence/process_termination.py`). Os dois foram portados; as funções
// abaixo existem só para manter o nome que as rotas chamam, sem duplicar lógica.
// ---------------------------------------------------------------------------

/// `file_manager.create_file(filename, content, binary=False)`
async fn file_manager_create_file(filename: &str, content: &str) -> Value {
    hexstrike_intelligence::exploit_gen::file_manager.create_file(filename, content, false)
}

/// `file_manager.delete_file(filename)`
fn file_manager_delete_file(filename: &str) -> Value {
    hexstrike_intelligence::exploit_gen::file_manager.delete_file(filename)
}

/// `env_manager.install_package(env_name, package) -> bool`
async fn env_manager_install_package(env_name: &str, package: &str) -> bool {
    hexstrike_intelligence::process_termination::env_manager
        .install_package(env_name, package)
        .await
}

/// `env_manager.get_python_path(env_name) -> str`
async fn env_manager_python_path(env_name: &str) -> String {
    hexstrike_intelligence::process_termination::env_manager
        .get_python_path(env_name)
        .await
}

/// `@app.route("/api/tools/http-framework", methods=["POST"])` —
/// `def http_framework_endpoint()`.
pub async fn http_framework_endpoint(Json(params): Json<Value>) -> ApiResult {
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("request");
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let data = params.get("data").cloned().unwrap_or(json!({}));
    let headers = params.get("headers").cloned().unwrap_or(json!({}));
    let cookies = params.get("cookies").cloned().unwrap_or(json!({}));

    info!(
        "{}",
        ModernVisualEngine::create_section_header("HTTP FRAMEWORK", "🔥", "FIRE_RED")
    );

    match action {
        "request" => {
            if url.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "URL parameter is required for request action"})),
                ));
            }

            let request_command = format!("{method} {url}");
            info!(
                "{}",
                ModernVisualEngine::format_command_execution(&request_command, "STARTING", 0.0)
            );
            let result = {
                let mut framework = http_framework.lock().unwrap();
                framework.intercept_request(url, method, &data, &headers, &cookies)
            };

            if json_truthy(result.get("success").unwrap_or(&Value::Null)) {
                info!(
                    "{}",
                    ModernVisualEngine::format_tool_status("HTTP-Framework", "SUCCESS", url, 0.0)
                );
            } else {
                error!(
                    "{}",
                    ModernVisualEngine::format_tool_status("HTTP-Framework", "FAILED", url, 0.0)
                );
            }

            Ok(Json(result))
        }
        "spider" => {
            if url.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "URL parameter is required for spider action"})),
                ));
            }

            let max_depth = params.get("max_depth").and_then(Value::as_i64).unwrap_or(3);
            let max_pages = params.get("max_pages").and_then(Value::as_i64).unwrap_or(100);

            let spider_command = format!("Spider {url}");
            info!(
                "{}",
                ModernVisualEngine::format_command_execution(&spider_command, "STARTING", 0.0)
            );
            let result = {
                let mut framework = http_framework.lock().unwrap();
                framework.spider_website(url, max_depth, max_pages.max(0) as usize)
            };

            if json_truthy(result.get("success").unwrap_or(&Value::Null)) {
                let total_pages = result
                    .get("total_pages")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let pages_info = format!("{total_pages} pages");
                info!(
                    "{}",
                    ModernVisualEngine::format_tool_status("HTTP-Spider", "SUCCESS", &pages_info, 0.0)
                );
            } else {
                error!(
                    "{}",
                    ModernVisualEngine::format_tool_status("HTTP-Spider", "FAILED", url, 0.0)
                );
            }

            Ok(Json(result))
        }
        "proxy_history" => {
            let framework = http_framework.lock().unwrap();
            let history_len = framework.proxy_history.len();
            let history = framework.proxy_history[history_len.saturating_sub(100)..].to_vec();
            Ok(Json(json!({
                "success": true,
                "history": history,
                "total_requests": history_len,
                "vulnerabilities": framework.vulnerabilities.clone(),
            })))
        }
        "set_rules" => {
            let rules = params.get("rules").cloned().unwrap_or(json!([]));
            let mut framework = http_framework.lock().unwrap();
            framework.set_match_replace_rules(&rules);
            let rules_set = rules.as_array().map(|r| r.len()).unwrap_or(0);
            Ok(Json(json!({"success": true, "rules_set": rules_set})))
        }
        "set_scope" => {
            let scope_host = params.get("host").cloned().unwrap_or(Value::Null);
            let include_sub = params
                .get("include_subdomains")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if !json_truthy(&scope_host) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "host parameter required"})),
                ));
            }
            let mut framework = http_framework.lock().unwrap();
            framework.set_scope(&py_str(&scope_host), include_sub);
            Ok(Json(json!({
                "success": true,
                "scope": framework.scope.clone(),
            })))
        }
        "repeater" => {
            let request_spec = params
                .get("request")
                .cloned()
                .unwrap_or(Value::Null);
            let request_spec = if json_truthy(&request_spec) {
                request_spec
            } else {
                json!({})
            };
            let result = {
                let mut framework = http_framework.lock().unwrap();
                framework.send_custom_request(&request_spec)
            };
            Ok(Json(result))
        }
        "intruder" => {
            if url.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "URL parameter required"})),
                ));
            }
            let location = params
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or("query");
            let fuzz_params = params.get("params").cloned().unwrap_or(json!([]));
            let payloads = params.get("payloads").cloned().unwrap_or(json!([]));
            let base_data = params.get("base_data").cloned().unwrap_or(json!({}));
            let max_requests = params
                .get("max_requests")
                .and_then(Value::as_i64)
                .unwrap_or(100);
            let result = {
                let mut framework = http_framework.lock().unwrap();
                framework.intruder_sniper(
                    url,
                    method,
                    location,
                    &fuzz_params,
                    &payloads,
                    &base_data,
                    max_requests,
                )
            };
            Ok(Json(result))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unknown action: {other}")})),
        )),
    }
}

/// `@app.route("/api/tools/browser-agent", methods=["POST"])` —
/// `def browser_agent_endpoint()`.
pub async fn browser_agent_endpoint(Json(params): Json<Value>) -> ApiResult {
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("navigate");
    let url = params.get("url").and_then(Value::as_str).unwrap_or("");
    let headless = params
        .get("headless")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let wait_time = params.get("wait_time").and_then(Value::as_i64).unwrap_or(5);
    let proxy_port = params.get("proxy_port").and_then(Value::as_i64);
    let active_tests = params
        .get("active_tests")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    info!(
        "{}",
        ModernVisualEngine::create_section_header("BROWSER AGENT", "🌐", "CRIMSON")
    );

    match action {
        "navigate" => {
            if url.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "URL parameter is required for navigate action"})),
                ));
            }

            // Setup browser if not already done
            let setup_success = {
                let mut agent = browser_agent.lock().unwrap();
                if agent.driver.is_none() {
                    agent.setup_browser(headless, proxy_port)
                } else {
                    true
                }
            };
            if !setup_success {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to setup browser"})),
                ));
            }

            let mut result = {
                let mut agent = browser_agent.lock().unwrap();
                agent.navigate_and_inspect(url, wait_time)
            };
            if json_truthy(result.get("success").unwrap_or(&Value::Null)) && active_tests {
                let page_info = result.get("page_info").cloned().unwrap_or(json!({}));
                let active_results = {
                    let mut agent = browser_agent.lock().unwrap();
                    agent.run_active_tests(&page_info, "<hexstrikeXSSTest123>")
                };
                let findings_count = active_results
                    .get("active_findings")
                    .and_then(Value::as_array)
                    .map(|f| f.len())
                    .unwrap_or(0);
                if let Value::Object(map) = &mut result {
                    map.insert("active_tests".to_string(), active_results);
                }
                if findings_count > 0 {
                    warn!(
                        "{}",
                        ModernVisualEngine::format_error_card(
                            "WARNING",
                            "BrowserAgent",
                            &format!("Active findings: {findings_count}"),
                            ""
                        )
                    );
                }
            }
            Ok(Json(result))
        }
        "screenshot" => {
            let active = browser_agent.lock().unwrap().driver.is_some();
            if !active {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Browser not initialized. Use navigate action first."})),
                ));
            }

            // `driver.save_screenshot(...)` / `driver.current_url`: só existem
            // com um driver vivo, que este port não tem (ver cabeçalho).
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Server error: selenium driver not ported"})),
            ))
        }
        "close" => {
            {
                let mut agent = browser_agent.lock().unwrap();
                agent.close_browser();
            }
            Ok(Json(json!({"success": true, "message": "Browser closed successfully"})))
        }
        "status" => {
            let agent = browser_agent.lock().unwrap();
            Ok(Json(json!({
                "success": true,
                "browser_active": agent.driver.is_some(),
                "screenshots_taken": agent.screenshots.len(),
                "pages_visited": agent.page_sources.len(),
            })))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unknown action: {other}")})),
        )),
    }
}

/// `int(time.time())`
fn current_unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `@app.route("/api/tools/burpsuite-alternative", methods=["POST"])` —
/// `def burpsuite_alternative()`.
pub async fn burpsuite_alternative(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let scan_type = params
        .get("scan_type")
        .and_then(Value::as_str)
        .unwrap_or("comprehensive");
    let headless = params
        .get("headless")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let max_depth = params.get("max_depth").and_then(Value::as_i64).unwrap_or(3);
    let max_pages = params.get("max_pages").and_then(Value::as_i64).unwrap_or(50);

    if target.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    info!(
        "{}",
        ModernVisualEngine::create_section_header("BURP SUITE ALTERNATIVE", "🔥", "BLOOD_RED")
    );
    let scan_message = format!("Starting {scan_type} scan of {target}");
    info!(
        "{}",
        ModernVisualEngine::format_highlighted_text(&scan_message, "RED")
    );

    let mut results = json!({
        "target": target,
        "scan_type": scan_type,
        "timestamp": iso_now(),
        "success": true,
    });

    // Phase 1: Browser-based reconnaissance
    if matches!(scan_type, "comprehensive" | "spider") {
        info!(
            "{}",
            ModernVisualEngine::format_tool_status(
                "BrowserAgent",
                "RUNNING",
                "Reconnaissance Phase",
                0.0
            )
        );

        let browser_result = {
            let mut agent = browser_agent.lock().unwrap();
            if agent.driver.is_none() {
                agent.setup_browser(headless, None);
            }
            agent.navigate_and_inspect(target, 5)
        };
        if let Value::Object(map) = &mut results {
            map.insert("browser_analysis".to_string(), browser_result);
        }
    }

    // Phase 2: HTTP spidering
    if matches!(scan_type, "comprehensive" | "spider") {
        info!(
            "{}",
            ModernVisualEngine::format_tool_status("HTTP-Spider", "RUNNING", "Discovery Phase", 0.0)
        );

        let spider_result = {
            let mut framework = http_framework.lock().unwrap();
            framework.spider_website(target, max_depth, max_pages.max(0) as usize)
        };
        if let Value::Object(map) = &mut results {
            map.insert("spider_analysis".to_string(), spider_result);
        }
    }

    // Phase 3: Vulnerability analysis
    if matches!(scan_type, "comprehensive" | "active") {
        info!(
            "{}",
            ModernVisualEngine::format_tool_status("VulnScanner", "RUNNING", "Analysis Phase", 0.0)
        );

        // Test discovered endpoints — `results.get('spider_analysis',
        // {}).get('discovered_urls', [target])`
        let discovered_urls: Vec<String> = results
            .get("spider_analysis")
            .and_then(|s| s.get("discovered_urls"))
            .and_then(Value::as_array)
            .map(|urls| {
                urls.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .take(20)
                    .collect()
            })
            .unwrap_or_else(|| vec![target.to_string()]);

        let mut vuln_results: Vec<Value> = Vec::new();
        for url in &discovered_urls {
            let test_result = {
                let mut framework = http_framework.lock().unwrap();
                framework.intercept_request(url, "GET", &json!({}), &json!({}), &json!({}))
            };
            if json_truthy(test_result.get("success").unwrap_or(&Value::Null)) {
                vuln_results.push(test_result);
            }
        }

        let (total_vulnerabilities, recent) = {
            let framework = http_framework.lock().unwrap();
            (
                framework.vulnerabilities.len(),
                framework.get_recent_vulns(20),
            )
        };

        if let Value::Object(map) = &mut results {
            map.insert(
                "vulnerability_analysis".to_string(),
                json!({
                    "tested_urls": vuln_results.len(),
                    "total_vulnerabilities": total_vulnerabilities,
                    "recent_vulnerabilities": recent,
                }),
            );
        }
    }

    // Generate summary
    let (total_vulns, vuln_summary) = {
        let framework = http_framework.lock().unwrap();
        let mut summary: BTreeMap<String, i64> = BTreeMap::new();
        for vuln in &framework.vulnerabilities {
            let severity = vuln.get("severity").and_then(Value::as_str).unwrap_or("unknown");
            *summary.entry(severity.to_string()).or_insert(0) += 1;
        }
        (framework.vulnerabilities.len(), summary)
    };

    let pages_analyzed = results
        .get("spider_analysis")
        .and_then(|s| s.get("discovered_urls"))
        .and_then(Value::as_array)
        .map(|urls| urls.len())
        .unwrap_or(0);

    let security_score = std::cmp::max(0, 100 - (total_vulns as i64) * 5);
    if let Value::Object(map) = &mut results {
        map.insert(
            "summary".to_string(),
            json!({
                "total_vulnerabilities": total_vulns,
                "vulnerability_breakdown": vuln_summary,
                "pages_analyzed": pages_analyzed,
                "security_score": security_score,
            }),
        );
    }

    // Display summary with enhanced colors
    info!(
        "{}",
        ModernVisualEngine::create_section_header("SCAN COMPLETE", "✅", "SUCCESS")
    );
    let vuln_message = format!("Found {total_vulns} vulnerabilities");
    let color_choice = if total_vulns > 0 { "YELLOW" } else { "GREEN" };
    info!(
        "{}",
        ModernVisualEngine::format_highlighted_text(&vuln_message, color_choice)
    );

    for (severity, count) in &vuln_summary {
        info!(
            "  {}",
            ModernVisualEngine::format_vulnerability_severity(severity, *count as usize)
        );
    }

    Ok(Json(results))
}

/// `@app.route("/api/tools/zap", methods=["POST"])` — `def zap()`.
pub async fn zap(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let scan_type = params
        .get("scan_type")
        .and_then(Value::as_str)
        .unwrap_or("baseline");
    let api_key = params
        .get("api_key")
        .and_then(Value::as_str)
        .unwrap_or("");
    let daemon = params
        .get("daemon")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let port = params.get("port").and_then(Value::as_str).unwrap_or("8090");
    let host = params
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0");
    let format_type = params
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("xml");
    let output_file = params
        .get("output_file")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if target.is_empty() && scan_type != "daemon" {
        warn!("🎯 ZAP called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required for scans"})),
        ));
    }

    let mut command = if daemon {
        let mut command = format!("zaproxy -daemon -host {host} -port {port}");
        if !api_key.is_empty() {
            command.push_str(&format!(" -config api.key={api_key}"));
        }
        command
    } else {
        let mut command = format!("zaproxy -cmd -quickurl {target}");
        if !format_type.is_empty() {
            command.push_str(&format!(" -quickout {format_type}"));
        }
        if !output_file.is_empty() {
            command.push_str(&format!(" -quickprogress -dir \"{output_file}\""));
        }
        if !api_key.is_empty() {
            command.push_str(&format!(" -config api.key={api_key}"));
        }
        command
    };

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting ZAP scan: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 ZAP scan completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/wafw00f", methods=["POST"])` — `def wafw00f()`.
pub async fn wafw00f(Json(params): Json<Value>) -> ApiResult {
    let target = params
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if target.is_empty() {
        warn!("🛡️ Wafw00f called without target parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Target parameter is required"})),
        ));
    }

    let mut command = format!("wafw00f {target}");

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🛡️ Starting Wafw00f WAF detection: {target}");
    let result = execute_command(&command, true).await;
    info!("📊 Wafw00f completed for {target}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/fierce", methods=["POST"])` — `def fierce()`.
pub async fn fierce(Json(params): Json<Value>) -> ApiResult {
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("");
    let dns_server = params
        .get("dns_server")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if domain.is_empty() {
        warn!("🌐 Fierce called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("fierce --domain {domain}");

    if !dns_server.is_empty() {
        command.push_str(&format!(" --dns-servers {dns_server}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting Fierce DNS recon: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 Fierce completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/tools/dnsenum", methods=["POST"])` — `def dnsenum()`.
pub async fn dnsenum(Json(params): Json<Value>) -> ApiResult {
    let domain = params
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("");
    let dns_server = params
        .get("dns_server")
        .and_then(Value::as_str)
        .unwrap_or("");
    let wordlist = params
        .get("wordlist")
        .and_then(Value::as_str)
        .unwrap_or("");
    let additional_args = params
        .get("additional_args")
        .and_then(Value::as_str)
        .unwrap_or("");

    if domain.is_empty() {
        warn!("🌐 DNSenum called without domain parameter");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain parameter is required"})),
        ));
    }

    let mut command = format!("dnsenum {domain}");

    if !dns_server.is_empty() {
        command.push_str(&format!(" --dnsserver {dns_server}"));
    }

    if !wordlist.is_empty() {
        command.push_str(&format!(" --file {wordlist}"));
    }

    if !additional_args.is_empty() {
        command.push_str(&format!(" {additional_args}"));
    }

    info!("🔍 Starting DNSenum: {domain}");
    let result = execute_command(&command, true).await;
    info!("📊 DNSenum completed for {domain}");
    Ok(Json(result))
}

/// `@app.route("/api/python/install", methods=["POST"])` —
/// `def install_python_package()`.
pub async fn install_python_package(Json(params): Json<Value>) -> ApiResult {
    let package = params
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or("");
    let env_name = params
        .get("env_name")
        .and_then(Value::as_str)
        .unwrap_or("default");

    if package.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Package name is required"})),
        ));
    }

    info!("📦 Installing Python package: {package} in env {env_name}");
    let success = env_manager_install_package(env_name, package).await;

    if success {
        Ok(Json(json!({
            "success": true,
            "message": format!("Package {package} installed successfully"),
            "env_name": env_name,
        })))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to install package {package}"),
            })),
        ))
    }
}

/// `@app.route("/api/python/execute", methods=["POST"])` —
/// `def execute_python_script()`.
pub async fn execute_python_script(Json(params): Json<Value>) -> ApiResult {
    let script = params
        .get("script")
        .and_then(Value::as_str)
        .unwrap_or("");
    let env_name = params
        .get("env_name")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let filename = params
        .get("filename")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("script_{}.py", current_unix_time()));

    if script.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Script content is required"})),
        ));
    }

    // Create script file
    let script_result = file_manager_create_file(&filename, script).await;
    if !json_truthy(script_result.get("success").unwrap_or(&Value::Null)) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(script_result)));
    }

    // Get Python path for environment
    let python_path = env_manager_python_path(env_name).await;
    let script_path = script_result
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Execute script
    let command = format!("{python_path} {script_path}");
    info!("🐍 Executing Python script in env {env_name}: {filename}");
    let mut result = execute_command(&command, false).await;

    // Clean up script file
    file_manager_delete_file(&filename);

    if let Value::Object(map) = &mut result {
        map.insert("env_name".to_string(), json!(env_name));
        map.insert("script_filename".to_string(), json!(filename));
    }
    info!("📊 Python script execution completed");
    Ok(Json(result))
}

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
        .route("/api/tools/http-framework", post(http_framework_endpoint))
        .route("/api/tools/browser-agent", post(browser_agent_endpoint))
        .route("/api/tools/burpsuite-alternative", post(burpsuite_alternative))
        .route("/api/tools/zap", post(zap))
        .route("/api/tools/wafw00f", post(wafw00f))
        .route("/api/tools/fierce", post(fierce))
        .route("/api/tools/dnsenum", post(dnsenum))
        .route("/api/python/install", post(install_python_package))
        .route("/api/python/execute", post(execute_python_script))
}

