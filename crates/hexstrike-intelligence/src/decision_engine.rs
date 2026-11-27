//! Port 1:1 de `hexstrike_server/intelligence/decision_engine.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W1.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    24  class TargetType
//!    34  class TechnologyStack
//!    53  class TargetProfile:
//!    92  class AttackStep:
//!   101  class AttackChain:
//!   151  class IntelligentDecisionEngine:
//! ```

//!
//! `decision_engine` (o singleton do fim do arquivo) é o global consumido por
//! `routes.decision_engine`; com crate único é referência normal entre
//! módulos, sem trait nem camada de inversão.
//!
//! ## Divergência medida no Python do split (NÃO é bug do port)
//!
//! `optimize_parameters` chama `parameter_optimizer.optimize_parameters_advanced`, mas
//! este módulo NÃO define nem importa `parameter_optimizer`: o
//! `_registry.FORWARD_LAZY` está vazio e o singleton nasce em
//! `intelligence/process_manager.py`. Logo o ramo avançado — que é o default
//! (`_use_advanced_optimizer = True`) — estoura
//! `NameError: name 'parameter_optimizer' is not defined` em TODA chamada, e o
//! `except Exception as e` das rotas devolve 500
//! `{"error": "Server error: name 'parameter_optimizer' is not defined"}`.
//! Aqui esse `NameError` é o `Err` de [`IntelligentDecisionEngine::optimize_parameters`]
//! (o `Result` é o equivalente Rust da exceção), e é isso que preserva a
//! paridade com o Python real. Quando `intelligence/process_manager.rs` ganhar
//! `parameter_optimizer` (shard W5), a correção é trocar o `Err` do ramo
//! avançado pela chamada.

use linked_hash_map::LinkedHashMap;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

/// `class TargetType(Enum)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum TargetType {
    WEB_APPLICATION,
    NETWORK_HOST,
    API_ENDPOINT,
    CLOUD_SERVICE,
    MOBILE_APP,
    BINARY_FILE,
    UNKNOWN,
}

impl TargetType {
    /// `.value` do Enum (as chaves de `tool_effectiveness` são essas strings).
    pub fn value(&self) -> &'static str {
        match self {
            TargetType::WEB_APPLICATION => "web_application",
            TargetType::NETWORK_HOST => "network_host",
            TargetType::API_ENDPOINT => "api_endpoint",
            TargetType::CLOUD_SERVICE => "cloud_service",
            TargetType::MOBILE_APP => "mobile_app",
            TargetType::BINARY_FILE => "binary_file",
            TargetType::UNKNOWN => "unknown",
        }
    }
}

/// `class TechnologyStack(Enum)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum TechnologyStack {
    APACHE,
    NGINX,
    IIS,
    NODEJS,
    PHP,
    PYTHON,
    JAVA,
    DOTNET,
    WORDPRESS,
    DRUPAL,
    JOOMLA,
    REACT,
    ANGULAR,
    VUE,
    UNKNOWN,
}

impl TechnologyStack {
    /// `.value` do Enum
    pub fn value(&self) -> &'static str {
        match self {
            TechnologyStack::APACHE => "apache",
            TechnologyStack::NGINX => "nginx",
            TechnologyStack::IIS => "iis",
            TechnologyStack::NODEJS => "nodejs",
            TechnologyStack::PHP => "php",
            TechnologyStack::PYTHON => "python",
            TechnologyStack::JAVA => "java",
            TechnologyStack::DOTNET => "dotnet",
            TechnologyStack::WORDPRESS => "wordpress",
            TechnologyStack::DRUPAL => "drupal",
            TechnologyStack::JOOMLA => "joomla",
            TechnologyStack::REACT => "react",
            TechnologyStack::ANGULAR => "angular",
            TechnologyStack::VUE => "vue",
            TechnologyStack::UNKNOWN => "unknown",
        }
    }
}

/// `@dataclass TargetProfile` — os campos seguem as ANOTAÇÕES do dataclass
/// (`Dict[str, Any]` vira `Map<String, Value>`, `Dict[int, str]` vira
/// `BTreeMap<i64, String>`).
#[derive(Debug, Clone)]
pub struct TargetProfile {
    pub target: String,
    pub target_type: TargetType,
    pub ip_addresses: Vec<String>,
    pub open_ports: Vec<i64>,
    pub services: BTreeMap<i64, String>,
    pub technologies: Vec<TechnologyStack>,
    pub cms_type: Option<String>,
    pub cloud_provider: Option<String>,
    pub security_headers: Map<String, Value>,
    pub ssl_info: Map<String, Value>,
    pub subdomains: Vec<String>,
    pub endpoints: Vec<String>,
    pub attack_surface_score: f64,
    pub risk_level: String,
    pub confidence_score: f64,
}

impl TargetProfile {
    /// `TargetProfile(target=target)` — o resto vem dos defaults do dataclass.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            target_type: TargetType::UNKNOWN,
            ip_addresses: Vec::new(),
            open_ports: Vec::new(),
            services: BTreeMap::new(),
            technologies: Vec::new(),
            cms_type: None,
            cloud_provider: None,
            security_headers: Map::new(),
            ssl_info: Map::new(),
            subdomains: Vec::new(),
            endpoints: Vec::new(),
            attack_surface_score: 0.0,
            risk_level: "unknown".to_string(),
            confidence_score: 0.0,
        }
    }

    /// `to_dict()` — MESMAS chaves do Python.
    pub fn to_dict(&self) -> Value {
        json!({
            "target": self.target,
            "target_type": self.target_type.value(),
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": self.technologies.iter().map(|t| t.value()).collect::<Vec<_>>(),
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score,
        })
    }
}

/// `@dataclass AttackStep`
#[derive(Debug, Clone)]
pub struct AttackStep {
    pub tool: String,
    pub parameters: Value,
    pub expected_outcome: String,
    pub success_probability: f64,
    /// segundos
    pub execution_time_estimate: i64,
    pub dependencies: Vec<String>,
}

/// `class AttackChain`
#[derive(Debug, Clone)]
pub struct AttackChain {
    pub target_profile: TargetProfile,
    pub steps: Vec<AttackStep>,
    pub success_probability: f64,
    pub estimated_time: i64,
    /// `Set[str]` do Python. Um `set` de str não tem ordem garantida (em Python
    /// a ordem é a dos hashes, que muda com o `PYTHONHASHSEED`); aqui é a ordem
    /// de inserção, sem repetição.
    pub required_tools: Vec<String>,
    pub risk_level: String,
}

impl AttackChain {
    /// `def __init__(self, target_profile)`
    pub fn new(target_profile: TargetProfile) -> Self {
        Self {
            target_profile,
            steps: Vec::new(),
            success_probability: 0.0,
            estimated_time: 0,
            required_tools: Vec::new(),
            risk_level: "unknown".to_string(),
        }
    }

    /// `add_step(step)`
    pub fn add_step(&mut self, step: AttackStep) {
        if !self.required_tools.contains(&step.tool) {
            self.required_tools.push(step.tool.clone());
        }
        self.estimated_time += step.execution_time_estimate;
        self.steps.push(step);
    }

    /// `calculate_success_probability()` — probabilidade composta dos passos.
    pub fn calculate_success_probability(&mut self) {
        if self.steps.is_empty() {
            self.success_probability = 0.0;
            return;
        }

        let mut prob = 1.0;
        for step in &self.steps {
            prob *= step.success_probability;
        }

        self.success_probability = prob;
    }

    /// `to_dict()`
    pub fn to_dict(&self) -> Value {
        let steps: Vec<Value> = self
            .steps
            .iter()
            .map(|step| {
                json!({
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies,
                })
            })
            .collect();

        json!({
            "target": self.target_profile.target,
            "steps": steps,
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": self.required_tools,
            "risk_level": self.risk_level,
        })
    }
}

/// `class IntelligentDecisionEngine`
///
/// Os três atributos do `__init__` são `pub` (o Python não tem privacidade em
/// atributo sem `_`); `_use_advanced_optimizer` fica privado, como o `_` do
/// nome indica.
pub struct IntelligentDecisionEngine {
    /// `Dict[str, Dict[str, float]]` — `LinkedHashMap` porque
    /// `select_optimal_tools` usa `list(dict.keys())` e a ORDEM é observável na
    /// resposta (`selected_tools`).
    pub tool_effectiveness: LinkedHashMap<&'static str, LinkedHashMap<&'static str, f64>>,
    /// `Dict[str, Dict[str, List[str]]]` — o Python monta no `__init__` e nunca
    /// mais lê; dict de tipos mistos (as listas de `ports` são int).
    pub technology_signatures: Value,
    /// `Dict[str, List[Dict[str, Any]]]`
    pub attack_patterns: BTreeMap<&'static str, Vec<Value>>,
    /// `self._use_advanced_optimizer`. Único estado mutável da instância no
    /// Python; `AtomicBool` porque o singleton é `static` (precisa ser `Sync`)
    /// e o Python não tem lock nenhum em volta dele.
    _use_advanced_optimizer: AtomicBool,
}

impl IntelligentDecisionEngine {
    /// `def __init__(self)`
    pub fn new() -> Self {
        Self {
            tool_effectiveness: Self::_initialize_tool_effectiveness(),
            technology_signatures: Self::_initialize_technology_signatures(),
            attack_patterns: Self::_initialize_attack_patterns(),
            // Enable advanced optimization by default
            _use_advanced_optimizer: AtomicBool::new(true),
        }
    }

    /// `_initialize_tool_effectiveness()`
    fn _initialize_tool_effectiveness() -> LinkedHashMap<&'static str, LinkedHashMap<&'static str, f64>> {
        let mut effectiveness = LinkedHashMap::new();

        effectiveness.insert(
            TargetType::WEB_APPLICATION.value(),
            [
                ("nmap", 0.8),
                ("gobuster", 0.9),
                ("nuclei", 0.95),
                ("nikto", 0.85),
                ("sqlmap", 0.9),
                ("ffuf", 0.9),
                ("feroxbuster", 0.85),
                ("katana", 0.88),
                ("httpx", 0.85),
                ("wpscan", 0.95),
                ("burpsuite", 0.9),
                ("dirsearch", 0.87),
                ("gau", 0.82),
                ("waybackurls", 0.8),
                ("arjun", 0.9),
                ("paramspider", 0.85),
                ("x8", 0.88),
                ("jaeles", 0.92),
                ("dalfox", 0.93),
                ("anew", 0.7),
                ("qsreplace", 0.75),
                ("uro", 0.7),
            ]
            .into_iter()
            .collect(),
        );

        effectiveness.insert(
            TargetType::NETWORK_HOST.value(),
            [
                ("nmap", 0.95),
                ("nmap-advanced", 0.97),
                ("masscan", 0.92),
                ("rustscan", 0.9),
                ("autorecon", 0.95),
                ("enum4linux", 0.8),
                ("enum4linux-ng", 0.88),
                ("smbmap", 0.85),
                ("rpcclient", 0.82),
                ("nbtscan", 0.75),
                ("arp-scan", 0.85),
                ("responder", 0.88),
                ("hydra", 0.8),
                ("netexec", 0.85),
                ("amass", 0.7),
            ]
            .into_iter()
            .collect(),
        );

        effectiveness.insert(
            TargetType::API_ENDPOINT.value(),
            [
                ("nuclei", 0.9),
                ("ffuf", 0.85),
                ("arjun", 0.95),
                ("paramspider", 0.88),
                ("httpx", 0.9),
                ("x8", 0.92),
                ("katana", 0.85),
                ("jaeles", 0.88),
                ("postman", 0.8),
            ]
            .into_iter()
            .collect(),
        );

        effectiveness.insert(
            TargetType::CLOUD_SERVICE.value(),
            [
                ("prowler", 0.95),
                ("scout-suite", 0.92),
                ("cloudmapper", 0.88),
                ("pacu", 0.85),
                ("trivy", 0.9),
                ("clair", 0.85),
                ("kube-hunter", 0.9),
                ("kube-bench", 0.88),
                ("docker-bench-security", 0.85),
                ("falco", 0.87),
                ("checkov", 0.9),
                ("terrascan", 0.88),
            ]
            .into_iter()
            .collect(),
        );

        effectiveness.insert(
            TargetType::BINARY_FILE.value(),
            [
                ("ghidra", 0.95),
                ("radare2", 0.9),
                ("gdb", 0.85),
                ("gdb-peda", 0.92),
                ("angr", 0.88),
                ("pwntools", 0.9),
                ("ropgadget", 0.85),
                ("ropper", 0.88),
                ("one-gadget", 0.82),
                ("libc-database", 0.8),
                ("checksec", 0.75),
                ("strings", 0.7),
                ("objdump", 0.75),
                ("binwalk", 0.8),
                ("pwninit", 0.85),
            ]
            .into_iter()
            .collect(),
        );

        effectiveness
    }

    /// `_initialize_technology_signatures()`
    fn _initialize_technology_signatures() -> Value {
        let mut headers = Map::new();
        headers.insert(TechnologyStack::APACHE.value().to_string(), json!(["Apache", "apache"]));
        headers.insert(TechnologyStack::NGINX.value().to_string(), json!(["nginx", "Nginx"]));
        headers.insert(TechnologyStack::IIS.value().to_string(), json!(["Microsoft-IIS", "IIS"]));
        headers.insert(TechnologyStack::PHP.value().to_string(), json!(["PHP", "X-Powered-By: PHP"]));
        headers.insert(
            TechnologyStack::NODEJS.value().to_string(),
            json!(["Express", "X-Powered-By: Express"]),
        );
        headers.insert(TechnologyStack::PYTHON.value().to_string(), json!(["Django", "Flask", "Werkzeug"]));
        headers.insert(TechnologyStack::JAVA.value().to_string(), json!(["Tomcat", "JBoss", "WebLogic"]));
        headers.insert(TechnologyStack::DOTNET.value().to_string(), json!(["ASP.NET", "X-AspNet-Version"]));

        let mut content = Map::new();
        content.insert(
            TechnologyStack::WORDPRESS.value().to_string(),
            json!(["wp-content", "wp-includes", "WordPress"]),
        );
        content.insert(TechnologyStack::DRUPAL.value().to_string(), json!(["Drupal", "drupal", "/sites/default"]));
        content.insert(TechnologyStack::JOOMLA.value().to_string(), json!(["Joomla", "joomla", "/administrator"]));
        content.insert(TechnologyStack::REACT.value().to_string(), json!(["React", "react", "__REACT_DEVTOOLS"]));
        content.insert(TechnologyStack::ANGULAR.value().to_string(), json!(["Angular", "angular", "ng-version"]));
        content.insert(TechnologyStack::VUE.value().to_string(), json!(["Vue", "vue", "__VUE__"]));

        let mut ports = Map::new();
        ports.insert(TechnologyStack::APACHE.value().to_string(), json!([80, 443, 8080, 8443]));
        ports.insert(TechnologyStack::NGINX.value().to_string(), json!([80, 443, 8080]));
        ports.insert(TechnologyStack::IIS.value().to_string(), json!([80, 443, 8080]));
        ports.insert(TechnologyStack::NODEJS.value().to_string(), json!([3000, 8000, 8080, 9000]));

        json!({"headers": headers, "content": content, "ports": ports})
    }

    /// `_initialize_attack_patterns()`
    fn _initialize_attack_patterns() -> BTreeMap<&'static str, Vec<Value>> {
        let mut patterns: BTreeMap<&'static str, Vec<Value>> = BTreeMap::new();

        patterns.insert(
            "web_reconnaissance",
            vec![
                json!({"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}}),
                json!({"tool": "httpx", "priority": 2, "params": {"probe": true, "tech_detect": true}}),
                json!({"tool": "katana", "priority": 3, "params": {"depth": 3, "js_crawl": true}}),
                json!({"tool": "gau", "priority": 4, "params": {"include_subs": true}}),
                json!({"tool": "waybackurls", "priority": 5, "params": {"get_versions": false}}),
                json!({"tool": "nuclei", "priority": 6, "params": {"severity": "critical,high", "tags": "tech"}}),
                json!({"tool": "dirsearch", "priority": 7, "params": {"extensions": "php,html,js,txt", "threads": 30}}),
                json!({"tool": "gobuster", "priority": 8, "params": {"mode": "dir", "extensions": "php,html,js,txt"}}),
            ],
        );

        patterns.insert(
            "api_testing",
            vec![
                json!({"tool": "httpx", "priority": 1, "params": {"probe": true, "tech_detect": true}}),
                json!({"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": true}}),
                json!({"tool": "x8", "priority": 3, "params": {"method": "GET", "wordlist": "/usr/share/wordlists/x8/params.txt"}}),
                json!({"tool": "paramspider", "priority": 4, "params": {"level": 2}}),
                json!({"tool": "nuclei", "priority": 5, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}}),
                json!({"tool": "ffuf", "priority": 6, "params": {"mode": "parameter", "method": "POST"}}),
            ],
        );

        patterns.insert(
            "network_discovery",
            vec![
                json!({"tool": "arp-scan", "priority": 1, "params": {"local_network": true}}),
                json!({"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": true}}),
                json!({"tool": "nmap-advanced", "priority": 3, "params": {"scan_type": "-sS", "os_detection": true, "version_detection": true}}),
                json!({"tool": "masscan", "priority": 4, "params": {"rate": 1000, "ports": "1-65535", "banners": true}}),
                json!({"tool": "enum4linux-ng", "priority": 5, "params": {"shares": true, "users": true, "groups": true}}),
                json!({"tool": "nbtscan", "priority": 6, "params": {"verbose": true}}),
                json!({"tool": "smbmap", "priority": 7, "params": {"recursive": true}}),
                json!({"tool": "rpcclient", "priority": 8, "params": {"commands": "enumdomusers;enumdomgroups;querydominfo"}}),
            ],
        );

        patterns.insert(
            "vulnerability_assessment",
            vec![
                json!({"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high,medium", "update": true}}),
                json!({"tool": "jaeles", "priority": 2, "params": {"threads": 20, "timeout": 20}}),
                json!({"tool": "dalfox", "priority": 3, "params": {"mining_dom": true, "mining_dict": true}}),
                json!({"tool": "nikto", "priority": 4, "params": {"comprehensive": true}}),
                json!({"tool": "sqlmap", "priority": 5, "params": {"crawl": 2, "batch": true}}),
            ],
        );

        patterns.insert(
            "comprehensive_network_pentest",
            vec![
                json!({"tool": "autorecon", "priority": 1, "params": {"port_scans": "top-1000-ports", "service_scans": "default"}}),
                json!({"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": true}}),
                json!({"tool": "nmap-advanced", "priority": 3, "params": {"aggressive": true, "nse_scripts": "vuln,exploit"}}),
                json!({"tool": "enum4linux-ng", "priority": 4, "params": {"shares": true, "users": true, "groups": true, "policy": true}}),
                json!({"tool": "responder", "priority": 5, "params": {"wpad": true, "duration": 180}}),
            ],
        );

        patterns.insert(
            "binary_exploitation",
            vec![
                json!({"tool": "checksec", "priority": 1, "params": {}}),
                json!({"tool": "ghidra", "priority": 2, "params": {"analysis_timeout": 300, "output_format": "xml"}}),
                json!({"tool": "ropper", "priority": 3, "params": {"gadget_type": "rop", "quality": 2}}),
                json!({"tool": "one-gadget", "priority": 4, "params": {"level": 1}}),
                json!({"tool": "pwntools", "priority": 5, "params": {"exploit_type": "local"}}),
                json!({"tool": "gdb-peda", "priority": 6, "params": {"commands": "checksec\ninfo functions\nquit"}}),
            ],
        );

        patterns.insert(
            "ctf_pwn_challenge",
            vec![
                json!({"tool": "pwninit", "priority": 1, "params": {"template_type": "python"}}),
                json!({"tool": "checksec", "priority": 2, "params": {}}),
                json!({"tool": "ghidra", "priority": 3, "params": {"analysis_timeout": 180}}),
                json!({"tool": "ropper", "priority": 4, "params": {"gadget_type": "all", "quality": 3}}),
                json!({"tool": "angr", "priority": 5, "params": {"analysis_type": "symbolic"}}),
                json!({"tool": "one-gadget", "priority": 6, "params": {"level": 2}}),
            ],
        );

        patterns.insert(
            "aws_security_assessment",
            vec![
                json!({"tool": "prowler", "priority": 1, "params": {"provider": "aws", "output_format": "json"}}),
                json!({"tool": "scout-suite", "priority": 2, "params": {"provider": "aws"}}),
                json!({"tool": "cloudmapper", "priority": 3, "params": {"action": "collect"}}),
                json!({"tool": "pacu", "priority": 4, "params": {"modules": "iam__enum_users_roles_policies_groups"}}),
            ],
        );

        patterns.insert(
            "kubernetes_security_assessment",
            vec![
                json!({"tool": "kube-bench", "priority": 1, "params": {"output_format": "json"}}),
                json!({"tool": "kube-hunter", "priority": 2, "params": {"report": "json"}}),
                json!({"tool": "falco", "priority": 3, "params": {"duration": 120, "output_format": "json"}}),
            ],
        );

        patterns.insert(
            "container_security_assessment",
            vec![
                json!({"tool": "trivy", "priority": 1, "params": {"scan_type": "image", "severity": "HIGH,CRITICAL"}}),
                json!({"tool": "clair", "priority": 2, "params": {"output_format": "json"}}),
                json!({"tool": "docker-bench-security", "priority": 3, "params": {}}),
            ],
        );

        patterns.insert(
            "iac_security_assessment",
            vec![
                json!({"tool": "checkov", "priority": 1, "params": {"output_format": "json"}}),
                json!({"tool": "terrascan", "priority": 2, "params": {"scan_type": "all", "output_format": "json"}}),
                json!({"tool": "trivy", "priority": 3, "params": {"scan_type": "config", "severity": "HIGH,CRITICAL"}}),
            ],
        );

        patterns.insert(
            "multi_cloud_assessment",
            vec![
                json!({"tool": "scout-suite", "priority": 1, "params": {"provider": "aws"}}),
                json!({"tool": "prowler", "priority": 2, "params": {"provider": "aws"}}),
                json!({"tool": "checkov", "priority": 3, "params": {"framework": "terraform"}}),
                json!({"tool": "terrascan", "priority": 4, "params": {"scan_type": "all"}}),
            ],
        );

        patterns.insert(
            "bug_bounty_reconnaissance",
            vec![
                json!({"tool": "amass", "priority": 1, "params": {"mode": "enum", "passive": false}}),
                json!({"tool": "subfinder", "priority": 2, "params": {"silent": true, "all_sources": true}}),
                json!({"tool": "httpx", "priority": 3, "params": {"probe": true, "tech_detect": true, "status_code": true}}),
                json!({"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": true, "form_extraction": true}}),
                json!({"tool": "gau", "priority": 5, "params": {"include_subs": true}}),
                json!({"tool": "waybackurls", "priority": 6, "params": {"get_versions": false}}),
                json!({"tool": "paramspider", "priority": 7, "params": {"level": 2}}),
                json!({"tool": "arjun", "priority": 8, "params": {"method": "GET,POST", "stable": true}}),
            ],
        );

        patterns.insert(
            "bug_bounty_vulnerability_hunting",
            vec![
                json!({"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high", "tags": "rce,sqli,xss,ssrf"}}),
                json!({"tool": "dalfox", "priority": 2, "params": {"mining_dom": true, "mining_dict": true}}),
                json!({"tool": "sqlmap", "priority": 3, "params": {"batch": true, "level": 2, "risk": 2}}),
                json!({"tool": "jaeles", "priority": 4, "params": {"threads": 20, "timeout": 20}}),
                json!({"tool": "ffuf", "priority": 5, "params": {"match_codes": "200,204,301,302,307,401,403", "threads": 40}}),
            ],
        );

        patterns.insert(
            "bug_bounty_high_impact",
            vec![
                json!({"tool": "nuclei", "priority": 1, "params": {"severity": "critical", "tags": "rce,sqli,ssrf,lfi,xxe"}}),
                json!({"tool": "sqlmap", "priority": 2, "params": {"batch": true, "level": 3, "risk": 3, "tamper": "space2comment"}}),
                json!({"tool": "jaeles", "priority": 3, "params": {"signatures": "rce,sqli,ssrf", "threads": 30}}),
                json!({"tool": "dalfox", "priority": 4, "params": {"blind": true, "mining_dom": true, "custom_payload": "alert(document.domain)"}}),
            ],
        );

        patterns
    }

    /// `analyze_target(target)`
    pub fn analyze_target(&self, target: &str) -> TargetProfile {
        let mut profile = TargetProfile::new(target);

        // Determine target type
        profile.target_type = self._determine_target_type(target);

        // Basic network analysis
        if profile.target_type == TargetType::WEB_APPLICATION || profile.target_type == TargetType::API_ENDPOINT {
            profile.ip_addresses = self._resolve_domain(target);
        }

        // Technology detection (basic heuristics)
        if profile.target_type == TargetType::WEB_APPLICATION {
            profile.technologies = self._detect_technologies(target);
            profile.cms_type = self._detect_cms(target);
        }

        // Calculate attack surface score
        profile.attack_surface_score = self._calculate_attack_surface(&profile);

        // Determine risk level
        profile.risk_level = self._determine_risk_level(&profile);

        // Set confidence score
        profile.confidence_score = self._calculate_confidence(&profile);

        profile
    }

    /// `_determine_target_type(target)`
    fn _determine_target_type(&self, target: &str) -> TargetType {
        // URL patterns
        if target.starts_with("http://") || target.starts_with("https://") {
            let path = urlparse_path(target);
            if path.contains("/api/") || path.ends_with("/api") {
                return TargetType::API_ENDPOINT;
            }
            return TargetType::WEB_APPLICATION;
        }

        // IP address pattern
        static IP_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").unwrap());
        if IP_RE.is_match(target) {
            return TargetType::NETWORK_HOST;
        }

        // Domain name pattern
        static DOMAIN_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());
        if DOMAIN_RE.is_match(target) {
            return TargetType::WEB_APPLICATION;
        }

        // File patterns
        if [".exe", ".bin", ".elf", ".so", ".dll"].iter().any(|ext| target.ends_with(ext)) {
            return TargetType::BINARY_FILE;
        }

        // Cloud service patterns
        let target_lower = target.to_lowercase();
        if ["amazonaws.com", "azure", "googleapis.com"].iter().any(|cloud| target_lower.contains(cloud)) {
            return TargetType::CLOUD_SERVICE;
        }

        TargetType::UNKNOWN
    }

    /// `_resolve_domain(target)` — DNS blocking, igual ao `socket.gethostbyname`.
    fn _resolve_domain(&self, target: &str) -> Vec<String> {
        // try:
        let hostname = if target.starts_with("http://") || target.starts_with("https://") {
            urlparse_hostname(target)
        } else {
            Some(target)
        };

        if let Some(hostname) = hostname {
            if !hostname.is_empty() {
                // `socket.gethostbyname` só devolve IPv4
                if let Ok(addrs) = (hostname, 0u16).to_socket_addrs() {
                    let ipv4 = addrs.into_iter().find_map(|addr| match addr {
                        SocketAddr::V4(v4) => Some(v4),
                        SocketAddr::V6(_) => None,
                    });
                    if let Some(ip) = ipv4 {
                        return vec![ip.ip().to_string()];
                    }
                }
            }
        }
        // except Exception: pass
        Vec::new()
    }

    /// `_detect_technologies(target)`
    fn _detect_technologies(&self, target: &str) -> Vec<TechnologyStack> {
        let mut technologies = Vec::new();
        let target_lower = target.to_lowercase();

        // This is a simplified version - in practice, you'd make HTTP requests
        // and analyze headers, content, etc.
        if target_lower.contains("wordpress") || target_lower.contains("wp-") {
            technologies.push(TechnologyStack::WORDPRESS);
        }

        if [".php", "php"].iter().any(|ext| target_lower.contains(ext)) {
            technologies.push(TechnologyStack::PHP);
        }

        if [".asp", ".aspx"].iter().any(|ext| target_lower.contains(ext)) {
            technologies.push(TechnologyStack::DOTNET);
        }

        if technologies.is_empty() {
            vec![TechnologyStack::UNKNOWN]
        } else {
            technologies
        }
    }

    /// `_detect_cms(target)`
    fn _detect_cms(&self, target: &str) -> Option<String> {
        let target_lower = target.to_lowercase();

        if target_lower.contains("wordpress") || target_lower.contains("wp-") {
            Some("WordPress".to_string())
        } else if target_lower.contains("drupal") {
            Some("Drupal".to_string())
        } else if target_lower.contains("joomla") {
            Some("Joomla".to_string())
        } else {
            None
        }
    }

    /// `_calculate_attack_surface(profile)`
    fn _calculate_attack_surface(&self, profile: &TargetProfile) -> f64 {
        let mut score = 0.0;

        // Base score by target type (`type_scores.get(..., 3.0)`)
        score += match profile.target_type {
            TargetType::WEB_APPLICATION => 7.0,
            TargetType::API_ENDPOINT => 6.0,
            TargetType::NETWORK_HOST => 8.0,
            TargetType::CLOUD_SERVICE => 5.0,
            TargetType::BINARY_FILE => 4.0,
            _ => 3.0,
        };

        // Add points for technologies / open ports / subdomains
        score += profile.technologies.len() as f64 * 0.5;
        score += profile.open_ports.len() as f64 * 0.3;
        score += profile.subdomains.len() as f64 * 0.2;

        // CMS adds attack surface (`if profile.cms_type:` — "" também é falso)
        if profile.cms_type.as_deref().is_some_and(|cms| !cms.is_empty()) {
            score += 1.5;
        }

        score.min(10.0)
    }

    /// `_determine_risk_level(profile)`
    fn _determine_risk_level(&self, profile: &TargetProfile) -> String {
        let score = profile.attack_surface_score;
        let level = if score >= 8.0 {
            "critical"
        } else if score >= 6.0 {
            "high"
        } else if score >= 4.0 {
            "medium"
        } else if score >= 2.0 {
            "low"
        } else {
            "minimal"
        };
        level.to_string()
    }

    /// `_calculate_confidence(profile)`
    fn _calculate_confidence(&self, profile: &TargetProfile) -> f64 {
        let mut confidence = 0.5f64;

        if !profile.ip_addresses.is_empty() {
            confidence += 0.1;
        }
        if profile.technologies.first().is_some_and(|tech| *tech != TechnologyStack::UNKNOWN) {
            confidence += 0.2;
        }
        if profile.cms_type.as_deref().is_some_and(|cms| !cms.is_empty()) {
            confidence += 0.1;
        }
        if profile.target_type != TargetType::UNKNOWN {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }

    /// `select_optimal_tools(profile, objective="comprehensive")`
    pub fn select_optimal_tools(&self, profile: &TargetProfile, objective: &str) -> Vec<&'static str> {
        let effectiveness_map = self.tool_effectiveness.get(profile.target_type.value());

        // Get base tools for target type
        let base_tools: Vec<&'static str> = match effectiveness_map {
            Some(map) => map.keys().copied().collect(),
            None => Vec::new(),
        };

        // `effectiveness_map.get(tool, 0)`
        let effectiveness = |tool: &str| -> f64 {
            effectiveness_map.and_then(|map| map.get(tool).copied()).unwrap_or(0.0)
        };

        // Apply objective-based filtering
        let mut selected_tools: Vec<&'static str> = if objective == "quick" {
            // Select top 3 most effective tools (sort estável, como o `sorted`
            // do Python: empates mantêm a ordem de inserção do dict)
            let mut sorted_tools = base_tools.clone();
            sorted_tools.sort_by(|a, b| {
                effectiveness(b).partial_cmp(&effectiveness(a)).unwrap_or(std::cmp::Ordering::Equal)
            });
            sorted_tools.into_iter().take(3).collect()
        } else if objective == "comprehensive" {
            // Select all tools with effectiveness > 0.7
            base_tools.iter().copied().filter(|tool| effectiveness(tool) > 0.7).collect()
        } else if objective == "stealth" {
            // Select passive tools with lower detection probability
            let stealth_tools = ["amass", "subfinder", "httpx", "nuclei"];
            base_tools.iter().copied().filter(|tool| stealth_tools.contains(tool)).collect()
        } else {
            base_tools
        };

        // Add technology-specific tools
        for tech in &profile.technologies {
            if *tech == TechnologyStack::WORDPRESS && !selected_tools.contains(&"wpscan") {
                selected_tools.push("wpscan");
            } else if *tech == TechnologyStack::PHP && !selected_tools.contains(&"nikto") {
                selected_tools.push("nikto");
            }
        }

        selected_tools
    }

    /// `optimize_parameters(tool, profile, context=None)`
    ///
    /// `Err` é o `NameError` que o Python do split levanta em toda chamada
    /// (ver a nota no topo do arquivo).
    pub fn optimize_parameters(
        &self,
        tool: &str,
        profile: &TargetProfile,
        context: Option<&Map<String, Value>>,
    ) -> Result<Value, String> {
        let empty = Map::new();
        let context = context.unwrap_or(&empty);

        // Use advanced parameter optimizer if available
        if self._use_advanced_optimizer.load(Ordering::Relaxed) {
            // return parameter_optimizer.optimize_parameters_advanced(tool, profile, context)
            return Err(PARAMETER_OPTIMIZER_UNDEFINED.to_string());
        }

        // Fallback to legacy optimization for compatibility
        let optimized_params = match tool {
            "nmap" => self._optimize_nmap_params(profile, context),
            "gobuster" => self._optimize_gobuster_params(profile, context),
            "nuclei" => self._optimize_nuclei_params(profile, context),
            "sqlmap" => self._optimize_sqlmap_params(profile, context),
            "ffuf" => self._optimize_ffuf_params(profile, context),
            "hydra" => self._optimize_hydra_params(profile, context),
            "rustscan" => self._optimize_rustscan_params(profile, context),
            "masscan" => self._optimize_masscan_params(profile, context),
            "nmap-advanced" => self._optimize_nmap_advanced_params(profile, context),
            "enum4linux-ng" => self._optimize_enum4linux_ng_params(profile, context),
            "autorecon" => self._optimize_autorecon_params(profile, context),
            "ghidra" => self._optimize_ghidra_params(profile, context),
            "pwntools" => self._optimize_pwntools_params(profile, context),
            "ropper" => self._optimize_ropper_params(profile, context),
            "angr" => self._optimize_angr_params(profile, context),
            "prowler" => self._optimize_prowler_params(profile, context),
            "scout-suite" => self._optimize_scout_suite_params(profile, context),
            "kube-hunter" => self._optimize_kube_hunter_params(profile, context),
            "trivy" => self._optimize_trivy_params(profile, context),
            "checkov" => self._optimize_checkov_params(profile, context),
            // Use advanced optimizer for unknown tools
            _ => return Err(PARAMETER_OPTIMIZER_UNDEFINED.to_string()),
        };

        Ok(optimized_params)
    }

    /// `enable_advanced_optimization()`
    pub fn enable_advanced_optimization(&self) {
        self._use_advanced_optimizer.store(true, Ordering::Relaxed);
    }

    /// `disable_advanced_optimization()` (use legacy)
    pub fn disable_advanced_optimization(&self) {
        self._use_advanced_optimizer.store(false, Ordering::Relaxed);
    }

    /// `_optimize_nmap_params(profile, context)`
    fn _optimize_nmap_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        if profile.target_type == TargetType::WEB_APPLICATION {
            params.insert("scan_type".to_string(), json!("-sV -sC"));
            params.insert("ports".to_string(), json!("80,443,8080,8443,8000,9000"));
        } else if profile.target_type == TargetType::NETWORK_HOST {
            params.insert("scan_type".to_string(), json!("-sS -O"));
            params.insert("additional_args".to_string(), json!("--top-ports 1000"));
        }

        // Adjust timing based on stealth requirements
        let additional_args = params.get("additional_args").and_then(Value::as_str).unwrap_or("");
        let timing = if get_truthy(context, "stealth", false) { " -T2" } else { " -T4" };
        params.insert("additional_args".to_string(), json!(format!("{additional_args}{timing}")));

        Value::Object(params)
    }

    /// `_optimize_gobuster_params(profile, context)`
    fn _optimize_gobuster_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("url".to_string(), json!(profile.target));
        params.insert("mode".to_string(), json!("dir"));

        // Select wordlist based on detected technologies
        let additional_args = if profile.technologies.contains(&TechnologyStack::PHP) {
            "-x php,html,txt,xml"
        } else if profile.technologies.contains(&TechnologyStack::DOTNET) {
            "-x asp,aspx,html,txt"
        } else if profile.technologies.contains(&TechnologyStack::JAVA) {
            "-x jsp,html,txt,xml"
        } else {
            "-x html,php,txt,js"
        };
        let threads = if get_truthy(context, "aggressive", false) { " -t 50" } else { " -t 20" };
        params.insert("additional_args".to_string(), json!(format!("{additional_args}{threads}")));

        Value::Object(params)
    }

    /// `_optimize_nuclei_params(profile, context)`
    fn _optimize_nuclei_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Set severity based on context
        if get_truthy(context, "quick", false) {
            params.insert("severity".to_string(), json!("critical,high"));
        } else {
            params.insert("severity".to_string(), json!("critical,high,medium"));
        }

        // Add technology-specific tags
        let mut tags = Vec::new();
        for tech in &profile.technologies {
            if *tech == TechnologyStack::WORDPRESS {
                tags.push("wordpress");
            } else if *tech == TechnologyStack::DRUPAL {
                tags.push("drupal");
            } else if *tech == TechnologyStack::JOOMLA {
                tags.push("joomla");
            }
        }

        if !tags.is_empty() {
            params.insert("tags".to_string(), json!(tags.join(",")));
        }

        Value::Object(params)
    }

    /// `_optimize_sqlmap_params(profile, context)`
    fn _optimize_sqlmap_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("url".to_string(), json!(profile.target));

        // Add database-specific options based on detected technologies
        let additional_args = if profile.technologies.contains(&TechnologyStack::PHP) {
            "--dbms=mysql --batch"
        } else if profile.technologies.contains(&TechnologyStack::DOTNET) {
            "--dbms=mssql --batch"
        } else {
            "--batch"
        };

        // Adjust aggressiveness
        let additional_args = if get_truthy(context, "aggressive", false) {
            format!("{additional_args} --level=3 --risk=2")
        } else {
            additional_args.to_string()
        };
        params.insert("additional_args".to_string(), json!(additional_args));

        Value::Object(params)
    }

    /// `_optimize_ffuf_params(profile, context)`
    fn _optimize_ffuf_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("url".to_string(), json!(profile.target));

        // Set match codes based on target type
        if profile.target_type == TargetType::API_ENDPOINT {
            params.insert("match_codes".to_string(), json!("200,201,202,204,301,302,401,403"));
        } else {
            params.insert("match_codes".to_string(), json!("200,204,301,302,307,401,403"));
        }

        // Adjust threads
        if get_truthy(context, "stealth", false) {
            params.insert("additional_args".to_string(), json!("-t 10 -p 1"));
        } else {
            params.insert("additional_args".to_string(), json!("-t 40"));
        }

        Value::Object(params)
    }

    /// `_optimize_hydra_params(profile, context)`
    fn _optimize_hydra_params(&self, profile: &TargetProfile, _context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Determine service based on open ports
        let service = if profile.open_ports.contains(&22) {
            "ssh"
        } else if profile.open_ports.contains(&21) {
            "ftp"
        } else if profile.open_ports.contains(&80) || profile.open_ports.contains(&443) {
            "http-get"
        } else {
            "ssh"
        };
        params.insert("service".to_string(), json!(service));

        // Set conservative parameters to avoid lockouts
        params.insert("additional_args".to_string(), json!("-t 4 -w 30"));

        Value::Object(params)
    }

    /// `_optimize_rustscan_params(profile, context)`
    fn _optimize_rustscan_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Adjust performance based on context
        if get_truthy(context, "stealth", false) {
            params.insert("ulimit".to_string(), json!(1000));
            params.insert("batch_size".to_string(), json!(500));
            params.insert("timeout".to_string(), json!(3000));
        } else if get_truthy(context, "aggressive", false) {
            params.insert("ulimit".to_string(), json!(10000));
            params.insert("batch_size".to_string(), json!(8000));
            params.insert("timeout".to_string(), json!(800));
        } else {
            params.insert("ulimit".to_string(), json!(5000));
            params.insert("batch_size".to_string(), json!(4500));
            params.insert("timeout".to_string(), json!(1500));
        }

        // Enable scripts for comprehensive scans
        if context.get("objective").and_then(Value::as_str).unwrap_or("normal") == "comprehensive" {
            params.insert("scripts".to_string(), json!(true));
        }

        Value::Object(params)
    }

    /// `_optimize_masscan_params(profile, context)`
    fn _optimize_masscan_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Intelligent rate limiting based on target type
        if get_truthy(context, "stealth", false) {
            params.insert("rate".to_string(), json!(100));
        } else if get_truthy(context, "aggressive", false) {
            params.insert("rate".to_string(), json!(10000));
        } else {
            params.insert("rate".to_string(), json!(1000));
        }

        // Enable banners for service detection
        if get_truthy(context, "service_detection", true) {
            params.insert("banners".to_string(), json!(true));
        }

        Value::Object(params)
    }

    /// `_optimize_nmap_advanced_params(profile, context)`
    fn _optimize_nmap_advanced_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Select scan type based on context
        if get_truthy(context, "stealth", false) {
            params.insert("scan_type".to_string(), json!("-sS"));
            params.insert("timing".to_string(), json!("T2"));
            params.insert("stealth".to_string(), json!(true));
        } else if get_truthy(context, "aggressive", false) {
            params.insert("scan_type".to_string(), json!("-sS"));
            params.insert("timing".to_string(), json!("T4"));
            params.insert("aggressive".to_string(), json!(true));
        } else {
            params.insert("scan_type".to_string(), json!("-sS"));
            params.insert("timing".to_string(), json!("T4"));
            params.insert("os_detection".to_string(), json!(true));
            params.insert("version_detection".to_string(), json!(true));
        }

        // Add NSE scripts based on target type
        if profile.target_type == TargetType::WEB_APPLICATION {
            params.insert("nse_scripts".to_string(), json!("http-*,ssl-*"));
        } else if profile.target_type == TargetType::NETWORK_HOST {
            params.insert("nse_scripts".to_string(), json!("default,discovery,safe"));
        }

        Value::Object(params)
    }

    /// `_optimize_enum4linux_ng_params(profile, context)`
    fn _optimize_enum4linux_ng_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Enable comprehensive enumeration by default
        params.insert("shares".to_string(), json!(true));
        params.insert("users".to_string(), json!(true));
        params.insert("groups".to_string(), json!(true));
        params.insert("policy".to_string(), json!(true));

        // Add authentication if available in context
        if get_truthy(context, "username", false) {
            params.insert("username".to_string(), context["username"].clone());
        }
        if get_truthy(context, "password", false) {
            params.insert("password".to_string(), context["password"].clone());
        }
        if get_truthy(context, "domain", false) {
            params.insert("domain".to_string(), context["domain"].clone());
        }

        Value::Object(params)
    }

    /// `_optimize_autorecon_params(profile, context)`
    fn _optimize_autorecon_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));

        // Adjust scan depth based on objective
        if get_truthy(context, "quick", false) {
            params.insert("port_scans".to_string(), json!("top-100-ports"));
            params.insert("timeout".to_string(), json!(180));
        } else if get_truthy(context, "comprehensive", true) {
            params.insert("port_scans".to_string(), json!("top-1000-ports"));
            params.insert("timeout".to_string(), json!(600));
        }

        // Set output directory
        params.insert(
            "output_dir".to_string(),
            json!(format!("/tmp/autorecon_{}", profile.target.replace('.', "_"))),
        );

        Value::Object(params)
    }

    /// `_optimize_ghidra_params(profile, context)`
    fn _optimize_ghidra_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("binary".to_string(), json!(profile.target));

        // Adjust analysis timeout based on context
        if get_truthy(context, "quick", false) {
            params.insert("analysis_timeout".to_string(), json!(120));
        } else if get_truthy(context, "comprehensive", true) {
            params.insert("analysis_timeout".to_string(), json!(600));
        } else {
            params.insert("analysis_timeout".to_string(), json!(300));
        }

        // Set project name based on binary (`os.path.basename`)
        let binary_name = Path::new(&profile.target)
            .file_name()
            .map(|name| name.to_string_lossy().replace('.', "_"))
            .unwrap_or_default();
        params.insert("project_name".to_string(), json!(format!("hexstrike_{binary_name}")));

        Value::Object(params)
    }

    /// `_optimize_pwntools_params(profile, context)`
    fn _optimize_pwntools_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target_binary".to_string(), json!(profile.target));

        // Set exploit type based on context
        if get_truthy(context, "remote_host", false) && get_truthy(context, "remote_port", false) {
            params.insert("exploit_type".to_string(), json!("remote"));
            params.insert("target_host".to_string(), context["remote_host"].clone());
            params.insert("target_port".to_string(), context["remote_port"].clone());
        } else {
            params.insert("exploit_type".to_string(), json!("local"));
        }

        Value::Object(params)
    }

    /// `_optimize_ropper_params(profile, context)`
    fn _optimize_ropper_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("binary".to_string(), json!(profile.target));

        // Set gadget type and quality based on context
        match context.get("exploit_type").and_then(Value::as_str) {
            Some("rop") => {
                params.insert("gadget_type".to_string(), json!("rop"));
                params.insert("quality".to_string(), json!(3));
            }
            Some("jop") => {
                params.insert("gadget_type".to_string(), json!("jop"));
                params.insert("quality".to_string(), json!(2));
            }
            _ => {
                params.insert("gadget_type".to_string(), json!("all"));
                params.insert("quality".to_string(), json!(2));
            }
        }

        // Set architecture if known
        if get_truthy(context, "arch", false) {
            params.insert("arch".to_string(), context["arch"].clone());
        }

        Value::Object(params)
    }

    /// `_optimize_angr_params(profile, context)`
    fn _optimize_angr_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("binary".to_string(), json!(profile.target));

        // Set analysis type based on context
        if get_truthy(context, "symbolic_execution", true) {
            params.insert("analysis_type".to_string(), json!("symbolic"));
        } else if get_truthy(context, "cfg_analysis", false) {
            params.insert("analysis_type".to_string(), json!("cfg"));
        } else {
            params.insert("analysis_type".to_string(), json!("static"));
        }

        // Add find/avoid addresses if provided
        if get_truthy(context, "find_address", false) {
            params.insert("find_address".to_string(), context["find_address"].clone());
        }
        if get_truthy(context, "avoid_addresses", false) {
            params.insert("avoid_addresses".to_string(), context["avoid_addresses"].clone());
        }

        Value::Object(params)
    }

    /// `_optimize_prowler_params(profile, context)`
    fn _optimize_prowler_params(&self, _profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("provider".to_string(), json!("aws"));

        // Set provider based on context or target analysis
        if get_truthy(context, "cloud_provider", false) {
            params.insert("provider".to_string(), context["cloud_provider"].clone());
        }

        // Set profile and region
        if get_truthy(context, "aws_profile", false) {
            params.insert("profile".to_string(), context["aws_profile"].clone());
        }
        if get_truthy(context, "aws_region", false) {
            params.insert("region".to_string(), context["aws_region"].clone());
        }

        // Set output format and directory
        params.insert("output_format".to_string(), json!("json"));
        params.insert(
            "output_dir".to_string(),
            json!(format!("/tmp/prowler_{}", params["provider"].as_str().unwrap_or_default())),
        );

        Value::Object(params)
    }

    /// `_optimize_scout_suite_params(profile, context)`
    fn _optimize_scout_suite_params(&self, _profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("provider".to_string(), json!("aws"));

        // Set provider based on context
        if get_truthy(context, "cloud_provider", false) {
            params.insert("provider".to_string(), context["cloud_provider"].clone());
        }

        // Set profile for AWS
        if params["provider"].as_str() == Some("aws") && get_truthy(context, "aws_profile", false) {
            params.insert("profile".to_string(), context["aws_profile"].clone());
        }

        // Set report directory
        params.insert(
            "report_dir".to_string(),
            json!(format!("/tmp/scout-suite_{}", params["provider"].as_str().unwrap_or_default())),
        );

        Value::Object(params)
    }

    /// `_optimize_kube_hunter_params(profile, context)`
    fn _optimize_kube_hunter_params(&self, _profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("report".to_string(), json!("json"));

        // Set target based on context
        if get_truthy(context, "kubernetes_target", false) {
            params.insert("target".to_string(), context["kubernetes_target"].clone());
        } else if get_truthy(context, "cidr", false) {
            params.insert("cidr".to_string(), context["cidr"].clone());
        } else if get_truthy(context, "interface", false) {
            params.insert("interface".to_string(), context["interface"].clone());
        }

        // Enable active hunting if specified
        if get_truthy(context, "active_hunting", false) {
            params.insert("active".to_string(), json!(true));
        }

        Value::Object(params)
    }

    /// `_optimize_trivy_params(profile, context)`
    fn _optimize_trivy_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("target".to_string(), json!(profile.target));
        params.insert("output_format".to_string(), json!("json"));

        // Determine scan type based on target
        let is_image = ["docker.io/", "gcr.io/", "quay.io/"]
            .iter()
            .any(|prefix| profile.target.starts_with(prefix))
            || profile.target.contains(':');
        if is_image {
            params.insert("scan_type".to_string(), json!("image"));
        } else if Path::new(&profile.target).is_dir() {
            params.insert("scan_type".to_string(), json!("fs"));
        } else {
            params.insert("scan_type".to_string(), json!("image"));
        }

        // Set severity filter
        if get_truthy(context, "severity", false) {
            params.insert("severity".to_string(), context["severity"].clone());
        } else {
            params.insert("severity".to_string(), json!("HIGH,CRITICAL"));
        }

        Value::Object(params)
    }

    /// `_optimize_checkov_params(profile, context)`
    fn _optimize_checkov_params(&self, profile: &TargetProfile, context: &Map<String, Value>) -> Value {
        let mut params = Map::new();
        params.insert("directory".to_string(), json!(profile.target));
        params.insert("output_format".to_string(), json!("json"));

        // Detect framework based on files in directory
        if get_truthy(context, "framework", false) {
            params.insert("framework".to_string(), context["framework"].clone());
        } else if Path::new(&profile.target).is_dir() {
            // Auto-detect framework (`os.listdir` + `os.path.isfile`)
            let files: Vec<String> = std::fs::read_dir(&profile.target)
                .map(|dir| {
                    dir.filter_map(|entry| entry.ok())
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .filter(|name| Path::new(&profile.target).join(name).is_file())
                        .collect()
                })
                .unwrap_or_default();

            if files.iter().any(|name| name.ends_with(".tf")) {
                params.insert("framework".to_string(), json!("terraform"));
            } else if files.iter().any(|name| name.ends_with(".yaml") || name.ends_with(".yml")) {
                params.insert("framework".to_string(), json!("kubernetes"));
            }
        }

        Value::Object(params)
    }

    /// `create_attack_chain(profile, objective="comprehensive")`
    pub fn create_attack_chain(&self, profile: &TargetProfile, objective: &str) -> Result<AttackChain, String> {
        let mut chain = AttackChain::new(profile.clone());

        // Select attack pattern based on target type and objective
        let pattern: Vec<&Value> = if profile.target_type == TargetType::WEB_APPLICATION {
            if objective == "quick" {
                self.attack_patterns["vulnerability_assessment"].iter().take(2).collect()
            } else {
                self.attack_patterns["web_reconnaissance"]
                    .iter()
                    .chain(self.attack_patterns["vulnerability_assessment"].iter())
                    .collect()
            }
        } else if profile.target_type == TargetType::API_ENDPOINT {
            self.attack_patterns["api_testing"].iter().collect()
        } else if profile.target_type == TargetType::NETWORK_HOST {
            if objective == "comprehensive" {
                self.attack_patterns["comprehensive_network_pentest"].iter().collect()
            } else {
                self.attack_patterns["network_discovery"].iter().collect()
            }
        } else if profile.target_type == TargetType::BINARY_FILE {
            if objective == "ctf" {
                self.attack_patterns["ctf_pwn_challenge"].iter().collect()
            } else {
                self.attack_patterns["binary_exploitation"].iter().collect()
            }
        } else if profile.target_type == TargetType::CLOUD_SERVICE {
            if objective == "aws" {
                self.attack_patterns["aws_security_assessment"].iter().collect()
            } else if objective == "kubernetes" {
                self.attack_patterns["kubernetes_security_assessment"].iter().collect()
            } else if objective == "containers" {
                self.attack_patterns["container_security_assessment"].iter().collect()
            } else if objective == "iac" {
                self.attack_patterns["iac_security_assessment"].iter().collect()
            } else {
                self.attack_patterns["multi_cloud_assessment"].iter().collect()
            }
        } else {
            // Handle bug bounty specific objectives
            if objective == "bug_bounty_recon" {
                self.attack_patterns["bug_bounty_reconnaissance"].iter().collect()
            } else if objective == "bug_bounty_hunting" {
                self.attack_patterns["bug_bounty_vulnerability_hunting"].iter().collect()
            } else if objective == "bug_bounty_high_impact" {
                self.attack_patterns["bug_bounty_high_impact"].iter().collect()
            } else {
                self.attack_patterns["web_reconnaissance"].iter().collect()
            }
        };

        // Create attack steps
        for step_config in pattern {
            let tool = step_config["tool"].as_str().unwrap_or_default();
            let optimized_params = self.optimize_parameters(tool, profile, None)?;

            // Calculate success probability based on tool effectiveness
            let effectiveness = self
                .tool_effectiveness
                .get(profile.target_type.value())
                .and_then(|map| map.get(tool).copied())
                .unwrap_or(0.5);
            let success_prob = effectiveness * profile.confidence_score;

            // Estimate execution time (simplified)
            let time_estimates: &[(&str, i64)] = &[
                ("nmap", 120),
                ("gobuster", 300),
                ("nuclei", 180),
                ("nikto", 240),
                ("sqlmap", 600),
                ("ffuf", 200),
                ("hydra", 900),
                ("amass", 300),
                ("ghidra", 300),
                ("radare2", 180),
                ("gdb", 120),
                ("gdb-peda", 150),
                ("angr", 600),
                ("pwntools", 240),
                ("ropper", 120),
                ("one-gadget", 60),
                ("checksec", 30),
                ("pwninit", 60),
                ("libc-database", 90),
                ("prowler", 600),
                ("scout-suite", 480),
                ("cloudmapper", 300),
                ("pacu", 420),
                ("trivy", 180),
                ("clair", 240),
                ("kube-hunter", 300),
                ("kube-bench", 120),
                ("docker-bench-security", 180),
                ("falco", 120),
                ("checkov", 240),
                ("terrascan", 200),
            ];
            let exec_time = time_estimates
                .iter()
                .find(|(name, _)| *name == tool)
                .map(|(_, seconds)| *seconds)
                .unwrap_or(180);

            let step = AttackStep {
                tool: tool.to_string(),
                parameters: optimized_params,
                expected_outcome: format!("Discover vulnerabilities using {tool}"),
                success_probability: success_prob,
                execution_time_estimate: exec_time,
                dependencies: Vec::new(),
            };

            chain.add_step(step);
        }

        // Calculate overall chain metrics
        chain.calculate_success_probability();
        chain.risk_level = profile.risk_level.clone();

        Ok(chain)
    }
}

/// `NameError` do ramo avançado de `optimize_parameters` (ver a nota no topo).
const PARAMETER_OPTIMIZER_UNDEFINED: &str = "name 'parameter_optimizer' is not defined";

/// `if x:` do Python — None/False/0/""/[]/{} são falsos.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `context.get(key, default)` seguido do `if x:` do Python.
fn get_truthy(context: &Map<String, Value>, key: &str, default: bool) -> bool {
    match context.get(key) {
        Some(value) => truthy(value),
        None => default,
    }
}

/// `urllib.parse.urlparse(url).path` (o que `_determine_target_type` usa).
fn urlparse_path(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    match rest.find('/') {
        Some(index) => &rest[index..],
        None => "",
    }
}

/// `urllib.parse.urlparse(url).hostname` (sem userinfo e sem porta).
fn urlparse_hostname(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);
    let host = match host.rsplit_once(':') {
        Some((host, _port)) if !host.contains(':') => host,
        _ => host,
    };
    if host.is_empty() { None } else { Some(host) }
}

/// `decision_engine = IntelligentDecisionEngine()` (o singleton consumido por
/// `routes.decision_engine`).
#[allow(non_upper_case_globals)]
pub static decision_engine: LazyLock<IntelligentDecisionEngine> =
    LazyLock::new(IntelligentDecisionEngine::new);
