//! Port 1:1 de `hexstrike_server/intelligence/ctf.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W6.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    18  class CTFChallenge:
//!    29  class CTFWorkflowManager:
//!   726  class CTFToolManager:
//! ```

use serde_json::{json, Value};

/// `@dataclass CTFChallenge` — campos na ordem do dataclass.
///
/// O dataclass do Python NÃO tem campo `target` nem método `to_dict()`: quem
/// toca `challenge.target` (ctf_automation) ou constrói
/// `CTFChallenge(..., target=...)` (routes/ctf_framework) levanta exceção, e
/// isso é reproduzido 1:1 — ver [`TARGET_ATTRIBUTE_ERROR`] e
/// [`TARGET_KWARG_TYPE_ERROR`].
pub struct CTFChallenge {
    pub name: String,
    pub category: String,
    pub description: String,
    pub points: i64,
    pub difficulty: String,
    pub files: Vec<String>,
    pub url: String,
    pub hints: Vec<String>,
}

/// `AttributeError: 'CTFChallenge' object has no attribute 'target'`
/// (o `except` do laço em `ctf_automation.py` engole e vira texto do passo).
pub const TARGET_ATTRIBUTE_ERROR: &str =
    "'CTFChallenge' object has no attribute 'target'";

/// `TypeError: CTFChallenge.__init__() got an unexpected keyword argument
/// 'target'` (o `except Exception` das rotas devolve 500 com esta string).
pub const TARGET_KWARG_TYPE_ERROR: &str =
    "CTFChallenge.__init__() got an unexpected keyword argument 'target'";

/// `list(dict.fromkeys(items))` — remove duplicatas preservando a ordem.
fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items.into_iter().filter(|item| seen.insert(item.clone())).collect()
}

/// `any(keyword in text for keyword in keywords)`
fn contains_any(text: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|keyword| text.contains(keyword))
}

/// `d[key][:n]` — as primeiras `n` strings da lista.
fn first_strings(value: Option<&Value>, n: usize) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(n)
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `table.get(key, default)` das tabelas por categoria (listas de dicts).
fn category_list(table: &Value, key: &str, default: Value) -> Vec<Value> {
    match table.get(key) {
        Some(found) => found.as_array().cloned().unwrap_or_default(),
        None => default.as_array().cloned().unwrap_or_default(),
    }
}

/// `base_times[difficulty]["avg"]` — dificuldade fora do mapa cai no valor de
/// `unknown` (o Python levantaria KeyError).
fn base_time_avg(difficulty: &str) -> f64 {
    match difficulty {
        "easy" => 30.0,
        "medium" => 60.0,
        "hard" => 120.0,
        "insane" => 240.0,
        _ => 90.0,
    }
}

/// `base_success[difficulty]`
fn base_success(difficulty: &str) -> f64 {
    match difficulty {
        "easy" => 0.85,
        "medium" => 0.65,
        "hard" => 0.45,
        "insane" => 0.25,
        _ => 0.55,
    }
}

/// `difficulty_multipliers[difficulty]`
fn difficulty_multiplier(difficulty: &str) -> f64 {
    match difficulty {
        "easy" => 1.0,
        "medium" => 1.2,
        "hard" => 1.5,
        "insane" => 2.0,
        _ => 1.3,
    }
}

/// `category_multipliers.get(category, 1.0)`
fn category_multiplier(category: &str) -> f64 {
    match category {
        "web" => 1.0,
        "crypto" => 1.3,
        "pwn" => 1.5,
        "forensics" => 1.2,
        "rev" => 1.4,
        "misc" => 0.8,
        "osint" => 0.9,
        _ => 1.0,
    }
}

/// Specialized workflow manager for CTF competitions
pub struct CTFWorkflowManager {
    pub category_tools: Value,
    pub solving_strategies: Value,
}

impl CTFWorkflowManager {
    pub fn new() -> Self {
        Self {
            category_tools: json!({
                "web": {
                    "reconnaissance": ["httpx", "katana", "gau", "waybackurls"],
                    "vulnerability_scanning": ["nuclei", "dalfox", "sqlmap", "nikto"],
                    "content_discovery": ["gobuster", "dirsearch", "feroxbuster"],
                    "parameter_testing": ["arjun", "paramspider", "x8"],
                    "specialized": ["wpscan", "joomscan", "droopescan"]
                },
                "crypto": {
                    "hash_analysis": ["hashcat", "john", "hash-identifier"],
                    "cipher_analysis": ["cipher-identifier", "cryptool", "cyberchef"],
                    "rsa_attacks": ["rsatool", "factordb", "yafu"],
                    "frequency_analysis": ["frequency-analysis", "substitution-solver"],
                    "modern_crypto": ["sage", "pycrypto", "cryptography"]
                },
                "pwn": {
                    "binary_analysis": ["checksec", "ghidra", "radare2", "gdb-peda"],
                    "exploit_development": ["pwntools", "ropper", "one-gadget"],
                    "heap_exploitation": ["glibc-heap-analysis", "heap-viewer"],
                    "format_string": ["format-string-exploiter"],
                    "rop_chains": ["ropgadget", "ropper", "angr"]
                },
                "forensics": {
                    "file_analysis": ["file", "binwalk", "foremost", "photorec"],
                    "image_forensics": ["exiftool", "steghide", "stegsolve", "zsteg"],
                    "memory_forensics": ["volatility", "rekall"],
                    "network_forensics": ["wireshark", "tcpdump", "networkminer"],
                    "disk_forensics": ["autopsy", "sleuthkit", "testdisk"]
                },
                "rev": {
                    "disassemblers": ["ghidra", "ida", "radare2", "binary-ninja"],
                    "debuggers": ["gdb", "x64dbg", "ollydbg"],
                    "decompilers": ["ghidra", "hex-rays", "retdec"],
                    "packers": ["upx", "peid", "detect-it-easy"],
                    "analysis": ["strings", "ltrace", "strace", "objdump"]
                },
                "misc": {
                    "encoding": ["base64", "hex", "url-decode", "rot13"],
                    "compression": ["zip", "tar", "gzip", "7zip"],
                    "qr_codes": ["qr-decoder", "zbar"],
                    "audio_analysis": ["audacity", "sonic-visualizer"],
                    "esoteric": ["brainfuck", "whitespace", "piet"]
                },
                "osint": {
                    "search_engines": ["google-dorking", "shodan", "censys"],
                    "social_media": ["sherlock", "social-analyzer"],
                    "image_analysis": ["reverse-image-search", "exif-analysis"],
                    "domain_analysis": ["whois", "dns-analysis", "certificate-transparency"],
                    "geolocation": ["geoint", "osm-analysis", "satellite-imagery"]
                }
            }),
            solving_strategies: json!({
                "web": [
                    {"strategy": "source_code_analysis", "description": "Analyze HTML/JS source for hidden information"},
                    {"strategy": "directory_traversal", "description": "Test for path traversal vulnerabilities"},
                    {"strategy": "sql_injection", "description": "Test for SQL injection in all parameters"},
                    {"strategy": "xss_exploitation", "description": "Test for XSS and exploit for admin access"},
                    {"strategy": "authentication_bypass", "description": "Test for auth bypass techniques"},
                    {"strategy": "session_manipulation", "description": "Analyze and manipulate session tokens"},
                    {"strategy": "file_upload_bypass", "description": "Test file upload restrictions and bypasses"}
                ],
                "crypto": [
                    {"strategy": "frequency_analysis", "description": "Perform frequency analysis for substitution ciphers"},
                    {"strategy": "known_plaintext", "description": "Use known plaintext attacks"},
                    {"strategy": "weak_keys", "description": "Test for weak cryptographic keys"},
                    {"strategy": "implementation_flaws", "description": "Look for implementation vulnerabilities"},
                    {"strategy": "side_channel", "description": "Exploit timing or other side channels"},
                    {"strategy": "mathematical_attacks", "description": "Use mathematical properties to break crypto"}
                ],
                "pwn": [
                    {"strategy": "buffer_overflow", "description": "Exploit buffer overflow vulnerabilities"},
                    {"strategy": "format_string", "description": "Exploit format string vulnerabilities"},
                    {"strategy": "rop_chains", "description": "Build ROP chains for exploitation"},
                    {"strategy": "heap_exploitation", "description": "Exploit heap-based vulnerabilities"},
                    {"strategy": "race_conditions", "description": "Exploit race condition vulnerabilities"},
                    {"strategy": "integer_overflow", "description": "Exploit integer overflow conditions"}
                ],
                "forensics": [
                    {"strategy": "file_carving", "description": "Recover deleted or hidden files"},
                    {"strategy": "metadata_analysis", "description": "Analyze file metadata for hidden information"},
                    {"strategy": "steganography", "description": "Extract hidden data from images/audio"},
                    {"strategy": "memory_analysis", "description": "Analyze memory dumps for artifacts"},
                    {"strategy": "network_analysis", "description": "Analyze network traffic for suspicious activity"},
                    {"strategy": "timeline_analysis", "description": "Reconstruct timeline of events"}
                ],
                "rev": [
                    {"strategy": "static_analysis", "description": "Analyze binary without execution"},
                    {"strategy": "dynamic_analysis", "description": "Analyze binary during execution"},
                    {"strategy": "anti_debugging", "description": "Bypass anti-debugging techniques"},
                    {"strategy": "unpacking", "description": "Unpack packed/obfuscated binaries"},
                    {"strategy": "algorithm_recovery", "description": "Reverse engineer algorithms"},
                    {"strategy": "key_recovery", "description": "Extract encryption keys from binaries"}
                ]
            }),
        }
    }

    /// Create advanced specialized workflow for CTF challenge with AI-powered
    /// optimization
    pub fn create_ctf_challenge_workflow(&self, challenge: &CTFChallenge) -> Value {
        let mut workflow = json!({
            "challenge": &challenge.name,
            "category": &challenge.category,
            "difficulty": &challenge.difficulty,
            "points": challenge.points,
            "tools": [],
            "strategies": [],
            "estimated_time": 0,
            "success_probability": 0.0,
            "automation_level": "high",
            "parallel_tasks": [],
            "dependencies": [],
            "fallback_strategies": [],
            "resource_requirements": {},
            "expected_artifacts": [],
            "validation_steps": []
        });

        // Enhanced tool selection using CTFToolManager
        let ctf_tool_manager = CTFToolManager::new();
        workflow["tools"] =
            json!(ctf_tool_manager.suggest_tools_for_challenge(&challenge.description, &challenge.category));

        // Get category-specific strategies with enhanced intelligence
        if let Some(strategies) = self.solving_strategies.get(challenge.category.as_str()) {
            workflow["strategies"] = strategies.clone();
            // Add fallback strategies for robustness
            workflow["fallback_strategies"] = json!(self._generate_fallback_strategies(&challenge.category));
        }

        // Advanced time estimation with machine learning-like scoring
        let base_time = base_time_avg(&challenge.difficulty);
        let category_mult = category_multiplier(&challenge.category);

        // Adjust based on description complexity
        let description_complexity = self._analyze_description_complexity(&challenge.description);
        let complexity_mult = 1.0 + (description_complexity * 0.3);

        // Convert to seconds
        workflow["estimated_time"] = json!((base_time * category_mult * complexity_mult * 60.0) as i64);

        // Enhanced success probability calculation
        let base_success = base_success(&challenge.difficulty);

        // Adjust based on tool availability and category expertise
        let tool_count = workflow["tools"].as_array().map_or(0, Vec::len) as f64;
        let tool_availability_bonus = 0.15_f64.min(tool_count * 0.02);
        workflow["success_probability"] = json!(0.95_f64.min(base_success + tool_availability_bonus));

        // Add advanced workflow components
        workflow["workflow_steps"] = Value::Array(self._create_advanced_category_workflow(challenge));
        workflow["parallel_tasks"] = Value::Array(self._identify_parallel_tasks(&challenge.category));
        workflow["resource_requirements"] = self._calculate_resource_requirements(challenge);
        workflow["expected_artifacts"] = Value::Array(self._predict_expected_artifacts(challenge));
        workflow["validation_steps"] = Value::Array(self._create_validation_steps(&challenge.category));

        workflow
    }

    /// Select appropriate tools based on challenge details
    pub fn _select_tools_for_challenge(&self, challenge: &CTFChallenge, category_tools: &Value) -> Vec<String> {
        let mut selected_tools: Vec<String> = Vec::new();

        // Always include reconnaissance tools for the category
        selected_tools.extend(first_strings(category_tools.get("reconnaissance"), 2)); // Top 2 recon tools

        // Add specialized tools based on challenge description
        let description_lower = challenge.description.to_lowercase();

        match challenge.category.as_str() {
            "web" => {
                if contains_any(&description_lower, &["sql", "injection", "database"]) {
                    selected_tools.push("sqlmap".to_string());
                }
                if contains_any(&description_lower, &["xss", "script", "javascript"]) {
                    selected_tools.push("dalfox".to_string());
                }
                if contains_any(&description_lower, &["wordpress", "wp"]) {
                    selected_tools.push("wpscan".to_string());
                }
                if contains_any(&description_lower, &["upload", "file"]) {
                    selected_tools.extend(["gobuster".to_string(), "feroxbuster".to_string()]);
                }
            }
            "crypto" => {
                if contains_any(&description_lower, &["hash", "md5", "sha"]) {
                    selected_tools.extend(["hashcat".to_string(), "john".to_string()]);
                }
                if contains_any(&description_lower, &["rsa", "public key"]) {
                    selected_tools.extend(["rsatool".to_string(), "factordb".to_string()]);
                }
                if contains_any(&description_lower, &["cipher", "encrypt"]) {
                    selected_tools.extend(["cipher-identifier".to_string(), "cyberchef".to_string()]);
                }
            }
            "pwn" => {
                selected_tools.extend([
                    "checksec".to_string(),
                    "ghidra".to_string(),
                    "pwntools".to_string(),
                ]);
                if contains_any(&description_lower, &["heap", "malloc"]) {
                    selected_tools.push("glibc-heap-analysis".to_string());
                }
                if contains_any(&description_lower, &["format", "printf"]) {
                    selected_tools.push("format-string-exploiter".to_string());
                }
            }
            "forensics" => {
                if contains_any(&description_lower, &["image", "jpg", "png"]) {
                    selected_tools.extend([
                        "exiftool".to_string(),
                        "steghide".to_string(),
                        "stegsolve".to_string(),
                    ]);
                }
                if contains_any(&description_lower, &["memory", "dump"]) {
                    selected_tools.push("volatility".to_string());
                }
                if contains_any(&description_lower, &["network", "pcap"]) {
                    selected_tools.extend(["wireshark".to_string(), "tcpdump".to_string()]);
                }
            }
            "rev" => {
                selected_tools.extend([
                    "ghidra".to_string(),
                    "radare2".to_string(),
                    "strings".to_string(),
                ]);
                if contains_any(&description_lower, &["packed", "upx"]) {
                    selected_tools.extend(["upx".to_string(), "peid".to_string()]);
                }
            }
            _ => {}
        }

        // Remove duplicates while preserving order
        dedup(selected_tools)
    }

    /// Create category-specific workflow steps
    pub fn _create_category_workflow(&self, challenge: &CTFChallenge) -> Vec<Value> {
        let workflows = json!({
            "web": [
                {"step": 1, "action": "reconnaissance", "description": "Analyze target URL and gather information"},
                {"step": 2, "action": "source_analysis", "description": "Examine HTML/JS source code for clues"},
                {"step": 3, "action": "directory_discovery", "description": "Discover hidden directories and files"},
                {"step": 4, "action": "vulnerability_testing", "description": "Test for common web vulnerabilities"},
                {"step": 5, "action": "exploitation", "description": "Exploit discovered vulnerabilities"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from compromised system"}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify the type of cipher or encoding"},
                {"step": 2, "action": "key_analysis", "description": "Analyze key properties and weaknesses"},
                {"step": 3, "action": "attack_selection", "description": "Select appropriate cryptographic attack"},
                {"step": 4, "action": "implementation", "description": "Implement and execute the attack"},
                {"step": 5, "action": "verification", "description": "Verify the decrypted result"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from decrypted data"}
            ],
            "pwn": [
                {"step": 1, "action": "binary_analysis", "description": "Analyze binary protections and architecture"},
                {"step": 2, "action": "vulnerability_discovery", "description": "Find exploitable vulnerabilities"},
                {"step": 3, "action": "exploit_development", "description": "Develop exploit payload"},
                {"step": 4, "action": "local_testing", "description": "Test exploit locally"},
                {"step": 5, "action": "remote_exploitation", "description": "Execute exploit against remote target"},
                {"step": 6, "action": "shell_interaction", "description": "Interact with gained shell to find flag"}
            ],
            "forensics": [
                {"step": 1, "action": "file_analysis", "description": "Analyze provided files and their properties"},
                {"step": 2, "action": "data_recovery", "description": "Recover deleted or hidden data"},
                {"step": 3, "action": "artifact_extraction", "description": "Extract relevant artifacts and evidence"},
                {"step": 4, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events"},
                {"step": 5, "action": "correlation_analysis", "description": "Correlate findings across different sources"},
                {"step": 6, "action": "flag_discovery", "description": "Locate flag in recovered data"}
            ],
            "rev": [
                {"step": 1, "action": "static_analysis", "description": "Perform static analysis of the binary"},
                {"step": 2, "action": "dynamic_analysis", "description": "Run binary and observe behavior"},
                {"step": 3, "action": "algorithm_identification", "description": "Identify key algorithms and logic"},
                {"step": 4, "action": "key_extraction", "description": "Extract keys or important values"},
                {"step": 5, "action": "solution_implementation", "description": "Implement solution based on analysis"},
                {"step": 6, "action": "flag_generation", "description": "Generate or extract the flag"}
            ]
        });

        category_list(&workflows, &challenge.category, json!([
            {"step": 1, "action": "analysis", "description": "Analyze the challenge"},
            {"step": 2, "action": "research", "description": "Research relevant techniques"},
            {"step": 3, "action": "implementation", "description": "Implement solution"},
            {"step": 4, "action": "testing", "description": "Test the solution"},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed"},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag"}
        ]))
    }

    /// Create team strategy for CTF competition
    pub fn create_ctf_team_strategy(&self, challenges: &[CTFChallenge], team_size: usize) -> Value {
        let mut strategy = json!({
            "team_size": team_size,
            "challenge_allocation": {},
            "priority_order": [],
            "estimated_total_time": 0,
            "expected_score": 0
        });

        // Sort challenges by points/time ratio for optimal strategy
        let mut challenge_efficiency: Vec<(usize, f64, Value)> = Vec::new();
        for (index, challenge) in challenges.iter().enumerate() {
            let workflow = self.create_ctf_challenge_workflow(challenge);
            let success_probability = workflow["success_probability"].as_f64().unwrap_or(0.0);
            let estimated_time = workflow["estimated_time"].as_f64().unwrap_or(0.0);
            let efficiency = (challenge.points as f64 * success_probability) / (estimated_time / 3600.0); // points per hour
            challenge_efficiency.push((index, efficiency, workflow));
        }

        // Sort by efficiency (highest first)
        challenge_efficiency.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Allocate challenges to team members
        let mut team_workload = vec![0_i64; team_size];
        let mut challenge_allocation = serde_json::Map::new();
        let mut expected_score = 0.0_f64;
        for (index, _, workflow) in &challenge_efficiency {
            // Assign to team member with least workload — `team_workload.index(
            // min(team_workload))` do Python; com `team_size` 0 o Python
            // levanta ValueError em `min([])` e aqui não há membro para alocar.
            let Some(team_member) = team_workload
                .iter()
                .copied()
                .min()
                .and_then(|least_workload| team_workload.iter().position(|load| *load == least_workload))
            else {
                continue;
            };
            let challenge = &challenges[*index];
            let estimated_time = workflow["estimated_time"].as_i64().unwrap_or(0);
            let success_probability = workflow["success_probability"].as_f64().unwrap_or(0.0);

            challenge_allocation
                .entry(team_member.to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("alocação por membro é uma lista")
                .push(json!({
                    "challenge": &challenge.name,
                    "category": &challenge.category,
                    "points": challenge.points,
                    "estimated_time": estimated_time,
                    "success_probability": success_probability
                }));

            team_workload[team_member] += estimated_time;
            expected_score += challenge.points as f64 * success_probability;
        }

        strategy["challenge_allocation"] = Value::Object(challenge_allocation);
        strategy["estimated_total_time"] = json!(team_workload.iter().copied().max().unwrap_or(0));
        strategy["priority_order"] = json!(challenge_efficiency
            .iter()
            .map(|(index, _, _)| challenges[*index].name.clone())
            .collect::<Vec<String>>());
        strategy["expected_score"] = json!(expected_score);

        strategy
    }

    /// Generate fallback strategies for when primary approaches fail
    pub fn _generate_fallback_strategies(&self, category: &str) -> Vec<Value> {
        let fallback_strategies = json!({
            "web": [
                {"strategy": "manual_source_review", "description": "Manually review all source code and comments"},
                {"strategy": "alternative_wordlists", "description": "Try alternative wordlists and fuzzing techniques"},
                {"strategy": "parameter_pollution", "description": "Test for HTTP parameter pollution vulnerabilities"},
                {"strategy": "race_conditions", "description": "Test for race condition vulnerabilities"},
                {"strategy": "business_logic", "description": "Focus on business logic flaws and edge cases"}
            ],
            "crypto": [
                {"strategy": "known_plaintext_attack", "description": "Use any known plaintext for cryptanalysis"},
                {"strategy": "frequency_analysis_variants", "description": "Try different frequency analysis approaches"},
                {"strategy": "mathematical_properties", "description": "Exploit mathematical properties of the cipher"},
                {"strategy": "implementation_weaknesses", "description": "Look for implementation-specific weaknesses"},
                {"strategy": "side_channel_analysis", "description": "Analyze timing or other side channels"}
            ],
            "pwn": [
                {"strategy": "alternative_exploitation", "description": "Try alternative exploitation techniques"},
                {"strategy": "information_leaks", "description": "Exploit information disclosure vulnerabilities"},
                {"strategy": "heap_feng_shui", "description": "Use heap manipulation techniques"},
                {"strategy": "ret2libc_variants", "description": "Try different ret2libc approaches"},
                {"strategy": "sigreturn_oriented", "description": "Use SIGROP (Signal Return Oriented Programming)"}
            ],
            "forensics": [
                {"strategy": "alternative_tools", "description": "Try different forensics tools and approaches"},
                {"strategy": "manual_hex_analysis", "description": "Manually analyze hex dumps and file structures"},
                {"strategy": "correlation_analysis", "description": "Correlate findings across multiple evidence sources"},
                {"strategy": "timeline_reconstruction", "description": "Reconstruct detailed timeline of events"},
                {"strategy": "deleted_data_recovery", "description": "Focus on recovering deleted or hidden data"}
            ],
            "rev": [
                {"strategy": "dynamic_analysis_focus", "description": "Shift focus to dynamic analysis techniques"},
                {"strategy": "anti_analysis_bypass", "description": "Bypass anti-analysis and obfuscation"},
                {"strategy": "library_analysis", "description": "Analyze linked libraries and dependencies"},
                {"strategy": "algorithm_identification", "description": "Focus on identifying key algorithms"},
                {"strategy": "patch_analysis", "description": "Analyze patches or modifications to standard code"}
            ],
            "misc": [
                {"strategy": "alternative_interpretations", "description": "Try alternative interpretations of the challenge"},
                {"strategy": "encoding_combinations", "description": "Try combinations of different encodings"},
                {"strategy": "esoteric_approaches", "description": "Consider esoteric or unusual solution approaches"},
                {"strategy": "metadata_focus", "description": "Focus heavily on metadata and hidden information"},
                {"strategy": "collaborative_solving", "description": "Use collaborative problem-solving techniques"}
            ],
            "osint": [
                {"strategy": "alternative_sources", "description": "Try alternative information sources"},
                {"strategy": "historical_data", "description": "Look for historical or archived information"},
                {"strategy": "social_engineering", "description": "Use social engineering techniques (ethically)"},
                {"strategy": "cross_reference", "description": "Cross-reference information across multiple platforms"},
                {"strategy": "deep_web_search", "description": "Search in deep web and specialized databases"}
            ]
        });
        category_list(&fallback_strategies, category, json!([]))
    }

    /// Analyze challenge description complexity to adjust time estimates
    pub fn _analyze_description_complexity(&self, description: &str) -> f64 {
        let mut complexity_score = 0.0;
        let description_lower = description.to_lowercase();

        // Length-based complexity
        let length = description.chars().count();
        if length > 500 {
            complexity_score += 0.3;
        } else if length > 200 {
            complexity_score += 0.1;
        }

        // Technical term density
        let technical_terms = [
            "algorithm", "encryption", "decryption", "vulnerability", "exploit",
            "buffer overflow", "sql injection", "xss", "csrf", "authentication",
            "authorization", "cryptography", "steganography", "forensics",
            "reverse engineering", "binary analysis", "memory corruption",
            "heap", "stack", "rop", "shellcode", "payload",
        ];

        let term_count = technical_terms.iter().filter(|term| description_lower.contains(**term)).count();
        complexity_score += 0.4_f64.min(term_count as f64 * 0.05);

        // Multi-step indicators
        let multi_step_indicators = ["first", "then", "next", "after", "finally", "step"];
        let step_count = multi_step_indicators.iter().filter(|indicator| description_lower.contains(**indicator)).count();
        complexity_score += 0.3_f64.min(step_count as f64 * 0.1);

        1.0_f64.min(complexity_score)
    }

    /// Create advanced category-specific workflow with parallel execution support
    pub fn _create_advanced_category_workflow(&self, challenge: &CTFChallenge) -> Vec<Value> {
        let advanced_workflows = json!({
            "web": [
                {"step": 1, "action": "automated_reconnaissance", "description": "Automated web reconnaissance and technology detection", "parallel": true, "tools": ["httpx", "whatweb", "katana"], "estimated_time": 300},
                {"step": 2, "action": "source_code_analysis", "description": "Comprehensive source code and comment analysis", "parallel": false, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "directory_enumeration", "description": "Multi-tool directory and file enumeration", "parallel": true, "tools": ["gobuster", "dirsearch", "feroxbuster"], "estimated_time": 900},
                {"step": 4, "action": "parameter_discovery", "description": "Parameter discovery and testing", "parallel": true, "tools": ["arjun", "paramspider"], "estimated_time": 600},
                {"step": 5, "action": "vulnerability_scanning", "description": "Automated vulnerability scanning", "parallel": true, "tools": ["sqlmap", "dalfox", "nikto"], "estimated_time": 1200},
                {"step": 6, "action": "manual_testing", "description": "Manual testing of discovered attack vectors", "parallel": false, "tools": ["manual"], "estimated_time": 1800},
                {"step": 7, "action": "exploitation", "description": "Exploit discovered vulnerabilities", "parallel": false, "tools": ["custom"], "estimated_time": 900},
                {"step": 8, "action": "flag_extraction", "description": "Extract and validate flag", "parallel": false, "tools": ["manual"], "estimated_time": 300}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify cipher type and properties", "parallel": false, "tools": ["cipher-identifier", "hash-identifier"], "estimated_time": 300},
                {"step": 2, "action": "key_space_analysis", "description": "Analyze key space and potential weaknesses", "parallel": false, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "automated_attacks", "description": "Launch automated cryptographic attacks", "parallel": true, "tools": ["hashcat", "john", "factordb"], "estimated_time": 1800},
                {"step": 4, "action": "mathematical_analysis", "description": "Mathematical analysis of cipher properties", "parallel": false, "tools": ["sage", "python"], "estimated_time": 1200},
                {"step": 5, "action": "frequency_analysis", "description": "Statistical and frequency analysis", "parallel": true, "tools": ["frequency-analysis", "substitution-solver"], "estimated_time": 900},
                {"step": 6, "action": "known_plaintext", "description": "Known plaintext and chosen plaintext attacks", "parallel": false, "tools": ["custom"], "estimated_time": 1200},
                {"step": 7, "action": "implementation_analysis", "description": "Analyze implementation for weaknesses", "parallel": false, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "solution_verification", "description": "Verify and extract flag", "parallel": false, "tools": ["manual"], "estimated_time": 300}
            ],
            "pwn": [
                {"step": 1, "action": "binary_reconnaissance", "description": "Comprehensive binary analysis and protection identification", "parallel": true, "tools": ["checksec", "file", "strings", "objdump"], "estimated_time": 600},
                {"step": 2, "action": "static_analysis", "description": "Static analysis with multiple tools", "parallel": true, "tools": ["ghidra", "radare2", "ida"], "estimated_time": 1800},
                {"step": 3, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": false, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1200},
                {"step": 4, "action": "vulnerability_identification", "description": "Identify exploitable vulnerabilities", "parallel": false, "tools": ["manual"], "estimated_time": 900},
                {"step": 5, "action": "exploit_development", "description": "Develop exploit payload", "parallel": false, "tools": ["pwntools", "ropper", "one-gadget"], "estimated_time": 2400},
                {"step": 6, "action": "local_testing", "description": "Test exploit locally", "parallel": false, "tools": ["gdb-peda"], "estimated_time": 600},
                {"step": 7, "action": "remote_exploitation", "description": "Execute exploit against remote target", "parallel": false, "tools": ["pwntools"], "estimated_time": 600},
                {"step": 8, "action": "post_exploitation", "description": "Post-exploitation and flag extraction", "parallel": false, "tools": ["manual"], "estimated_time": 300}
            ],
            "forensics": [
                {"step": 1, "action": "evidence_acquisition", "description": "Acquire and validate digital evidence", "parallel": false, "tools": ["file", "exiftool"], "estimated_time": 300},
                {"step": 2, "action": "file_analysis", "description": "Comprehensive file structure analysis", "parallel": true, "tools": ["binwalk", "foremost", "strings"], "estimated_time": 900},
                {"step": 3, "action": "metadata_extraction", "description": "Extract and analyze metadata", "parallel": true, "tools": ["exiftool", "steghide"], "estimated_time": 600},
                {"step": 4, "action": "steganography_detection", "description": "Detect and extract hidden data", "parallel": true, "tools": ["stegsolve", "zsteg", "outguess"], "estimated_time": 1200},
                {"step": 5, "action": "memory_analysis", "description": "Memory dump analysis if applicable", "parallel": false, "tools": ["volatility", "volatility3"], "estimated_time": 1800},
                {"step": 6, "action": "network_analysis", "description": "Network traffic analysis if applicable", "parallel": false, "tools": ["wireshark", "tcpdump"], "estimated_time": 1200},
                {"step": 7, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events", "parallel": false, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "evidence_correlation", "description": "Correlate findings and extract flag", "parallel": false, "tools": ["manual"], "estimated_time": 600}
            ],
            "rev": [
                {"step": 1, "action": "binary_triage", "description": "Initial binary triage and classification", "parallel": true, "tools": ["file", "strings", "checksec"], "estimated_time": 300},
                {"step": 2, "action": "packer_detection", "description": "Detect and unpack if necessary", "parallel": false, "tools": ["upx", "peid", "detect-it-easy"], "estimated_time": 600},
                {"step": 3, "action": "static_disassembly", "description": "Static disassembly and analysis", "parallel": true, "tools": ["ghidra", "ida", "radare2"], "estimated_time": 2400},
                {"step": 4, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": false, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1800},
                {"step": 5, "action": "algorithm_identification", "description": "Identify key algorithms and logic", "parallel": false, "tools": ["manual"], "estimated_time": 1200},
                {"step": 6, "action": "key_extraction", "description": "Extract keys, passwords, or critical values", "parallel": false, "tools": ["manual"], "estimated_time": 900},
                {"step": 7, "action": "solution_implementation", "description": "Implement solution based on analysis", "parallel": false, "tools": ["python", "custom"], "estimated_time": 1200},
                {"step": 8, "action": "flag_generation", "description": "Generate or extract the flag", "parallel": false, "tools": ["manual"], "estimated_time": 300}
            ],
            "misc": [
                {"step": 1, "action": "challenge_analysis", "description": "Analyze challenge type and requirements", "parallel": false, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "encoding_detection", "description": "Detect encoding or obfuscation methods", "parallel": true, "tools": ["base64", "hex", "rot13"], "estimated_time": 600},
                {"step": 3, "action": "format_identification", "description": "Identify file formats or data structures", "parallel": false, "tools": ["file", "binwalk"], "estimated_time": 300},
                {"step": 4, "action": "specialized_analysis", "description": "Apply specialized analysis techniques", "parallel": true, "tools": ["qr-decoder", "audio-analysis"], "estimated_time": 900},
                {"step": 5, "action": "pattern_recognition", "description": "Identify patterns and relationships", "parallel": false, "tools": ["manual"], "estimated_time": 600},
                {"step": 6, "action": "solution_implementation", "description": "Implement solution approach", "parallel": false, "tools": ["python", "custom"], "estimated_time": 900},
                {"step": 7, "action": "validation", "description": "Validate solution and extract flag", "parallel": false, "tools": ["manual"], "estimated_time": 300}
            ],
            "osint": [
                {"step": 1, "action": "target_identification", "description": "Identify and validate targets", "parallel": false, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "automated_reconnaissance", "description": "Automated OSINT gathering", "parallel": true, "tools": ["sherlock", "theHarvester", "sublist3r"], "estimated_time": 1200},
                {"step": 3, "action": "social_media_analysis", "description": "Social media intelligence gathering", "parallel": true, "tools": ["sherlock", "social-analyzer"], "estimated_time": 900},
                {"step": 4, "action": "domain_analysis", "description": "Domain and DNS intelligence", "parallel": true, "tools": ["whois", "dig", "amass"], "estimated_time": 600},
                {"step": 5, "action": "search_engine_intelligence", "description": "Search engine and database queries", "parallel": true, "tools": ["shodan", "censys"], "estimated_time": 900},
                {"step": 6, "action": "correlation_analysis", "description": "Correlate information across sources", "parallel": false, "tools": ["manual"], "estimated_time": 1200},
                {"step": 7, "action": "verification", "description": "Verify findings and extract flag", "parallel": false, "tools": ["manual"], "estimated_time": 600}
            ]
        });

        category_list(&advanced_workflows, &challenge.category, json!([
            {"step": 1, "action": "analysis", "description": "Analyze the challenge", "parallel": false, "tools": ["manual"], "estimated_time": 600},
            {"step": 2, "action": "research", "description": "Research relevant techniques", "parallel": false, "tools": ["manual"], "estimated_time": 900},
            {"step": 3, "action": "implementation", "description": "Implement solution", "parallel": false, "tools": ["custom"], "estimated_time": 1800},
            {"step": 4, "action": "testing", "description": "Test the solution", "parallel": false, "tools": ["manual"], "estimated_time": 600},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed", "parallel": false, "tools": ["manual"], "estimated_time": 900},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag", "parallel": false, "tools": ["manual"], "estimated_time": 300}
        ]))
    }

    /// Identify tasks that can be executed in parallel for efficiency
    pub fn _identify_parallel_tasks(&self, category: &str) -> Vec<Value> {
        let parallel_tasks = json!({
            "web": [
                {"task_group": "reconnaissance", "tasks": ["httpx", "whatweb", "katana"], "max_concurrent": 3},
                {"task_group": "directory_enumeration", "tasks": ["gobuster", "dirsearch", "feroxbuster"], "max_concurrent": 2},
                {"task_group": "parameter_discovery", "tasks": ["arjun", "paramspider"], "max_concurrent": 2},
                {"task_group": "vulnerability_scanning", "tasks": ["sqlmap", "dalfox", "nikto"], "max_concurrent": 2}
            ],
            "crypto": [
                {"task_group": "hash_cracking", "tasks": ["hashcat", "john"], "max_concurrent": 2},
                {"task_group": "cipher_analysis", "tasks": ["frequency-analysis", "substitution-solver"], "max_concurrent": 2},
                {"task_group": "factorization", "tasks": ["factordb", "yafu"], "max_concurrent": 2}
            ],
            "pwn": [
                {"task_group": "binary_analysis", "tasks": ["checksec", "file", "strings", "objdump"], "max_concurrent": 4},
                {"task_group": "static_analysis", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "gadget_finding", "tasks": ["ropper", "ropgadget"], "max_concurrent": 2}
            ],
            "forensics": [
                {"task_group": "file_analysis", "tasks": ["binwalk", "foremost", "strings"], "max_concurrent": 3},
                {"task_group": "steganography", "tasks": ["stegsolve", "zsteg", "outguess"], "max_concurrent": 3},
                {"task_group": "metadata_extraction", "tasks": ["exiftool", "steghide"], "max_concurrent": 2}
            ],
            "rev": [
                {"task_group": "initial_analysis", "tasks": ["file", "strings", "checksec"], "max_concurrent": 3},
                {"task_group": "disassembly", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "packer_detection", "tasks": ["upx", "peid", "detect-it-easy"], "max_concurrent": 3}
            ],
            "osint": [
                {"task_group": "username_search", "tasks": ["sherlock", "social-analyzer"], "max_concurrent": 2},
                {"task_group": "domain_recon", "tasks": ["sublist3r", "amass", "dig"], "max_concurrent": 3},
                {"task_group": "search_engines", "tasks": ["shodan", "censys"], "max_concurrent": 2}
            ],
            "misc": [
                {"task_group": "encoding_detection", "tasks": ["base64", "hex", "rot13"], "max_concurrent": 3},
                {"task_group": "format_analysis", "tasks": ["file", "binwalk"], "max_concurrent": 2}
            ]
        });

        category_list(&parallel_tasks, category, json!([]))
    }

    /// Calculate estimated resource requirements for challenge
    pub fn _calculate_resource_requirements(&self, challenge: &CTFChallenge) -> Value {
        let mut base_requirements = json!({
            "cpu_cores": 2,
            "memory_mb": 2048,
            "disk_space_mb": 1024,
            "network_bandwidth": "medium",
            "gpu_required": false,
            "special_tools": []
        });

        // Adjust based on category
        let category_adjustments = json!({
            "web": {"cpu_cores": 4, "memory_mb": 4096, "network_bandwidth": "high"},
            "crypto": {"cpu_cores": 8, "memory_mb": 8192, "gpu_required": true},
            "pwn": {"cpu_cores": 4, "memory_mb": 4096, "special_tools": ["gdb", "pwntools"]},
            "forensics": {"cpu_cores": 2, "memory_mb": 8192, "disk_space_mb": 4096},
            "rev": {"cpu_cores": 4, "memory_mb": 8192, "special_tools": ["ghidra", "ida"]},
            "osint": {"cpu_cores": 2, "memory_mb": 2048, "network_bandwidth": "high"},
            "misc": {"cpu_cores": 2, "memory_mb": 2048}
        });

        if let (Some(base), Some(adjustments)) =
            (base_requirements.as_object_mut(), category_adjustments.get(challenge.category.as_str()).and_then(Value::as_object))
        {
            for (key, value) in adjustments {
                base.insert(key.clone(), value.clone());
            }
        }

        // Adjust based on difficulty
        let multiplier = difficulty_multiplier(&challenge.difficulty);
        let scale = |value: &Value| (value.as_f64().unwrap_or(0.0) * multiplier) as i64;
        base_requirements["cpu_cores"] = json!(scale(&base_requirements["cpu_cores"]));
        base_requirements["memory_mb"] = json!(scale(&base_requirements["memory_mb"]));
        base_requirements["disk_space_mb"] = json!(scale(&base_requirements["disk_space_mb"]));

        base_requirements
    }

    /// Predict expected artifacts and outputs from challenge solving
    pub fn _predict_expected_artifacts(&self, challenge: &CTFChallenge) -> Vec<Value> {
        let artifacts = json!({
            "web": [
                {"type": "http_responses", "description": "HTTP response data and headers"},
                {"type": "source_code", "description": "Downloaded source code and scripts"},
                {"type": "directory_lists", "description": "Discovered directories and files"},
                {"type": "vulnerability_reports", "description": "Vulnerability scan results"},
                {"type": "exploit_payloads", "description": "Working exploit payloads"},
                {"type": "session_data", "description": "Session tokens and cookies"}
            ],
            "crypto": [
                {"type": "plaintext", "description": "Decrypted plaintext data"},
                {"type": "keys", "description": "Recovered encryption keys"},
                {"type": "cipher_analysis", "description": "Cipher analysis results"},
                {"type": "frequency_data", "description": "Frequency analysis data"},
                {"type": "mathematical_proof", "description": "Mathematical proof of solution"}
            ],
            "pwn": [
                {"type": "exploit_code", "description": "Working exploit code"},
                {"type": "shellcode", "description": "Custom shellcode payloads"},
                {"type": "memory_dumps", "description": "Memory dumps and analysis"},
                {"type": "rop_chains", "description": "ROP chain constructions"},
                {"type": "debug_output", "description": "Debugging session outputs"}
            ],
            "forensics": [
                {"type": "recovered_files", "description": "Recovered deleted files"},
                {"type": "extracted_data", "description": "Extracted hidden data"},
                {"type": "timeline", "description": "Timeline of events"},
                {"type": "metadata", "description": "File metadata and properties"},
                {"type": "network_flows", "description": "Network traffic analysis"}
            ],
            "rev": [
                {"type": "decompiled_code", "description": "Decompiled source code"},
                {"type": "algorithm_analysis", "description": "Identified algorithms"},
                {"type": "key_values", "description": "Extracted keys and constants"},
                {"type": "control_flow", "description": "Control flow analysis"},
                {"type": "solution_script", "description": "Solution implementation script"}
            ],
            "osint": [
                {"type": "intelligence_report", "description": "Compiled intelligence report"},
                {"type": "social_profiles", "description": "Discovered social media profiles"},
                {"type": "domain_data", "description": "Domain registration and DNS data"},
                {"type": "correlation_matrix", "description": "Information correlation analysis"},
                {"type": "verification_data", "description": "Verification of findings"}
            ],
            "misc": [
                {"type": "decoded_data", "description": "Decoded or decrypted data"},
                {"type": "pattern_analysis", "description": "Pattern recognition results"},
                {"type": "solution_explanation", "description": "Explanation of solution approach"},
                {"type": "intermediate_results", "description": "Intermediate calculation results"}
            ]
        });

        category_list(&artifacts, &challenge.category, json!([
            {"type": "solution_data", "description": "Solution-related data"},
            {"type": "analysis_results", "description": "Analysis results and findings"}
        ]))
    }

    /// Create validation steps to verify solution correctness
    pub fn _create_validation_steps(&self, category: &str) -> Vec<Value> {
        let validation_steps = json!({
            "web": [
                {"step": "response_validation", "description": "Validate HTTP responses and status codes"},
                {"step": "payload_verification", "description": "Verify exploit payloads work correctly"},
                {"step": "flag_format_check", "description": "Check flag format matches expected pattern"},
                {"step": "reproducibility_test", "description": "Test solution reproducibility"}
            ],
            "crypto": [
                {"step": "decryption_verification", "description": "Verify decryption produces readable text"},
                {"step": "key_validation", "description": "Validate recovered keys are correct"},
                {"step": "mathematical_check", "description": "Verify mathematical correctness"},
                {"step": "flag_extraction", "description": "Extract and validate flag from plaintext"}
            ],
            "pwn": [
                {"step": "exploit_reliability", "description": "Test exploit reliability and success rate"},
                {"step": "payload_verification", "description": "Verify payload executes correctly"},
                {"step": "shell_validation", "description": "Validate shell access and commands"},
                {"step": "flag_retrieval", "description": "Successfully retrieve flag from target"}
            ],
            "forensics": [
                {"step": "data_integrity", "description": "Verify integrity of recovered data"},
                {"step": "timeline_accuracy", "description": "Validate timeline accuracy"},
                {"step": "evidence_correlation", "description": "Verify evidence correlation is correct"},
                {"step": "flag_location", "description": "Confirm flag location and extraction"}
            ],
            "rev": [
                {"step": "algorithm_accuracy", "description": "Verify algorithm identification is correct"},
                {"step": "key_extraction", "description": "Validate extracted keys and values"},
                {"step": "solution_testing", "description": "Test solution against known inputs"},
                {"step": "flag_generation", "description": "Generate correct flag using solution"}
            ],
            "osint": [
                {"step": "source_verification", "description": "Verify information sources are reliable"},
                {"step": "cross_reference", "description": "Cross-reference findings across sources"},
                {"step": "accuracy_check", "description": "Check accuracy of gathered intelligence"},
                {"step": "flag_confirmation", "description": "Confirm flag from verified information"}
            ],
            "misc": [
                {"step": "solution_verification", "description": "Verify solution approach is correct"},
                {"step": "output_validation", "description": "Validate output format and content"},
                {"step": "edge_case_testing", "description": "Test solution with edge cases"},
                {"step": "flag_extraction", "description": "Extract and validate final flag"}
            ]
        });

        category_list(&validation_steps, category, json!([
            {"step": "general_validation", "description": "General solution validation"},
            {"step": "flag_verification", "description": "Verify flag format and correctness"}
        ]))
    }
}

/// Advanced tool manager for CTF challenges with comprehensive tool arsenal
pub struct CTFToolManager {
    pub tool_commands: Value,
    pub tool_categories: Value,
}

/// `self.tool_commands` do Python: comando base de cada ferramenta. Em pares
/// porque `json!` estoura o limite de recursão do macro com ~150 chaves.
/// Os `{}` de alguns comandos são literais: o Python nunca os formata.
const TOOL_COMMANDS: &[(&str, &str)] = &[
                // Web Application Security Tools
                ("httpx", "httpx -probe -tech-detect -status-code -title -content-length"),
                ("katana", "katana -depth 3 -js-crawl -form-extraction -headless"),
                ("sqlmap", "sqlmap --batch --level 3 --risk 2 --threads 5"),
                ("dalfox", "dalfox url --mining-dom --mining-dict --deep-domxss"),
                ("gobuster", "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js"),
                ("dirsearch", "dirsearch -u {} -e php,html,js,txt,xml,json -t 50"),
                ("feroxbuster", "feroxbuster -u {} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt"),
                ("arjun", "arjun -u {} --get --post"),
                ("paramspider", "paramspider -d {}"),
                ("wpscan", "wpscan --url {} --enumerate ap,at,cb,dbe"),
                ("nikto", "nikto -h {} -C all"),
                ("whatweb", "whatweb -v -a 3"),

                // Cryptography Challenge Tools
                ("hashcat", "hashcat -m 0 -a 0 --potfile-disable --quiet"),
                ("john", "john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5"),
                ("hash-identifier", "hash-identifier"),
                ("hashid", "hashid -m"),
                ("cipher-identifier", "python3 /opt/cipher-identifier/cipher_identifier.py"),
                ("factordb", "python3 /opt/factordb/factordb.py"),
                ("rsatool", "python3 /opt/rsatool/rsatool.py"),
                ("yafu", "yafu"),
                ("sage", "sage -python"),
                ("openssl", "openssl"),
                ("gpg", "gpg --decrypt"),
                ("steganography", "stegcracker"),
                ("frequency-analysis", "python3 /opt/frequency-analysis/freq_analysis.py"),
                ("substitution-solver", "python3 /opt/substitution-solver/solve.py"),
                ("vigenere-solver", "python3 /opt/vigenere-solver/vigenere.py"),
                ("base64", "base64 -d"),
                ("base32", "base32 -d"),
                ("hex", "xxd -r -p"),
                ("rot13", "tr 'A-Za-z' 'N-ZA-Mn-za-m'"),

                // Binary Exploitation (Pwn) Tools
                ("checksec", "checksec --file"),
                ("pwntools", "python3 -c 'from pwn import *; context.log_level = \"debug\"'"),
                ("ropper", "ropper --file {} --search"),
                ("ropgadget", "ROPgadget --binary"),
                ("one-gadget", "one_gadget"),
                ("gdb-peda", "gdb -ex 'source /opt/peda/peda.py'"),
                ("gdb-gef", "gdb -ex 'source /opt/gef/gef.py'"),
                ("gdb-pwngdb", "gdb -ex 'source /opt/Pwngdb/pwngdb.py'"),
                ("angr", "python3 -c 'import angr'"),
                ("radare2", "r2 -A"),
                ("ghidra", "analyzeHeadless /tmp ghidra_project -import"),
                ("binary-ninja", "binaryninja"),
                ("ltrace", "ltrace"),
                ("strace", "strace -f"),
                ("objdump", "objdump -d -M intel"),
                ("readelf", "readelf -a"),
                ("nm", "nm -D"),
                ("ldd", "ldd"),
                ("file", "file"),
                ("strings", "strings -n 8"),
                ("hexdump", "hexdump -C"),
                ("pwninit", "pwninit"),
                ("libc-database", "python3 /opt/libc-database/find.py"),

                // Forensics Investigation Tools
                ("binwalk", "binwalk -e --dd='.*'"),
                ("foremost", "foremost -i {} -o /tmp/foremost_output"),
                ("photorec", "photorec /log /cmd"),
                ("testdisk", "testdisk /log"),
                ("exiftool", "exiftool -all"),
                ("steghide", "steghide extract -sf {} -p ''"),
                ("stegsolve", "java -jar /opt/stegsolve/stegsolve.jar"),
                ("zsteg", "zsteg -a"),
                ("outguess", "outguess -r"),
                ("jsteg", "jsteg reveal"),
                ("volatility", "volatility -f {} imageinfo"),
                ("volatility3", "python3 /opt/volatility3/vol.py -f"),
                ("rekall", "rekall -f"),
                ("wireshark", "tshark -r"),
                ("tcpdump", "tcpdump -r"),
                ("networkminer", "mono /opt/NetworkMiner/NetworkMiner.exe"),
                ("autopsy", "autopsy"),
                ("sleuthkit", "fls -r"),
                ("scalpel", "scalpel -c /etc/scalpel/scalpel.conf"),
                ("bulk-extractor", "bulk_extractor -o /tmp/bulk_output"),
                ("ddrescue", "ddrescue"),
                ("dc3dd", "dc3dd"),

                // Reverse Engineering Tools
                ("ida", "ida64"),
                ("ida-free", "ida64 -A"),
                ("retdec", "retdec-decompiler"),
                ("upx", "upx -d"),
                ("peid", "peid"),
                ("detect-it-easy", "die"),
                ("x64dbg", "x64dbg"),
                ("ollydbg", "ollydbg"),
                ("immunity", "immunity"),
                ("windbg", "windbg"),
                ("apktool", "apktool d"),
                ("jadx", "jadx"),
                ("dex2jar", "dex2jar"),
                ("jd-gui", "jd-gui"),
                ("dnspy", "dnspy"),
                ("ilspy", "ilspy"),
                ("dotpeek", "dotpeek"),

                // OSINT and Reconnaissance Tools
                ("sherlock", "sherlock"),
                ("social-analyzer", "social-analyzer"),
                ("theHarvester", "theHarvester -d {} -b all"),
                ("recon-ng", "recon-ng"),
                ("maltego", "maltego"),
                ("spiderfoot", "spiderfoot"),
                ("shodan", "shodan search"),
                ("censys", "censys search"),
                ("whois", "whois"),
                ("dig", "dig"),
                ("nslookup", "nslookup"),
                ("host", "host"),
                ("dnsrecon", "dnsrecon -d"),
                ("fierce", "fierce -dns"),
                ("sublist3r", "sublist3r -d"),
                ("amass", "amass enum -d"),
                ("assetfinder", "assetfinder"),
                ("subfinder", "subfinder -d"),
                ("waybackurls", "waybackurls"),
                ("gau", "gau"),
                ("httpx-osint", "httpx -title -tech-detect -status-code"),

                // Miscellaneous Challenge Tools
                ("qr-decoder", "zbarimg"),
                ("barcode-decoder", "zbarimg"),
                ("audio-analysis", "audacity"),
                ("sonic-visualizer", "sonic-visualizer"),
                ("spectrum-analyzer", "python3 /opt/spectrum-analyzer/analyze.py"),
                ("brainfuck", "python3 /opt/brainfuck/bf.py"),
                ("whitespace", "python3 /opt/whitespace/ws.py"),
                ("piet", "python3 /opt/piet/piet.py"),
                ("malbolge", "python3 /opt/malbolge/malbolge.py"),
                ("ook", "python3 /opt/ook/ook.py"),
                ("zip", "unzip -P"),
                ("7zip", "7z x -p"),
                ("rar", "unrar x -p"),
                ("tar", "tar -xf"),
                ("gzip", "gunzip"),
                ("bzip2", "bunzip2"),
                ("xz", "unxz"),
                ("lzma", "unlzma"),
                ("compress", "uncompress"),

                // Modern Web Technologies
                ("jwt-tool", "python3 /opt/jwt_tool/jwt_tool.py"),
                ("jwt-cracker", "jwt-cracker"),
                ("graphql-voyager", "graphql-voyager"),
                ("graphql-playground", "graphql-playground"),
                ("postman", "newman run"),
                ("burpsuite", "java -jar /opt/burpsuite/burpsuite.jar"),
                ("owasp-zap", "zap.sh -cmd"),
                ("websocket-king", "python3 /opt/websocket-king/ws_test.py"),

                // Cloud and Container Security
                ("docker", "docker"),
                ("kubectl", "kubectl"),
                ("aws-cli", "aws"),
                ("azure-cli", "az"),
                ("gcloud", "gcloud"),
                ("terraform", "terraform"),
                ("ansible", "ansible"),

                // Mobile Application Security
                ("adb", "adb"),
                ("frida", "frida"),
                ("objection", "objection"),
                ("mobsf", "python3 /opt/mobsf/manage.py"),
                ("apkleaks", "apkleaks -f"),
                ("qark", "qark --apk"),
];

impl CTFToolManager {
    pub fn new() -> Self {
        Self {
            tool_commands: Value::Object(
                TOOL_COMMANDS
                    .iter()
                    .map(|(tool, command)| (tool.to_string(), Value::String(command.to_string())))
                    .collect(),
            ),
            // Tool categories for intelligent selection
            tool_categories: json!({
                "web_recon": ["httpx", "katana", "waybackurls", "gau", "whatweb"],
                "web_vuln": ["sqlmap", "dalfox", "nikto", "wpscan"],
                "web_discovery": ["gobuster", "dirsearch", "feroxbuster"],
                "web_params": ["arjun", "paramspider"],
                "crypto_hash": ["hashcat", "john", "hash-identifier", "hashid"],
                "crypto_cipher": ["cipher-identifier", "frequency-analysis", "substitution-solver"],
                "crypto_rsa": ["rsatool", "factordb", "yafu"],
                "crypto_modern": ["sage", "openssl", "gpg"],
                "pwn_analysis": ["checksec", "file", "strings", "objdump", "readelf"],
                "pwn_exploit": ["pwntools", "ropper", "ropgadget", "one-gadget"],
                "pwn_debug": ["gdb-peda", "gdb-gef", "ltrace", "strace"],
                "pwn_advanced": ["angr", "ghidra", "radare2"],
                "forensics_file": ["binwalk", "foremost", "photorec", "exiftool"],
                "forensics_image": ["steghide", "stegsolve", "zsteg", "outguess"],
                "forensics_memory": ["volatility", "volatility3", "rekall"],
                "forensics_network": ["wireshark", "tcpdump", "networkminer"],
                "rev_static": ["ghidra", "ida", "radare2", "strings"],
                "rev_dynamic": ["gdb-peda", "ltrace", "strace"],
                "rev_unpack": ["upx", "peid", "detect-it-easy"],
                "osint_social": ["sherlock", "social-analyzer", "theHarvester"],
                "osint_domain": ["whois", "dig", "sublist3r", "amass"],
                "osint_search": ["shodan", "censys", "recon-ng"],
                "misc_encoding": ["base64", "base32", "hex", "rot13"],
                "misc_compression": ["zip", "7zip", "rar", "tar"],
                "misc_esoteric": ["brainfuck", "whitespace", "piet", "malbolge"]
            }),
        }
    }

    /// Get optimized command for CTF tool with intelligent parameter selection
    pub fn get_tool_command(&self, tool: &str, target: &str, additional_args: &str) -> String {
        let mut base_command = self
            .tool_commands
            .get(tool)
            .and_then(Value::as_str)
            .unwrap_or(tool)
            .to_string();

        // Add intelligent parameter optimization based on tool type
        if matches!(tool, "hashcat" | "john") {
            // For hash cracking, add common wordlists and rules
            if !base_command.contains("wordlist") {
                base_command.push_str(" --wordlist=/usr/share/wordlists/rockyou.txt");
            }
            if tool == "hashcat" && !base_command.contains("--rules") {
                base_command.push_str(" --rules-file=/usr/share/hashcat/rules/best64.rule");
            }
        } else if matches!(tool, "sqlmap") {
            // For SQL injection, add tamper scripts and optimization
            if !base_command.contains("--tamper") {
                base_command.push_str(" --tamper=space2comment,charencode,randomcase");
            }
            if !base_command.contains("--threads") {
                base_command.push_str(" --threads=5");
            }
        } else if matches!(tool, "gobuster" | "dirsearch" | "feroxbuster") {
            // For directory brute forcing, optimize threads and extensions
            if !base_command.contains("-t") {
                base_command.push_str(" -t 50");
            }
        }

        if additional_args.is_empty() {
            format!("{base_command} {target}")
        } else {
            format!("{base_command} {additional_args} {target}")
        }
    }

    /// Get all tools for a specific category
    pub fn get_category_tools(&self, category: &str) -> Vec<String> {
        first_strings(self.tool_categories.get(category), usize::MAX)
    }

    /// Suggest optimal tools based on challenge description and category
    pub fn suggest_tools_for_challenge(&self, challenge_description: &str, category: &str) -> Vec<String> {
        let mut suggested_tools: Vec<String> = Vec::new();
        let description_lower = challenge_description.to_lowercase();

        // Category-based tool suggestions
        match category {
            "web" => {
                suggested_tools.extend(first_strings(self.tool_categories.get("web_recon"), 2));

                if contains_any(&description_lower, &["sql", "injection", "database", "mysql", "postgres"]) {
                    suggested_tools.extend(["sqlmap".to_string(), "hash-identifier".to_string()]);
                }
                if contains_any(&description_lower, &["xss", "script", "javascript", "dom"]) {
                    suggested_tools.extend(["dalfox".to_string(), "katana".to_string()]);
                }
                if contains_any(&description_lower, &["wordpress", "wp", "cms"]) {
                    suggested_tools.push("wpscan".to_string());
                }
                if contains_any(&description_lower, &["directory", "hidden", "files", "admin"]) {
                    suggested_tools.extend(["gobuster".to_string(), "dirsearch".to_string()]);
                }
                if contains_any(&description_lower, &["parameter", "param", "get", "post"]) {
                    suggested_tools.extend(["arjun".to_string(), "paramspider".to_string()]);
                }
                if contains_any(&description_lower, &["jwt", "token", "session"]) {
                    suggested_tools.push("jwt-tool".to_string());
                }
                if contains_any(&description_lower, &["graphql", "api"]) {
                    suggested_tools.push("graphql-voyager".to_string());
                }
            }
            "crypto" => {
                if contains_any(&description_lower, &["hash", "md5", "sha", "password"]) {
                    suggested_tools.extend([
                        "hashcat".to_string(),
                        "john".to_string(),
                        "hash-identifier".to_string(),
                    ]);
                }
                if contains_any(&description_lower, &["rsa", "public key", "private key", "factorization"]) {
                    suggested_tools.extend(["rsatool".to_string(), "factordb".to_string(), "yafu".to_string()]);
                }
                if contains_any(&description_lower, &["cipher", "encrypt", "decrypt", "substitution"]) {
                    suggested_tools.extend(["cipher-identifier".to_string(), "frequency-analysis".to_string()]);
                }
                if contains_any(&description_lower, &["vigenere", "polyalphabetic"]) {
                    suggested_tools.push("vigenere-solver".to_string());
                }
                if contains_any(&description_lower, &["base64", "base32", "encoding"]) {
                    suggested_tools.extend(["base64".to_string(), "base32".to_string()]);
                }
                if contains_any(&description_lower, &["rot", "caesar", "shift"]) {
                    suggested_tools.push("rot13".to_string());
                }
                if contains_any(&description_lower, &["pgp", "gpg", "signature"]) {
                    suggested_tools.push("gpg".to_string());
                }
            }
            "pwn" => {
                suggested_tools.extend([
                    "checksec".to_string(),
                    "file".to_string(),
                    "strings".to_string(),
                ]);

                if contains_any(&description_lower, &["buffer", "overflow", "bof"]) {
                    suggested_tools.extend(["pwntools".to_string(), "gdb-peda".to_string(), "ropper".to_string()]);
                }
                if contains_any(&description_lower, &["format", "printf", "string"]) {
                    suggested_tools.extend(["pwntools".to_string(), "gdb-peda".to_string()]);
                }
                if contains_any(&description_lower, &["heap", "malloc", "free"]) {
                    suggested_tools.extend(["pwntools".to_string(), "gdb-gef".to_string()]);
                }
                if contains_any(&description_lower, &["rop", "gadget", "chain"]) {
                    suggested_tools.extend(["ropper".to_string(), "ropgadget".to_string()]);
                }
                if contains_any(&description_lower, &["shellcode", "exploit"]) {
                    suggested_tools.extend(["pwntools".to_string(), "one-gadget".to_string()]);
                }
                if contains_any(&description_lower, &["canary", "stack", "protection"]) {
                    suggested_tools.extend(["checksec".to_string(), "pwntools".to_string()]);
                }
            }
            "forensics" => {
                if contains_any(&description_lower, &["image", "jpg", "png", "gif", "steganography"]) {
                    suggested_tools.extend([
                        "exiftool".to_string(),
                        "steghide".to_string(),
                        "stegsolve".to_string(),
                        "zsteg".to_string(),
                    ]);
                }
                if contains_any(&description_lower, &["memory", "dump", "ram"]) {
                    suggested_tools.extend(["volatility".to_string(), "volatility3".to_string()]);
                }
                if contains_any(&description_lower, &["network", "pcap", "wireshark", "traffic"]) {
                    suggested_tools.extend(["wireshark".to_string(), "tcpdump".to_string()]);
                }
                if contains_any(&description_lower, &["file", "deleted", "recovery", "carving"]) {
                    suggested_tools.extend(["binwalk".to_string(), "foremost".to_string(), "photorec".to_string()]);
                }
                if contains_any(&description_lower, &["disk", "filesystem", "partition"]) {
                    suggested_tools.extend(["testdisk".to_string(), "sleuthkit".to_string()]);
                }
                if contains_any(&description_lower, &["audio", "wav", "mp3", "sound"]) {
                    suggested_tools.extend(["audacity".to_string(), "sonic-visualizer".to_string()]);
                }
            }
            "rev" => {
                suggested_tools.extend([
                    "file".to_string(),
                    "strings".to_string(),
                    "objdump".to_string(),
                ]);

                if contains_any(&description_lower, &["packed", "upx", "packer"]) {
                    suggested_tools.extend(["upx".to_string(), "peid".to_string(), "detect-it-easy".to_string()]);
                }
                if contains_any(&description_lower, &["android", "apk", "mobile"]) {
                    suggested_tools.extend(["apktool".to_string(), "jadx".to_string(), "dex2jar".to_string()]);
                }
                if contains_any(&description_lower, &[".net", "dotnet", "csharp"]) {
                    suggested_tools.extend(["dnspy".to_string(), "ilspy".to_string()]);
                }
                if contains_any(&description_lower, &["java", "jar", "class"]) {
                    suggested_tools.extend(["jd-gui".to_string(), "jadx".to_string()]);
                }
                if contains_any(&description_lower, &["windows", "exe", "dll"]) {
                    suggested_tools.extend(["ghidra".to_string(), "ida".to_string(), "x64dbg".to_string()]);
                }
                if contains_any(&description_lower, &["linux", "elf", "binary"]) {
                    suggested_tools.extend(["ghidra".to_string(), "radare2".to_string(), "gdb-peda".to_string()]);
                }
            }
            "osint" => {
                if contains_any(&description_lower, &["username", "social", "media"]) {
                    suggested_tools.extend(["sherlock".to_string(), "social-analyzer".to_string()]);
                }
                if contains_any(&description_lower, &["domain", "subdomain", "dns"]) {
                    suggested_tools.extend(["sublist3r".to_string(), "amass".to_string(), "dig".to_string()]);
                }
                if contains_any(&description_lower, &["email", "harvest", "contact"]) {
                    suggested_tools.push("theHarvester".to_string());
                }
                if contains_any(&description_lower, &["ip", "port", "service"]) {
                    suggested_tools.extend(["shodan".to_string(), "censys".to_string()]);
                }
                if contains_any(&description_lower, &["whois", "registration", "owner"]) {
                    suggested_tools.push("whois".to_string());
                }
            }
            "misc" => {
                if contains_any(&description_lower, &["qr", "barcode", "code"]) {
                    suggested_tools.push("qr-decoder".to_string());
                }
                if contains_any(&description_lower, &["zip", "archive", "compressed"]) {
                    suggested_tools.extend(["zip".to_string(), "7zip".to_string(), "rar".to_string()]);
                }
                if contains_any(&description_lower, &["brainfuck", "bf", "esoteric"]) {
                    suggested_tools.push("brainfuck".to_string());
                }
                if contains_any(&description_lower, &["whitespace", "ws"]) {
                    suggested_tools.push("whitespace".to_string());
                }
                if contains_any(&description_lower, &["piet", "image", "program"]) {
                    suggested_tools.push("piet".to_string());
                }
            }
            _ => {}
        }

        // Remove duplicates while preserving order
        dedup(suggested_tools)
    }
}
