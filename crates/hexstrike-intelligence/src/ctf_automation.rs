//! Port 1:1 de `hexstrike_server/intelligence/ctf_automation.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W6.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  class CTFChallengeAutomator:
//!   237  class CTFTeamCoordinator:
//! ```

//! Port 1:1 de `hexstrike_server/intelligence/ctf_automation.py`.
//!
//! Inventário Python (ordem de definição) — checklist do shard W6.
//! NÃO invente símbolo: o que não está aqui não existe no monólito.
//!
//! ```text
//!    20  class CTFChallengeAutomator:
//!   237  class CTFTeamCoordinator:
//! ```
//!
//! As classes moram aqui, mas os singletons (`ctf_manager`, `ctf_tools`,
//! `ctf_automator`, `ctf_coordinator`) NÃO: o `_registry.py` os atribui a
//! `intelligence/process_manager.py`. O corpo das funções abaixo usa
//! `ctf_manager`/`ctf_tools` de lá, igual ao Python (globais de módulo).

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use serde_json::{json, Value};

use crate::ctf::{CTFChallenge, TARGET_ATTRIBUTE_ERROR};
use crate::process_manager::{ctf_manager, ctf_tools};

/// `flag_patterns` do Python — `re.findall(pattern, output, re.IGNORECASE)`.
static FLAG_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"[a-zA-Z0-9_]+\{[^}]+\}",
        r"[0-9a-f]{32}", // MD5 hash
        r"[0-9a-f]{40}", // SHA1 hash
        r"[0-9a-f]{64}", // SHA256 hash
    ]
    .iter()
    .map(|pattern| Regex::new(&format!("(?i){pattern}")).expect("regex do Python válido"))
    .collect()
});

/// `common_formats` de `_validate_flag_format` — `re.match(pattern, flag,
/// re.IGNORECASE)`.
static COMMON_FORMATS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^flag\{.+\}$",
        r"^FLAG\{.+\}$",
        r"^ctf\{.+\}$",
        r"^CTF\{.+\}$",
        r"^[a-zA-Z0-9_]+\{.+\}$",
    ]
    .iter()
    .map(|pattern| Regex::new(&format!("(?i){pattern}")).expect("regex do Python válido"))
    .collect()
});

/// Advanced automation system for CTF challenge solving
pub struct CTFChallengeAutomator {
    // Estado do `__init__` do Python: o resto do módulo nunca lê estes campos.
    pub active_challenges: Value,
    pub solution_cache: Value,
    pub learning_database: Value,
    pub success_patterns: Value,
}

impl CTFChallengeAutomator {
    pub fn new() -> Self {
        Self {
            active_challenges: json!({}),
            solution_cache: json!({}),
            learning_database: json!({}),
            success_patterns: json!({}),
        }
    }

    /// Attempt to automatically solve a CTF challenge
    ///
    /// O `except Exception` do Python só dispara se algo levantar; no corpo,
    /// o único ponto que levantaria (`challenge.target`) está dentro dos
    /// passos e é engolido lá — por isso não há caminho `status: "error"`
    /// (nem o `logger.error` do `except`) no port.
    pub fn auto_solve_challenge(&self, challenge: &CTFChallenge) -> Value {
        let mut result = json!({
            "challenge_id": &challenge.name,
            "status": "in_progress",
            "automated_steps": [],
            "manual_steps": [],
            "confidence": 0.0,
            "estimated_completion": 0,
            "artifacts": [],
            "flag_candidates": [],
            "next_actions": []
        });

        // Create workflow
        let workflow = ctf_manager.create_ctf_challenge_workflow(challenge);

        let mut confidence = 0.0_f64;
        let mut automated_steps: Vec<Value> = Vec::new();
        let mut flag_candidates: Vec<String> = Vec::new();
        let mut flag: Option<String> = None;

        // Execute automated steps
        for step in workflow["workflow_steps"].as_array().cloned().unwrap_or_default() {
            let step_result = if step.get("parallel").and_then(Value::as_bool).unwrap_or(false) {
                self._execute_parallel_step(&step, challenge)
            } else {
                self._execute_sequential_step(&step, challenge)
            };

            automated_steps.push(step_result.clone());

            // Check for flag candidates
            let candidates = self._extract_flag_candidates(step_result["output"].as_str().unwrap_or(""));
            flag_candidates.extend(candidates.clone());

            // Update confidence based on step success
            if step_result["success"].as_bool().unwrap_or(false) {
                confidence += 0.1;
            }

            // Early termination if flag found
            if let Some(first) = candidates.first() {
                if self._validate_flag_format(first) {
                    flag = Some(first.clone());
                    break;
                }
            }
        }

        result["automated_steps"] = Value::Array(automated_steps);
        result["flag_candidates"] = json!(flag_candidates);

        // If not solved automatically, provide manual guidance
        match flag {
            Some(flag) => {
                result["status"] = json!("solved");
                result["flag"] = json!(flag);
            }
            None => {
                result["manual_steps"] = Value::Array(self._generate_manual_guidance(challenge, &result));
                result["status"] = json!("needs_manual_intervention");
            }
        }

        result["confidence"] = json!(1.0_f64.min(confidence));

        result
    }

    /// Execute a step with parallel tool execution
    pub fn _execute_parallel_step(&self, step: &Value, challenge: &CTFChallenge) -> Value {
        let mut step_result = json!({
            "step": &step["step"],
            "action": &step["action"],
            "success": false,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        });

        let start_time = Instant::now();
        let tools = step.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
        // `challenge` só apareceria em `challenge.target or challenge.name`.
        let _ = challenge;

        let mut output = String::new();
        // `tools_used` do Python: só recebe `append` no ramo que morre no
        // `challenge.target` — fica sempre vazio.
        let tools_used: Vec<String> = Vec::new();
        let success = false;

        // Execute tools in parallel (simulated for now)
        for tool in tools {
            let tool = tool.as_str().unwrap_or_default().to_string();
            if tool != "manual" {
                // Python: `ctf_tools.get_tool_command(tool, challenge.target or
                // challenge.name)` — o dataclass não tem `target`, então o
                // `except` do laço registra o erro e nada é executado.
                output.push_str(&format!("[{tool}] Error: {TARGET_ATTRIBUTE_ERROR}\n"));
            }
        }

        step_result["success"] = json!(success);
        step_result["output"] = json!(output);
        step_result["tools_used"] = json!(tools_used);
        step_result["execution_time"] = json!(start_time.elapsed().as_secs_f64());

        step_result
    }

    /// Execute a step sequentially
    pub fn _execute_sequential_step(&self, step: &Value, challenge: &CTFChallenge) -> Value {
        let mut step_result = json!({
            "step": &step["step"],
            "action": &step["action"],
            "success": false,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        });

        let start_time = Instant::now();
        let tools = step.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
        let _ = challenge;

        let mut output = String::new();
        // `tools_used` do Python: só recebe `append` no ramo que morre no
        // `challenge.target` — fica sempre vazio.
        let tools_used: Vec<String> = Vec::new();
        let mut success = false;

        for tool in tools {
            let tool = tool.as_str().unwrap_or_default().to_string();
            if tool == "manual" {
                output.push_str(&format!("[MANUAL] {}\n", step["description"].as_str().unwrap_or("")));
                success = true;
            } else if tool == "custom" {
                output.push_str("[CUSTOM] Custom implementation required\n");
                success = true;
            } else {
                // Python: `ctf_tools.get_tool_command(tool, challenge.target or
                // challenge.name)` — ver `_execute_parallel_step`.
                output.push_str(&format!("[{tool}] Error: {TARGET_ATTRIBUTE_ERROR}\n"));
            }
        }

        step_result["success"] = json!(success);
        step_result["output"] = json!(output);
        step_result["tools_used"] = json!(tools_used);
        step_result["execution_time"] = json!(start_time.elapsed().as_secs_f64());

        step_result
    }

    /// Extract potential flags from tool output
    pub fn _extract_flag_candidates(&self, output: &str) -> Vec<String> {
        let mut candidates: Vec<String> = Vec::new();
        for pattern in FLAG_PATTERNS.iter() {
            candidates.extend(pattern.find_iter(output).map(|found| found.as_str().to_string()));
        }

        // Python: `list(set(candidates))` (ordem não determinística).
        let mut seen = HashSet::new();
        candidates.into_iter().filter(|candidate| seen.insert(candidate.clone())).collect()
    }

    /// Validate if a string matches common flag formats
    pub fn _validate_flag_format(&self, flag: &str) -> bool {
        COMMON_FORMATS.iter().any(|pattern| pattern.is_match(flag))
    }

    /// Generate manual guidance when automation fails
    pub fn _generate_manual_guidance(&self, challenge: &CTFChallenge, current_result: &Value) -> Vec<Value> {
        let mut guidance: Vec<Value> = Vec::new();

        // Analyze what was attempted
        let mut attempted_tools: Vec<String> = Vec::new();
        for step in current_result["automated_steps"].as_array().cloned().unwrap_or_default() {
            attempted_tools.extend(
                step.get("tools_used")
                    .and_then(Value::as_array)
                    .map(|tools| tools.iter().filter_map(|tool| tool.as_str().map(str::to_string)).collect::<Vec<String>>())
                    .unwrap_or_default(),
            );
        }

        // Suggest alternative approaches
        let all_category_tools = ctf_tools.get_category_tools(&format!("{}_recon", challenge.category));
        let unused_tools: Vec<String> = all_category_tools
            .into_iter()
            .filter(|tool| !attempted_tools.contains(tool))
            .collect();

        if !unused_tools.is_empty() {
            guidance.push(json!({
                "action": "try_alternative_tools",
                "description": format!("Try these alternative tools: {}", unused_tools.iter().take(3).cloned().collect::<Vec<String>>().join(", "))
            }));
        }

        // Category-specific guidance
        match challenge.category.as_str() {
            "web" => guidance.extend([
                json!({"action": "manual_source_review", "description": "Manually review all HTML/JS source code for hidden comments or clues"}),
                json!({"action": "parameter_fuzzing", "description": "Manually fuzz parameters with custom payloads"}),
                json!({"action": "cookie_analysis", "description": "Analyze cookies and session management"}),
            ]),
            "crypto" => guidance.extend([
                json!({"action": "cipher_research", "description": "Research the specific cipher type and known attacks"}),
                json!({"action": "key_analysis", "description": "Analyze key properties and potential weaknesses"}),
                json!({"action": "frequency_analysis", "description": "Perform detailed frequency analysis"}),
            ]),
            "pwn" => guidance.extend([
                json!({"action": "manual_debugging", "description": "Manually debug the binary to understand control flow"}),
                json!({"action": "exploit_development", "description": "Develop custom exploit based on vulnerability analysis"}),
                json!({"action": "payload_crafting", "description": "Craft specific payloads for the identified vulnerability"}),
            ]),
            "forensics" => guidance.extend([
                json!({"action": "manual_analysis", "description": "Manually analyze file structures and metadata"}),
                json!({"action": "steganography_deep_dive", "description": "Deep dive into steganography techniques"}),
                json!({"action": "timeline_analysis", "description": "Reconstruct detailed timeline of events"}),
            ]),
            "rev" => guidance.extend([
                json!({"action": "algorithm_analysis", "description": "Focus on understanding the core algorithm"}),
                json!({"action": "key_extraction", "description": "Extract hardcoded keys or important values"}),
                json!({"action": "dynamic_analysis", "description": "Use dynamic analysis to understand runtime behavior"}),
            ]),
            _ => {}
        }

        guidance
    }
}

/// `member_challenge_scores[member]` do Python: lá `challenge` é o objeto
/// `CTFChallenge`; aqui é o NOME, porque o `jsonify` do Python não consegue
/// serializar o dataclass (a estrutura nunca chega ao cliente).
pub struct ChallengeScore {
    challenge: String,
    score: f64,
    estimated_time: i64,
}

/// Coordinate team efforts in CTF competitions
pub struct CTFTeamCoordinator {
    // Estado do `__init__` do Python: o resto do módulo nunca lê estes campos.
    pub team_members: Value,
    pub challenge_assignments: Value,
    pub team_communication: Value,
    pub shared_resources: Value,
}

impl CTFTeamCoordinator {
    pub fn new() -> Self {
        Self {
            team_members: json!({}),
            challenge_assignments: json!({}),
            team_communication: json!([]),
            shared_resources: json!({}),
        }
    }

    /// Optimize team strategy based on member skills and challenge types
    pub fn optimize_team_strategy(&self, challenges: &[CTFChallenge], team_skills: &Value) -> Value {
        let mut strategy = json!({
            "assignments": {},
            "priority_queue": [],
            "collaboration_opportunities": [],
            "resource_sharing": {},
            "estimated_total_score": 0,
            "time_allocation": {}
        });

        // Analyze team skills
        let mut skill_matrix: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();
        if let Some(team_skills) = team_skills.as_object() {
            for (member, skills) in team_skills {
                let skills: Vec<String> = skills
                    .as_array()
                    .map(|list| list.iter().filter_map(|skill| skill.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                let has = |skill: &str, alternative: &str| {
                    skills.iter().any(|member_skill| member_skill == skill || member_skill == alternative)
                };

                let mut row = BTreeMap::new();
                row.insert("web".to_string(), has("web", "webapp"));
                row.insert("crypto".to_string(), has("crypto", "cryptography"));
                row.insert("pwn".to_string(), has("pwn", "binary"));
                row.insert("forensics".to_string(), has("forensics", "investigation"));
                row.insert("rev".to_string(), has("reverse", "reversing"));
                row.insert("osint".to_string(), has("osint", "intelligence"));
                row.insert("misc".to_string(), true); // Everyone can handle misc

                skill_matrix.insert(member.clone(), row);
            }
        }

        // Score challenges for each team member
        let mut member_challenge_scores: BTreeMap<String, Vec<ChallengeScore>> = BTreeMap::new();
        for (member, member_skills) in &skill_matrix {
            let mut scores: Vec<ChallengeScore> = Vec::new();

            for challenge in challenges {
                let base_score = challenge.points as f64;
                let mut skill_multiplier = 1.0;

                if member_skills.get(&challenge.category).copied().unwrap_or(false) {
                    skill_multiplier = 1.5; // 50% bonus for skill match
                }

                let difficulty_penalty = match challenge.difficulty.as_str() {
                    "easy" => 1.0,
                    "medium" => 0.9,
                    "hard" => 0.7,
                    "insane" => 0.5,
                    _ => 0.8,
                };

                let final_score = base_score * skill_multiplier * difficulty_penalty;

                scores.push(ChallengeScore {
                    challenge: challenge.name.clone(),
                    score: final_score,
                    estimated_time: self._estimate_solve_time(challenge, member_skills),
                });
            }

            member_challenge_scores.insert(member.clone(), scores);
        }

        // Assign challenges using Hungarian algorithm approximation
        let assignments = self._assign_challenges_optimally(&member_challenge_scores);

        // Create priority queue
        let mut all_assignments: Vec<Value> = Vec::new();
        if let Some(by_member) = assignments.as_object() {
            for (member, member_challenges) in by_member {
                for challenge_info in member_challenges.as_array().cloned().unwrap_or_default() {
                    all_assignments.push(json!({
                        "member": member,
                        "challenge": &challenge_info["challenge"],
                        "priority": challenge_info["score"],
                        "estimated_time": challenge_info["estimated_time"]
                    }));
                }
            }
        }

        strategy["assignments"] = assignments;
        strategy["priority_queue"] = {
            all_assignments.sort_by(|left, right| {
                let left = left["priority"].as_f64().unwrap_or(0.0);
                let right = right["priority"].as_f64().unwrap_or(0.0);
                right.partial_cmp(&left).unwrap_or(std::cmp::Ordering::Equal)
            });
            Value::Array(all_assignments)
        };

        // Identify collaboration opportunities
        strategy["collaboration_opportunities"] =
            Value::Array(self._identify_collaboration_opportunities(challenges, team_skills));

        strategy
    }

    /// Estimate solve time for a challenge based on member skills
    pub fn _estimate_solve_time(&self, challenge: &CTFChallenge, member_skills: &BTreeMap<String, bool>) -> i64 {
        let base_time = match challenge.difficulty.as_str() {
            "easy" => 1800,    // 30 minutes
            "medium" => 3600,  // 1 hour
            "hard" => 7200,    // 2 hours
            "insane" => 14400, // 4 hours
            _ => 5400,         // 1.5 hours
        };

        // Skill bonus
        if member_skills.get(&challenge.category).copied().unwrap_or(false) {
            return (base_time as f64 * 0.7) as i64; // 30% faster with relevant skills
        }

        base_time
    }

    /// Assign challenges to team members optimally
    pub fn _assign_challenges_optimally(&self, member_challenge_scores: &BTreeMap<String, Vec<ChallengeScore>>) -> Value {
        let mut assignments: BTreeMap<String, Vec<Value>> =
            member_challenge_scores.keys().map(|member| (member.clone(), Vec::new())).collect();
        let mut assigned_challenges: HashSet<String> = HashSet::new();

        // Simple greedy assignment (in practice, would use Hungarian algorithm)
        for _ in 0..member_challenge_scores.len() {
            let mut best_assignment: Option<(&String, &ChallengeScore)> = None;
            let mut best_score = -1.0;

            for (member, challenge_scores) in member_challenge_scores {
                for challenge_info in challenge_scores {
                    if !assigned_challenges.contains(&challenge_info.challenge) && challenge_info.score > best_score {
                        best_score = challenge_info.score;
                        best_assignment = Some((member, challenge_info));
                    }
                }
            }

            if let Some((member, challenge_info)) = best_assignment {
                assignments.get_mut(member).expect("membro veio das chaves").push(json!({
                    "challenge": &challenge_info.challenge,
                    "score": challenge_info.score,
                    "estimated_time": challenge_info.estimated_time
                }));
                assigned_challenges.insert(challenge_info.challenge.clone());
            }
        }

        Value::Object(assignments.into_iter().map(|(member, items)| (member, Value::Array(items))).collect())
    }

    /// Identify challenges that would benefit from team collaboration
    pub fn _identify_collaboration_opportunities(&self, challenges: &[CTFChallenge], team_skills: &Value) -> Vec<Value> {
        let mut collaboration_opportunities: Vec<Value> = Vec::new();

        for challenge in challenges {
            if matches!(challenge.difficulty.as_str(), "hard" | "insane") {
                // High-difficulty challenges benefit from collaboration
                let mut relevant_members: Vec<String> = Vec::new();
                if let Some(team_skills) = team_skills.as_object() {
                    for (member, skills) in team_skills {
                        let skills: Vec<String> = skills
                            .as_array()
                            .map(|list| list.iter().filter_map(|skill| skill.as_str().map(str::to_lowercase)).collect())
                            .unwrap_or_default();

                        if skills.contains(&challenge.category) {
                            relevant_members.push(member.clone());
                        }
                    }
                }

                if relevant_members.len() >= 2 {
                    collaboration_opportunities.push(json!({
                        "challenge": &challenge.name,
                        "recommended_team": relevant_members,
                        "reason": format!("High-difficulty {} challenge benefits from collaboration", challenge.category)
                    }));
                }
            }
        }

        collaboration_opportunities
    }
}
