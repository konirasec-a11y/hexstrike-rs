> Documento de referência sobre o **projeto original em Python**, não sobre este
> fork. Ele mede o grafo de dependências de `hexstrike_server/` e é o que
> justifica a divisão em 4 crates: `hexstrike-core` (camadas 0-1),
> `hexstrike-intelligence` (2-17), `hexstrike-routes` (9) e o binário. Leia-o se
> quiser entender por que um módulo mora no crate onde mora.

# Ranking de Importância por Acoplamento — hexstrike_server (pós-split)

Método: grafo dirigido de dependências medido no código real (uso de símbolos
via `_registry.HOME`, contando apenas chamada `nome(` e acesso `nome.` — o que
exclui falsos positivos de strings de comando tipo "sqlmap -u x").
**fan-in** = nº de módulos que dependem dele (dependentes).
**w.in** = peso total de usos dos símbolos dele por outros módulos.

## Ranking (ordem de importância = centralidade)

| # | Módulo | fan-in | w.in | O que fornece (símbolo → usos) | Quem consome (principais) |
|---|--------|--------|------|----------------------------------|---------------------------|
| 1 | `core` | **28/32** | **813** | `logger` (629), `app` (156) | TODOS — cloud_enhanced(116), web_enhanced(66), http_testing(62), network_pentest(57), vuln_intel(51) |
| 2 | `visual_engine` | 6 | 226 | `ModernVisualEngine` (220) | vuln_intel(180), http_testing(30), process_mgmt(6) |
| 3 | `intelligence.exploit_gen` | **17** | 142 | **`execute_command` (108)**, `cve_intelligence` (6), `execute_command_with_recovery` (4), `file_manager` (2) | cloud_enhanced(25), decision_engine(17), web_enhanced(14), network_pentest(12), http_testing(10), vuln_intel(10) |
| 4 | `intelligence.process_manager` | 5 | 41 | `enhanced_process_manager` (22), `ctf_tools` (6), `ctf_manager` (2) | process_mgmt_v10(23), ctf_framework(7), param_optimizer(5) |
| 5 | `intelligence.error_recovery` | 2 | 36 | `error_handler` (19), `RecoveryAction` (7), `degradation_manager` (5) | exploit_gen(22), routes.error_handling(14) |
| 6 | `intelligence.vuln_intel` | 3 | 20 | `cache` (15), `telemetry` (3) | exploit_gen(12), process_manager(5), process_mgmt_v10(3) |
| 7 | `intelligence.bugbounty` | 1 | 16 | `bugbounty_manager` (8), `BugBountyTarget` (5) | routes.bugbounty(16) |
| 8 | `intelligence.decision_engine` | 1 | 15 | `decision_engine` (11), `TechnologyStack` (3) | routes.decision_engine(15) |
| 9 | `intelligence.process_termination` | 3 | 13 | `ProcessManager` (9), `env_manager` (2) | process_mgmt(7), http_testing(3), vuln_intel(3) |
| 10 | `routes.decision_engine` | 3 | 7 | `analyze_target` (3), `detect_technologies` (2) | intelligence.decision_engine(3), param_optimizer(2), exploit_gen(2) |
| 11 | `intelligence.ctf` | 2 | 6 | `ctf_manager`, `ctf_tools` | ctf_automation, process_manager |
| 12 | `routes.process_mgmt` | 2 | 6 | `format_tool_output` etc. | process_termination(7), vuln_intel(3) |
| 13 | `intelligence.param_optimizer` | 1 | 5 | `parameter_optimizer` | process_manager |
| 14 | `routes.ctf_framework` | 2 | 4 | — | ctf_tools, process_termination |
| 15–20 | ctf_automation, process_mgmt_v10, http_testing, payloads, error_handling | 1 | 1–2 | (pouco consumidos) | — |
| 21–32 | **21 módulos `routes/*`** | **0** | 0 | tool functions (só via HTTP) | **ninguém** — folhas do grafo |

## Camadas topológicas (ordem de construção)

- **Camada 0**: `core` (43 LOC, zero deps, 28 dependentes)
- **Camada 1**: `visual_engine`
- **Camadas 2–8**: cadeia `intelligence/*` (bugbounty → ctf → ctf_automation → decision_engine → error_recovery → **exploit_gen**)
- **Camada 9**: 14 módulos `routes/*` de uma vez (desbloqueados por exploit_gen)
- **Camadas 10–17**: process_manager → ctf_framework → process_termination → process_mgmt + http_testing → vuln_intel → process_mgmt_v10

## Curva de desbloqueio (portando na ordem do ranking)

1. `core` → 6,2% | 2. `+visual_engine` → 6,2% | 3. `+exploit_gen` → **46,9%** (12 módulos desbloqueiam de uma vez)
4. `+process_manager` → 50% | 5. `+error_recovery` → 56,2% | 6. `+vuln_intel` → 62,5% | 7. `+bugbounty` → 68,8% | 8. `+decision_engine` → 75% | 9. `+process_termination` → 84,4% | ~12 → 93,8% | 32/32 → 100%

## Ciclos detectados (o monolito tinha referências para frente; o `_registry` resolve com lazy-stitching)

- `intelligence.bugbounty` ↔ `routes.bugbounty` (mútuo)
- `intelligence.process_manager` → `routes.process_mgmt_v10` (para frente)
- `intelligence.vuln_intel` → `routes.process_mgmt`; `intelligence.process_termination` → `routes.process_mgmt`
- `intelligence.exploit_gen` → `routes.decision_engine`; `intelligence.decision_engine` ↔ `routes.decision_engine`

Em Rust esses ciclos precisam ser quebrados (inversão via trait ou movendo a função para o lado intelligence).

## hexstrike_mcp (topologia estrela, medida por imports)

`config` (base) → `client` (HTTP; 14 dependentes: main + 13 tools) + `mcp_instance` (14 dependentes) → 13 arquivos `tools/*` (folhas). O `client` acopla-se ao server pela superfície HTTP externa: `/health` + as 156 rotas.
