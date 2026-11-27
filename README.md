# HexStrike-RS

Servidor de pentest com API HTTP, em Rust. É o porte do
[HexStrike AI](https://github.com/0x4m4/hexstrike-ai) v6.0: a mesma API, as
mesmas respostas, o mesmo comportamento observável — em um binário único.

## O que ele faz

Recebe JSON, monta o comando da ferramenta certa, executa, e devolve o
resultado. Em cima disso há uma camada de decisão (qual ferramenta usar e com
quais parâmetros, a partir do alvo), inteligência de CVE, workflows de bug
bounty e CTF, gerenciamento de processos e relatórios visuais.

São **156 rotas HTTP** que orquestram as ferramentas de segurança que já
existem na sua máquina:

| rotas | família |
|---|---|
| 90 | `/api/tools/<ferramenta>` — nmap, gobuster, sqlmap, nuclei, ffuf, radare2, ghidra, … |
| 17 | `/api/process*` — processos em execução, fila, pool, dashboard |
| 7 | `/api/ctf/*` — workflows, automação, sugestão de ferramentas |
| 7 | `/api/error-handling/*` — classificação de erro, estratégias de recuperação |
| 6 | `/api/bugbounty/*` — recon, caça de vulnerabilidade, OSINT |
| 6 | `/api/intelligence/*` — análise de alvo, seleção de ferramentas, cadeia de ataque |
| 5 | `/api/vuln-intel/*` — monitor de CVE, threat feeds, geração de exploit |
| 4 | `/api/files/*` — criar, modificar, apagar, listar |
| 3 | `/api/cache/stats`, `/api/cache/clear`, `/api/telemetry` |
| 3 | `/api/ai/*` — payload e teste de payload |
| 3 | `/api/visual/*` — card, resumo e saída formatada |
| 2 | `/api/python/*` — venv e execução de script |
| 1 | `/health` |

**Ele não embarca as ferramentas.** O servidor as invoca pelo `PATH`; se o
binário não existe, a rota responde com o erro do shell e o `/health` reporta
`false` para aquela ferramenta. É o mesmo modelo do projeto original.

## O que é cada pasta

```
crates/       o servidor (é o que você compila)
docs/         documentação de arquitetura
migration/    referência em Python e harness de paridade — não é usado pelo servidor
vendor/       cópia intocada do projeto original, para comparação
```

Se você só quer rodar o servidor, ignore `migration/` e `vendor/`.

## Requisitos

- Linux
- Rust 1.85 ou mais novo (edition 2024)
- As ferramentas que você pretende usar, instaladas e no `PATH`

## Compilar e rodar

```bash
cargo build --release
./target/release/hexstrike-server --port 8888
```

| opção | efeito |
|---|---|
| `--port <n>` | porta (default `8888`, ou `HEXSTRIKE_PORT`) |
| `--debug` | modo debug |
| `HEXSTRIKE_PORT` / `HEXSTRIKE_HOST` | variáveis de ambiente lidas na inicialização |

O servidor escuta em `0.0.0.0`. Confira o que está disponível:

```bash
curl http://127.0.0.1:8888/health
```

A resposta traz `tools_status` (as 127 ferramentas reconhecidas, uma por uma),
`total_tools_available`, `category_stats`, `cache_stats` e `telemetry`.

## Usar a API

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","scan_type":"-sT","ports":"22,80"}'
```

```json
{"stdout": "Starting Nmap 7.993 …\n22/tcp closed ssh\n80/tcp open  http\n",
 "stderr": "", "return_code": 0, "success": true, "timed_out": false,
 "partial_results": false, "execution_time": 0.0848,
 "timestamp": "2026-11-26T16:59:18.305580"}
```

Todo resultado de execução tem exatamente essas 8 chaves. As rotas que usam
recuperação (`use_recovery`, default `true`) acrescentam `recovery_info` com as
tentativas feitas.

Corpo inválido ou parâmetro obrigatório faltando responde `400` com
`{"error": "..."}` — nunca executa nada.

## Cliente MCP

O cliente MCP é o do projeto original, em Python, **sem modificação**: ele fala
com este servidor por HTTP. Use-o para expor as 151 tools para um agente:

```bash
python hexstrike_mcp.py --server http://127.0.0.1:8888
```

## Como os comandos são executados

`sh -c "<comando>"`, com as mesmas mensagens de log do original:

- **cache** com chave `md5(comando)`: só resultados com sucesso entram; 1000
  entradas, TTL de 3600 s. Repetir a mesma chamada devolve o mesmo resultado,
  inclusive o mesmo `timestamp`.
- **timeout** de 300 s: `SIGTERM`, espera 5 s, `SIGKILL`.
- saída **parcial** em timeout conta como sucesso, como no original.
- `stdout` e `stderr` são lidos em paralelo e logados linha a linha
  (`📤 STDOUT:` / `📥 STDERR:`).
- cada processo aparece em `/api/processes/list` enquanto roda.

O log segue o formato do Python:
`2026-11-26 18:11:29,871 - hexstrike_intelligence::vuln_intel - INFO - 🚀 EXECUTING: …`

## Arquitetura

Quatro crates, um por camada de dependência. A seta só aponta para baixo, então
é o compilador — não a disciplina — que impede uma camada de baixo de importar
uma de cima:

```
crates/hexstrike-core/           core e visual_engine          (sem dependências)
crates/hexstrike-intelligence/   intelligence/ e os globais    (-> core)
crates/hexstrike-routes/         as rotas e a montagem do app  (-> core, intelligence)
crates/hexstrike-server/         binário                       (-> todos)
```

Cada arquivo tem o nome do módulo Python correspondente. O estudo de
acoplamento que definiu essa divisão está em
[`docs/acoplamento-do-original.md`](docs/acoplamento-do-original.md).

## Paridade com o original

O comportamento foi verificado rota a rota, não declarado: um harness em Docker
sobe o servidor Python original e este, no **mesmo container** (mesmo `PATH`,
porque o `/health` testa ferramenta com `which`), dispara as 156 rotas nos dois
e compara o JSON — chave, ordem e valor.

```bash
cd migration
docker compose run --rm parity              # 156 rotas
docker compose run --rm -e E2E=1 parity     # + aceitação pelo cliente MCP
```

Saída por rota: `OK`, `DIFF` (com o caminho JSON da divergência) ou `MISSING`.
Código de saída 1 se algo não bater. Hoje: **156/156 OK, 0 DIFF, 0 MISSING**, e
7/7 na aceitação pelo cliente MCP em Python.

Diferenças conhecidas, todas de transporte:

- a *reason phrase* HTTP vem na forma canônica (`Bad Request`) onde o Werkzeug
  responde em caixa alta (`BAD REQUEST`); o corpo é idêntico;
- `/api/vuln-intel/cve-monitor` consulta o NVD ao vivo, então a quantidade de
  análises varia entre duas chamadas;
- `repr` de dicionário nos logs sai com chave alfabética.

## Licença

MIT, derivada do projeto original — ver [LICENSE](LICENSE).
