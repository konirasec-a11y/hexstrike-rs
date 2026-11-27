# migration/

Tudo que existe para **produzir e verificar** o porte. Nada aqui é usado pelo
servidor em execução: quem só quer usar o HexStrike-RS não precisa desta pasta.

```
migration/
  hexstrike-ai/          referência em Python: o split 1:1 auditado do original
  docker-compose.yml     harness de paridade (Python original x porte)
  docker/parity/         Dockerfile e os scripts do harness
  scripts/               check_routes.py — cobra as 156 rotas (path, método)
  work/                  saída das execuções (ignorada pelo git)
```

## Referência em Python

`hexstrike-ai/` é o projeto original reorganizado em pacotes, preservando cada
arquivo e símbolo (`hexstrike_server/` com 32 módulos, `hexstrike_mcp/` com 16).
Cada arquivo Rust tem o módulo Python correspondente; é essa correspondência
que tornou o porte auditável arquivo a arquivo.

O original intocado está em `../vendor/hexstrike-ai/`.

## Harness de paridade

Sobe os dois servidores no mesmo container e compara o JSON das 156 rotas:

```bash
cd migration
docker compose run --rm parity            # 156 rotas
docker compose run --rm -e E2E=1 parity   # + aceitação pelo cliente MCP
docker compose run --rm -e ROUTES_FILTER=/health parity   # uma rota só
```

O manifesto é gerado do próprio `app.url_map` do Python — o harness não tem
lista de rotas escrita à mão, então não dá para ele "esquecer" uma rota.
Saída por rota: `OK`, `DIFF` (com o caminho JSON da divergência) ou `MISSING`.
Código de saída 1 se algo não bater.

`HEXSTRIKE_PY` troca o pacote Python usado como referência.

## check_routes.py

Confere a cobertura sem subir nada:

```bash
python3 scripts/check_routes.py        # usa migration/hexstrike-ai/
```

Compara os pares `(path, método)` do `app.url_map` do Python com as chamadas
`.route(...)` do Rust, normalizando `<int:pid>` (Flask) e `{pid}` (axum). Falha
se faltar rota, se sobrar rota inventada, ou se o caminho do pacote Python não
existir.
