#!/bin/sh
# Orquestra o teste de paridade dentro do container de paridade.
set -eu

echo "== 1/5 manifesto (fonte: app.url_map do Python) =="
python3 /rs/migration/docker/parity/gen_manifest.py

echo "== 2/5 build do port Rust =="
cd /rs && cargo build --quiet

mkdir -p /work/pyrun /work/rsrun
rm -rf /work/dump   # sem isso, sobra dump de um filtro anterior

echo "== 3/5 sobe Python :8888 e Rust :8889 =="
( cd /work/pyrun && python3 /hs/hexstrike_server.py --port 8888 >/work/pyrun.log 2>&1 & )
( cd /work/rsrun && /cargo-target/debug/hexstrike-server --port 8889 >/work/rsrun.log 2>&1 & )

for port in 8888 8889; do
  i=0
  while [ $i -lt 90 ]; do
    curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1 && break
    i=$((i+1)); sleep 1
  done
  curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1 || { echo "porta $port não subiu"; tail -20 /work/*run.log; exit 1; }
  echo "  :$port up"
done

echo "== 4/6 dump das rotas nos dois lados =="
# /api/files/* grava em /tmp/hexstrike_files: sem limpar, o segundo dump herda o
# estado do primeiro. Tem de RECRIAR a pasta vazia, não só apagar: o
# FileOperationsManager do Python a cria no import do pacote, então apagá-la
# faz o Python responder "Directory does not exist" e o diff mente.
reset_files_dir() { rm -rf /tmp/hexstrike_files && mkdir -p /tmp/hexstrike_files; }
reset_files_dir
python3 /rs/migration/docker/parity/dump.py --base http://127.0.0.1:8888 --only "${ROUTES_FILTER:-}" --out /work/dump/py >/work/dump_py.log 2>&1 || true
reset_files_dir
python3 /rs/migration/docker/parity/dump.py --base http://127.0.0.1:8889 --only "${ROUTES_FILTER:-}" --out /work/dump/rs >/work/dump_rs.log 2>&1 || true

echo "== 5/6 diff rota a rota =="
python3 /rs/migration/docker/parity/compare.py /work/dump/py /work/dump/rs || RC=1

if [ "${E2E:-0}" = "1" ]; then
  echo "== 6/6 aceitacao pelo cliente MCP em Python =="
  python3 /rs/migration/docker/parity/e2e.py || RC=1
fi

exit ${RC:-0}
