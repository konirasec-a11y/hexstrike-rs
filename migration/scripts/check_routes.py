"""Confere se o router Rust registra exatamente as (path, método) do Python.

O manifesto vem do próprio Flask (`app.url_map`), não de uma lista à mão —
se o split tem 156 rotas, o gate cobra 156. A varredura do lado Rust lê as
chamadas `.route("...", get(...)/post(...))` dos módulos.

Uso:
  python3 scripts/check_routes.py <caminho-do-pacote-python>
"""
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]  # scripts -> migration -> repo
# Depois do split: as rotas moram em `hexstrike-routes`, e as 11 rotas de
# `exploit_gen` moram em `hexstrike-intelligence` (como no Python).
SRC_ROUTES = ROOT / "crates/hexstrike-routes/src"
SRC_INTEL = ROOT / "crates/hexstrike-intelligence/src"
# Pacote Python do split (referência do porte). Argumento > HEXSTRIKE_PY > default.
DEFAULT_PY = ROOT / "migration/hexstrike-ai/hexstrike_server"
PY = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(
    os.environ.get("HEXSTRIKE_PY", DEFAULT_PY))
if not PY.is_dir():
    sys.exit(f"pacote Python não encontrado em {PY}\n"
             f"passe o caminho: python3 scripts/check_routes.py <hexstrike_server/> "
             f"ou defina HEXSTRIKE_PY")

METHODS = ("get", "post", "put", "delete", "patch")
# `<int:pid>` (Flask) e `:pid` (axum) são a mesma rota; normaliza para comparar.
CONVERTER = re.compile(r"<(?:\w+:)?(\w+)>")
AXUM_PARAM = re.compile(r"\{(\w+)\}")


def norm(path):
    """`<int:pid>` (Flask) e `{pid}` (axum) viram `:pid` — mesma rota."""
    path = CONVERTER.sub(lambda m: ":" + m.group(1), path)
    return AXUM_PARAM.sub(lambda m: ":" + m.group(1), path)


PY_ROUTE = re.compile(r"@app\.route\(\s*[\"']([^\"']+)[\"']\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?\)")


def python_routes():
    out = set()
    for f in sorted(PY.rglob("*.py")):
        text = f.read_text()
        for m in PY_ROUTE.finditer(text):
            path = m.group(1)
            methods = re.findall(r"[\"'](\w+)[\"']", m.group(2) or "") or ["GET"]
            for meth in methods:
                out.add((norm(path), meth.upper()))
    return out


def rust_routes():
    out = set()
    arquivos = sorted(SRC_ROUTES.rglob("*.rs")) + [SRC_INTEL / "exploit_gen.rs"]
    for f in arquivos:
        text = f.read_text()
        i = 0
        while True:
            i = text.find(".route(", i)
            if i < 0:
                break
            j = text.find('"', i)
            k = text.find('"', j + 1)
            path = text[j + 1:k]
            # varre até o parêntese que fecha o .route(
            depth, p = 1, i + len(".route(")
            while p < len(text) and depth:
                if text[p] == "(":
                    depth += 1
                elif text[p] == ")":
                    depth -= 1
                p += 1
            tail = text[k + 1:p]
            for meth in METHODS:
                if re.search(rf"\b{meth}!\(", tail) or re.search(rf"\b{meth}\(", tail):
                    out.add((norm(path), meth.upper()))
            i = p
    return out


def main():
    py, rs = python_routes(), rust_routes()
    missing, extra = sorted(py - rs), sorted(rs - py)
    print(f"Python: {len(py)} pares (path, método)")
    print(f"Rust:   {len(rs)} pares (path, método)")
    print(f"cobertura: {len(py & rs)}/{len(py)}")
    if missing:
        print(f"\nFALTANDO ({len(missing)}):")
        for path, meth in missing:
            print(f"  {meth:6} {path}")
    if extra:
        print(f"\nINVENTADAS ({len(extra)}):")
        for path, meth in extra:
            print(f"  {meth:6} {path}")
    return 0 if not missing and not extra else 1


if __name__ == "__main__":
    sys.exit(main())
