"""Gera o manifesto das rotas a partir do app.url_map do PYTHON.

A fonte da verdade é o próprio Flask: se o split tiver 156 rotas, o manifesto
tem 156 entradas e o harness não pode "esquecer" rota nenhuma.
"""
import json
import sys

import hexstrike_server as hs

routes = [r for r in hs.app.url_map.iter_rules() if r.endpoint != "static"]
out = []
for r in sorted(routes, key=lambda x: str(x)):
    methods = sorted(m for m in r.methods if m in ("GET", "POST", "PUT", "DELETE"))
    out.append({"rule": str(r), "methods": methods})

json.dump(out, open("/work/routes.json", "w"), indent=1)
print(f"manifest: {len(out)} rotas")
sys.exit(0)
