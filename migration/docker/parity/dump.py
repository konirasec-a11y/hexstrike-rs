"""Dispara todas as rotas do manifesto contra um servidor e grava o JSON cru.

Uso: dump.py --base http://127.0.0.1:8888 --out /work/dump/py
"""
import argparse
import json
import os
import re
import urllib.error
import urllib.request

# Conversores de rota do Flask (`<int:pid>`, `<task_id>`) não são URL válida:
# o hyper recusa `<`/`>` com 400, enquanto o Flask devolve 404. Para exercitar
# a rota de verdade, o path vira um valor concreto (int -> 1, resto -> x).
CONVERTER = re.compile(r"<[^>]+>")


def concrete(rule):
    def repl(m):
        seg = m.group(0)
        return "1" if seg in ("<int>",) or seg.startswith("<int:") else "x"
    return CONVERTER.sub(repl, rule)


VOLATILE = {
    "uptime", "timestamp", "start_time", "execution_time", "duration",
    "duration_ms", "elapsed", "hits", "misses", "hit_count", "miss_count",
    "cpu_percent", "memory_percent", "pid", "threads", "last_updated",
    "disk_usage", "uptime_seconds", "bytes_sent", "bytes_recv",
    "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout",
    "load_average", "memory_used_mb",
    # relógios e amostras vivas medidas pelos shards W3 e W5
    "search_period", "analysis_timestamp", "memory_available_gb",
    "network_bytes_sent", "network_bytes_recv", "disk_free_gb",
    "disk_percent", "active_connections", "cpu_avg_10", "memory_avg_10",
    "measurements", "total", "available",
    "ip_addresses",
}


def call(base, route):
    rule, methods = route["rule"], route["methods"]
    method = "GET" if "GET" in methods else methods[0]
    url = base + concrete(rule)
    body = None if method == "GET" else b"{}"
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except Exception as e:  # timeout / conexão recusada
        return {"status": None, "error": type(e).__name__, "body": None}
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = raw.decode("utf-8", "replace")[:4000]
    return {"status": status, "body": parsed}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", default="/work/routes.json")
    # Filtro de subcaminho: permite um smoke test curto em vez de disparar as
    # 156 rotas (várias das quais executam ferramentas reais e podem segurar
    # a resposta até o próprio timeout).
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    routes = json.load(open(args.manifest))
    if args.only:
        routes = [r for r in routes if args.only in r["rule"]]
    for i, route in enumerate(routes):
        result = call(args.base, route)
        name = f"{i:03d}.json"
        json.dump({"route": route, **result}, open(os.path.join(args.out, name), "w"), indent=1)
        print(f"{route['rule']:<55} {route['methods']} -> {result['status']}")
    print(f"dump: {len(routes)} rotas em {args.out}")


if __name__ == "__main__":
    main()
