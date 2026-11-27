"""Diff de paridade entre dois dumps (Python vs Rust).

Regras, todas deliberadas:
- ORDEM das chaves tem que ser idêntica (o Flask usa JSON_SORT_KEYS=False e o
  port usa serde_json preserve_order; ordem diferente = resposta diferente).
- Chaves voláteis (VOLATILE) comparam só presença e tipo, não valor.
- Rotas que não existem no Rust são MISSING, nunca "ignoradas".
Saída: OK / DIFF / MISSING por rota + resumo; exit 1 se qualquer rota não bater.
"""
import json
import os
import re
import sys

# Chaves que o Python devolve a partir de `set` (=> ordem muda a cada processo,
# por hash randomization). Comparar como conjunto é o único 1:1 possível:
# ordem insensível, conteúdo cobrado.
SET_LIKE = {"critical_operations"}

# Listas cujo TAMANHO depende de resposta viva do NVD (uma chamada por CVE, e
# algumas falham entre os dois dumps). Compara tipo e forma dos elementos, não
# a contagem — o resto da resposta continua cobrado chave a chave.
SHAPE_ONLY = {"exploitability_analysis"}

# `payload_<epoch>` no nome do arquivo: o epoch muda entre os dois dumps, então
# o caminho é comparado com o sufixo mascarado (o resto do path continua cobrado).
TIMESTAMPED = re.compile(r"(payload_)\d+")


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


def walk(py, rs, path, diffs):
    if type(py) is not type(rs):
        diffs.append(f"{path}: tipo {type(py).__name__} != {type(rs).__name__}")
        return
    if isinstance(py, dict):
        pk, rk = list(py), list(rs)
        if pk != rk:
            only_py = [k for k in pk if k not in rs]
            only_rs = [k for k in rk if k not in py]
            diffs.append(
                f"{path}: ordem/chaves diferem\n    py={pk}\n    rs={rk}"
                + (f"\n    só py={only_py}" if only_py else "")
                + (f"\n    só rs={only_rs}" if only_rs else "")
            )
            return
        for k in pk:
            if k in VOLATILE:
                continue
            if k in SHAPE_ONLY:
                if isinstance(py[k], list) != isinstance(rs[k], list) or type(py[k]) is not type(rs[k]):
                    diffs.append(f"{path}.{k}: tipo difere")
                continue
            if k in SET_LIKE and isinstance(py[k], list) and isinstance(rs[k], list):
                if sorted(map(str, py[k])) != sorted(map(str, rs[k])):
                    diffs.append(f"{path}.{k}: conjunto difere\n    py={sorted(py[k])}\n    rs={sorted(rs[k])}")
                continue
            walk(py[k], rs[k], f"{path}.{k}", diffs)
    elif isinstance(py, list):
        if len(py) != len(rs):
            diffs.append(f"{path}: len {len(py)} != {len(rs)}")
            return
        for i, (a, b) in enumerate(zip(py, rs)):
            walk(a, b, f"{path}[{i}]", diffs)
    elif isinstance(py, float) or isinstance(rs, float):
        try:
            if abs(float(py) - float(rs)) > 1e-6:
                diffs.append(f"{path}: {py!r} != {rs!r}")
        except (TypeError, ValueError):
            diffs.append(f"{path}: {py!r} != {rs!r}")
    elif isinstance(py, str) and isinstance(rs, str) and TIMESTAMPED.search(py):
        if TIMESTAMPED.sub(r"\1<ts>", py) != TIMESTAMPED.sub(r"\1<ts>", rs):
            diffs.append(f"{path}: {py!r} != {rs!r}")
    elif py != rs:
        diffs.append(f"{path}: {py!r} != {rs!r}")


def main():
    if len(sys.argv) != 3:
        print("uso: compare.py <dump_py> <dump_rs>")
        return 2
    dpy, drs = sys.argv[1], sys.argv[2]
    ok = diff = missing = 0
    manifest = json.load(open("/work/routes.json")) if os.path.exists("/work/routes.json") else []
    for name in sorted(os.listdir(dpy)):
        a = json.load(open(os.path.join(dpy, name)))
        route = a["route"]
        rs_path = os.path.join(drs, name)
        if not os.path.exists(rs_path):
            print(f"MISSING  {route['rule']}")
            missing += 1
            continue
        b = json.load(open(rs_path))
        if b["status"] == 404 and a["status"] != 404:
            print(f"MISSING  {route['rule']} (rota ainda não portada)")
            missing += 1
            continue
        if b["status"] is None:
            print(f"MISSING  {route['rule']} (rust não respondeu: {b['error']})")
            missing += 1
            continue
        diffs = []
        if a["status"] != b["status"]:
            diffs.append(f"http: {a['status']} != {b['status']}")
        walk(a["body"], b["body"], "$", diffs)
        if diffs:
            print(f"DIFF     {route['rule']}")
            for d in diffs[:6]:
                print(f"    {d}")
            diff += 1
        else:
            print(f"OK       {route['rule']}")
            ok += 1
    not_run = len(manifest) - (ok + diff + missing)
    total = ok + diff + missing
    print(f"\nparity: {ok}/{total} rotas executadas OK | {diff} DIFF | {missing} MISSING")
    if not_run:
        print(f"NAO EXECUTADAS: {not_run}/{len(manifest)} rotas (filtro --only ativo)")
    if missing:
        print("MISSING = rota existe no Python e não respondeu no Rust")
    return 0 if diff == 0 and missing == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
