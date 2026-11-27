"""Aceitação ponta a ponta: o cliente MCP em Python falando com o port Rust.

O diff rota-a-rota (`compare.py`) olha o JSON cru. Este teste usa o
`HexStrikeClient` de `hexstrike_mcp/client.py` — o consumidor real — e portanto
cobre o que o JSON cru não cobre: `raise_for_status`, `.json()`, o fallback
`{"error": ..., "success": False}` e a semântica das rotas que as tools usam.

`hexstrike_mcp/__init__.py` importa `server` (fastmcp), que não faz parte do
alvo; o pacote é registrado sem executar o `__init__` para carregar só
`config` + `client`.
"""
import json
import re
import sys
import types

sys.path.insert(0, "/hs")
sys.path.insert(0, "/rs/docker/parity")

_pkg = types.ModuleType("hexstrike_mcp")
_pkg.__path__ = ["/hs/hexstrike_mcp"]
sys.modules["hexstrike_mcp"] = _pkg

from hexstrike_mcp.client import HexStrikeClient  # noqa: E402

from compare import walk  # noqa: E402

REASON = re.compile(r"(Client|Server) Error: ([A-Za-z ]+) for url")


HOST_PORT = re.compile(r"https?://127\.0\.0\.1:\d+")


def reason_case(value):
    """Normaliza só o que é transporte: a caixa da reason-phrase e a porta do
    servidor (os dois lados rodam em portas diferentes, e o `requests` embute a
    URL na mensagem de erro)."""
    if isinstance(value, str):
        value = HOST_PORT.sub("http://SERVER", value)
        return REASON.sub(lambda m: f"{m.group(1)} Error: {m.group(2).upper()} for url", value)
    if isinstance(value, dict):
        return {k: reason_case(v) for k, v in value.items()}
    if isinstance(value, list):
        return [reason_case(v) for v in value]
    return value

# Casos que as tools do MCP realmente exercitam (cliente -> rota -> resposta).
CASES = [
    ("check_health", lambda c: c.check_health()),
    ("safe_get cache/stats", lambda c: c.safe_get("api/cache/stats")),
    ("safe_get telemetry", lambda c: c.safe_get("api/telemetry")),
    ("execute_command", lambda c: c.execute_command("echo hexstrike-e2e")),
    (
        "safe_post analyze-target",
        lambda c: c.safe_post(
            "api/intelligence/analyze-target",
            {"target": "http://example.com", "objective": "quick"},
        ),
    ),
    (
        "safe_post suggest-tools",
        lambda c: c.safe_post(
            "api/ctf/suggest-tools", {"challenge": "forensics", "difficulty": "easy"}
        ),
    ),
    (
        "safe_post processes/list",
        lambda c: c.safe_post("api/processes/list", {}),
    ),
]


def run(base):
    client = HexStrikeClient(base)
    out = {}
    for name, call in CASES:
        try:
            out[name] = call(client)
        except Exception as e:  # o cliente já devolve dict de erro; isto é o resto
            out[name] = {"__exception__": f"{type(e).__name__}: {e}"}
    return out


def main():
    py = run("http://127.0.0.1:8888")
    rs = run("http://127.0.0.1:8889")
    ok = bad = 0
    for name, _ in CASES:
        a, b = py[name], rs[name]
        diffs = []
        walk(a, b, "$", diffs)
        if diffs and reason_case(a) == reason_case(b):
            ok += 1
            print(f"KNOWN E2E {name} (so a caixa da reason-phrase HTTP difere)")
            continue
        if diffs:
            bad += 1
            print(f"DIFF E2E {name}")
            for d in diffs[:4]:
                print(f"    {d}")
        else:
            ok += 1
            print(f"OK   E2E {name}")
    print(f"\naceitacao pelo cliente Python: {ok}/{ok + bad} casos OK | {bad} DIFF")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
