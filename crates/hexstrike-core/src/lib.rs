//! `hexstrike_server/core.py` + `visual_engine.py` (camadas 0-1 do ranking).
//!
//! Sem dependência de nenhum outro crate do workspace: é isso que impede,
//! pelo compilador, que a camada 0 importe rotas.

pub mod core;
pub mod visual_engine;

// `core.py` expõe estes nomes na raiz do pacote (o `_registry.py` os atribui a
// `core`), então quem faz `crate::core::x` continua funcionando igual ao Python.
pub use core::{api_host, api_port, debug_mode, runtime, RuntimeConfig, API_HOST, API_PORT};
// CACHE_SIZE / CACHE_TTL / COMMAND_TIMEOUT vivem em `intelligence/vuln_intel.py`
// segundo o `_registry.py`, não em core.

