//! Equivalente de `hexstrike_server/_state.py`: os globais do monólito.
//!
//! No Python são singletons de módulo (`cache = HexStrikeCache()`,
//! `telemetry = TelemetryCollector()`), reatribuídos por
//! `_state.set_global(...)`. Aqui são `static` com o MESMO nome, para que o
//! corpo das rotas continue lendo `cache` / `telemetry` sem injeção.

use std::sync::{LazyLock, Mutex};

use crate::vuln_intel::{
    HexStrikeCache, TelemetryCollector, CACHE_SIZE, CACHE_TTL,
};

#[allow(non_upper_case_globals)]
pub static cache: LazyLock<Mutex<HexStrikeCache>> =
    LazyLock::new(|| Mutex::new(HexStrikeCache::new(CACHE_SIZE, CACHE_TTL)));

#[allow(non_upper_case_globals)]
pub static telemetry: LazyLock<Mutex<TelemetryCollector>> =
    LazyLock::new(|| Mutex::new(TelemetryCollector::new()));
