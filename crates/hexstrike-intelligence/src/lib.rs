//! `hexstrike_server/intelligence/` (camadas 2-17 do ranking).
//!
//! Depende só de `hexstrike-core`. As rotas NÃO entram aqui: se uma camada
//! de inteligência precisasse de uma rota, o compilador recusaria — é o
//! ranking virando regra.

pub mod _state;
pub mod decision_engine;
pub mod error_recovery;
pub mod bugbounty;
pub mod ctf;
pub mod ctf_automation;
pub mod param_optimizer;
pub mod process_manager;
pub mod process_termination;
pub mod vuln_intel;
pub mod exploit_gen;
