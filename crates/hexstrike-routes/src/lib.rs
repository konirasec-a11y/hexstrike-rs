//! `hexstrike_server/routes/` (camada 9) + a montagem do `app`.
//!
//! É a ÚNICA camada que pode depender de `hexstrike-intelligence`.

pub mod process_mgmt;
pub mod decision_engine;
pub mod bugbounty;
pub mod security_tools;
pub mod cloud_security;
pub mod cloud_enhanced;
pub mod network_pentest;
pub mod binary_analysis;
pub mod binary_enhanced;
pub mod web_security;
pub mod web_enhanced;
pub mod http_testing;
pub mod payloads;
pub mod api_testing;
pub mod ctf_tools;
pub mod bugbounty_recon;
pub mod vuln_intel;
pub mod ctf_framework;
pub mod process_mgmt_v10;
pub mod error_handling;

use axum::Router;

/// As 156 rotas, montadas na ordem do `__init__.py` do split.
pub fn build_router() -> Router {
    let mut app = Router::new();
    app = app.merge(hexstrike_intelligence::exploit_gen::routes());
    app = app.merge(process_mgmt::routes());
    app = app.merge(decision_engine::routes());
    app = app.merge(bugbounty::routes());
    app = app.merge(security_tools::routes());
    app = app.merge(cloud_security::routes());
    app = app.merge(cloud_enhanced::routes());
    app = app.merge(network_pentest::routes());
    app = app.merge(binary_analysis::routes());
    app = app.merge(binary_enhanced::routes());
    app = app.merge(web_security::routes());
    app = app.merge(web_enhanced::routes());
    app = app.merge(http_testing::routes());
    app = app.merge(payloads::routes());
    app = app.merge(api_testing::routes());
    app = app.merge(ctf_tools::routes());
    app = app.merge(bugbounty_recon::routes());
    app = app.merge(vuln_intel::routes());
    app = app.merge(ctf_framework::routes());
    app = app.merge(process_mgmt_v10::routes());
    app = app.merge(error_handling::routes());
    app
}
