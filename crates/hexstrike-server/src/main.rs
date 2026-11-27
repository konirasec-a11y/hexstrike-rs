//! Port 1:1 de `hexstrike_server/main.py` (o `if __name__ == "__main__"` do
//! monólito virou `main()` no split).
//!
//! CLI (`--debug`, `--port`), banner, box de startup e `app.run(...)`.

use clap::Parser;
use tracing::info;

use hexstrike_core::core::{self, api_port, debug_mode, runtime, API_PORT};
use hexstrike_intelligence::vuln_intel::{CACHE_SIZE, CACHE_TTL, COMMAND_TIMEOUT};
use hexstrike_core::visual_engine::{color, ModernVisualEngine};

/// CLI 1:1 do `main.py`: `--debug` e `--port` (default `API_PORT`).
#[derive(Parser, Debug)]
#[command(name = "hexstrike-server", about = "Run the HexStrike AI API Server")]
struct Args {
    /// Enable debug mode (`parser.add_argument("--debug", action="store_true")`)
    #[arg(long)]
    debug: bool,

    /// Port for the API server (default: 8888)
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // "MUST BE FIRST" — logging config antes de tudo (core.py)
    core::init();

    let args = Args::parse();

    // main.py: if args.debug: set_global('DEBUG_MODE', True)
    if args.debug {
        runtime().set_debug_mode(true);
        info!("Debug mode enabled");
    }

    // main.py: if args.port != API_PORT: set_global('API_PORT', args.port)
    if let Some(port) = args.port {
        if port != *API_PORT {
            runtime().set_api_port(port);
        }
    }

    // print(BANNER)
    println!("{}", ModernVisualEngine::create_banner());

    let port = api_port();
    let debug = debug_mode();
    let (mg, bold, reset) = (color("MATRIX_GREEN"), color("BOLD"), color("RESET"));
    let (neon_blue, cyber_orange, warning, gray, purple) = (
        color("NEON_BLUE"), color("CYBER_ORANGE"), color("WARNING"),
        color("TERMINAL_GRAY"), color("ELECTRIC_PURPLE"),
    );
    let startup_info = format!(
        "
{mg}{bold}╭─────────────────────────────────────────────────────────────────────────────╮{reset}
{bold}│{reset} {neon_blue}🚀 Starting HexStrike AI Tools API Server{reset}
{bold}├─────────────────────────────────────────────────────────────────────────────┤{reset}
{bold}│{reset} {cyber_orange}🌐 Port:{reset} {port}
{bold}│{reset} {warning}🔧 Debug Mode:{reset} {debug}
{bold}│{reset} {warning}💾 Cache Size:{reset} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{bold}│{reset} {gray}⏱️  Command Timeout:{reset} {COMMAND_TIMEOUT}s
{bold}│{reset} {purple}✨ Enhanced Visual Engine:{reset} Active
{mg}{bold}╰─────────────────────────────────────────────────────────────────────────────╯{reset}",
    );
    for line in startup_info.trim().split('\n') {
        if !line.trim().is_empty() {
            info!("{line}");
        }
    }

    // app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    info!("Servidor ouvindo em http://0.0.0.0:{port}");
    axum::serve(listener, hexstrike_routes::build_router()).await?;

    Ok(())
}
