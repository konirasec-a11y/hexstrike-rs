//! Port 1:1 de `hexstrike_server/visual_engine.py` (`ModernVisualEngine`).

//! Port 1:1 de `visual_engine.py` (linhas 101-440 do monólito) —
//! `ModernVisualEngine`: paleta ANSI, estilos de progresso e os 11 métodos
//! estáticos de formatação. Strings de saída byte-a-byte equivalentes.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Map;

use crate::core::{api_host, api_port};

/// `ModernVisualEngine.COLORS` — paleta ANSI completa (todas as 47 chaves).
pub static COLORS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("MATRIX_GREEN", "\x1b[38;5;46m"),
        ("NEON_BLUE", "\x1b[38;5;51m"),
        ("ELECTRIC_PURPLE", "\x1b[38;5;129m"),
        ("CYBER_ORANGE", "\x1b[38;5;208m"),
        ("HACKER_RED", "\x1b[38;5;196m"),
        ("TERMINAL_GRAY", "\x1b[38;5;240m"),
        ("BRIGHT_WHITE", "\x1b[97m"),
        ("RESET", "\x1b[0m"),
        ("BOLD", "\x1b[1m"),
        ("DIM", "\x1b[2m"),
        // New reddish tones and highlighting colors
        ("BLOOD_RED", "\x1b[38;5;124m"),
        ("CRIMSON", "\x1b[38;5;160m"),
        ("DARK_RED", "\x1b[38;5;88m"),
        ("FIRE_RED", "\x1b[38;5;202m"),
        ("ROSE_RED", "\x1b[38;5;167m"),
        ("BURGUNDY", "\x1b[38;5;52m"),
        ("SCARLET", "\x1b[38;5;197m"),
        ("RUBY", "\x1b[38;5;161m"),
        // Unified theme primary/secondary
        ("PRIMARY_BORDER", "\x1b[38;5;160m"), // CRIMSON
        ("ACCENT_LINE", "\x1b[38;5;196m"),    // HACKER_RED
        ("ACCENT_GRADIENT", "\x1b[38;5;124m"), // BLOOD_RED
        // Highlighting colors
        ("HIGHLIGHT_RED", "\x1b[48;5;196m\x1b[38;5;15m"),
        ("HIGHLIGHT_YELLOW", "\x1b[48;5;226m\x1b[38;5;16m"),
        ("HIGHLIGHT_GREEN", "\x1b[48;5;46m\x1b[38;5;16m"),
        ("HIGHLIGHT_BLUE", "\x1b[48;5;51m\x1b[38;5;16m"),
        ("HIGHLIGHT_PURPLE", "\x1b[48;5;129m\x1b[38;5;15m"),
        // Status colors with reddish tones
        ("SUCCESS", "\x1b[38;5;46m"),
        ("WARNING", "\x1b[38;5;208m"),
        ("ERROR", "\x1b[38;5;196m"),
        ("CRITICAL", "\x1b[48;5;196m\x1b[38;5;15m\x1b[1m"),
        ("INFO", "\x1b[38;5;51m"),
        ("DEBUG", "\x1b[38;5;240m"),
        // Vulnerability severity colors
        ("VULN_CRITICAL", "\x1b[48;5;124m\x1b[38;5;15m\x1b[1m"),
        ("VULN_HIGH", "\x1b[38;5;196m\x1b[1m"),
        ("VULN_MEDIUM", "\x1b[38;5;208m\x1b[1m"),
        ("VULN_LOW", "\x1b[38;5;226m"),
        ("VULN_INFO", "\x1b[38;5;51m"),
        // Tool status colors
        ("TOOL_RUNNING", "\x1b[38;5;46m\x1b[5m"),
        ("TOOL_SUCCESS", "\x1b[38;5;46m\x1b[1m"),
        ("TOOL_FAILED", "\x1b[38;5;196m\x1b[1m"),
        ("TOOL_TIMEOUT", "\x1b[38;5;208m\x1b[1m"),
        ("TOOL_RECOVERY", "\x1b[38;5;129m\x1b[1m"),
        // Progress and animation colors
        ("PROGRESS_BAR", "\x1b[38;5;46m"),
        ("PROGRESS_EMPTY", "\x1b[38;5;240m"),
        ("SPINNER", "\x1b[38;5;51m"),
        ("PULSE", "\x1b[38;5;196m\x1b[5m"),
    ])
});

/// Acesso estilo dict: `ModernVisualEngine.COLORS['KEY']`.
/// (chave inexistente devolve "" — os call sites do port sempre usam chaves válidas)
pub fn color(key: &str) -> &'static str {
    COLORS.get(key).copied().unwrap_or("")
}

/// `COLORS.get(color, COLORS['FIRE_RED'])` (usado em `create_section_header`).
pub fn color_or(key: &str, default: &'static str) -> &'static str {
    COLORS.get(key).copied().unwrap_or(default)
}

/// `ModernVisualEngine.PROGRESS_STYLES`
pub static PROGRESS_STYLES: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        HashMap::from([
            ("dots", vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            ("bars", vec!["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]),
            ("arrows", vec!["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"]),
            ("pulse", vec!["●", "◐", "◑", "◒", "◓", "◔", "◕", "◖", "◗", "◘"]),
        ])
    });

// Helpers de parity com slicing/padding do Python (str = codepoints Unicode)
pub fn py_truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn py_pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Estrutura portadora dos métodos estáticos (mesma superfície de chamada:
/// `ModernVisualEngine::create_banner()` etc.).
pub struct ModernVisualEngine;

impl ModernVisualEngine {
    /// `create_banner()` — banner ASCII blood-red (1:1, incluindo API_HOST:API_PORT)
    pub fn create_banner() -> String {
        let border_color = color("PRIMARY_BORDER");
        let accent = color("ACCENT_LINE");
        let gradient = color("ACCENT_GRADIENT");
        let reset = color("RESET");
        let bold = color("BOLD");
        let title_block = format!("{accent}{bold}");
        let bright_white = color("BRIGHT_WHITE");
        let terminal_gray = color("TERMINAL_GRAY");
        format!(
            "
{title_block}
██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
{reset}
{border_color}┌─────────────────────────────────────────────────────────────────────┐
│  {bright_white}🚀 HexStrike AI - Blood-Red Offensive Intelligence Core{border_color}        │
│  {accent}⚡ AI-Automated Recon | Exploitation | Analysis Pipeline{border_color}          │
│  {gradient}🎯 Bug Bounty | CTF | Red Team | Zero-Day Research{border_color}              │
└─────────────────────────────────────────────────────────────────────┘{reset}

{terminal_gray}[INFO] Server starting on {host}:{port}
[INFO] 150+ integrated modules | Adaptive AI decision engine active
[INFO] Blood-red theme engaged – unified offensive operations UI{reset}
",
            title_block = title_block,
            reset = reset,
            border_color = border_color,
            bright_white = bright_white,
            accent = accent,
            gradient = gradient,
            terminal_gray = terminal_gray,
            host = api_host(),
            port = api_port(),
        )
    }

    /// `create_progress_bar(current, total, width=50, tool="")`
    pub fn create_progress_bar(current: usize, total: usize, width: usize, tool: &str) -> String {
        let percentage = if total == 0 {
            0.0
        } else {
            (current as f64 / total as f64 * 100.0).min(100.0)
        };
        let filled = (width as f64 * percentage / 100.0) as usize;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
        let border = color("PRIMARY_BORDER");
        let fill_col = color("ACCENT_LINE");
        let reset = color("RESET");
        let dash = "─".repeat((width + 4).saturating_sub(tool.chars().count()));
        let dash_bottom = "─".repeat(width + 10);
        format!(
            "
{border}┌─ {tool} ─{dash}┐
│ {fill_col}{bar}{border} │ {percentage:6.1}%
└─{dash_bottom}┘{reset}",
            border = border,
            tool = tool,
            dash = dash,
            fill_col = fill_col,
            bar = bar,
            percentage = percentage,
            dash_bottom = dash_bottom,
            reset = reset,
        )
    }

    /// `render_progress_bar(progress, width=40, style='cyber', label="", eta=0, speed="")`
    pub fn render_progress_bar(
        progress: f64,
        width: usize,
        style: &str,
        label: &str,
        eta: f64,
        speed: &str,
    ) -> String {
        let progress = progress.clamp(0.0, 1.0);
        let filled_width = (width as f64 * progress) as usize;
        let empty_width = width - filled_width;

        let (filled_char, empty_char, bar_color, progress_color) = match style {
            "cyber" => ("█", "░", color("ACCENT_LINE"), color("PRIMARY_BORDER")),
            "matrix" => ("▓", "▒", color("ACCENT_LINE"), color("ACCENT_GRADIENT")),
            "neon" => ("━", "─", color("PRIMARY_BORDER"), color("CYBER_ORANGE")),
            _ => ("█", "░", color("ACCENT_LINE"), color("PRIMARY_BORDER")),
        };

        let filled_part = format!("{bar_color}{}", filled_char.repeat(filled_width));
        let empty_part =
            format!("{}{}", color("TERMINAL_GRAY"), empty_char.repeat(empty_width));
        let percentage = format!("{:.1}%", progress * 100.0);

        let mut extra_info = String::new();
        if eta > 0.0 {
            extra_info.push_str(&format!(" ETA: {eta:.1}s"));
        }
        if !speed.is_empty() {
            extra_info.push_str(&format!(" Speed: {speed}"));
        }

        let bar_display = format!(
            "[{filled_part}{empty_part}{}] {progress_color}{percentage}{}",
            color("RESET"),
            color("RESET")
        );

        if !label.is_empty() {
            format!("{label}: {bar_display}{extra_info}")
        } else {
            format!("{bar_display}{extra_info}")
        }
    }
}

/// Linha do dashboard (equivalente dos dicts `proc_info` do Python).
pub struct ProcessRow {
    pub pid: u32,
    pub status: String,
    pub command: String,
    pub duration: f64,
}

impl ModernVisualEngine {
    /// `create_live_dashboard(processes)`
    pub fn create_live_dashboard(processes: &[ProcessRow]) -> String {
        if processes.is_empty() {
            return format!(
                "
{}╭─────────────────────────────────────────────────────────────────────────────╮
│ {}📊 HEXSTRIKE LIVE DASHBOARD{}                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ {}No active processes currently running{}                                    │
╰─────────────────────────────────────────────────────────────────────────────╯{}\n",
                color("PRIMARY_BORDER"),
                color("ACCENT_LINE"),
                color("PRIMARY_BORDER"),
                color("TERMINAL_GRAY"),
                color("PRIMARY_BORDER"),
                color("RESET"),
            );
        }

        let mut lines = vec![
            format!(
                "{}╭─────────────────────────────────────────────────────────────────────────────╮",
                color("PRIMARY_BORDER")
            ),
            format!(
                "│ {}📊 HEXSTRIKE LIVE DASHBOARD{}                                           │",
                color("ACCENT_LINE"),
                color("PRIMARY_BORDER")
            ),
            "├─────────────────────────────────────────────────────────────────────────────┤".to_string(),
        ];

        for p in processes {
            let status = if p.status.is_empty() { "unknown" } else { &p.status };
            let cmd = if p.command.chars().count() > 50 {
                format!("{}...", py_truncate(&p.command, 50))
            } else if p.command.is_empty() {
                "unknown".to_string()
            } else {
                p.command.clone()
            };
            let status_color =
                if status == "running" { color("ACCENT_LINE") } else { color("HACKER_RED") };
            lines.push(format!(
                "│ {}PID {}{} | {}{}{} | {}{}{} │",
                color("CYBER_ORANGE"),
                p.pid,
                color("PRIMARY_BORDER"),
                status_color,
                status,
                color("PRIMARY_BORDER"),
                color("BRIGHT_WHITE"),
                cmd,
                color("PRIMARY_BORDER"),
            ));
        }

        lines.push(format!(
            "╰─────────────────────────────────────────────────────────────────────────────╯{}",
            color("RESET")
        ));
        lines.join("\n")
    }

    /// `format_vulnerability_card(vuln_data)`
    pub fn format_vulnerability_card(vuln_data: &Map<String, serde_json::Value>) -> String {
        let severity = vuln_data
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_uppercase();
        let name = vuln_data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown Vulnerability");
        let description = vuln_data
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("No description available");

        let severity_color = match severity.as_str() {
            "CRITICAL" => color("VULN_CRITICAL"),
            "HIGH" => color("HACKER_RED"),
            "MEDIUM" => color("ACCENT_GRADIENT"),
            "LOW" => color("CYBER_ORANGE"),
            "INFO" => color("TERMINAL_GRAY"),
            _ => color("TERMINAL_GRAY"),
        };

        format!(
            "
{color}┌─ 🚨 VULNERABILITY DETECTED ─────────────────────────────────────┐
│ {bright_white}{name:<60}{color} │
│ {gray}Severity: {color}{severity:<52}{color} │
│ {gray}{description:<58}{color} │
└─────────────────────────────────────────────────────────────────┘{reset}",
            color = severity_color,
            bright_white = color("BRIGHT_WHITE"),
            name = py_pad(name, 60),
            gray = color("TERMINAL_GRAY"),
            severity = py_pad(&severity, 52),
            description = py_pad(&py_truncate(description, 58), 58),
            reset = color("RESET"),
        )
    }

    /// `format_error_card(error_type, tool_name, error_message, recovery_action="")`
    pub fn format_error_card(
        error_type: &str,
        tool_name: &str,
        error_message: &str,
        recovery_action: &str,
    ) -> String {
        let color_ = match error_type.to_uppercase().as_str() {
            "CRITICAL" => color("VULN_CRITICAL"),
            "ERROR" => color("TOOL_FAILED"),
            "TIMEOUT" => color("TOOL_TIMEOUT"),
            "RECOVERY" => color("TOOL_RECOVERY"),
            "WARNING" => color("WARNING"),
            _ => color("ERROR"),
        };
        let reset = color("RESET");
        let bright = color("BRIGHT_WHITE");
        let recovery_col = color("TOOL_RECOVERY");

        let mut card = format!(
            "
{color}┌─ 🔥 ERROR DETECTED ─────────────────────────────────────────────┐{reset}
{color}│ {bright}Tool: {tool:<55}{color} │{reset}
{color}│ {bright}Type: {error_type:<55}{color} │{reset}
{color}│ {bright}Error: {error_message:<53}{color} │{reset}",
            color = color_,
            reset = reset,
            bright = bright,
            tool = py_pad(tool_name, 55),
            error_type = py_pad(error_type, 55),
            error_message = py_pad(&py_truncate(error_message, 53), 53),
        );

        if !recovery_action.is_empty() {
            card.push_str(&format!(
                "
{color}│ {recovery_col}Recovery: {recovery:<50}{color} │{reset}",
                color = color_,
                recovery_col = recovery_col,
                recovery = py_pad(&py_truncate(recovery_action, 50), 50),
                reset = reset,
            ));
        }

        card.push_str(&format!(
            "
{color}└─────────────────────────────────────────────────────────────────┘{reset}",
            color = color_,
            reset = reset,
        ));
        card
    }

    /// `format_tool_status(tool_name, status, target="", progress=0.0)`
    pub fn format_tool_status(tool_name: &str, status: &str, target: &str, progress: f64) -> String {
        let color_ = match status.to_uppercase().as_str() {
            "RUNNING" => color("TOOL_RUNNING"),
            "SUCCESS" => color("TOOL_SUCCESS"),
            "FAILED" => color("TOOL_FAILED"),
            "TIMEOUT" => color("TOOL_TIMEOUT"),
            "RECOVERY" => color("TOOL_RECOVERY"),
            _ => color("INFO"),
        };

        let mut progress_bar = String::new();
        if progress > 0.0 {
            let filled = (20.0 * progress) as usize;
            let empty = 20 - filled;
            progress_bar = format!(
                " [{}{}{}{}] {:.1}%",
                color("PROGRESS_BAR"),
                "█".repeat(filled),
                color("PROGRESS_EMPTY"),
                "░".repeat(empty),
                progress * 100.0
            );
        }

        format!(
            "{}🔧 {}{} | {}{}{} | {}{}{}{}",
            color_,
            tool_name.to_uppercase(),
            color("RESET"),
            color_,
            status,
            color("RESET"),
            color("BRIGHT_WHITE"),
            target,
            color("RESET"),
            progress_bar,
        )
    }

    /// `format_highlighted_text(text, highlight_type="RED")`
    pub fn format_highlighted_text(text: &str, highlight_type: &str) -> String {
        let color_ = match highlight_type.to_uppercase().as_str() {
            "RED" => color("HIGHLIGHT_RED"),
            "YELLOW" => color("HIGHLIGHT_YELLOW"),
            "GREEN" => color("HIGHLIGHT_GREEN"),
            "BLUE" => color("HIGHLIGHT_BLUE"),
            "PURPLE" => color("HIGHLIGHT_PURPLE"),
            _ => color("HIGHLIGHT_RED"),
        };
        format!("{color_} {text} {}", color("RESET"))
    }

    /// `format_vulnerability_severity(severity, count=0)`
    pub fn format_vulnerability_severity(severity: &str, count: usize) -> String {
        let color_ = match severity.to_uppercase().as_str() {
            "CRITICAL" => color("VULN_CRITICAL"),
            "HIGH" => color("VULN_HIGH"),
            "MEDIUM" => color("VULN_MEDIUM"),
            "LOW" => color("VULN_LOW"),
            "INFO" => color("VULN_INFO"),
            _ => color("INFO"),
        };
        let count_text = if count > 0 { format!(" ({count})") } else { String::new() };
        format!("{}{}{}{}", color_, severity.to_uppercase(), count_text, color("RESET"))
    }

    /// `create_section_header(title, icon="🔥", color="FIRE_RED")`
    pub fn create_section_header(title: &str, icon: &str, color_key: &str) -> String {
        let header_color = color_or(color_key, color("FIRE_RED"));
        format!(
            "
{}{}{}
{}{} {}{}
{}{}{}",
            header_color,
            "═".repeat(70),
            color("RESET"),
            header_color,
            icon,
            title.to_uppercase(),
            color("RESET"),
            header_color,
            "═".repeat(70),
            color("RESET"),
        )
    }

    /// `format_command_execution(command, status, duration=0.0)`
    pub fn format_command_execution(command: &str, status: &str, duration: f64) -> String {
        let color_ = match status.to_uppercase().as_str() {
            "STARTING" => color("INFO"),
            "RUNNING" => color("TOOL_RUNNING"),
            "SUCCESS" => color("TOOL_SUCCESS"),
            "FAILED" => color("TOOL_FAILED"),
            "TIMEOUT" => color("TOOL_TIMEOUT"),
            _ => color("INFO"),
        };
        let duration_text = if duration > 0.0 { format!(" ({duration:.2}s)") } else { String::new() };
        let ellipsis = if command.chars().count() > 60 { "..." } else { "" };
        format!(
            "{}▶ {}{} | {}{}{}",
            color_,
            py_truncate(command, 60),
            ellipsis,
            status.to_uppercase(),
            duration_text,
            color("RESET")
        )
    }
}
