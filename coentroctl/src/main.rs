use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use shared_utils::logging::{init_logging, LogOptions};
use tracing::info;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum LogLevelArg {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevelArg> for tracing::Level {
    fn from(level: LogLevelArg) -> Self {
        match level {
            LogLevelArg::Trace => tracing::Level::TRACE,
            LogLevelArg::Debug => tracing::Level::DEBUG,
            LogLevelArg::Info => tracing::Level::INFO,
            LogLevelArg::Warn => tracing::Level::WARN,
            LogLevelArg::Error => tracing::Level::ERROR,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, after_help = "Examples:\n  coentroctl status --json\n  coentroctl tunnel up --server vpn.example.com:4433 --json\n  coentroctl routes list\n  coentroctl dns show")]
struct Args {
    /// Log level
    #[arg(
        short,
        long,
        value_enum,
        default_value = "info",
        env = "COENTRO_LOG_LEVEL"
    )]
    log_level: LogLevelArg,

    /// Emit JSON output (where supported)
    #[arg(long, env = "COENTRO_JSON_LOGS")]
    json_logs: bool,

    /// Output format for command results (table|json)
    #[arg(long, value_enum, default_value = "table")]
    output: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show helper/cluster status (placeholder)
    Status,
    /// Manage tunnels (placeholder wrapper around client IPC)
    Tunnel {
        #[command(subcommand)]
        action: TunnelCmd,
    },
    /// Manage routes (stubbed)
    Routes {
        #[command(subcommand)]
        action: RouteCmd,
    },
    /// Manage DNS (stubbed)
    Dns {
        #[command(subcommand)]
        action: DnsCmd,
    },
}

#[derive(Subcommand, Debug)]
enum TunnelCmd {
    Up {
        /// Server address (host:port)
        #[arg(long)]
        server: Option<String>,
    },
    Down,
}

#[derive(Subcommand, Debug)]
enum RouteCmd {
    List,
    Add {
        /// CIDR to add
        #[arg(long)]
        cidr: String,
    },
    Del {
        /// CIDR to remove
        #[arg(long)]
        cidr: String,
    },
}

#[derive(Subcommand, Debug)]
enum DnsCmd {
    Show,
    Set {
        /// DNS servers to set
        #[arg(long, value_delimiter = ',')]
        servers: Vec<String>,
    },
    Restore,
}

#[derive(Serialize)]
struct Message<'a> {
    status: &'a str,
    detail: &'a str,
}

fn print_msg(fmt: OutputFormat, status: &str, detail: &str) {
    match fmt {
        OutputFormat::Table => println!("{status}: {detail}"),
        OutputFormat::Json => {
            let msg = Message { status, detail };
            println!("{}", serde_json::to_string_pretty(&msg).unwrap());
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level: tracing::Level = args.log_level.into();
    let _guard = init_logging(LogOptions {
        level,
        json_format: args.json_logs,
        ..Default::default()
    });

    match args.command {
        Command::Status => {
            // Placeholder until IPC/backend is wired
            print_msg(
                args.output,
                "ok",
                "status command is scaffolded; helper/management API not wired yet",
            );
        }
        Command::Tunnel { action } => match action {
            TunnelCmd::Up { server } => {
                let detail = if let Some(s) = server {
                    format!("tunnel up stub; would connect to {s}")
                } else {
                    "tunnel up stub; no server provided".to_string()
                };
                print_msg(args.output, "not_implemented", &detail);
            }
            TunnelCmd::Down => {
                print_msg(
                    args.output,
                    "not_implemented",
                    "tunnel down stub; helper IPC integration pending",
                );
            }
        },
        Command::Routes { action } => match action {
            RouteCmd::List => {
                print_msg(
                    args.output,
                    "not_implemented",
                    "routes list stub; will query helper IPC when available",
                );
            }
            RouteCmd::Add { cidr } => {
                print_msg(
                    args.output,
                    "not_implemented",
                    &format!("routes add stub for {cidr}; helper IPC not wired"),
                );
            }
            RouteCmd::Del { cidr } => {
                print_msg(
                    args.output,
                    "not_implemented",
                    &format!("routes del stub for {cidr}; helper IPC not wired"),
                );
            }
        },
        Command::Dns { action } => match action {
            DnsCmd::Show => {
                print_msg(
                    args.output,
                    "not_implemented",
                    "dns show stub; will query helper IPC when available",
                );
            }
            DnsCmd::Set { servers } => {
                print_msg(
                    args.output,
                    "not_implemented",
                    &format!(
                        "dns set stub for servers {:?}; helper IPC not wired",
                        servers
                    ),
                );
            }
            DnsCmd::Restore => {
                print_msg(
                    args.output,
                    "not_implemented",
                    "dns restore stub; helper IPC not wired",
                );
            }
        },
    }

    info!("coentroctl command completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_renders_with_examples() {
        let mut cmd = Args::command();
        let help = cmd.render_long_help().to_string();
        assert!(
            help.contains("Examples:"),
            "help output should include examples for quick start"
        );
    }

    #[test]
    fn parses_status_default_output() {
        let args = Args::parse_from(["bin", "status"]);
        match args.command {
            Command::Status => {}
            _ => panic!("expected status subcommand"),
        }
        assert!(matches!(args.output, OutputFormat::Table));
    }

    #[test]
    fn parses_tunnel_up_with_json_output() {
        let args = Args::parse_from([
            "bin",
            "--output",
            "json",
            "tunnel",
            "up",
            "--server",
            "vpn.example.com:4433",
        ]);
        assert!(matches!(args.output, OutputFormat::Json));
        match args.command {
            Command::Tunnel { action } => match action {
                TunnelCmd::Up { server } => {
                    assert_eq!(server.as_deref(), Some("vpn.example.com:4433"));
                }
                _ => panic!("expected tunnel up action"),
            },
            _ => panic!("expected tunnel subcommand"),
        }
    }
}
