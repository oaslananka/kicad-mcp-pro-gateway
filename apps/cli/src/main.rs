use std::path::PathBuf;

use clap::{Parser, Subcommand};
use companion_core::config::{self, CliOverrides};
use companion_protocol::{IpcRequest, IpcResponse};
use kicad_mcp_gateway_cli::ipc_client::{ok_or_bail, send_request};

#[derive(Parser)]
#[command(
    name = "kicad-mcp-gateway",
    version,
    about = "KiCad MCP Pro Gateway CLI"
)]
struct Cli {
    /// Override the data directory (defaults to the platform data dir / env / config).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prepare the local data directory, device identity, and daemon.
    Setup,
    #[command(subcommand)]
    Daemon(DaemonAction),
    #[command(subcommand)]
    Device(DeviceAction),
    /// Begin device pairing (development mock provider until a cloud relay exists).
    Pair,
    /// Show daemon/device/session/workspace status.
    Status,
    #[command(subcommand)]
    Workspace(WorkspaceAction),
    #[command(subcommand)]
    Session(SessionAction),
    #[command(subcommand)]
    Audit(AuditAction),
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon in the background.
    Start,
    /// Report whether the daemon is reachable.
    Status,
}

#[derive(Subcommand)]
enum DeviceAction {
    /// Show local device identity status.
    Status,
}

#[derive(Subcommand)]
enum WorkspaceAction {
    /// Authorize a directory as a workspace.
    Add { path: String },
    /// List authorized workspaces.
    List,
    /// Remove a workspace authorization.
    Remove { workspace_id: String },
}

#[derive(Subcommand)]
enum SessionAction {
    List,
    Approve {
        session_id: String,
    },
    Deny {
        session_id: String,
        #[arg(long, default_value = "denied by user")]
        reason: String,
    },
    Pause {
        session_id: String,
    },
    Resume {
        session_id: String,
    },
    Revoke {
        session_id: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let overrides = CliOverrides {
        data_dir: cli.data_dir.clone(),
        ..Default::default()
    };
    let cfg = config::load(overrides)?;

    match cli.command {
        Command::Setup => run_setup(&cfg).await,
        Command::Daemon(DaemonAction::Start) => daemon_start(&cfg).await,
        Command::Daemon(DaemonAction::Status) => daemon_status(&cfg).await,
        Command::Device(DeviceAction::Status) => device_status(&cfg).await,
        Command::Pair => pair(&cfg).await,
        Command::Status => status(&cfg).await,
        Command::Workspace(action) => workspace(&cfg, action).await,
        Command::Session(action) => session(&cfg, action).await,
        Command::Audit(AuditAction::List) => audit_list(&cfg).await,
    }
}

async fn run_setup(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    println!("KiCad MCP Pro Gateway\n");
    std::fs::create_dir_all(&cfg.data_dir)?;
    println!(
        "\u{2713} local data directory ready ({})",
        cfg.data_dir.display()
    );

    match send_request(&cfg.data_dir, IpcRequest::Status).await {
        Ok(response) => {
            let response = ok_or_bail(response)?;
            if let IpcResponse::Status(status) = response {
                if status.device_fingerprint.is_some() {
                    println!("\u{2713} secure device identity ready");
                } else {
                    println!("\u{2717} no device identity yet \u{2014} run `kicad-mcp-gateway pair` after starting the daemon");
                }
                println!(
                    "{} KiCad MCP Pro {}",
                    if status.core_bridge_reachable {
                        "\u{2713}"
                    } else {
                        "\u{2717}"
                    },
                    if status.core_bridge_reachable {
                        "detected"
                    } else {
                        "offline"
                    }
                );
            }
            println!("\u{2713} local daemon available");
        }
        Err(_) => {
            println!("\u{2717} local daemon not reachable \u{2014} run `kicad-mcp-gateway daemon start` first");
        }
    }
    Ok(())
}

async fn daemon_start(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    if send_request(&cfg.data_dir, IpcRequest::Status)
        .await
        .is_ok()
    {
        println!("daemon is already running");
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot locate sibling daemon binary"))?;
    let daemon_binary = dir.join(if cfg!(windows) {
        "kicad-mcp-gateway-daemon.exe"
    } else {
        "kicad-mcp-gateway-daemon"
    });

    std::process::Command::new(&daemon_binary)
        .env("GATEWAY_DATA_DIR", &cfg.data_dir)
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!("failed to start daemon at {}: {e}", daemon_binary.display())
        })?;

    println!("daemon starting (data dir: {})", cfg.data_dir.display());
    Ok(())
}

async fn daemon_status(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    match send_request(&cfg.data_dir, IpcRequest::Status).await {
        Ok(_) => {
            println!("daemon: running");
            Ok(())
        }
        Err(_) => {
            println!("daemon: not running");
            Ok(())
        }
    }
}

async fn device_status(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    let response = ok_or_bail(send_request(&cfg.data_dir, IpcRequest::PairingStatus).await?)?;
    if let IpcResponse::PairingStatus(view) = response {
        match view.device_fingerprint {
            Some(fp) => println!("device fingerprint: {fp}\npaired: {}", view.paired),
            None => println!("no device identity yet"),
        }
    }
    Ok(())
}

async fn pair(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    println!("Device pairing\n");
    println!("Using local mock pairing provider (no production cloud backend exists yet).\n");
    let response = ok_or_bail(send_request(&cfg.data_dir, IpcRequest::BeginPairing).await?)?;
    if let IpcResponse::PairingBegun(view) = response {
        println!("Pairing code:\n{}", view.pairing_code);
    }
    Ok(())
}

async fn status(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    let response = ok_or_bail(send_request(&cfg.data_dir, IpcRequest::Status).await?)?;
    if let IpcResponse::Status(view) = response {
        println!("KiCad MCP Pro Gateway\n");
        println!(
            "Device: {}",
            view.device_fingerprint
                .as_deref()
                .unwrap_or("(not created yet)")
        );
        println!("Paired: {}", view.paired);
        println!(
            "KiCad MCP Pro: {}",
            if view.core_bridge_reachable {
                "Detected"
            } else {
                "Offline"
            }
        );
        println!("Active sessions: {}", view.active_session_count);
        println!("Authorized workspaces: {}", view.workspace_count);
    }
    Ok(())
}

async fn workspace(
    cfg: &companion_core::CompanionConfig,
    action: WorkspaceAction,
) -> anyhow::Result<()> {
    match action {
        WorkspaceAction::Add { path } => {
            let display_name = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            let response = ok_or_bail(
                send_request(
                    &cfg.data_dir,
                    IpcRequest::AuthorizeWorkspace { path, display_name },
                )
                .await?,
            )?;
            if let IpcResponse::WorkspaceAuthorized(view) = response {
                println!(
                    "authorized workspace {} ({})",
                    view.display_name, view.workspace_id
                );
            }
        }
        WorkspaceAction::List => {
            let response =
                ok_or_bail(send_request(&cfg.data_dir, IpcRequest::ListWorkspaces).await?)?;
            if let IpcResponse::Workspaces(workspaces) = response {
                if workspaces.is_empty() {
                    println!("no authorized workspaces");
                }
                for w in workspaces {
                    println!(
                        "{}  {}  {}",
                        w.workspace_id, w.display_name, w.canonical_root
                    );
                }
            }
        }
        WorkspaceAction::Remove { workspace_id } => {
            let workspace_id = workspace_id
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid workspace id: {e:?}"))?;
            ok_or_bail(
                send_request(&cfg.data_dir, IpcRequest::RemoveWorkspace { workspace_id }).await?,
            )?;
            println!("removed workspace {workspace_id}");
        }
    }
    Ok(())
}

async fn session(
    cfg: &companion_core::CompanionConfig,
    action: SessionAction,
) -> anyhow::Result<()> {
    match action {
        SessionAction::List => {
            let response =
                ok_or_bail(send_request(&cfg.data_dir, IpcRequest::ListSessions).await?)?;
            if let IpcResponse::Sessions(sessions) = response {
                if sessions.is_empty() {
                    println!("no active sessions");
                }
                for s in sessions {
                    println!(
                        "{}  {}  {}  {}  effective expiry {}",
                        s.session_id,
                        s.remote_principal,
                        s.status,
                        s.capability_profile,
                        s.expires_at
                    );
                }
            }
        }
        SessionAction::Approve { session_id } => {
            let session_id = parse_session_id(&session_id)?;
            ok_or_bail(
                send_request(&cfg.data_dir, IpcRequest::ApproveSession { session_id }).await?,
            )?;
            println!("approved session {session_id}");
        }
        SessionAction::Deny { session_id, reason } => {
            let session_id = parse_session_id(&session_id)?;
            ok_or_bail(
                send_request(
                    &cfg.data_dir,
                    IpcRequest::DenySession { session_id, reason },
                )
                .await?,
            )?;
            println!("denied session {session_id}");
        }
        SessionAction::Pause { session_id } => {
            let session_id = parse_session_id(&session_id)?;
            ok_or_bail(
                send_request(&cfg.data_dir, IpcRequest::PauseSession { session_id }).await?,
            )?;
            println!("paused session {session_id}");
        }
        SessionAction::Resume { session_id } => {
            let session_id = parse_session_id(&session_id)?;
            ok_or_bail(
                send_request(&cfg.data_dir, IpcRequest::ResumeSession { session_id }).await?,
            )?;
            println!("resumed session {session_id}");
        }
        SessionAction::Revoke { session_id } => {
            let session_id = parse_session_id(&session_id)?;
            ok_or_bail(
                send_request(&cfg.data_dir, IpcRequest::RevokeSession { session_id }).await?,
            )?;
            println!("revoked session {session_id}");
        }
    }
    Ok(())
}

fn parse_session_id(raw: &str) -> anyhow::Result<companion_core::SessionId> {
    raw.parse()
        .map_err(|e| anyhow::anyhow!("invalid session id: {e:?}"))
}

async fn audit_list(cfg: &companion_core::CompanionConfig) -> anyhow::Result<()> {
    let response = ok_or_bail(send_request(&cfg.data_dir, IpcRequest::AuditSummary).await?)?;
    if let IpcResponse::AuditSummary(view) = response {
        println!("audit events: {}", view.total_events);
        println!("{}", view.note);
    }
    Ok(())
}
