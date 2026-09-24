use companion_core::config::{self, CliOverrides};
use kicad_mcp_gateway_daemon::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = config::load(CliOverrides::default())?;
    run(config).await
}
