use clap::Parser;
use rmcp::ServiceExt;
use secure_research::{
    bridge::Bridge,
    error::{ErrorCode, Result},
    mcp::Adapter,
};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    socket: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("research-client: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args = Args::parse();
    let bridge = Arc::new(Bridge::connect_with_retry(&args.socket).await?);
    let result = async {
        let server = Adapter::new(bridge.clone())
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|_| ErrorCode::InvalidRequest)?;
        server.waiting().await.map_err(|_| ErrorCode::Cancelled)?;
        Ok(())
    }
    .await;
    bridge.close().await;
    result
}
