use clap::Parser;
use secure_research::{
    config::EgressConfig,
    diagnostics::{self, Component},
    egress,
    error::{ErrorCode, Result},
    socket,
};
use std::io::Read;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 3)]
    listen_fd: u32,
    #[arg(long)]
    config: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::Egress, error);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let mut bytes = Vec::new();
    std::fs::File::open(args.config)
        .map_err(|_| ErrorCode::InvalidRequest)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ErrorCode::SizeLimit);
    }
    let config: EgressConfig =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    config.validate()?;
    let listener = socket::activated_listener(args.listen_fd, &config.socket_path)?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()
        .map_err(|_| ErrorCode::WorkerFailed)?.block_on(async move {
            let listener = tokio::net::UnixListener::from_std(listener).map_err(|_| ErrorCode::PermissionDenied)?;
            let stop = CancellationToken::new();
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| ErrorCode::WorkerFailed)?;
            let serving = egress::serve(listener, config, stop.clone());
            tokio::pin!(serving);
            tokio::select! {
                result = &mut serving => result,
                _ = async { tokio::select! { _ = term.recv() => (), _ = tokio::signal::ctrl_c() => () } } => {
                    stop.cancel(); serving.await
                }
            }
        })
}
