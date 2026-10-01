//! Private subprocess entry point; never installed as an agent-facing tool.
use secure_research::{
    browser::engine::{self, WorkerSettings},
    error::{ErrorCode, Result},
    worker,
};
use std::path::Path;

fn main() {
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| ErrorCode::WorkerFailed)
        .and_then(|runtime| runtime.block_on(run()));
    if let Err(error) = result {
        std::process::exit(worker::worker_exit(error));
    }
}

async fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(ErrorCode::InvalidRequest);
    }
    let bytes = worker::read_bounded(Path::new("/responses/config.json"), 64 * 1024)?;
    let settings: WorkerSettings =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    // Chromiumoxide inherits stdin. Retain a non-inheritable pipe descriptor for
    // IPC and replace fd 0 before spawning Chromium so it cannot consume frames.
    let fd = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdin(), 3)
        .map_err(|_| ErrorCode::WorkerFailed)?;
    let input = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    rustix::stdio::dup2_stdin(
        std::fs::File::open("/dev/null").map_err(|_| ErrorCode::WorkerFailed)?,
    )
    .map_err(|_| ErrorCode::WorkerFailed)?;
    let stop = tokio_util::sync::CancellationToken::new();
    let signal = stop.clone();
    let watcher = tokio::spawn(async move {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            term.recv().await;
            signal.cancel();
        }
    });
    let output = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdout(), 3)
        .map_err(|_| ErrorCode::WorkerFailed)?;
    let output = tokio::net::unix::pipe::Sender::from_owned_fd(output)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let result = engine::run(settings, input, output, stop).await;
    watcher.abort();
    let _ = watcher.await;
    result
}
