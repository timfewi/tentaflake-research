use clap::Parser;
use secure_research::{
    budget::Ledger,
    config::{Capability, Config},
    diagnostics::{self, Component},
    error::{ErrorCode, Result},
    fetch::IsolatedParser,
    http::ProtectedHttp,
    provider::{
        Brave, Firecrawl, OpenAi, ScrapeProvider, SearchProvider, Searxng, Spider,
        SummarizeProvider, Tavily,
    },
    rpc,
    service::{Dependencies, Service},
    socket,
    store::EvidenceStore,
};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 3)]
    listen_fd: u32,
    #[arg(long)]
    temporary_directory: PathBuf,
    #[arg(long, required = true)]
    public_only: bool,
    #[arg(long)]
    config: PathBuf,
}
fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::Service, error);
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    let mut bytes = Vec::new();
    File::open(&args.config)
        .map_err(|_| ErrorCode::InvalidRequest)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ErrorCode::SizeLimit);
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    config.validate()?;
    if !args.public_only || !args.temporary_directory.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    // Adoption consumes activation environment before any runtime thread exists.
    let listener = socket::activated_listener(args.listen_fd, &config.socket_path)?;
    for directory in [&config.state_directory, &args.temporary_directory] {
        std::fs::create_dir_all(directory).map_err(|_| ErrorCode::Storage)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ErrorCode::Storage)?;
    }
    // Strict mode also needs an exclusive service lock: budget recovery must
    // never interrupt another live instance with a separate ephemeral archive.
    let instance = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(config.state_directory.join("service.lock"))
        .map_err(|_| ErrorCode::Storage)?;
    if !instance
        .metadata()
        .map_err(|_| ErrorCode::Storage)?
        .is_file()
    {
        return Err(ErrorCode::Storage);
    }
    rustix::fs::flock(
        &instance,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_| ErrorCode::Capacity)?;
    let ledger = Ledger::open(
        &config.state_directory.join("budget.sqlite"),
        config.limits.clone(),
    )?;
    ledger.recover()?;
    let store = EvidenceStore::open(&config, args.temporary_directory.clone())?;
    // Build the eligible adapters in operator order. A credential directory is
    // only read when at least one provider is actually enabled and granted.
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let mut search_providers: Vec<Arc<dyn SearchProvider>> = Vec::new();
    for name in &config.search_order {
        if !config.provider_allowed(name, Capability::Search) {
            continue;
        }
        let provider = config
            .providers
            .get(name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let adapter: Arc<dyn SearchProvider> = match name.as_str() {
            // Self-hosted SearXNG is credential-less: its origin is operator
            // configuration and no credential directory is read for it.
            "searxng" => Arc::new(if config.searxng_socket.is_some() {
                Searxng::local(provider)?
            } else {
                Searxng::from_config(provider)?
            }),
            "brave" | "tavily" => {
                let directory = credentials.as_ref().ok_or(ErrorCode::Authentication)?;
                if !directory.is_absolute() {
                    return Err(ErrorCode::Authentication);
                }
                match name.as_str() {
                    "brave" => Arc::new(Brave::from_credentials(provider, directory)?),
                    _ => Arc::new(Tavily::from_credentials(provider, directory)?),
                }
            }
            _ => return Err(ErrorCode::InvalidRequest),
        };
        search_providers.push(adapter);
    }
    // Scrape adapters follow the same grant rule: a credential directory is
    // only read when the provider is explicitly enabled and granted scrape.
    let mut scrape_providers: Vec<Arc<dyn ScrapeProvider>> = Vec::new();
    for name in &config.scrape_order {
        if !config.provider_allowed(name, Capability::Scrape) {
            continue;
        }
        let directory = credentials.as_ref().ok_or(ErrorCode::Authentication)?;
        if !directory.is_absolute() {
            return Err(ErrorCode::Authentication);
        }
        let provider = config
            .providers
            .get(name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let adapter: Arc<dyn ScrapeProvider> = match name.as_str() {
            "spider" => Arc::new(Spider::from_credentials(provider, directory)?),
            "firecrawl" => Arc::new(Firecrawl::from_credentials(provider, directory)?),
            _ => return Err(ErrorCode::InvalidRequest),
        };
        scrape_providers.push(adapter);
    }
    // Summarization is the separately enabled expansion; the same grant rule
    // applies and an empty order leaves Research fully usable without it.
    let mut summarize_providers: Vec<Arc<dyn SummarizeProvider>> = Vec::new();
    for name in &config.summarize_order {
        if !config.provider_allowed(name, Capability::Summarize) {
            continue;
        }
        let directory = credentials.as_ref().ok_or(ErrorCode::Authentication)?;
        if !directory.is_absolute() {
            return Err(ErrorCode::Authentication);
        }
        let provider = config
            .providers
            .get(name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let adapter: Arc<dyn SummarizeProvider> = match name.as_str() {
            "openai" => Arc::new(OpenAi::from_credentials(provider, directory)?),
            _ => return Err(ErrorCode::InvalidRequest),
        };
        summarize_providers.push(adapter);
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|_| ErrorCode::WorkerFailed)?.block_on(async move {
        let _instance = instance;
        let listener = tokio::net::UnixListener::from_std(listener).map_err(|_| ErrorCode::PermissionDenied)?;
        let http = Arc::new(ProtectedHttp::new(&config.egress_socket, config.egress_uid.ok_or(ErrorCode::InvalidRequest)?, config.limits.clone(), ledger.clone(), &config.robots.user_agent).await?.with_searxng_socket(config.searxng_socket.as_deref())?);
        let parser = config.workers.clone().map(|worker| IsolatedParser::new(worker, args.temporary_directory, config.limits.parser_concurrency)).transpose()?.map(|parser| Arc::new(parser) as Arc<dyn secure_research::fetch::Parser>);
        let control = config.egress_control_file.clone();
        let service = Service::new(config, Dependencies { ledger, store, http, parser, search_providers, scrape_providers, summarize_providers })?;
        let stop = CancellationToken::new();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|_| ErrorCode::WorkerFailed)?;
        let serving = rpc::serve(listener, service, &control, stop.clone());
        tokio::pin!(serving);
        tokio::select! {
            result = &mut serving => result,
            _ = async { tokio::select! { _ = term.recv() => (), _ = tokio::signal::ctrl_c() => () } } => { stop.cancel(); serving.await }
        }
    })
}
