use clap::Parser;
use secure_research::{
    budget::{
        Ledger, check_guarded_host, open_guarded, provision_guarded, run_guard_witness,
        validate_guarded_state,
    },
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
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 3)]
    listen_fd: u32,
    #[arg(long)]
    temporary_directory: Option<PathBuf>,
    #[arg(long)]
    public_only: bool,
    #[arg(long)]
    config: Option<PathBuf>,
    /// Root-only, separately authorized one-time ledger initialization.
    #[arg(long, conflicts_with_all = ["config", "temporary_directory", "public_only"])]
    provision_ledger: bool,
    /// Root-only pre-start inspection of the marker's actual host path.
    #[arg(long, conflicts_with_all = ["provision_ledger", "config", "temporary_directory", "public_only", "state_directory"])]
    check_ledger_guard: bool,
    /// Host-owned fixed-target ledger witness, using one activated Unix socket.
    #[arg(long, conflicts_with_all = ["provision_ledger", "check_ledger_guard", "config", "temporary_directory", "public_only", "state_directory"])]
    ledger_witness: bool,
    #[arg(long, requires = "ledger_witness")]
    witness_service_uid: Option<u32>,
    #[arg(long, requires = "ledger_witness")]
    witness_process_uid: Option<u32>,
    #[arg(long, requires = "ledger_witness")]
    witness_socket: Option<PathBuf>,
    #[arg(long, requires = "ledger_witness")]
    witness_state_directory: Option<PathBuf>,
    #[arg(long, requires = "provision_ledger")]
    state_directory: Option<PathBuf>,
    #[arg(long)]
    ledger_marker: Option<PathBuf>,
}
fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::Service, error);
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    if args.ledger_witness {
        let marker = args
            .ledger_marker
            .as_deref()
            .ok_or(ErrorCode::InvalidRequest)?;
        let state_path = args
            .witness_state_directory
            .as_deref()
            .ok_or(ErrorCode::InvalidRequest)?;
        let uid = args.witness_service_uid.ok_or(ErrorCode::InvalidRequest)?;
        let witness_uid = args.witness_process_uid.ok_or(ErrorCode::InvalidRequest)?;
        let socket_path = args
            .witness_socket
            .as_deref()
            .ok_or(ErrorCode::InvalidRequest)?;
        if !socket_path.is_absolute() {
            return Err(ErrorCode::InvalidRequest);
        }
        let listener = socket::activated_listener(args.listen_fd, socket_path)?;
        if std::fs::symlink_metadata(socket_path)
            .map_err(|_| ErrorCode::PermissionDenied)?
            .uid()
            != 0
        {
            return Err(ErrorCode::PermissionDenied);
        }
        return run_guard_witness(marker, state_path, uid, witness_uid, listener);
    }
    if args.check_ledger_guard {
        return check_guarded_host(
            args.ledger_marker
                .as_deref()
                .ok_or(ErrorCode::InvalidRequest)?,
        );
    }
    if args.provision_ledger {
        return provision_guarded(
            args.state_directory
                .as_deref()
                .ok_or(ErrorCode::InvalidRequest)?,
            args.ledger_marker
                .as_deref()
                .ok_or(ErrorCode::InvalidRequest)?,
        );
    }
    if args.ledger_marker.is_some() {
        return Err(ErrorCode::InvalidRequest);
    }
    let temporary_directory = args.temporary_directory.ok_or(ErrorCode::InvalidRequest)?;
    let config_path = args.config.ok_or(ErrorCode::InvalidRequest)?;
    let mut bytes = Vec::new();
    File::open(&config_path)
        .map_err(|_| ErrorCode::InvalidRequest)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ErrorCode::SizeLimit);
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    config.validate()?;
    if !args.public_only || !temporary_directory.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    // Adoption consumes activation environment before any runtime thread exists.
    let listener = socket::activated_listener(args.listen_fd, &config.socket_path)?;
    if config.ledger_guard_marker.is_none() {
        std::fs::create_dir_all(&config.state_directory).map_err(|_| ErrorCode::Storage)?;
        std::fs::set_permissions(
            &config.state_directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(|_| ErrorCode::Storage)?;
    } else {
        validate_guarded_state(&config.state_directory)?;
    }
    std::fs::create_dir_all(&temporary_directory).map_err(|_| ErrorCode::Storage)?;
    std::fs::set_permissions(&temporary_directory, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| ErrorCode::Storage)?;
    // Keep the original lock even in guarded mode, so a still-running legacy
    // instance cannot overlap the protected-ledger process. Guarded mode also
    // holds its separately protected lock for its entire lifetime.
    let instance = lock_instance(&config.state_directory)?;
    let ledger_path = config.state_directory.join("budget.sqlite");
    let ledger = match &config.ledger_guard_marker {
        Some(marker) => open_guarded(
            &ledger_path,
            marker,
            config
                .ledger_guard_witness_socket
                .as_deref()
                .ok_or(ErrorCode::InvalidRequest)?,
            config.limits.clone(),
        )?,
        None => Ledger::open(&ledger_path, config.limits.clone())?,
    };
    ledger.recover()?;
    let store = EvidenceStore::open(&config, temporary_directory.clone())?;
    // Ranking alone never grants access or causes a credential read.
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let search_providers = build_search_providers(&config, credentials.as_deref())?;
    let scrape_providers = build_scrape_providers(&config, credentials.as_deref())?;
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
        let parser = config.workers.clone().map(|worker| IsolatedParser::new(worker, temporary_directory, config.limits.parser_concurrency)).transpose()?.map(|parser| Arc::new(parser) as Arc<dyn secure_research::fetch::Parser>);
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

fn lock_instance(state: &Path) -> Result<File> {
    let instance = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(state.join("service.lock"))
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
    Ok(instance)
}

fn build_search_providers(
    config: &Config,
    credentials: Option<&Path>,
) -> Result<Vec<Arc<dyn SearchProvider>>> {
    let mut providers: Vec<Arc<dyn SearchProvider>> = Vec::new();
    for name in &config.search_order {
        if !config.provider_allowed(name, Capability::Search) {
            continue;
        }
        let provider = config
            .providers
            .get(name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let adapter: Arc<dyn SearchProvider> = match name.as_str() {
            "searxng" => Arc::new(if config.searxng_socket.is_some() {
                Searxng::local(provider)?
            } else {
                Searxng::from_config(provider)?
            }),
            "brave" | "tavily" | "spider" => {
                let directory = credentials
                    .filter(|path| path.is_absolute())
                    .ok_or(ErrorCode::Authentication)?;
                match name.as_str() {
                    "brave" => Arc::new(Brave::from_credentials(provider, directory)?),
                    "tavily" => Arc::new(Tavily::from_credentials(provider, directory)?),
                    "spider" => Arc::new(Spider::from_credentials(provider, directory)?),
                    _ => unreachable!(),
                }
            }
            _ => return Err(ErrorCode::InvalidRequest),
        };
        providers.push(adapter);
    }
    Ok(providers)
}

fn build_scrape_providers(
    config: &Config,
    credentials: Option<&Path>,
) -> Result<Vec<Arc<dyn ScrapeProvider>>> {
    let mut providers: Vec<Arc<dyn ScrapeProvider>> = Vec::new();
    for name in &config.scrape_order {
        if !config.provider_allowed(name, Capability::Scrape) {
            continue;
        }
        let directory = credentials
            .filter(|path| path.is_absolute())
            .ok_or(ErrorCode::Authentication)?;
        let provider = config
            .providers
            .get(name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let adapter: Arc<dyn ScrapeProvider> = match name.as_str() {
            "spider" => Arc::new(Spider::from_credentials(provider, directory)?),
            "firecrawl" => Arc::new(Firecrawl::from_credentials(provider, directory)?),
            _ => return Err(ErrorCode::InvalidRequest),
        };
        providers.push(adapter);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_research::{
        config::{DataClass, ProviderConfig},
        http::{HttpRequest, HttpResponse, Transport},
        policy::PublicUrl,
        provider::{Context, SearchQuery},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn legacy_lock_excludes_other_instances() {
        let state = tempfile::tempdir().unwrap();
        let held = lock_instance(state.path()).unwrap();
        assert!(matches!(
            lock_instance(state.path()),
            Err(ErrorCode::Capacity)
        ));
        drop(held);
        assert!(lock_instance(state.path()).is_ok());
    }

    struct SpiderTransport(AtomicUsize);

    #[async_trait::async_trait]
    impl Transport for SpiderTransport {
        async fn get(
            &self,
            _: u32,
            _: Uuid,
            _: HttpRequest,
            _: &CancellationToken,
        ) -> Result<HttpResponse> {
            panic!("unexpected GET")
        }

        async fn post(
            &self,
            _: u32,
            _: Uuid,
            request: HttpRequest,
            body: Vec<u8>,
            _: &CancellationToken,
        ) -> Result<HttpResponse> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert!(request.headers["authorization"].is_sensitive());
            assert_eq!(request.headers["authorization"], "Bearer fixture-key");
            assert!(!String::from_utf8_lossy(&body).contains("fixture-key"));
            let content = match request.target.url().path() {
                "/search" => {
                    assert!(request.query);
                    r#"{"content":[{"title":"Battery recycling","url":"https://example.com/recycling","description":"Fixture"}]}"#
                }
                "/scrape" => {
                    assert!(!request.query);
                    r#"[{"content":"Fixture page","status":200}]"#
                }
                _ => panic!("unexpected endpoint"),
            };
            Ok(HttpResponse {
                status: 200,
                headers: Default::default(),
                body: content.as_bytes().to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn spider_binary_construction_obeys_independent_grants() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("spider"), b"fixture-key\n").unwrap();
        let transport = SpiderTransport(AtomicUsize::new(0));
        let context = Context {
            owner: 1001,
            job: Uuid::new_v4(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            stop: CancellationToken::new(),
        };
        let query = SearchQuery {
            q: "battery recycling".into(),
            count: 1,
            language: None,
            country: None,
            freshness: None,
        };
        let target = PublicUrl::parse("https://example.com/recycling").unwrap();
        for (capabilities, data, search_allowed, scrape_allowed) in [
            (
                vec![Capability::Search],
                vec![DataClass::Queries],
                true,
                false,
            ),
            (
                vec![Capability::Scrape],
                vec![DataClass::Urls, DataClass::Content],
                false,
                true,
            ),
            (
                vec![Capability::Search, Capability::Scrape],
                vec![DataClass::Queries, DataClass::Urls, DataClass::Content],
                true,
                true,
            ),
            (
                vec![Capability::Search, Capability::Scrape],
                vec![DataClass::Urls, DataClass::Content],
                false,
                true,
            ),
            (
                vec![Capability::Search, Capability::Scrape],
                vec![DataClass::Queries, DataClass::Content],
                true,
                false,
            ),
            (
                vec![Capability::Search, Capability::Scrape],
                vec![DataClass::Queries, DataClass::Urls],
                true,
                false,
            ),
        ] {
            let mut config = Config {
                allowed_client_uids: vec![1001],
                egress_uid: Some(1002),
                search_order: vec!["spider".into()],
                scrape_order: vec!["spider".into()],
                ..Config::default()
            };
            config.providers.insert(
                "spider".into(),
                ProviderConfig {
                    enable: true,
                    capabilities: capabilities.into_iter().collect(),
                    data: data.into_iter().collect(),
                    credential: Some("spider".into()),
                    request_micro_usd: Some(125_000),
                    ..ProviderConfig::default()
                },
            );
            // Startup validates the full config first. Incomplete dual grants
            // must fail there even though neither builder widens its own grant.
            let granted_capabilities = config.providers["spider"].capabilities.len();
            assert_eq!(
                config.validate().is_ok(),
                granted_capabilities == 1 || (search_allowed && scrape_allowed)
            );
            let search = build_search_providers(&config, Some(directory.path())).unwrap();
            let scrape = build_scrape_providers(&config, Some(directory.path())).unwrap();
            assert_eq!(search.len(), if search_allowed { 1 } else { 0 });
            assert_eq!(scrape.len(), if scrape_allowed { 1 } else { 0 });
            if let Some(provider) = search.first() {
                let response = provider
                    .search(&transport, &context, &query, 2, 4096)
                    .await
                    .unwrap();
                assert_eq!(response.data.hits[0].title, "Battery recycling");
                assert!(response.data.hits[0].untrusted);
                assert!(!String::from_utf8_lossy(&response.raw).contains("fixture-key"));
            }
            if let Some(provider) = scrape.first() {
                let response = provider
                    .scrape(&transport, &context, &target, 4096)
                    .await
                    .unwrap();
                assert_eq!(response.text, b"Fixture page");
            }
        }
        // Two populated orders do not read credentials for a disabled provider.
        let mut disabled = Config {
            search_order: vec!["spider".into()],
            scrape_order: vec!["spider".into()],
            ..Config::default()
        };
        disabled
            .providers
            .insert("spider".into(), ProviderConfig::default());
        assert!(build_search_providers(&disabled, None).unwrap().is_empty());
        assert!(build_scrape_providers(&disabled, None).unwrap().is_empty());
        assert_eq!(transport.0.load(Ordering::SeqCst), 7);
    }
}
