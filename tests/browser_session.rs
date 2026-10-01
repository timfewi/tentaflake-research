//! Service supervisor against the actual isolated worker. All responses and
//! cancellation signals belong to this synthetic fixture; no provider is used.
use secure_research::{
    browser::{
        engine::WorkerSettings,
        launch::Settings,
        sandbox::SandboxConfig,
        session::{Broker, Pool},
        wire,
    },
    config::MIB,
    error::{ErrorCode, Result},
    http::HttpResponse,
};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .expect("missing pinned browser test setting")
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            if std::env::current_exe().unwrap() == Path::new("/worker") {
                use secure_research::protocol::{VERSION, read_frame, write_frame};
                let mut output = tokio::io::stdout();
                write_frame(&mut output, &wire::Output::Ready { version: VERSION })
                    .await
                    .unwrap();
                let mut input = tokio::io::stdin();
                while read_frame::<_, wire::Input>(&mut input)
                    .await
                    .unwrap()
                    .is_some()
                {}
                // Prove the supervisor permits cooperative teardown before
                // joining the broker and deleting this synthetic workspace.
                tokio::time::sleep(Duration::from_millis(100)).await;
                std::fs::write("/output/eof-observed", b"closed").unwrap();
            } else {
                check().await;
            }
        });
}

struct DrainWitness {
    root: PathBuf,
    observed: AtomicBool,
}

#[async_trait::async_trait]
impl Broker for DrainWitness {
    async fn request(&self, _: wire::HttpRequest, _: CancellationToken) -> Result<HttpResponse> {
        Err(ErrorCode::PolicyDenied)
    }

    async fn drain(&self) {
        let observed = std::fs::read_dir(&self.root).unwrap().any(|entry| {
            std::fs::read(entry.unwrap().path().join("output/eof-observed"))
                .is_ok_and(|bytes| bytes == b"closed")
        });
        self.observed.store(observed, Ordering::SeqCst);
    }
}

struct CleanupDenial {
    root: PathBuf,
}

#[async_trait::async_trait]
impl Broker for CleanupDenial {
    async fn request(&self, _: wire::HttpRequest, _: CancellationToken) -> Result<HttpResponse> {
        Err(ErrorCode::PolicyDenied)
    }

    async fn drain(&self) {
        let workspace = std::fs::read_dir(&self.root)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let scratch = workspace.join("scratch");
        std::fs::write(scratch.join("held"), b"synthetic").unwrap();
        std::fs::set_permissions(scratch, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
}

#[derive(Default)]
struct Synthetic {
    entered: Notify,
    cancelled: AtomicUsize,
    active: AtomicUsize,
}

struct Flight<'a>(&'a AtomicUsize);
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Broker for Synthetic {
    async fn request(
        &self,
        request: wire::HttpRequest,
        stop: CancellationToken,
    ) -> Result<HttpResponse> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let _flight = Flight(&self.active);
        if request.url.ends_with("/held") {
            self.entered.notify_one();
            stop.cancelled().await;
            self.cancelled.fetch_add(1, Ordering::SeqCst);
            return Err(ErrorCode::Cancelled);
        }
        if request.url.ends_with("/denied") {
            return Err(ErrorCode::AccessBlocked);
        }
        let body = if request.url.ends_with("/image") {
            "<!doctype html><p>Fixture quote.</p><img src='/held'>"
        } else {
            "<!doctype html><p>Fixture quote.</p>"
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
        Ok(HttpResponse {
            status: 200,
            headers,
            body: body.as_bytes().to_vec(),
        })
    }
}

fn open(route: &str) -> wire::Action {
    wire::Action::Open {
        url: format!("https://example.com/{route}"),
    }
}

fn empty(root: &Path, broker: &Synthetic) {
    assert_eq!(
        broker.active.load(Ordering::SeqCst),
        0,
        "broker outlived session cleanup"
    );
    assert_eq!(
        std::fs::read_dir(root).unwrap().count(),
        0,
        "private workspace survived cleanup"
    );
}

async fn check() {
    let config = SandboxConfig {
        worker: PathBuf::from(env!("CARGO_BIN_EXE_research-browser-worker")),
        bubblewrap: required("RESEARCH_TEST_BWRAP"),
        chromium_sandbox: required("RESEARCH_TEST_CHROMIUM_SANDBOX"),
        fontconfig: required("RESEARCH_TEST_FONTCONFIG"),
        store_paths: std::fs::read_to_string(required("RESEARCH_TEST_CHROMIUM_CLOSURE"))
            .unwrap()
            .lines()
            .map(PathBuf::from)
            .collect(),
    };
    let settings = WorkerSettings {
        launch: Settings {
            chromium: required("RESEARCH_TEST_CHROMIUM"),
            width: 1365,
            height: 768,
            operation_seconds: 5,
            html_bytes: 8 * MIB,
            requests: 64,
            actions: 16,
            locale: "en-US".into(),
            timezone: "UTC".into(),
            accept_language: "en-US,en;q=0.9".into(),
        },
        read_post_rules: vec![],
        redirects: 5,
        response_bytes: 8 * MIB,
        idle_seconds: 10,
        lifetime_seconds: 30,
    };
    let root = tempfile::tempdir().unwrap();
    let pool = Pool::new(1).unwrap();
    let witness = Arc::new(DrainWitness {
        root: root.path().to_owned(),
        observed: AtomicBool::new(false),
    });
    let synthetic = SandboxConfig {
        worker: std::env::current_exe().unwrap(),
        ..config.clone()
    };
    let session = pool
        .start(
            &synthetic,
            settings.clone(),
            root.path(),
            witness.clone(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    session.close().await;
    assert!(
        witness.observed.load(Ordering::SeqCst),
        "supervisor killed its worker before EOF cleanup"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    let startup_broker = Arc::new(Synthetic::default());
    let mut missing_wrap = synthetic.clone();
    missing_wrap.bubblewrap = PathBuf::from("/fixture-missing-bwrap");
    assert!(matches!(
        pool.start(
            &missing_wrap,
            settings.clone(),
            root.path(),
            startup_broker.clone(),
            &CancellationToken::new(),
        )
        .await,
        Err(ErrorCode::WorkerFailed)
    ));
    empty(root.path(), &startup_broker);
    let mut missing = settings.clone();
    missing.launch.chromium = PathBuf::from("/fixture-missing-chromium");
    assert!(matches!(
        pool.start(
            &config,
            missing,
            root.path(),
            startup_broker.clone(),
            &CancellationToken::new()
        )
        .await,
        Err(ErrorCode::WorkerFailed)
    ));
    empty(root.path(), &startup_broker);
    for scenario in [
        "normal",
        "cancel",
        "drop_call",
        "drop_session",
        "job_stop",
        "idle",
    ] {
        let broker = Arc::new(Synthetic::default());
        let job = CancellationToken::new();
        let call = CancellationToken::new();
        let mut settings = settings.clone();
        if scenario == "idle" {
            settings.idle_seconds = 1;
        }
        let session = pool
            .start(&config, settings.clone(), root.path(), broker.clone(), &job)
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            assert!(
                matches!(
                    pool.start(&config, settings, root.path(), broker.clone(), &job)
                        .await,
                    Err(ErrorCode::Capacity)
                ),
                "pool exceeded its worker limit"
            );
            match scenario {
                "normal" => {
                    assert!(matches!(
                        session.execute(open("denied"), &call).await,
                        Err(ErrorCode::AccessBlocked)
                    ));
                    let snapshot = session
                        .execute(open("image"), &call)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        String::from_utf8(snapshot.html)
                            .unwrap()
                            .contains("Fixture quote.")
                    );
                    assert!(snapshot.metadata.pending_requests);
                    broker.entered.notified().await;
                    // Navigating cancels the old image, including its error-only
                    // reply/acknowledgement. The next action must remain usable.
                    session.execute(open("next"), &call).await.unwrap().unwrap();
                    session
                        .execute(wire::Action::Read, &call)
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        session
                            .execute(wire::Action::Close, &call)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(broker.cancelled.load(Ordering::SeqCst), 1);
                }
                "cancel" => {
                    let operation = session.execute(open("held"), &call);
                    let cancel = async {
                        broker.entered.notified().await;
                        call.cancel();
                    };
                    let (result, ()) = tokio::join!(operation, cancel);
                    assert!(matches!(result, Err(ErrorCode::Cancelled)));
                    assert_eq!(broker.cancelled.load(Ordering::SeqCst), 1);
                }
                "drop_call" => {
                    {
                        let operation = session.execute(open("held"), &call);
                        tokio::pin!(operation);
                        tokio::select! {
                            _ = broker.entered.notified() => {},
                            _ = &mut operation => panic!("held operation completed"),
                        }
                    }
                    assert!(
                        session.is_closed(),
                        "dropped operation did not cancel worker"
                    );
                    session.close().await;
                    assert_eq!(broker.cancelled.load(Ordering::SeqCst), 1);
                }
                "drop_session" => {
                    session
                        .execute(open("image"), &call)
                        .await
                        .unwrap()
                        .unwrap();
                    broker.entered.notified().await;
                    // Actual drop happens below; no close call may mask it.
                }
                "job_stop" => {
                    job.cancel();
                    // Observe propagation before calling close, which would
                    // otherwise mask a missing parent/child token relationship.
                    assert!(session.is_closed());
                    session.close().await;
                    assert!(matches!(
                        session.execute(wire::Action::Read, &call).await,
                        Err(ErrorCode::Cancelled)
                    ));
                }
                "idle" => {
                    while !session.is_closed() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    session.close().await;
                    assert!(matches!(
                        session.execute(wire::Action::Read, &call).await,
                        Err(ErrorCode::SourceExpired)
                    ));
                }
                _ => unreachable!(),
            }
        })
        .await;
        if result.is_err() {
            session.close().await;
        }
        result.expect("browser supervisor test timed out");
        drop(session);
        if scenario == "drop_session" {
            tokio::time::timeout(Duration::from_secs(10), async {
                while std::fs::read_dir(root.path()).unwrap().count() != 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("dropped session retained its workspace");
            assert_eq!(broker.cancelled.load(Ordering::SeqCst), 1);
        }
        empty(root.path(), &broker);
        println!("PASS browser supervisor {scenario}");
        // The next iteration proves that cleanup returned the same pool permit.
    }

    let denied_root = tempfile::tempdir().unwrap();
    let denied_pool = Pool::new(1).unwrap();
    let denied = denied_pool
        .start(
            &synthetic,
            settings.clone(),
            denied_root.path(),
            Arc::new(CleanupDenial {
                root: denied_root.path().to_owned(),
            }),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let close_result = denied
        .execute(wire::Action::Close, &CancellationToken::new())
        .await;
    let workspace = std::fs::read_dir(denied_root.path())
        .unwrap()
        .next()
        .expect("failed cleanup must retain the workspace")
        .unwrap()
        .path();
    std::fs::set_permissions(
        workspace.join("scratch"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::remove_dir_all(workspace).unwrap();
    assert!(matches!(close_result, Err(ErrorCode::Storage)));
    assert!(matches!(
        denied_pool
            .start(
                &synthetic,
                settings.clone(),
                denied_root.path(),
                Arc::new(Synthetic::default()),
                &CancellationToken::new(),
            )
            .await,
        Err(ErrorCode::Capacity)
    ));
    println!("PASS browser supervisor failed-cleanup error and capacity hold");

    let startup_root = tempfile::tempdir().unwrap();
    let startup_pool = Pool::new(1).unwrap();
    let mut missing = settings;
    missing.launch.chromium = PathBuf::from("/fixture-missing-chromium");
    let startup_result = startup_pool
        .start(
            &config,
            missing,
            startup_root.path(),
            Arc::new(CleanupDenial {
                root: startup_root.path().to_owned(),
            }),
            &CancellationToken::new(),
        )
        .await;
    let workspace = std::fs::read_dir(startup_root.path())
        .unwrap()
        .next()
        .expect("failed startup cleanup must retain the workspace")
        .unwrap()
        .path();
    let scratch_mode = std::fs::metadata(workspace.join("scratch"))
        .unwrap()
        .permissions()
        .mode();
    std::fs::set_permissions(
        workspace.join("scratch"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::remove_dir_all(workspace).unwrap();
    let startup_error = startup_result.err().expect("startup should fail");
    assert_eq!(
        startup_error,
        ErrorCode::Storage,
        "scratch mode: {:o}",
        scratch_mode
    );
    println!("PASS browser supervisor startup cleanup failure is visible");
}
