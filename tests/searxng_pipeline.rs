//! Real service/RPC and real adapters, synthetic upstreams (no provider calls).
use secure_research::{
    bridge::Bridge,
    budget::{Charge, Ledger},
    config::{Capability, Config, DataClass, Privacy, ProviderConfig},
    egress::{EgressMode, EgressState},
    error::{ErrorCode, Result},
    http::{HttpRequest, HttpResponse, Transport},
    protocol::Tool,
    provider::Searxng,
    rpc,
    service::{Dependencies, Service},
    store::EvidenceStore,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct Upstream {
    ledger: Arc<Ledger>,
    search: AtomicUsize,
}
#[async_trait::async_trait]
impl Transport for Upstream {
    async fn get(
        &self,
        _: u32,
        _: Uuid,
        _: HttpRequest,
        _: &CancellationToken,
    ) -> Result<HttpResponse> {
        panic!("local search must not use public retrieval");
    }
    async fn searxng(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        _: &CancellationToken,
    ) -> Result<HttpResponse> {
        assert_eq!(request.target.origin(), "http://searxng.invalid");
        assert_eq!(request.target.url().path(), "/search");
        let throttled = request
            .target
            .url()
            .query_pairs()
            .any(|(name, value)| name == "q" && value == "retry-budget");
        let body = if throttled {
            Vec::new()
        } else {
            serde_json::to_vec(&json!({"results":[
                {"title":"First", "url":"https://a.example.org/", "content":"Exact é 👩‍🔬", "score":2},
                {"title":"Second", "url":"https://b.example.org/", "content":"Relevant", "score":1}
            ]}))
            .unwrap()
        };
        let charge = self.ledger.reserve(
            owner,
            job,
            Charge {
                bytes: request.max_bytes + 1,
                requests: 1,
                queries: u32::from(request.query),
                ..Default::default()
            },
        )?;
        self.search.fetch_add(1, Ordering::SeqCst);
        charge.finish(body.len() as u64, Some(0))?;
        let mut headers = http::HeaderMap::new();
        if throttled {
            headers.insert("retry-after", "0".parse().unwrap());
        }
        Ok(HttpResponse {
            status: if throttled { 429 } else { 200 },
            headers,
            body,
        })
    }
}

async fn call(bridge: &Bridge, tool: Tool, args: Value) -> Value {
    bridge
        .call(tool, args, CancellationToken::new())
        .await
        .unwrap()
}

async fn pipeline(privacy: Privacy) {
    let root = tempfile::tempdir().unwrap();
    let owner = rustix::process::getuid().as_raw();
    let search = ProviderConfig {
        enable: true,
        capabilities: [Capability::Search].into(),
        data: [DataClass::Queries].into(),
        storage_rights: true,
        ..Default::default()
    };
    let config = Config {
        state_directory: root.path().join("state"),
        allowed_client_uids: vec![owner],
        egress_uid: Some(1002),
        privacy,
        searxng_socket: Some(root.path().join("local.sock")),
        search_order: vec!["searxng".into(), "brave".into()],
        providers: [
            ("searxng".into(), search.clone()),
            // A grant without an installed adapter must not be advertised.
            (
                "brave".into(),
                ProviderConfig {
                    credential: Some("not-installed".into()),
                    request_micro_usd: Some(1000),
                    ..search.clone()
                },
            ),
        ]
        .into(),
        ..Default::default()
    };
    std::fs::create_dir_all(&config.state_directory).unwrap();
    let ledger = Ledger::open(
        &config.state_directory.join("budget.sqlite"),
        config.limits.clone(),
    )
    .unwrap();
    let upstream = Arc::new(Upstream {
        ledger: ledger.clone(),
        search: AtomicUsize::new(0),
    });
    let store = EvidenceStore::open(&config, root.path().into()).unwrap();
    let service = Service::new(
        config,
        Dependencies {
            ledger,
            store,
            http: upstream.clone(),
            parser: None,
            search_providers: vec![Arc::new(Searxng::local(&search).unwrap())],
            scrape_providers: vec![],
            summarize_providers: vec![],
        },
    )
    .unwrap();
    service
        .update_egress(EgressState {
            version: 1,
            generation: Uuid::new_v4(),
            mode: EgressMode::Ready,
            valid_until: chrono::Utc::now().timestamp() + 10,
            region: None,
        })
        .await
        .unwrap();
    let socket = root.path().join("rpc.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let serving = tokio::spawn(async move {
        rpc::connection(
            listener.accept().await.unwrap().0,
            service,
            CancellationToken::new(),
        )
        .await
    });
    let bridge = Bridge::connect(&socket).await.unwrap();
    let mut ids = Vec::new();
    for iteration in 0..2 {
        // With no external analysis and persistent storage rights, a practical
        // deployment reuses the search record across jobs.
        let cached = privacy == Privacy::Practical && iteration == 1;
        let started = call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"start", "limits":{"queries":1,"requests":2,"micro_usd":1000}}),
        )
        .await;
        let job = started["job"]["id"].clone();
        assert_eq!(started["remaining"]["queries"], 1);
        assert_eq!(started["remaining"]["requests"], 2);
        assert_eq!(started["remaining"]["micro_usd"], 1000);
        let capabilities = &started["capabilities"];
        assert_eq!(capabilities["privacy"], json!(privacy));
        assert_eq!(capabilities["http"], true);
        assert_eq!(capabilities["browser"], false);
        assert_eq!(
            capabilities["search"],
            json!([{"provider":"searxng", "request_micro_usd":0,
                "storage":if privacy == Privacy::Strict {"job"} else {"persistent"}}])
        );
        for unavailable in ["scrape", "summarize"] {
            assert_eq!(capabilities[unavailable], json!([]));
        }
        let args = json!({"job_id":job,"queries":[{"q":"example","count":2}]});
        let result = call(&bridge, Tool::ResearchSearch, args.clone()).await;
        assert_eq!(result["coverage"]["success"], 1);
        let data = &result["items"][0]["data"]["result"];
        assert_eq!(data["provider"], "searxng");
        let hits = data["results"]["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 2, "local search must never drop hits");
        assert_eq!(hits[0]["title"], "First");
        assert_eq!(hits[1]["title"], "Second");
        assert_eq!(hits[0]["snippet"], "Exact é 👩‍🔬");
        assert_eq!(result["usage"]["queries"], if cached { 0 } else { 1 });
        assert_eq!(result["usage"]["requests"], if cached { 0 } else { 1 });
        let status = call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"status", "job_id":job}),
        )
        .await;
        assert_eq!(status["remaining"]["queries"], if cached { 1 } else { 0 });
        assert_eq!(status["remaining"]["requests"], if cached { 2 } else { 1 });
        assert_eq!(&status["capabilities"], capabilities);
        let source = data["source"]["id"].clone();
        ids.push(source.clone());
        let metadata = call(
            &bridge,
            Tool::ResearchRead,
            json!({"kind":"metadata","source_id":source}),
        )
        .await;
        let representations = metadata["representations"].as_array().unwrap();
        assert_eq!(representations.len(), 2);
        let raw = representations
            .iter()
            .find(|r| r["extraction_version"] == "searxng-http-json/v1")
            .unwrap();
        let evidence = call(
            &bridge,
            Tool::ResearchRead,
            json!({"kind":"source","source_id":source,"representation_id":raw["id"]}),
        )
        .await;
        assert!(evidence["content"].as_str().unwrap().contains("Exact é 👩‍🔬"));
        call(&bridge, Tool::ResearchSearch, args).await;
        call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"finish","job_id":job}),
        )
        .await;
        // Strict evidence is job-scoped and expires with the job.
        if privacy == Privacy::Strict {
            assert!(matches!(
                bridge
                    .call(
                        Tool::ResearchRead,
                        json!({"kind":"metadata","source_id":source}),
                        CancellationToken::new()
                    )
                    .await,
                Err(ErrorCode::SourceExpired)
            ));
        }
    }
    if privacy == Privacy::Practical {
        assert_eq!(ids[0], ids[1]);
        assert_eq!(upstream.search.load(Ordering::SeqCst), 1);
    } else {
        assert_ne!(ids[0], ids[1]);
        assert_eq!(upstream.search.load(Ordering::SeqCst), 2);
    }
    let before = upstream.search.load(Ordering::SeqCst);
    let started = call(
        &bridge,
        Tool::ResearchJob,
        json!({"operation":"start","limits":{"requests":1,"queries":1}}),
    )
    .await;
    let job = started["job"]["id"].clone();
    let denied = call(
        &bridge,
        Tool::ResearchSearch,
        json!({"job_id":job,"queries":[{"q":"retry-budget"}]}),
    )
    .await;
    assert_eq!(denied["items"][0]["error"], "budget_exceeded", "{denied}");
    assert_eq!(denied["usage"]["requests"], 1);
    assert_eq!(denied["usage"]["queries"], 1);
    assert_eq!(
        upstream.search.load(Ordering::SeqCst),
        before + 1,
        "a local retry passed the exhausted job budget"
    );
    bridge.close().await;
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn local_search_cache_and_ephemeral_evidence_cross_rpc() {
    pipeline(Privacy::Practical).await;
}

#[tokio::test]
async fn strict_local_search_keeps_evidence_job_scoped() {
    pipeline(Privacy::Strict).await;
}
