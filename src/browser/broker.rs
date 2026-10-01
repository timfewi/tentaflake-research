//! One session's fixed job authority. Request futures may be cancelled, but
//! tracked HTTP/archive work is joined before the supervisor releases the job.
use super::{session::Broker, wire};
use crate::{
    archive::Source,
    error::{ErrorCode, Result},
    fetch::Fetcher,
    http::HttpResponse,
    provider::Context,
};
use serde::Serialize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Clone, Serialize)]
pub struct Receipt {
    pub source: Source,
    pub method: String,
    pub main_document: bool,
    pub redirects: u32,
    pub status: u16,
    pub error: Option<ErrorCode>,
}

pub struct JobBroker {
    fetcher: Arc<Fetcher>,
    context: Context,
    maximum: usize,
    requests: AtomicUsize,
    receipts: Arc<Mutex<Vec<Receipt>>>,
    work: TaskTracker,
}

impl JobBroker {
    pub fn new(fetcher: Arc<Fetcher>, context: Context, maximum: u32) -> Result<Self> {
        if maximum == 0 || maximum > 4096 {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            fetcher,
            context,
            maximum: maximum as usize,
            requests: AtomicUsize::new(0),
            receipts: Arc::new(Mutex::new(Vec::new())),
            work: TaskTracker::new(),
        })
    }

    pub fn receipts(&self) -> Result<Vec<Receipt>> {
        Ok(self
            .receipts
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .clone())
    }
}

#[async_trait::async_trait]
impl Broker for JobBroker {
    async fn request(
        &self,
        input: wire::HttpRequest,
        stop: CancellationToken,
    ) -> Result<HttpResponse> {
        if self.context.stop.is_cancelled() || stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        self.requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.maximum).then_some(count + 1)
            })
            .map_err(|_| ErrorCode::Capacity)?;
        let context = Context {
            owner: self.context.owner,
            job: self.context.job,
            deadline: self.context.deadline,
            stop: self.context.stop.child_token(),
        };
        let fetcher = self.fetcher.clone();
        let receipts = self.receipts.clone();
        let maximum = self.maximum;
        let guard = context.stop.clone().drop_guard();
        // The tracker retains this task even if the request's JoinHandle is
        // dropped. In particular, a started archive write must finish before
        // EvidenceStore::finish_job is allowed to delete strict-mode state.
        let result = self
            .work
            .spawn(async move {
                let (method, main_document, redirects) =
                    (input.method.clone(), input.main_document, input.redirects);
                let fetching = fetcher.browser_entity(&context, input);
                tokio::pin!(fetching);
                let entity = tokio::select! {
                    biased;
                    _ = stop.cancelled() => { context.stop.cancel(); let _ = fetching.await; return Err(ErrorCode::Cancelled); },
                    _ = context.stop.cancelled() => { let _ = fetching.await; return Err(ErrorCode::Cancelled); },
                    result = &mut fetching => result?,
                };
                let mut receipts = receipts.lock().map_err(|_| ErrorCode::Storage)?;
                if receipts.len() >= maximum {
                    return Err(ErrorCode::Capacity);
                }
                receipts.push(Receipt {
                    source: entity.source,
                    method,
                    main_document,
                    redirects,
                    status: entity.response.status,
                    error: entity.error,
                });
                if let Some(error) = entity.error {
                    return Err(error);
                }
                Ok(entity.response)
            })
            .await
            .map_err(|_| ErrorCode::WorkerFailed)?;
        guard.disarm();
        result
    }

    async fn drain(&self) {
        self.work.close();
        self.work.wait().await;
    }
}
