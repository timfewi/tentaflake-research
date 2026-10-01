//! Private browser worker loop. The service still owns policy, robots, budgets
//! and evidence; this process only executes fixed reading actions and asks for
//! checked HTTP entities over bounded IPC.
use super::{
    body::Bodies,
    cdp::{Cdp, Event},
    launch::{Launched, Settings},
    read::{PageSnapshot, Reader},
    request,
    targets::Targets,
    wire,
};
use crate::{
    config::ReadPostRule,
    error::{ErrorCode, Result},
    policy::PublicUrl,
    protocol::{read_frame, write_frame},
};
use base64::Engine;
use chromiumoxide::cdp::browser_protocol::{fetch, page};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSettings {
    pub launch: Settings,
    pub read_post_rules: Vec<ReadPostRule>,
    pub redirects: u32,
    pub response_bytes: u64,
    pub idle_seconds: u64,
    pub lifetime_seconds: u64,
}

impl WorkerSettings {
    pub fn validate(&self) -> Result<()> {
        self.launch.validate()?;
        if self.read_post_rules.len() > 64
            || self.redirects > 10
            || self.response_bytes == 0
            || self.response_bytes > super::body::MAX_BYTES
            || !(1..=300).contains(&self.idle_seconds)
            || !(1..=600).contains(&self.lifetime_seconds)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

struct Pending {
    session: String,
    request: String,
    main: bool,
    deadline: Instant,
    network: Option<String>,
    frame: String,
}

struct Reading {
    reader: Reader,
    opened: bool,
}

struct Worker {
    cdp: Arc<Cdp>,
    settings: WorkerSettings,
    targets: Targets,
    session: String,
    frame: String,
    responses: Bodies,
    output: Arc<Bodies>,
    pending: HashMap<u64, Pending>,
    cancelled: HashSet<u64>,
    inflight: HashMap<(String, String), String>,
    redirects: HashMap<(String, String), u32>,
    requests: u64,
    last_action: u64,
    errors: Vec<ErrorCode>,
    loaded: watch::Sender<Option<String>>,
    main_error: watch::Sender<Option<ErrorCode>>,
}

async fn send(output: &mut (impl AsyncWrite + Unpin), message: &wire::Output) -> Result<()> {
    timeout(Duration::from_secs(5), write_frame(output, message))
        .await
        .map_err(|_| ErrorCode::Timeout)?
}

/// Must be called inside the supervisor-created namespaces. All exits explicitly
/// stop CDP, kill/wait Chromium and join the worker's own tasks before returning.
pub async fn run<R, W>(
    settings: WorkerSettings,
    input: R,
    mut output: W,
    stop: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    settings.validate()?;
    let lifetime = Instant::now() + Duration::from_secs(settings.lifetime_seconds);
    let (launched, mut events) = Launched::start(&settings.launch, &stop).await?;
    let cdp = launched.cdp.clone();
    let (incoming, mut messages) = mpsc::channel(8);
    let mut inputs = JoinSet::new();
    inputs.spawn(async move {
        let mut input = input;
        loop {
            let message = read_frame::<_, wire::Input>(&mut input).await;
            let terminal = !matches!(message, Ok(Some(_)));
            if incoming.send(message).await.is_err() || terminal {
                break;
            }
        }
    });
    let mut actions = JoinSet::new();
    let mut writes = JoinSet::new();
    let work = async {
        let targets = Targets::create(cdp.clone(), &settings.launch, &mut events).await?;
        let session = targets.main_session().to_owned();
        let frame = cdp
            .command::<page::GetFrameTreeParams>(Some(&session), json!({}))
            .await?
            .frame_tree
            .frame
            .id
            .as_ref()
            .to_owned();
        let mut reading = Some(Reading {
            reader: Reader::new(cdp.clone(), session.clone(), settings.launch.html_bytes),
            opened: false,
        });
        let (loaded, _) = watch::channel(None);
        let (main_error, _) = watch::channel(None);
        let mut worker = Worker {
            cdp: cdp.clone(),
            settings,
            targets,
            session,
            frame,
            responses: Bodies::open(Path::new("/responses"))?,
            output: Arc::new(Bodies::open(Path::new("/output"))?),
            pending: HashMap::new(),
            cancelled: HashSet::new(),
            inflight: HashMap::new(),
            redirects: HashMap::new(),
            requests: 0,
            last_action: 0,
            errors: vec![],
            loaded,
            main_error,
        };
        send(
            &mut output,
            &wire::Output::Ready {
                version: crate::protocol::VERSION,
            },
        )
        .await?;
        let mut idle = Instant::now() + Duration::from_secs(worker.settings.idle_seconds);
        let stopped = cdp.stopped();
        loop {
            let request_deadline = worker
                .pending
                .values()
                .map(|request| request.deadline)
                .min()
                .unwrap_or(lifetime);
            tokio::select! {
                biased;
                _ = stopped.cancelled() => return Err(ErrorCode::WorkerFailed),
                _ = tokio::time::sleep_until(request_deadline), if !worker.pending.is_empty() => return Err(ErrorCode::Timeout),
                _ = tokio::time::sleep_until(idle), if actions.is_empty() => return Err(ErrorCode::SourceExpired),
                message = messages.recv() => {
                    match message.ok_or(ErrorCode::Cancelled)??.ok_or(ErrorCode::Cancelled)? {
                        wire::Input::Http { id, result } => worker.reply(id, result, &mut output).await?,
                        wire::Input::Action { id, action } => {
                            if id != worker.last_action + 1 { return Err(ErrorCode::InvalidRequest); }
                            worker.last_action = id;
                            if matches!(action, wire::Action::Close) { return Ok(Some(id)); }
                            if id > u64::from(worker.settings.launch.actions) { return Err(ErrorCode::BudgetExceeded); }
                            let Some(state) = reading.take() else {
                                send(&mut output, &wire::Output::Completed { id, result: Err(ErrorCode::Capacity) }).await?;
                                continue;
                            };
                            let cdp = cdp.clone();
                            let session = worker.session.clone();
                            let loaded = worker.loaded.subscribe();
                            let main_error = worker.main_error.subscribe();
                            let seconds = worker.settings.launch.operation_seconds;
                            actions.spawn(async move {
                                let mut state = state;
                                let result = timeout(Duration::from_secs(seconds), perform(&mut state, cdp, &session, action, loaded, main_error)).await.unwrap_or(Err(ErrorCode::Timeout));
                                (id, state, result)
                            });
                        }
                    }
                }
                event = events.recv() => {
                    let event = event.ok_or(ErrorCode::WorkerFailed)?;
                    timeout(Duration::from_secs(worker.settings.launch.operation_seconds), worker.event(event, &mut output)).await.map_err(|_| ErrorCode::Timeout)??;
                }
                Some(completed) = actions.join_next(), if !actions.is_empty() => {
                    let (id, state, result) = completed.map_err(|_| ErrorCode::WorkerFailed)?;
                    reading = Some(state);
                    idle = Instant::now() + Duration::from_secs(worker.settings.idle_seconds);
                    let result = match result {
                        Ok(mut snapshot) => {
                            snapshot.metadata.pending_requests = !worker.pending.is_empty() || !worker.inflight.is_empty();
                            snapshot.metadata.request_errors = worker.errors.clone();
                            snapshot.metadata.validate(worker.settings.launch.html_bytes)?;
                            let bodies = worker.output.clone();
                            let maximum = worker.settings.launch.html_bytes;
                            writes.spawn_blocking(move || {
                                bodies.write(id, &snapshot.html, maximum)?;
                                Ok::<_, ErrorCode>(snapshot.metadata)
                            });
                            writes.join_next().await.ok_or(ErrorCode::WorkerFailed)?.map_err(|_| ErrorCode::WorkerFailed)?
                        },
                        Err(error) => Err(error),
                    };
                    let fatal = matches!(result, Err(ErrorCode::Timeout | ErrorCode::WorkerFailed));
                    send(&mut output, &wire::Output::Completed { id, result: result.map(Some) }).await?;
                    if fatal { return Err(ErrorCode::WorkerFailed); }
                }
            }
        }
    };
    let result = tokio::select! {
        biased;
        _ = stop.cancelled() => Err(ErrorCode::Cancelled),
        result = timeout_at(lifetime, work) => result.unwrap_or(Err(ErrorCode::Timeout)),
    };
    inputs.abort_all();
    actions.abort_all();
    launched.close().await;
    while inputs.join_next().await.is_some() {}
    while actions.join_next().await.is_some() {}
    // Blocking local-file writes cannot be aborted once started. Retain their
    // handles independently of action futures and join them before Close ACK.
    while writes.join_next().await.is_some() {}
    if let Ok(Some(id)) = result {
        send(
            &mut output,
            &wire::Output::Completed {
                id,
                result: Ok(None),
            },
        )
        .await?;
    }
    if let Err(code) = result {
        let _ = send(&mut output, &wire::Output::Stopped { code }).await;
    }
    result.map(|_| ())
}

async fn perform(
    state: &mut Reading,
    cdp: Arc<Cdp>,
    session: &str,
    action: wire::Action,
    mut loaded: watch::Receiver<Option<String>>,
    main_error: watch::Receiver<Option<ErrorCode>>,
) -> Result<PageSnapshot> {
    let destination = match action {
        wire::Action::Open { url } => Some(PublicUrl::parse(&url)?),
        wire::Action::FollowLink { reference } if state.opened => {
            Some(state.reader.follow_link(&reference).await?)
        }
        wire::Action::Read if state.opened => None,
        wire::Action::Expand { reference } if state.opened => {
            state.reader.expand(&reference).await?;
            None
        }
        wire::Action::Scroll { direction } if state.opened => {
            state.reader.scroll(direction).await?;
            None
        }
        _ => return Err(ErrorCode::InvalidRequest),
    };
    if let Some(destination) = destination {
        state.opened = false;
        state.reader.invalidate();
        let navigation = cdp
            .command::<page::NavigateParams>(Some(session), json!({"url":destination.as_str()}))
            .await?;
        if navigation.error_text.is_some() {
            return Err((*main_error.borrow()).unwrap_or(ErrorCode::EgressUnavailable));
        }
        if let Some(loader) = navigation.loader_id {
            loop {
                if loaded.borrow().as_deref() == Some(loader.as_ref()) {
                    break;
                }
                loaded
                    .changed()
                    .await
                    .map_err(|_| ErrorCode::WorkerFailed)?;
            }
        }
        state.opened = true;
    }
    state.reader.read().await
}

impl Worker {
    fn error(&mut self, error: ErrorCode) {
        // Distinct fixed codes are bounded and remain visible on later reads.
        if !self.errors.contains(&error) {
            self.errors.push(error);
        }
    }

    async fn fail(&self, session: &str, request: &str) -> Result<()> {
        self.cdp
            .command::<fetch::FailRequestParams>(
                Some(session),
                json!({"requestId":request,"errorReason":"BlockedByClient"}),
            )
            .await?;
        Ok(())
    }

    async fn event(&mut self, event: Event, output: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        let navigation = if event.method == "Page.frameStartedNavigating"
            && self.targets.owns_session(event.session.as_deref())
            && !matches!(
                event.params["navigationType"].as_str(),
                Some("sameDocument" | "historySameDocument")
            ) {
            event.params["frameId"].as_str()
        } else {
            None
        };
        let detached = (event.method == "Target.detachedFromTarget")
            .then(|| event.params["sessionId"].as_str())
            .flatten();
        let failed = (event.method == "Network.loadingFailed")
            .then(|| event.params["requestId"].as_str())
            .flatten();
        self.inflight.retain(|(session, _), frame| {
            detached != Some(session.as_str())
                && !navigation
                    .is_some_and(|navigated| navigated == self.frame || navigated == frame)
        });
        if self.targets.owns_session(event.session.as_deref()) {
            if event.method == "Network.requestWillBeSent" {
                let request = event.params["requestId"]
                    .as_str()
                    .ok_or(ErrorCode::WorkerFailed)?;
                if self.inflight.len() >= self.settings.launch.requests as usize {
                    return Err(ErrorCode::Capacity);
                }
                self.inflight.insert(
                    (
                        event.session.clone().ok_or(ErrorCode::WorkerFailed)?,
                        request.to_owned(),
                    ),
                    event.params["frameId"].as_str().unwrap_or("").to_owned(),
                );
            } else if matches!(
                event.method.as_str(),
                "Network.loadingFinished" | "Network.loadingFailed"
            ) {
                let request = event.params["requestId"]
                    .as_str()
                    .ok_or(ErrorCode::WorkerFailed)?;
                self.inflight.remove(&(
                    event.session.clone().ok_or(ErrorCode::WorkerFailed)?,
                    request.to_owned(),
                ));
                if event.method == "Network.loadingFailed" && event.params["canceled"] != true {
                    self.error(if event.params.get("blockedReason").is_some() {
                        ErrorCode::PolicyDenied
                    } else {
                        ErrorCode::EgressUnavailable
                    });
                }
            }
        }
        let obsolete: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, request)| {
                navigation.is_some_and(|frame| frame == self.frame || frame == request.frame)
                    || detached == Some(request.session.as_str())
                    || (failed.is_some()
                        && event.session.as_deref() == Some(request.session.as_str())
                        && failed == request.network.as_deref())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in obsolete {
            let pending = self.pending.remove(&id).ok_or(ErrorCode::WorkerFailed)?;
            self.cancelled.insert(id);
            if navigation.is_some() {
                // Chromium can remove the old interception concurrently with
                // navigation. Either outcome retires this known request; its
                // response must never be delivered into the next document.
                let _ = self.fail(&pending.session, &pending.request).await;
            }
            send(output, &wire::Output::CancelHttp { id }).await?;
        }
        let blocked = self.targets.blocked_targets;
        if self.targets.handle(&event).await? {
            if self.targets.blocked_targets != blocked {
                self.error(ErrorCode::PolicyDenied);
            }
            if event.method == "Fetch.authRequired" {
                self.error(ErrorCode::AccessBlocked);
            }
            return Ok(());
        }
        if event.method == "Page.lifecycleEvent"
            && event.session.as_deref() == Some(&self.session)
            && event.params["frameId"].as_str() == Some(&self.frame)
            && event.params["name"] == "DOMContentLoaded"
        {
            let loader = event.params["loaderId"]
                .as_str()
                .ok_or(ErrorCode::WorkerFailed)?
                .to_owned();
            self.loaded.send_replace(Some(loader));
        }
        if event.method != "Fetch.requestPaused" {
            return Ok(());
        }
        if !self.targets.owns_session(event.session.as_deref()) {
            return Err(ErrorCode::PolicyDenied);
        }
        let session = event.session.ok_or(ErrorCode::WorkerFailed)?;
        let paused: fetch::EventRequestPaused =
            serde_json::from_value(event.params).map_err(|_| ErrorCode::WorkerFailed)?;
        self.requests += 1;
        if self.requests > u64::from(self.settings.launch.requests) {
            return Err(ErrorCode::BudgetExceeded);
        }
        let main =
            paused.frame_id.as_ref() == self.frame && paused.resource_type.as_ref() == "Document";
        if main {
            self.main_error.send_replace(None);
        }
        let depth = match paused.redirected_request_id {
            Some(previous) => {
                self.redirects
                    .get(&(session.clone(), previous.as_ref().to_owned()))
                    .ok_or(ErrorCode::InvalidResponse)?
                    + 1
            }
            None => 0,
        };
        let id = paused.request_id.as_ref().to_owned();
        self.redirects.insert((session.clone(), id.clone()), depth);
        let checked =
            request::from_cdp(&paused.request, paused.resource_type.as_ref(), main, depth)
                .and_then(|request| {
                    request::check(&request, &self.settings.read_post_rules)?;
                    Ok(request)
                });
        let checked = if depth > self.settings.redirects {
            Err(ErrorCode::BudgetExceeded)
        } else {
            checked
        };
        let checked = match checked {
            Ok(request) if self.pending.len() < 8 => request,
            Ok(_) => {
                self.error(ErrorCode::Capacity);
                self.fail(&session, &id).await?;
                return Ok(());
            }
            Err(error) => {
                self.error(error);
                if main {
                    self.main_error.send_replace(Some(error));
                }
                self.fail(&session, &id).await?;
                return Ok(());
            }
        };
        self.pending.insert(
            self.requests,
            Pending {
                session,
                request: id,
                main,
                deadline: Instant::now()
                    + Duration::from_secs(self.settings.launch.operation_seconds),
                network: paused.network_id.map(|id| id.as_ref().to_owned()),
                frame: paused.frame_id.as_ref().to_owned(),
            },
        );
        send(
            output,
            &wire::Output::Http {
                id: self.requests,
                request: checked,
            },
        )
        .await
    }

    async fn reply(
        &mut self,
        id: u64,
        result: Result<wire::HttpReply>,
        output: &mut (impl AsyncWrite + Unpin),
    ) -> Result<()> {
        // Cancellation and a completed service fetch can cross in the pipes.
        // Acknowledge that one late result for cleanup without feeding it to CDP.
        if self.cancelled.remove(&id) {
            send(output, &wire::Output::Consumed { id }).await?;
            return Ok(());
        }
        let pending = self.pending.remove(&id).ok_or(ErrorCode::InvalidRequest)?;
        match result {
            Err(error) => {
                self.error(error);
                if pending.main {
                    self.main_error.send_replace(Some(error));
                }
                self.fail(&pending.session, &pending.request).await?;
                send(output, &wire::Output::Consumed { id }).await?;
            }
            Ok(reply) => {
                reply.validate(self.settings.response_bytes)?;
                let bytes = self.responses.read(
                    id,
                    reply.body_bytes,
                    &reply.body_sha256,
                    self.settings.response_bytes,
                )?;
                self.cdp.command::<fetch::FulfillRequestParams>(Some(&pending.session), json!({
                    "requestId":pending.request,"responseCode":reply.status,
                    "responseHeaders":reply.headers.iter().map(|(name,value)|json!({"name":name,"value":value})).collect::<Vec<_>>(),
                    "body":base64::engine::general_purpose::STANDARD.encode(bytes),
                })).await?;
                send(output, &wire::Output::Consumed { id }).await?;
            }
        }
        Ok(())
    }
}
