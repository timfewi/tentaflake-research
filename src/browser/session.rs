//! Service-side worker supervision. A Broker is constructed for one authorized
//! job; worker messages cannot choose its owner, credentials, budgets or store.
use super::{
    body::Bodies,
    engine::WorkerSettings,
    read::PageSnapshot,
    request,
    sandbox::{SandboxConfig, Workspace},
    wire,
};
use crate::{
    diagnostics::{self, Component, Event},
    error::{ErrorCode, Result},
    http::HttpResponse,
    protocol::{read_frame, write_frame},
};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use tokio::{
    process::{Child, ChildStdin},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[async_trait::async_trait]
pub trait Broker: Send + Sync {
    /// Implementations must use the job's protected transport, account before
    /// IO, enforce robots and retain raw evidence as appropriate. Cancellation
    /// applies to this request only; the broker owns no worker-provided paths.
    async fn request(
        &self,
        request: wire::HttpRequest,
        stop: CancellationToken,
    ) -> Result<HttpResponse>;

    /// Called after all request futures end, including aborted futures. Brokers
    /// that start non-abortable archive IO must retain and join that work here.
    async fn drain(&self) {}
}

pub struct Pool {
    permits: Arc<Semaphore>,
}

fn finish_workspace_cleanup<T>(
    cleanup: std::io::Result<()>,
    permit: OwnedSemaphorePermit,
    result: Result<T>,
) -> Result<T> {
    match cleanup {
        Ok(()) => {
            drop(permit);
            result
        }
        Err(_) => {
            diagnostics::emit(Component::Service, Event::BrowserWorkspaceCleanupFailed);
            permit.forget();
            Err(ErrorCode::Storage)
        }
    }
}

impl Pool {
    pub fn new(maximum: usize) -> Result<Self> {
        if !(1..=32).contains(&maximum) {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(maximum)),
        })
    }

    pub async fn start(
        &self,
        sandbox: &SandboxConfig,
        settings: WorkerSettings,
        temporary: &Path,
        broker: Arc<dyn Broker>,
        job_stop: &CancellationToken,
    ) -> Result<Session> {
        sandbox.validate()?;
        settings.validate()?;
        if job_stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::Capacity)?;
        let mut workspace = Workspace::new(temporary)?;
        let prepared = (|| -> Result<_> {
            let bytes = serde_json::to_vec(&settings).map_err(|_| ErrorCode::InvalidRequest)?;
            if bytes.len() > 64 * 1024 {
                return Err(ErrorCode::SizeLimit);
            }
            // This directory is private and has not yet been exposed to the worker.
            std::fs::write(workspace.root().join("responses/config.json"), bytes)
                .map_err(|_| ErrorCode::Storage)?;
            let responses = Arc::new(Bodies::open(&workspace.root().join("responses"))?);
            let snapshots = Arc::new(Bodies::open(&workspace.root().join("output"))?);
            let mut command = workspace.command(sandbox, Some(&settings.launch.timezone))?;
            command.args(["--", "/worker"]);
            Ok((responses, snapshots, command))
        })();
        let (responses, snapshots, mut command) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return finish_workspace_cleanup(workspace.close(), permit, Err(error));
            }
        };
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                return finish_workspace_cleanup(
                    workspace.close(),
                    permit,
                    Err(ErrorCode::WorkerFailed),
                );
            }
        };
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return finish_workspace_cleanup(
                workspace.close(),
                permit,
                Err(ErrorCode::WorkerFailed),
            );
        };
        let (commands, calls) = mpsc::channel(1);
        let (done, closed) = watch::channel(None);
        let (ready, started) = oneshot::channel();
        let stop = job_stop.child_token();
        let session = Session {
            commands,
            stop: stop.clone(),
            closed,
        };
        let (incoming, messages) = mpsc::channel(8);
        let mut readers = JoinSet::new();
        readers.spawn(async move {
            let mut output = output;
            loop {
                let message = read_frame::<_, wire::Output>(&mut output).await;
                let terminal = !matches!(message, Ok(Some(_)));
                if incoming.send(message).await.is_err() || terminal {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut actor = Actor {
                settings,
                broker,
                stop,
                input: Some(input),
                calls,
                messages,
                responses,
                snapshots,
                pending: HashMap::new(),
                active: None,
                last_action: 0,
                last_request: 0,
                ready: Some(ready),
                http: JoinSet::new(),
                files: JoinSet::new(),
                readers,
            };
            actor.run(child, workspace, permit, done).await;
        });
        let result = started.await.unwrap_or(Err(ErrorCode::WorkerFailed));
        if let Err(error) = result {
            session.close().await;
            // Startup failure is not the final outcome if scratch cleanup also
            // failed. The latter keeps capacity withheld and must be visible.
            return Err(if *session.closed.borrow() == Some(ErrorCode::Storage) {
                ErrorCode::Storage
            } else {
                error
            });
        }
        Ok(session)
    }
}

pub struct Session {
    commands: mpsc::Sender<Call>,
    stop: CancellationToken,
    closed: watch::Receiver<Option<ErrorCode>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Session {
    pub fn is_closed(&self) -> bool {
        self.stop.is_cancelled() || self.closed.borrow().is_some()
    }

    pub async fn close(&self) {
        self.stop.cancel();
        let mut closed = self.closed.clone();
        let _ = closed.wait_for(Option::is_some).await;
    }

    pub async fn execute(
        &self,
        action: wire::Action,
        cancelled: &CancellationToken,
    ) -> Result<Option<PageSnapshot>> {
        if let Some(error) = *self.closed.borrow() {
            return Err(error);
        }
        if cancelled.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .try_send(Call { action, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ErrorCode::Capacity,
                mpsc::error::TrySendError::Closed(_) => ErrorCode::JobClosed,
            })?;
        // Dropping a caller future also stops its worker. The actor retains all
        // cleanup handles and the pool permit until shutdown has actually ended.
        let guard = self.stop.clone().drop_guard();
        let result = tokio::select! {
            biased;
            result = result => result.unwrap_or(Err(ErrorCode::WorkerFailed)),
            _ = cancelled.cancelled() => { self.close().await; Err(ErrorCode::Cancelled) },
        };
        guard.disarm();
        result
    }
}

struct Call {
    action: wire::Action,
    reply: oneshot::Sender<Result<Option<PageSnapshot>>>,
}
struct Active {
    id: u64,
    close: bool,
    receiving: bool,
    deadline: Instant,
    reply: oneshot::Sender<Result<Option<PageSnapshot>>>,
}
#[derive(PartialEq)]
enum Phase {
    Fetching,
    Writing,
    Delivered,
}
struct Pending {
    stop: CancellationToken,
    phase: Phase,
    cancelled: bool,
    file: bool,
}
enum FileResult {
    Reply(u64, Result<wire::HttpReply>),
    Snapshot(u64, Result<PageSnapshot>),
}
struct Actor {
    settings: WorkerSettings,
    broker: Arc<dyn Broker>,
    stop: CancellationToken,
    input: Option<ChildStdin>,
    calls: mpsc::Receiver<Call>,
    messages: mpsc::Receiver<Result<Option<wire::Output>>>,
    responses: Arc<Bodies>,
    snapshots: Arc<Bodies>,
    pending: HashMap<u64, Pending>,
    active: Option<Active>,
    last_action: u64,
    last_request: u64,
    ready: Option<oneshot::Sender<Result<()>>>,
    http: JoinSet<(u64, Result<HttpResponse>)>,
    files: JoinSet<FileResult>,
    readers: JoinSet<()>,
}

impl Actor {
    async fn send(&mut self, message: wire::Input) -> Result<()> {
        timeout(
            Duration::from_secs(5),
            write_frame(
                self.input.as_mut().ok_or(ErrorCode::WorkerFailed)?,
                &message,
            ),
        )
        .await
        .map_err(|_| ErrorCode::Timeout)?
    }

    async fn run(
        &mut self,
        mut child: Child,
        mut workspace: Workspace,
        permit: OwnedSemaphorePermit,
        done: watch::Sender<Option<ErrorCode>>,
    ) {
        let lifetime = Instant::now() + Duration::from_secs(self.settings.lifetime_seconds);
        let initialized =
            Instant::now() + Duration::from_secs(self.settings.launch.operation_seconds + 15);
        let stopped = self.stop.clone();
        let work = async {
            loop {
                let deadline = if self.ready.is_some() {
                    initialized.min(lifetime)
                } else {
                    self.active
                        .as_ref()
                        .map_or(lifetime, |active| active.deadline.min(lifetime))
                };
                tokio::select! {
                    biased;
                    _ = stopped.cancelled() => return Err(ErrorCode::Cancelled),
                    _ = tokio::time::sleep_until(deadline) => return Err(ErrorCode::Timeout),
                    call = self.calls.recv(), if self.ready.is_none() => {
                        let call = call.ok_or(ErrorCode::Cancelled)?;
                        if self.active.is_some() { let _ = call.reply.send(Err(ErrorCode::Capacity)); continue; }
                        self.last_action += 1;
                        let id = self.last_action;
                        let close = matches!(call.action, wire::Action::Close);
                        if id > u64::from(self.settings.launch.actions) && !close { let _ = call.reply.send(Err(ErrorCode::BudgetExceeded)); return Err(ErrorCode::BudgetExceeded); }
                        self.active = Some(Active { id, close, receiving: false, reply: call.reply,
                            deadline: Instant::now() + Duration::from_secs(self.settings.launch.operation_seconds + 5) });
                        self.send(wire::Input::Action { id, action: call.action }).await?;
                    }
                    message = self.messages.recv() => {
                        let message = message.ok_or(ErrorCode::WorkerFailed)??.ok_or(ErrorCode::WorkerFailed)?;
                        if self.message(message).await? { return Ok(()); }
                    }
                    Some(result) = self.http.join_next(), if !self.http.is_empty() => {
                        let (id, result) = result.map_err(|_| ErrorCode::WorkerFailed)?;
                        self.fetched(id, result).await?;
                    }
                    Some(result) = self.files.join_next(), if !self.files.is_empty() => {
                        self.file(result.map_err(|_| ErrorCode::WorkerFailed)?).await?;
                    }
                }
            }
        };
        let result = timeout_at(lifetime, work)
            .await
            .unwrap_or(Err(ErrorCode::Timeout));
        self.stop.cancel();
        for request in self.pending.values() {
            request.stop.cancel();
        }
        // EOF asks the worker to close Chromium and lets Bubblewrap's namespace
        // reaper finish normally. Killing the outer Bubblewrap process first
        // can race descendant teardown with removal of shared scratch files.
        drop(self.input.take());
        if !matches!(
            timeout(Duration::from_secs(5), child.wait()).await,
            Ok(Ok(_))
        ) {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.readers.abort_all();
        while self.readers.join_next().await.is_some() {}
        let cooperative = async { while self.http.join_next().await.is_some() {} };
        if timeout(Duration::from_secs(5), cooperative).await.is_err() {
            self.http.abort_all();
            while self.http.join_next().await.is_some() {}
        }
        self.broker.drain().await;
        // A started filesystem task cannot be aborted safely. It retains only
        // private directory descriptors; join before dropping the workspace.
        while self.files.join_next().await.is_some() {}
        self.pending.clear();
        // Cleanup is part of the security boundary: do not let `TempDir::drop`
        // silently report success. Only release the pool permit when the
        // scratch tree is actually gone, so sensitive evidence cannot be reused
        // over. A maintenance-based retry is possible future work; for now a
        // persistent failure keeps this capacity out of the pool until restart.
        let result = finish_workspace_cleanup(workspace.close(), permit, result);
        let terminal = result.err().unwrap_or(ErrorCode::JobClosed);
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(Err(terminal));
        }
        if let Some(active) = self.active.take() {
            let answer = if result.is_ok() && active.close {
                Ok(None)
            } else {
                Err(terminal)
            };
            let _ = active.reply.send(answer);
        }
        while let Ok(call) = self.calls.try_recv() {
            let _ = call.reply.send(Err(terminal));
        }
        done.send_replace(Some(terminal));
    }

    async fn message(&mut self, message: wire::Output) -> Result<bool> {
        if let Some(ready) = self.ready.take() {
            if matches!(
                message,
                wire::Output::Ready {
                    version: crate::protocol::VERSION
                }
            ) {
                let _ = ready.send(Ok(()));
                return Ok(false);
            }
            self.ready = Some(ready);
            return Err(ErrorCode::ProtocolVersion);
        }
        match message {
            wire::Output::Http { id, request: input } => {
                if id <= self.last_request
                    || id > u64::from(self.settings.launch.requests)
                    || self.pending.len() >= 8
                    || input.redirects > self.settings.redirects
                {
                    return Err(ErrorCode::InvalidRequest);
                }
                self.last_request = id;
                request::check(&input, &self.settings.read_post_rules)?;
                let stop = self.stop.child_token();
                self.pending.insert(
                    id,
                    Pending {
                        stop: stop.clone(),
                        phase: Phase::Fetching,
                        cancelled: false,
                        file: false,
                    },
                );
                let broker = self.broker.clone();
                self.http
                    .spawn(async move { (id, broker.request(input, stop).await) });
            }
            wire::Output::Consumed { id } => {
                let pending = self.pending.remove(&id).ok_or(ErrorCode::InvalidRequest)?;
                if pending.phase != Phase::Delivered {
                    return Err(ErrorCode::InvalidRequest);
                }
                if pending.file {
                    self.responses.remove(id)?;
                }
            }
            wire::Output::CancelHttp { id } => {
                let pending = self.pending.get_mut(&id).ok_or(ErrorCode::InvalidRequest)?;
                if pending.cancelled {
                    return Err(ErrorCode::InvalidRequest);
                }
                pending.cancelled = true;
                pending.stop.cancel();
            }
            wire::Output::Completed { id, result } => {
                let active = self.active.as_mut().ok_or(ErrorCode::InvalidRequest)?;
                if active.id != id || active.receiving {
                    return Err(ErrorCode::InvalidRequest);
                }
                match result {
                    Ok(None) if active.close => return Ok(true),
                    Ok(Some(snapshot)) if !active.close => {
                        active.receiving = true;
                        snapshot.validate(self.settings.launch.html_bytes)?;
                        let bodies = self.snapshots.clone();
                        let maximum = self.settings.launch.html_bytes;
                        self.files.spawn_blocking(move || {
                            FileResult::Snapshot(
                                id,
                                (|| {
                                    let html = bodies.read(
                                        id,
                                        snapshot.html_bytes,
                                        &snapshot.html_sha256,
                                        maximum,
                                    )?;
                                    bodies.remove(id)?;
                                    Ok(PageSnapshot {
                                        metadata: snapshot,
                                        html,
                                    })
                                })(),
                            )
                        });
                    }
                    Err(
                        error @ (ErrorCode::Timeout
                        | ErrorCode::WorkerFailed
                        | ErrorCode::Cancelled),
                    ) => return Err(error),
                    Err(error) => {
                        let active = self.active.take().ok_or(ErrorCode::InvalidRequest)?;
                        let _ = active.reply.send(Err(error));
                    }
                    _ => return Err(ErrorCode::InvalidRequest),
                }
            }
            wire::Output::Stopped { code } => return Err(code),
            wire::Output::Ready { .. } => return Err(ErrorCode::ProtocolVersion),
        }
        Ok(false)
    }

    async fn fetched(&mut self, id: u64, result: Result<HttpResponse>) -> Result<()> {
        let pending = self.pending.get_mut(&id).ok_or(ErrorCode::InvalidRequest)?;
        if pending.phase != Phase::Fetching {
            return Err(ErrorCode::InvalidRequest);
        }
        if pending.cancelled {
            pending.phase = Phase::Delivered;
            return self
                .send(wire::Input::Http {
                    id,
                    result: Err(ErrorCode::Cancelled),
                })
                .await;
        }
        match result {
            Err(error) => {
                pending.phase = Phase::Delivered;
                self.send(wire::Input::Http {
                    id,
                    result: Err(error),
                })
                .await?;
            }
            Ok(response) => {
                pending.phase = Phase::Writing;
                let bodies = self.responses.clone();
                let maximum = self.settings.response_bytes;
                self.files.spawn_blocking(move || {
                    FileResult::Reply(
                        id,
                        (|| {
                            let reply = wire::HttpReply::from_response(&response, maximum)?;
                            bodies.write(id, &response.body, maximum)?;
                            Ok(reply)
                        })(),
                    )
                });
            }
        }
        Ok(())
    }

    async fn file(&mut self, result: FileResult) -> Result<()> {
        match result {
            FileResult::Reply(id, result) => {
                let pending = self.pending.get_mut(&id).ok_or(ErrorCode::InvalidRequest)?;
                if pending.phase != Phase::Writing {
                    return Err(ErrorCode::InvalidRequest);
                }
                pending.phase = Phase::Delivered;
                pending.file = result.is_ok();
                self.send(wire::Input::Http { id, result }).await?;
            }
            FileResult::Snapshot(id, result) => {
                if let Err(error) = &result {
                    return Err(*error);
                }
                let active = self.active.take().ok_or(ErrorCode::InvalidRequest)?;
                if active.id != id || active.close {
                    return Err(ErrorCode::InvalidRequest);
                }
                let _ = active.reply.send(result.map(Some));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_result_controls_startup_error_and_pool_capacity() {
        let pool = Arc::new(Semaphore::new(1));
        let permit = pool.clone().try_acquire_owned().unwrap();
        let result: Result<()> =
            finish_workspace_cleanup(Ok(()), permit, Err(ErrorCode::WorkerFailed));
        assert_eq!(result, Err(ErrorCode::WorkerFailed));
        assert_eq!(pool.available_permits(), 1);

        let permit = pool.clone().try_acquire_owned().unwrap();
        let result: Result<()> = finish_workspace_cleanup(
            Err(std::io::Error::other("synthetic cleanup failure")),
            permit,
            Err(ErrorCode::WorkerFailed),
        );
        assert_eq!(result, Err(ErrorCode::Storage));
        assert_eq!(pool.available_permits(), 0);
    }
}
