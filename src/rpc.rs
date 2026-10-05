//! Bounded Unix RPC. A dedicated reader owns each frame until completion; task
//! completion and cancellation cannot discard a partially consumed frame.

use crate::diagnostics::{self, Component, Event};
use crate::egress::{EgressMode, EgressState, control_state_diagnostic};
use crate::error::{ErrorCode, Result};
use crate::protocol::{self, Operation, Outcome, Request, Response, VERSION};
use crate::service::Service;
use crate::socket;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn serve(
    listener: UnixListener,
    service: Arc<Service>,
    control: &Path,
    stop: CancellationToken,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(service.limits().rpc_connections));
    let mut connections = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut maintenance = tokio::time::interval(Duration::from_secs(60));
    let mut control_issue = None;
    let mut observed_generation = None;
    let result = loop {
        tokio::select! {
            _ = stop.cancelled() => break Ok(()),
            _ = maintenance.tick() => {
                if let Err(error) = service.maintenance().await { break Err(error); }
            }
            _ = tick.tick() => {
                let state = match control_state_diagnostic(control) {
                    Ok(state) => {
                        control_issue = None;
                        if state.mode != EgressMode::Offline {
                            if observed_generation.is_some_and(|generation| generation != state.generation) {
                                diagnostics::emit(Component::Service, Event::GenerationChanged);
                            }
                            observed_generation = Some(state.generation);
                        }
                        state
                    }
                    Err(issue) => {
                        if control_issue != Some(issue) {
                            diagnostics::emit(Component::Service, control_event(issue));
                            control_issue = Some(issue);
                        }
                        EgressState::offline()
                    }
                };
                if let Err(error) = service.update_egress(state).await { break Err(error); }
                if let Err(error) = service.expire().await { break Err(error); }
            }
            accepted = listener.accept() => {
                let (socket, _) = match accepted { Ok(pair) => pair, Err(_) => break Err(ErrorCode::WorkerFailed) };
                let permit = match slots.clone().try_acquire_owned() { Ok(permit) => permit, Err(_) => continue };
                let service = service.clone();
                let stop = stop.child_token();
                connections.spawn(async move { let _permit = permit; connection(socket, service, stop).await });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if result.is_err() { break Err(ErrorCode::WorkerFailed); }
            }
        }
    };
    stop.cancel();
    while connections.join_next().await.is_some() {}
    service.shutdown().await?;
    result
}

fn control_event(issue: crate::egress::LeaseReadError) -> Event {
    match issue {
        crate::egress::LeaseReadError::Unavailable => Event::ControlLeaseUnavailable,
        crate::egress::LeaseReadError::Invalid => Event::ControlLeaseInvalid,
        crate::egress::LeaseReadError::Expired => Event::ControlLeaseExpired,
    }
}

pub async fn connection(
    socket: UnixStream,
    service: Arc<Service>,
    stop: CancellationToken,
) -> Result<()> {
    let owner = socket::authorized_peer(&socket, service.allowed_uids())?;
    let connection_id = Uuid::new_v4();
    let stop = stop.child_token();
    let _stop_on_drop = stop.clone().drop_guard();
    let (mut reader, mut writer) = socket.into_split();
    let (input, mut incoming) = mpsc::channel(16);
    let reader_stop = stop.clone();
    let reading = tokio::spawn(async move {
        loop {
            let request = protocol::read_frame::<_, Request>(&mut reader).await;
            let end = !matches!(request, Ok(Some(_)));
            if input.send(request).await.is_err() || end {
                break;
            }
        }
        reader_stop.cancel();
    });
    let (output, mut outgoing) = mpsc::channel::<Response>(32);
    let writer_stop = stop.clone();
    let writing = tokio::spawn(async move {
        while let Some(response) = outgoing.recv().await {
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    protocol::write_frame(&mut writer, &response)
                )
                .await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        writer_stop.cancel();
    });
    let mut last_id = 0;
    let mut hello = false;
    let hello_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut calls = JoinSet::new();
    let mut requests: HashMap<u64, CancellationToken> = HashMap::new();
    let result = loop {
        tokio::select! {
            _ = stop.cancelled() => break Ok(()),
            _ = tokio::time::sleep_until(hello_deadline), if !hello => break Err(ErrorCode::Timeout),
            Some(result) = calls.join_next(), if !calls.is_empty() => {
                match result { Ok(id) => { requests.remove(&id); }, Err(_) => break Err(ErrorCode::WorkerFailed) }
            }
            message = incoming.recv() => {
                let request = match message { Some(Ok(Some(request))) => request, Some(Ok(None)) | None => break Ok(()), Some(Err(error)) => break Err(error) };
                if request.version != VERSION {
                    let _ = output.send(Response { version: VERSION, id: request.id, outcome: Outcome::Error { code: ErrorCode::ProtocolVersion } }).await;
                    break Err(ErrorCode::ProtocolVersion);
                }
                if request.id <= last_id { break Err(ErrorCode::InvalidRequest); }
                last_id = request.id;
                if !hello && !matches!(request.operation, Operation::Hello) { break Err(ErrorCode::ProtocolVersion); }
                let outcome = match request.operation {
                    Operation::Hello if !hello => {
                        hello = true;
                        Outcome::Result { value: json!({"version":VERSION,"max_frame":protocol::MAX_FRAME,"tools":protocol::TOOLS}) }
                    }
                    Operation::Hello => break Err(ErrorCode::InvalidRequest),
                    Operation::Cancel { request_id } => {
                        let found = requests.get(&request_id);
                        if let Some(stop) = found { stop.cancel(); }
                        Outcome::Result { value: json!({"cancelled":found.is_some()}) }
                    }
                    Operation::Call { tool, arguments } => {
                        if requests.len() >= service.limits().rpc_requests { Outcome::Error { code: ErrorCode::Capacity } }
                        else {
                            let request_stop = stop.child_token();
                            requests.insert(request.id, request_stop.clone());
                            let service = service.clone();
                            let output = output.clone();
                            let connection_stop = stop.clone();
                            calls.spawn(async move {
                                let outcome = match service.call(owner, connection_id, tool, arguments.clone(), request_stop).await {
                                    Ok(value) => Outcome::Result { value },
                                    Err(code) => {
                                        let failure = service.failure(tool, &arguments, code);
                                        // Detailed failures fit the existing v1 JSON result
                                        // envelope; the MCP adapter marks them as errors.
                                        if failure.details.is_some() {
                                            Outcome::Result { value: json!(failure) }
                                        } else {
                                            Outcome::Error { code: failure.code }
                                        }
                                    },
                                };
                                tokio::select! { _ = connection_stop.cancelled() => (), _ = output.send(Response { version: VERSION, id: request.id, outcome }) => () }
                                request.id
                            });
                            continue;
                        }
                    }
                };
                if output.send(Response { version: VERSION, id: request.id, outcome }).await.is_err() { break Err(ErrorCode::Cancelled); }
            }
        }
    };
    stop.cancel();
    // Only the socket reader may be aborted. Operations cooperate with tokens
    // and are joined before job archives and worker profiles are removed.
    reading.abort();
    let _ = reading.await;
    for token in requests.values() {
        token.cancel();
    }
    while calls.join_next().await.is_some() {}
    service.disconnect(connection_id).await?;
    drop(output);
    let _ = writing.await;
    result
}
