//! Bounded CDP transport for chromiumoxide's typed commands. The upstream high
//! level handler automatically resumes child targets and detaches service
//! workers, and its websocket has no message-size cap. This dispatcher leaves
//! attachment/resumption to our policy and retains Chromium's site isolation.

use crate::error::{ErrorCode, Result};
use async_tungstenite::{
    WebSocketStream,
    tokio::ConnectStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use chromiumoxide_types::Command;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MAX_MESSAGE: usize = 64 * 1024 * 1024;
// A bounded 32 MiB HTTP entity needs roughly 43 MiB in CDP's base64 field.
const MAX_COMMAND: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct QueueLimits {
    command: usize,
    response: usize,
    event: usize,
    events: usize,
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            command: MAX_COMMAND,
            response: MAX_MESSAGE,
            event: 1024 * 1024,
            events: 4 * 1024 * 1024,
        }
    }
}

fn retain_bytes(budget: &Arc<Semaphore>, bytes: usize) -> Result<OwnedSemaphorePermit> {
    budget
        .clone()
        .try_acquire_many_owned(u32::try_from(bytes).map_err(|_| ErrorCode::SizeLimit)?)
        .map_err(|_| ErrorCode::Capacity)
}

struct Payload {
    text: String,
    // The receiver owns the permit through deserialization. Sending a response
    // does not release its byte allowance while the caller still retains it.
    _bytes: OwnedSemaphorePermit,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(rename = "sessionId")]
    pub session: Option<String>,
    #[serde(skip)]
    _bytes: Option<OwnedSemaphorePermit>,
}

#[derive(Serialize)]
struct Call<'a, T> {
    id: u64,
    method: &'a str,
    params: T,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    session: Option<&'a str>,
}
struct Queued {
    id: u64,
    payload: Payload,
    session: Option<String>,
    reply: oneshot::Sender<Result<Payload>>,
}
struct Pending {
    session: Option<String>,
    reply: oneshot::Sender<Result<Payload>>,
}

// Borrow response data without materializing a page-controlled Value tree.
// Events have their smaller size/aggregate limits checked before decoding.
#[derive(Deserialize)]
struct Envelope<'a> {
    id: Option<u64>,
    #[serde(rename = "sessionId")]
    session: Option<&'a str>,
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    #[serde(borrow)]
    error: Option<&'a RawValue>,
}

pub struct Cdp {
    commands: mpsc::Sender<Queued>,
    stop: CancellationToken,
    timeout: Duration,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    command_bytes: Arc<Semaphore>,
    next_id: AtomicU64,
    limits: QueueLimits,
}
impl Drop for Cdp {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Cdp {
    /// Only service-authored command types and parameters use this helper.
    /// Neither the method nor its parameters are exposed through the MCP API.
    pub async fn command<T: Command + serde::de::DeserializeOwned>(
        &self,
        session: Option<&str>,
        params: Value,
    ) -> Result<T::Response> {
        self.call(
            session,
            serde_json::from_value::<T>(params).map_err(|_| ErrorCode::WorkerFailed)?,
        )
        .await
    }
    /// The endpoint comes from the supervised child's DevTools startup line,
    /// never a page, tool argument or external discovery endpoint.
    pub async fn connect(
        endpoint: &str,
        timeout: Duration,
        stop: CancellationToken,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        Self::connect_bounded(endpoint, timeout, stop, QueueLimits::default()).await
    }

    async fn connect_bounded(
        endpoint: &str,
        timeout: Duration,
        stop: CancellationToken,
        limits: QueueLimits,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        let endpoint = url::Url::parse(endpoint).map_err(|_| ErrorCode::WorkerFailed)?;
        if endpoint.scheme() != "ws"
            || endpoint.host_str() != Some("127.0.0.1")
            || endpoint.port().is_none()
            || !endpoint.path().starts_with("/devtools/browser/")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ErrorCode::WorkerFailed);
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE))
            .max_write_buffer_size(MAX_MESSAGE);
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(5),
            async_tungstenite::tokio::connect_async_with_config(endpoint.as_str(), Some(config)),
        )
        .await
        .map_err(|_| ErrorCode::Timeout)?
        .map_err(|_| ErrorCode::WorkerFailed)?;
        let (commands, incoming) = mpsc::channel(64);
        let (events, outgoing) = mpsc::channel(128);
        let stop = stop.child_token();
        let task = tokio::spawn(run(socket, incoming, events, stop.clone(), limits));
        Ok((
            Arc::new(Self {
                commands,
                stop,
                timeout,
                task: tokio::sync::Mutex::new(Some(task)),
                command_bytes: Arc::new(Semaphore::new(limits.command)),
                next_id: AtomicU64::new(0),
                limits,
            }),
            outgoing,
        ))
    }

    pub async fn call<T: Command>(&self, session: Option<&str>, command: T) -> Result<T::Response> {
        if self.stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        let method = command.identifier().as_ref().to_owned();
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| ErrorCode::Capacity)?
            + 1;
        let text = serde_json::to_string(&Call {
            id,
            method: &method,
            params: command,
            session,
        })
        .map_err(|_| ErrorCode::WorkerFailed)?;
        if text.len() > self.limits.command {
            return Err(ErrorCode::SizeLimit);
        }
        let bytes = retain_bytes(&self.command_bytes, text.len())?;
        let (reply, response) = oneshot::channel();
        self.commands
            .try_send(Queued {
                id,
                payload: Payload {
                    text,
                    _bytes: bytes,
                },
                session: session.map(str::to_owned),
                reply,
            })
            .map_err(|_| ErrorCode::Capacity)?;
        let response = tokio::select! {
            biased;
            _ = self.stop.cancelled() => return Err(ErrorCode::Cancelled),
            result = tokio::time::timeout(self.timeout, response) => match result {
                Ok(result) => result.map_err(|_| ErrorCode::WorkerFailed)??,
                Err(_) => { self.stop.cancel(); return Err(ErrorCode::Timeout); }
            }
        };
        serde_json::from_str(&response.text).map_err(|_| ErrorCode::WorkerFailed)
    }

    pub fn stopped(&self) -> CancellationToken {
        self.stop.clone()
    }
    pub async fn close(&self) {
        self.stop.cancel();
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

async fn run(
    mut socket: WebSocketStream<ConnectStream>,
    mut incoming: mpsc::Receiver<Queued>,
    events: mpsc::Sender<Event>,
    stop: CancellationToken,
    limits: QueueLimits,
) {
    let _stop_on_exit = stop.clone().drop_guard();
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let response_bytes = Arc::new(Semaphore::new(limits.response));
    let event_bytes = Arc::new(Semaphore::new(limits.events));
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            command = incoming.recv() => {
                let Some(command) = command else { break; };
                if command.reply.is_closed() { continue; }
                if pending.len() >= 128 { let _ = command.reply.send(Err(ErrorCode::Capacity)); continue; }
                pending.insert(command.id, Pending { session: command.session, reply: command.reply });
                let Payload { text, _bytes } = command.payload;
                if !matches!(tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(text.into()))).await, Ok(Ok(()))) { break; }
            }
            message = socket.next() => {
                let message = match message { Some(Ok(Message::Text(message))) => message,
                    Some(Ok(Message::Ping(_)|Message::Pong(_))) => continue, _ => break };
                let Ok(envelope) = serde_json::from_str::<Envelope<'_>>(&message) else { break; };
                if let Some(id) = envelope.id {
                    let Some(request) = pending.remove(&id) else { break; };
                    if envelope.session != request.session.as_deref() { break; }
                    let result = if envelope.error.is_some() { Err(ErrorCode::WorkerFailed) }
                        else if let Some(result) = envelope.result {
                            let Ok(bytes) = retain_bytes(&response_bytes, result.get().len()) else { break; };
                            Ok(Payload { text: result.get().to_owned(), _bytes: bytes })
                        } else { Err(ErrorCode::WorkerFailed) };
                    let _ = request.reply.send(result);
                } else {
                    if message.len() > limits.event { break; }
                    let Ok(bytes) = retain_bytes(&event_bytes, message.len()) else { break; };
                    let Ok(mut event) = serde_json::from_str::<Event>(&message) else { break; };
                    event._bytes = Some(bytes);
                    // Stop an overflowing session instead of accumulating page-
                    // controlled events in an unbounded queue.
                    if events.try_send(event).is_err() { break; }
                }
            }
        }
    }
    for (_, request) in pending {
        let _ = request.reply.send(Err(ErrorCode::WorkerFailed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chromiumoxide::cdp::browser_protocol::browser::GetVersionParams;
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};

    type Server = WebSocketStream<async_tungstenite::tokio::TokioAdapter<TcpStream>>;

    async fn fixture(limits: QueueLimits) -> (Arc<Cdp>, mpsc::Receiver<Event>, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "ws://{}/devtools/browser/fixture",
            listener.local_addr().unwrap()
        );
        let (server, client) = tokio::join!(
            async {
                async_tungstenite::tokio::accept_async(listener.accept().await.unwrap().0)
                    .await
                    .unwrap()
            },
            Cdp::connect_bounded(
                &endpoint,
                Duration::from_secs(2),
                CancellationToken::new(),
                limits
            ),
        );
        let (cdp, events) = client.unwrap();
        (cdp, events, server)
    }

    async fn send(server: &mut Server, value: Value) {
        server
            .send(Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn event_byte_limit_covers_dequeued_events_until_consumed() {
        let limits = QueueLimits {
            event: 1024,
            events: 700,
            ..Default::default()
        };
        let (cdp, mut events, mut server) = fixture(limits).await;
        let event = json!({"method":"Fixture.event","params":{"data":"x".repeat(400)}});
        send(&mut server, event.clone()).await;
        let held = events.recv().await.unwrap();
        assert_eq!(held.params["data"].as_str().unwrap().len(), 400);
        // The queue has no events, but the consumer still retains these bytes.
        send(&mut server, event).await;
        tokio::time::timeout(Duration::from_secs(2), cdp.stopped().cancelled())
            .await
            .unwrap();
        assert!(events.recv().await.is_none());
        drop(held);
        cdp.close().await;
    }

    #[tokio::test]
    async fn consumed_event_releases_capacity_and_oversized_event_stops_session() {
        let limits = QueueLimits {
            event: 512,
            events: 700,
            ..Default::default()
        };
        let (cdp, mut events, mut server) = fixture(limits).await;
        for _ in 0..3 {
            send(
                &mut server,
                json!({"method":"Fixture.event","params":{"data":"x".repeat(400)}}),
            )
            .await;
            drop(events.recv().await.unwrap());
            assert!(!cdp.stopped().is_cancelled());
        }
        send(
            &mut server,
            json!({"method":"Fixture.event","params":{"data":"x".repeat(513)}}),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(2), cdp.stopped().cancelled())
            .await
            .unwrap();
        assert!(events.recv().await.is_none());
        cdp.close().await;
    }

    #[tokio::test]
    async fn responses_still_awaiting_consumers_share_a_byte_limit() {
        let limits = QueueLimits {
            response: 1500,
            ..Default::default()
        };
        let (cdp, _events, mut server) = fixture(limits).await;
        let mut replies = Vec::new();
        for id in 1..=2 {
            let text = json!({"id":id,"method":"Browser.getVersion","params":{}}).to_string();
            let (reply, response) = oneshot::channel();
            cdp.commands
                .try_send(Queued {
                    id,
                    session: None,
                    reply,
                    payload: Payload {
                        _bytes: retain_bytes(&cdp.command_bytes, text.len()).unwrap(),
                        text,
                    },
                })
                .unwrap_or_else(|_| panic!("fixture queue unexpectedly full"));
            replies.push(response);
            let sent: Value =
                serde_json::from_str(&server.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap();
            assert_eq!(sent["id"], id);
            send(
                &mut server,
                json!({"id":id,"result":{"data":"x".repeat(900)}}),
            )
            .await;
        }
        tokio::time::timeout(Duration::from_secs(2), cdp.stopped().cancelled())
            .await
            .unwrap();
        let mut replies = replies.into_iter();
        assert!(replies.next().unwrap().await.unwrap().is_ok());
        assert!(replies.next().unwrap().await.is_err());
        cdp.close().await;
    }

    #[tokio::test]
    async fn command_bytes_are_reserved_before_queue_admission() {
        let limits = QueueLimits {
            command: 80,
            ..Default::default()
        };
        let (commands, mut incoming) = mpsc::channel(64);
        let cdp = Cdp {
            commands,
            stop: CancellationToken::new(),
            timeout: Duration::from_secs(2),
            task: tokio::sync::Mutex::new(None),
            command_bytes: Arc::new(Semaphore::new(limits.command)),
            next_id: AtomicU64::new(0),
            limits,
        };
        let first = cdp.call(None, GetVersionParams {});
        tokio::pin!(first);
        assert!(futures_util::poll!(first.as_mut()).is_pending());
        assert_eq!(
            cdp.call(None, GetVersionParams {}).await.unwrap_err(),
            ErrorCode::Capacity
        );
        drop(incoming.recv().await.unwrap());
        let third = cdp.call(None, GetVersionParams {});
        tokio::pin!(third);
        assert!(futures_util::poll!(third.as_mut()).is_pending());
        cdp.stop.cancel();
        assert_eq!(third.await.unwrap_err(), ErrorCode::Cancelled);
        drop(incoming);
    }
}
