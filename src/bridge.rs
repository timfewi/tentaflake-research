//! Client-side multiplexing, with cancellation even when an MCP call future is
//! dropped. No provider credentials, environment proxies or network targets live
//! in this adapter.

use crate::error::{ErrorCode, Result};
use crate::protocol::{self, Operation, Outcome, Request, Response, Tool, VERSION};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

struct Command {
    tool: Tool,
    arguments: Value,
    stop: CancellationToken,
    reply: oneshot::Sender<Result<Value>>,
}
struct Pending {
    reply: oneshot::Sender<Result<Value>>,
    done: CancellationToken,
}

pub struct Bridge {
    commands: mpsc::Sender<Command>,
    stop: CancellationToken,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Bridge {
    pub async fn connect(socket: &Path) -> Result<Self> {
        Ok(Self::from_stream(socket, Self::open(socket).await?))
    }

    async fn open(socket: &Path) -> Result<UnixStream> {
        let mut stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(socket))
            .await
            .map_err(|_| ErrorCode::Timeout)?
            .map_err(|_| ErrorCode::EgressUnavailable)?;
        tokio::time::timeout(Duration::from_secs(5), async {
            protocol::write_frame(
                &mut stream,
                &Request {
                    version: VERSION,
                    id: 1,
                    operation: Operation::Hello,
                },
            )
            .await?;
            let hello: Response = protocol::read_frame(&mut stream)
                .await?
                .ok_or(ErrorCode::ProtocolVersion)?;
            if hello.version != VERSION || hello.id != 1 {
                return Err(ErrorCode::ProtocolVersion);
            }
            match hello.outcome {
                Outcome::Result { value }
                    if value["version"] == VERSION
                        && value["max_frame"] == protocol::MAX_FRAME
                        && value["tools"]
                            == serde_json::to_value(protocol::TOOLS)
                                .map_err(|_| ErrorCode::ProtocolVersion)? =>
                {
                    Ok(())
                }
                _ => Err(ErrorCode::ProtocolVersion),
            }
        })
        .await
        .map_err(|_| ErrorCode::Timeout)??;
        Ok(stream)
    }

    fn from_stream(socket: &Path, stream: UnixStream) -> Self {
        let (commands, incoming) = mpsc::channel(16);
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(socket.to_owned(), stream, incoming, stop.clone()));
        Self {
            commands,
            stop,
            task: tokio::sync::Mutex::new(Some(task)),
        }
    }

    /// Connect to the service, retrying a bounded number of times with a short
    /// backoff. A transient socket-activation or service-restart window (for
    /// example a short NixOS switch that briefly stops the socket-activated
    /// service) can make the first connect fail; retrying keeps the stdio MCP
    /// client from exiting immediately with a "Connection closed" error during
    /// that window. Every attempt opens a fresh connection.
    pub async fn connect_with_retry(socket: &Path) -> Result<Self> {
        Ok(Self::from_stream(
            socket,
            Self::open_with_retry(socket).await?,
        ))
    }

    async fn open_with_retry(socket: &Path) -> Result<UnixStream> {
        const MAX_ATTEMPTS: u32 = 5;
        const BASE_BACKOFF: Duration = Duration::from_millis(250);
        let mut attempt: u32 = 0;
        loop {
            match Self::open(socket).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS {
                        return Err(error);
                    }
                    tokio::time::sleep(BASE_BACKOFF * (1_u32 << (attempt - 1))).await;
                }
            }
        }
    }

    pub async fn call(
        &self,
        tool: Tool,
        arguments: Value,
        stop: CancellationToken,
    ) -> Result<Value> {
        self.call_detailed(tool, arguments, stop)
            .await
            .map_err(|failure| failure.code)
    }

    pub async fn call_detailed(
        &self,
        tool: Tool,
        arguments: Value,
        stop: CancellationToken,
    ) -> std::result::Result<Value, crate::error::ToolFailure> {
        let value = self.call_wire(tool, arguments, stop).await?;
        if value.as_object().is_some_and(|object| {
            object.len() == 2 && object.contains_key("error") && object.contains_key("details")
        }) {
            let failure = serde_json::from_value(value).map_err(|_| ErrorCode::InvalidResponse)?;
            Err(failure)
        } else {
            Ok(value)
        }
    }

    async fn call_wire(
        &self,
        tool: Tool,
        arguments: Value,
        stop: CancellationToken,
    ) -> Result<Value> {
        if stop.is_cancelled() || self.stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        // Serializing now also bounds command-queue memory before admission.
        if serde_json::to_vec(&arguments)
            .map_err(|_| ErrorCode::InvalidRequest)?
            .len()
            > protocol::MAX_FRAME - 1024
        {
            return Err(ErrorCode::SizeLimit);
        }
        let stop = stop.child_token();
        let _cancel_on_drop = stop.clone().drop_guard();
        let (reply, result) = oneshot::channel();
        self.commands
            .try_send(Command {
                tool,
                arguments,
                stop: stop.clone(),
                reply,
            })
            .map_err(|_| ErrorCode::Capacity)?;
        tokio::select! {
            result = result => result.map_err(|_| ErrorCode::Cancelled)?,
            _ = stop.cancelled() => Err(ErrorCode::Cancelled),
            _ = self.stop.cancelled() => Err(ErrorCode::Cancelled),
        }
    }

    pub async fn close(&self) {
        self.stop.cancel();
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

async fn run(
    socket: PathBuf,
    mut stream: UnixStream,
    mut commands: mpsc::Receiver<Command>,
    stop: CancellationToken,
) {
    let _stop_on_exit = stop.clone().drop_guard();
    let mut first = None;
    loop {
        run_session(stream, &mut commands, stop.clone(), first.take()).await;
        // Dispatched work has already failed and is never replayed. Only an
        // undispatched command can request a fresh, fully checked session.
        loop {
            let command = tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                command = commands.recv() => match command { Some(command) => command, None => return },
            };
            let connection = tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = command.stop.cancelled() => Err(ErrorCode::Cancelled),
                connection = Bridge::open_with_retry(&socket) => connection,
            };
            match connection {
                Ok(connected) => {
                    stream = connected;
                    first = Some(command);
                    break;
                }
                Err(error) => {
                    let _ = command.reply.send(Err(error));
                }
            }
        }
    }
}

async fn run_session(
    stream: UnixStream,
    commands: &mut mpsc::Receiver<Command>,
    stop: CancellationToken,
    mut first: Option<Command>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (responses, mut incoming) = mpsc::channel(32);
    let reading = tokio::spawn(async move {
        loop {
            let response = protocol::read_frame::<_, Response>(&mut reader).await;
            let ended = !matches!(response, Ok(Some(_)));
            if responses.send(response).await.is_err() || ended {
                break;
            }
        }
    });
    let (cancels, mut cancelled) = mpsc::channel(32);
    let mut watches = JoinSet::new();
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut acknowledgements = HashSet::new();
    let mut next_id = 1_u64;
    loop {
        let operation = tokio::select! {
            _ = stop.cancelled() => break,
            Some(_) = watches.join_next(), if !watches.is_empty() => continue,
            response = incoming.recv() => {
                let response = match response { Some(Ok(Some(response))) if response.version == VERSION => response, _ => break };
                if acknowledgements.remove(&response.id) {
                    if !matches!(response.outcome, Outcome::Result { .. }) { break; }
                    continue;
                }
                if let Outcome::Progress { completed, total } = response.outcome {
                    if completed > total || !pending.contains_key(&response.id) { break; }
                    continue;
                }
                let Some(request) = pending.remove(&response.id) else { break; };
                request.done.cancel();
                let result = match response.outcome { Outcome::Result { value } => Ok(value), Outcome::Error { code } => Err(code), Outcome::Progress { .. } => unreachable!() };
                let _ = request.reply.send(result);
                continue;
            }
            Some(id) = cancelled.recv() => {
                if !pending.contains_key(&id) { continue; }
                if acknowledgements.len() >= 32 { break; }
                Operation::Cancel { request_id: id }
            }
            command = async { match first.take() { Some(command) => Some(command), None => commands.recv().await } } => {
                let Some(command) = command else { break; };
                if command.stop.is_cancelled() { let _ = command.reply.send(Err(ErrorCode::Cancelled)); continue; }
                if pending.len() >= 16 { let _ = command.reply.send(Err(ErrorCode::Capacity)); continue; }
                let Some(id) = next_id.checked_add(1) else { break; };
                let done = CancellationToken::new();
                pending.insert(id, Pending { reply: command.reply, done: done.clone() });
                let cancels = cancels.clone();
                watches.spawn(async move {
                    tokio::select! { biased; _ = done.cancelled() => (), _ = command.stop.cancelled() => { let _ = cancels.send(id).await; } }
                });
                Operation::Call { tool: command.tool, arguments: command.arguments }
            }
        };
        let Some(id) = next_id.checked_add(1) else {
            break;
        };
        next_id = id;
        if matches!(operation, Operation::Cancel { .. }) {
            acknowledgements.insert(id);
        }
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                protocol::write_frame(
                    &mut writer,
                    &Request {
                        version: VERSION,
                        id,
                        operation
                    }
                )
            )
            .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
    reading.abort();
    let _ = reading.await;
    for (_, request) in pending {
        request.done.cancel();
        let _ = request.reply.send(Err(ErrorCode::Cancelled));
    }
    drop(cancelled);
    while watches.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    fn hello_reply() -> serde_json::Value {
        serde_json::json!({
            "version": VERSION,
            "max_frame": protocol::MAX_FRAME,
            "tools": protocol::TOOLS,
        })
    }

    async fn reply(stream: &mut UnixStream, id: u64, value: Value) {
        protocol::write_frame(
            stream,
            &Response {
                version: VERSION,
                id,
                outcome: Outcome::Result { value },
            },
        )
        .await
        .unwrap();
    }

    async fn handshake(stream: &mut UnixStream) {
        let request: Request = protocol::read_frame(stream).await.unwrap().unwrap();
        assert!(matches!(request.operation, Operation::Hello));
        reply(stream, request.id, hello_reply()).await;
    }

    #[tokio::test]
    async fn connect_with_retry_waits_for_a_transiently_absent_listener() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("research.sock");

        // Bind the listener only after a delay, as if the socket-activated
        // service were briefly down (e.g. a short NixOS switch) while the MCP
        // client starts. `Bridge::connect` alone would fail immediately; the
        // retrying entrypoint must wait and succeed.
        let path = socket.clone();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let listener = UnixListener::bind(&path).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await;
        });

        let bridge = Bridge::connect_with_retry(&socket).await.unwrap();
        bridge.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reconnects_future_calls_without_replaying_dispatched_work() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("research.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for marker in [1, 2] {
                let (mut stream, _) = listener.accept().await.unwrap();
                handshake(&mut stream).await;
                let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
                let Operation::Call { arguments, .. } = request.operation else {
                    panic!("expected a fresh call");
                };
                assert_eq!(arguments["marker"], marker);
                if marker == 2 {
                    reply(&mut stream, request.id, serde_json::json!({"fresh": true})).await;
                }
                // The first call reached the peer, but its response is lost.
            }
        });
        let bridge = Bridge::connect(&socket).await.unwrap();
        assert_eq!(
            bridge
                .call(
                    Tool::ResearchJob,
                    serde_json::json!({"marker": 1}),
                    CancellationToken::new()
                )
                .await
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            bridge
                .call(Tool::ResearchJob, Value::Null, cancelled)
                .await
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        let fresh = tokio::time::timeout(
            Duration::from_secs(2),
            bridge.call(
                Tool::ResearchJob,
                serde_json::json!({"marker": 2}),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fresh["fresh"], true);
        bridge.close().await;
        assert_eq!(
            bridge
                .call(Tool::ResearchJob, Value::Null, CancellationToken::new())
                .await
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_reconnect_does_not_poison_the_next_call() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("research.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (connecting, started) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await;
            let _: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
            drop(stream);

            let (mut stream, _) = listener.accept().await.unwrap();
            let hello: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
            assert!(matches!(hello.operation, Operation::Hello));
            connecting.send(()).unwrap();
            // Hold the handshake. Cancellation must close this connection
            // without sending a call, even before the five-second timeout.
            assert!(
                protocol::read_frame::<_, Request>(&mut stream)
                    .await
                    .unwrap()
                    .is_none()
            );
            drop(stream);

            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await;
            let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
            let Operation::Call { arguments, .. } = request.operation else {
                panic!("expected a fresh call");
            };
            assert_eq!(arguments["marker"], 3);
            reply(&mut stream, request.id, serde_json::json!({"fresh": true})).await;
        });
        let bridge = std::sync::Arc::new(Bridge::connect(&socket).await.unwrap());
        assert_eq!(
            bridge
                .call(Tool::ResearchJob, Value::Null, CancellationToken::new())
                .await
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        let stop = CancellationToken::new();
        let client = bridge.clone();
        let cancel = stop.clone();
        let pending =
            tokio::spawn(async move { client.call(Tool::ResearchJob, Value::Null, cancel).await });
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .unwrap()
            .unwrap();
        stop.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err(),
            ErrorCode::Cancelled
        );
        let fresh = tokio::time::timeout(
            Duration::from_secs(2),
            bridge.call(
                Tool::ResearchJob,
                serde_json::json!({"marker": 3}),
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fresh["fresh"], true);
        bridge.close().await;
        server.await.unwrap();
    }
}
