use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use abyssal_agent_protocol::{
    AgentMessage, AgentOperation, CommandOutcome, PROTOCOL_VERSION, ServerMessage,
};
use futures_util::{SinkExt, StreamExt};
use http::{Request, Uri};
use tokio::sync::{RwLock, Semaphore, mpsc};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::protocol::Message;
use uuid::Uuid;

use crate::elevation::ElevationState;

pub fn to_ws_url(base: &str) -> anyhow::Result<String> {
    let base = base.trim_end_matches('/');
    let converted = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        anyhow::bail!("control plane URL must start with http:// or https://, got: {base}");
    };
    Ok(format!("{converted}/ws/agent"))
}

/// Connects to the control plane's `/ws/agent` endpoint, authenticating via
/// a `Bearer` header (validated server-side before the WebSocket upgrade
/// completes), and serves incoming commands until the connection closes.
pub async fn connect_and_serve(
    ws_url: &str,
    credential: &str,
    elevation: &ElevationState,
    trust: &crate::tls::Trust,
) -> anyhow::Result<()> {
    let uri: Uri = ws_url.parse()?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("invalid websocket URL: missing host"))?
        .as_str();
    // Host only (no port) -- threaded down to `IsolateHost` so it can
    // allow-list exactly the control plane's own address, never an
    // admin-supplied one.
    let control_plane_host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("invalid websocket URL: missing host"))?
        .to_string();

    let request = Request::builder()
        .uri(ws_url)
        .header("Host", authority)
        .header("Authorization", format!("Bearer {credential}"))
        .header("X-Agent-Protocol-Version", PROTOCOL_VERSION.to_string())
        // Coarse platform family + the agent binary's own version --
        // persisted onto the `hosts` row at connect time so features like
        // Thanatos can route to the right per-OS logic instead of
        // assuming every host is Linux.
        .header("X-Agent-Os", std::env::consts::OS)
        .header("X-Agent-Version", env!("CARGO_PKG_VERSION"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())?;

    let (ws_stream, _response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(trust.rustls_config())),
    )
    .await?;
    tracing::info!("connected to control plane");

    let (mut sink, mut stream) = ws_stream.split();
    let closed = Arc::new(AtomicBool::new(false));
    // Every reply goes out through this one writer, in the order they finish.
    let (outgoing, mut out_rx) = mpsc::channel::<Message>(64);
    {
        let closed = closed.clone();
        tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                if sink.send(message).await.is_err() {
                    closed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });
    }
    let elevation = elevation.clone();
    let host: Arc<str> = control_plane_host.into();
    let runner: Runner = Arc::new(move |operation| {
        let elevation = elevation.clone();
        let host = host.clone();
        Box::pin(async move { crate::ops::run(operation, &elevation, &host).await })
    });
    set_current_outgoing(Some(outgoing.clone()));
    let serve = Serve::start(outgoing.clone(), closed, runner, exclusive_gate());

    while let Some(message) = stream.next().await {
        match message? {
            Message::Text(text) => {
                let server_msg: ServerMessage = match serde_json::from_str(&text) {
                    Ok(msg) => msg,
                    Err(e) => {
                        // A newer control plane sent something this build
                        // doesn't know. Answer a command with an error rather
                        // than dropping the connection: an agent that
                        // disconnects over it is knocked offline every time a
                        // sweep sends it.
                        tracing::warn!(error = %e, "unrecognized message from the control plane");
                        if let Some(response) = unsupported_command(&text) {
                            serve.reply(&response).await;
                        }
                        continue;
                    }
                };
                match server_msg {
                    ServerMessage::Ping => serve.reply(&AgentMessage::Pong).await,
                    ServerMessage::Command {
                        request_id,
                        operation,
                    } => serve.command(request_id, operation).await,
                }
            }
            Message::Ping(payload) => serve.send(Message::Pong(payload)).await,
            Message::Close(_) => break,
            _ => {}
        }
        if serve.is_closed() {
            break;
        }
    }
    serve.close();
    clear_current_outgoing(&outgoing);
    Ok(())
}

/// The live connection's outgoing queue, for messages the agent sends on its
/// own (`thanatos_stream`'s telemetry) rather than in reply to a command.
static CURRENT_OUTGOING: std::sync::Mutex<Option<mpsc::Sender<Message>>> =
    std::sync::Mutex::new(None);

fn set_current_outgoing(sender: Option<mpsc::Sender<Message>>) {
    *CURRENT_OUTGOING.lock().unwrap() = sender;
}

/// Only if it's still this connection's: a reconnect may already have
/// replaced it.
fn clear_current_outgoing(ours: &mpsc::Sender<Message>) {
    let mut current = CURRENT_OUTGOING.lock().unwrap();
    if current.as_ref().is_some_and(|c| c.same_channel(ours)) {
        *current = None;
    }
}

/// Sends `message` on the current connection without waiting. False when
/// there's no connection or its queue is full; the caller keeps the data.
pub fn push_unsolicited(message: &AgentMessage) -> bool {
    let Some(sender) = CURRENT_OUTGOING.lock().unwrap().clone() else {
        return false;
    };
    let Ok(payload) = serde_json::to_string(message) else {
        return false;
    };
    sender.try_send(Message::Text(payload)).is_ok()
}

/// Most read-only operations a connection runs at once.
const MAX_CONCURRENT_READS: usize = 8;

/// Process-wide, so it also holds across a reconnect: a write still running
/// for an old connection excludes everything on the new one. Reads hold it
/// shared, a write holds it alone. Tokio's lock is fair, so a waiting write
/// isn't starved by a stream of reads.
fn exclusive_gate() -> Arc<RwLock<()>> {
    static GATE: OnceLock<Arc<RwLock<()>>> = OnceLock::new();
    GATE.get_or_init(|| Arc::new(RwLock::new(()))).clone()
}

/// Runs one operation -- `ops::run` with this connection's elevation state
/// and control-plane host; a fake in tests.
type Runner = Arc<
    dyn Fn(
            AgentOperation,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CommandOutcome> + Send>>
        + Send
        + Sync,
>;

/// One connection's command runner. Reads (`runs_concurrently`) run in
/// parallel, up to `MAX_CONCURRENT_READS`; everything else goes through one
/// queue, in arrival order, alone. Replies go out on `outgoing` in whatever
/// order they finish -- the control plane matches them by request id. Pings
/// are answered straight away, even mid-operation.
struct Serve {
    outgoing: mpsc::Sender<Message>,
    exclusive: mpsc::UnboundedSender<(Uuid, AgentOperation)>,
    reads: Arc<Semaphore>,
    gate: Arc<RwLock<()>>,
    runner: Runner,
    /// Set when the connection ends: work that hasn't started by then is
    /// dropped, not run. The control plane has already told the admin the
    /// host disconnected, so running it late would surprise them (and a
    /// retry would run it twice).
    closed: Arc<AtomicBool>,
}

impl Serve {
    fn start(
        outgoing: mpsc::Sender<Message>,
        closed: Arc<AtomicBool>,
        runner: Runner,
        gate: Arc<RwLock<()>>,
    ) -> Self {
        let (exclusive, mut ex_rx) = mpsc::unbounded_channel::<(Uuid, AgentOperation)>();
        {
            let outgoing = outgoing.clone();
            let runner = runner.clone();
            let closed = closed.clone();
            let gate = gate.clone();
            tokio::spawn(async move {
                while let Some((request_id, operation)) = ex_rx.recv().await {
                    if closed.load(Ordering::SeqCst) {
                        continue;
                    }
                    let _alone = gate.clone().write_owned().await;
                    if closed.load(Ordering::SeqCst) {
                        continue;
                    }
                    let outcome = runner(operation).await;
                    send_response(&outgoing, request_id, outcome).await;
                }
            });
        }

        Self {
            outgoing,
            exclusive,
            reads: Arc::new(Semaphore::new(MAX_CONCURRENT_READS)),
            gate,
            runner,
            closed,
        }
    }

    async fn command(&self, request_id: Uuid, operation: AgentOperation) {
        if !operation.runs_concurrently() {
            let _ = self.exclusive.send((request_id, operation));
            return;
        }
        let reads = self.reads.clone();
        let outgoing = self.outgoing.clone();
        let runner = self.runner.clone();
        let closed = self.closed.clone();
        let gate = self.gate.clone();
        tokio::spawn(async move {
            let Ok(_slot) = reads.acquire_owned().await else {
                return;
            };
            let _shared = gate.read_owned().await;
            if closed.load(Ordering::SeqCst) {
                return;
            }
            let outcome = runner(operation).await;
            send_response(&outgoing, request_id, outcome).await;
        });
    }

    async fn reply(&self, message: &AgentMessage) {
        if let Ok(payload) = serde_json::to_string(message) {
            self.send(Message::Text(payload)).await;
        }
    }

    async fn send(&self, message: Message) {
        if self.outgoing.send(message).await.is_err() {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Stops queued work from starting. What's already running finishes;
    /// its reply has nowhere to go.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

async fn send_response(
    outgoing: &mpsc::Sender<Message>,
    request_id: Uuid,
    outcome: CommandOutcome,
) {
    let response = AgentMessage::Response {
        request_id,
        outcome,
    };
    if let Ok(payload) = serde_json::to_string(&response) {
        let _ = outgoing.send(Message::Text(payload)).await;
    }
}

/// The reply to a command this build can't parse (an operation added after
/// it, most likely), if `text` is a command at all.
fn unsupported_command(text: &str) -> Option<AgentMessage> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let request_id = value.get("Command")?.get("request_id")?.clone();
    let request_id: uuid::Uuid = serde_json::from_value(request_id).ok()?;
    Some(AgentMessage::Response {
        request_id,
        outcome: abyssal_agent_protocol::CommandOutcome::Err(format!(
            "this agent (v{}, protocol {PROTOCOL_VERSION}) doesn't support this operation -- \
             update it with 'Update agent' on /admin/hosts",
            env!("CARGO_PKG_VERSION")
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    /// A fake runner: `ServiceStatus { unit: "name:ms" }` is a read and
    /// `StartService { unit: "name:ms" }` a write, each taking `ms`. Every
    /// start and end is recorded.
    #[derive(Clone, Default)]
    struct Recorder(Arc<std::sync::Mutex<Vec<(String, bool, Instant)>>>);

    impl Recorder {
        fn runner(&self) -> Runner {
            let rec = self.clone();
            Arc::new(move |op| {
                let rec = rec.clone();
                Box::pin(async move {
                    let spec = match op {
                        AgentOperation::ServiceStatus { unit }
                        | AgentOperation::StartService { unit } => unit,
                        other => format!("{other:?}:0"),
                    };
                    let (name, ms) = spec.split_once(':').unwrap();
                    let (name, ms) = (name.to_string(), ms.parse::<u64>().unwrap());
                    rec.0
                        .lock()
                        .unwrap()
                        .push((name.clone(), true, Instant::now()));
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    rec.0
                        .lock()
                        .unwrap()
                        .push((name.clone(), false, Instant::now()));
                    CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
                        stdout: name,
                        stderr: String::new(),
                        exit_code: Some(0),
                    })
                })
            })
        }

        /// Each operation's (start, end).
        fn spans(&self) -> std::collections::HashMap<String, (Instant, Instant)> {
            let mut out = std::collections::HashMap::new();
            for (name, start, at) in self.0.lock().unwrap().iter() {
                let entry = out.entry(name.clone()).or_insert((*at, *at));
                if *start { entry.0 = *at } else { entry.1 = *at }
            }
            out
        }

        fn max_concurrent(&self) -> usize {
            let (mut now, mut max) = (0usize, 0usize);
            for (_, start, _) in self.0.lock().unwrap().iter() {
                if *start {
                    now += 1;
                    max = max.max(now)
                } else {
                    now -= 1
                }
            }
            max
        }
    }

    fn read(spec: &str) -> AgentOperation {
        AgentOperation::ServiceStatus { unit: spec.into() }
    }
    fn write(spec: &str) -> AgentOperation {
        AgentOperation::StartService { unit: spec.into() }
    }

    struct Harness {
        serve: Serve,
        out: mpsc::Receiver<Message>,
        rec: Recorder,
    }

    fn harness() -> Harness {
        let rec = Recorder::default();
        let (tx, out) = mpsc::channel(256);
        let serve = Serve::start(
            tx,
            Arc::new(AtomicBool::new(false)),
            rec.runner(),
            Arc::new(RwLock::new(())),
        );
        Harness { serve, out, rec }
    }

    /// The next `n` replies' stdout, or "pong", in arrival order.
    async fn replies(out: &mut mpsc::Receiver<Message>, n: usize) -> Vec<String> {
        let mut got = Vec::new();
        while got.len() < n {
            let msg = tokio::time::timeout(Duration::from_secs(10), out.recv())
                .await
                .expect("a reply in time")
                .expect("channel open");
            let Message::Text(text) = msg else { continue };
            match serde_json::from_str::<AgentMessage>(&text).unwrap() {
                AgentMessage::Pong => got.push("pong".to_string()),
                AgentMessage::Response {
                    outcome: CommandOutcome::Ok(o),
                    ..
                } => got.push(o.stdout),
                other => panic!("unexpected reply {other:?}"),
            }
        }
        got
    }

    #[test]
    fn reads_are_classified_concurrent_and_writes_are_not() {
        assert!(read("x:0").runs_concurrently());
        assert!(AgentOperation::Ping.runs_concurrently());
        assert!(
            AgentOperation::ScanSecurityEvents {
                extra_fim_paths: vec![],
                channel_offsets: vec![],
                c2_ports: vec![],
                fast_only: false
            }
            .runs_concurrently()
        );
        for op in [
            write("x:0"),
            AgentOperation::InstallPackage {
                package: "x".into(),
            },
            AgentOperation::RefreshPackageIndex,
            AgentOperation::Reboot,
            AgentOperation::SelfUpdate {
                version: "1.0.0".into(),
                from_control_plane: true,
                sha256: None,
            },
            AgentOperation::UninstallAgent { purge: true },
            AgentOperation::Deescalate,
            AgentOperation::ScourgeCaptureStart {
                bpf: String::new(),
                max_seconds: 1,
                max_mb: 1,
                retention_days: 1,
                max_total_mb: 1,
            },
        ] {
            assert!(!op.runs_concurrently(), "{op:?} must run alone");
        }
    }

    #[tokio::test]
    async fn reads_run_in_parallel() {
        let mut h = harness();
        let started = Instant::now();
        for i in 0..4 {
            h.serve
                .command(Uuid::new_v4(), read(&format!("r{i}:300")))
                .await;
        }
        replies(&mut h.out, 4).await;
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "four 300ms reads took {:?}",
            started.elapsed()
        );
        assert_eq!(h.rec.max_concurrent(), 4);
    }

    #[tokio::test]
    async fn reads_are_capped() {
        let mut h = harness();
        for i in 0..(MAX_CONCURRENT_READS + 4) {
            h.serve
                .command(Uuid::new_v4(), read(&format!("r{i}:150")))
                .await;
        }
        replies(&mut h.out, MAX_CONCURRENT_READS + 4).await;
        assert_eq!(h.rec.max_concurrent(), MAX_CONCURRENT_READS);
    }

    #[tokio::test]
    async fn writes_run_alone_in_arrival_order() {
        let mut h = harness();
        for name in ["w1", "w2", "w3"] {
            h.serve
                .command(Uuid::new_v4(), write(&format!("{name}:80")))
                .await;
        }
        assert_eq!(replies(&mut h.out, 3).await, ["w1", "w2", "w3"]);
        assert_eq!(h.rec.max_concurrent(), 1);
    }

    #[tokio::test]
    async fn a_write_never_overlaps_a_read() {
        let mut h = harness();
        h.serve.command(Uuid::new_v4(), read("r1:300")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.serve.command(Uuid::new_v4(), write("w1:100")).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.serve.command(Uuid::new_v4(), read("r2:100")).await;
        replies(&mut h.out, 3).await;
        let spans = h.rec.spans();
        let (w_start, w_end) = spans["w1"];
        for r in ["r1", "r2"] {
            let (r_start, r_end) = spans[r];
            assert!(
                r_end <= w_start || r_start >= w_end,
                "{r} overlapped the write"
            );
        }
        // The read that arrived after the write waited for it (fair lock).
        assert!(spans["r2"].0 >= w_end);
    }

    #[tokio::test]
    async fn pings_are_answered_during_a_long_write() {
        let mut h = harness();
        h.serve.command(Uuid::new_v4(), write("slow:600")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.serve.reply(&AgentMessage::Pong).await;
        h.serve.command(Uuid::new_v4(), read("quick:0")).await;
        assert_eq!(
            replies(&mut h.out, 1).await,
            ["pong"],
            "pong came after the write"
        );
        assert_eq!(
            replies(&mut h.out, 2).await,
            ["slow", "quick"],
            "the read waited for the write"
        );
    }

    #[tokio::test]
    async fn work_queued_when_the_connection_ends_never_starts() {
        let mut h = harness();
        h.serve.command(Uuid::new_v4(), write("running:200")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.serve
            .command(Uuid::new_v4(), write("queued-write:10"))
            .await;
        h.serve
            .command(Uuid::new_v4(), read("queued-read:10"))
            .await;
        h.serve.close();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let spans = h.rec.spans();
        assert!(spans.contains_key("running"), "what was running finishes");
        assert!(!spans.contains_key("queued-write"));
        assert!(!spans.contains_key("queued-read"));
        let _ = h.out.try_recv();
    }

    #[test]
    fn an_unknown_operation_gets_an_error_reply() {
        let id = "4f0c5a0e-8a51-4a59-9d55-6e1b3c1f2a77";
        let text = format!(
            r#"{{"Command":{{"request_id":"{id}","operation":{{"SomeFutureOp":{{"x":1}}}}}}}}"#
        );
        assert!(serde_json::from_str::<ServerMessage>(&text).is_err());
        match unsupported_command(&text) {
            Some(AgentMessage::Response {
                request_id,
                outcome: abyssal_agent_protocol::CommandOutcome::Err(message),
            }) => {
                assert_eq!(request_id.to_string(), id);
                assert!(message.contains("update it"), "{message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn non_commands_and_garbage_get_no_reply() {
        assert!(unsupported_command(r#""SomeFutureMessage""#).is_none());
        assert!(unsupported_command(r#"{"Command":{"operation":"Ping"}}"#).is_none());
        assert!(unsupported_command("not json").is_none());
    }

    #[test]
    fn a_reply_round_trips_through_the_protocol() {
        let text = r#"{"Command":{"request_id":"4f0c5a0e-8a51-4a59-9d55-6e1b3c1f2a77","operation":"NoSuchOp"}}"#;
        let reply = serde_json::to_string(&unsupported_command(text).unwrap()).unwrap();
        assert!(serde_json::from_str::<AgentMessage>(&reply).is_ok());
    }
}
