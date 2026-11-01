use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use uuid::Uuid;
use yofc_management_protocol::{LocalFrame, read_frame, write_frame};

const KURA_REQUIRED_METHODS: &[&str] = &["kura.configuration.list", "kura.snapshot.list"];
const KURA_METHODS: &[&str] = &[
    "kura.configuration.list",
    "kura.snapshot.list",
    "kura.configuration.get",
    "kura.configuration.outcome",
    "kura.configuration.update",
    "kura.snapshot.save",
    "kura.snapshot.rollback",
];
#[derive(Clone)]
struct Bridge {
    epoch: u64,
    tx: mpsc::Sender<LocalFrame>,
    methods: HashSet<String>,
}

#[cfg(test)]
mod configuration_write_tests {
    use super::*;
    async fn bridge() -> (Local, mpsc::Receiver<LocalFrame>) {
        let mut local = Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
        local.enable_configuration_updates(true);
        let (tx, rx) = mpsc::channel(8);
        *local.bridge.write().await = Some(Bridge {
            epoch: 1,
            tx,
            methods: HashSet::from(["kura.configuration.update".into()]),
        });
        (local, rx)
    }
    #[tokio::test]
    async fn write_rejections_before_queue_are_definite_and_reads_cannot_invoke_writes() {
        let local = Local::new(0, 0);
        assert_eq!(
            local.update_configuration(json!({})).await.unwrap_err(),
            "UNSUPPORTED"
        );
        assert_eq!(
            local.snapshot("kura.snapshot.save", json!({})).await.unwrap_err(),
            "UNSUPPORTED"
        );
        assert_eq!(
            local.snapshot("kura.snapshot.rollback", json!({})).await.unwrap_err(),
            "UNSUPPORTED"
        );
        let (local, mut rx) = bridge().await;
        assert_eq!(
            local
                .call_with_params("kura.configuration.update", Some(json!({})))
                .await
                .unwrap_err(),
            "UNSUPPORTED"
        );
        assert_eq!(
            local
                .call_with_params("kura.snapshot.save", Some(json!({})))
                .await
                .unwrap_err(),
            "UNSUPPORTED"
        );
        assert!(rx.try_recv().is_err());
        let bridge = local.bridge.read().await.clone().unwrap();
        for i in 0..8 {
            bridge
                .tx
                .try_send(LocalFrame {
                    version: 1,
                    kind: "request".into(),
                    request_id: i.to_string(),
                    method: "unused".into(),
                    params: None,
                    result: None,
                    error: None,
                })
                .unwrap();
        }
        assert_eq!(
            local.update_configuration(json!({})).await.unwrap_err(),
            "RESOURCE_EXHAUSTED"
        );
        assert!(local.pending.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn disconnect_and_unrecognized_reply_after_queue_are_unknown() {
        for code in [None, Some("INTERNAL"), Some("CONFLICT"), Some("TIMEOUT")] {
            let (local, mut rx) = bridge().await;
            let copy = local.clone();
            let task = tokio::spawn(async move { copy.update_configuration(json!({})).await });
            let request = rx.recv().await.unwrap();
            let call = local
                .pending
                .lock()
                .unwrap()
                .remove(&request.request_id)
                .unwrap();
            if let Some(code) = code {
                call.tx.send(request.response(None, Some(code))).unwrap();
            } else {
                drop(call);
            }
            let result = task.await.unwrap().unwrap_err();
            assert_eq!(
                result,
                match code {
                    Some("CONFLICT") => "CONFLICT",
                    Some("TIMEOUT") => "TIMEOUT",
                    _ => "OUTCOME_UNKNOWN",
                }
            );
            assert!(local.pending.lock().unwrap().is_empty());
        }
    }
}
struct PendingCall {
    epoch: u64,
    method: String,
    tx: oneshot::Sender<LocalFrame>,
}
type Pending = HashMap<String, PendingCall>;

struct PendingGuard {
    pending: Arc<StdMutex<Pending>>,
    id: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.pending.lock().unwrap().remove(&self.id);
    }
}
#[derive(Clone)]
pub struct Local {
    pub network: Option<crate::network::Network>,
    kura_network_interfaces: Option<Vec<String>>,
    bridge: Arc<RwLock<Option<Bridge>>>,
    pending: Arc<StdMutex<Pending>>,
    next: Arc<AtomicU64>,
    pub started: std::time::Instant,
    uid: u32,
    kura_uid: u32,
    admin_uid: u32,
    slots: Arc<Semaphore>,
    calls: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    configuration_updates: bool,
    snapshots: bool,
    pub(crate) configuration_write_lock: Arc<tokio::sync::Mutex<()>>,
}
impl Local {
    pub fn new(kura_uid: u32, admin_uid: u32) -> Self {
        Self {
            network: None,
            kura_network_interfaces: None,
            bridge: Default::default(),
            pending: Default::default(),
            next: Arc::new(AtomicU64::new(1)),
            started: std::time::Instant::now(),
            uid: unsafe { libc::geteuid() },
            kura_uid,
            admin_uid,
            slots: Arc::new(Semaphore::new(16)),
            calls: Arc::new(Semaphore::new(4)),
            requests: Arc::new(Semaphore::new(4)),
            configuration_updates: false,
            snapshots: false,
            configuration_write_lock: Default::default(),
        }
    }
    /// None disables the Kura network API; Some(empty) explicitly enables reads.
    pub fn delegate_kura_network(&mut self, interfaces: Option<Vec<String>>) -> Result<()> {
        if let Some(interfaces) = &interfaces {
            self.network
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("UNSUPPORTED: network unavailable"))?
                .validate_kura_delegation(interfaces)?;
        }
        self.kura_network_interfaces = interfaces;
        Ok(())
    }
    pub async fn status(&self) -> Value {
        json!({"agentAvailable":true,"kuraAvailable":self.bridge.read().await.is_some(),"uptimeSeconds":self.started.elapsed().as_secs(),"version":env!("CARGO_PKG_VERSION")})
    }
    pub async fn call(&self, method: &str) -> Result<Value, &'static str> {
        self.call_with_params(method, None).await
    }
    pub async fn call_with_params(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, &'static str> {
        if matches!(method, "kura.configuration.update" | "kura.snapshot.save" | "kura.snapshot.rollback") {
            return Err("UNSUPPORTED");
        }
        self.call_bridge(method, params, false).await
    }
    pub fn enable_configuration_updates(&mut self, enabled: bool) {
        self.configuration_updates = enabled;
    }
    pub fn configuration_updates_enabled(&self) -> bool {
        self.configuration_updates
    }
    pub fn enable_snapshots(&mut self, enabled: bool) { self.snapshots = enabled; }
    pub fn snapshots_enabled(&self) -> bool { self.snapshots }
    #[cfg(test)]
    pub(crate) async fn install_test_bridge(&self, methods: &[&str]) -> mpsc::Receiver<LocalFrame> {
        let (tx, rx) = mpsc::channel(8);
        *self.bridge.write().await = Some(Bridge {
            epoch: 1,
            tx,
            methods: methods.iter().copied().map(str::to_string).collect(),
        });
        rx
    }
    #[cfg(test)]
    pub(crate) fn complete_pending(&self, id: &str, result: Option<Value>, error: Option<&str>) {
        let call = self.pending.lock().unwrap().remove(id).expect("pending call");
        let frame = LocalFrame {
            version: 1,
            kind: "response".into(),
            request_id: id.into(),
            method: call.method.clone(),
            params: None,
            result,
            error: error.map(str::to_string),
        };
        call.tx.send(frame).ok();
    }
    pub async fn snapshot(&self, method: &'static str, params: Value) -> Result<Value, &'static str> {
        if !self.snapshots || !matches!(method, "kura.snapshot.save" | "kura.snapshot.rollback") {
            return Err("UNSUPPORTED");
        }
        self.call_bridge(method, Some(params), true).await
    }
    pub async fn update_configuration(&self, params: Value) -> Result<Value, &'static str> {
        if !self.configuration_updates {
            return Err("UNSUPPORTED");
        }
        self.call_bridge("kura.configuration.update", Some(params), true)
            .await
    }
    async fn call_bridge(
        &self,
        method: &str,
        params: Option<Value>,
        write: bool,
    ) -> Result<Value, &'static str> {
        let _permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| "RESOURCE_EXHAUSTED")?;
        let bridge = self.bridge.read().await.clone().ok_or("KURA_UNAVAILABLE")?;
        if !KURA_METHODS.contains(&method) || !bridge.methods.contains(method) {
            return Err("UNSUPPORTED");
        }
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(
            id.clone(),
            PendingCall {
                epoch: bridge.epoch,
                method: method.into(),
                tx,
            },
        );
        let _pending = PendingGuard {
            pending: self.pending.clone(),
            id: id.clone(),
        };
        let f = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: id.clone(),
            method: method.into(),
            params,
            result: None,
            error: None,
        };
        let sent = bridge.tx.try_send(f).is_ok();
        if !sent {
            return Err("RESOURCE_EXHAUSTED");
        }
        // Queue admission is the last point at which no delivery is certain.
        // A timeout, closed bridge or malformed response after it may follow a
        // completed write. Never turn that into a retryable read failure.
        let uncertain = if write {
            "OUTCOME_UNKNOWN"
        } else {
            "KURA_UNAVAILABLE"
        };
        let frame = tokio::time::timeout(Duration::from_secs(if write { 25 } else { 2 }), rx)
            .await
            .map_err(|_| if write { "OUTCOME_UNKNOWN" } else { "TIMEOUT" })?
            .map_err(|_| uncertain)?;
        match frame.error.as_deref() {
            None => Ok(frame.result.unwrap_or(Value::Null)),
            Some("RESOURCE_EXHAUSTED") => Err("RESOURCE_EXHAUSTED"),
            Some("INVALID_ARGUMENT") => Err("INVALID_ARGUMENT"),
            Some("NOT_FOUND") => Err("NOT_FOUND"),
            Some("UNSUPPORTED") => Err("UNSUPPORTED"),
            Some("CONFLICT") if write => Err("CONFLICT"),
            Some("FORBIDDEN") if write => Err("FORBIDDEN"),
            Some("TIMEOUT") if write => Err("TIMEOUT"),
            Some("KURA_UNAVAILABLE") if write => Err("KURA_UNAVAILABLE"),
            _ => Err(uncertain),
        }
    }
    pub async fn listen(&self, path: &Path) -> Result<UnixListener> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("socket requires directory"))?;
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
        }
        let dir = std::fs::symlink_metadata(parent)?;
        ensure!(
            dir.is_dir() && dir.uid() == self.uid && dir.mode() & 0o027 == 0,
            "unsafe socket directory"
        );
        if let Ok(m) = std::fs::symlink_metadata(path) {
            ensure!(
                m.file_type().is_socket() && m.uid() == self.uid,
                "refusing to replace non-owned socket"
            );
            ensure!(
                UnixStream::connect(path).await.is_err(),
                "agent socket already active"
            );
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(listener)
    }
    pub async fn serve(self, listener: UnixListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                continue;
            };
            let local = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = local.connection(stream).await {
                    tracing::debug!(error=%e,"local peer disconnected");
                }
            });
        }
    }
    async fn connection(&self, stream: UnixStream) -> Result<()> {
        let peer = stream.peer_cred()?.uid();
        ensure!(
            peer == 0 || peer == self.kura_uid || peer == self.admin_uid,
            "FORBIDDEN"
        );
        let (mut read, mut write) = stream.into_split();
        let first = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut read)).await??;
        let epoch = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<LocalFrame>(8);
        if first.kind == "register" {
            ensure!(
                peer == self.kura_uid && first.method == "kura.register",
                "FORBIDDEN"
            );
            let methods = first
                .params
                .as_ref()
                .and_then(|v| v.get("methods"))
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?;
            ensure!(
                methods.len() <= KURA_METHODS.len()
                    && methods
                        .iter()
                        .all(|v| v.as_str().is_some_and(|m| KURA_METHODS.contains(&m)))
                    && methods
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<HashSet<_>>()
                        .len()
                        == methods.len()
                    && KURA_REQUIRED_METHODS
                        .iter()
                        .all(|m| methods.iter().any(|v| v.as_str() == Some(m))),
                "UNSUPPORTED"
            );
            let mut bridge = self.bridge.write().await;
            ensure!(bridge.is_none(), "CONFLICT");
            *bridge = Some(Bridge {
                epoch,
                tx: tx.clone(),
                methods: methods
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            });
            drop(bridge);
        } else {
            ensure!(
                first.kind == "request"
                    && (first.method == "agent.status"
                        || (first.method.starts_with("network.")
                            && (peer == 0 || peer == self.admin_uid))),
                "FORBIDDEN"
            );
        }
        let registered = first.kind == "register";
        let outcome: Result<()> = async {
            // Include the acknowledgement in the cleanup scope: a peer that closes
            // immediately after registration must not leave a stale bridge owner.
            if registered {
                let ack = first.response(Some(json!({"registered":true})), None);
                tokio::time::timeout(Duration::from_secs(2), write_frame(&mut write, &ack)).await??;
            }
            let reader = async {
                let mut first_request = (!registered).then_some(first);
                let mut active = HashSet::new();
                let mut requests = JoinSet::<(String, LocalFrame)>::new();
                loop {
                    let f = if let Some(first) = first_request.take() {
                        first
                    } else {
                        // Preserve this exact read future while processing completions.
                        // read_exact is not cancellation safe after consuming a partial frame.
                        let incoming = read_frame(&mut read);
                        tokio::pin!(incoming);
                        loop {
                            tokio::select! {
                                incoming = &mut incoming => break incoming?,
                                done = requests.join_next(), if !requests.is_empty() => {
                                    let (id, response) = done.unwrap()?;
                                    active.remove(&id);
                                    tx.try_send(response).map_err(|_| anyhow::anyhow!("RESOURCE_EXHAUSTED"))?;
                                }
                            }
                        }
                    };
                    if f.kind == "response" && registered {
                        let mut pending = self.pending.lock().unwrap();
                        if let Some(call) = pending.get(&f.request_id) {
                            ensure!(call.epoch == epoch && call.method == f.method
                                && f.params.is_none() && (f.result.is_some() ^ f.error.is_some()),
                                "PROTOCOL_MISMATCH");
                            let call = pending.remove(&f.request_id).unwrap();
                            let _ = call.tx.send(f);
                        }
                    } else if f.kind == "request" {
                        // A duplicate in-flight ID cannot safely receive two correlated
                        // replies. Close this session; never execute it a second time.
                        ensure!(!active.contains(&f.request_id), "CONFLICT: duplicate request ID");
                        let Ok(permit) = self.requests.clone().try_acquire_owned() else {
                            tx.try_send(f.response(None, Some("RESOURCE_EXHAUSTED")))
                                .map_err(|_| anyhow::anyhow!("RESOURCE_EXHAUSTED"))?;
                            continue;
                        };
                        active.insert(f.request_id.clone());
                        let local = self.clone();
                        requests.spawn(async move {
                            let _permit = permit;
                            let result = tokio::time::timeout(Duration::from_secs(25),
                                local.local_request(&f, peer, registered)).await;
                            let response = match result {
                                Ok(Ok(value)) => f.response(Some(value), None),
                                Ok(Err(code)) => f.response(None, Some(&code)),
                                Err(_) => f.response(None, Some("TIMEOUT")),
                            };
                            (f.request_id, response)
                        });
                    } else {
                        tx.try_send(f.response(None, Some("FORBIDDEN")))
                            .map_err(|_| anyhow::anyhow!("RESOURCE_EXHAUSTED"))?;
                    }
                }
            };
            let writer = async {
                while let Some(f) = rx.recv().await {
                    if f.kind == "request" && !self.pending.lock().unwrap()
                        .get(&f.request_id).is_some_and(|p| p.epoch == epoch && p.method == f.method) {
                        continue;
                    }
                    tokio::time::timeout(Duration::from_secs(2), write_frame(&mut write, &f)).await??;
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! { result = reader => result, result = writer => result }
        }.await;
        if registered {
            let mut bridge = self.bridge.write().await;
            if bridge.as_ref().is_some_and(|b| b.epoch == epoch) {
                *bridge = None;
            }
            self.pending
                .lock()
                .unwrap()
                .retain(|_, call| call.epoch != epoch);
        }
        outcome
    }
    async fn local_request(
        &self,
        f: &LocalFrame,
        peer: u32,
        registered: bool,
    ) -> Result<Value, String> {
        if f.method == "agent.status" {
            return Ok(self.status().await);
        }
        if f.method.starts_with("network.kura.") {
            if !registered {
                return Err("FORBIDDEN".into());
            }
            let interfaces = self.kura_network_interfaces.as_ref().ok_or("FORBIDDEN")?;
            return self
                .network
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .kura_request(
                    f.method.clone(),
                    f.params.clone().unwrap_or(Value::Null),
                    f.request_id.clone(),
                    interfaces.clone(),
                )
                .await
                .map_err(|error| crate::network::error_code(&error).into());
        }
        if registered || (peer != 0 && peer != self.admin_uid) {
            return Err("FORBIDDEN".into());
        }
        let network = self.network.as_ref().ok_or("UNSUPPORTED")?;
        let params = f.params.clone().unwrap_or(Value::Null);
        if matches!(
            f.method.as_str(),
            "network.takeover.plan" | "network.takeover.prepare"
        ) {
            return network
                .takeover(
                    f.method.clone(),
                    serde_json::from_value(params).map_err(|_| "INVALID_ARGUMENT")?,
                    f.request_id.clone(),
                    "local-authorized".into(),
                )
                .await
                .map_err(|e| crate::network::error_code(&e).into());
        }
        let (change, action) = match f.method.as_str() {
            "network.inspect" => (None, None),
            "network.prepare" => (
                Some(serde_json::from_value(params).map_err(|_| "INVALID_ARGUMENT")?),
                None,
            ),
            "network.confirm" | "network.rollback" | "network.transaction" => (
                None,
                Some(serde_json::from_value(params).map_err(|_| "INVALID_ARGUMENT")?),
            ),
            _ => return Err("UNSUPPORTED".into()),
        };
        network
            .request(
                f.method.clone(),
                change,
                action,
                f.request_id.clone(),
                "local-authorized".into(),
            )
            .await
            .map_err(|e| crate::network::error_code(&e).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn request(id: &str, method: &str) -> LocalFrame {
        LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: id.into(),
            method: method.into(),
            params: None,
            result: None,
            error: None,
        }
    }

    async fn receive(peer: &mut UnixStream) -> LocalFrame {
        tokio::time::timeout(Duration::from_secs(1), read_frame(peer))
            .await
            .unwrap()
            .unwrap()
    }

    fn connect(local: &Local) -> (UnixStream, tokio::task::JoinHandle<Result<()>>) {
        let (peer, stream) = UnixStream::pair().unwrap();
        let local = local.clone();
        (
            peer,
            tokio::spawn(async move { local.connection(stream).await }),
        )
    }

    async fn register(local: &Local) -> (UnixStream, tokio::task::JoinHandle<Result<()>>) {
        let (mut peer, job) = connect(local);
        let mut f = request("register", "kura.register");
        f.kind = "register".into();
        f.params = Some(json!({"methods":KURA_METHODS}));
        write_frame(&mut peer, &f).await.unwrap();
        assert_eq!(receive(&mut peer).await.result.unwrap()["registered"], true);
        (peer, job)
    }

    #[tokio::test]
    async fn optional_configuration_get_preserves_params_and_typed_errors() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        for code in [
            "NOT_FOUND",
            "INVALID_ARGUMENT",
            "UNSUPPORTED",
            "RESOURCE_EXHAUSTED",
            "internal-secret",
        ] {
            let caller = local.clone();
            let call = tokio::spawn(async move {
                caller
                    .call_with_params(
                        "kura.configuration.get",
                        Some(json!({"pid":"test.pid","locale":"zh"})),
                    )
                    .await
            });
            let outgoing = receive(&mut peer).await;
            assert_eq!(
                outgoing.params,
                Some(json!({"pid":"test.pid","locale":"zh"}))
            );
            write_frame(&mut peer, &outgoing.response(None, Some(code)))
                .await
                .unwrap();
            assert_eq!(
                call.await.unwrap().unwrap_err(),
                if code == "internal-secret" {
                    "KURA_UNAVAILABLE"
                } else {
                    code
                }
            );
        }
        job.abort();
    }

    #[tokio::test]
    async fn legacy_bridge_remains_usable_without_optional_configuration_get() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = connect(&local);
        let mut registration = request("legacy", "kura.register");
        registration.kind = "register".into();
        registration.params = Some(json!({"methods":KURA_REQUIRED_METHODS}));
        write_frame(&mut peer, &registration).await.unwrap();
        assert_eq!(receive(&mut peer).await.result.unwrap()["registered"], true);
        assert_eq!(
            local
                .call_with_params(
                    "kura.configuration.get",
                    Some(json!({"pid":"test.pid","locale":"en"}))
                )
                .await,
            Err("UNSUPPORTED")
        );
        let caller = local.clone();
        let call = tokio::spawn(async move { caller.call("kura.configuration.list").await });
        let outgoing = receive(&mut peer).await;
        assert!(outgoing.params.is_none());
        write_frame(
            &mut peer,
            &outgoing.response(Some(json!(["test.pid"])), None),
        )
        .await
        .unwrap();
        assert_eq!(call.await.unwrap().unwrap(), json!(["test.pid"]));
        job.abort();
    }

    #[tokio::test]
    async fn unknown_duplicate_or_missing_registration_methods_do_not_install_owner() {
        let uid = unsafe { libc::geteuid() };
        for methods in [
            json!(["kura.configuration.list"]),
            json!([
                "kura.configuration.list",
                "kura.snapshot.list",
                "system.reboot"
            ]),
            json!([
                "kura.configuration.list",
                "kura.snapshot.list",
                "kura.snapshot.list"
            ]),
        ] {
            let local = Local::new(uid, uid);
            let (mut peer, job) = connect(&local);
            let mut registration = request("invalid", "kura.register");
            registration.kind = "register".into();
            registration.params = Some(json!({"methods":methods}));
            write_frame(&mut peer, &registration).await.unwrap();
            assert!(job.await.unwrap().is_err());
            assert_eq!(local.status().await["kuraAvailable"], false);
        }
    }

    #[tokio::test]
    async fn slow_local_request_does_not_block_same_connection() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let blocked_status = local.bridge.write().await;
        let (mut peer, job) = connect(&local);
        write_frame(&mut peer, &request("slow", "agent.status"))
            .await
            .unwrap();
        write_frame(&mut peer, &request("fast", "network.inspect"))
            .await
            .unwrap();
        let fast = receive(&mut peer).await;
        assert_eq!(fast.request_id, "fast");
        assert_eq!(fast.error.as_deref(), Some("UNSUPPORTED"));
        drop(blocked_status);
        assert_eq!(receive(&mut peer).await.request_id, "slow");
        drop(peer);
        let _ = job.await;
    }

    #[tokio::test]
    async fn outgoing_call_preserves_fragmented_reverse_response() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        let first_local = local.clone();
        let first_call = tokio::spawn(async move { first_local.call(KURA_METHODS[0]).await });
        let first = receive(&mut peer).await;
        let reply = first.response(Some(json!(["confirmed"])), None);
        let body = serde_json::to_vec(&reply).unwrap();
        let bytes = [
            (body.len() as u32).to_be_bytes().as_slice(),
            body.as_slice(),
        ]
        .concat();
        peer.write_all(&bytes[..bytes.len() - 3]).await.unwrap();
        // Let the peer reader consume the prefix. An outgoing write must not
        // cancel that read_exact and interpret the remaining bytes as a header.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second_local = local.clone();
        let second_call = tokio::spawn(async move { second_local.call(KURA_METHODS[1]).await });
        let second = receive(&mut peer).await;
        assert_eq!(second.method, KURA_METHODS[1]);
        peer.write_all(&bytes[bytes.len() - 3..]).await.unwrap();
        write_frame(&mut peer, &second.response(Some(json!([0])), None))
            .await
            .unwrap();
        assert_eq!(first_call.await.unwrap().unwrap(), json!(["confirmed"]));
        assert_eq!(second_call.await.unwrap().unwrap(), json!([0]));
        assert!(local.pending.lock().unwrap().is_empty());
        drop(peer);
        let _ = job.await;
    }

    #[tokio::test]
    async fn response_method_mismatch_closes_owner_and_fails_pending_call() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        let caller = local.clone();
        let call = tokio::spawn(async move { caller.call(KURA_METHODS[0]).await });
        let mut reply = receive(&mut peer).await.response(Some(json!([])), None);
        reply.method = KURA_METHODS[1].into();
        write_frame(&mut peer, &reply).await.unwrap();
        assert!(
            job.await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("PROTOCOL_MISMATCH")
        );
        assert_eq!(call.await.unwrap(), Err("KURA_UNAVAILABLE"));
        assert_eq!(local.status().await["kuraAvailable"], false);
        assert!(local.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancelled_call_releases_correlation_and_late_response_is_ignored() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        let caller = local.clone();
        let call = tokio::spawn(async move { caller.call(KURA_METHODS[0]).await });
        let outgoing = receive(&mut peer).await;
        assert_eq!(local.pending.lock().unwrap().len(), 1);
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert!(local.pending.lock().unwrap().is_empty());
        assert_eq!(local.calls.available_permits(), 4);
        write_frame(&mut peer, &outgoing.response(Some(json!([])), None))
            .await
            .unwrap();
        write_frame(&mut peer, &request("still-live", "agent.status"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.result.unwrap()["kuraAvailable"],
            true
        );
        drop(peer);
        let _ = job.await;
    }

    #[tokio::test]
    async fn duplicate_inflight_id_closes_connection_without_second_execution() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let blocked = local.bridge.write().await;
        let (mut peer, job) = connect(&local);
        let f = request("same", "agent.status");
        write_frame(&mut peer, &f).await.unwrap();
        write_frame(&mut peer, &f).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(1), job)
            .await
            .unwrap();
        assert!(
            outcome
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("duplicate request ID")
        );
        drop(blocked);
        // JoinSet aborts the request tasks when their connection ends.
        tokio::task::yield_now().await;
        assert_eq!(local.requests.available_permits(), 4);
    }

    #[tokio::test]
    async fn incoming_capacity_is_bounded_and_recovers() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let capacity = local.requests.clone().acquire_many_owned(4).await.unwrap();
        let (mut peer, job) = connect(&local);
        write_frame(&mut peer, &request("full", "agent.status"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.error.as_deref(),
            Some("RESOURCE_EXHAUSTED")
        );
        drop(capacity);
        write_frame(&mut peer, &request("ready", "agent.status"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.result.unwrap()["agentAvailable"],
            true
        );
        drop(peer);
        let _ = job.await;
    }

    #[tokio::test]
    async fn registered_kura_role_cannot_gain_admin_methods_from_same_uid() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        for method in [
            "network.inspect",
            "network.prepare",
            "network.confirm",
            "network.takeover.prepare",
            "network.kura.view",
        ] {
            write_frame(&mut peer, &request("policy", method))
                .await
                .unwrap();
            assert_eq!(receive(&mut peer).await.error.as_deref(), Some("FORBIDDEN"));
        }
        write_frame(&mut peer, &request("health", "agent.status"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.result.unwrap()["agentAvailable"],
            true
        );
        drop(peer);
        let _ = job.await;
    }

    #[tokio::test]
    async fn explicit_read_only_delegation_requires_registered_role_on_real_socket() {
        let uid = unsafe { libc::geteuid() };
        let root = std::env::temp_dir().join(format!("kura-delegation-{}", Uuid::new_v4()));
        let mut local = Local::new(uid, uid);
        local.network =
            Some(crate::network::Network::open(root.clone(), root.join("state"), vec![]).unwrap());
        local.delegate_kura_network(Some(vec![])).unwrap();
        assert!(
            local
                .delegate_kura_network(Some(vec!["eth0".into()]))
                .is_err()
        );
        let (mut peer, job) = register(&local).await;
        write_frame(&mut peer, &request("view", "network.kura.view"))
            .await
            .unwrap();
        let view = receive(&mut peer).await;
        assert!(view.error.is_none());
        assert_eq!(view.result.unwrap()["schemaVersion"], 1);
        let (mut admin, admin_job) = connect(&local);
        write_frame(&mut admin, &request("admin-view", "network.kura.view"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut admin).await.error.as_deref(),
            Some("FORBIDDEN")
        );
        write_frame(&mut peer, &request("still-forbidden", "network.inspect"))
            .await
            .unwrap();
        assert_eq!(receive(&mut peer).await.error.as_deref(), Some("FORBIDDEN"));
        drop(admin);
        let _ = admin_job.await;
        drop(peer);
        let _ = job.await;
        drop(local);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unavailable_bridge_does_not_disable_agent() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        assert_eq!(
            local.call("kura.configuration.list").await,
            Err("KURA_UNAVAILABLE")
        );
        assert_eq!(local.status().await["agentAvailable"], true);
    }

    #[tokio::test]
    async fn disconnected_registration_releases_bridge_owner() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, server) = UnixStream::pair().unwrap();
        let frame = LocalFrame {
            version: 1,
            kind: "register".into(),
            request_id: "register".into(),
            method: "kura.register".into(),
            params: Some(json!({"methods":KURA_METHODS})),
            result: None,
            error: None,
        };
        write_frame(&mut peer, &frame).await.unwrap();
        drop(peer);
        let _ = local.connection(server).await;
        assert_eq!(local.status().await["kuraAvailable"], false);
        assert!(local.pending.lock().unwrap().is_empty());
    }
}
