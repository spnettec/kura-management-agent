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
#[cfg(test)]
mod template_bridge_tests {
    use super::*;
    #[tokio::test]
    async fn read_path_and_wrong_original_registration_never_queue_a_template_export() {
        let local=Local::new(7,9);let mut rx=local.install_test_bridge(&["kura.network.template.export"]).await;
        assert_eq!(local.call_with_params("kura.network.template.export",Some(json!({}))).await.unwrap_err(),"UNSUPPORTED");
        assert_eq!(local.network_template_export(Uuid::new_v4().to_string(),"rev".into(),"a".repeat(64),Uuid::new_v4(),1,json!({})).await.unwrap_err(),"CONFLICT");
        assert_eq!(local.network_template_export(Uuid::new_v4().to_string(),"rev".into(),"a".repeat(64),local.instance_id,2,json!({})).await.unwrap_err(),"CONFLICT");
        assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn registered_export_disconnect_is_unknown_and_has_exactly_one_queued_request() {
        let local=Local::new(7,9);let mut rx=local.install_test_bridge(&["kura.network.template.export"]).await;
        let copy=local.clone();let operation=Uuid::new_v4().to_string();let expected=operation.clone();
        let task=tokio::spawn(async move{copy.network_template_export(operation,"rev".into(),"a".repeat(64),copy.instance_id,1,json!({})).await});
        let request=rx.recv().await.unwrap();assert_eq!(request.params.as_ref().unwrap()["operationId"],expected);
        local.pending.lock().unwrap().remove(&request.request_id);
        assert_eq!(task.await.unwrap().unwrap_err(),"OUTCOME_UNKNOWN");assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn deposit_requires_the_actual_registered_connection_epoch_even_for_admin_uid() {
        let local=Local::new(7,9);let _rx=local.install_test_bridge(&[]).await;
        let frame=LocalFrame{version:1,kind:"request".into(),request_id:Uuid::new_v4().to_string(),method:"network.nm.template.deposit".into(),
            params:Some(json!({"bridgeEpoch":1,"ready":true})),result:None,error:None};
        for (peer,registered,epoch) in [(9,true,1),(7,false,1),(7,true,2)] {
            assert_eq!(local.template_deposit(&frame,peer,registered,epoch).await.unwrap_err(),"FORBIDDEN");
        }
        assert_eq!(local.local_request(&frame,9,false).await.unwrap_err(),"FORBIDDEN");
        assert_eq!(local.local_request(&frame,7,true).await.unwrap_err(),"FORBIDDEN");
        for method in ["network.nm.template.confirmed","network.nm.template.chunk"] {
            let mut read=frame.clone();read.method=method.into();
            assert_eq!(local.template_deposit(&read,9,true,1).await.unwrap_err(),"FORBIDDEN");
            assert_eq!(local.template_deposit(&read,7,true,2).await.unwrap_err(),"FORBIDDEN");
            assert_eq!(local.local_request(&read,9,false).await.unwrap_err(),"FORBIDDEN");
        }
    }

    #[tokio::test]
    async fn original_firewall_reads_preserve_a_paired_provider_conflict() {
        let local = Local::new(7, 9);
        let methods = ["kura.firewall.source", "kura.firewall.origin", "kura.configuration.get"];
        let mut requests = local.install_test_bridge(&methods).await;
        for method in methods {
            let peer = local.clone();
            let read = tokio::spawn(async move { peer.call_bridge_bound(method, None, false, Some(1)).await });
            let request = requests.recv().await.unwrap();
            assert_eq!(request.method, method);
            let pending = local.pending.lock().unwrap().remove(&request.request_id).unwrap();
            pending.tx.send(request.response(None, Some("CONFLICT"))).unwrap();
            let expected = if method == "kura.configuration.get" { "KURA_UNAVAILABLE" } else { "CONFLICT" };
            assert_eq!(read.await.unwrap().unwrap_err(), expected);
            assert!(requests.try_recv().is_err());
        }
    }
}
#[cfg(test)]
mod renewal_tests;
// A reserved role read or drain can traverse the same confirmed provider
// cohort as owner(), including authenticated UDS reads back into the Agent.
const CONFIRMED_CORE_READ_BUDGET: Duration = Duration::from_secs(20);
// The paired owner coordinator has a bounded 60-second proof and settlement window.
const IMPORTED_AUTHORITY_REQUEST_BUDGET: Duration = Duration::from_secs(65);
const IMPORTED_AUTHORITY_REQUESTS: &[&str] = &[
    "firewall.kura.imported.review",
    "firewall.kura.imported.prepare",
    "firewall.kura.imported.apply",
    "firewall.kura.imported.confirm",
    "firewall.kura.imported.rollback",
    "firewall.kura.imported.source.review",
    "firewall.kura.imported.source.observe",
];
const KURA_METHODS: &[&str] = &[
    "kura.configuration.list",
    "kura.snapshot.list",
    "kura.configuration.get",
    "kura.network.roles",
    "kura.firewall.source",
    "kura.firewall.origin",
    "kura.network.fence",
    "kura.network.owner",
    "kura.network.startup.profile",
    "kura.network.template.export",
    "kura.configuration.outcome",
    "kura.configuration.update",
    "kura.snapshot.save",
    "kura.snapshot.rollback",
    "kura.recovery.verify",
    "kura.recovery.complete",
    "kura.ordinary.verify",
];
#[derive(Clone)]
struct Bridge {
    epoch: u64,
    tx: mpsc::Sender<LocalFrame>,
    methods: HashSet<String>,
    peer_pid: Option<i32>,
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
            peer_pid: None,
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
            local
                .snapshot("kura.snapshot.save", json!({}))
                .await
                .unwrap_err(),
            "UNSUPPORTED"
        );
        assert_eq!(
            local
                .snapshot("kura.snapshot.rollback", json!({}))
                .await
                .unwrap_err(),
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
    instance_id: Uuid,
    pub(crate) remote: Option<crate::remote::Remote>,
    pub(crate) management_connection: Arc<StdMutex<Option<String>>>,
    pub(crate) enrollment: Option<crate::enrollment::Enrollment>,
    pub(crate) kura_remote_management: bool,
    pub(crate) kura_firewall_write: bool,
    pub(crate) firewall_remote: bool,
    pub(crate) nm_remote: bool,
    pub(crate) system_state: Option<std::path::PathBuf>,
    pub network: Option<crate::network::Network>,
    pub(crate) nm: Option<crate::nm::Nm>,
    pub firewall: Option<crate::firewall::Firewall>,
    pub recovery: Option<crate::recovery::Recovery>,
    native_snapshot_validation: Option<crate::native_snapshot_validation::Service>,
    pub(crate) ordinary_boot: Option<crate::boot_control::Control>,
    pub(crate) ordinary_handoff_remote: bool,
    pub(crate) system_control: Option<crate::system_control::Control>,
    pub(crate) system_control_remote: bool,
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
            instance_id: Uuid::new_v4(),
            remote: None,
            management_connection: Default::default(),
            enrollment: None,
            kura_remote_management: false,
            kura_firewall_write: false,
            firewall_remote: false,
            nm_remote: false,
            system_state: None,
            network: None,
            nm: None,
            firewall: None,
            recovery: None,
            native_snapshot_validation: None,
            ordinary_boot: None,
            ordinary_handoff_remote: false,
            system_control: None,
            system_control_remote: false,
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
    /// A read-only recovery observation is bound to one agent instance and one uninterrupted bridge session.
    pub async fn recovery_verification(
        &self,
        params: Value,
    ) -> Result<(Value, String, u64), &'static str> {
        let epoch = self
            .bridge
            .read()
            .await
            .as_ref()
            .ok_or("KURA_UNAVAILABLE")?
            .epoch;
        let result = self
            .call_bridge("kura.recovery.verify", Some(params), false)
            .await?;
        if self.bridge.read().await.as_ref().map(|b| b.epoch) != Some(epoch) {
            return Err("KURA_UNAVAILABLE");
        }
        Ok((result, self.instance_id.to_string(), epoch))
    }
    pub async fn ordinary_verification(
        &self,
        params: Value,
    ) -> Result<(Value, String, u64), &'static str> {
        let epoch = self
            .bridge
            .read()
            .await
            .as_ref()
            .ok_or("KURA_UNAVAILABLE")?
            .epoch;
        let result = self
            .call_bridge("kura.ordinary.verify", Some(params), false)
            .await?;
        if self.bridge.read().await.as_ref().map(|b| b.epoch) != Some(epoch) {
            return Err("KURA_UNAVAILABLE");
        }
        Ok((result, self.instance_id.to_string(), epoch))
    }
    pub(crate) async fn network_roles(&self) -> Result<crate::nm::roles::Observation, &'static str> {
        let epoch=self.bridge.read().await.as_ref().ok_or("KURA_UNAVAILABLE")?.epoch;
        let value=self.call_bridge_limited("kura.network.roles",Some(json!({})),false,Some(epoch),CONFIRMED_CORE_READ_BUDGET).await?;
        if self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {return Err("KURA_UNAVAILABLE");}
        crate::nm::roles::Observation::new(self.instance_id,epoch,value).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_role_fence(&self) -> Result<crate::nm::roles::Observation, &'static str> {
        let epoch=self.bridge.read().await.as_ref().ok_or("KURA_UNAVAILABLE")?.epoch;
        let value=self.call_bridge_limited("kura.network.fence",Some(json!({})),false,Some(epoch),CONFIRMED_CORE_READ_BUDGET).await?;
        if self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {return Err("KURA_UNAVAILABLE");}
        if value.as_object().is_none_or(|v|v.len()!=3) || value["schemaVersion"]!=1 || value["fenced"]!=true {
            return Err("CONFLICT");
        }
        crate::nm::roles::Observation::new(self.instance_id,epoch,value["roles"].clone()).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_firewall_origin(&self,expected:&crate::nm::roles::Observation)
            ->Result<Option<crate::nm::roles::Origin>,&'static str> {
        let epoch={let current=self.bridge.read().await;let bridge=current.as_ref().ok_or("KURA_UNAVAILABLE")?;
            if !expected.matches_registration(self.instance_id,bridge.epoch){return Err("CONFLICT");}
            if !bridge.methods.contains("kura.firewall.origin"){return Ok(None);}bridge.epoch};
        let value=self.call_bridge_limited("kura.firewall.origin",Some(json!({"networkRevision":expected.source_revision()})),false,Some(epoch),Duration::from_secs(8)).await?;
        if self.bridge.read().await.as_ref().map(|bridge|bridge.epoch)!=Some(epoch){return Err("KURA_UNAVAILABLE");}
        crate::nm::roles::Origin::new(self.instance_id,epoch,expected,value).map(Some).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_firewall_source(&self,expected:&crate::nm::roles::Observation)
            ->Result<crate::nm::roles::FirewallSource,&'static str> {
        let epoch=self.bridge.read().await.as_ref().ok_or("KURA_UNAVAILABLE")?.epoch;
        if !expected.matches_registration(self.instance_id,epoch){return Err("CONFLICT");}
        let revision=expected.source_revision();
        let value=self.call_bridge_limited("kura.firewall.source",Some(json!({"networkRevision":revision})),false,Some(epoch),Duration::from_secs(2)).await?;
        if self.bridge.read().await.as_ref().map(|bridge|bridge.epoch)!=Some(epoch){return Err("KURA_UNAVAILABLE");}
        crate::nm::roles::FirewallSource::new(self.instance_id,epoch,expected,value).map_err(|_|"CONFLICT")
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn require_continuity_registration(
        &self, roles: &crate::nm::roles::Observation,
        anchor: &crate::nm::handover::continuity::RegistrationAnchor,
    ) -> Result<(), &'static str> {
        let bridge = self.bridge.read().await;
        let bridge = bridge.as_ref().ok_or("KURA_UNAVAILABLE")?;
        if !roles.matches_registration(self.instance_id, bridge.epoch) {
            return Err("CONFLICT");
        }
        anchor.require_peer(bridge.peer_pid).map_err(|error| crate::network::error_code(&error))
    }

    #[cfg(target_os = "linux")]
    async fn verify_nm_upgrade_registration(&self, params: Value, legacy_stop: bool) -> Result<Value, String> {
        use crate::nm::handover::continuity::{legacy_stop_registration_anchor, registration_anchor};

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Request {
            operation_id: String,
        }
        #[derive(serde::Deserialize, Clone)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct StopRequest {
            operation_id: String,
            confirmation_token: String,
            startup_confirmation_token: String,
        }
        let (id, stop) = if legacy_stop {
            let input: StopRequest = serde_json::from_value(params).map_err(|_| "INVALID_ARGUMENT")?;
            (input.operation_id.clone(), Some(input))
        } else {
            let input: Request = serde_json::from_value(params).map_err(|_| "INVALID_ARGUMENT")?;
            (input.operation_id, None)
        };
        let operation = crate::nm::handover::template::operation(&id)
            .map_err(|_| "INVALID_ARGUMENT")?;
        let observe = || {
            let stop = stop.clone();
            async move {
            tokio::task::spawn_blocking(move || match stop {
                Some(input) => legacy_stop_registration_anchor(operation, &input.confirmation_token, &input.startup_confirmation_token),
                None => registration_anchor(operation),
            })
                .await.map_err(|_| "INTERNAL")?
                .map_err(|error| {
                    tracing::debug!(code=crate::network::error_code(&error), "Original NM upgrade anchor refused");
                    crate::network::error_code(&error)
                })
            }
        };
        let anchor = observe().await?;
        let session = self.bridge.read().await.as_ref().cloned().ok_or("KURA_UNAVAILABLE")?;
        anchor.require_peer(session.peer_pid).map_err(|error| crate::network::error_code(&error))?;
        let roles = self.network_roles().await?;
        if !roles.matches_registration(self.instance_id, session.epoch) {
            return Err("KURA_UNAVAILABLE".into());
        }
        let source = self.network_firewall_source(&roles).await?;
        let model = self.network_firewall_origin(&roles).await?.ok_or("UNSUPPORTED")?;
        anchor.require_source(&roles, &source, &model).map_err(|error| crate::network::error_code(&error))?;
        if observe().await? != anchor || !self.bridge.read().await.as_ref()
            .is_some_and(|bridge| bridge.epoch == session.epoch && bridge.peer_pid == session.peer_pid)
        {
            return Err("CONFLICT".into());
        }
        Ok(anchor.parameters())
    }
    pub(crate) async fn network_owner(&self) -> Result<crate::nm::roles::Owner, &'static str> {
        let epoch=self.bridge.read().await.as_ref().ok_or("KURA_UNAVAILABLE")?.epoch;
        let value=self.call_bridge_limited("kura.network.owner",Some(json!({})),false,Some(epoch),CONFIRMED_CORE_READ_BUDGET).await?;
        if self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {return Err("KURA_UNAVAILABLE");}
        crate::nm::roles::Owner::new(self.instance_id,epoch,value).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_owner_registration(&self,instance:Uuid,epoch:u64)->Result<(),&'static str> {
        if instance!=self.instance_id || self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {return Err("CONFLICT");}Ok(())
    }
    pub(crate) async fn network_startup_association(&self,params:Value)->Result<crate::nm::roles::StartupAssociation,&'static str> {
        let epoch=self.bridge.read().await.as_ref().ok_or("KURA_UNAVAILABLE")?.epoch;
        let value=self.call_bridge("kura.network.startup.profile",Some(params),false).await?;
        if self.bridge.read().await.as_ref().map(|bridge|bridge.epoch)!=Some(epoch) {return Err("KURA_UNAVAILABLE");}
        if serde_json::to_vec(&value).map_err(|_|"CONFLICT")?.len()>16384 {return Err("CONFLICT");}
        crate::nm::roles::StartupAssociation::new(self.instance_id,epoch,value).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_runtime_executable(&self,mut params:Value,pid:u32) -> Result<crate::nm::roles::RuntimeExecutable,&'static str> {
        let expected_pid = i32::try_from(pid).map_err(|_|"CONFLICT")?;
        let epoch = {
            let current = self.bridge.read().await;
            let bridge = current.as_ref().ok_or("KURA_UNAVAILABLE")?;
            if bridge.peer_pid != Some(expected_pid) {return Err("CONFLICT");}
            bridge.epoch
        };
        params["executableProcessId"] = json!(pid);
        let value=self.call_bridge_bound("kura.network.startup.profile",Some(params),false,Some(epoch)).await
            .map_err(|code| if code=="INVALID_ARGUMENT" {"UNSUPPORTED"} else {code})?;
        if !self.bridge.read().await.as_ref().is_some_and(|bridge|bridge.epoch==epoch && bridge.peer_pid==Some(expected_pid)) {
            return Err("CONFLICT");
        }
        crate::nm::roles::RuntimeExecutable::new(value,pid).map_err(|_|"CONFLICT")
    }
    pub(crate) async fn network_template_export(&self,operation:String,revision:String,nonce:String,instance:Uuid,epoch:u64,firewall_source:Value)->Result<Value,&'static str> {
        if instance!=self.instance_id || epoch==0 {return Err("CONFLICT");}
        let result=self.call_bridge_bound("kura.network.template.export",Some(json!({"operationId":operation,"revision":revision,"depositToken":nonce,"firewallSource":firewall_source})),true,Some(epoch)).await?;
        if self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {return Err("OUTCOME_UNKNOWN");}
        Ok(result)
    }
    pub async fn recovery_completion(&self, params: Value) -> Result<Value, &'static str> {
        self.call_bridge("kura.recovery.complete", Some(params), true)
            .await
    }
    pub async fn call_with_params(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, &'static str> {
        if matches!(
            method,
            "kura.configuration.update" | "kura.snapshot.save" | "kura.snapshot.rollback" | "kura.network.template.export"
        ) {
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
    pub(crate) async fn configuration_bridge_state(&self) -> (bool, bool) {
        let current = self.bridge.read().await;
        let bridge = current.as_ref().filter(|bridge| !bridge.tx.is_closed());
        let ready = self.configuration_updates && bridge.is_some_and(|bridge| {
            bridge.methods.contains(yofc_management_protocol::CONFIGURATION_UPDATE_CAPABILITY)
        });
        (bridge.is_some(), ready)
    }
    pub fn enable_snapshots(&mut self, enabled: bool) {
        self.snapshots = enabled;
    }
    pub fn snapshots_enabled(&self) -> bool {
        self.snapshots
    }
    #[cfg(test)]
    pub(crate) async fn install_test_bridge(&self, methods: &[&str]) -> mpsc::Receiver<LocalFrame> {
        let (tx, rx) = mpsc::channel(8);
        *self.bridge.write().await = Some(Bridge {
            epoch: 1,
            tx,
            methods: methods.iter().copied().map(str::to_string).collect(),
            peer_pid: None,
        });
        rx
    }
    #[cfg(test)]
    pub(crate) fn complete_pending(&self, id: &str, result: Option<Value>, error: Option<&str>) {
        let call = self
            .pending
            .lock()
            .unwrap()
            .remove(id)
            .expect("pending call");
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
    pub async fn snapshot(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, &'static str> {
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
        self.call_bridge_bound(method,params,write,None).await
    }
    async fn call_bridge_bound(&self,method:&str,params:Option<Value>,write:bool,expected:Option<u64>)->Result<Value,&'static str> {
        self.call_bridge_limited(method,params,write,expected,Duration::from_secs(if write {25} else {2})).await
    }
    async fn call_bridge_limited(&self,method:&str,params:Option<Value>,write:bool,expected:Option<u64>,budget:Duration)->Result<Value,&'static str> {
        let _permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| "RESOURCE_EXHAUSTED")?;
        let bridge = self.bridge.read().await.clone().ok_or("KURA_UNAVAILABLE")?;
        if expected.is_some_and(|epoch|epoch!=bridge.epoch) {return Err("CONFLICT");}
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
        let frame = tokio::time::timeout(budget, rx)
            .await
            .map_err(|_| if write { "OUTCOME_UNKNOWN" } else { "TIMEOUT" })?
            .map_err(|_| uncertain)?;
        match frame.error.as_deref() {
            None => Ok(frame.result.unwrap_or(Value::Null)),
            Some("RESOURCE_EXHAUSTED") => Err("RESOURCE_EXHAUSTED"),
            Some("INVALID_ARGUMENT") => Err("INVALID_ARGUMENT"),
            Some("NOT_FOUND") => Err("NOT_FOUND"),
            Some("UNSUPPORTED") => Err("UNSUPPORTED"),
            // A paired original firewall read can conflict with an ordinary CM
            // update while its provider views converge. Preserve that refusal.
            Some("CONFLICT") if write || matches!(method, "kura.firewall.source" | "kura.firewall.origin") => {
                Err("CONFLICT")
            }
            Some("FORBIDDEN") if write => Err("FORBIDDEN"),
            Some("TIMEOUT") if write => Err("TIMEOUT"),
            Some("KURA_UNAVAILABLE") if write => Err("KURA_UNAVAILABLE"),
            _ => Err(uncertain),
        }
    }
    pub(crate) fn enable_native_snapshot_validation(&mut self, runtime: std::path::PathBuf) {
        self.native_snapshot_validation = Some(crate::native_snapshot_validation::Service::new(runtime));
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
                    // Rejections (handshake, protocol, bridge conflicts) close the
                    // socket without a wire reply, so the peer only sees EOF. The
                    // operator needs the reason in the journal, not a debug line.
                    tracing::warn!(error=%e,"local control peer rejected");
                }
            });
        }
    }
    async fn connection(&self, stream: UnixStream) -> Result<()> {
        let credentials = stream.peer_cred()?;
        let peer = credentials.uid();
        ensure!(
            peer == 0 || peer == self.kura_uid || peer == self.admin_uid,
            "FORBIDDEN"
        );
        let (mut read, mut write) = stream.into_split();
        let first = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut read)).await??;
        use crate::native_snapshot_validation::{
            GUARDED_HEALTH, GUARDED_ORIGINAL, GUARDED_RELEASE, GUARDED_RELEASE_ORIGINAL, GUARDED_START,
            MAIN_HEALTH, MAIN_ORIGINAL, MAIN_START, MAIN_STOP, METHOD, ORIGINAL, STAGE,
        };
        if first.kind == "request" && matches!(first.method.as_str(), METHOD | ORIGINAL | STAGE | MAIN_START
            | MAIN_STOP | MAIN_ORIGINAL | MAIN_HEALTH | GUARDED_START | GUARDED_ORIGINAL | GUARDED_HEALTH
            | GUARDED_RELEASE | GUARDED_RELEASE_ORIGINAL) {
            let reply = self.native_snapshot_response(peer, &first, &mut read).await;
            tokio::time::timeout(Duration::from_secs(2), write_frame(&mut write, &reply)).await??;
            return Ok(());
        }
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
                #[cfg(target_os = "linux")]
                peer_pid: credentials.pid(),
                #[cfg(not(target_os = "linux"))]
                peer_pid: None,
            });
            drop(bridge);
        } else {
            ensure!(
                first.kind == "request"
                    && (first.method == "agent.status"
                        || (first.method.starts_with("remote.")
                            && (peer == 0 || peer == self.admin_uid || peer == self.kura_uid))
                        || ((first.method.starts_with("network.")
                            || first.method.starts_with("firewall.")
                            || first.method.starts_with("recovery.")
                            || first.method.starts_with("ordinary.boot.")
                            || crate::system_control::operation(&first.method).is_some())
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
                            // Recovery includes bounded Java/profile checks, unit stop/start and
                            // application evidence. Dropping this future does not cancel its
                            // blocking transaction; a timeout must never invite a write retry.
                            let recovery_write = matches!(f.method.as_str(),
                                "recovery.prepare" | "recovery.execute" | "recovery.rollback"
                                | "recovery.compensation.prepare" | "recovery.compensation.execute"
                                | "recovery.snapshots.prepare" | "recovery.snapshots.execute"
                                | "recovery.normal.forward.prepare"
        | "recovery.normal.prepare" | "recovery.normal.execute"
                                | "recovery.health.prepare" | "recovery.health.execute"
                                | "recovery.completion.prepare" | "recovery.completion.execute"
                                | "recovery.ordinary.prepare" | "recovery.ordinary.execute" | "recovery.ordinary.cancel"
                                | "ordinary.boot.prepare" | "ordinary.boot.execute"
                                | "ordinary.boot.cancel" | "ordinary.boot.reconcile")
                                  || matches!(f.method.as_str(),"network.nm.ownership.prepare"|"network.nm.ownership.original"|"network.nm.ownership.cancel"|"network.nm.ownership.fence"|"network.nm.ownership.fence.arm"|"network.nm.ownership.activate"|"network.nm.ownership.startup.prepare"|"network.nm.ownership.startup.verify"|"network.nm.ownership.startup.stop"|"network.nm.ownership.startup.publish"|"network.nm.ownership.startup.start"|"network.nm.ownership.startup.complete"|"network.nm.ownership.startup.recovery.prepare"|"network.nm.ownership.startup.recovery.original"|"network.nm.ownership.startup.recovery.execute"|"network.nm.ownership.startup.recovery.cancel")
                                || crate::system_control::operation(&f.method).is_some_and(|op|op!=23);
                            let imported = IMPORTED_AUTHORITY_REQUESTS.contains(&f.method.as_str());
                            let budget = if recovery_write {
                                Duration::from_secs(600)
                            } else if imported {
                                IMPORTED_AUTHORITY_REQUEST_BUDGET
                            } else {
                                Duration::from_secs(25)
                            };
                            let ambiguous = recovery_write || (imported && !f.method.ends_with(".review"));
                            let result = tokio::time::timeout(budget,
                                  async {
                                      if matches!(f.method.as_str(),"network.nm.template.deposit"|"network.nm.template.confirmed"|"network.nm.template.chunk") {
                                          local.template_deposit(&f,peer,registered,epoch).await
                                      }
                                      else {local.local_request(&f, peer, registered).await}
                                  }).await;
                            let response = match result {
                                Ok(Ok(value)) => f.response(Some(value), None),
                                Ok(Err(code)) => f.response(None, Some(&code)),
                                Err(_) => f.response(None, Some(if ambiguous { "OUTCOME_UNKNOWN" } else { "TIMEOUT" })),
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
    async fn template_deposit(&self,f:&LocalFrame,peer:u32,registered:bool,epoch:u64)->Result<Value,String> {
        if !registered || peer!=self.kura_uid || self.bridge.read().await.as_ref().map(|b|b.epoch)!=Some(epoch) {
            return Err("FORBIDDEN".into());
        }
        if matches!(f.method.as_str(),"network.nm.template.confirmed"|"network.nm.template.chunk") {
            let root=self.system_state.clone().ok_or("UNSUPPORTED")?;let method=f.method.clone();let params=f.params.clone().unwrap_or(Value::Null);
            return tokio::task::spawn_blocking(move||crate::nm::handover::confirmed_read(&root,&method,params)).await
                .map_err(|_|String::from("KURA_UNAVAILABLE"))?.map_err(|e|crate::network::error_code(&e).to_string());
        }
        self.nm.as_ref().ok_or("UNSUPPORTED")?.deposit_template(f.params.clone().unwrap_or(Value::Null),self.instance_id,epoch).await
            .map_err(|error|match crate::network::error_code(&error) {"INTERNAL"=>"OUTCOME_UNKNOWN",code=>code}.to_string())
    }
    async fn native_snapshot_response(
        &self,
        peer: u32,
        request: &LocalFrame,
        read: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> LocalFrame {
        if peer != 0 {
            return request.response(None, Some("FORBIDDEN"));
        }
        let Some(service) = &self.native_snapshot_validation else {
            return request.response(None, Some("UNSUPPORTED"));
        };
        use crate::native_snapshot_validation::{GUARDED_HEALTH, GUARDED_RELEASE, GUARDED_RELEASE_ORIGINAL, MAIN_HEALTH};
        if matches!(request.method.as_str(), GUARDED_RELEASE | GUARDED_RELEASE_ORIGINAL) {
            let result = if request.method == GUARDED_RELEASE {
                self.guarded_write_release(request.params.as_ref()).await
            } else {
                Self::guarded_release_original(request.params.as_ref()).await
            };
            return match result {
                Ok(value) => request.response(Some(value), None),
                Err(code) => request.response(None, Some(code)),
            };
        }
        if matches!(request.method.as_str(), MAIN_HEALTH | GUARDED_HEALTH) {
            return match self.fixed_main_health(request.params.as_ref(), request.method == GUARDED_HEALTH).await {
                Ok(value) => request.response(Some(value), None),
                Err(code) => request.response(None, Some(code)),
            };
        }
        match service.handle(&request.method, request.params.as_ref(), read).await {
            Ok(value) => request.response(Some(value), None),
            Err(code) => request.response(None, Some(code)),
        }
    }

    async fn fixed_main_health(&self, params: Option<&Value>, guarded: bool) -> Result<Value, &'static str> {
        use crate::{core_validation::native_application, recovery::health::FixedMainRequest};
        let request: FixedMainRequest = serde::Deserialize::deserialize(params.ok_or("INVALID_ARGUMENT")?)
            .map_err(|_| "INVALID_ARGUMENT")?;
        request.validate()?;
        let id = request.restore_id.clone();
        let before = tokio::task::spawn_blocking(move || native_application(&id, guarded))
            .await.map_err(|_| "INTERNAL")??;
        if before["receiptSha256"] != request.receipt_sha256 {
            return Err("CONFLICT");
        }
        let nonce = crate::durable::hash(uuid::Uuid::new_v4().as_bytes());
        // The verifier's admission binds the artifact the Main actually reads; a
        // converted publication reports that digest instead of the source lineage.
        let bound = before.get("publishedSha256").and_then(Value::as_str)
            .unwrap_or_else(|| before["snapshotSha256"].as_str().unwrap_or_default());
        let challenge = request.challenge(&Value::String(bound.to_string()), &nonce);
        let (report, instance, epoch) = self.recovery_verification(challenge).await?;
        let verified = request.report(&report, &before, &nonce, guarded)?;
        let id = request.restore_id.clone();
        let after = tokio::task::spawn_blocking(move || native_application(&id, guarded))
            .await.map_err(|_| "INTERNAL")??;
        if before != after || self.bridge.read().await.as_ref().map(|bridge| bridge.epoch) != Some(epoch) {
            return Err("CONFLICT");
        }
        Ok(json!({"scope":"administrator-selected-checks","selectedChecksVerified":verified,
                  "originalApplication":before,"agentInstanceId":instance,"bridgeEpoch":epoch,
                  "report":report,"ordinaryWritesReleased":false,"kuraRecoveryVerified":false}))
    }

    async fn guarded_release_original(params: Option<&Value>) -> Result<Value, &'static str> {
        let values = params.and_then(Value::as_object).ok_or("INVALID_ARGUMENT")?;
        let identity = values.get("restoreId").and_then(Value::as_str)
            .filter(|id| crate::core_validation::restore_id(id) && values.len() == 1)
            .ok_or("INVALID_ARGUMENT")?.to_owned();
        tokio::task::spawn_blocking(move || crate::core_validation::fixed_release(&identity, None))
            .await.map_err(|_| "INTERNAL")?
    }

    async fn guarded_write_release(&self, params: Option<&Value>) -> Result<Value, &'static str> {
        let health = self.fixed_main_health(params, true).await?;
        if health["selectedChecksVerified"] != true {
            return Err("CONFLICT");
        }
        let params: crate::recovery::health::FixedMainRequest =
            serde::Deserialize::deserialize(params.ok_or("INVALID_ARGUMENT")?).map_err(|_| "INVALID_ARGUMENT")?;
        let proof = &health["originalApplication"];
        let report = &health["report"];
        let epoch = health["bridgeEpoch"].as_u64().ok_or("CONFLICT")?;
        let nonce = crate::durable::hash(uuid::Uuid::new_v4().as_bytes());
        let challenge = params.challenge(&proof["snapshotSha256"], &nonce);
        let health_sha = crate::durable::hash(&serde_json::to_vec(&health).map_err(|_| "INTERNAL")?);
        let identity = params.restore_id.clone();
        let issue = json!({"schema":1,"action":"main-release-issue","restoreId":identity,
            "expectedSha256":params.receipt_sha256,"healthReceiptSha256":health_sha,"nonce":nonce,
            "checks":{"componentPids":challenge["componentPids"],"checkIds":challenge["checkIds"],
                      "additionalSelfPids":challenge["additionalSelfPids"]}});
        let id = identity.clone();
        let intent = tokio::task::spawn_blocking(move || crate::core_validation::fixed_release(&id, Some(issue)))
            .await.map_err(|_| "UNKNOWN")??;
        if intent["root"] != proof["root"] || intent["normalReceiptSha256"] != params.receipt_sha256
            || intent["healthReceiptSha256"] != health_sha || intent["nonce"] != nonce
        {
            return Err("UNKNOWN");
        }
        let reply = self.call_bridge_bound("kura.recovery.complete", Some(json!({
            "challenge":challenge,"completionId":intent["completionId"],"decisionSha256":intent["decisionSha256"],
            "policySha256":intent["decisionSha256"],"notAfterUnixMillis":intent["notAfterUnixMillis"],
            "healthReceiptSha256":health_sha,"bounds":{"sourceCount":report["sourceConfigurationCount"],
            "managedCount":report["managedConfigurationCount"],"propertyCount":report["propertyCount"],
            "materializedSelfPids":report["materializedSelfPids"]}
        })), true, Some(epoch)).await;
        let status = tokio::task::spawn_blocking(move || crate::core_validation::fixed_release(&identity, None))
            .await.map_err(|_| "UNKNOWN")?.map_err(|_| "UNKNOWN")?;
        if status["state"] != "GUARDED_RELEASE_COMMITTED" || !["root","restoreId","completionId","decisionSha256",
            "normalReceiptSha256","healthReceiptSha256","nonce"].into_iter().all(|key| status[key] == intent[key])
        {
            return Err("UNKNOWN");
        }
        let reply_verified = reply.is_ok_and(|reply| reply["writeReleaseCommitted"] == true
            && reply["kuraRecoveryVerified"] == false && reply["completionId"] == intent["completionId"]
            && reply["decisionSha256"] == intent["decisionSha256"] && reply["receiptSha256"] == status["releaseReceiptSha256"]
            && reply["processId"] == report["processId"] && reply["recoveryId"] == status["restoreId"]);
        Ok(json!({"release":status,"bridgeReplyVerified":reply_verified,"kuraRecoveryVerified":false}))
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
        if matches!(f.method.as_str(), "remote.renewal-status" | "remote.renew-identity") {
            let enrollment = self.enrollment.clone().ok_or("UNSUPPORTED")?;
            // Credential changes require the fixed source grant plus channel
            // control. Authorized operators can still read original public proof
            // after the source grant is revoked. First binding is unchanged.
            let allowed = if registered { self.kura_remote_management }
                else { peer==0 || peer==self.admin_uid };
            if !allowed || f.method=="remote.renew-identity" && !enrollment.granted() {
                return Err("FORBIDDEN".into());
            }
            let remote = self.remote.clone().ok_or("UNSUPPORTED")?;
            let params = f.params.clone().unwrap_or(json!({}));
            if f.method == "remote.renewal-status" {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields,rename_all="camelCase")]
                struct Read { operation_id:Option<String> }
                let input:Read=serde_json::from_value(params).map_err(|_|String::from("INVALID_ARGUMENT"))?;
                return tokio::task::spawn_blocking(move ||enrollment.renewal_status(input.operation_id.as_deref(),&remote))
                    .await.map_err(|_|String::from("INTERNAL"))?
                    .map_err(|error|crate::network::error_code(&error).into());
            }
            let input:crate::enrollment::RenewInput=serde_json::from_value(params).map_err(|_|String::from("INVALID_ARGUMENT"))?;
            let actor=format!("{}-uid:{peer}",if registered {"kura"} else {"local"});
            // Once admitted, any failure may have crossed a durable boundary.
            // Reconcile through the original operation; never retry this request.
            return enrollment.renew(input,remote,actor).await.map_err(|error|match crate::network::error_code(&error) {
                "INVALID_ARGUMENT"=>String::from("INVALID_ARGUMENT"),
                "FORBIDDEN"=>String::from("FORBIDDEN"),
                _=>String::from("UNKNOWN"),
            });
        }
        if matches!(
            f.method.as_str(),
            "remote.enrollment-status" | "remote.bind"
        ) {
            let enrollment = self.enrollment.clone().ok_or("UNSUPPORTED")?;
            let can_enroll =
                enrollment.granted() && (registered || peer == 0 || peer == self.admin_uid);
            let params = f.params.clone().unwrap_or(Value::Null);
            if f.method == "remote.enrollment-status" {
                if !params.is_null() && params != json!({}) {
                    return Err("INVALID_ARGUMENT".into());
                }
                let binding_blocked = self
                    .remote
                    .as_ref()
                    .is_some_and(|r| r.status()["recoveryRequired"] == true);
                return tokio::task::spawn_blocking(move || {
                    let mut status = enrollment.status(can_enroll && !binding_blocked)?;
                    if binding_blocked {
                        status["recoveryRequired"] = json!(true);
                    }
                    Ok::<_, anyhow::Error>(status)
                })
                .await
                .map_err(|_| String::from("INTERNAL"))?
                .map_err(|e| crate::network::error_code(&e).to_string());
            }
            if !can_enroll {
                return Err("FORBIDDEN".into());
            }
            let input =
                serde_json::from_value(params).map_err(|_| String::from("INVALID_ARGUMENT"))?;
            let remote = self.remote.clone().ok_or("UNSUPPORTED")?;
            let actor = format!("{}-uid:{peer}", if registered { "kura" } else { "local" });
            return enrollment.bind(input, remote, actor).await.map_err(|e| {
                match crate::network::error_code(&e) {
                    "INTERNAL" => String::from("UNKNOWN"),
                    code => code.to_string(),
                }
            });
        }
        if f.method.starts_with("remote.") {
            if matches!(
                f.method.as_str(),
                "remote.recovery-status" | "remote.resolve-disabled"
            ) && (registered || (peer != 0 && peer != self.admin_uid))
            {
                return Err("FORBIDDEN".into());
            }
            if registered && !self.kura_remote_management && f.method != "remote.status" {
                return Err("FORBIDDEN".into());
            }
            if !registered && peer != 0 && peer != self.admin_uid && f.method != "remote.status" {
                return Err("FORBIDDEN".into());
            }
            let can_control = if registered {
                self.kura_remote_management
            } else {
                peer == 0 || peer == self.admin_uid
            };
            let remote = self.remote.clone().ok_or("UNSUPPORTED")?;
            let method = f.method.clone();
            let params = f.params.clone().unwrap_or(Value::Null);
            let actor = format!("{}-uid:{peer}", if registered { "kura" } else { "local" });
            return tokio::task::spawn_blocking(move || {
                if method == "remote.status" {
                    if !params.is_null() && params != json!({}) {
                        return Err("INVALID_ARGUMENT".into());
                    }
                    let mut view = remote.status();
                    view["canControl"] = json!(can_control);
                    return Ok(view);
                }
                if method == "remote.recovery-status" {
                    if !params.is_null() && params != json!({}) {
                        return Err("INVALID_ARGUMENT".into());
                    }
                    return remote
                        .recovery_status()
                        .map_err(|e| crate::network::error_code(&e).to_string());
                }
                if method == "remote.resolve-disabled" {
                    let observation: crate::remote::RecoveryObservation =
                        serde_json::from_value(params)
                            .map_err(|_| String::from("INVALID_ARGUMENT"))?;
                    return remote.resolve_disabled(observation, actor).map_err(|e| {
                        match crate::network::error_code(&e) {
                            "INTERNAL" => "UNKNOWN",
                            code => code,
                        }
                        .to_string()
                    });
                }
                if method != "remote.set-enabled" {
                    return Err("UNSUPPORTED".into());
                }
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields, rename_all = "camelCase")]
                struct Input {
                    expected_revision: String,
                    enabled: bool,
                }
                let input: Input =
                    serde_json::from_value(params).map_err(|_| String::from("INVALID_ARGUMENT"))?;
                remote
                    .set_enabled(&input.expected_revision, input.enabled, actor)
                    .map(|mut view| {
                        view["canControl"] = json!(can_control);
                        view
                    })
                    .map_err(|error| crate::network::error_code(&error).to_string())
            })
            .await
            .map_err(|_| String::from("INTERNAL"))?;
        }
        if f.method.starts_with("firewall.kura.") {
            if !registered || peer != self.kura_uid {
                return Err("FORBIDDEN".into());
            }
            if f.method.starts_with("firewall.kura.imported.") {
                let params=f.params.clone().unwrap_or(Value::Null);
                let result=if matches!(f.method.as_str(),"firewall.kura.imported.outcome"|"firewall.kura.imported.cancel"|"firewall.kura.imported.recover"|"firewall.kura.imported.source.outcome") {
                    self.firewall.as_ref().ok_or("UNSUPPORTED")?.imported_metadata_request(f.method.clone(),params,peer).await
                }else{
                    self.nm.as_ref().ok_or("UNSUPPORTED")?.imported_firewall_request(
                        f.method.clone(),params,peer,f.request_id.clone(),self.kura_firewall_write).await
                };
                return result.map_err(|error|if error.to_string().starts_with("OUTCOME_UNKNOWN") {
                    "OUTCOME_UNKNOWN".into()
                }else{crate::network::error_code(&error).into()});
            }
            return self
                .firewall
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .kura_request(
                    f.method.clone(),
                    f.params.clone().unwrap_or(Value::Null),
                    f.request_id.clone(),
                    peer,
                    self.kura_firewall_write,
                )
                .await
                .map_err(|error| {
                    if error.to_string().starts_with("OUTCOME_UNKNOWN") {
                        "OUTCOME_UNKNOWN".into()
                    } else {
                        crate::network::error_code(&error).into()
                    }
                });
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
        if f.method == "network.nm.preview" {
            return self
                .nm
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .preview(f.params.clone().unwrap_or(Value::Null))
                .await
                .map_err(|error| crate::network::error_code(&error).into());
        }
        if f.method == "network.nm.inspect" {
            if f.params
                .as_ref()
                .is_some_and(|p| !p.is_null() && *p != json!({}))
            {
                return Err("INVALID_ARGUMENT".into());
            }
            return self
                .nm
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .inspect()
                .await
                .map_err(|error| crate::network::error_code(&error).into());
        }
        if f.method.starts_with("network.nm.") {
            if f.method.starts_with("network.nm.template.") {return Err("FORBIDDEN".into());}
            if f.method.starts_with("network.nm.ownership.") {
                #[cfg(target_os = "linux")]
                if matches!(f.method.as_str(), "network.nm.ownership.upgrade.verify" | "network.nm.ownership.startup.legacy.stop-review") {
                    let legacy_stop = f.method.ends_with(".stop-review");
                    if peer != 0 || (legacy_stop && registered) {
                        return Err("FORBIDDEN".into());
                    }
                    return self.verify_nm_upgrade_registration(f.params.clone().unwrap_or(Value::Null), legacy_stop).await;
                }
                if f.method == "network.nm.ownership.fence.arm" && (peer != 0 || registered) {
                    return Err("FORBIDDEN".into());
                }
                return self.nm.as_ref().ok_or("UNSUPPORTED")?
                    .ownership_request(f.method.clone(),f.params.clone().unwrap_or(Value::Null),format!("local-uid:{peer}"))
                    .await.map_err(|e|crate::network::error_code(&e).to_string());
            }
            // Detail at debug level only; the caller still receives the stable code.
            return self
                .nm
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .dispatch_nm(&f.method, f.params.clone().unwrap_or(Value::Null))
                .await
                .map_err(|error| {
                    tracing::debug!(error=%error, method=%f.method, "NM local call failed");
                    crate::network::error_code(&error).into()
                });
        }
        if f.method == "network.nm.prepare" {
            return self
                .nm
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .prepare(f.params.clone().unwrap_or(Value::Null))
                .await
                .map_err(|error| crate::network::error_code(&error).into());
        }
        if f.method == "network.nm.apply" {
            return self
                .nm
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .apply()
                .await
                .map_err(|error| crate::network::error_code(&error).into());
        }
        if f.method == "network.nm.confirm" || f.method == "network.nm.rollback" {
            let params = f.params.clone().unwrap_or(Value::Null);
            return if f.method == "network.nm.confirm" {
                self.nm.as_ref().ok_or("UNSUPPORTED")?.confirm(params).await
            } else {
                self.nm.as_ref().ok_or("UNSUPPORTED")?.rollback(params).await
            }
            .map_err(|error| crate::network::error_code(&error).into());
        }
        if f.method == "network.nm.status"
            || f.method == "network.nm.recover"
            || f.method == "network.nm.archive"
        {
            if f.params
                .as_ref()
                .is_some_and(|p| !p.is_null() && *p != json!({}))
            {
                return Err("INVALID_ARGUMENT".into());
            }
            let nm = self.nm.as_ref().ok_or("UNSUPPORTED")?;
            return if f.method == "network.nm.status" {
                nm.transaction_status().await
            } else if f.method == "network.nm.recover" {
                nm.recover().await
            } else {
                nm.archive().await
            }
            .map_err(|error| crate::network::error_code(&error).into());
        }
        if let Some(operation) = crate::system_control::operation(&f.method) {
            let params = f.params.clone().unwrap_or(Value::Null);
            let action = if matches!(operation, 25 | 27 | 28) {
                Some(serde_json::from_value(params).map_err(|_| String::from("INVALID_ARGUMENT"))?)
            } else {
                if !params.is_null() && params != json!({}) {
                    return Err("INVALID_ARGUMENT".into());
                }
                None
            };
            return self
                .system_control
                .as_ref()
                .ok_or("UNSUPPORTED")?
                .request(operation, action, None, self.clone())
                .await
                .map_err(|e| crate::boot_control::error_code(&e).to_string());
        }
        if f.method.starts_with("ordinary.boot.") {
            let control = self.ordinary_boot.as_ref().ok_or("UNSUPPORTED")?;
            let _lease = if f.method == "ordinary.boot.status" {
                None
            } else {
                Some(self.configuration_write_lock.clone().lock_owned().await)
            };
            return control
                .request(&f.method, f.params.clone().unwrap_or(Value::Null), None)
                .await
                .map_err(|e| crate::boot_control::error_code(&e).to_string());
        }
        if f.method.starts_with("recovery.") {
            return self
                .recovery_request(&f.method, f.params.clone().unwrap_or(Value::Null))
                .await;
        }
        if f.method.starts_with("firewall.") {
            return self
                .firewall_request(
                    &f.method,
                    f.params.clone().unwrap_or(Value::Null),
                    f.request_id.clone(),
                )
                .await;
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

    async fn recovery_request(&self, method: &str, params: Value) -> Result<Value, String> {
        validate_admin_params(method, &params)?;
        let recovery = self.recovery.as_ref().ok_or("UNSUPPORTED")?;
        let result = match method {
            "recovery.status" => recovery.status().await,
            "recovery.snapshot.inventory" => tokio::task::spawn_blocking(crate::core_validation::native_inventory)
                .await
                .map_err(|_| "INTERNAL")?,
            "recovery.upload" => {
                recovery
                    .upload(
                        params["uploadId"].as_str().unwrap_or_default(),
                        params["dataBase64"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.prepare" => {
                recovery
                    .prepare(
                        params["uploadId"].as_str().unwrap_or_default(),
                        params["expectedSha256"].as_str().unwrap_or_default(),
                        params["unit"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.execute" => {
                recovery
                    .execute(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.compensation.prepare" => {
                recovery
                    .prepare_compensation(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.compensation.execute" => {
                recovery
                    .execute_compensation(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.snapshots.prepare" => {
                recovery
                    .prepare_snapshot_set(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.snapshots.execute" => {
                recovery
                    .execute_snapshot_set(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.normal.forward.prepare" => {
                recovery
                    .prepare_applied_normal_boot(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.normal.prepare" => {
                recovery
                    .prepare_normal_boot(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.normal.execute" => {
                recovery
                    .execute_normal_boot(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.health.prepare" => {
                recovery
                    .prepare_health(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.health.execute" => {
                recovery
                    .execute_health(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                        self.clone(),
                    )
                    .await
            }
            "recovery.completion.prepare" => {
                recovery
                    .prepare_completion(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.completion.execute" => {
                recovery
                    .execute_completion(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                        self.clone(),
                    )
                    .await
            }
            "recovery.ordinary.prepare" => {
                recovery
                    .prepare_ordinary(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.ordinary.cancel" => {
                recovery
                    .cancel_ordinary(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            "recovery.ordinary.execute" => {
                recovery
                    .execute_ordinary(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                        self.clone(),
                    )
                    .await
            }
            "recovery.rollback" => {
                recovery
                    .rollback(
                        params["transactionId"].as_str().unwrap_or_default(),
                        params["confirmToken"].as_str().unwrap_or_default(),
                    )
                    .await
            }
            _ => return Err("UNSUPPORTED".into()),
        };
        result.map_err(|error| {
            let message = format!("{error:#}");
            for code in [
                "OUTCOME_UNKNOWN",
                "INVALID_ARGUMENT",
                "CONFLICT",
                "FORBIDDEN",
                "RESOURCE_EXHAUSTED",
                "NOT_FOUND",
            ] {
                if message.starts_with(code) {
                    return code.to_string();
                }
            }
            "INTERNAL".to_string()
        })
    }

    async fn firewall_request(
        &self,
        method: &str,
        params: Value,
        request_id: String,
    ) -> Result<Value, String> {
        validate_admin_params(method, &params)?;
        let firewall = self.firewall.as_ref().ok_or("UNSUPPORTED")?;
        let result = match method {
            "firewall.status" => firewall.status().await,
            "firewall.prepare" => {
                let confirm = params["confirmSeconds"].as_u64().unwrap_or(0);
                let candidate = params.get("candidate").cloned().unwrap_or_else(|| {
                    json!({
                        "policy": params["policy"].clone(),
                        "rules": params.get("rules").cloned().unwrap_or_else(|| json!([])),
                    })
                });
                firewall.prepare(candidate, confirm, request_id).await
            }
            "firewall.apply" => firewall.apply().await,
            "firewall.confirm" => {
                firewall
                    .confirm(params["token"].as_str().unwrap_or_default())
                    .await
            }
            "firewall.rollback" => {
                firewall
                    .rollback(params["token"].as_str().unwrap_or_default())
                    .await
            }
            _ => return Err("UNSUPPORTED".into()),
        };
        result.map_err(|error| {
            let message = format!("{error:#}");
            for code in [
                "INVALID_ARGUMENT",
                "CONFLICT",
                "FORBIDDEN",
                "RESOURCE_EXHAUSTED",
            ] {
                if message.starts_with(code) {
                    return code.to_string();
                }
            }
            "INTERNAL".to_string()
        })
    }
}

// Reject unsupported fields before executing a partial administrative request.
fn validate_admin_params(method: &str, value: &Value) -> Result<(), String> {
    let (required, optional): (&[&str], &[&str]) = match method {
        "firewall.status" | "firewall.apply" | "recovery.status" | "recovery.snapshot.inventory" => (&[], &[]),
        "firewall.prepare" if value.get("candidate").is_some() => {
            if value["candidate"]["schemaVersion"] != 2 && value["candidate"]["schemaVersion"] != 3
            {
                return Err("INVALID_ARGUMENT".into());
            }
            (&["candidate", "confirmSeconds"], &[])
        }
        "firewall.prepare" => (&["policy", "confirmSeconds"], &["rules"]),
        "firewall.confirm" | "firewall.rollback" => (&["token"], &[]),
        "recovery.upload" => (&["uploadId", "dataBase64"], &[]),
        "recovery.prepare" => (&["uploadId", "expectedSha256", "unit"], &[]),
        "recovery.execute"
        | "recovery.rollback"
        | "recovery.compensation.prepare"
        | "recovery.compensation.execute"
        | "recovery.snapshots.prepare"
        | "recovery.snapshots.execute"
        | "recovery.normal.forward.prepare"
        | "recovery.normal.prepare"
        | "recovery.normal.execute"
        | "recovery.health.prepare"
        | "recovery.health.execute"
        | "recovery.completion.prepare"
        | "recovery.completion.execute"
        | "recovery.ordinary.prepare"
        | "recovery.ordinary.execute"
        | "recovery.ordinary.cancel" => (&["transactionId", "confirmToken"], &[]),
        _ => return Err("UNSUPPORTED".into()),
    };
    if value.is_null() && required.is_empty() {
        return Ok(());
    }
    let object = value.as_object().ok_or("INVALID_ARGUMENT")?;
    if object
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
        || object.iter().any(|(key, value)| match key.as_str() {
            "rules" => !value.is_array(),
            "candidate" => !value.is_object(),
            "confirmSeconds" => value.as_u64().is_none(),
            _ => !value.is_string(),
        })
    {
        return Err("INVALID_ARGUMENT".into());
    }
    Ok(())
}

#[cfg(test)]
mod firewall_dispatch_tests {
    use super::*;
    use crate::firewall::Firewall;

    #[tokio::test]
    async fn kura_firewall_requires_registered_exact_uid_and_separate_default_off_grant() {
        let (mut local, _dir) = local_with_firewall();
        local.kura_uid = 1000;
        let mut frame = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: "view".into(),
            method: "firewall.kura.view".into(),
            params: Some(json!({})),
            result: None,
            error: None,
        };
        assert_eq!(
            local.local_request(&frame, 0, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 0, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 1000, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        let view = local.local_request(&frame, 1000, true).await.unwrap();
        assert_eq!(view["writeEnabled"], false);
        frame.method = "firewall.kura.preview".into();
        frame.params = Some(json!({"expectedRevision":0,"sourceDigest":"a".repeat(64),"candidate":{},"destinationPrefixes":{"ipv4":[],"ipv6":[]}}));
        for (uid,registered) in [(0,false),(0,true),(1000,false)] {assert_eq!(local.local_request(&frame,uid,registered).await.unwrap_err(),"FORBIDDEN");}
        assert_eq!(local.local_request(&frame,1000,true).await.unwrap_err(),"UNSUPPORTED");
        for method in ["review","prepare","outcome","cancel","recover","apply","confirm","rollback"] {
            frame.method=format!("firewall.kura.imported.{method}");
            for (uid,registered) in [(0,false),(0,true),(1000,false)] {
                assert_eq!(local.local_request(&frame,uid,registered).await.unwrap_err(),"FORBIDDEN");
            }
        }
        frame.method = "firewall.kura.prepare".into();
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        frame.method = "firewall.prepare".into();
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap_err(),
            "FORBIDDEN"
        );
    }

    fn local_with_firewall() -> (Local, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("fw-uds-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut local = Local::new(0, 0);
        local.firewall = Some(
            Firewall::open(dir.clone(), None)
                .unwrap()
                .enable_writes(true),
        );
        (local, dir)
    }

    #[tokio::test]
    async fn firewall_v3_uds_keeps_full_metadata_and_never_downgrades_invalid_shapes() {
        let (local, dir) = local_with_firewall();
        let candidate = json!({"schemaVersion":3,"ipv4":{"inputPolicy":"drop","forwardPolicy":"drop","allowIcmp":false},
            "ipv6":{"inputPolicy":"accept","forwardPolicy":"drop","allowIcmp":true},"input":[],"portForward":[],"nat":[]});
        let mut invalid = candidate.clone();
        invalid["schemaVersion"] = json!(2);
        assert_eq!(
            local
                .firewall_request(
                    "firewall.prepare",
                    json!({"candidate":invalid,"confirmSeconds":60}),
                    "wrong-version".into()
                )
                .await
                .unwrap_err(),
            "INVALID_ARGUMENT"
        );
        assert!(!dir.join("firewall/transaction.json").exists());
        let prepared = local
            .firewall_request(
                "firewall.prepare",
                json!({"candidate":candidate,"confirmSeconds":60}),
                "v3".into(),
            )
            .await
            .unwrap();
        assert_eq!(prepared["policy"], "per-family");
        local
            .firewall_request("firewall.apply", json!({}), "apply".into())
            .await
            .unwrap();
        local
            .firewall_request(
                "firewall.confirm",
                json!({"token":prepared["token"]}),
                "confirm".into(),
            )
            .await
            .unwrap();
        let retained: Value =
            serde_json::from_slice(&std::fs::read(dir.join("firewall/transaction.json")).unwrap())
                .unwrap();
        assert_eq!(retained["candidate"], candidate);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn firewall_v2_uds_preserves_schema_and_rejects_mixed_or_downgraded_payloads() {
        let (local, dir) = local_with_firewall();
        let candidate = json!({"schemaVersion":2,"inputPolicy":"accept","forwardPolicy":"drop","input":[],"forward":[],"destinationNat":[],"sourceNat":[]});
        for invalid in [
            json!({"candidate":{"policy":"accept","rules":[]},"confirmSeconds":60}),
            json!({"candidate":candidate,"policy":"accept","confirmSeconds":60}),
        ] {
            assert_eq!(
                local
                    .firewall_request("firewall.prepare", invalid, "invalid".into())
                    .await
                    .unwrap_err(),
                "INVALID_ARGUMENT"
            );
        }
        let prepared = local
            .firewall_request(
                "firewall.prepare",
                json!({"candidate":candidate,"confirmSeconds":60}),
                "v2".into(),
            )
            .await
            .unwrap();
        local
            .firewall_request("firewall.apply", json!({}), "apply".into())
            .await
            .unwrap();
        let confirmed = local
            .firewall_request(
                "firewall.confirm",
                json!({"token":prepared["token"]}),
                "confirm".into(),
            )
            .await
            .unwrap();
        assert_eq!(confirmed["revision"], 1);
        let retained: Value =
            serde_json::from_slice(&std::fs::read(dir.join("firewall/transaction.json")).unwrap())
                .unwrap();
        assert_eq!(retained["candidate"], candidate);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn applied_forward_normal_remains_local_administrator_only() {
        let local = Local::new(1000, 2000);
        let frame = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: "forward-normal".into(),
            method: "recovery.normal.forward.prepare".into(),
            params: Some(json!({"transactionId":"rec-owned","confirmToken":"owned-token"})),
            result: None,
            error: None,
        };
        for (peer, registered) in [(1000, true), (0, true), (1001, false)] {
            assert_eq!(
                local
                    .local_request(&frame, peer, registered)
                    .await
                    .unwrap_err(),
                "FORBIDDEN"
            );
        }
        assert_eq!(
            local.local_request(&frame, 0, false).await.unwrap_err(),
            "UNSUPPORTED"
        );
    }
    #[test]
    fn applied_forward_normal_request_cannot_self_authorize_or_choose_a_unit() {
        let value = json!({"transactionId":"rec-owned","confirmToken":"owned-token"});
        assert!(validate_admin_params("recovery.normal.forward.prepare", &value).is_ok());
        for field in [
            "unit",
            "source",
            "acceptAppliedForwardSource",
            "normalStartupAuthoritySha256",
        ] {
            let mut extra = value.clone();
            extra[field] = json!("untrusted");
            assert!(validate_admin_params("recovery.normal.forward.prepare", &extra).is_err());
        }
    }
    #[test]
    fn administrative_requests_never_ignore_unsupported_or_malformed_fields() {
        for (method, value) in [
            (
                "firewall.prepare",
                json!({"policy":"drop","rules":[],"confirmSeconds":60,"nat":[]}),
            ),
            ("firewall.apply", json!({"unexpected":true})),
            (
                "recovery.prepare",
                json!({"uploadId":"u","expectedSha256":"a","unit":"fixture.service","factoryReset":true}),
            ),
            (
                "recovery.execute",
                json!({"transactionId":"t","confirmToken":123}),
            ),
        ] {
            assert_eq!(
                validate_admin_params(method, &value).unwrap_err(),
                "INVALID_ARGUMENT"
            );
        }
        assert!(validate_admin_params("firewall.status", &Value::Null).is_ok());
    }

    #[tokio::test]
    async fn firewall_methods_dispatch_with_typed_errors() {
        let (local, dir) = local_with_firewall();
        let status = local
            .firewall_request("firewall.status", json!({}), "r1".into())
            .await
            .unwrap();
        assert_eq!(status["table"], "yofc_kura");
        assert_eq!(status["revision"], 0);
        // Invalid confirm window maps to INVALID_ARGUMENT, never INTERNAL.
        let error = local
            .firewall_request(
                "firewall.prepare",
                json!({"policy": "drop", "rules": [], "confirmSeconds": 5}),
                "r2".into(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, "INVALID_ARGUMENT");
        // Double apply maps to CONFLICT.
        let _ = local
            .firewall_request(
                "firewall.prepare",
                json!({"policy": "accept", "rules": [], "confirmSeconds": 60}),
                "r3".into(),
            )
            .await
            .unwrap();
        let _ = local
            .firewall_request("firewall.apply", json!({}), "r4".into())
            .await
            .unwrap();
        let error = local
            .firewall_request("firewall.apply", json!({}), "r5".into())
            .await
            .unwrap_err();
        assert_eq!(error, "CONFLICT");
        let error = local
            .firewall_request("firewall.confirm", json!({"token": "wrong"}), "r6".into())
            .await
            .unwrap_err();
        assert_eq!(error, "FORBIDDEN");
        assert!(
            local
                .firewall_request("firewall.nope", json!({}), "r7".into())
                .await
                .is_err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn nm_observation_is_default_off_and_rejects_caller_selected_targets() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = connect(&local);
        write_frame(&mut peer, &request("nm-default", "network.nm.inspect"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.error.as_deref(),
            Some("UNSUPPORTED")
        );
        write_frame(
            &mut peer,
            &request("nm-preview-default", "network.nm.preview"),
        )
        .await
        .unwrap();
        assert_eq!(
            receive(&mut peer).await.error.as_deref(),
            Some("UNSUPPORTED")
        );
        let mut input = request("nm-target", "network.nm.inspect");
        input.params = Some(json!({"interfaces":["ungranted0"]}));
        write_frame(&mut peer, &input).await.unwrap();
        assert_eq!(
            receive(&mut peer).await.error.as_deref(),
            Some("INVALID_ARGUMENT")
        );
        drop(peer);
        assert!(job.await.unwrap().is_err());
    }

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
    async fn configuration_readiness_follows_unix_bridge_registration_and_disconnect() {
        let uid = unsafe { libc::geteuid() };
        let mut local = Local::new(uid, uid);
        local.enable_configuration_updates(true);
        assert_eq!(local.configuration_bridge_state().await, (false, false));
        let (mut peer, server) = connect(&local);
        let mut registration = request("read-only", "kura.register");
        registration.kind = "register".into();
        registration.params = Some(json!({"methods":KURA_REQUIRED_METHODS}));
        write_frame(&mut peer, &registration).await.unwrap();
        assert_eq!(receive(&mut peer).await.result.unwrap()["registered"], true);
        assert_eq!(local.configuration_bridge_state().await, (true, false));
        assert_eq!(local.update_configuration(json!({})).await, Err("UNSUPPORTED"));
        drop(peer);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
        assert_eq!(local.configuration_bridge_state().await, (false, false));

        let (writer, server) = register(&local).await;
        assert_eq!(local.configuration_bridge_state().await, (true, true));
        drop(writer);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
        assert_eq!(local.configuration_bridge_state().await, (false, false));
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
    async fn actual_socket_startup_association_registers_the_optional_method_and_refuses_replaced_sessions() {
        for replace in [false,true] {
            let uid=unsafe{libc::geteuid()};let local=Local::new(uid,uid);let (mut peer,server)=register(&local).await;
            let params=json!({"operationId":Uuid::new_v4(),"planSha256":"a".repeat(64),"nonce":"b".repeat(64)});
            let caller=local.clone();let input=params.clone();let job=tokio::spawn(async move{caller.network_startup_association(input).await});
            let frame=receive(&mut peer).await;assert_eq!(frame.method,"kura.network.startup.profile");assert_eq!(frame.params,Some(params.clone()));
            if replace {local.bridge.write().await.as_mut().unwrap().epoch=2;}
            let value=json!({"schemaVersion":1,"operationId":params["operationId"],"planSha256":params["planSha256"],"nonce":params["nonce"],
                "observerInstanceId":Uuid::new_v4(),"profileId":format!("profile-{}",Uuid::new_v4()),"processId":4321,"frameworkStartLevel":6,"ordinaryLoad":true});
            write_frame(&mut peer,&frame.response(Some(value),None)).await.unwrap();
            let result=job.await.unwrap();
            if replace {assert!(result.is_err());}else{let report=serde_json::to_value(result.unwrap()).unwrap();assert_eq!(report["agentInstance"],local.instance_id.to_string());assert_eq!(report["bridgeEpoch"],1);}
            drop(peer);let _=server.await;
        }
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
    async fn firewall_confirmation_token_is_usable_without_reading_private_state() {
        let root = std::env::temp_dir().join(format!("firewall-wire-{}", Uuid::new_v4()));
        let uid = unsafe { libc::geteuid() };
        let mut local = Local::new(uid, uid);
        local.firewall = Some(
            crate::firewall::Firewall::open(root.clone(), None)
                .unwrap()
                .enable_writes(true),
        );
        let (mut peer, job) = connect(&local);
        let mut prepare = request("p", "firewall.prepare");
        prepare.params = Some(json!({"policy":"accept","rules":[],"confirmSeconds":60}));
        write_frame(&mut peer, &prepare).await.unwrap();
        let result = receive(&mut peer).await.result.unwrap();
        let token = result["token"].as_str().unwrap().to_string();
        write_frame(&mut peer, &request("a", "firewall.apply"))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut peer).await.result.unwrap()["state"],
            "WAIT_CONFIRM"
        );
        let mut confirm = request("c", "firewall.confirm");
        confirm.params = Some(json!({"token":token}));
        write_frame(&mut peer, &confirm).await.unwrap();
        assert_eq!(
            receive(&mut peer).await.result.unwrap()["state"],
            "COMMITTED"
        );
        write_frame(&mut peer, &request("s", "firewall.status"))
            .await
            .unwrap();
        let value = receive(&mut peer).await.result.unwrap();
        assert_eq!(value["revision"], 1);
        assert!(value["transaction"].get("token").is_none());
        drop(peer);
        let _ = job.await;
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn boot_administrative_first_frame_reaches_default_off_handler_without_disconnect() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        for method in [
            "network.nm.inspect",
            "network.nm.preview",
            "network.nm.prepare",
            "network.nm.apply",
            "network.nm.confirm",
            "network.nm.rollback",
            "network.nm.status",
            "network.nm.recover",
            "network.nm.archive",
            "network.nm.ownership.startup.prepare",
            "network.nm.ownership.startup.verify",
            "network.nm.ownership.startup.stop",
            "network.nm.ownership.startup.publish",
            "network.nm.ownership.startup.start",
            "network.nm.ownership.startup.complete",
            "network.nm.ownership.startup.recovery.prepare",
            "network.nm.ownership.startup.recovery.original",
            "network.nm.ownership.startup.recovery.execute",
            "network.nm.ownership.startup.recovery.cancel",
            "ordinary.boot.status",
            "ordinary.boot.prepare",
            "ordinary.boot.execute",
            "ordinary.boot.cancel",
            "ordinary.boot.reconcile",
            "service.status",
            "service.restart.prepare",
            "system.reboot.prepare",
        ] {
            let (mut peer, job) = connect(&local);
            write_frame(&mut peer, &request("boot-first", method))
                .await
                .unwrap();
            assert_eq!(
                receive(&mut peer).await.error.as_deref(),
                Some("UNSUPPORTED")
            );
            drop(peer);
            let _ = job.await;
        }
    }

    #[tokio::test]
    async fn registered_kura_role_cannot_gain_admin_methods_from_same_uid() {
        let uid = unsafe { libc::geteuid() };
        let local = Local::new(uid, uid);
        let (mut peer, job) = register(&local).await;
        for method in [
            "firewall.prepare",
            "recovery.execute",
            "network.inspect",
            "network.prepare",
            "network.confirm",
            "network.takeover.prepare",
            "network.kura.view",
            "network.nm.ownership.startup.prepare",
            "network.nm.ownership.startup.verify",
            "network.nm.ownership.startup.stop",
            "network.nm.ownership.startup.publish",
            "network.nm.ownership.startup.start",
            "network.nm.ownership.startup.complete",
            "network.nm.ownership.startup.recovery.prepare",
            "network.nm.ownership.startup.recovery.original",
            "network.nm.ownership.startup.recovery.execute",
            "network.nm.ownership.startup.recovery.cancel",
            "ordinary.boot.status",
            "ordinary.boot.prepare",
            "ordinary.boot.execute",
            "ordinary.boot.cancel",
            "ordinary.boot.reconcile",
            "service.status",
            "service.restart.prepare",
            "service.restart",
            "system.reboot.prepare",
            "system.reboot",
            "system.control.cancel",
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
    async fn recovery_observation_rejects_changed_session_and_agent_instances_have_distinct_identity()
     {
        let local = Local::new(0, 0);
        assert_eq!(local.instance_id, local.clone().instance_id);
        assert_ne!(local.instance_id, Local::new(0, 0).instance_id);
        let mut rx = local.install_test_bridge(&["kura.recovery.verify"]).await;
        let requester = local.clone();
        let task = tokio::spawn(async move { requester.recovery_verification(json!({})).await });
        let frame = rx.recv().await.unwrap();
        let (tx, _rx) = mpsc::channel(8);
        *local.bridge.write().await = Some(Bridge {
            epoch: 2,
            tx,
            methods: HashSet::from(["kura.recovery.verify".into()]),
            peer_pid: None,
        });
        local.complete_pending(&frame.request_id, Some(json!({"old":true})), None);
        assert_eq!(task.await.unwrap().unwrap_err(), "KURA_UNAVAILABLE");
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

#[cfg(test)]
mod remote_control_tests {
    use super::*;
    #[tokio::test]
    async fn remote_recovery_is_local_admin_only_even_with_kura_switch_delegation() {
        let dir = std::env::temp_dir().join(format!("remote-recovery-role-{}", Uuid::new_v4()));
        let mut local = Local::new(1000, 0);
        local.kura_remote_management = true;
        local.remote = Some(crate::remote::Remote::open(dir, false, None).unwrap());
        let mut frame = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: "inspect".into(),
            method: "remote.recovery-status".into(),
            params: None,
            result: None,
            error: None,
        };
        assert_eq!(
            local.local_request(&frame, 0, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 1000, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        let inspection = local.local_request(&frame, 0, false).await.unwrap();
        assert_eq!(inspection["canResolve"], false);
        frame.method = "remote.resolve-disabled".into();
        frame.params = Some(inspection["observation"].clone());
        assert_eq!(
            local.local_request(&frame, 0, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 0, false).await.unwrap_err(),
            "CONFLICT"
        );
        frame.params.as_mut().unwrap()["enabled"] = json!(true);
        assert_eq!(
            local.local_request(&frame, 0, false).await.unwrap_err(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(local.remote.as_ref().unwrap().status()["enabled"], false);
    }
    #[tokio::test]
    async fn enrollment_requires_its_own_grant_even_for_delegated_kura() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("enrollment-roles-{}", Uuid::new_v4()));
        crate::durable::directory(&root).unwrap();
        let db = crate::transport::database(root.join("db").to_str().unwrap())
            .await
            .unwrap();
        let mut local = Local::new(1000, 0);
        local.remote = Some(crate::remote::Remote::open(root.clone(), false, None).unwrap());
        local.kura_remote_management = true;
        let mut frame = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: "status".into(),
            method: "remote.enrollment-status".into(),
            params: None,
            result: None,
            error: None,
        };
        local.enrollment = Some(
            crate::enrollment::Enrollment::open(
                root.clone(),
                None,
                None,
                1000,
                db.clone(),
                "boot".into(),
            )
            .unwrap(),
        );
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap()["canEnroll"],
            false
        );
        frame.method = "remote.bind".into();
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&frame, 0, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        local.enrollment = Some(
            crate::enrollment::Enrollment::open(
                root.clone(),
                None,
                Some(root.join("kura")),
                1000,
                db,
                "boot".into(),
            )
            .unwrap(),
        );
        frame.method = "remote.enrollment-status".into();
        local.kura_remote_management = false;
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap()["canEnroll"],
            true
        );
        assert_eq!(
            local.local_request(&frame, 1000, false).await.unwrap()["canEnroll"],
            false
        );
        frame.method = "remote.bind".into();
        assert_eq!(
            local.local_request(&frame, 1000, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        frame.params = Some(json!({"privateKey":"forbidden","path":"/arbitrary"}));
        assert_eq!(
            local.local_request(&frame, 1000, true).await.unwrap_err(),
            "INVALID_ARGUMENT"
        );
    }
    #[tokio::test]
    async fn kura_delegation_is_narrow_and_status_never_grants_write_permission() {
        let dir = std::env::temp_dir().join(format!("remote-uds-{}", Uuid::new_v4()));
        let remote = crate::remote::Remote::open(
            dir,
            false,
            Some(("https://example.invalid:8443".into(), "gw".into(), 1)),
        )
        .unwrap();
        let mut local = Local::new(1000, 0);
        local.remote = Some(remote.clone());
        let status = LocalFrame {
            version: 1,
            kind: "request".into(),
            request_id: "status".into(),
            method: "remote.status".into(),
            params: None,
            result: None,
            error: None,
        };
        let view = local.local_request(&status, 1000, true).await.unwrap();
        assert_eq!(view["enabled"], false);
        let mut change = status.clone();
        change.method = "remote.set-enabled".into();
        change.params = Some(json!({"expectedRevision":view["revision"],"enabled":true}));
        assert_eq!(
            local.local_request(&change, 1000, true).await.unwrap_err(),
            "FORBIDDEN"
        );
        assert_eq!(
            local.local_request(&change, 1000, false).await.unwrap_err(),
            "FORBIDDEN"
        );
        local.kura_remote_management = true;
        assert_eq!(
            local.local_request(&change, 1000, true).await.unwrap()["enabled"],
            true
        );
        let mut invalid = change.clone();
        invalid.params = Some(
            json!({"expectedRevision":remote.status()["revision"],"enabled":false,"endpoint":"https://other.invalid"}),
        );
        assert_eq!(
            local.local_request(&invalid, 1000, true).await.unwrap_err(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(remote.status()["gatewayId"], "gw");
        invalid.params =
            Some(json!({"expectedRevision":remote.status()["revision"],"enabled":"false"}));
        assert_eq!(
            local.local_request(&invalid, 0, false).await.unwrap_err(),
            "INVALID_ARGUMENT"
        );
    }
}

#[cfg(test)]
mod nm_role_bridge_tests {
    use super::*;
    #[tokio::test]
    async fn actual_java_writer_model_uses_only_the_registered_read_and_never_falls_back_after_an_error() {
        let exchange:Value=serde_json::from_str(include_str!("nm/fixtures/legacy-origin-v32.json")).unwrap();
        for defect in ["none","missing","peer","revision","kernel","unsupported"] {
            let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
            let expected=crate::nm::roles::Observation::new(local.instance_id,1,exchange["roles"].clone()).unwrap();
            let mut rx=local.install_test_bridge(if defect=="missing"{&[]}else{&["kura.firewall.origin"]}).await;
            if defect=="missing" {assert!(local.network_firewall_origin(&expected).await.unwrap().is_none());assert!(rx.try_recv().is_err());continue;}
            let caller=local.clone();let revision=expected.source_revision().to_owned();let job=tokio::spawn(async move{caller.network_firewall_origin(&expected).await});
            let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.firewall.origin");assert_eq!(frame.params,Some(json!({"networkRevision":revision})));
            let mut value=exchange["origin"].clone();
            match defect {"peer"=>local.bridge.write().await.as_mut().unwrap().epoch=2,"revision"=>value["networkRevision"]=json!("changed"),"kernel"=>value["kernelObserved"]=json!(true),_=>{}};
            local.complete_pending(&frame.request_id,Some(value),if defect=="unsupported"{Some("UNSUPPORTED")}else{None});
            let reply=job.await.unwrap();assert_eq!(reply.is_ok(),defect=="none","{defect}");if let Ok(origin)=reply {assert!(origin.is_some());}assert!(rx.try_recv().is_err());
        }
    }
    fn projection()->Value {json!({"schemaVersion":1,"pid":"org.eclipse.kura.net.admin.NetworkConfigurationService","revision":"paired-revision","interfaces":[]})}
    #[tokio::test]
    async fn original_firewall_source_is_registered_readonly_and_binds_exact_network_revision() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        let expected=crate::nm::roles::Observation::new(local.instance_id,1,projection()).unwrap();
        let wrong=crate::nm::roles::Observation::new(Uuid::new_v4(),1,projection()).unwrap();
        let mut rx=local.install_test_bridge(&["kura.firewall.source"]).await;
        assert_eq!(local.network_firewall_source(&wrong).await.err().unwrap(),"CONFLICT");assert!(rx.try_recv().is_err());
        let value=serde_json::to_value(crate::nm::roles::fixture_firewall_source(&expected)).unwrap()["source"].clone();
        let caller=local.clone();let job=tokio::spawn(async move{caller.network_firewall_source(&expected).await});
        let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.firewall.source");assert_eq!(frame.params,Some(json!({"networkRevision":"paired-revision"})));
        local.complete_pending(&frame.request_id,Some(value),None);
        let result=serde_json::to_value(job.await.unwrap().unwrap()).unwrap();assert_eq!(result["source"]["backendPolicyObserved"],false);assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn original_firewall_source_missing_capability_changed_peer_or_forged_policy_refuses() {
        for defect in ["missing","peer","policy","pid"] {
            let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
            let expected=crate::nm::roles::Observation::new(local.instance_id,1,projection()).unwrap();
            let mut rx=local.install_test_bridge(if defect=="missing"{&[]}else{&["kura.firewall.source"]}).await;
            if defect=="missing" {assert_eq!(local.network_firewall_source(&expected).await.err().unwrap(),"UNSUPPORTED");assert!(rx.try_recv().is_err());continue;}
            let mut value=serde_json::to_value(crate::nm::roles::fixture_firewall_source(&expected)).unwrap()["source"].clone();
            let caller=local.clone();let job=tokio::spawn(async move{caller.network_firewall_source(&expected).await});let frame=rx.recv().await.unwrap();
            match defect {"peer"=>local.bridge.write().await.as_mut().unwrap().epoch=2,"policy"=>value["backendPolicyObserved"]=json!(true),
                "pid"=>value["families"][1]["pid"]=json!(crate::nm::roles::FIREWALL_V4_PID),_=>unreachable!()};
            local.complete_pending(&frame.request_id,Some(value),None);assert!(job.await.unwrap().is_err());assert!(rx.try_recv().is_err());
        }
    }
    #[tokio::test]
    async fn roles_bind_the_registered_session_and_never_select_a_pid_or_write() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        let mut rx=local.install_test_bridge(&["kura.network.roles"]).await;
        let caller=local.clone();let job=tokio::spawn(async move{caller.network_roles().await});
        let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.network.roles");assert_eq!(frame.params,Some(json!({})));
        local.complete_pending(&frame.request_id,Some(projection()),None);
        let observed=serde_json::to_value(job.await.unwrap().unwrap()).unwrap();
        assert_eq!(observed["agentInstance"],local.instance_id.to_string());assert_eq!(observed["bridgeEpoch"],1);
        assert_eq!(observed["roles"]["revision"],"paired-revision");assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn missing_capability_bad_projection_and_replaced_registration_never_grant_a_role_lease() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        assert!(local.network_roles().await.is_err());
        for replace in [false,true] {
            let mut rx=local.install_test_bridge(&["kura.network.roles"]).await;
            let caller=local.clone();let job=tokio::spawn(async move{caller.network_roles().await});
            let frame=rx.recv().await.unwrap();let mut value=projection();
            if replace {local.bridge.write().await.as_mut().unwrap().epoch=2;} else {value["pid"]=json!("another.pid");}
            local.complete_pending(&frame.request_id,Some(value),None);
            let result=job.await.unwrap();assert!(result.is_err());assert!(rx.try_recv().is_err());
        }
    }
    #[tokio::test]
    async fn paired_role_and_fence_reads_allow_the_confirmed_cohort_to_finish() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        let mut rx=local.install_test_bridge(&["kura.network.roles","kura.network.fence"]).await;
        let reader=local.clone();
        let roles=tokio::spawn(async move{reader.network_roles().await});
        let reader=local.clone();
        let fence=tokio::spawn(async move{reader.network_role_fence().await});
        let requests=[rx.recv().await.unwrap(),rx.recv().await.unwrap()];
        tokio::time::sleep(Duration::from_millis(2150)).await;
        for request in requests {
            let reply=match request.method.as_str() {
                "kura.network.roles"=>projection(),
                "kura.network.fence"=>json!({"schemaVersion":1,"fenced":true,"roles":projection()}),
                _=>unreachable!(),
            };
            local.complete_pending(&request.request_id,Some(reply),None);
        }
        assert!(roles.await.unwrap().unwrap()==fence.await.unwrap().unwrap());
        assert!(rx.try_recv().is_err());
    }
    #[tokio::test]
    async fn writer_role_source_requires_the_quiescence_reply_and_same_registration() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        for fenced in [false,true] {
            let mut rx=local.install_test_bridge(&["kura.network.fence"]).await;
            let caller=local.clone();let job=tokio::spawn(async move{caller.network_role_fence().await});
            let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.network.fence");
            local.complete_pending(&frame.request_id,Some(json!({"schemaVersion":1,"fenced":fenced,"roles":projection()})),None);
            assert_eq!(job.await.unwrap().is_ok(),fenced);assert!(rx.try_recv().is_err());
        }
    }
    #[tokio::test]
    async fn native_original_drain_adapter_uses_registered_paired_callback_and_rejects_source_or_epoch_drift() {
        use crate::nm::roles::{BridgeSource,Observation,Source};
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        let original=Observation::new(local.instance_id,1,projection()).unwrap();
        let operation=uuid::Uuid::new_v4();let plan="a".repeat(64);
        for defect in ["none","revision","instance","epoch","not-fenced"] {
            let mut rx=local.install_test_bridge(&["kura.network.fence"]).await;
            let expected=if defect=="instance" {Observation::new(uuid::Uuid::new_v4(),1,projection()).unwrap()}else{original.clone()};
            let source=BridgeSource::new(local.clone());let plan=plan.clone();
            let job=tokio::task::spawn_blocking(move||source.legacy_drain(&expected,operation,&plan,std::time::Instant::now()+Duration::from_secs(2)));
            let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.network.fence");assert_eq!(frame.params,Some(json!({})));
            if defect=="epoch" {local.bridge.write().await.as_mut().unwrap().epoch=2;}
            let mut roles=projection();if defect=="revision" {roles["revision"]=json!("changed");}
            local.complete_pending(&frame.request_id,Some(json!({"schemaVersion":1,"fenced":defect!="not-fenced","roles":roles})),None);
            assert_eq!(job.await.unwrap().is_ok(),defect=="none","{defect}");assert!(rx.try_recv().is_err());
        }
        let mut rx=local.install_test_bridge(&["kura.network.fence"]).await;let source=BridgeSource::new(local.clone());
        let job=tokio::task::spawn_blocking(move||source.legacy_drain(&original,uuid::Uuid::nil(),"wrong",std::time::Instant::now()+Duration::from_secs(2)));
        assert!(job.await.unwrap().is_err());assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn runtime_executable_observation_requires_the_same_kernel_peer_and_epoch() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        let mut rx=local.install_test_bridge(&["kura.network.startup.profile"]).await;
        local.bridge.write().await.as_mut().unwrap().peer_pid=Some(97);
        assert!(matches!(local.network_runtime_executable(json!({}),98).await,Err("CONFLICT")));
        assert!(rx.try_recv().is_err());
        for defect in ["none","claimed-pid","epoch"] {
            let mut rx=local.install_test_bridge(&["kura.network.startup.profile"]).await;
            local.bridge.write().await.as_mut().unwrap().peer_pid=Some(97);
            let caller=local.clone();
            let job=tokio::spawn(async move{caller.network_runtime_executable(json!({"nonce":"existing-challenge"}),97).await});
            let frame=rx.recv().await.unwrap();
            assert_eq!(frame.method,"kura.network.startup.profile");
            assert_eq!(frame.params,Some(json!({"nonce":"existing-challenge","executableProcessId":97})));
            if defect=="epoch"{local.bridge.write().await.as_mut().unwrap().epoch=2;}
            let response=json!({"schemaVersion":1,"processId":if defect=="claimed-pid"{98}else{97},
                "startTicks":205,"path":"/usr/bin/java","device":2,"inode":7,"size":1024,"ctime":9,"ctimeNanos":10});
            local.complete_pending(&frame.request_id,Some(response),None);
            assert_eq!(job.await.unwrap().is_ok(),defect=="none");
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn actual_owner_projection_is_fixed_authenticated_and_refuses_changed_registration_or_claims() {
        let local=Local::new(unsafe{libc::geteuid()},unsafe{libc::geteuid()});
        for defect in ["none","registration","ready","pid","operation","plan","mirror","networkOnly","firewallPid","firewallRevision","firewallDigest"] {
            let mut rx=local.install_test_bridge(&["kura.network.owner"]).await;
            let caller=local.clone();let job=tokio::spawn(async move{caller.network_owner().await});
            let frame=rx.recv().await.unwrap();assert_eq!(frame.method,"kura.network.owner");assert_eq!(frame.params,Some(json!({})));
            let mut value=json!({"schemaVersion":2,"pid":"org.eclipse.kura.net.admin.NetworkConfigurationService",
                "operationId":"12345678-1234-4123-8123-123456789abc","planSha256":"a".repeat(64),"mirrorSha256":"b".repeat(64),"roles":projection(),
                "firewall":{"schemaVersion":1,"pids":[crate::nm::roles::FIREWALL_V4_PID,crate::nm::roles::FIREWALL_V6_PID],
                    "revision":"1","sourceDigest":"c".repeat(64)}});
            match defect {
                "registration"=>local.bridge.write().await.as_mut().unwrap().epoch=2,
                "ready"=>{value["ready"]=json!(true);},
                "pid"=>value["pid"]=json!("another.pid"),
                "operation"=>value["operationId"]=json!(uuid::Uuid::nil()),
                "plan"=>value["planSha256"]=json!("a".repeat(63)),
                "mirror"=>value["mirrorSha256"]=json!("B".repeat(64)),
                "networkOnly"=>{value["schemaVersion"]=json!(1);value.as_object_mut().unwrap().remove("firewall");},
                "firewallPid"=>value["firewall"]["pids"][1]=json!(crate::nm::roles::FIREWALL_V4_PID),
                "firewallRevision"=>value["firewall"]["revision"]=json!("0"),
                "firewallDigest"=>value["firewall"]["sourceDigest"]=json!("C".repeat(64)),
                _=>{},
            }
            local.complete_pending(&frame.request_id,Some(value),None);
            assert_eq!(job.await.unwrap().is_ok(),defect=="none","{defect}");assert!(rx.try_recv().is_err());
        }
    }

}
