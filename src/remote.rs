//! Durable, local-only control of the management channel. No key generation,
//! identity replacement, system service stop, or task deletion is granted here.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;
mod recovery;
pub use recovery::RecoveryObservation;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Decision {
    version: u32,
    revision: String,
    enabled: bool,
    actor: String,
}
struct State {
    decision: Decision,
    active: u32,
    fault: bool,
    connection: &'static str,
    target: Option<(String, String, u64)>,
    binding_fault: bool,
}
#[derive(Clone)]
pub struct Remote {
    root: PathBuf,
    state: Arc<Mutex<State>>,
    changes: watch::Sender<String>,
}
pub struct Admission {
    state: Arc<Mutex<State>>,
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.state.lock().unwrap().active -= 1;
    }
}
impl Remote {
    pub fn open(
        root: PathBuf,
        initial_enabled: bool,
        target: Option<(String, String, u64)>,
    ) -> Result<Self> {
        crate::durable::directory(&root)?;
        let path = root.join("remote-management.json");
        let decision: Decision = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let (bytes, metadata) = crate::durable::read(&path, 4096)?;
                ensure!(
                    metadata.uid == unsafe { libc::geteuid() } && metadata.mode == 0o600,
                    "FORBIDDEN"
                );
                serde_json::from_slice(&bytes)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    !recovery::present(&root.join("remote-management-pending.json"))?
                        && !recovery::present(&root.join("remote-management-resolution.json"))?,
                    "CONFLICT: retained remote recovery evidence without decision"
                );
                ensure!(
                    !initial_enabled || target.is_some(),
                    "CONFLICT: no registered identity"
                );
                let decision = Decision {
                    version: 1,
                    revision: uuid::Uuid::new_v4().to_string(),
                    enabled: initial_enabled,
                    actor: "installation".into(),
                };
                crate::durable::publish_new(
                    &path,
                    &serde_json::to_vec(&decision)?,
                    crate::durable::FileMetadata::private(),
                )?;
                decision
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(
            decision.version == 1 && uuid::Uuid::parse_str(&decision.revision).is_ok(),
            "CONFLICT: invalid remote control state"
        );
        let (changes, _) = watch::channel(decision.revision.clone());
        Ok(Self {
            root: root.clone(),
            changes,
            state: Arc::new(Mutex::new(State {
                decision,
                active: 0,
                target,
                binding_fault: false,
                fault: recovery::present(&root.join("remote-management-pending.json"))?
                    || recovery::present(&root.join("remote-management-resolution.json"))?,
                connection: "DISCONNECTED",
            })),
        })
    }
    pub fn inhibit_binding(&self) {
        let mut state = self.state.lock().unwrap();
        state.binding_fault = true;
        self.changes.send_replace(uuid::Uuid::new_v4().to_string());
    }
    pub fn bind_target(
        &self,
        expected: &str,
        target: (String, String, u64),
        actor: String,
        commit: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.fault
                && !state.binding_fault
                && state.target.is_none()
                && !state.decision.enabled
                && state.active == 0,
            "CONFLICT: identity admission unavailable"
        );
        ensure!(
            state.decision.revision == expected,
            "CONFLICT: remote settings changed"
        );
        let decision = Decision {
            version: 1,
            revision: uuid::Uuid::new_v4().to_string(),
            enabled: false,
            actor,
        };
        if let Err(error) = commit(&serde_json::to_vec(&decision)?) {
            state.binding_fault = true;
            self.changes.send_replace(uuid::Uuid::new_v4().to_string());
            return Err(error);
        }
        state.target = Some(target);
        state.decision = decision;
        state.connection = "DISCONNECTED";
        self.changes.send_replace(state.decision.revision.clone());
        Ok(())
    }
    pub fn subscribe(&self) -> watch::Receiver<String> {
        self.changes.subscribe()
    }
    pub fn session(&self) -> Option<String> {
        let state = self.state.lock().unwrap();
        (!state.fault && !state.binding_fault && state.decision.enabled && state.target.is_some())
            .then(|| state.decision.revision.clone())
    }
    pub fn admit(&self, revision: &str) -> Result<Admission> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.fault
                && !state.binding_fault
                && state.decision.enabled
                && state.target.is_some()
                && state.decision.revision == revision,
            "FORBIDDEN: remote session disabled or changed"
        );
        state.active += 1;
        Ok(Admission {
            state: self.state.clone(),
        })
    }
    pub fn connection(&self, revision: &str, connection: &'static str) {
        let mut state = self.state.lock().unwrap();
        if state.decision.revision == revision {
            state.connection = connection;
        }
    }
    pub fn status(&self) -> Value {
        let state = self.state.lock().unwrap();
        let connection = if state.fault || state.binding_fault {
            "RECOVERY_REQUIRED"
        } else if state.target.is_none() {
            "UNBOUND"
        } else if !state.decision.enabled {
            "DISABLED"
        } else {
            state.connection
        };
        let mut view = json!({"enabled": state.decision.enabled, "bound":state.target.is_some(), "revision":state.decision.revision,
            "connectionState": connection, "activeRequests":state.active, "recoveryRequired":state.fault || state.binding_fault});
        if let Some((endpoint, gateway, generation)) = &state.target {
            view["endpoint"] = json!(endpoint);
            view["gatewayId"] = json!(gateway);
            view["bindingGeneration"] = json!(generation.to_string());
        }
        view
    }
    pub fn set_enabled(&self, expected: &str, enabled: bool, actor: String) -> Result<Value> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.fault && !state.binding_fault,
            "CONFLICT: remote control recovery required"
        );
        ensure!(
            state.decision.revision == expected,
            "CONFLICT: remote settings changed"
        );
        ensure!(
            !enabled || state.target.is_some(),
            "CONFLICT: no registered identity"
        );
        ensure!(
            state.active == 0,
            "CONFLICT: accepted remote requests are executing"
        );
        if state.decision.enabled != enabled {
            let decision = Decision {
                version: 1,
                revision: uuid::Uuid::new_v4().to_string(),
                enabled,
                actor,
            };
            // Publish the decision before closing or opening any stream. Restarts use the same choice.
            let pending = self.root.join("remote-management-pending.json");
            let persisted = (|| {
                crate::durable::publish_new(
                    &pending,
                    &serde_json::to_vec(&decision)?,
                    crate::durable::FileMetadata::private(),
                )?;
                crate::durable::json(&self.root.join("remote-management.json"), &decision)?;
                crate::durable::remove(&pending)?;
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = persisted {
                // An uncertain fsync/rename must disable admission immediately;
                // retained intent also blocks writes after process restart.
                state.fault = true;
                self.changes.send_replace(uuid::Uuid::new_v4().to_string());
                return Err(error);
            }
            state.decision = decision;
            state.connection = "DISCONNECTED";
            self.changes.send_replace(state.decision.revision.clone());
        }
        drop(state);
        Ok(self.status())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("remote-control-{}", uuid::Uuid::new_v4()))
    }
    fn target() -> Option<(String, String, u64)> {
        Some(("https://example.invalid:8443".into(), "gateway".into(), 4))
    }
    #[test]
    fn defaults_off_unbound_and_persists_explicit_decision_across_restart() {
        let dir = root();
        let remote = Remote::open(dir.clone(), false, target()).unwrap();
        assert_eq!(remote.status()["connectionState"], "DISABLED");
        assert!(remote.session().is_none());
        let old = remote.status()["revision"].as_str().unwrap().to_string();
        let enabled = remote.set_enabled(&old, true, "local-root".into()).unwrap();
        let revision = enabled["revision"].as_str().unwrap();
        assert!(remote.admit(&old).is_err());
        let reopened = Remote::open(dir.clone(), false, target()).unwrap();
        assert_eq!(reopened.session().as_deref(), Some(revision));
        let disabled = reopened
            .set_enabled(revision, false, "kura-uid:1000".into())
            .unwrap();
        assert_eq!(
            Remote::open(dir.clone(), true, target()).unwrap().status(),
            disabled
        );
        let unbound = Remote::open(root(), false, None).unwrap();
        assert_eq!(unbound.status()["connectionState"], "UNBOUND");
        assert!(
            unbound
                .set_enabled(
                    unbound.status()["revision"].as_str().unwrap(),
                    true,
                    "root".into()
                )
                .is_err()
        );
    }
    #[test]
    fn admitted_work_cannot_be_cancelled_and_old_stream_never_regains_admission() {
        let remote = Remote::open(root(), true, target()).unwrap();
        let revision = remote.session().unwrap();
        let permit = remote.admit(&revision).unwrap();
        assert!(remote.set_enabled(&revision, false, "root".into()).is_err());
        assert!(remote.session().is_some());
        drop(permit);
        let disabled = remote.set_enabled(&revision, false, "root".into()).unwrap();
        assert!(remote.admit(&revision).is_err());
        remote
            .set_enabled(disabled["revision"].as_str().unwrap(), true, "root".into())
            .unwrap();
        assert!(remote.admit(&revision).is_err());
        assert!(remote.admit(&remote.session().unwrap()).is_ok());
    }
    #[test]
    fn incomplete_switch_decision_blocks_remote_admission_after_restart() {
        let dir = root();
        let remote = Remote::open(dir.clone(), true, target()).unwrap();
        let revision = remote.session().unwrap();
        crate::durable::json(
            &dir.join("remote-management-pending.json"),
            &json!({"evidence":"retained"}),
        )
        .unwrap();
        assert!(remote.set_enabled(&revision, false, "root".into()).is_err());
        assert!(remote.session().is_none());
        assert!(remote.admit(&revision).is_err());
        let reopened = Remote::open(dir.clone(), true, target()).unwrap();
        assert_eq!(reopened.status()["connectionState"], "RECOVERY_REQUIRED");
        assert!(reopened.session().is_none());
        assert!(reopened.admit(&revision).is_err());
        assert!(
            reopened
                .set_enabled(&revision, false, "root".into())
                .is_err()
        );
        assert_eq!(
            std::fs::read(dir.join("remote-management-pending.json")).unwrap(),
            br#"{"evidence":"retained"}"#
        );
    }
    #[test]
    fn unsafe_or_corrupt_decisions_do_not_reset_to_enabled_or_create_a_new_identity() {
        let dir = root();
        Remote::open(dir.clone(), false, target()).unwrap();
        let path = dir.join("remote-management.json");
        std::fs::write(&path, b"broken").unwrap();
        assert!(Remote::open(dir.clone(), true, target()).is_err());
        std::fs::remove_file(&path).unwrap();
        let other = dir.join("other");
        std::fs::write(&other, b"keep").unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(Remote::open(dir, true, target()).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"keep");
    }
}
