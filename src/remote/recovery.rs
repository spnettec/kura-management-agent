//! Explicit local operator resolution. Unknown switch intents are archived, never replayed.
use super::*;
use std::{fs, io::ErrorKind, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecoveryObservation {
    expected_revision: String,
    decision_sha256: String,
    pending_sha256: Option<String>,
    resolution_sha256: Option<String>,
}

pub(super) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let (bytes, metadata) = crate::durable::read(path, 8192)?;
    ensure!(
        metadata.uid == unsafe { libc::geteuid() } && metadata.mode == 0o600,
        "FORBIDDEN"
    );
    Ok(bytes)
}

fn optional(path: &Path) -> Result<Option<Vec<u8>>> {
    if present(path)? {
        Ok(Some(read(path)?))
    } else {
        Ok(None)
    }
}

struct Evidence {
    observation: RecoveryObservation,
    decision: Vec<u8>,
    pending: Option<Vec<u8>>,
    resolution: Option<Vec<u8>>,
}

impl Remote {
    fn evidence(&self, state: &State) -> Result<Evidence> {
        let decision = read(&self.root.join("remote-management.json"))?;
        let pending = optional(&self.root.join("remote-management-pending.json"))?;
        let resolution = optional(&self.root.join("remote-management-resolution.json"))?;
        let observation = RecoveryObservation {
            expected_revision: state.decision.revision.clone(),
            decision_sha256: crate::durable::hash(&decision),
            pending_sha256: pending.as_deref().map(crate::durable::hash),
            resolution_sha256: resolution.as_deref().map(crate::durable::hash),
        };
        Ok(Evidence {
            observation,
            decision,
            pending,
            resolution,
        })
    }

    pub fn recovery_status(&self) -> Result<Value> {
        let state = self.state.lock().unwrap();
        let evidence = self.evidence(&state)?;
        Ok(json!({"observation": evidence.observation,
            "recoveryRequired":state.fault || state.binding_fault, "activeRequests":state.active,
            "canResolve":state.fault && !state.binding_fault && state.active==0}))
    }

    pub fn resolve_disabled(&self, expected: RecoveryObservation, actor: String) -> Result<Value> {
        self.resolve_with_hook(expected, actor, |_| Ok(()))
    }

    fn resolve_with_hook(
        &self,
        expected: RecoveryObservation,
        actor: String,
        mut checkpoint: impl FnMut(&str) -> Result<()>,
    ) -> Result<Value> {
        ensure!(
            !actor.is_empty() && actor.len() <= 160 && !actor.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        ensure!(
            uuid::Uuid::parse_str(&expected.expected_revision).is_ok()
                && [
                    &Some(expected.decision_sha256.clone()),
                    &expected.pending_sha256,
                    &expected.resolution_sha256
                ]
                .into_iter()
                .all(|hash| hash.as_ref().is_none_or(|s| s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))),
            "INVALID_ARGUMENT"
        );
        let mut state = self.state.lock().unwrap();
        ensure!(
            state.fault && !state.binding_fault && state.active == 0,
            "CONFLICT: no idle remote recovery to resolve"
        );
        let evidence = self.evidence(&state)?;
        ensure!(
            expected == evidence.observation,
            "CONFLICT: recovery evidence changed; inspect again"
        );
        let archives = self.root.join("remote-management-recoveries");
        crate::durable::directory(&archives)?;
        ensure!(
            fs::read_dir(&archives)?.count() < 64,
            "RESOURCE_EXHAUSTED: retain and archive prior resolutions"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let archive = archives.join(&id);
        // A new directory per explicit attempt, including retries after unknown outcomes.
        fs::create_dir(&archive)?;
        crate::durable::directory(&archive)?;
        crate::durable::sync_directory(&archives)?;
        let decision = Decision {
            version: 1,
            revision: uuid::Uuid::new_v4().to_string(),
            enabled: false,
            actor,
        };
        let decision_bytes = serde_json::to_vec(&decision)?;
        let guard = json!({"version":1,"archiveId":id,"observation":expected,
            "decision":decision,"decisionSha256":crate::durable::hash(&decision_bytes)});
        let pending_path = self.root.join("remote-management-pending.json");
        let guard_path = self.root.join("remote-management-resolution.json");
        let persisted = (|| {
            crate::durable::publish_new(
                &archive.join("decision-before.json"),
                &evidence.decision,
                crate::durable::FileMetadata::private(),
            )?;
            for (name, bytes) in [
                ("pending-before.json", evidence.pending.as_deref()),
                ("resolution-before.json", evidence.resolution.as_deref()),
            ] {
                if let Some(bytes) = bytes {
                    crate::durable::publish_new(
                        &archive.join(name),
                        bytes,
                        crate::durable::FileMetadata::private(),
                    )?;
                }
            }
            crate::durable::publish_new(
                &archive.join("operator-decision.json"),
                &serde_json::to_vec(&guard)?,
                crate::durable::FileMetadata::private(),
            )?;
            checkpoint("archived")?;
            crate::durable::json(&guard_path, &guard)?;
            checkpoint("guarded")?;
            crate::durable::write(
                &self.root.join("remote-management.json"),
                &decision_bytes,
                crate::durable::FileMetadata::private(),
            )?;
            checkpoint("decision")?;
            if evidence.pending.is_some() {
                fs::rename(&pending_path, archive.join("pending-original.json"))?;
                crate::durable::sync_directory(&archive)?;
                crate::durable::sync_directory(&self.root)?;
            }
            checkpoint("pending-archived")?;
            fs::rename(&guard_path, archive.join("completed-intent.json"))?;
            crate::durable::sync_directory(&archive)?;
            crate::durable::sync_directory(&self.root)?;
            checkpoint("completed")?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = persisted {
            state.fault = true;
            self.changes.send_replace(uuid::Uuid::new_v4().to_string());
            return Err(error);
        }
        state.decision = decision;
        state.connection = "DISCONNECTED";
        state.fault = false;
        self.changes.send_replace(state.decision.revision.clone());
        drop(state);
        Ok(json!({"status":self.status(),"resolutionId":id}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Remote, PathBuf, Vec<u8>, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("remote-resolution-{}", uuid::Uuid::new_v4()));
        let target = Some(("https://example.invalid:8443".into(), "gw".into(), 1));
        let first = Remote::open(dir.clone(), true, target.clone()).unwrap();
        let before = read(&dir.join("remote-management.json")).unwrap();
        let pending = br#"{"evidence":"unknown original request; never replay"}"#.to_vec();
        crate::durable::write(
            &dir.join("remote-management-pending.json"),
            &pending,
            crate::durable::FileMetadata::private(),
        )
        .unwrap();
        drop(first);
        (
            Remote::open(dir.clone(), true, target).unwrap(),
            dir,
            before,
            pending,
        )
    }
    fn observation(remote: &Remote) -> RecoveryObservation {
        serde_json::from_value(remote.recovery_status().unwrap()["observation"].clone()).unwrap()
    }
    #[test]
    fn operator_resolves_to_off_preserving_every_original_and_other_subsystems() {
        let (remote, dir, before, pending) = fixture();
        let old = remote.status()["revision"].as_str().unwrap().to_owned();
        assert!(remote.session().is_none());
        assert!(remote.set_enabled(&old, false, "root".into()).is_err());
        crate::durable::directory(&dir.join("firewall")).unwrap();
        crate::durable::json(
            &dir.join("firewall/transaction.json"),
            &json!({"state":"RECOVERY_REQUIRED","evidence":"retained"}),
        )
        .unwrap();
        let other = fs::read(dir.join("firewall/transaction.json")).unwrap();
        let expected = observation(&remote);
        let result = remote
            .resolve_disabled(expected.clone(), "local-uid:0".into())
            .unwrap();
        assert_eq!(result["status"]["enabled"], false);
        assert_eq!(result["status"]["recoveryRequired"], false);
        assert_ne!(result["status"]["revision"], old);
        assert!(remote.session().is_none());
        let archive = dir
            .join("remote-management-recoveries")
            .join(result["resolutionId"].as_str().unwrap());
        assert_eq!(read(&archive.join("decision-before.json")).unwrap(), before);
        assert_eq!(read(&archive.join("pending-before.json")).unwrap(), pending);
        assert_eq!(
            read(&archive.join("pending-original.json")).unwrap(),
            pending
        );
        assert!(archive.join("completed-intent.json").is_file());
        assert_eq!(
            fs::read(dir.join("firewall/transaction.json")).unwrap(),
            other
        );
        assert!(!dir.join("remote-management-pending.json").exists());
        assert!(!dir.join("remote-management-resolution.json").exists());
        assert!(
            remote
                .resolve_disabled(expected, "local-uid:0".into())
                .is_err()
        );
        let reopened = Remote::open(
            dir.clone(),
            true,
            remote.state.lock().unwrap().target.clone(),
        )
        .unwrap();
        assert_eq!(reopened.status()["enabled"], false);
        assert_eq!(reopened.status()["recoveryRequired"], false);
    }
    #[test]
    fn stale_observation_is_rejected_without_changing_any_evidence() {
        let (remote, dir, before, _) = fixture();
        let expected = observation(&remote);
        crate::durable::json(
            &dir.join("remote-management-pending.json"),
            &json!({"changed":true}),
        )
        .unwrap();
        let changed = read(&dir.join("remote-management-pending.json")).unwrap();
        assert!(remote.resolve_disabled(expected, "root".into()).is_err());
        assert_eq!(read(&dir.join("remote-management.json")).unwrap(), before);
        assert_eq!(
            read(&dir.join("remote-management-pending.json")).unwrap(),
            changed
        );
        assert!(!dir.join("remote-management-recoveries").exists());
        assert!(remote.session().is_none());
    }
    #[test]
    fn interruption_at_each_publication_boundary_stays_blocked_or_durably_off() {
        for boundary in [
            "archived",
            "guarded",
            "decision",
            "pending-archived",
            "completed",
        ] {
            let (remote, dir, before, pending) = fixture();
            let failed = remote.resolve_with_hook(observation(&remote), "root".into(), |phase| {
                ensure!(phase != boundary, "injected interruption");
                Ok(())
            });
            assert!(failed.is_err());
            assert!(remote.session().is_none());
            assert_eq!(remote.status()["recoveryRequired"], true);
            assert!(
                remote
                    .set_enabled(
                        remote.status()["revision"].as_str().unwrap(),
                        true,
                        "root".into()
                    )
                    .is_err()
            );
            let archive = fs::read_dir(dir.join("remote-management-recoveries"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert_eq!(read(&archive.join("decision-before.json")).unwrap(), before);
            assert_eq!(read(&archive.join("pending-before.json")).unwrap(), pending);
            let reopened = Remote::open(
                dir.clone(),
                true,
                remote.state.lock().unwrap().target.clone(),
            )
            .unwrap();
            if boundary == "completed" {
                assert_eq!(reopened.status()["recoveryRequired"], false);
                assert_eq!(reopened.status()["enabled"], false);
            } else {
                assert_eq!(reopened.status()["recoveryRequired"], true);
            }
            // An uncertain caller must inspect again; this is a new explicit OFF decision.
            remote
                .resolve_disabled(observation(&remote), "root-new-inspection".into())
                .unwrap();
            assert_eq!(remote.status()["enabled"], false);
            assert!(remote.session().is_none());
        }
    }
    #[test]
    fn recovery_cannot_discard_admitted_work_or_read_links() {
        let (remote, dir, _, pending) = fixture();
        remote.state.lock().unwrap().active = 1;
        assert!(
            remote
                .resolve_disabled(observation(&remote), "root".into())
                .is_err()
        );
        remote.state.lock().unwrap().active = 0;
        let path = dir.join("remote-management-pending.json");
        fs::rename(&path, dir.join("original")).unwrap();
        std::os::unix::fs::symlink(dir.join("original"), &path).unwrap();
        assert!(remote.recovery_status().is_err());
        assert_eq!(fs::read(dir.join("original")).unwrap(), pending);
        assert!(remote.session().is_none());
    }
    #[test]
    fn missing_decision_with_retained_intent_is_not_a_new_install() {
        let (_, dir, _, pending) = fixture();
        fs::rename(
            dir.join("remote-management.json"),
            dir.join("original-decision"),
        )
        .unwrap();
        assert!(Remote::open(dir.clone(), false, None).is_err());
        assert!(!dir.join("remote-management.json").exists());
        assert_eq!(
            read(&dir.join("remote-management-pending.json")).unwrap(),
            pending
        );
    }
}
