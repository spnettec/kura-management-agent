//! Admission for the enrollment store's durable managed-identity renewal.
use super::*;

impl Remote {
    /// The store commits the new identity and this exact OFF decision together.
    /// A known rejection changes neither target nor switch revision. An uncertain
    /// commit inhibits all admission until the retained identity journal is resolved.
    pub(crate) fn renew_target(
        &self,
        expected_revision: &str,
        expected_target: &(String, String, u64),
        actor: String,
        commit: impl FnOnce(&[u8]) -> Result<bool>,
    ) -> Result<bool> {
        ensure!(
            !actor.is_empty() && actor.len() <= 160 && !actor.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.fault && !state.binding_fault && !state.decision.enabled && state.active == 0,
            "CONFLICT: renewal requires an idle, healthy, disabled channel"
        );
        ensure!(
            state.decision.revision == expected_revision
                && state.target.as_ref() == Some(expected_target),
            "CONFLICT: original identity or remote decision changed"
        );
        ensure!(
            expected_target.2 > 0 && expected_target.2 < i64::MAX as u64,
            "CONFLICT: binding generation exhausted"
        );
        let next = (
            expected_target.0.clone(),
            expected_target.1.clone(),
            expected_target.2 + 1,
        );
        let decision = Decision {
            version: 1,
            revision: uuid::Uuid::new_v4().to_string(),
            enabled: false,
            actor,
        };
        match commit(&serde_json::to_vec(&decision)?) {
            Ok(false) => Ok(false),
            Ok(true) => {
                state.target = Some(next);
                state.decision = decision;
                state.connection = "DISCONNECTED";
                self.changes.send_replace(state.decision.revision.clone());
                Ok(true)
            }
            Err(error) => {
                state.binding_fault = true;
                self.changes.send_replace(uuid::Uuid::new_v4().to_string());
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("managed-renewal-{}", uuid::Uuid::new_v4()))
    }
    fn target() -> (String, String, u64) {
        (
            "https://example.invalid:8443".into(),
            "renewal-gateway".into(),
            4,
        )
    }
    #[test]
    fn successful_renewal_stays_off_and_old_stream_never_regains_admission() {
        let root = root();
        let remote = Remote::open(root.clone(), false, Some(target())).unwrap();
        let before = remote.status();
        let revision = before["revision"].as_str().unwrap();
        assert!(
            remote
                .renew_target(
                    revision,
                    &target(),
                    "authenticated-local-admin".into(),
                    |bytes| {
                        let decision: Value = serde_json::from_slice(bytes)?;
                        assert_eq!(decision["enabled"], false);
                        assert_ne!(decision["revision"], revision);
                        crate::durable::write(
                            &root.join("remote-management.json"),
                            bytes,
                            crate::durable::FileMetadata::private(),
                        )?;
                        Ok(true)
                    }
                )
                .unwrap()
        );
        let after = remote.status();
        assert_eq!(after["enabled"], false);
        assert_eq!(after["connectionState"], "DISABLED");
        assert_eq!(after["bindingGeneration"], "5");
        assert_eq!(after["gatewayId"], before["gatewayId"]);
        assert_eq!(after["endpoint"], before["endpoint"]);
        assert!(remote.session().is_none());
        assert!(remote.admit(revision).is_err());
        let mut next = target();
        next.2 = 5;
        assert_eq!(
            Remote::open(root, true, Some(next)).unwrap().status(),
            after
        );
        remote
            .set_enabled(
                after["revision"].as_str().unwrap(),
                true,
                "local-admin".into(),
            )
            .unwrap();
        assert!(remote.admit(revision).is_err());
        assert!(remote.admit(&remote.session().unwrap()).is_ok());
    }
    #[test]
    fn admission_refuses_enabled_active_changed_unbound_or_exhausted_identity_before_commit() {
        let calls = AtomicUsize::new(0);
        let enabled = Remote::open(root(), true, Some(target())).unwrap();
        let revision = enabled.session().unwrap();
        let permit = enabled.admit(&revision).unwrap();
        assert!(
            enabled
                .renew_target(&revision, &target(), "admin".into(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(true)
                })
                .is_err()
        );
        assert_eq!(enabled.status()["activeRequests"], 1);
        assert!(enabled.session().is_some());
        drop(permit);
        assert!(
            enabled
                .renew_target(&revision, &target(), "admin".into(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(true)
                })
                .is_err()
        );
        let disabled = enabled
            .set_enabled(&revision, false, "admin".into())
            .unwrap();
        assert!(
            enabled
                .renew_target(&revision, &target(), "admin".into(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(true)
                })
                .is_err()
        );
        for wrong in [
            ("https://another.invalid:8443".into(), target().1, 4),
            (target().0, "another-gateway".into(), 4),
            (target().0, target().1, 5),
        ] {
            assert!(
                enabled
                    .renew_target(
                        disabled["revision"].as_str().unwrap(),
                        &wrong,
                        "admin".into(),
                        |_| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(true)
                        }
                    )
                    .is_err()
            );
        }
        let unbound = Remote::open(root(), false, None).unwrap();
        assert!(
            unbound
                .renew_target(
                    unbound.status()["revision"].as_str().unwrap(),
                    &target(),
                    "admin".into(),
                    |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(true)
                    }
                )
                .is_err()
        );
        for generation in [0, i64::MAX as u64, u64::MAX] {
            let mut value = target();
            value.2 = generation;
            let remote = Remote::open(root(), false, Some(value.clone())).unwrap();
            assert!(
                remote
                    .renew_target(
                        remote.status()["revision"].as_str().unwrap(),
                        &value,
                        "admin".into(),
                        |_| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(true)
                        }
                    )
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn known_rejection_preserves_original_target_switch_bytes_and_revision() {
        let root = root();
        let remote = Remote::open(root.clone(), false, Some(target())).unwrap();
        let before = remote.status();
        let bytes = std::fs::read(root.join("remote-management.json")).unwrap();
        let changes = remote.subscribe();
        assert!(
            !remote
                .renew_target(
                    before["revision"].as_str().unwrap(),
                    &target(),
                    "admin".into(),
                    |_| Ok(false)
                )
                .unwrap()
        );
        assert_eq!(remote.status(), before);
        assert_eq!(
            std::fs::read(root.join("remote-management.json")).unwrap(),
            bytes
        );
        assert!(!changes.has_changed().unwrap());
    }
    #[test]
    fn uncertain_commit_retains_evidence_and_inhibits_switch_without_retry() {
        let root = root();
        let remote = Remote::open(root.clone(), false, Some(target())).unwrap();
        let before = remote.status();
        let revision = before["revision"].as_str().unwrap();
        let calls = AtomicUsize::new(0);
        let pending = root.join("test-retained-renewal-intent.json");
        assert!(
            remote
                .renew_target(revision, &target(), "admin".into(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    crate::durable::publish_new(
                        &pending,
                        b"retained-original-intent",
                        crate::durable::FileMetadata::private(),
                    )?;
                    anyhow::bail!("injected failure after intent publication")
                })
                .is_err()
        );
        assert_eq!(remote.status()["connectionState"], "RECOVERY_REQUIRED");
        assert_eq!(remote.status()["bindingGeneration"], "4");
        assert!(remote.session().is_none());
        assert!(remote.set_enabled(revision, true, "admin".into()).is_err());
        assert!(remote.set_enabled(revision, false, "admin".into()).is_err());
        assert!(
            remote
                .renew_target(revision, &target(), "admin".into(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(true)
                })
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(pending).unwrap(), b"retained-original-intent");
    }
}
