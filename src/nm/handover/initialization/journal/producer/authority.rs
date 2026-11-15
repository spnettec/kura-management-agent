//! Persisted authority audit,never a fresh live capability. The live variant
//! retains its historical JSON bytes; stopped authority has an explicit scope.
use super::*;
use crate::nm::handover::startup::StoppedRuntimeChallenge;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(in crate::nm) enum OwnerAuthority {
    Live(roles::Owner),
    Stopped(StoppedOwner),
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Scope {
    StoppedConfirmed,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct StoppedOwner {
    schema_version: u8,
    authority_kind: Scope,
    original_owner: roles::Owner,
    firewall_revision: u64,
    firewall_source_digest: String,
    original_startup_receipt_sha256: String,
    selected_profile_sha256: String,
    runtime_sha256: String,
}

impl OwnerAuthority {
    /// Capacity estimation only. This value is never persisted or used to
    /// construct a capability; reserve the larger stopped audit for both intents.
    pub(super) fn reserved(&self) -> Self {
        Self::Stopped(StoppedOwner {
            schema_version: 1,
            authority_kind: Scope::StoppedConfirmed,
            original_owner: self.original().clone(),
            firewall_revision: u64::MAX,
            firewall_source_digest: "f".repeat(64),
            original_startup_receipt_sha256: "f".repeat(64),
            selected_profile_sha256: "f".repeat(64),
            runtime_sha256: "f".repeat(64),
        })
    }
    pub(in crate::nm) fn stopped(
        original: &roles::Owner,
        revision: u64,
        source: &str,
        challenge: &StoppedRuntimeChallenge,
    ) -> Result<Self> {
        let parameters = challenge.parameters();
        let value = Self::Stopped(StoppedOwner {
            schema_version: 1,
            authority_kind: Scope::StoppedConfirmed,
            original_owner: original.clone(),
            firewall_revision: revision,
            firewall_source_digest: source.into(),
            original_startup_receipt_sha256: parameters["originalStartupReceiptSha256"]
                .as_str()
                .context("CONFLICT: stopped original startup identity")?
                .into(),
            selected_profile_sha256: parameters["selectedProfileSha256"]
                .as_str()
                .context("CONFLICT: stopped selected profile identity")?
                .into(),
            runtime_sha256: challenge.runtime_digest()?,
        });
        value.require_complete()?;
        Ok(value)
    }
    fn original(&self) -> &roles::Owner {
        match self {
            Self::Live(owner) => owner,
            Self::Stopped(owner) => &owner.original_owner,
        }
    }
    pub(in crate::nm) fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped(_))
    }
    pub(in crate::nm) fn require_complete(&self) -> Result<()> {
        self.original().require_complete()?;
        if let Self::Stopped(owner) = self {
            ensure!(
                owner.schema_version == 1
                    && owner.firewall_revision > 0
                    && hex(&owner.firewall_source_digest, 64)
                    && hex(&owner.original_startup_receipt_sha256, 64)
                    && hex(&owner.selected_profile_sha256, 64)
                    && hex(&owner.runtime_sha256, 64),
                "CONFLICT: stopped confirmed authority audit shape"
            );
        }
        Ok(())
    }
    fn firewall(&self) -> Result<(u64, &str)> {
        self.require_complete()?;
        match self {
            Self::Live(owner) => owner.firewall_binding(),
            Self::Stopped(owner) => Ok((owner.firewall_revision, &owner.firewall_source_digest)),
        }
    }
    pub(in crate::nm) fn require_firewall(&self, revision: u64, source: &str) -> Result<()> {
        if let Self::Live(owner) = self {
            return owner.require_firewall(revision, source);
        }
        ensure!(
            self.firewall()? == (revision, source),
            "CONFLICT: recorded authority differs from original current confirmed firewall"
        );
        Ok(())
    }
    pub(in crate::nm) fn require_same_firewall(&self, other: &Self) -> Result<()> {
        if let (Self::Live(left), Self::Live(right)) = (self, other) {
            return left.require_same_firewall(right);
        }
        ensure!(
            self.firewall()? == other.firewall()?,
            "CONFLICT: recorded authority changed the prepared current firewall"
        );
        Ok(())
    }
    pub(in crate::nm) fn require_runtime(&self, runtime: &str) -> Result<()> {
        self.require_complete()?;
        if let Self::Stopped(owner) = self {
            ensure!(
                owner.runtime_sha256 == runtime,
                "CONFLICT: stopped audit differs from captured runtime authority"
            );
        }
        Ok(())
    }
    pub(in crate::nm) fn require_original(
        &self,
        operation: uuid::Uuid,
        plan: &str,
        mirror: &str,
        roles: &roles::ConfigurationRoles,
    ) -> Result<()> {
        self.require_complete()?;
        self.original()
            .require_original(operation, plan, mirror, roles)
    }
    pub(in crate::nm) fn mirror_hash(&self) -> &str {
        self.original().mirror_hash()
    }
    pub(in crate::nm) fn role_configuration(&self) -> &roles::ConfigurationRoles {
        self.original().role_configuration()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> roles::Owner {
        roles::Owner::new(uuid::Uuid::from_u128(11),7,json!({
            "schemaVersion":2,"pid":roles::PID,"operationId":uuid::Uuid::from_u128(12),
            "planSha256":"b".repeat(64),"mirrorSha256":"c".repeat(64),
            "roles":{"schemaVersion":1,"pid":roles::PID,"revision":"stored-audit-only","interfaces":[]},
            "firewall":{"schemaVersion":1,"pids":[roles::FIREWALL_V4_PID,roles::FIREWALL_V6_PID],
                "revision":"7","sourceDigest":"e".repeat(64)}})).unwrap()
    }
    // Deserializable storage audit only. This constructs no runtime challenge,
    // registered lease,Verified or Observed capability.
    fn audit() -> OwnerAuthority {
        OwnerAuthority::Stopped(StoppedOwner {
            schema_version: 1,
            authority_kind: Scope::StoppedConfirmed,
            original_owner: original(),
            firewall_revision: 9,
            firewall_source_digest: "d".repeat(64),
            original_startup_receipt_sha256: "a".repeat(64),
            selected_profile_sha256: "b".repeat(64),
            runtime_sha256: "f".repeat(64),
        })
    }

    #[test]
    fn live_authority_keeps_historical_core_owner_bytes_and_strict_firewall_checks() {
        let owner = original();
        let before = serde_json::to_vec(&owner).unwrap();
        let recorded = OwnerAuthority::Live(owner);
        assert_eq!(serde_json::to_vec(&recorded).unwrap(), before);
        let decoded: OwnerAuthority = serde_json::from_slice(&before).unwrap();
        assert!(!decoded.is_stopped());
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), before);
        decoded.require_firewall(7, &"e".repeat(64)).unwrap();
        assert!(decoded.require_firewall(9, &"d".repeat(64)).is_err());
    }

    #[test]
    fn stopped_audit_binds_confirmed_firewall_without_fabricating_a_current_core_projection() {
        let recorded = audit();
        let original_bytes = serde_json::to_vec(recorded.original()).unwrap();
        recorded.require_firewall(9, &"d".repeat(64)).unwrap();
        recorded.require_runtime(&"f".repeat(64)).unwrap();
        assert!(recorded.require_runtime(&"a".repeat(64)).is_err());
        assert!(
            recorded
                .original()
                .require_firewall(9, &"d".repeat(64))
                .is_err()
        );
        recorded
            .original()
            .require_firewall(7, &"e".repeat(64))
            .unwrap();
        let bytes = serde_json::to_vec(&recorded).unwrap();
        let decoded: OwnerAuthority = serde_json::from_slice(&bytes).unwrap();
        assert!(decoded.is_stopped());
        assert_eq!(
            serde_json::to_vec(decoded.original()).unwrap(),
            original_bytes
        );
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    }

    #[test]
    fn stopped_audit_rejects_ambiguous_scope_unknown_fields_and_incomplete_original_identity() {
        for defect in [
            "scope", "version", "field", "source", "startup", "profile", "runtime", "original",
        ] {
            let mut value = serde_json::to_value(audit()).unwrap();
            match defect {
                "scope" => value["authorityKind"] = json!("LIVE"),
                "version" => value["schemaVersion"] = json!(2),
                "field" => value["ownerGrant"] = json!(true),
                "source" => value["firewallSourceDigest"] = json!("bad"),
                "startup" => value["originalStartupReceiptSha256"] = json!("bad"),
                "profile" => value["selectedProfileSha256"] = json!("bad"),
                "runtime" => value["runtimeSha256"] = json!("bad"),
                "original" => value["originalOwner"]
                    .as_object_mut()
                    .unwrap()
                    .remove("firewall")
                    .map(|_| ())
                    .unwrap(),
                _ => unreachable!(),
            }
            let rejected = serde_json::from_value::<OwnerAuthority>(value)
                .map_or(true, |owner| owner.require_complete().is_err());
            assert!(rejected, "{defect}");
        }
    }

    fn proposal(owner: OwnerAuthority, version: u8, kind: Option<Kind>) -> Record {
        let state = if kind.is_some() {
            State::Observing
        } else {
            State::Prepared
        };
        let directory = Directory {
            device: 7,
            inode: 19,
        };
        let reference = Reference {
            file: MarkerIdentity {
                device: 7,
                inode: 19,
                sha256: "d".repeat(64),
            },
            firewall: directory.clone(),
            history: directory.clone(),
            parent: directory,
        };
        Record {
            forward_command:None,inverse_command:None,confirmation_command:None,cancellation_command:None,
            origin:None,
            backend: Backend::Imported,
            schema_version: version,
            kind,
            expiry:None,
            id: uuid::Uuid::new_v4(),
            uid: 77,
            request_id: "stored-authority-shape".into(),
            owner_sha256: "a".repeat(64),
            input_sha256: "b".repeat(64),
            initialization_receipt_sha256: "c".repeat(64),
            state,
            deadline_ms: 60_000,
            base: Head::Initialization {
                receipt_sha256: "c".repeat(64),
            },
            plan: reference,
            forward_intent: false,
            inverse_intent: false,
            confirmed_decision: false,
            forward: None,
            inverse: None,
            forward_dispatch: None,
            inverse_dispatch: None,
            negative: None,
            forward_capture_intent: false,
            inverse_capture_intent: false,
            negative_capture_intent: false,
            settlement_intent: false,
            authorization: Some(Authorization {
                token: "f".repeat(32),
                delegation: Binding {
                    operation_id: uuid::Uuid::from_u128(12),
                    plan_sha256: "b".repeat(64),
                    lease_sha256: "a".repeat(64),
                },
                owner,
                network_cohort_sha256: "e".repeat(64),
                source_stamp: "d".repeat(64),
                runtime_sha256: "f".repeat(64),
            }),
        }
    }

    #[test]
    fn stopped_audit_requires_new_record_version_and_never_turns_observations_into_dispatch() {
        let live = OwnerAuthority::Live(original());
        proposal(live.clone(), 2, None).validate().unwrap();
        proposal(live.clone(), 3, Some(Kind::SourceObservation))
            .validate()
            .unwrap();
        assert!(proposal(audit(), 2, None).validate().is_err());
        assert!(
            proposal(audit(), 3, Some(Kind::SourceObservation))
                .validate()
                .is_err()
        );
        assert!(proposal(live.clone(), 4, None).validate().is_err());
        proposal(audit(), 4, None).validate().unwrap();
        let mut observed = proposal(audit(), 4, Some(Kind::SourceObservation));
        observed.validate().unwrap();
        observed.forward_intent = true;
        assert!(observed.validate().is_err());
        let mut pending = proposal(live, 2, None);
        pending.forward_dispatch = Some(
            execution::Intent::reserve(&pending.authorization.as_ref().unwrap().owner).unwrap(),
        );
        pending.state = State::Applying;
        pending.forward_intent = true;
        assert!(
            pending.validate().is_err(),
            "old record cannot acquire stopped dispatch by relabeling owner data"
        );
        pending.schema_version = 4;
        pending.validate().unwrap();
    }
}
