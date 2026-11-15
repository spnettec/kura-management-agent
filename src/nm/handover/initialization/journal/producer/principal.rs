//! Remote ownership audit is separate from the Kura peer UID and from fresh
//! Core/NM authority. The packaged agent's actual service UID may be root.
use super::*;
use yofc_management_protocol::imported::Envelope;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct OriginAudit {
    schema_version: u8,
    authority_kind: String,
    service_uid: u32,
    authority_sha256: String,
    original_task_id: uuid::Uuid,
    original_command_sha256: String,
    operation_id: uuid::Uuid,
}
impl OriginAudit {
    pub(in crate::nm) fn command_sha256(&self) -> &str {
        &self.original_command_sha256
    }
    pub(in crate::nm) fn require(&self, uid: u32, request_id: &str, id: uuid::Uuid) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.authority_kind == "REMOTE_ORIGINAL"
                && uid <= i32::MAX as u32
                && uid == self.service_uid
                && hex(&self.authority_sha256, 64)
                && hex(&self.original_command_sha256, 64)
                && !self.original_task_id.is_nil()
                && !self.operation_id.is_nil()
                && id == self.operation_id,
            "CONFLICT: imported remote principal audit"
        );
        let expected = format!(
            "remote-{}",
            durable::hash(&serde_json::to_vec(&[
                "firewall.imported.original.v1",
                &self.authority_sha256,
                &self.original_task_id.to_string(),
                &self.original_command_sha256
            ])?)
        );
        ensure!(
            request_id == expected,
            "CONFLICT: remote principal/request binding"
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct CommandAudit {
    schema_version: u8,
    authority_sha256: String,
    original_task_id: uuid::Uuid,
    task_id: uuid::Uuid,
    command_sha256: String,
    operation: i32,
}
impl CommandAudit {
    pub(in crate::nm) fn require(&self, origin: &OriginAudit, operation: i32) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.authority_sha256 == origin.authority_sha256
                && self.original_task_id == origin.original_task_id
                && !self.task_id.is_nil()
                && hex(&self.command_sha256, 64)
                && self.operation == operation
                && matches!(operation, 41..=44),
            "CONFLICT: original remote action audit"
        );
        Ok(())
    }
    pub(in crate::nm) fn command_sha256(&self) -> &str {
        &self.command_sha256
    }
    pub(super) fn reserved(origin: &OriginAudit, operation: i32) -> Self {
        Self {
            schema_version: 1,
            authority_sha256: origin.authority_sha256.clone(),
            original_task_id: origin.original_task_id,
            task_id: uuid::Uuid::from_u128(u128::MAX),
            command_sha256: "f".repeat(64),
            operation,
        }
    }
}

/// No Deserialize/Clone. Constructed only from the checked encrypted original
/// admission. Its audit is not a runtime, owner lease or native write grant.
pub(crate) struct RemotePrincipal {
    origin: OriginAudit,
    request_id: String,
    input: Value,
    command: Option<CommandAudit>,
}
impl RemotePrincipal {
    pub(crate) fn authenticated(original: &crate::journal::imported::Original) -> Result<Self> {
        let (authority, hash) = original.checked_binding()?;
        let input = Envelope::from_wire(
            original
                .command
                .imported_firewall
                .as_ref()
                .context("CONFLICT")?,
            original.command.operation,
        )?;
        let origin = OriginAudit {
            schema_version: 1,
            authority_kind: "REMOTE_ORIGINAL".into(),
            service_uid: unsafe { libc::geteuid() },
            authority_sha256: authority.into(),
            original_task_id: uuid::Uuid::parse_str(&original.command.command_id)?,
            original_command_sha256: hash.into(),
            operation_id: input
                .request
                .original_operation()
                .context("CONFLICT: remote preparation required")?,
        };
        origin.require(
            origin.service_uid,
            &original.request_id,
            origin.operation_id,
        )?;
        Ok(Self {
            origin,
            request_id: original.request_id.clone(),
            input: input.original_input()?,
            command: None,
        })
    }
    pub(crate) fn for_action(
        prepared: &crate::journal::imported::Original,
        admitted: &crate::journal::imported::Original,
    ) -> Result<Self> {
        let mut principal = Self::authenticated(prepared)?;
        let (authority, hash) = admitted.checked_binding()?;
        let input = Envelope::from_wire(
            admitted
                .command
                .imported_firewall
                .as_ref()
                .context("CONFLICT")?,
            admitted.command.operation,
        )?;
        ensure!(
            matches!(admitted.command.operation, 41..=44)
                && authority == principal.origin.authority_sha256
                && input.request.original_task() == Some(principal.origin.original_task_id),
            "FORBIDDEN: original action admission owner"
        );
        principal.command = Some(CommandAudit {
            schema_version: 1,
            authority_sha256: authority.into(),
            original_task_id: principal.origin.original_task_id,
            task_id: uuid::Uuid::parse_str(&admitted.command.command_id)?,
            command_sha256: hash.into(),
            operation: admitted.command.operation,
        });
        Ok(principal)
    }
    pub(in crate::nm) fn command(&self, operation: i32) -> Result<CommandAudit> {
        let command = self
            .command
            .as_ref()
            .context("FORBIDDEN: original action admission required")?;
        command.require(&self.origin, operation)?;
        Ok(command.clone())
    }
    pub(in crate::nm) fn uid(&self) -> u32 {
        self.origin.service_uid
    }
    pub(in crate::nm) fn request_id(&self) -> &str {
        &self.request_id
    }
    pub(in crate::nm) fn require_input(&self, value: &Value) -> Result<()> {
        self.origin
            .require(self.uid(), self.request_id(), self.origin.operation_id)?;
        ensure!(
            *value == self.input,
            "CONFLICT: remote original input changed"
        );
        Ok(())
    }
    pub(in crate::nm) fn require_action(&self, value: &Value) -> Result<()> {
        self.origin
            .require(self.uid(), self.request_id(), self.origin.operation_id)?;
        ensure!(
            value["originalRequestId"] == self.request_id
                && value["id"] == json!(self.origin.operation_id)
                && value["ownerKey"] == self.input["ownerKey"],
            "FORBIDDEN: remote original action principal"
        );
        Ok(())
    }
    pub(super) fn require_action_dto(
        &self,
        value: &Cancel,
        operation: i32,
    ) -> Result<CommandAudit> {
        self.require_action(&json!({"originalRequestId":value.original_request_id,"id":value.id,"ownerKey":value.owner_key}))?;
        self.command(operation)
    }
    #[cfg(test)]
    pub(in crate::nm::handover::initialization) fn storage_action(&self, operation: i32) -> Self {
        Self {
            origin: self.origin.clone(),
            request_id: self.request_id.clone(),
            input: self.input.clone(),
            command: Some(CommandAudit {
                schema_version: 1,
                authority_sha256: self.origin.authority_sha256.clone(),
                original_task_id: self.origin.original_task_id,
                task_id: uuid::Uuid::new_v4(),
                command_sha256: durable::hash(
                    format!("storage-action-{}", uuid::Uuid::new_v4()).as_bytes(),
                ),
                operation,
            }),
        }
    }
}
pub(super) struct Preparation<'a> {
    pub(super) uid: u32,
    pub(super) request_id: &'a str,
    pub(super) origin: Option<OriginAudit>,
}
impl<'a> Preparation<'a> {
    pub(super) fn local(uid: u32, request_id: &'a str) -> Result<Self> {
        request(uid, request_id)?;
        Ok(Self {
            uid,
            request_id,
            origin: None,
        })
    }
    pub(super) fn remote(principal: &'a RemotePrincipal) -> Result<Self> {
        principal.origin.require(
            principal.uid(),
            principal.request_id(),
            principal.origin.operation_id,
        )?;
        Ok(Self {
            uid: principal.uid(),
            request_id: principal.request_id(),
            origin: Some(principal.origin.clone()),
        })
    }
}

/// Pointer and original lookup shape only. The loaded Record must then prove
/// schema5+OriginAudit for uid0. Local creation continues to use request().
pub(in crate::nm) fn original_request(uid: u32, value: &str) -> Result<()> {
    request_shape(uid, value)?;
    if uid == 0 {
        ensure!(
            value
                .strip_prefix("remote-")
                .is_some_and(|suffix| hex(suffix, 64)),
            "CONFLICT: root service requires remote original identity"
        );
        Ok(())
    } else {
        Ok(())
    }
}

/// Explicit synthetic admission for storage tests only; no registered Core
/// owner, native socket or packaged runtime is constructed by this helper.
#[cfg(test)]
pub(in crate::nm::handover::initialization) async fn storage_principal(
    input: &Value,
    source: bool,
) -> RemotePrincipal {
    use prost::Message;
    use yofc_management_protocol::imported::{Observation, Proposal, Request};
    let mut public = input.clone();
    let key = public
        .as_object_mut()
        .unwrap()
        .remove("ownerKey")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let request = if source {
        Request::SourceObserve {
            observation: serde_json::from_value::<Observation>(public).unwrap(),
        }
    } else {
        Request::Prepare {
            proposal: serde_json::from_value::<Proposal>(public).unwrap(),
        }
    };
    let envelope = Envelope {
        request,
        owner_key: Some(key),
    };
    let command = yofc_management_protocol::v1::ReadCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        operation: envelope.request.operation(),
        idempotency_key: "principal-root-audit-fixture".into(),
        expires_at_unix_ms: i64::MAX,
        imported_firewall: Some(envelope.to_wire().unwrap()),
        ..Default::default()
    };
    let hash = durable::hash(&command.encode_to_vec());
    let path =
        std::env::temp_dir().join(format!("principal-origin-{}.sqlite", uuid::Uuid::new_v4()));
    let db = crate::transport::database(path.to_str().unwrap())
        .await
        .unwrap();
    crate::journal::claim(&db, &command, &hash).await.unwrap();
    crate::journal::imported::bind(&db, &command, &"d".repeat(64), &hash)
        .await
        .unwrap();
    let original = crate::journal::imported::load(&db, &command.command_id, &"d".repeat(64))
        .await
        .unwrap();
    let principal = RemotePrincipal::authenticated(&original).unwrap();
    db.close().await;
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(format!("{}.plan-key", path.display())).unwrap();
    principal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::handover::initialization::tests::producer_cases as fixtures;

    #[tokio::test]
    async fn remote_service_origin_uses_actual_service_uid_and_cannot_downgrade_or_relabel_a_record()
     {
        let (f, snapshot, proof, input) = fixtures::fixture();
        let principal = storage_principal(&input, false).await;
        assert_eq!(principal.uid(), unsafe { libc::geteuid() });
        assert!(
            prepare(
                &f.root,
                &snapshot,
                serde_json::from_value(input.clone()).unwrap(),
                0,
                principal.request_id(),
                &proof
            )
            .is_err()
        );
        assert!(
            prepare(
                &f.root,
                &snapshot,
                serde_json::from_value(input.clone()).unwrap(),
                77,
                principal.request_id(),
                &proof
            )
            .is_err()
        );
        let _guard = crate::system_change::Guard::observe(&f.root).unwrap();
        let receipt = prepare_remote(
            &f.root,
            &snapshot,
            serde_json::from_value(input.clone()).unwrap(),
            &principal,
            &proof,
        )
        .unwrap();
        let record = active(&f.root).unwrap();
        assert_eq!(record.schema_version, 5);
        assert_eq!(record.uid, principal.uid());
        assert!(record.origin.is_some());
        for version in 1..=4 {
            let mut changed = record.clone();
            changed.schema_version = version;
            assert!(changed.validate().is_err());
        }
        let mut changed = record.clone();
        changed.origin = None;
        assert!(changed.validate().is_err());
        changed.schema_version = 2;
        assert!(
            changed.validate().is_err(),
            "remote namespace cannot become a local record"
        );
        let mut changed = record.clone();
        changed.uid ^= 1;
        assert!(changed.validate().is_err());
        for field in ["authority", "hash", "operation", "request"] {
            let mut changed = record.clone();
            let origin = changed.origin.as_mut().unwrap();
            match field {
                "authority" => origin.authority_sha256 = "e".repeat(64),
                "hash" => origin.original_command_sha256 = "f".repeat(64),
                "operation" => origin.operation_id = uuid::Uuid::new_v4(),
                _ => changed.request_id = format!("remote-{}", "0".repeat(64)),
            }
            assert!(changed.validate().is_err(), "{field}");
        }
        let mut altered = input.clone();
        altered["confirmSeconds"] = json!(299);
        assert!(principal.require_input(&altered).is_err());
        let action =
            serde_json::from_value(fixtures::action(&input, &receipt, principal.request_id()))
                .unwrap();
        cancel_remote(&f.root, &principal.storage_action(44), action).unwrap();
        let historical = outcome(
            &f.root,
            principal.uid(),
            serde_json::from_value(fixtures::outcome(&input, principal.request_id())).unwrap(),
        )
        .unwrap();
        assert_eq!(historical["historical"], true);
        assert_eq!(historical["state"], "ROLLED_BACK");
        assert_eq!(
            Snapshot::take(&f.root).unwrap().revision(),
            snapshot.revision()
        );
    }

    #[tokio::test]
    async fn remote_service_local_records_keep_their_serialization_and_reject_remote_origin_or_zero_uid()
     {
        let (f, snapshot, proof, input) = fixtures::fixture();
        let principal = storage_principal(&input, false).await;
        let receipt =
            fixtures::prepare(&f, &snapshot, &proof, &input, "local-serialization-v51").unwrap();
        let _guard = crate::system_change::Guard::observe(&f.root).unwrap();
        let bytes = fs::read(f.root.join("firewall/transaction.json")).unwrap();
        let record = active(&f.root).unwrap();
        assert_eq!(serde_json::to_vec(&record).unwrap(), bytes);
        assert!(
            serde_json::to_value(&record)
                .unwrap()
                .get("origin")
                .is_none()
        );
        let mut changed = record.clone();
        changed.origin = Some(principal.origin.clone());
        assert!(changed.validate().is_err());
        let mut changed = record;
        changed.uid = 0;
        assert!(changed.validate().is_err());
        assert_eq!(receipt["state"], "PREPARED");
    }
}
