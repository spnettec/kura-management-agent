//! Original managed-renewal journal. Historical results never use the live pointer.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Lineage {
    operation_id: String,
    request_sha256: String,
    previous_candidate_id: String,
    previous_receipt_sha256: String,
}

/// Public references only. Center confirmation is supplied by the authenticated
/// local operator; it is not a signed assertion or a claim of TLS readiness.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RenewInput {
    pub operation_id: String,
    pub expected_revision: String,
    previous_receipt_sha256: String,
    request_id: String,
    expected_stage_sha256: String,
    center_operation_id: String,
    center_previous_certificate_sha256: String,
    center_certificate_sha256: String,
    center_previous_binding_generation: u64,
    center_binding_generation: u64,
    operator: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Request {
    schema: String,
    input: RenewInput,
    previous_candidate_id: String,
    previous_request_id: String,
    previous_stage_sha256: String,
    previous_certificate_sha256: String,
    previous_binding_generation: u64,
    endpoint: String,
    gateway_id: String,
    previous_decision_sha256: String,
    next_decision_sha256: String,
    actor: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OutcomeState {
    Applied,
    Rejected,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Outcome {
    schema: String,
    operation_id: String,
    request_sha256: String,
    state: OutcomeState,
    rejection_code: Option<String>,
    candidate_id: Option<String>,
    receipt_sha256: Option<String>,
    accepted_at_unix_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RefusedRequest {
    schema: String,
    input: RenewInput,
    actor: String,
    refused_at_unix_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RefusedResult {
    schema: String,
    operation_id: String,
    request_sha256: String,
    state: String,
    rejection_code: String,
}

pub(super) fn validate_receipt(r: &Receipt) -> Result<()> {
    ensure!(
        r.request_id == r.material.request_id,
        "CONFLICT: managed identity record"
    );
    match &r.renewal {
        None => ensure!(
            r.schema == "yofc.agent.enrollment.v1" && r.binding_generation == 1,
            "CONFLICT: managed identity record"
        ),
        Some(lineage) => {
            ensure!(
                r.schema == "yofc.agent.enrollment.v2"
                    && r.binding_generation > 1
                    && r.binding_generation <= i64::MAX as u64,
                "CONFLICT: managed identity record"
            );
            uuid(&lineage.operation_id)?;
            uuid(&lineage.previous_candidate_id)?;
            digest(&lineage.request_sha256)?;
            digest(&lineage.previous_receipt_sha256)?;
        }
    }
    Ok(())
}

impl Store {
    fn read_refused_renewal(&self, id: &str) -> Result<Option<Value>> {
        uuid(id)?;
        let path = self.renewal_operations().join(id);
        directory(&path, unsafe { libc::geteuid() })?;
        let bytes = own(&path.join("request.json"), 32768)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        if value["schema"] != "yofc.agent.identity-renewal.refused-request.v1" {
            return Ok(None);
        }
        exact(&path, &["request.json", "request-complete", "result.json"])?;
        let request: RefusedRequest = serde_json::from_slice(&bytes)?;
        request.input.validate()?;
        ensure!(
            request.input.operation_id == id
                && request.refused_at_unix_ms > 0
                && !request.actor.is_empty()
                && request.actor.len() <= 160
                && !request.actor.chars().any(char::is_control),
            "CONFLICT: original refusal request"
        );
        let hash = crate::durable::hash(&bytes);
        ensure!(
            own(&path.join("request-complete"), 65)? == format!("{hash}\n").as_bytes(),
            "CONFLICT: original refusal request"
        );
        let result: RefusedResult =
            serde_json::from_slice(&own(&path.join("result.json"), 16384)?)?;
        ensure!(
            result.schema == "yofc.agent.identity-renewal.refused-result.v1"
                && result.operation_id == id
                && result.request_sha256 == hash
                && result.state == "REJECTED"
                && result.rejection_code == "CONFLICT",
            "CONFLICT: original refusal result"
        );
        let input = request.input;
        Ok(Some(
            json!({"operationId":id,"state":"REJECTED","rejectionCode":"CONFLICT",
            "rejectionSource":"ADMISSION","previousReceiptSha256":input.previous_receipt_sha256,
            "requestId":input.request_id,"stageSha256":input.expected_stage_sha256,
            "centerOperationId":input.center_operation_id,
            "previousCertificateSha256":input.center_previous_certificate_sha256,
            "certificateSha256":input.center_certificate_sha256,
            "previousBindingGeneration":input.center_previous_binding_generation,
            "bindingGeneration":null,"receiptSha256":null,"acceptedAtUnixMs":null,
            "remoteEnabledAtCommit":null,"operator":input.operator,"actor":request.actor}),
        ))
    }

    // No credential callback ran. Persist only the original public refusal;
    // never manufacture old identity proof from the current pointer.
    fn record_refused_renewal(&self, input: &RenewInput, actor: String) -> Result<()> {
        input.validate()?;
        ensure!(
            !actor.is_empty() && actor.len() <= 160 && !actor.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        ensure!(
            !self.renewal_blocked()?,
            "CONFLICT: unsettled original history"
        );
        crate::durable::directory(&self.renewal_operations())?;
        ensure!(
            fs::read_dir(self.renewal_operations())?.count() < 64,
            "RESOURCE_EXHAUSTED"
        );
        let path = self.renewal_operations().join(&input.operation_id);
        ensure!(
            !present(&path)?,
            "CONFLICT: original operation already exists"
        );
        fs::create_dir(&path)?;
        crate::durable::directory(&path)?;
        crate::durable::sync_directory(&self.renewal_operations())?;
        let request = RefusedRequest {
            schema: "yofc.agent.identity-renewal.refused-request.v1".into(),
            input: input.clone(),
            actor,
            refused_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
        };
        let bytes = serde_json::to_vec(&request)?;
        let hash = crate::durable::hash(&bytes);
        crate::durable::publish_new(
            &path.join("request.json"),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        crate::durable::publish_new(
            &path.join("request-complete"),
            format!("{hash}\n").as_bytes(),
            crate::durable::FileMetadata::private(),
        )?;
        let result = RefusedResult {
            schema: "yofc.agent.identity-renewal.refused-result.v1".into(),
            operation_id: input.operation_id.clone(),
            request_sha256: hash,
            state: "REJECTED".into(),
            rejection_code: "CONFLICT".into(),
        };
        crate::durable::publish_new(
            &path.join("result.json"),
            &serde_json::to_vec(&result)?,
            crate::durable::FileMetadata::private(),
        )
    }
    fn renewal_operations(&self) -> PathBuf {
        self.base().join("renewals")
    }
    fn renewal_pending(&self) -> PathBuf {
        self.base().join("renewal-pending.json")
    }

    fn historical_receipt(&self, id: &str, expected: &str) -> Result<Receipt> {
        uuid(id)?;
        digest(expected)?;
        let path = self.base().join("candidates").join(id);
        directory(&path, unsafe { libc::geteuid() })?;
        let bytes = own(&path.join("receipt.json"), 16384)?;
        ensure!(
            crate::durable::hash(&bytes) == expected
                && own(&path.join("identity-complete"), 65)? == format!("{expected}\n").as_bytes()
                && own(&path.join("completed-intent.json"), 16384)? == bytes,
            "CONFLICT: original identity receipt"
        );
        let record: Receipt = serde_json::from_slice(&bytes)?;
        validate_receipt(&record)?;
        ensure!(
            record.candidate_id == id,
            "CONFLICT: original identity receipt"
        );
        Ok(record)
    }

    fn renewal_request(&self, id: &str) -> Result<(Request, Vec<u8>)> {
        uuid(id)?;
        let path = self.renewal_operations().join(id);
        directory(&path, unsafe { libc::geteuid() })?;
        let bytes = own(&path.join("request.json"), 32768)?;
        ensure!(
            own(&path.join("request-complete"), 65)?
                == format!("{}\n", crate::durable::hash(&bytes)).as_bytes(),
            "CONFLICT: original renewal request"
        );
        let request: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            request.schema == "yofc.agent.identity-renewal.request.v1"
                && request.input.operation_id == id,
            "CONFLICT: original renewal request"
        );
        request.input.validate()?;
        uuid(&request.previous_candidate_id)?;
        uuid(&request.previous_request_id)?;
        digest(&request.previous_stage_sha256)?;
        digest(&request.previous_certificate_sha256)?;
        digest(&request.previous_decision_sha256)?;
        digest(&request.next_decision_sha256)?;
        gateway(&request.gateway_id)?;
        endpoint(&request.endpoint)?;
        ensure!(
            request.previous_binding_generation > 0
                && request.previous_binding_generation < i64::MAX as u64,
            "CONFLICT: original renewal generation"
        );
        let names = if present(&path.join("result.json"))? {
            vec!["request.json", "request-complete", "result.json"]
        } else {
            vec!["request.json", "request-complete"]
        };
        exact(&path, &names)?;
        Ok((request, bytes))
    }

    fn renewal_result(&self, id: &str) -> Result<(Request, Outcome)> {
        let (request, bytes) = self.renewal_request(id)?;
        let result: Outcome = serde_json::from_slice(&own(
            &self.renewal_operations().join(id).join("result.json"),
            16384,
        )?)?;
        ensure!(
            result.schema == "yofc.agent.identity-renewal.result.v1"
                && result.operation_id == id
                && result.request_sha256 == crate::durable::hash(&bytes),
            "CONFLICT: original renewal result"
        );
        if result.state == OutcomeState::Rejected {
            ensure!(
                matches!(
                    result.rejection_code.as_deref(),
                    Some("INVALID_ARGUMENT" | "FORBIDDEN" | "CONFLICT")
                ) && result.candidate_id.is_none()
                    && result.receipt_sha256.is_none()
                    && result.accepted_at_unix_ms.is_none(),
                "CONFLICT: rejected renewal result"
            );
        } else {
            let record = self.historical_receipt(
                result.candidate_id.as_deref().unwrap_or(""),
                result.receipt_sha256.as_deref().unwrap_or(""),
            )?;
            let previous = self.historical_receipt(
                &request.previous_candidate_id,
                &request.input.previous_receipt_sha256,
            )?;
            let lineage = record
                .renewal
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("CONFLICT: renewal lineage"))?;
            ensure!(
                result.rejection_code.is_none()
                    && result.accepted_at_unix_ms == Some(record.accepted_at_unix_ms)
                    && lineage.operation_id == id
                    && lineage.request_sha256 == result.request_sha256
                    && lineage.previous_candidate_id == request.previous_candidate_id
                    && lineage.previous_receipt_sha256 == request.input.previous_receipt_sha256
                    && previous.request_id == request.previous_request_id
                    && previous.stage_sha256 == request.previous_stage_sha256
                    && previous.material.client_certificate_sha256
                        == request.previous_certificate_sha256
                    && previous.binding_generation == request.previous_binding_generation
                    && previous.material.endpoint == request.endpoint
                    && previous.material.gateway_id == request.gateway_id
                    && record.binding_generation == request.previous_binding_generation + 1
                    && record.binding_generation == request.input.center_binding_generation
                    && request.input.center_previous_binding_generation
                        == previous.binding_generation
                    && request.input.center_previous_certificate_sha256
                        == previous.material.client_certificate_sha256
                    && record.request_id == request.input.request_id
                    && record.stage_sha256 == request.input.expected_stage_sha256
                    && record.material.client_certificate_sha256
                        == request.input.center_certificate_sha256
                    && record.material.endpoint == request.endpoint
                    && record.material.gateway_id == request.gateway_id,
                "CONFLICT: original renewal result does not bind the original identity"
            );
        }
        Ok((request, result))
    }

    pub(super) fn renewal_blocked(&self) -> Result<bool> {
        if present(&self.renewal_pending())? {
            return Ok(true);
        }
        let operations = self.renewal_operations();
        if !present(&operations)? {
            return Ok(false);
        }
        directory(&operations, unsafe { libc::geteuid() })?;
        for entry in fs::read_dir(operations)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str() else {
                return Ok(true);
            };
            let settled = match self.read_refused_renewal(id) {
                Ok(Some(_)) => true,
                Ok(None) => self.renewal_result(id).is_ok(),
                Err(_) => false,
            };
            if !settled {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Original public proof only. Never inspect current pointer or infer a result.
    pub(super) fn read_renewal(&self, id: &str) -> Result<Value> {
        uuid(id)?;
        match self.read_refused_renewal(id) {
            Ok(Some(value)) => return Ok(value),
            Err(_) => return Ok(json!({"operationId":id,"state":"UNKNOWN"})),
            Ok(None) => {}
        }
        let Ok((request, result)) = self.renewal_result(id) else {
            return Ok(json!({"operationId":id,"state":"UNKNOWN"}));
        };
        Ok(
            json!({"operationId":id,"state":result.state,"rejectionCode":result.rejection_code,
            "previousReceiptSha256":request.input.previous_receipt_sha256,
            "requestId":request.input.request_id,"stageSha256":request.input.expected_stage_sha256,
            "centerOperationId":request.input.center_operation_id,
            "previousCertificateSha256":request.previous_certificate_sha256,
            "certificateSha256":request.input.center_certificate_sha256,
            "previousBindingGeneration":request.previous_binding_generation,
            "bindingGeneration":if result.state==OutcomeState::Applied {Some(request.previous_binding_generation+1)} else {None},
            "receiptSha256":result.receipt_sha256,"acceptedAtUnixMs":result.accepted_at_unix_ms,
            "remoteEnabledAtCommit":false,"operator":request.input.operator,"actor":request.actor}),
        )
    }

    fn finish_rejected(&self, request: &Request, bytes: &[u8], code: &str) -> Result<bool> {
        ensure!(
            crate::durable::hash(&own(&self.pointer(), 16384)?)
                == request.input.previous_receipt_sha256
                && crate::durable::hash(&own(&self.root.join("remote-management.json"), 4096)?)
                    == request.previous_decision_sha256
                && own(&self.renewal_pending(), 32768)? == bytes,
            "CONFLICT: renewal publication is uncertain"
        );
        crate::durable::remove(&self.renewal_pending())?;
        self.publish_renewal_result(
            request,
            bytes,
            OutcomeState::Rejected,
            Some(code.into()),
            None,
        )?;
        Ok(false)
    }

    fn publish_renewal_result(
        &self,
        request: &Request,
        bytes: &[u8],
        state: OutcomeState,
        rejection_code: Option<String>,
        candidate: Option<&Candidate>,
    ) -> Result<()> {
        let receipt = candidate
            .map(|c| serde_json::to_vec(&c.receipt))
            .transpose()?;
        let result = Outcome {
            schema: "yofc.agent.identity-renewal.result.v1".into(),
            operation_id: request.input.operation_id.clone(),
            request_sha256: crate::durable::hash(bytes),
            state,
            rejection_code,
            candidate_id: candidate.map(|c| c.receipt.candidate_id.clone()),
            receipt_sha256: receipt.as_deref().map(crate::durable::hash),
            accepted_at_unix_ms: candidate.map(|c| c.receipt.accepted_at_unix_ms),
        };
        crate::durable::publish_new(
            &self
                .renewal_operations()
                .join(&request.input.operation_id)
                .join("result.json"),
            &serde_json::to_vec(&result)?,
            crate::durable::FileMetadata::private(),
        )
    }

    fn renew_with_hook(
        &self,
        input: &RenewInput,
        actor: String,
        decision: &[u8],
        mut checkpoint: impl FnMut(&str) -> Result<()>,
    ) -> Result<bool> {
        input.validate()?;
        ensure!(
            !present(&self.pending())? && !self.renewal_blocked()?,
            "CONFLICT: unsettled identity history"
        );
        let previous = self
            .record()?
            .ok_or_else(|| anyhow::anyhow!("CONFLICT: no managed identity"))?;
        // Key/material and original acceptance must still be intact. Expiration
        // does not erase a historical identity; replacement material is checked now.
        self.load("renewal-admission-validation")?
            .ok_or_else(|| anyhow::anyhow!("CONFLICT"))?;
        let old_bytes = own(&self.pointer(), 16384)?;
        ensure!(
            crate::durable::hash(&old_bytes) == input.previous_receipt_sha256,
            "CONFLICT: original identity changed"
        );
        let old_decision = own(&self.root.join("remote-management.json"), 4096)?;
        let old: Value = serde_json::from_slice(&old_decision)?;
        let next: Value = serde_json::from_slice(decision)?;
        ensure!(
            old["enabled"] == false
                && old["version"] == 1
                && old["revision"] == input.expected_revision
                && next["enabled"] == false
                && next["version"] == 1
                && next["revision"].as_str().is_some_and(|s| uuid(s).is_ok())
                && next["revision"] != old["revision"],
            "CONFLICT: remote decision changed"
        );
        ensure!(
            !actor.is_empty() && actor.len() <= 160 && !actor.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        crate::durable::directory(&self.renewal_operations())?;
        ensure!(
            fs::read_dir(self.renewal_operations())?.count() < 64,
            "RESOURCE_EXHAUSTED: retain original renewal history"
        );
        let path = self.renewal_operations().join(&input.operation_id);
        ensure!(
            !present(&path)?,
            "CONFLICT: original operation already exists"
        );
        fs::create_dir(&path)?;
        crate::durable::directory(&path)?;
        crate::durable::sync_directory(&self.renewal_operations())?;
        checkpoint("operation-created")?;
        let request = Request {
            schema: "yofc.agent.identity-renewal.request.v1".into(),
            input: input.clone(),
            previous_candidate_id: previous.candidate_id.clone(),
            previous_request_id: previous.request_id.clone(),
            previous_stage_sha256: previous.stage_sha256.clone(),
            previous_certificate_sha256: previous.material.client_certificate_sha256.clone(),
            previous_binding_generation: previous.binding_generation,
            endpoint: previous.material.endpoint.clone(),
            gateway_id: previous.material.gateway_id.clone(),
            previous_decision_sha256: crate::durable::hash(&old_decision),
            next_decision_sha256: crate::durable::hash(decision),
            actor: actor.clone(),
        };
        let bytes = serde_json::to_vec(&request)?;
        crate::durable::publish_new(
            &path.join("request.json"),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("request")?;
        crate::durable::publish_new(
            &path.join("request-complete"),
            format!("{}\n", crate::durable::hash(&bytes)).as_bytes(),
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("request-complete")?;
        crate::durable::publish_new(
            &self.renewal_pending(),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("reserved")?;
        if previous.binding_generation >= i64::MAX as u64
            || input.center_previous_binding_generation != previous.binding_generation
            || input.center_binding_generation != previous.binding_generation + 1
            || input.center_previous_certificate_sha256
                != previous.material.client_certificate_sha256
            || input.center_certificate_sha256 == previous.material.client_certificate_sha256
            || input.request_id == previous.request_id
        {
            return self.finish_rejected(&request, &bytes, "CONFLICT");
        }
        let bind = BindInput {
            expected_revision: input.expected_revision.clone(),
            request_id: input.request_id.clone(),
            expected_stage_sha256: input.expected_stage_sha256.clone(),
            operator: input.operator.clone(),
        };
        let lineage = Lineage {
            operation_id: input.operation_id.clone(),
            request_sha256: crate::durable::hash(&bytes),
            previous_candidate_id: previous.candidate_id.clone(),
            previous_receipt_sha256: input.previous_receipt_sha256.clone(),
        };
        let candidate = match self.prepare_candidate(
            &bind,
            actor,
            input.center_binding_generation,
            Some(lineage),
        ) {
            Ok(value) => value,
            Err(error) => {
                let code = crate::network::error_code(&error);
                return if matches!(code, "INVALID_ARGUMENT" | "FORBIDDEN" | "CONFLICT") {
                    self.finish_rejected(&request, &bytes, code)
                } else {
                    Err(error)
                };
            }
        };
        if candidate.receipt.material.gateway_id != previous.material.gateway_id
            || candidate.receipt.material.endpoint != previous.material.endpoint
            || candidate.receipt.material.client_certificate_sha256
                != input.center_certificate_sha256
        {
            return self.finish_rejected(&request, &bytes, "CONFLICT");
        }
        let receipt = serde_json::to_vec(&candidate.receipt)?;
        crate::durable::publish_new(
            &candidate.path.join("receipt.json"),
            &receipt,
            crate::durable::FileMetadata::private(),
        )?;
        crate::durable::publish_new(
            &candidate.path.join("identity-complete"),
            format!("{}\n", crate::durable::hash(&receipt)).as_bytes(),
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("candidate")?;
        crate::durable::write(
            &self.pointer(),
            &receipt,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("pointer")?;
        crate::durable::write(
            &self.root.join("remote-management.json"),
            decision,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("decision")?;
        crate::durable::publish_new(
            &candidate.path.join("completed-intent.json"),
            &receipt,
            crate::durable::FileMetadata::private(),
        )?;
        checkpoint("completed-intent")?;
        ensure!(
            own(&self.renewal_pending(), 32768)? == bytes,
            "CONFLICT: renewal intent changed"
        );
        crate::durable::remove(&self.renewal_pending())?;
        checkpoint("pending-removed")?;
        self.publish_renewal_result(
            &request,
            &bytes,
            OutcomeState::Applied,
            None,
            Some(&candidate),
        )?;
        checkpoint("result")?;
        Ok(true)
    }
}

impl RenewInput {
    fn validate(&self) -> Result<()> {
        for value in [
            &self.operation_id,
            &self.expected_revision,
            &self.request_id,
            &self.center_operation_id,
        ] {
            uuid(value)?;
        }
        for value in [
            &self.previous_receipt_sha256,
            &self.expected_stage_sha256,
            &self.center_previous_certificate_sha256,
            &self.center_certificate_sha256,
        ] {
            digest(value)?;
        }
        ensure!(
            !self.operator.is_empty()
                && self.operator.len() <= 128
                && !self.operator.chars().any(char::is_control),
            "INVALID_ARGUMENT"
        );
        ensure!(
            self.center_previous_binding_generation > 0
                && self.center_binding_generation > 0
                && self.center_binding_generation <= i64::MAX as u64,
            "INVALID_ARGUMENT"
        );
        Ok(())
    }
}

pub(super) fn verify_lineage(store: &Store, record: &Receipt) -> Result<()> {
    let mut current = record.clone();
    for _ in 0..16 {
        validate_receipt(&current)?;
        let Some(lineage) = &current.renewal else {
            return Ok(());
        };
        let (request, result) = store.renewal_result(&lineage.operation_id)?;
        let current_hash = crate::durable::hash(&serde_json::to_vec(&current)?);
        ensure!(
            result.state == OutcomeState::Applied
                && result.candidate_id.as_deref() == Some(current.candidate_id.as_str())
                && result.receipt_sha256.as_deref() == Some(current_hash.as_str()),
            "CONFLICT: managed identity lineage"
        );
        current = store.historical_receipt(
            &request.previous_candidate_id,
            &request.input.previous_receipt_sha256,
        )?;
    }
    anyhow::bail!("CONFLICT: managed identity lineage limit")
}

impl Enrollment {
    pub fn renewal_status(
        &self,
        operation: Option<&str>,
        remote: &crate::remote::Remote,
    ) -> Result<Value> {
        if let Some(id) = operation {
            return self.store.read_renewal(id);
        }
        let status = remote.status();
        let fault =
            self.fault() || present(&self.store.pending())? || status["recoveryRequired"] == true;
        let record = self.store.record();
        let mut result = json!({"version":1,"canRenew":self.granted() && !self.legacy && !fault
            && self.current().is_some() && status["enabled"]==false && status["activeRequests"]==0,
            "recoveryRequired":fault || record.is_err(),"legacyIdentity":self.legacy,
            "remoteEnabled":status["enabled"],"activeRequests":status["activeRequests"],
            "revision":status["revision"]});
        if let Ok(Some(record)) = record {
            result["currentReceiptSha256"] =
                json!(crate::durable::hash(&own(&self.store.pointer(), 16384)?));
            result["currentRequestId"] = json!(record.request_id);
            result["clientCertificateSha256"] = json!(record.material.client_certificate_sha256);
            result["clientCertificateNotAfter"] = json!(record.material.not_after);
            result["bindingGeneration"] = json!(record.binding_generation);
            result["gatewayId"] = json!(record.material.gateway_id);
            result["endpoint"] = json!(record.material.endpoint);
        }
        if result["recoveryRequired"] == true {
            result["canRenew"] = json!(false);
        }
        Ok(result)
    }

    pub async fn renew(
        &self,
        input: RenewInput,
        remote: crate::remote::Remote,
        actor: String,
    ) -> Result<Value> {
        input.validate()?;
        ensure!(
            self.granted() && !self.legacy && !self.startup_fault && self.current().is_some(),
            "CONFLICT: managed identity renewal is unavailable"
        );
        let root = self.store.root.clone();
        let guard = tokio::task::spawn_blocking(move || {
            crate::system_change::Guard::acquire(&root, crate::system_change::Subsystem::Identity)
        })
        .await??;
        // An old ambiguous write must keep its original identity/channel. This is
        // the same conservative read set as the console's credential rotation.
        let pending:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE state IN ('QUEUED','RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23,30,34,38,39,45,46,48))")
            .fetch_one(&self.db).await?;
        let owned = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            ensure!(
                !owned.store.renewal_blocked()? && !present(&owned.store.pending())?,
                "CONFLICT: unsettled identity history"
            );
            ensure!(
                !present(&owned.store.renewal_operations().join(&input.operation_id))?,
                "CONFLICT: original operation already exists"
            );
            let refuse = || -> Result<Value> {
                if let Err(error) = owned.store.record_refused_renewal(&input, actor.clone()) {
                    remote.inhibit_binding();
                    return Err(error);
                }
                owned.store.read_renewal(&input.operation_id)
            };
            if pending {
                return refuse();
            }
            let previous = owned
                .store
                .record()?
                .ok_or_else(|| anyhow::anyhow!("CONFLICT: no managed identity"))?;
            if crate::durable::hash(&own(&owned.store.pointer(), 16384)?)
                != input.previous_receipt_sha256
            {
                return refuse();
            }
            let target = (
                previous.material.endpoint,
                previous.material.gateway_id,
                previous.binding_generation,
            );
            let mut entered = false;
            let admission = remote.renew_target(
                &input.expected_revision,
                &target,
                actor.clone(),
                |decision| {
                    entered = true;
                    let applied =
                        owned
                            .store
                            .renew_with_hook(&input, actor.clone(), decision, |_| Ok(()))?;
                    if applied {
                        let config = owned.store.load(&owned.boot_id)?.ok_or_else(|| {
                            anyhow::anyhow!("CONFLICT: committed identity is unavailable")
                        })?;
                        // Publish while renew_target still holds its admission mutex.
                        // A simultaneous explicit enable can only use the new config.
                        owned.config.send_replace(Some(config));
                    }
                    Ok(applied)
                },
            );
            if admission.is_err() {
                if !entered {
                    return refuse();
                }
                anyhow::bail!("UNKNOWN: reconcile the original identity renewal");
            }
            owned.store.read_renewal(&input.operation_id)
        })
        .await?
    }
}

#[cfg(test)]
mod tests;
