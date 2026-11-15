//! Effect-free physical observations. These plans never impersonate Transfer ACKs.
use super::*;

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct ObservationPlan {
    schema_version: u8,
    operation_id: uuid::Uuid,
    initialization_receipt_sha256: String,
    source_receipt_sha256: String,
    revision: u64,
    physical_epoch: epoch::Epoch,
    observed: Value,
}

fn object_table(kind: &str, value: &Value) -> Result<(String, String)> {
    let family = value["family"]
        .as_str()
        .context("UNSUPPORTED: native object has no family provenance")?;
    let table = value[if kind == "table" { "name" } else { "table" }]
        .as_str()
        .context("UNSUPPORTED: native object has no table provenance")?;
    ensure!(
        !family.is_empty() && !table.is_empty(),
        "CONFLICT: empty native object identity"
    );
    Ok((family.into(), table.into()))
}

impl CurrentSource {
    fn protected_objects(&self, snapshot: &Snapshot) -> Result<Vec<Value>> {
        let mut chains: BTreeSet<Chain> = self.selected.keys().cloned().collect();
        for family in ["ip", "ip6"] {
            for name in ["INPUT", "FORWARD", "OUTPUT"] {
                chains.insert(Chain {
                    family: family.into(),
                    table: "filter".into(),
                    name: name.into(),
                });
            }
        }
        let tables: BTreeSet<_> = chains
            .iter()
            .map(|key| (key.family.clone(), key.table.clone()))
            .collect();
        let mut protected = Vec::new();
        let mut receipts = BTreeSet::new();
        for entry in &snapshot.objects {
            let (kind, value) = entry.as_object().unwrap().iter().next().unwrap();
            let table = object_table(kind, value)?;
            let receipt = table.0 == "inet" && self.receipt_tables.contains(&table.1);
            let owned = receipt
                || kind == "table" && tables.contains(&table)
                || kind == "chain"
                    && chains.contains(&Chain {
                        family: table.0.clone(),
                        table: table.1.clone(),
                        name: value["name"]
                            .as_str()
                            .context("CONFLICT: native chain name")?
                            .into(),
                    });
            if owned {
                ensure!(
                    value["handle"].as_u64().is_some_and(|id| id > 0),
                    "UNSUPPORTED: protected declaration has no original kernel handle"
                );
                if receipt && kind == "table" {
                    receipts.insert(table.1);
                }
                protected.push(entry.clone());
            }
        }
        ensure!(
            receipts == self.receipt_tables,
            "CONFLICT: known native receipt table is missing"
        );
        // Receipt tables belong to original acknowledged operations in their entirety.
        for (key, rows) in &snapshot.rules {
            if key.family == "inet" && self.receipt_tables.contains(&key.table) {
                for row in rows {
                    let id = handle(row)?;
                    protected.push(json!({"receiptRule":row,
                        "rawSha256":snapshot.fingerprints.get(&(key.clone(),id)),
                        "rawPayload":snapshot.payloads.get(&(key.clone(),id))}));
                }
            }
        }
        protected.sort_by_key(Value::to_string);
        Ok(protected)
    }

    fn require_owned_native(&self, observed: &Snapshot) -> Result<()> {
        ensure!(
            self.snapshot.generation.is_some() && observed.generation.is_some(),
            "UNSUPPORTED: source observation requires complete generation evidence"
        );
        ensure!(
            self.snapshot.payloads.len() == self.snapshot.fingerprints.len()
                && observed.payloads.len() == observed.fingerprints.len(),
            "UNSUPPORTED: source observation requires complete raw parameter payloads"
        );
        ensure!(
            self.protected_objects(&self.snapshot)? == self.protected_objects(observed)?,
            "CONFLICT: protected native declaration or original receipt changed"
        );
        for (key, handles) in &self.selected {
            let actual = observed.rules.get(key).cloned().unwrap_or_default();
            let expected: BTreeSet<_> = handles.iter().copied().collect();
            let ordered = actual
                .iter()
                .map(handle)
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|id| expected.contains(id))
                .collect::<Vec<_>>();
            ensure!(
                &ordered == handles,
                "CONFLICT: owned native handles disappeared or changed order"
            );
            for id in handles {
                let identity = (key.clone(), *id);
                let before = self.snapshot.rules[key]
                    .iter()
                    .find(|row| row["handle"].as_u64() == Some(*id))
                    .context("CONFLICT: original owned rule missing")?;
                let after = actual
                    .iter()
                    .find(|row| row["handle"].as_u64() == Some(*id))
                    .context("CONFLICT: observed owned rule missing")?;
                ensure!(
                    before == after
                        && self.snapshot.fingerprints.get(&identity)
                            == observed.fingerprints.get(&identity)
                        && raw::same_semantics(
                            &self.snapshot.payloads[&identity],
                            &observed.payloads[&identity]
                        )?,
                    "CONFLICT: owned native rule metadata or complete raw semantics changed"
                );
            }
        }
        let mut checked = self.clone();
        checked.snapshot = observed.clone();
        checked.require_model()
    }

    /// Pure evidence construction,not a live owner grant or a native dispatch.
    pub(in crate::nm) fn observe_source(
        &self,
        operation_id: uuid::Uuid,
        physical_epoch: &epoch::Epoch,
        observed: &Value,
    ) -> Result<ObservationPlan> {
        self.require_epoch(physical_epoch)?;
        ensure!(
            !operation_id.is_nil()
                && self
                    .snapshot
                    .table_absent(&format!("yofc_fwt_{}", operation_id.simple()))
                && self
                    .snapshot
                    .table_absent(&format!("yofc_fwi_{}", operation_id.simple())),
            "CONFLICT: observation cannot reuse a native operation identity"
        );
        let observed = canonical_source(observed)?;
        let snapshot = Snapshot::read(&observed)?;
        self.require_owned_native(&snapshot)?;
        ensure!(
            snapshot.digest()? != self.snapshot.digest()?,
            "CONFLICT: physical source is unchanged;no observation event required"
        );
        Ok(ObservationPlan {
            schema_version: 1,
            operation_id,
            initialization_receipt_sha256: self.anchor.clone(),
            source_receipt_sha256: self.receipt.clone(),
            revision: self.revision,
            physical_epoch: physical_epoch.clone(),
            observed,
        })
    }

    pub(in crate::nm) fn decode_observation(&self, bytes: &[u8]) -> Result<ObservationPlan> {
        let claimed: Value =
            serde_json::from_slice(bytes).context("CONFLICT: source observation encoding")?;
        let id = serde_json::from_value(claimed["operationId"].clone())?;
        let physical_epoch = serde_json::from_value(claimed["physicalEpoch"].clone())?;
        let actual = self.observe_source(id, &physical_epoch, &claimed["observed"])?;
        ensure!(
            claimed == serde_json::to_value(&actual)?,
            "CONFLICT: source observation differs from its original parent"
        );
        Ok(actual)
    }
}

impl ObservationPlan {
    pub(in crate::nm) fn operation(&self) -> uuid::Uuid {
        self.operation_id
    }
    pub(in crate::nm) fn require_native(&self, native: &Value) -> Result<()> {
        ensure!(
            Snapshot::read(&canonical_source(native)?)?.digest()?
                == Snapshot::read(&self.observed)?.digest()?,
            "CONFLICT: observed full native source changed before publication"
        );
        Ok(())
    }
    pub(in crate::nm) fn require_epoch(&self, physical_epoch: &epoch::Epoch) -> Result<()> {
        self.physical_epoch.require(physical_epoch)
    }
    pub(in crate::nm) fn settled_source(&self, parent: &CurrentSource) -> Result<CurrentSource> {
        let actual =
            parent.observe_source(self.operation_id, &self.physical_epoch, &self.observed)?;
        ensure!(
            self == &actual,
            "CONFLICT: source observation parent changed"
        );
        let mut current = parent.clone();
        current.snapshot = Snapshot::read(&self.observed)?;
        current.receipt = digest(
            &json!({"schemaVersion":1,"domain":"nft.imported.current-source.observation.v1",
            "observation":self,"nativeSourceSha256":current.snapshot.digest()?,
            "knownReceiptTables":current.receipt_tables}),
        )?;
        Ok(current)
    }
    pub(in crate::nm) fn parameters(&self) -> Result<Value> {
        Ok(
            json!({"schemaVersion":1,"reviewKind":"nft.imported.source-observation.v1",
            "operationId":self.operation_id,"initializationReceiptSha256":self.initialization_receipt_sha256,
            "sourceReceiptSha256":self.source_receipt_sha256,"revision":self.revision,
            "observedNativeSha256":Snapshot::read(&self.observed)?.digest()?,"physicalEpoch":self.physical_epoch,
            "logicalRevisionChanged":false,"kernelEffect":false,"dispatched":false,"ownerGrant":false}),
        )
    }
}
