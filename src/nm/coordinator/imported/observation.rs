//! Source observations collect fresh authority separately from strict updates.
use super::*;
use handover::initialization::producer::observation;

impl Coordinator {
    pub(super) fn imported_source_request(
        &self,
        method: &str,
        value: Value,
        uid: u32,
        request: &str,
        write_grant: bool,
        remote:Option<&super::producer::principal::RemotePrincipal>,
    ) -> Result<Value> {
        ensure!(
            matches!(
                method,
                "firewall.kura.imported.source.review" | "firewall.kura.imported.source.observe"
            ),
            "UNSUPPORTED: source observation method"
        );
        let reviewing = method.ends_with(".review");
        ensure!(
            reviewing || write_grant,
            "FORBIDDEN: imported source observation grant disabled"
        );
        let review = if reviewing {
            Some(
                serde_json::from_value::<observation::Review>(value.clone())
                    .context("INVALID_ARGUMENT: source observation review")?,
            )
        } else {
            None
        };
        let change = if reviewing {
            None
        } else {
            Some(
                serde_json::from_value::<observation::Change>(value)
                    .context("INVALID_ARGUMENT: source observation intent")?,
            )
        };
        let id = review
            .as_ref()
            .map(|r| r.operation_id)
            .or_else(|| change.as_ref().map(|c| c.operation_id))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let snapshot = {
            let _guard = Guard::acquire(&self.root, Subsystem::Firewall)?;
            Snapshot::take(&self.root)?
        };
        // No EX across reverse Core/CM/drain readers. Observed cannot be used as Verified.
        let proof = self.imported_observation(&snapshot, id, deadline)?;
        let _guard = Guard::acquire(&self.root, Subsystem::Firewall)?;
        self.recheck_imported_observation(&snapshot, &proof, deadline)?;
        if let Some(input) = review {
            observation::review(&snapshot, input, &proof)
        } else {
            if let Some(principal)=remote {
                observation::prepare_remote(&self.root,&snapshot,change.unwrap(),principal,&proof)
            } else {observation::prepare(&self.root, &snapshot, change.unwrap(), uid, request, &proof)}
        }
    }
}
