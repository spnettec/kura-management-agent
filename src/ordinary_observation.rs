//! Shared read-only ordinary-JVM observation contract. Historical receipts
//! may use schema 1; every new live observation requires provider schema 2.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ComponentState {
    pub(crate) pid: String,
    pub(crate) registered: bool,
}

#[cfg(test)]
mod level_tests {
    use super::*;

    fn fixture() -> (Spec, Report) {
        let spec = Spec {
            id: "handoff-11111111-1111-4111-8111-111111111111".into(),
            profile_id: "profile-22222222-2222-4222-8222-222222222222".into(),
            nonce: "a".repeat(64),
            snapshot_sha256: "b".repeat(64),
            component_pids: vec!["business".into()],
            check_ids: vec!["business.check".into()],
        };
        let report = serde_json::from_value(json!({
            "schema":2,"handoffId":spec.id,"profileId":spec.profile_id,
            "nonce":spec.nonce,"approvedSnapshotSha256":spec.snapshot_sha256,
            "observerInstanceId":"33333333-3333-4333-8333-333333333333",
            "processId":234,"frameworkStartLevel":6,"ordinaryLoad":true,"ready":true,
            "components":[{"pid":"business","registered":true}],
            "providers":[{"id":"business.check","available":true,"unique":true}],
            "checks":[{"id":"business.check","passed":true}]
        }))
        .unwrap();
        (spec, report)
    }

    #[test]
    fn ordinary_level_six_preserves_selected_provider_and_identity_validation() {
        let (spec, report) = fixture();
        assert!(spec.validate(&report, 234).is_ok());
        let mut forged = report.clone();
        forged.providers[0].available = false;
        forged.providers[0].unique = false;
        assert!(spec.validate(&forged, 234).is_err());
        let mut wrong_pid = report.clone();
        wrong_pid.process_id = 235;
        assert!(spec.validate(&wrong_pid, 234).is_err());
    }

    #[test]
    fn below_minimum_or_inconsistent_readiness_never_becomes_ready() {
        let (spec, mut report) = fixture();
        report.framework_start_level = 4;
        assert!(spec.validate(&report, 234).is_err());
        report.ready = false;
        report.checks[0].passed = false;
        assert!(spec.validate(&report, 234).is_ok());
        report.framework_start_level = 6;
        assert!(spec.validate(&report, 234).is_err());
        report.framework_start_level = u32::MAX;
        report.ready = true;
        report.checks[0].passed = true;
        assert!(spec.validate(&report, 234).is_err());
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CheckState {
    pub(crate) id: String,
    pub(crate) passed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderState {
    pub(crate) id: String,
    pub(crate) available: bool,
    pub(crate) unique: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Report {
    pub(crate) schema: u32,
    pub(crate) handoff_id: String,
    pub(crate) profile_id: String,
    pub(crate) nonce: String,
    approved_snapshot_sha256: String,
    pub(crate) observer_instance_id: String,
    pub(crate) process_id: u32,
    pub(crate) framework_start_level: u32,
    pub(crate) ordinary_load: bool,
    pub(crate) ready: bool,
    pub(crate) components: Vec<ComponentState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) providers: Vec<ProviderState>,
    pub(crate) checks: Vec<CheckState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Spec {
    pub id: String,
    pub profile_id: String,
    pub nonce: String,
    pub snapshot_sha256: String,
    pub component_pids: Vec<String>,
    pub check_ids: Vec<String>,
}
impl Spec {
    pub fn parameters(&self) -> Value {
        json!({"handoffId":self.id,"profileId":self.profile_id,"nonce":self.nonce,"snapshotSha256":self.snapshot_sha256,"componentPids":self.component_pids,"checkIds":self.check_ids})
    }
    pub fn validate(&self, r: &Report, pid: u32) -> Result<()> {
        let providers_ready = match r.schema {
            1 => {
                ensure!(
                    r.providers.is_empty(),
                    "CONFLICT: historical ordinary provider shape"
                );
                true
            }
            2 => {
                ensure!(
                    r.providers.iter().map(|p| p.id.clone()).collect::<Vec<_>>() == self.check_ids
                        && r.providers.iter().all(|p| !p.unique || p.available)
                        && r.checks
                            .iter()
                            .zip(&r.providers)
                            .all(|(check, provider)| !check.passed
                                || (provider.available && provider.unique)),
                    "CONFLICT: ordinary provider shape"
                );
                r.providers.iter().all(|p| p.available)
            }
            _ => anyhow::bail!("CONFLICT: ordinary observation schema"),
        };
        ensure!(
            matches!(r.schema, 1 | 2)
                && r.handoff_id == self.id
                && r.profile_id == self.profile_id
                && r.nonce == self.nonce
                && r.approved_snapshot_sha256 == self.snapshot_sha256
                && r.process_id == pid
                && r.ordinary_load
                && uuid::Uuid::parse_str(&r.observer_instance_id).is_ok()
                && r.components
                    .iter()
                    .map(|s| s.pid.clone())
                    .collect::<Vec<_>>()
                    == self.component_pids
                && r.checks.iter().map(|s| s.id.clone()).collect::<Vec<_>>() == self.check_ids
                && r.ready
                    == (r.framework_start_level >= 5
                        && r.framework_start_level <= i32::MAX as u32
                        && r.components.iter().all(|s| s.registered)
                        && providers_ready)
                && (r.ready || r.checks.iter().all(|s| !s.passed)),
            "CONFLICT: ordinary observation identity or shape"
        );
        Ok(())
    }
}
