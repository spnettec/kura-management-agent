use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Source {
    Applied(crate::controlled_startup::Application),
    Partial(crate::controlled_startup::PartialApplication),
}
impl Source {
    pub(super) fn receipt_sha256(&self) -> &str {
        match self {
            Self::Applied(p) => &p.receipt_sha256,
            Self::Partial(p) => &p.receipt_sha256,
        }
    }
    pub(super) fn backup_sha256(&self) -> &str {
        match self {
            Self::Applied(p) => &p.backup_sha256,
            Self::Partial(p) => &p.backup_sha256,
        }
    }
    pub(super) fn plan_sha256(&self) -> Result<&str> {
        match self {
            Self::Applied(p) => Ok(&p
                .compensation
                .as_ref()
                .context("source intent missing")?
                .plan_sha256),
            Self::Partial(p) => Ok(&p.plan_sha256),
        }
    }
    pub(super) fn status(&self) -> &'static str {
        match self {
            Self::Applied(_) => "CM_APPLIED",
            Self::Partial(_) => "RECOVERY_REQUIRED",
        }
    }
}
impl Inverse {
    pub(super) fn source_proof(&self) -> Result<Source> {
        match (&self.source_application, &self.source_partial) {
            (Some(applied), None) => Ok(Source::Applied(applied.clone())),
            (None, Some(partial)) => Ok(Source::Partial(partial.clone())),
            _ => anyhow::bail!("CONFLICT: ambiguous inverse source evidence"),
        }
    }
}
impl Recovery {
    pub(super) fn source_proof(&self, j: &Journal) -> Result<Source> {
        if j.cm_application.is_some() {
            return Ok(Source::Applied(self.source_application(j)?));
        }
        ensure!(
            j.controlled_issued
                && (j.state == State::RecoveryRequired
                    || j.inverse
                        .as_ref()
                        .is_some_and(|i| i.source_partial.is_some())),
            "CONFLICT: no failed controlled source"
        );
        ensure!(
            self.0
                .inverse_startup
                .as_ref()
                .context("FORBIDDEN: inverse profile disabled")?
                .allows_partial_source()?,
            "FORBIDDEN: partial CM source disabled"
        );
        self.stopped(&j.unit)?;
        self.verify_startup(j)?;
        let proof = self
            .0
            .startup
            .as_ref()
            .context("source profile missing")?
            .partial_application(
                j.controlled_startup
                    .as_ref()
                    .context("source request missing")?,
                &j.id,
                &j.sha256,
                j.target_metadata.context("source owner missing")?,
            )?;
        let (bytes, metadata) =
            durable::read(&self.retained_snapshot_path(j, &j.target)?, LIMIT_BYTES)?;
        ensure!(
            durable::hash(&bytes) == j.sha256 && Some(metadata) == j.target_metadata,
            "CONFLICT: partial source candidate drifted"
        );
        Ok(Source::Partial(proof))
    }
}
