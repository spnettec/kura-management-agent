//! Explicit stopped confirmed authority. A failed running/Core sample never
//! calls this path; selection and EX recheck use the actual original unit state.
use super::*;

impl Coordinator {
    pub(super) fn imported_stopped_context<T>(
        &self,
        snapshot: &Snapshot,
        deadline: Instant,
        validate_native: impl FnOnce(&handover::native::epoch::Epoch, &Value) -> Result<T>,
    ) -> Result<(CurrentContext, T)> {
        let (active, original_owner) = self
            .handover
            .active_owner()?
            .context("FORBIDDEN: stopped proposal requires complete active original owner")?;
        snapshot.require_original(&active.binding)?;
        original_owner.require_complete()?;
        let (original, challenge) = self
            .handover
            .stopped_runtime_challenge(&self.startup_systemctl)?;
        let cohort = self.imported_network_cohort(&active, deadline)?;
        let epoch = handover::native::epoch::Epoch::capture()?;
        snapshot.require_native_epoch(&epoch)?;
        challenge.epoch().require(&epoch)?;
        let checked = validate_native(&epoch, &self.original_native_source(deadline)?)?;
        epoch.require(&handover::native::epoch::Epoch::capture()?)?;
        self.handover
            .stopped_runtime_finish(&original, &challenge, &self.startup_systemctl)?;
        let (again, owner) = self
            .handover
            .active_owner()?
            .context("FORBIDDEN: original stopped ownership no longer active")?;
        ensure!(
            again == active && owner == original_owner && Instant::now() < deadline,
            "CONFLICT: original stopped owner changed or observation expired"
        );
        let runtime_hash = challenge.runtime_digest()?;
        let context = CurrentContext {
            source_stamp: snapshot.stamp().into(),
            active,
            original_owner,
            cohort,
            deadline,
            authority: RuntimeAuthority::Stopped {
                original: Box::new(original),
                challenge: Box::new(challenge),
            },
            runtime_hash,
        };
        context.require(snapshot)?;
        Ok((context, checked))
    }

    pub(super) fn recheck_stopped_context(
        &self,
        snapshot: &Snapshot,
        proof: &CurrentContext,
        deadline: Instant,
        validate_native: impl FnOnce(&handover::native::epoch::Epoch, &Value) -> Result<()>,
    ) -> Result<()> {
        proof.require(snapshot)?;
        let RuntimeAuthority::Stopped {
            original,
            challenge,
        } = &proof.authority
        else {
            anyhow::bail!("FORBIDDEN: separate stopped confirmed capability required");
        };
        ensure!(
            proof.runtime_hash == challenge.runtime_digest()?,
            "CONFLICT: stopped runtime audit binding changed"
        );
        self.handover
            .stopped_runtime_finish(original, challenge, &self.startup_systemctl)?;
        ensure!(
            self.imported_network_cohort(&proof.active, deadline)? == proof.cohort,
            "CONFLICT: stopped original network cohort changed during review"
        );
        let epoch = handover::native::epoch::Epoch::capture()?;
        snapshot.require_native_epoch(&epoch)?;
        challenge.epoch().require(&epoch)?;
        validate_native(&epoch, &self.original_native_source(deadline)?)?;
        epoch.require(&handover::native::epoch::Epoch::capture()?)?;
        self.handover
            .stopped_runtime_finish(original, challenge, &self.startup_systemctl)?;
        proof.require(snapshot)
    }
}
