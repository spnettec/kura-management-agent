//! Internal scheduler for the original imported transaction. Source observations
//! and ambiguous sends never become rollback work.
use super::*;
use handover::initialization::producer::expiry::{self, Tick};

impl Coordinator {
    /// True means imported work is still pending and other NM recovery must wait.
    pub(in crate::nm) fn expire_imported(&self) -> Result<bool> {
        let work = {
            let _guard = Guard::observe(&self.root)?;
            match expiry::poll(&self.root)? {
                Tick::Idle => return Ok(false),
                Tick::Pending => return Ok(true),
                Tick::Cancel(work) => {
                    expiry::cancel(&self.root, &work)?;
                    return Ok(false);
                }
                Tick::Rollback(work) => work,
            }
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        // No EX across reverse Core readers on a running unit. The stopped mode
        // is selected explicitly from actual unit state,not from a failed call.
        let proof = self.imported_authority(work.snapshot(), deadline)?;
        let _guard = Guard::acquire(&self.root, Subsystem::Firewall)?;
        self.recheck_imported_authority(work.snapshot(), &proof, deadline)?;
        self.imported_forwarding_ready(work.snapshot(), true)?;
        producer::execution::expire(&self.root, work.snapshot(), &proof, &work, deadline, || {
            self.original_native_source(deadline)
        })?;
        Ok(false)
    }
}
