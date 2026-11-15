//! Fresh actual authority for ordinary imported proposals. The original owner
//! lease and baseline stay immutable while the current firewall view advances.
use super::*;
use handover::initialization::producer::{self, Snapshot, authority::OwnerAuthority};
use std::collections::BTreeMap;

mod observation;
mod stopped;
mod expiry;

struct Runtime {
    original: handover::Requirements,
    challenge: handover::startup::CurrentRuntimeChallenge,
    witness: handover::startup::CompletionWitness,
}

/// Not deserializable and not constructible by a command payload. Persisted
/// proposal metadata is never accepted as this fresh live authority.
enum RuntimeAuthority {
    Live { owner: Box<roles::Owner>, runtime: Option<Box<Runtime>> },
    Stopped { original: Box<handover::Requirements>, challenge: Box<handover::startup::StoppedRuntimeChallenge> },
}
struct CurrentContext {
    source_stamp: String,
    active: handover::Active,
    original_owner: roles::Owner,
    cohort: String,
    deadline: Instant,
    authority: RuntimeAuthority,
    runtime_hash: String,
}
pub(in crate::nm) struct Verified {
    context: CurrentContext,
}
/// A distinct live capability for effect-free observations,not an update grant.
pub(in crate::nm) struct Observed {
    context: CurrentContext,
    plan: handover::native::lineage::ObservationPlan,
}
impl Verified {
    /// Storage unit tests only: not evidence of a registered/live owner lease.
    #[cfg(test)]
    pub(in crate::nm) fn storage_fixture(
        snapshot: &Snapshot,
        active: handover::Active,
        original_owner: roles::Owner,
        owner: roles::Owner,
        cohort: String,
        deadline: Instant,
    ) -> Result<Self> {
        CurrentContext::current_owner(snapshot, &active, &original_owner, &owner)?;
        Ok(Self { context: CurrentContext {
            source_stamp: snapshot.stamp().into(),
            active,
            original_owner,
            cohort,
            deadline,
            authority: RuntimeAuthority::Live { owner:Box::new(owner), runtime: None },
            runtime_hash: digest(&json!({"syntheticStorageContractOnly":true}))?,
        } })
    }
    pub(in crate::nm) fn require(&self, snapshot: &Snapshot) -> Result<()> {
        self.context.require(snapshot)
    }
    pub(in crate::nm) fn binding(&self) -> &handover::Binding {
        &self.context.active.binding
    }
    pub(in crate::nm) fn recorded_owner(&self, snapshot: &Snapshot) -> Result<OwnerAuthority> {
        self.context.recorded_owner(snapshot)
    }
    pub(in crate::nm) fn cohort(&self) -> &str {
        &self.context.cohort
    }
    pub(in crate::nm) fn runtime_hash(&self) -> &str {
        &self.context.runtime_hash
    }
}
impl Observed {
    #[cfg(test)]
    pub(in crate::nm) fn storage_fixture(snapshot: &Snapshot, proof: Verified,
        plan: handover::native::lineage::ObservationPlan) -> Result<Self> {
        proof.require(snapshot)?;
        snapshot.require_observation(&plan)?;
        Ok(Self { context: proof.context, plan })
    }
    pub(in crate::nm) fn require(&self, snapshot: &Snapshot) -> Result<()> {
        self.context.require(snapshot)?;
        snapshot.require_observation(&self.plan)
    }
    pub(in crate::nm) fn binding(&self) -> &handover::Binding { &self.context.active.binding }
    pub(in crate::nm) fn recorded_owner(&self,snapshot:&Snapshot) -> Result<OwnerAuthority> { self.context.recorded_owner(snapshot) }
    pub(in crate::nm) fn cohort(&self) -> &str { &self.context.cohort }
    pub(in crate::nm) fn runtime_hash(&self) -> &str { &self.context.runtime_hash }
    pub(in crate::nm) fn plan(&self) -> &handover::native::lineage::ObservationPlan { &self.plan }
}
impl CurrentContext {
    fn require(&self, snapshot: &Snapshot) -> Result<()> {
        ensure!(Instant::now() < self.deadline && snapshot.stamp() == self.source_stamp,
            "CONFLICT: imported authority expired or source changed");
        snapshot.require_original(&self.active.binding)?;
        match &self.authority {
            RuntimeAuthority::Live { owner,.. } => owner.require_firewall(snapshot.revision(),snapshot.source()),
            RuntimeAuthority::Stopped { challenge,.. } => {
                self.original_owner.require_complete()?;
                snapshot.require_native_epoch(challenge.epoch())
            }
        }
    }
    fn recorded_owner(&self,snapshot:&Snapshot) -> Result<OwnerAuthority> {
        self.require(snapshot)?;
        match &self.authority {
            RuntimeAuthority::Live { owner,.. } => Ok(OwnerAuthority::Live(owner.as_ref().clone())),
            RuntimeAuthority::Stopped { challenge,.. } => OwnerAuthority::stopped(
                &self.original_owner,snapshot.revision(),snapshot.source(),challenge),
        }
    }
    fn current_owner(
        snapshot: &Snapshot,
        active: &handover::Active,
        original: &roles::Owner,
        owner: &roles::Owner,
    ) -> Result<()> {
        snapshot.require_original(&active.binding)?;
        original.require_complete()?;
        owner.require_original(
            active.binding.operation(),
            active.binding.plan_hash(),
            original.mirror_hash(),
            original.role_configuration(),
        )?;
        owner.require_complete()?;
        owner.require_firewall(snapshot.revision(), snapshot.source())
    }
}

impl Coordinator {
    fn imported_forwarding_state(&self) -> Result<BTreeMap<String, bool>> {
        let mut values = BTreeMap::new();
        for (family, path) in [
            ("ipv4", "/proc/sys/net/ipv4/ip_forward"),
            ("ipv6", "/proc/sys/net/ipv6/conf/all/forwarding"),
        ] {
            let raw = std::fs::read_to_string(path)
                .context("UNSUPPORTED: actual address family forwarding state unavailable")?;
            values.insert(
                family.into(),
                match raw.trim() {
                    "0" => false,
                    "1" => true,
                    _ => anyhow::bail!("CONFLICT: invalid address family forwarding state"),
                },
            );
        }
        Ok(values)
    }
    fn imported_forwarding_ready(&self, snapshot: &Snapshot, inverse: bool) -> Result<()> {
        let (v4, v6) = snapshot.forwarding_families(&self.root, inverse)?;
        let values = self.imported_forwarding_state()?;
        ensure!(
            (!v4 || values["ipv4"]) && (!v6 || values["ipv6"]),
            "FORBIDDEN: requested address family forwarding is not enabled by the system owner"
        );
        Ok(())
    }
    /// Bind the current network content/identity without embedding the manual
    /// firewall journal's pending/confirmed phase into the network component.
    /// NM's established source digest intentionally excludes reapply counters.
    fn imported_network_cohort(
        &self,
        active: &handover::Active,
        deadline: Instant,
    ) -> Result<String> {
        let forwarding = self.imported_forwarding_state()?;
        let nat = self.observed_nat(deadline)?;
        let marker = ownership::marker(&self.root)?;
        let (source, devices) = self.source.capture(deadline)?;
        active
            .baseline
            .validate_current(&self.source.config.interfaces, &devices)?;
        let (again, again_devices) = self.source.capture(deadline)?;
        active
            .baseline
            .validate_current(&self.source.config.interfaces, &again_devices)?;
        ensure!(
            source["sourceDigest"] == again["sourceDigest"]
                && settlement::nat_equal(nat.as_ref(), self.observed_nat(deadline)?.as_ref())
                && marker == ownership::marker(&self.root)?
                && forwarding == self.imported_forwarding_state()?,
            "CONFLICT: imported network cohort changed during observation"
        );
        digest(
            &json!({"schemaVersion":1,"domain":"nm.imported.ordinary.cohort.v1",
            "profiles":source["sourceDigest"],"automaticNat":nat,"natOwnership":marker,
            "familyForwarding":forwarding,"delegation":active.binding,"roles":active.baseline.roles.roles}),
        )
    }
    fn imported_authority(&self, snapshot: &Snapshot, deadline: Instant) -> Result<Verified> {
        let (context, ()) = self.imported_context(snapshot, deadline, |_, native| snapshot.require_native(native))?;
        Ok(Verified { context })
    }
    fn imported_observation(&self, snapshot: &Snapshot, id: uuid::Uuid, deadline: Instant) -> Result<Observed> {
        let (context, plan) = self.imported_context(snapshot, deadline,
            |epoch, native| snapshot.observation_plan(id, epoch, native))?;
        Ok(Observed { context, plan })
    }
    fn imported_context<T>(&self, snapshot: &Snapshot, deadline: Instant,
        validate_native: impl FnOnce(&handover::native::epoch::Epoch, &Value) -> Result<T>,
    ) -> Result<(CurrentContext, T)> {
        if self.handover.current_runtime_is_stopped(&self.startup_systemctl)? {
            return self.imported_stopped_context(snapshot,deadline,validate_native);
        }
        let (active, original_owner) = self
            .handover
            .active_owner()?
            .context("FORBIDDEN: ordinary proposal requires the complete active original owner")?;
        let source = self
            .role_source
            .as_ref()
            .context("UNSUPPORTED: registered actual Core owner observer")?;
        let (original, challenge) = self
            .handover
            .current_runtime_challenge(&self.startup_systemctl)?;
        let witness = self.startup_witness(&original, challenge.completion(), deadline)?;
        let owner = witness.owner.clone();
        CurrentContext::current_owner(snapshot, &active, &original_owner, &owner)?;
        let current_roles = witness.roles.clone();
        ensure!(
            source.raw(deadline)? == current_roles,
            "CONFLICT: actual Core roles differ from current owner cohort"
        );
        let original_cm = active
            .baseline
            .firewall_source
            .as_ref()
            .context("UNSUPPORTED: original stored firewall source")?;
        ensure!(
            source
                .firewall_source(&current_roles, deadline)?
                .parameters()?
                == original_cm.parameters()?,
            "CONFLICT: original stored firewall source changed"
        );
        source.legacy_drain(
            &current_roles,
            active.binding.operation(),
            active.binding.plan_hash(),
            deadline,
        )?;
        let cohort = self.imported_network_cohort(&active, deadline)?;
          let native_epoch = handover::native::epoch::Epoch::capture()?;
          snapshot.require_native_epoch(&native_epoch)?;
        let checked = validate_native(&native_epoch, &self.original_native_source(deadline)?)?;
          native_epoch.require(&handover::native::epoch::Epoch::capture()?)?;
        ensure!(
            source.owner(deadline)? == owner
                && source.raw(deadline)? == current_roles
                && source
                    .firewall_source(&current_roles, deadline)?
                    .parameters()?
                    == original_cm.parameters()?,
            "CONFLICT: actual Core cohort changed during imported review/drain"
        );
        source.owner_still_registered(&owner, deadline)?;
        source.association_still_registered(&witness.association, deadline)?;
        let runtime_hash = digest(
            &json!({"schemaVersion":1,"domain":"nm.imported.current-runtime.v1",
            "currentRuntime":challenge.parameters(),
              "roles":witness.roles,"association":witness.association,"owner":witness.owner,"nativeEpoch":native_epoch}),
        )?;
        Ok((CurrentContext {
            source_stamp: snapshot.stamp().into(),
            active,
            original_owner,
            cohort,
            deadline,
            authority: RuntimeAuthority::Live { owner:Box::new(owner), runtime: Some(Box::new(Runtime {
                original,
                challenge,
                witness,
            })) },
            runtime_hash,
        }, checked))
    }
    /// Called with the system EX guard after all reverse Core calls completed.
    /// Registration checks are local; they do not call back into a Core reader.
    fn recheck_imported_authority(
        &self,
        snapshot: &Snapshot,
        proof: &Verified,
        deadline: Instant,
    ) -> Result<()> {
        self.recheck_imported_context(snapshot, &proof.context, deadline,
            |_, native| snapshot.require_native(native))
    }
    fn recheck_imported_observation(&self, snapshot: &Snapshot, proof: &Observed, deadline: Instant) -> Result<()> {
        proof.require(snapshot)?;
        self.recheck_imported_context(snapshot, &proof.context, deadline, |epoch, native| {
            proof.plan.require_epoch(epoch)?;
            proof.plan.require_native(native)
        })
    }
    fn recheck_imported_context(&self, snapshot: &Snapshot, proof: &CurrentContext, deadline: Instant,
        validate_native: impl FnOnce(&handover::native::epoch::Epoch, &Value) -> Result<()>,
    ) -> Result<()> {
        proof.require(snapshot)?;
        snapshot.require_current(&self.root)?;
        let (active, original_owner) = self
            .handover
            .active_owner()?
            .context("FORBIDDEN: original owner is no longer active")?;
        ensure!(
            active == proof.active && original_owner == proof.original_owner,
            "CONFLICT: immutable original owner changed during imported review"
        );
        if matches!(&proof.authority, RuntimeAuthority::Stopped{..}) {
            return self.recheck_stopped_context(snapshot,proof,deadline,validate_native);
        }
        let RuntimeAuthority::Live { owner,runtime }=&proof.authority else {unreachable!()};
        let source = self
            .role_source
            .as_ref()
            .context("UNSUPPORTED: actual owner observer")?;
        source.owner_still_registered(owner, deadline)?;
        let runtime = runtime
            .as_ref()
            .context("FORBIDDEN: storage-only proof cannot authorize a live proposal")?;
        self.handover.current_runtime_finish(
            &runtime.original,
            &runtime.challenge,
            &runtime.witness,
            &self.startup_systemctl,
        )?;
        source.association_still_registered(&runtime.witness.association, deadline)?;
        ensure!(
            self.imported_network_cohort(&active, deadline)? == proof.cohort,
            "CONFLICT: network cohort changed during imported review"
        );
          let native_epoch = handover::native::epoch::Epoch::capture()?;
          snapshot.require_native_epoch(&native_epoch)?;
            validate_native(&native_epoch, &self.original_native_source(deadline)?)?;
          native_epoch.require(&handover::native::epoch::Epoch::capture()?)?;
        source.owner_still_registered(owner, deadline)?;
        source.association_still_registered(&runtime.witness.association, deadline)
    }
    pub(in crate::nm) fn imported_request(
        &self,
        method: &str,
        value: Value,
        uid: u32,
        request: &str,
        write_grant: bool,
    ) -> Result<Value> {
        self.imported_request_with_remote(method,value,uid,request,write_grant,None)
    }
    pub(in crate::nm) fn imported_remote_request(&self,method:&str,value:Value,
        principal:&producer::principal::RemotePrincipal,write_grant:bool)->Result<Value> {
        self.imported_request_with_remote(method,value,principal.uid(),principal.request_id(),write_grant,Some(principal))
    }
    pub(in crate::nm) fn imported_remote_review(&self,method:&str,value:Value,request:&str)->Result<Value> {
        ensure!(matches!(method,"firewall.kura.imported.review"|"firewall.kura.imported.source.review"),
            "UNSUPPORTED: remote review method");
        self.imported_request_with_remote(method,value,unsafe {libc::geteuid()},request,false,None)
    }
    fn imported_request_with_remote(&self,method:&str,value:Value,uid:u32,request:&str,
        write_grant:bool,remote:Option<&producer::principal::RemotePrincipal>)->Result<Value> {
        if matches!(method,"firewall.kura.imported.source.review"|"firewall.kura.imported.source.observe") {
            return self.imported_source_request(method,value,uid,request,write_grant,remote);
        }
        ensure!(
            matches!(
                method,
                "firewall.kura.imported.review"
                    | "firewall.kura.imported.prepare"
                    | "firewall.kura.imported.apply"
                    | "firewall.kura.imported.confirm"
                    | "firewall.kura.imported.rollback"
            ),
            "UNSUPPORTED: imported ordinary method"
        );
        ensure!(
            method.ends_with(".review") || write_grant,
            "FORBIDDEN: imported preparation grant disabled"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let review = if method.ends_with(".review") {
            Some(
                serde_json::from_value::<producer::Review>(value.clone())
                    .context("INVALID_ARGUMENT: imported review")?,
            )
        } else {
            None
        };
        let action = if matches!(
            method,
            "firewall.kura.imported.apply"
                | "firewall.kura.imported.confirm"
                | "firewall.kura.imported.rollback"
        ) {
            if let Some(principal)=remote {principal.require_action(&value)?;}
            Some(
                serde_json::from_value::<producer::Cancel>(value.clone())
                    .context("INVALID_ARGUMENT: imported original action")?,
            )
        } else {
            None
        };
        let change = if review.is_none() && action.is_none() {
            Some(
                serde_json::from_value::<producer::Change>(value)
                    .context("INVALID_ARGUMENT: imported preparation")?,
            )
        } else {
            None
        };
        let snapshot = {
            let _guard = Guard::acquire(&self.root, Subsystem::Firewall)?;
            if let Some(action) = &action {
                let snapshot = Snapshot::pending(&self.root, uid, action)?;
                snapshot.admit_action(&self.root, method)?;
                snapshot
            } else {
                Snapshot::take(&self.root)?
            }
        };
        // Core's three confirmed readers call our shared observation endpoints;
        // no exclusive OS guard may be held across these reverse calls.
        let proof = self.imported_authority(&snapshot, deadline)?;
        let _guard = Guard::acquire(&self.root, Subsystem::Firewall)?;
        self.recheck_imported_authority(&snapshot, &proof, deadline)?;
        if let Some(action) = action {
            let inverse = method.ends_with(".rollback");
            self.imported_forwarding_ready(&snapshot, inverse)?;
            if method.ends_with(".confirm") {
                if let Some(principal)=remote {return producer::execution::confirm_remote(&self.root,&snapshot,&proof,principal,action);}
                return producer::execution::confirm(&self.root, &snapshot, &proof, uid, action);
            }
            if let Some(principal)=remote {
                return producer::execution::execute_remote(&self.root,&snapshot,&proof,
                    producer::execution::RemoteAction {principal,action,inverse},deadline,||self.original_native_source(deadline));
            }
            return producer::execution::execute(
                &self.root,
                &snapshot,
                &proof,
                uid,
                action,
                inverse,
                deadline,
                || self.original_native_source(deadline),
            );
        }
        if let Some(review) = review {
            producer::review(&snapshot, review, &proof)
        } else {
            if let Some(principal)=remote {
                producer::prepare_remote(&self.root,&snapshot,change.unwrap(),principal,&proof)
            } else {producer::prepare(&self.root, &snapshot, change.unwrap(), uid, request, &proof)}
        }
    }
}
