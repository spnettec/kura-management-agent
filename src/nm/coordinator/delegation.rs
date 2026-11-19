//! Original-operation delegation. Fence dispatch is once-only; activation needs
//! actual Core owner proof outside the guard, then fresh backend checks inside it.
use super::*;
use handover::template::Transfer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Prepare {operation_id:String,source_digest:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Original {operation_id:String}
#[derive(Default,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Status {
    #[serde(default)] include_preparation_source:bool,
    #[serde(default)] include_legacy_kernel_source:bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Confirm {operation_id:String,confirmation_token:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct StartupConfirm {operation_id:String,confirmation_token:String,startup_confirmation_token:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct RecoveryReview {operation_id:String,confirmation_token:String,startup_confirmation_token:String,recovery_id:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct RecoveryConfirm {operation_id:String,confirmation_token:String,startup_confirmation_token:String,recovery_id:String,recovery_confirmation_token:String}
struct CapturedSource {
    baseline:handover::Baseline,kernel:Value,native:Option<handover::native::factory::Reviewed>,
}
impl CapturedSource {
    fn source_digest(&self)->&str {self.native.as_ref().map_or(self.baseline.source_digest.as_str(),|source|source.binding())}
    fn bind(mut self,id:uuid::Uuid)->Result<handover::Baseline> {
        if let Some(source)=self.native {let transfer=source.bind(id)?;self.baseline.source_digest=transfer.source_binding()?;self.baseline.native_transfer=Some(transfer);}
        Ok(self.baseline)
    }
}
fn original_automatic_nat(origin:&roles::Origin,roles:&roles::Observation,devices:&[Device])->Result<Option<NatSet>> {
    origin.require(roles)?;
    let expected=roles.roles.adopted_nat(devices)?;
    let expected_pairs=expected.as_ref().map(NatSet::pairs).transpose()?.unwrap_or_default();
    // ConfigurationRoles and NatSet project IPv4. The full two-family writer
    // model remains authenticated above and bound by the separate raw review.
    let ipv4=&origin.families()[0];
    let mut pairs=std::collections::BTreeSet::new();
    for row in ipv4.automatic_nat.iter().filter(|row|row.masquerade) {
        ensure!(pairs.insert(roles::NatPair{lan:row.source_interface.clone(),wan:row.destination_interface.clone()}),"CONFLICT: duplicate original automatic NAT pair");
    }
    ensure!(pairs==expected_pairs,"CONFLICT: original writer model does not cover the complete CM automatic NAT matrix");
    Ok(expected)
}

#[cfg(test)]
mod original_automatic_nat_tests {
    use super::*;

    fn input() -> (roles::Observation, Value, Vec<Device>) {
        let exchange: Value = serde_json::from_str(include_str!("../fixtures/legacy-origin-v32.json")).unwrap();
        let mut projected = exchange["roles"].clone();
        projected["interfaces"][0]["ipv4Status"] = json!("netIPv4StatusDisabled");
        let roles = roles::Observation::new(uuid::Uuid::new_v4(), 41, projected).unwrap();
        let mut model = exchange["origin"].clone();
        model["families"][0]["automaticNat"][0]["masquerade"] = json!(true);
        let devices = ["eth0", "lan0", "wan0"].iter().enumerate().map(|(index, name)| Device {
            interface: (*name).into(), device_path: format!("/device/{index}"), device_type: 1,
            active_connection_path: "/".into(), managed: true, state: 100, active_profile: None,
        }).collect();
        (roles, model, devices)
    }

    #[test]
    fn original_ipv4_nat_accepts_an_inactive_ipv6_family_without_inventing_ipv6_nat() {
        let (roles, model, devices) = input();
        assert_eq!(model["families"][1]["automaticNat"], json!([]));
        let origin = roles::Origin::new(roles.agent_instance, roles.bridge_epoch, &roles, model.clone()).unwrap();
        let nat = original_automatic_nat(&origin, &roles, &devices).unwrap().unwrap();
        assert_eq!(nat.pairs().unwrap(), std::collections::BTreeSet::from([
            roles::NatPair { lan: "lan0".into(), wan: "wan0".into() },
        ]));
        assert_eq!(origin.parameters().unwrap(), model, "the original two-family model is retained for raw review");
    }

    #[test]
    fn original_ipv4_nat_still_rejects_missing_duplicate_reversed_and_extra_pairs() {
        for defect in ["missing", "duplicate", "reversed", "extra"] {
            let (roles, mut model, devices) = input();
            let row = model["families"][0]["automaticNat"][0].clone();
            let rows = model["families"][0]["automaticNat"].as_array_mut().unwrap();
            match defect {
                "missing" => rows.clear(),
                "duplicate" => rows.push(row),
                "reversed" => { rows[0]["sourceInterface"] = json!("wan0"); rows[0]["destinationInterface"] = json!("lan0"); },
                "extra" => { let mut extra = row; extra["sourceInterface"] = json!("eth0"); rows.push(extra); },
                _ => unreachable!(),
            }
            let origin = roles::Origin::new(roles.agent_instance, roles.bridge_epoch, &roles, model).unwrap();
            assert!(original_automatic_nat(&origin, &roles, &devices).err().unwrap().to_string().starts_with("CONFLICT:"), "{defect}");
        }
    }

    #[test]
    fn original_ipv4_nat_disabled_remains_absent_with_both_original_families() {
        let (roles, mut model, devices) = input();
        let mut projected = serde_json::to_value(&roles.roles).unwrap();
        projected["interfaces"][1]["natEnabled"] = json!(false);
        let roles = roles::Observation::new(roles.agent_instance, roles.bridge_epoch, projected).unwrap();
        model["families"][0]["automaticNat"] = json!([]);
        let origin = roles::Origin::new(roles.agent_instance, roles.bridge_epoch, &roles, model).unwrap();
        assert!(original_automatic_nat(&origin, &roles, &devices).unwrap().is_none());
    }
}
impl Coordinator {
    fn original_native_witness(&self,baseline:&handover::Baseline,id:uuid::Uuid,plan:&str,deadline:Instant,initializing:bool)->Result<(Value,Value)> {
        let source=self.role_source.as_ref().context("UNSUPPORTED: original Java source observer")?;
        let model=if let Some(expected)=baseline.native_transfer.as_ref().and_then(|native|native.source_model_sha256.as_ref()) {
            let origin=source.firewall_origin(&baseline.roles,deadline)?.context("CONFLICT: original writer model capability disappeared")?;
            let model=origin.parameters()?;ensure!(&digest(&model)?==expected,"CONFLICT: original writer model changed before native effect");model
        }else{Value::Null};
        source.legacy_drain(&baseline.roles,id,plan,deadline)?;
        let (profile,devices)=self.source.capture(deadline)?;baseline.validate_origin_current(&self.source.config.interfaces,&devices)?;
        ensure!(source.raw(deadline)?==baseline.roles&&Some(source.firewall_source(&baseline.roles,deadline)?)==baseline.firewall_source,"CONFLICT: original CM role/firewall source changed before native effect");
        if initializing {
            let before=transaction::FirewallBinding{revision:0,confirmed_sha256:String::new(),journal_settled:true};
            self.verify_original_backend_pair(baseline,&profile,&devices,&before,deadline)?;
        }else{
            let firewall=self.firewall_binding()?;
            ensure!(digest(&serde_json::to_value(&firewall)?)?==baseline.firewall_digest,"CONFLICT: original firewall source changed before native effect");
            if !model.is_null(){self.verify_original_backend_pair(baseline,&profile,&devices,&firewall,deadline)?;}
        }
        Ok((self.original_native_source(deadline)?,model))
    }
    fn verify_original_backend_pair(&self,baseline:&handover::Baseline,profile:&Value,devices:&[Device],firewall:&transaction::FirewallBinding,deadline:Instant)->Result<()> {
        baseline.validate_origin_current(&self.source.config.interfaces,devices)?;let nat=self.observed_nat(deadline)?;let marker=ownership::marker(&self.root)?;let forwarding=self.ipv4_forwarding()?;
        let observed=digest(&json!({"profiles":profile["sourceDigest"],"automaticNat":nat,"natOwnership":marker,"firewall":firewall,"ipv4Forwarding":forwarding,"kuraRoles":baseline.roles,"delegation":Value::Null}))?;
        let pair=handover::Baseline::bind_pair_source(&observed,baseline.firewall_source.as_ref(),baseline.firewall_fence.as_ref())?;
        let native=baseline.native_transfer.as_ref().context("CONFLICT: original native plan missing")?;
        ensure!(nat.is_none()&&marker.is_null()&&pair==native.source_digest&&native.source_binding()?==baseline.source_digest&&digest(&serde_json::to_value(firewall)?)?==baseline.firewall_digest,
            "CONFLICT: original backend pair source differs");Ok(())
    }
    fn startup_recovery(&self,input:RecoveryConfirm,actor:&str,deadline:Instant,cancel:bool)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let approval=handover::startup::RecoveryApproval{id:handover::template::operation(&input.recovery_id)?,token:input.recovery_confirmation_token};
        let command={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            if cancel{return self.handover.startup_recovery_cancel(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&approval);}
            let status=self.handover.startup_recovery_original(id,&input.confirmation_token,actor,&input.startup_confirmation_token,approval.id)?;
            // Backend availability is fresh admission, never a prerequisite
            // for reading an already issued compensation's own receipts.
            if status["state"]=="PREPARED" {
                let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
                self.verify_delegated_backend(&expected.baseline,deadline)?;
            }
            match self.handover.startup_recovery_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&approval,&self.startup_systemctl)? {
                handover::startup::RecoveryStep::Observed(value)=>return Ok(value),
                handover::startup::RecoveryStep::Dispatch(command)=>command,
            }
        };
        (*command).execute()
    }
    pub(super) fn startup_witness(&self,expected:&handover::Requirements,challenge:&handover::startup::CompletionChallenge,deadline:Instant)->Result<handover::startup::CompletionWitness> {
        let source=self.role_source.as_ref().context("UNSUPPORTED: registered startup/Core source unavailable")?;
        // read is the participating network-writer drain fence, not raw CM.
        // These reverse bridge reads run without our exclusive OS guard.
        let before=source.read(deadline)?;
        let association=source.association(&challenge.spec,deadline)?;
        let owner=source.owner(deadline)?;
        ensure!(source.read(deadline)?==before,"CONFLICT: CM/drain registration changed during startup witnesses");
        let witness=handover::startup::CompletionWitness{roles:before,association,owner};witness.require(expected,challenge)?;Ok(witness)
    }
    fn startup_completion(&self,input:StartupConfirm,actor:&str,deadline:Instant)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let (expected,challenge)={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            match self.handover.startup_completion_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&self.startup_systemctl)? {
                handover::startup::CompletionStep::Observed(value)=>return Ok(value),
                handover::startup::CompletionStep::Challenge(challenge)=>(expected,challenge),
            }
        };
        let witness=self.startup_witness(&expected,&challenge,deadline)?;
        let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
        ensure!(self.handover.requirements(id,&input.confirmation_token,actor)?==expected,"CONFLICT: original parent changed during startup completion");
        let source=self.role_source.as_ref().context("UNSUPPORTED: actual registered startup source")?;
        source.association_still_registered(&witness.association,deadline)?;source.owner_still_registered(&witness.owner,deadline)?;
        self.verify_delegated_backend(&expected.baseline,deadline)?;
        self.require_current_firewall_owner(&witness.owner,&expected.baseline,deadline)?;
        self.handover.startup_completion_finish(&expected,actor,&input.startup_confirmation_token,&challenge,witness,&self.startup_systemctl)
    }
    fn startup_start(&self,input:StartupConfirm,actor:&str,deadline:Instant)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let command={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            match self.handover.startup_start_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&self.startup_systemctl)? {
                handover::startup::StartStep::Observed(value)=>return Ok(value),
                handover::startup::StartStep::Dispatch(command)=>command,
            }
        };
        // Do not hold the OS guard during startup: Kura's original confirmed
        // handler needs shared read callbacks. The persistent parent and start
        // intent still exclude competing managed writers.
        (*command).execute()
    }
    fn startup_publication(&self,input:StartupConfirm,actor:&str,deadline:Instant)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let command={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            match self.handover.startup_publication_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&self.startup_systemctl)? {
                handover::startup::PublicationStep::Observed(value)=>return Ok(value),
                handover::startup::PublicationStep::Dispatch(command)=>command,
            }
        };
        // Kura is stopped. Persistent original fencing excludes other managed
        // writers while bound descriptors publish only the reviewed files.
        (*command).execute()
    }
    fn startup_stop(&self,input:StartupConfirm,actor:&str,deadline:Instant)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let (expected,challenge)={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            match self.handover.startup_stop_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&self.startup_systemctl)? {
                handover::startup::AssociationStep::Observed(value)=>return Ok(value),
                handover::startup::AssociationStep::Challenge(challenge)=>(expected,challenge),
            }
        };
        let source=self.role_source.as_ref().context("UNSUPPORTED: registered startup source unavailable")?;
        let before=source.raw(deadline)?;
        ensure!(before.roles==expected.baseline.roles.roles,"CONFLICT: original CM role projection changed before stop");
        let observed=source.association(&challenge.spec,deadline)?;
        observed.require(&challenge.spec,&challenge.profile_id,challenge.pid,&before)?;
        ensure!(source.raw(deadline)?==before,"CONFLICT: CM source/registration changed during fresh stop association");
        let command={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            ensure!(self.handover.requirements(id,&input.confirmation_token,actor)?==expected,"CONFLICT: original startup parent changed before stop admission");
            source.association_still_registered(&observed,deadline)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            self.handover.startup_stop_arm(&expected,actor,&input.startup_confirmation_token,(observed.clone(),before),&self.startup_systemctl,deadline)?
        };
        // The durable original fence and stop intent exclude every competing
        // managed writer. Release the OS guard during the bounded service job.
        source.association_still_registered(&observed,deadline)
            .context("OUTCOME_UNKNOWN: admitted original stop registration changed;never redispatch")?;
        command.execute()
    }
    fn startup_association(&self,input:StartupConfirm,actor:&str,deadline:Instant)->Result<Value> {
        let id=handover::template::operation(&input.operation_id)?;
        let (expected,challenge)={
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            match self.handover.startup_association_begin(id,&input.confirmation_token,actor,&input.startup_confirmation_token,&self.startup_systemctl)? {
                handover::startup::AssociationStep::Observed(value)=>return Ok(value),
                handover::startup::AssociationStep::Challenge(challenge)=>(expected,challenge),
            }
        };
        // The persistent original fence blocks system writers while pure JVM
        // reads run without the OS guard. No snapshot/health callback is used.
        let source=self.role_source.as_ref().context("UNSUPPORTED: registered startup source unavailable")?;
        let before=source.raw(deadline)?;
        ensure!(before.roles==expected.baseline.roles.roles,"CONFLICT: original CM role projection changed before startup association");
        let observed=source.association(&challenge.spec,deadline)?;
        observed.require(&challenge.spec,&challenge.profile_id,challenge.pid,&before)?;
        ensure!(source.raw(deadline)?==before,"CONFLICT: CM source/registration changed during startup association");
        let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
        ensure!(self.handover.requirements(id,&input.confirmation_token,actor)?==expected,"CONFLICT: original startup parent changed during JVM read");
        source.association_still_registered(&observed,deadline)?;
        self.verify_delegated_backend(&expected.baseline,deadline)?;
        self.handover.startup_association_finish(&expected,actor,&input.startup_confirmation_token,&challenge,(observed,before),&self.startup_systemctl)
    }
    pub(super) fn verify_delegated_backend(&self,baseline:&handover::Baseline,deadline:Instant)->Result<()> {
        if baseline.native_transfer.as_ref().is_some_and(|native|native.source_model_sha256.is_some()) {
            let kernel=self.current_kernel_policy(deadline)?;
            ensure!(kernel["sourceKind"]=="nft.imported.confirmed.v1"&&kernel["originalSourceDigest"]==baseline.source_digest&&kernel["originalFirewallDigest"]==baseline.firewall_digest,
                "CONFLICT: original initialization transition receipt required");
            let (profile,devices)=self.source.capture(deadline)?;let before=transaction::FirewallBinding{revision:0,confirmed_sha256:String::new(),journal_settled:true};
            self.verify_original_backend_pair(baseline,&profile,&devices,&before,deadline)?;
            let (again,devices_again)=self.source.capture(deadline)?;self.verify_original_backend_pair(baseline,&again,&devices_again,&before,deadline)?;
            ensure!(profile==again&&kernel==self.current_kernel_policy(deadline)?,"CONFLICT: initialized backend changed during observation");return Ok(());
        }
        let forwarding=self.ipv4_forwarding()?;let nat=self.observed_nat(deadline)?;
        let marker=ownership::marker(&self.root)?;let firewall=self.firewall_binding()?;
        let (source,devices)=self.source.capture(deadline)?;baseline.validate_origin_current(&self.source.config.interfaces,&devices)?;
        ensure!(forwarding==self.ipv4_forwarding()? && settlement::nat_equal(nat.as_ref(),self.observed_nat(deadline)?.as_ref())
            && marker==ownership::marker(&self.root)? && firewall==self.firewall_binding()?,"CONFLICT: delegated backend changed during owner proof");
        let observed=digest(&json!({"profiles":source["sourceDigest"],"automaticNat":nat,"natOwnership":marker,
            "firewall":firewall,"ipv4Forwarding":forwarding,"kuraRoles":baseline.roles,"delegation":Value::Null}))?;
        ensure!(handover::Baseline::bind_pair_source(&observed,baseline.firewall_source.as_ref(),baseline.firewall_fence.as_ref())?==baseline.source_digest && digest(&serde_json::to_value(firewall)?)?==baseline.firewall_digest
            && serde_json::to_value(nat)?==baseline.automatic_nat,"CONFLICT: original backend changed before delegation activation");Ok(())
    }
    // Called only after reacquiring the existing original-operation OS guard.
    // The original firewall CAS/journal binding is independently checked above
    // and again by activation;this digest is not kernel-rule adoption authority.
    fn require_current_firewall_owner(&self,owner:&roles::Owner,baseline:&handover::Baseline,deadline:Instant)->Result<()> {
        let observed=crate::firewall::core_confirmed_witness(&self.root)?;
        owner.require_firewall(observed.revision,&observed.source_digest)?;
        let kernel=self.current_kernel_policy(deadline)?;
        ensure!(kernel["sourceDigest"]==observed.source_digest,"CONFLICT: Core and kernel policy sources differ");
        let original=baseline.firewall_source.as_ref().context("UNSUPPORTED: original stored firewall source required for new activation")?;
        crate::firewall::require_original_static_rules(&self.root,original.rules())
    }
    fn activation(&self,id:uuid::Uuid,token:&str,actor:&str,deadline:Instant,recover:bool)->Result<Value> {
        if recover {
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,token,actor)?;
            ensure!(expected.recovering(),"OUTCOME_UNKNOWN: query original activation phase");
            // Acknowledge only this already published lease/receipt. This never
            // dispatches a marker,kernel action,service job or new owner proof.
            // New protocol availability cannot rewrite or hide old receipt bytes.
            self.handover.recovery_requires_startup(&expected)?;
            return self.handover.recover(token,actor,|baseline|self.verify_delegated_backend(baseline,deadline));
        }
        let (expected,challenge)={let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            let expected=self.handover.requirements(id,token,actor)?;
            ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: query original activation phase");
              ensure!(expected.baseline.firewall_fence.is_some(),
                  "UNSUPPORTED: a historical single-fence plan cannot grant a fresh owner;query its original outcome");
            self.verify_delegated_backend(&expected.baseline,deadline)?;
            let challenge=self.handover.startup_activation_challenge(&expected,&self.startup_systemctl)?;
            (expected,challenge)};
        // Core confirmed reads call back into our shared observation endpoint.
        // Persistent FENCED/LEASE_INTENT keeps competitors out while unlocked.
        let source=self.role_source.as_ref().context("UNSUPPORTED: actual Core owner observer")?;
        let witness=self.startup_witness(&expected,&challenge,deadline)?;
        let proof=witness.owner.clone();expected.verify(&proof)?;
        let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
        ensure!(self.handover.requirements(id,token,actor)?==expected,"CONFLICT: original owner plan changed during proof");
        source.owner_still_registered(&proof,deadline)?;
        self.require_current_firewall_owner(&proof,&expected.baseline,deadline)?;
        source.association_still_registered(&witness.association,deadline)?;
        let startup_receipt=self.handover.startup_activation_finish(&expected,&challenge,&witness,&self.startup_systemctl)?;
        self.handover.activate_proven(token,actor,proof,startup_receipt,|baseline|self.verify_delegated_backend(baseline,deadline))
    }
    fn delegation_baseline(&self,id:uuid::Uuid,deadline:Instant)->Result<handover::Baseline> {
        self.delegation_source(deadline)?.bind(id)
    }
    fn legacy_kernel_source(&self,deadline:Instant)->Result<Value> {
        #[cfg(test)]
        if !self.real.load(std::sync::atomic::Ordering::Relaxed) {
            let values=self.fake.lock().unwrap().legacy_kernel.clone()
                .context("UNSUPPORTED: legacy kernel fixture not configured")?;
            return crate::firewall::fixture_legacy_kernel(values,deadline);
        }
        crate::firewall::observe_legacy_kernel(deadline)
    }
    pub(super) fn original_native_source(&self,deadline:Instant)->Result<Value> {
        #[cfg(test)]
        if !self.real.load(std::sync::atomic::Ordering::Relaxed) {
            return self.fake.lock().unwrap().native_kernel.clone().context("UNSUPPORTED: complete native source fixture not configured");
        }
        handover::native::raw::observe(||Ok(serde_json::from_str(&self.run_nft_until(&["-j","-p","list","ruleset"],None,deadline)?)?),deadline)
    }
    fn legacy_source_review(&self,deadline:Instant)->Result<Value> {
        let (before,_)=self.capture_source(deadline)?;
        let roles=serde_json::from_value::<Option<roles::Observation>>(before["roleObservation"].clone())?
            .context("UNSUPPORTED: authenticated original CM source required")?;
        let exporter=self.role_source.as_ref().context("UNSUPPORTED: original stored firewall source")?;
        let stored=exporter.firewall_source(&roles,deadline)?;stored.require(&roles)?;
        let origin=exporter.firewall_origin(&roles,deadline)?;
        if let Some(origin)=&origin {ensure!(origin.stored(&roles)?==stored,"CONFLICT: stored/model source changed before kernel read");}
        if let Some(origin)=origin {
            let native=self.original_native_source(deadline)?;
            let classification=handover::native::classify::review_raw(&origin,&roles,&native)?;
            let current_stored=exporter.firewall_source(&roles,deadline)?;let (after,_)=self.capture_source(deadline)?;
            ensure!(exporter.firewall_origin(&roles,deadline)?==Some(origin.clone()),"CONFLICT: original writer model/registration changed during raw review");
            ensure!(before==after&&stored==current_stored&&handover::native::classify::kernel_digest(&native)?==handover::native::classify::kernel_digest(&self.original_native_source(deadline)?)?,
                "CONFLICT: raw generation/native/CM source changed during review");
            let result=json!({"schemaVersion":2,"reviewKind":"legacy.raw.source.v1",
                "reviewDigest":digest(&json!({"domain":"legacy.raw.review.v1","backend":before["sourceDigest"],"storedFirewall":stored,"classification":classification["classificationDigest"]}))?,
                "networkRevision":roles.source_revision(),"firewallSource":stored.parameters()?,"writerModel":origin.parameters()?,"nativeKernel":native,"classification":classification,"preparationReady":false});
            ensure!(serde_json::to_vec(&result)?.len()<=1024*1024-4096,"RESOURCE_EXHAUSTED: paired raw source review");return Ok(result);
        }
        let kernel=self.legacy_kernel_source(deadline)?;
        let current_stored=exporter.firewall_source(&roles,deadline)?;
        let (after,_)=self.capture_source(deadline)?;
        let current_kernel=self.legacy_kernel_source(deadline)?;
        ensure!(exporter.firewall_origin(&roles,deadline)?.is_none(),"CONFLICT: original model capability changed during legacy review");
        ensure!(before==after && stored==current_stored && kernel["snapshotSha256"]==current_kernel["snapshotSha256"]
            && kernel["snapshot"]==current_kernel["snapshot"],"CONFLICT: legacy kernel/CM/backend source changed during review");
        let result=json!({"schemaVersion":1,"reviewKind":"legacy.kernel.source.v1",
            "reviewDigest":digest(&json!({"domain":"legacy.kernel.review.v1","backend":before["sourceDigest"],
                "storedFirewall":stored,"kernel":kernel["snapshot"]}))?,
            "networkRevision":roles.source_revision(),"firewallSource":stored.parameters()?,"firewallKernel":kernel,
            "preparationReady":false});
        ensure!(serde_json::to_vec(&result)?.len()<=1024*1024-4096,"RESOURCE_EXHAUSTED: paired legacy source review");
        Ok(result)
    }
    fn current_kernel_policy(&self,deadline:Instant)->Result<Value> {
        let before=self.firewall_binding()?;
        ensure!(before.journal_settled,"CONFLICT: firewall policy transaction is not settled");
        let ruleset=if handover::initialization::confirmed_source(&self.root,None)?.is_some(){self.original_native_source(deadline)?}
            else{serde_json::from_str(&self.run_nft_until(&["-j","-p","list","ruleset"],None,deadline)?)?};
        let observed=crate::firewall::initialized_kernel_source(&self.root,&ruleset)?;
        ensure!(observed["confirmedSha256"]==before.confirmed_sha256 && observed["revision"].as_str().and_then(|value|value.parse::<u64>().ok())==Some(before.revision)
            && self.firewall_binding()?==before,"CONFLICT: confirmed kernel policy authority changed during observation");
        Ok(observed)
    }
    fn delegation_source(&self,deadline:Instant)->Result<CapturedSource> {
        let (source,devices)=self.capture_source(deadline)?;
        let roles=serde_json::from_value::<Option<roles::Observation>>(source["roleObservation"].clone())?
            .context("UNSUPPORTED: authenticated original CM source required")?;
        let exporter=self.role_source.as_ref().context("UNSUPPORTED: original stored firewall source")?;
        let firewall_source=exporter.firewall_source(&roles,deadline)?;firewall_source.require(&roles)?;
        let firewall_fence=self.handover.observe_firewall_fence()?;
        let firewall=self.firewall_binding()?;ensure!(firewall.journal_settled,"CONFLICT: original firewall transaction is not settled");
        // An existing private receipt selects the existing private contract. A
        // bridge advertising legacy models does not replace that authority.
        let legacy=firewall.confirmed_sha256.is_empty();
        let origin=if legacy{exporter.firewall_origin(&roles,deadline)?}else{None};
        ensure!(!legacy || origin.is_some(),
            "UNSUPPORTED: preparing an unowned firewall requires its registered original writer model");
        if let Some(origin)=&origin {ensure!(origin.stored(&roles)?==firewall_source,"CONFLICT: original writer model/stored CM mismatch");}
        let kernel=if origin.is_some(){self.original_native_source(deadline)?}else{self.current_kernel_policy(deadline)?};
        let owned_nat=self.observed_nat(deadline)?;
        let automatic_nat=if let Some(origin)=&origin {
            ensure!(owned_nat.is_none(),"UNSUPPORTED: original legacy source overlaps an already owned native NAT policy");
            original_automatic_nat(origin,&roles,&devices)?
        }else{owned_nat.clone()};
        let baseline=handover::Baseline{source_digest:handover::Baseline::bind_pair_source(source["sourceDigest"].as_str().context("CONFLICT: NM source identity")?,Some(&firewall_source),Some(&firewall_fence))?,roles,
            profiles:devices.iter().map(handover::ProfileBinding::observe).collect::<Result<Vec<_>>>()?,
              firewall_digest:digest(&serde_json::to_value(self.firewall_binding()?)?)?,automatic_nat:serde_json::to_value(automatic_nat)?,firewall_source:Some(firewall_source),native_transfer:None,firewall_fence:Some(firewall_fence)};
        let native=origin.as_ref().map(|origin|handover::native::factory::Reviewed::new(&baseline.source_digest,origin,&baseline.roles,&kernel)).transpose()?;
        let original_nat:Option<NatSet>=serde_json::from_value(baseline.automatic_nat.clone())?;
        // Legacy writer NAT is proved by its complete original model/raw matrix.
        // Separately bind any agent-owned NAT to its own committed receipt.
        ownership::capture(&self.root,owned_nat.as_ref())?;
        self.require_forwarding(original_nat.as_ref())?;
        let (rechecked,rechecked_devices)=self.capture_source(deadline)?;
        baseline.validate_origin_current(&self.source.config.interfaces,&rechecked_devices)?;
        let kernel_unchanged=if origin.is_some(){
            handover::native::classify::kernel_digest(&kernel)?==handover::native::classify::kernel_digest(&self.original_native_source(deadline)?)?
        }else{kernel==self.current_kernel_policy(deadline)?};
        ensure!(source==rechecked && Some(exporter.firewall_source(&baseline.roles,deadline)?)==baseline.firewall_source
              && Some(self.handover.observe_firewall_fence()?)==baseline.firewall_fence
            && self.firewall_binding()?==firewall
            && (!legacy || exporter.firewall_origin(&baseline.roles,deadline)?==origin)
            && kernel_unchanged,
            "CONFLICT: original source changed during template admission");Ok(CapturedSource{baseline,kernel,native})
    }
    pub(in crate::nm) fn deposit_template(&self,value:Value,instance:uuid::Uuid,epoch:u64)->Result<Value> {
        let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
        Transfer::new(&self.root).deposit(value,instance,epoch)
    }
    fn finish_delegation_plan(&self,id:uuid::Uuid,actor:&str,deadline:Instant)->Result<Value> {
        let _guard=Guard::observe(&self.root)?;
        let transfer=Transfer::new(&self.root);transfer.recover(id,actor)?;
        if let Some(status)=self.handover.original(id,actor)? {return Ok(status);}
        let (binding,baseline)=transfer.ready(id,actor)?;
        ensure!(self.delegation_baseline(id,deadline)?==baseline,"CONFLICT: original source changed after template export");
        self.handover.plan_with_template(id,actor.into(),baseline,binding)
    }
    pub(in crate::nm) fn ownership_status(&self,value:Value)->Result<Value> {
        let input:Status=if value.is_null(){Status::default()}else{serde_json::from_value(value).context("INVALID_ARGUMENT: ownership status fields")?};
        ensure!(!(input.include_preparation_source && input.include_legacy_kernel_source),
            "INVALID_ARGUMENT: select one ownership source review");
        let _guard=Guard::observe(&self.root)?;let parent=self.handover.status()?;
        let mut result=if parent["state"]!="UNMANAGED" {parent} else {Transfer::new(&self.root).status()?};
        if input.include_preparation_source || input.include_legacy_kernel_source {
            let deadline=Instant::now()+Duration::from_secs(60);
            self.handover.ensure_unmanaged()?;
            ensure!(matches!(Transfer::new(&self.root).admission()?,handover::template::Admission::Empty),
                "OUTCOME_UNKNOWN: original preparation already exists");
            if input.include_legacy_kernel_source {
                result["legacyKernelReview"]=self.legacy_source_review(deadline)?;
                return Ok(result);
            }
            let captured=self.delegation_source(deadline)?;let baseline=&captured.baseline;
            result["preparationSource"]=json!({"schemaVersion":1,"sourceDigest":captured.source_digest(),
                "networkRevision":baseline.roles.source_revision(),"firewallSource":baseline.firewall_source.as_ref()
                      .context("UNSUPPORTED: original firewall source")?.parameters()?,"firewallKernel":captured.kernel,"firewallFence":baseline.firewall_fence});
            if let Some(native)=&captured.native {result["preparationSource"]["nativeSource"]=native.parameters();}
        }
        Ok(result)
    }

    pub(in crate::nm) fn ownership_request(&self,method:&str,value:Value,actor:&str)->Result<Value> {
        let deadline=Instant::now()+Duration::from_secs(60);
        match method {
            "network.nm.ownership.prepare"=>{
                let input:Prepare=serde_json::from_value(value).context("INVALID_ARGUMENT: ownership prepare fields")?;
                let id=handover::template::operation(&input.operation_id)?;
                let (baseline,nonce)={
                    let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                    self.handover.ensure_unmanaged()?;
                    ensure!(matches!(Transfer::new(&self.root).admission()?,handover::template::Admission::Empty),
                        "OUTCOME_UNKNOWN: query the original template export before another preparation");
                    let baseline=self.delegation_baseline(id,deadline)?;
                    ensure!(baseline.source_digest==input.source_digest,"CONFLICT: reviewed ownership source changed");
                    let original=baseline.firewall_source.as_ref().context("UNSUPPORTED: original stored firewall source required")?;
                    if baseline.native_transfer.is_none(){crate::firewall::require_original_static_rules(&self.root,original.rules())?;}
                    let nonce=Transfer::new(&self.root).start(id,actor.into(),baseline.clone())?;(baseline,nonce)
                };
                // The durable transfer keeps admission closed while the OS guard
                // is released. The registered Java callback can now deposit.
                let exporter=self.role_source.as_ref().context("UNSUPPORTED: original template exporter")?;
                let firewall_source=baseline.firewall_source.as_ref().context("UNSUPPORTED: original firewall source missing")?;
                let _outcome=exporter.export(id,&baseline.roles,firewall_source,&nonce,deadline);
                // Even a lost Java reply may have left a complete original
                // ciphertext receipt. Adjudicate it; never call export again.
                self.finish_delegation_plan(id,actor,deadline)
            }
            "network.nm.ownership.original"=>{
                let input:Original=serde_json::from_value(value).context("INVALID_ARGUMENT: original ownership fields")?;
                let id=handover::template::operation(&input.operation_id)?;
                let pending_activation={
                    let _guard=Guard::observe(&self.root)?;
                    Transfer::new(&self.root).recover(id,actor)?;
                    if let Some(status)=self.handover.original(id,actor)? {
                        if status["state"]=="LEASE_INTENT" {
                            Some(status["confirmationToken"].as_str().context("CONFLICT: original activation token")?.to_string())
                        } else {
                        // Only adjudicate this original pre-fence cancellation;
                        // never fence/activate while querying a lost prepare.
                        let token=status["confirmationToken"].as_str().map(str::to_owned);
                        if let Some(token)=token {self.handover.recover(&token,actor,|_|anyhow::bail!("OUTCOME_UNKNOWN: activation proof requires explicit controller"))?;}
                        let settled=self.handover.original(id,actor)?.context("CONFLICT: original ownership disappeared")?;
                        if settled["state"]=="CANCELLED" {Transfer::new(&self.root).cancel(id,actor)?;}
                        return Ok(settled);
                        }
                    } else {None}
                };
                if let Some(token)=pending_activation {
                    return self.activation(id,&token,actor,deadline,true)
                        .context("OUTCOME_UNKNOWN: original activation remains unresolved;retain its evidence and do not reissue");
                }
                self.finish_delegation_plan(id,actor,deadline)
            }
            "network.nm.ownership.fence"=>{
                let input:Confirm=serde_json::from_value(value).context("INVALID_ARGUMENT: original fence fields")?;
                let id=handover::template::operation(&input.operation_id)?;let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                self.handover.original(id,actor)?.context("NOT_FOUND: original fence plan")?;
                self.handover.fence(&input.confirmation_token,actor,||self.delegation_baseline(id,deadline))
            }
            "network.nm.ownership.activate"=>{
                let input:Confirm=serde_json::from_value(value).context("INVALID_ARGUMENT: original activation fields")?;
                self.activation(handover::template::operation(&input.operation_id)?,&input.confirmation_token,actor,deadline,false)
            }
            "network.nm.ownership.native.original"=>{
                let input:Original=serde_json::from_value(value).context("INVALID_ARGUMENT: original native query fields")?;
                let id=handover::template::operation(&input.operation_id)?;let _guard=Guard::observe(&self.root)?;
                self.handover.native_original(id,actor,||handover::native::raw::observe(||Ok(serde_json::from_str(&self.run_nft_until(&["-j","-p","list","ruleset"],None,deadline)?)?),deadline))
            }
            "network.nm.ownership.native.apply"|"network.nm.ownership.native.rollback"=>{
                let input:Confirm=serde_json::from_value(value).context("INVALID_ARGUMENT: original native effect fields")?;
                let id=handover::template::operation(&input.operation_id)?;let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                self.handover.native_change(id,&input.confirmation_token,actor,method.ends_with(".rollback"),|baseline,operation,plan,_after|self.original_native_witness(baseline,operation,plan,deadline,false).map(|value|value.0),|batch|handover::native::raw::writer::dispatch(batch,deadline))
            }
            "network.nm.ownership.initialization.apply"=>{
                let input:Confirm=serde_json::from_value(value).context("INVALID_ARGUMENT: original initialization fields")?;
                let id=handover::template::operation(&input.operation_id)?;let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                self.handover.initialize_policy(id,&input.confirmation_token,actor,|baseline,id,plan|self.original_native_witness(baseline,id,plan,deadline,true),|path,bytes|crate::durable::publish_new(path,bytes,crate::durable::FileMetadata::private()))
            }
            "network.nm.ownership.initialization.original"=>{
                let input:Original=serde_json::from_value(value).context("INVALID_ARGUMENT: original initialization query fields")?;
                let id=handover::template::operation(&input.operation_id)?;let _guard=Guard::observe(&self.root)?;
                self.handover.initialization_original(id,actor,|baseline,id,plan|self.original_native_witness(baseline,id,plan,deadline,true))
            }
            "network.nm.ownership.startup.prepare"=>{
                let input:Confirm=serde_json::from_value(value).context("INVALID_ARGUMENT: original startup prepare fields")?;
                let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                let id=handover::template::operation(&input.operation_id)?;
                let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;
                self.verify_delegated_backend(&expected.baseline,deadline)?;
                self.handover.startup_prepare(id,&input.confirmation_token,actor,&self.startup_profile,&self.startup_systemctl)
            }
            "network.nm.ownership.startup.verify"=>self.startup_association(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original startup verification fields")?,actor,deadline),
            "network.nm.ownership.startup.stop"=>self.startup_stop(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original startup stop fields")?,actor,deadline),
            "network.nm.ownership.startup.publish"=>self.startup_publication(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original startup publication fields")?,actor,deadline),
            "network.nm.ownership.startup.start"=>self.startup_start(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original startup start fields")?,actor,deadline),
            "network.nm.ownership.startup.complete"=>self.startup_completion(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original startup completion fields")?,actor,deadline),
            "network.nm.ownership.startup.recovery.prepare"|"network.nm.ownership.startup.recovery.original"=>{
                let input:RecoveryReview=serde_json::from_value(value).context("INVALID_ARGUMENT: original recovery review fields")?;
                let id=handover::template::operation(&input.operation_id)?;let recovery_id=handover::template::operation(&input.recovery_id)?;
                let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
                if method.ends_with(".original") {return self.handover.startup_recovery_original(id,&input.confirmation_token,actor,&input.startup_confirmation_token,recovery_id);}
                let expected=self.handover.requirements(id,&input.confirmation_token,actor)?;self.verify_delegated_backend(&expected.baseline,deadline)?;
                self.handover.startup_recovery_prepare(id,&input.confirmation_token,actor,&input.startup_confirmation_token,recovery_id,&self.startup_systemctl)
            }
            "network.nm.ownership.startup.recovery.execute"|"network.nm.ownership.startup.recovery.cancel"=>self.startup_recovery(serde_json::from_value(value)
                .context("INVALID_ARGUMENT: original recovery confirmation fields")?,actor,deadline,method.ends_with(".cancel")),
            "network.nm.ownership.status"=>self.ownership_status(value),
            "network.nm.ownership.cancel"=>{
                let input:Original=serde_json::from_value(value).context("INVALID_ARGUMENT: original ownership cancel fields")?;
                let id=handover::template::operation(&input.operation_id)?;
                let _guard=Guard::observe(&self.root)?;
                self.handover.cancel_before_fence(id,actor)?;Transfer::new(&self.root).cancel(id,actor)
            }
            _=>anyhow::bail!("UNSUPPORTED: ownership method"),
        }
    }
}
