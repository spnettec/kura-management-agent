//! Recovery over the original identity, immutable read sets and fresh state.
use super::*;
use std::collections::BTreeSet;

pub(super) fn profile_rows(detached: &[preview::DetachedCandidate], changes: &Value) -> Result<Vec<Value>> {
    let edited = edited_surface(changes)?;
    Ok(detached.iter().map(|d| json!({
        "interface":d.interface,"profilePath":d.profile_path,"devicePath":d.device_path,
        "uuid":d.uuid,"versionId":d.version_id,"storedSha256":d.stored_sha256,
        "sourceSha256":d.source_sha256,"appliedSha256":d.applied_sha256,
        "settings":d.stored,"sourceSettings":d.source_settings,
        "applied":d.applied,"sourceApplied":d.source_applied,"appliedVersion":d.applied_version,
        "edited":edited[&d.interface],
    })).collect())
}

pub(in crate::nm) fn nat_equal(a: Option<&NatSet>, b: Option<&NatSet>) -> bool {
    match (a,b) {
        (None,None) => true,
        (Some(a),Some(b)) => matches!((a.pairs(),b.pairs()),(Ok(a),Ok(b)) if a==b),
        _ => false,
    }
}

pub(in crate::nm) fn parse_nat(snapshot: &Value) -> Result<NatSet> {
    let entries = snapshot["nftables"].as_array().context("CONFLICT: NAT table format")?;
    let (mut table,mut chain) = (false,false);
    let mut pairs = BTreeSet::new();
    for entry in entries {
        let object = entry.as_object().context("CONFLICT: NAT entry format")?;
        ensure!(object.len() == 1, "CONFLICT: unexpected NAT entry");
        if object.contains_key("metainfo") {continue;}
        if let Some(value) = object.get("table") {
            ensure!(!table && value["family"] == "inet" && value["name"] == NAT_TABLE,
                "CONFLICT: NAT table identity");
            ensure!(value["flags"].is_null() || value["flags"].as_array().is_some_and(|flags| flags.is_empty()),
                "CONFLICT: NAT table disabled or lifetime differs");
            table = true;
        } else if let Some(value) = object.get("chain") {
            ensure!(!chain && value["family"] == "inet" && value["table"] == NAT_TABLE
                && value["name"] == "postrouting" && value["type"] == "nat"
                && value["hook"] == "postrouting" && value["policy"] == "accept"
                && (value["prio"] == 100 || value["prio"] == "srcnat"),
                "CONFLICT: NAT chain semantics");
            chain = true;
        } else if let Some(rule) = object.get("rule") {
            ensure!(rule["family"] == "inet" && rule["table"] == NAT_TABLE
                && rule["chain"] == "postrouting", "CONFLICT: NAT rule identity");
            let (input,output,comment) = rule_pair(rule)?;
            ensure!(comment.as_deref() == Some(NAT_COMMENT), "CONFLICT: NAT comment");
            let (mut inputs,mut outputs,mut masquerades,mut comments) = (0,0,0,0);
            for expression in rule["expr"].as_array().context("CONFLICT: NAT expressions")? {
                let expr = expression.as_object().context("CONFLICT: NAT expression")?;
                ensure!(expr.len() == 1, "CONFLICT: NAT expression shape");
                if let Some(value) = expr.get("match") {
                    ensure!(value["op"] == "==" && value["right"].is_string(), "CONFLICT: NAT match semantics");
                    match value["left"]["meta"]["key"].as_str() {
                        Some("iifname") => inputs += 1,
                        Some("oifname") => outputs += 1,
                        _ => anyhow::bail!("CONFLICT: unexpected NAT match"),
                    }
                } else if let Some(value) = expr.get("masquerade") {
                    ensure!(value.is_null() || value.as_object().is_some_and(|v| v.is_empty()), "CONFLICT: unexpected masquerade options");
                    masquerades += 1;
                } else if expr.get("comment").is_some_and(|v| v["text"] == NAT_COMMENT) {
                    comments += 1;
                } else {anyhow::bail!("CONFLICT: unexpected NAT expression");}
            }
            ensure!(inputs == 1 && outputs == 1 && masquerades == 1 && comments <= 1,
                "CONFLICT: incomplete or duplicate NAT expressions");
            let pair = (input.context("CONFLICT: NAT input")?,output.context("CONFLICT: NAT output")?);
            ensure!(pair.0 != pair.1 && pairs.insert(pair), "CONFLICT: duplicate NAT pair");
        } else {anyhow::bail!("CONFLICT: unexpected owned NAT object");}
    }
    ensure!(table && chain && !pairs.is_empty(), "CONFLICT: NAT table incomplete");
    NatSet::from_pairs(pairs.into_iter().map(|(lan,wan)|roles::NatPair{lan,wan}).collect())?
        .context("CONFLICT: empty NAT policy")
}

struct Checkpoint {
    devices: BTreeSet<String>,
    created: i64,
}
enum Scope {Gone, Safe, Unsafe}
enum NatObservation {Absent, Present(NatSet), Invalid}
enum NatRestoration {Ready, Pending, Unsafe}

impl Coordinator {
    fn blocked(&self, journal: &mut transaction::Journal, action: &str) -> Result<Value> {
        journal.state = transaction::State::RecoveryRequired;
        self.save(journal)?;
        Ok(json!({"state":"RECOVERY_REQUIRED","action":action}))
    }
    pub(super) fn bound_owner(&self, journal: &mut transaction::Journal, deadline: Instant) -> Result<String> {
        let observed = self.source.binding(deadline)?;
        let bytes = crate::durable::read(&self.intent_path(journal.operation_id,None), LIMIT)?.0;
        let header: transaction::IntentHeader = serde_json::from_slice(&bytes)?;
        let valid = crate::durable::hash(&bytes) == journal.intent_sha256
            && header.nm_identity == journal.nm_identity && header.nat_before == journal.nat_before
            && journal.nm_identity.as_ref().is_some_and(|expected| expected.identity == observed.identity)
            && journal.nat_before.is_some();
        if !valid {
            self.blocked(journal, "original-nm-identity-unproven")?;
            anyhow::bail!("CONFLICT: original NM bus/service identity unproven");
        }
        Ok(observed.identity.service_owner)
    }
    fn checkpoint(&self, owner: &str, path: &str, deadline: Instant) -> Result<Option<Checkpoint>> {
        let value = self.call(owner,path,PROPERTIES,"GetAll",
            &[json!({"type":"s","data":"org.freedesktop.NetworkManager.Checkpoint"})],deadline)?;
        let parsed = (|| -> Result<Checkpoint> {
            let values = fields(value,"a{sv}",1)?;
            let data = &values[0];
            let mut devices = BTreeSet::new();
            for device in variant(&data["Devices"],"ao")?.as_array().context("CONFLICT: checkpoint devices")? {
                ensure!(devices.insert(object_path(device,"Devices")?), "CONFLICT: duplicate checkpoint device");
            }
            ensure!(!devices.is_empty(), "CONFLICT: checkpoint scope empty");
            let created = variant(&data["Created"],"x")?.as_i64().filter(|v| *v >= 0).context("CONFLICT: checkpoint creation")?;
            Ok(Checkpoint {devices,created})
        })();
        Ok(parsed.ok())
    }
    fn checkpoint_scope(&self, journal: &transaction::Journal, owner: &str, rollback: bool, deadline: Instant) -> Result<Scope> {
        let Some(path) = journal.checkpoint_path.as_deref() else {return Ok(Scope::Unsafe);};
        object_path(&json!(path),"Checkpoint")?;
        let value = self.call(owner,ROOT,PROPERTIES,"Get",
            &[json!({"type":"s","data":MANAGER}),json!({"type":"s","data":"Checkpoints"})],deadline)?;
        let values = fields(value,"v",1)?;
        let live = variant(&values[0],"ao")?.as_array().context("CONFLICT: checkpoint list")?;
        let mut paths = BTreeSet::new();
        for value in live {ensure!(paths.insert(object_path(value,"Checkpoint")?),"CONFLICT: duplicate checkpoint");}
        if !paths.contains(path) {return Ok(Scope::Gone);}
        let Some(own) = self.checkpoint(owner,path,deadline)? else {return Ok(Scope::Unsafe);};
        let payload = self.verify_action_intent(journal,CHECKPOINT_ACTION)?;
        let expected = payload["devices"].as_array().context("CONFLICT: checkpoint intent devices")?
            .iter().map(|p| object_path(p,"Devices")).collect::<Result<BTreeSet<_>>>()?;
        if own.devices != expected || expected.is_empty() {return Ok(Scope::Unsafe);}
        if rollback {
            for foreign in paths.iter().filter(|p| p.as_str() != path) {
                let Some(other) = self.checkpoint(owner,foreign,deadline)? else {return Ok(Scope::Unsafe);};
                // NM rollback also removes newer overlapping checkpoints.
                if other.created >= own.created && !other.devices.is_disjoint(&own.devices) {return Ok(Scope::Unsafe);}
            }
        }
        Ok(Scope::Safe)
    }
    fn profile_state(&self, journal: &transaction::Journal, desired: bool, deadline: Instant) -> Result<bool> {
        let (source,devices) = self.source.capture(deadline)?;
        let action = if journal.action_intents.iter().any(|a| a.action == PROFILE_ACTION) {PROFILE_ACTION} else {CHECKPOINT_ACTION};
        let payload = self.verify_action_intent(journal,action)?;
        let valid = (|| -> Result<()> {
            let expected = journal.nm_identity.as_ref().context("CONFLICT: NM identity")?;
            let observed: Identity = serde_json::from_value(source["source"]["identity"].clone())?;
            ensure!(observed == expected.identity, "CONFLICT: NM identity changed");
            let profiles = payload["profiles"].as_array().filter(|v| !v.is_empty()).context("CONFLICT: profile read set")?;
            for row in profiles {
                let device = devices.iter().find(|d| Some(d.interface.as_str()) == row["interface"].as_str()).context("CONFLICT: interface missing")?;
                ensure!(device.managed && device.state == 100 && Some(device.device_path.as_str()) == row["devicePath"].as_str(), "CONFLICT: device readback");
                let profile = device.active_profile.as_ref().context("CONFLICT: active profile missing")?;
                ensure!(Some(profile.profile_path.as_str()) == row["profilePath"].as_str()
                    && Some(profile.uuid.as_str()) == row["uuid"].as_str(), "CONFLICT: profile identity changed");
                ensure!(profile.version_id >= row["versionId"].as_u64().filter(|v| *v > 0).context("CONFLICT: profile version")?
                    && profile.applied_version >= row["appliedVersion"].as_u64().context("CONFLICT: applied version")?, "CONFLICT: profile counters regressed");
                let stored = if desired {&row["settings"]} else {&row["sourceSettings"]};
                let applied = if desired {&row["applied"]} else {&row["sourceApplied"]};
                ensure!(stored.is_object() && applied.is_object(), "CONFLICT: profile read set missing");
                self.verify_edited_fields(&profile.settings,&json!({"settings":stored}),&row["edited"])?;
                self.verify_edited_fields(&profile.applied,&json!({"settings":applied}),&row["edited"])?;
            }
            Ok(())
        })();
        Ok(valid.is_ok())
    }
    fn nat_observation(&self, deadline: Instant) -> Result<NatObservation> {
        match self.run_nft_until(&["-j","list","table","inet",NAT_TABLE],None,deadline) {
            Ok(text) => Ok(serde_json::from_str::<Value>(&text).ok()
                .and_then(|value| parse_nat(&value).ok()).map(NatObservation::Present).unwrap_or(NatObservation::Invalid)),
            Err(_) => {
                let value: Value = serde_json::from_str(&self.run_nft_until(&["-j","list","ruleset"],None,deadline)?)?;
                let entries = value["nftables"].as_array().context("CONFLICT: nft ruleset format")?;
                ensure!(!entries.iter().any(|e| e["table"]["family"] == "inet" && e["table"]["name"] == NAT_TABLE), "CONFLICT: owned NAT table cannot be read");
                Ok(NatObservation::Absent)
            }
        }
    }
    pub(super) fn observed_nat(&self, deadline: Instant) -> Result<Option<NatSet>> {
        match self.nat_observation(deadline)? {
            NatObservation::Absent => Ok(None), NatObservation::Present(v) => Ok(Some(v)),
            NatObservation::Invalid => anyhow::bail!("CONFLICT: owned NAT table has unexpected semantics"),
        }
    }
    fn candidate_state(&self, journal: &transaction::Journal, deadline: Instant) -> Result<bool> {
        self.ensure_role_binding(journal,deadline)?;
        if !self.profile_state(journal,true,deadline)? {return Ok(false);}
        let payload = self.verify_action_intent(journal,FIREWALL_ACTION)?;
        let expected: Option<NatSet> = serde_json::from_value(payload["nat"].clone())?;
        self.require_forwarding(expected.as_ref())?;
        let actual = match self.nat_observation(deadline)? {
            NatObservation::Absent => None, NatObservation::Present(v) => Some(v), NatObservation::Invalid => return Ok(false),
        };
        Ok(nat_equal(actual.as_ref(),expected.as_ref()) && self.ensure_firewall_binding(journal).is_ok())
    }
    fn restore_nat(&self, journal: &mut transaction::Journal, deadline: Instant) -> Result<NatRestoration> {
        let baseline = journal.nat_before.as_ref().context("CONFLICT: NAT baseline missing")?;
        let before: Option<NatSet> = serde_json::from_value(baseline.get("nat").context("CONFLICT: NAT baseline shape")?.clone())?;
        let actual = match self.nat_observation(deadline)? {
            NatObservation::Absent => None, NatObservation::Present(v) => Some(v), NatObservation::Invalid => return Ok(NatRestoration::Unsafe),
        };
        if nat_equal(actual.as_ref(),before.as_ref()) {return Ok(NatRestoration::Ready);}
        if !journal.action_intents.iter().any(|a| a.action == FIREWALL_ACTION) {return Ok(NatRestoration::Unsafe);}
        let payload = self.verify_action_intent(journal,FIREWALL_ACTION)?;
        let proposed: Option<NatSet> = serde_json::from_value(payload["nat"].clone())?;
        if !nat_equal(actual.as_ref(),proposed.as_ref()) {return Ok(NatRestoration::Unsafe);}
        if journal.nat_restore_dispatched {return Ok(NatRestoration::Pending);}
        journal.nat_restore_dispatched = true;
        self.save(journal)?;
        let text = match &before {
            Some(nat) => nat.render()?,
            None => format!("destroy table inet {NAT_TABLE}\n"),
        };
        let result = self.run_nft_until(&["-f","-"],Some(&text),deadline);
        result.map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: NAT restoration response unconfirmed"))?;
        let restored = self.observed_nat(deadline)?;
        Ok(if nat_equal(restored.as_ref(),before.as_ref()) {NatRestoration::Ready} else {NatRestoration::Unsafe})
    }
    pub(super) fn rollback_settle(&self, journal: &mut transaction::Journal, deadline: Instant) -> Result<()> {
        ownership::ensure_baseline(&self.root,journal.nat_before.as_ref().context("CONFLICT: NAT baseline missing")?)?;
        let owner = self.bound_owner(journal,deadline)?;
        match self.checkpoint_scope(journal,&owner,true,deadline)? {
            Scope::Unsafe => {self.blocked(journal,"checkpoint-ownership-or-overlap-unproven")?;anyhow::bail!("CONFLICT: safe owned rollback unproven");}
            Scope::Safe => {
                if journal.rollback_dispatched {anyhow::bail!("OUTCOME_UNKNOWN: original rollback pending; no resend");}
                journal.state = transaction::State::RollbackRunning;
                journal.rollback_dispatched = true;
                self.save(journal)?;
                let path = journal.checkpoint_path.clone().unwrap();
                self.call(&owner,ROOT,MANAGER,"CheckpointRollback",&[json!({"type":"o","data":path})],deadline)
                    .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: checkpoint rollback response unconfirmed"))?;
            }
            Scope::Gone => {journal.state = transaction::State::RollbackRunning;self.save(journal)?;}
        }
        if !self.profile_state(journal,false,deadline)? {
            self.blocked(journal,"rollback-profile-mismatch")?;
            anyhow::bail!("CONFLICT: rollback state not restored");
        }
        match self.restore_nat(journal,deadline)? {
            NatRestoration::Ready => self.finish(journal,transaction::State::RolledBack),
            NatRestoration::Pending => anyhow::bail!("OUTCOME_UNKNOWN: original NAT restoration pending; no resend"),
            NatRestoration::Unsafe => {self.blocked(journal,"rollback-nat-mismatch")?;anyhow::bail!("CONFLICT: NAT restoration unproven");}
        }
    }
    fn complete_confirm(&self, journal: &mut transaction::Journal, deadline: Instant, prevalidated: bool) -> Result<Value> {
        ownership::confirmation(&self.root,journal)?;
        let owner = self.bound_owner(journal,deadline)?;
        match self.checkpoint_scope(journal,&owner,false,deadline)? {
            Scope::Unsafe => return self.blocked(journal,"checkpoint-ownership-unproven"),
            Scope::Safe => {
                if !prevalidated && !self.candidate_state(journal,deadline)? {return self.blocked(journal,"confirm-candidate-mismatch");}
                if journal.checkpoint_destroy_dispatched {
                    return Ok(json!({"state":"CONFIRM_DECIDED","action":"confirmation-pending"}));
                }
                journal.checkpoint_destroy_dispatched = true;
                self.save(journal)?;
                self.call(&owner,ROOT,MANAGER,"CheckpointDestroy",
                    &[json!({"type":"o","data":journal.checkpoint_path})],deadline)
                    .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: checkpoint confirmation response unconfirmed"))?;
            }
            Scope::Gone => {}
        }
        // Required after either destroy acknowledgement or observed absence:
        // an expired checkpoint may have restored the source after the decision.
        if !self.candidate_state(journal,deadline)? {return self.blocked(journal,"confirm-candidate-mismatch");}
        self.finish(journal,transaction::State::Committed)?;
        Ok(json!({"operationId":journal.operation_id.to_string(),"state":"COMMITTED","action":"confirmed"}))
    }
    pub(super) fn confirm_settle(&self, journal: &mut transaction::Journal, deadline: Instant) -> Result<Value> {
        ownership::ensure_baseline(&self.root,journal.nat_before.as_ref().context("CONFLICT: NAT baseline missing")?)?;
        let owner = self.bound_owner(journal,deadline)?;
        ensure!(matches!(self.checkpoint_scope(journal,&owner,false,deadline)?,Scope::Safe), "CONFLICT: owned checkpoint absent or changed");
        ensure!(self.candidate_state(journal,deadline)?, "CONFLICT: NM candidate readback mismatch");
        journal.confirmed_decision = true;
        journal.state = transaction::State::ConfirmDecided;
        self.save(journal)?;
        self.complete_confirm(journal,deadline,true)
    }
    pub(super) fn recover_settle(&self) -> Result<Value> {
        let Some(mut journal) = self.journal()? else {return Ok(json!({"state":"NONE","action":"none"}));};
        if journal.state.terminal() || journal.state == transaction::State::RecoveryRequired {
            return Ok(json!({"state":serde_json::to_value(&journal.state)?,"action":"none"}));
        }
        if journal.state == transaction::State::Prepared {
            self.finish(&mut journal,transaction::State::Cancelled)?;
            return Ok(json!({"state":"CANCELLED","action":"cancelled"}));
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        if let Err(error) = self.bound_owner(&mut journal,deadline) {
            if journal.state == transaction::State::RecoveryRequired {return Ok(json!({"state":"RECOVERY_REQUIRED","action":"original-nm-identity-unproven"}));}
            return Err(error);
        }
        if journal.state == transaction::State::CheckpointIntent {
            // There was no acknowledged path. Neither set difference nor time
            // proximity attributes any observed checkpoint to this operation.
            return self.blocked(&mut journal,"checkpoint-create-unattributed");
        }
        if journal.state == transaction::State::ConfirmDecided {
            if !journal.confirmed_decision {return self.blocked(&mut journal,"confirmation-decision-missing");}
            return self.complete_confirm(&mut journal,deadline,false);
        }
        if journal.state == transaction::State::WaitConfirm && now() < journal.deadline_ms.unwrap_or(0) {
            return Ok(json!({"state":"WAIT_CONFIRM","action":"none"}));
        }
        let expired = journal.state == transaction::State::WaitConfirm;
        match self.rollback_settle(&mut journal,deadline) {
            Ok(()) => Ok(json!({"state":"ROLLED_BACK","action":if expired {"expired-rollback"} else {"checkpoint-rollback"}})),
            Err(_) if journal.state == transaction::State::RecoveryRequired => Ok(json!({"state":"RECOVERY_REQUIRED","action":"rollback-unproven"})),
            Err(error) => Err(error),
        }
    }
}
