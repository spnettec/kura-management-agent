//! Native effects are phases of the original ownership journal,not a new retry
//! queue. A lost reply can only be adjudicated from its complete kernel receipt.
use super::*;

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
enum Phase {Intent,Applied,InverseIntent,Reverted,Rejected,InverseRejected}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(super) struct Step {schema_version:u8,state:Phase,#[serde(default,skip_serializing_if="Option::is_none")]kernel_digest:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]batch_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]kernel_rejection:Option<Rejection>,
    #[serde(default,skip_serializing_if="Option::is_none")]epoch:Option<native::epoch::Epoch>}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Rejection {errno:i32,sequence:u32,reply_sha256:String}
impl Store {
    pub(super) fn native_epoch(&self,j:&Journal)->Option<native::epoch::Epoch> {
        j.native.as_ref().and_then(|step|step.epoch.clone())
    }
    pub(super) fn native_applied_digest(&self,j:&Journal)->Result<String> {
        j.native.as_ref().filter(|step|step.state==Phase::Applied).and_then(|step|step.kernel_digest.clone()).context("OUTCOME_UNKNOWN: complete original native acknowledgement required")
    }
    #[cfg(target_os = "linux")]
    pub(super) fn native_applied_batch(&self, journal: &Journal) -> Result<String> {
        journal.native.as_ref().filter(|step| step.state == Phase::Applied)
            .and_then(|step| step.batch_sha256.clone())
            .context("OUTCOME_UNKNOWN: original applied batch digest required")
    }
    pub(super) fn validate_native_journal(&self,j:&Journal,p:&Plan)->Result<()> {
        if let Some(native)=&p.baseline.native_transfer {
            ensure!(p.schema_version==5 && native.operation_id==j.operation_id,"CONFLICT: original native plan operation");
            if let Some(step)=&j.native {
                ensure!(matches!(j.state,State::Fenced|State::LeaseIntent|State::Committed)&&[1,2,3].contains(&step.schema_version),
                    "CONFLICT: original native phase outside paired ownership fence");
                ensure!((step.schema_version==3)==step.epoch.is_some(),"CONFLICT: native physical epoch schema");
                if let Some(epoch)=&step.epoch {epoch.validate()?;}
                ensure!(match step.state {Phase::Intent|Phase::InverseIntent|Phase::Rejected|Phase::InverseRejected=>step.kernel_digest.is_none(),Phase::Applied|Phase::Reverted=>step.kernel_digest.as_ref().is_some_and(|v|hex(v,64))},"CONFLICT: original native acknowledgement shape");
                ensure!(if step.schema_version==1 {step.batch_sha256.is_none()&&step.kernel_rejection.is_none()&&!matches!(step.state,Phase::Rejected|Phase::InverseRejected)}else{step.batch_sha256.as_ref().is_some_and(|v|hex(v,64))},"CONFLICT: original native wire binding");
                ensure!(if matches!(step.state,Phase::Rejected|Phase::InverseRejected){step.kernel_rejection.as_ref().is_some_and(|v|(1..=4095).contains(&v.errno)&&v.sequence>0&&hex(&v.reply_sha256,64))}else{step.kernel_rejection.is_none()},"CONFLICT: original kernel rejection receipt");
            }
            if matches!(j.state,State::LeaseIntent|State::Committed) {self.require_native_ready(j,p)?;}
        }else{ensure!(j.native.is_none(),"CONFLICT: native phase without original source");}
        Ok(())
    }
    pub(super) fn require_native_ready(&self,j:&Journal,p:&Plan)->Result<()> {
        ensure!(p.baseline.native_transfer.is_none() || j.native.as_ref().is_some_and(|v|v.state==Phase::Applied && v.kernel_digest.as_ref().is_some_and(|h|hex(h,64))),
            "OUTCOME_UNKNOWN: original native transfer must be acknowledged before startup or owner activation");Ok(())
    }
    pub(in crate::nm) fn native_change(&self,id:uuid::Uuid,token:&str,actor:&str,inverse:bool,
        inspect:impl FnMut(&Baseline,uuid::Uuid,&str,bool)->Result<Value>,apply:impl FnOnce(&Value)->Result<()>)->Result<Value> {
        self.native_change_at(id,token,actor,inverse,(inspect,apply,native::epoch::Epoch::capture),true)
    }
    /// Explicit synthetic storage adapter; never used by a normal binary.
    #[cfg(test)]
    pub(in crate::nm) fn native_change_fixture(&self,id:uuid::Uuid,token:&str,actor:&str,inverse:bool,
        inspect:impl FnMut(&Baseline,uuid::Uuid,&str,bool)->Result<Value>,apply:impl FnOnce(&Value)->Result<()>)->Result<Value> {
        self.native_change_at(id,token,actor,inverse,(inspect,apply,||Ok(native::epoch::Epoch::storage_fixture())),false)
    }
    #[cfg(test)]
    pub(in crate::nm) fn native_change_epoch_fixture(&self,id:uuid::Uuid,token:&str,actor:&str,inverse:bool,
        io:(impl FnMut(&Baseline,uuid::Uuid,&str,bool)->Result<Value>,impl FnOnce(&Value)->Result<()>,impl FnMut()->Result<native::epoch::Epoch>))->Result<Value> {
        self.native_change_at(id,token,actor,inverse,io,false)
    }
    fn native_change_at(&self,id:uuid::Uuid,token:&str,actor:&str,inverse:bool,
        io:(impl FnMut(&Baseline,uuid::Uuid,&str,bool)->Result<Value>,impl FnOnce(&Value)->Result<()>,impl FnMut()->Result<native::epoch::Epoch>),
        require_generation:bool)->Result<Value> {
        let (mut inspect,apply,mut observe_epoch)=io;
        let (mut journal,plan)=self.load()?.context("NOT_FOUND: original native ownership plan")?;Self::authorize(&journal,token,&plan,actor)?;
        ensure!(journal.operation_id==id && journal.state==State::Fenced,"CONFLICT: native effect requires its original fenced plan");
        ensure!(!inverse||journal.initialization.is_none(),"CONFLICT: original initialization must be separately retired before native inverse");
        let transfer=plan.baseline.native_transfer.as_ref().context("UNSUPPORTED: original native source was not reviewed")?;
        ensure!(if inverse {journal.native.as_ref().is_some_and(|v|v.state==Phase::Applied)}else{journal.native.is_none()},
            "OUTCOME_UNKNOWN: query the original native effect;never reissue");
        startup::require_no_native_child(&self.root,id)?;
        self.require_pair_identity(&journal,&plan)?;
        let epoch=observe_epoch()?;
        if inverse {journal.native.as_ref().and_then(|step|step.epoch.as_ref()).context("UNSUPPORTED: legacy native effect has no original physical epoch;separate lawful restore required")?.require(&epoch)?;}
        let current=inspect(&plan.baseline,id,&journal.plan_sha256,false)?;let batch=transfer.batch(&current,inverse)?;
        ensure!(!require_generation||batch.get("expectedGeneration").is_some(),"UNSUPPORTED: native physical effect requires complete generation fencing");
        epoch.require(&observe_epoch()?)?;
        ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"CONFLICT: original network marker changed before native intent");self.require_pair_identity(&journal,&plan)?;
        let batch_sha256=Some(digest(&batch)?);let schema_version=3;
        journal.native=Some(Step{schema_version,state:if inverse{Phase::InverseIntent}else{Phase::Intent},kernel_digest:None,batch_sha256:batch_sha256.clone(),kernel_rejection:None,epoch:Some(epoch.clone())});
        durable::json(&self.journal_path(),&journal)?;
        epoch.require(&observe_epoch()?)?;
        if let Err(error)=apply(&batch) {
            epoch.require(&observe_epoch()?)?;
            if batch_sha256.is_some() && let Some(rejected)=error.downcast_ref::<native::raw::wire::Rejected>() {
                journal.native=Some(Step{schema_version,state:if inverse{Phase::InverseRejected}else{Phase::Rejected},kernel_digest:None,batch_sha256,
                    kernel_rejection:Some(Rejection{errno:rejected.errno,sequence:rejected.sequence,reply_sha256:rejected.reply_sha256.clone()}),epoch:Some(epoch)});
                durable::json(&self.journal_path(),&journal)?;return self.status();
            }
            anyhow::bail!("OUTCOME_UNKNOWN: original native batch reply lost;query only");
        }
        let current=inspect(&plan.baseline,id,&journal.plan_sha256,true).map_err(|_|anyhow::anyhow!("OUTCOME_UNKNOWN: original native readback unavailable;query only"))?;
        let kernel_digest=transfer.acknowledge(&current,inverse)?;
        epoch.require(&observe_epoch()?)?;
        ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"OUTCOME_UNKNOWN: original network marker changed during native effect");
        self.require_pair_identity(&journal,&plan)?;
        journal.native=Some(Step{schema_version,state:if inverse{Phase::Reverted}else{Phase::Applied},kernel_digest:Some(kernel_digest),batch_sha256,kernel_rejection:None,epoch:Some(epoch)});
        durable::json(&self.journal_path(),&journal)?;self.status()
    }
    pub(in crate::nm) fn native_original(&self,id:uuid::Uuid,actor:&str,observe:impl FnOnce()->Result<Value>)->Result<Value> {
        self.native_original_at(id,actor,observe,native::epoch::Epoch::capture)
    }
    #[cfg(test)]
    pub(in crate::nm) fn native_original_fixture(&self,id:uuid::Uuid,actor:&str,observe:impl FnOnce()->Result<Value>)->Result<Value> {
        self.native_original_at(id,actor,observe,||Ok(native::epoch::Epoch::storage_fixture()))
    }
    #[cfg(test)]
    pub(in crate::nm) fn native_original_epoch_fixture(&self,id:uuid::Uuid,actor:&str,
        io:(impl FnOnce()->Result<Value>,impl FnMut()->Result<native::epoch::Epoch>))->Result<Value> {
        self.native_original_at(id,actor,io.0,io.1)
    }
    fn native_original_at(&self,id:uuid::Uuid,actor:&str,observe:impl FnOnce()->Result<Value>,mut observe_epoch:impl FnMut()->Result<native::epoch::Epoch>)->Result<Value> {
        let (mut journal,plan)=self.load()?.context("NOT_FOUND: original native ownership plan")?;
        ensure!(journal.operation_id==id && plan.actor==actor,"FORBIDDEN: original native actor required");
        let Some(step)=&journal.native else{return self.status();};
        if matches!(step.state,Phase::Rejected|Phase::InverseRejected) {
            ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"CONFLICT: original rejected network marker changed");self.require_pair_identity(&journal,&plan)?;return self.status();
        }
        ensure!(step.epoch.is_some()||!matches!(step.state,Phase::Intent|Phase::InverseIntent),
            "OUTCOME_UNKNOWN: original native intent has no physical epoch;matching current bytes cannot adjudicate historical work");
        let transfer=plan.baseline.native_transfer.as_ref().context("CONFLICT: original native source missing")?;
        let inverse=matches!(step.state,Phase::InverseIntent|Phase::Reverted);
        if let Some(epoch)=&step.epoch {epoch.require(&observe_epoch()?)?;}
        let kernel_digest=transfer.acknowledge(&observe()?,inverse)?;
        if let Some(epoch)=&step.epoch {epoch.require(&observe_epoch()?)?;}
        ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"OUTCOME_UNKNOWN: original network marker changed during native query");self.require_pair_identity(&journal,&plan)?;
        if matches!(step.state,Phase::Intent|Phase::InverseIntent) {
            journal.native=Some(Step{schema_version:step.schema_version,state:if inverse{Phase::Reverted}else{Phase::Applied},kernel_digest:Some(kernel_digest),batch_sha256:step.batch_sha256.clone(),kernel_rejection:None,epoch:step.epoch.clone()});
            durable::json(&self.journal_path(),&journal)?;
        }else{ensure!(step.kernel_digest.as_ref()==Some(&kernel_digest),"CONFLICT: original native kernel acknowledgement changed");}
        self.status()
    }
}
