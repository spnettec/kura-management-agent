//! Opaque original CM template transfer. Only received bytes can settle a deposit;
//! neither a query nor a crash recovery encrypts or sends another request to Kura.
use super::*;

pub(crate) const CHUNK_SIZE: usize = 256 * 1024;
const CIPHER_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
pub(crate) struct Binding {
    operation_id: uuid::Uuid,
    intent_sha256: String,
    manifest_sha256: String,
    template_sha256: String,
    receipt_sha256: String,
    chunk_count: usize,
}
impl Binding {
    pub(in crate::nm) fn template_hash(&self)->&str {&self.template_sha256}
    pub(in crate::nm) fn chunk_count(&self)->usize {self.chunk_count}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_change::{Guard,Subsystem};
    struct Fixture {root:PathBuf,transfer:Transfer,id:uuid::Uuid,source:Baseline,nonce:String}
    impl Fixture {
        fn new()->Self {
            let root=std::env::temp_dir().join(format!("nm-template-{}",uuid::Uuid::new_v4()));durable::directory(&root).unwrap();
            let roles=roles::Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":roles::PID,"revision":"paired-original",
                "interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]})).unwrap();
            let source=Baseline{source_digest:"a".repeat(64),roles,profiles:vec![ProfileBinding{interface:"eth0".into(),profile_uuid:None,origin_cas:None}],firewall_digest:"b".repeat(64),automatic_nat:Value::Null,native_transfer:None,firewall_fence:None,firewall_source:None};
            let id=uuid::Uuid::new_v4();let transfer=Transfer::new(&root);
            let nonce=transfer.start(id,"local-uid:fixture".into(),source.clone()).unwrap();Self{root,transfer,id,source,nonce}
        }
        fn part(&self,body:&str,index:usize,count:usize,whole:&str)->Value {
            json!({"operationId":self.id,"revision":"paired-original","depositToken":self.nonce,
                "templateSha256":durable::hash(whole.as_bytes()),"chunkIndex":index,"chunkCount":count,"ciphertextChunk":body})
        }
        fn deposit(&self,p:Value)->Result<Value> {self.transfer.deposit(p,self.source.roles.agent_instance,1)}
        fn single(&self)->Value {self.part("AAAA-BBBB",0,1,"AAAA-BBBB")}
        fn ready(&self)->Binding {self.deposit(self.single()).unwrap();self.transfer.ready(self.id,"local-uid:fixture").unwrap().0}
        fn prefix(&self,missing:bool) {
            self.ready();let (mut j,_)=self.transfer.load().unwrap().unwrap();
            j.phase=Phase::Depositing;j.next_chunk=0;j.pending=Some(ChunkIntent{index:0,sha256:durable::hash(b"AAAA-BBBB"),length:9});j.receipt_sha256=None;
            durable::json(&self.transfer.journal(),&j).unwrap();
            fs::remove_file(self.transfer.path(self.id,"chunk-0.receipt.json")).unwrap();
            fs::remove_file(self.transfer.path(self.id,"receipt.json")).unwrap();
            if missing {fs::remove_file(self.transfer.path(self.id,"chunk-0.cipher")).unwrap();}
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}}
    #[test]
    fn original_nonce_instance_epoch_and_strict_fields_are_required_before_any_deposit() {
        let f=Fixture::new();let original=read(&f.transfer.path(f.id,"intent.json")).unwrap();
        for field in ["depositToken","revision","operationId"] {
            let mut bad=f.single();bad[field]=json!(if field=="operationId" {uuid::Uuid::new_v4().to_string()} else {"forged".into()});assert!(f.deposit(bad).is_err());
        }
        for field in ["pid","ready","bridgeEpoch"] {let mut bad=f.single();bad[field]=json!(true);assert!(f.deposit(bad).is_err());}
        assert!(f.transfer.deposit(f.single(),uuid::Uuid::new_v4(),1).is_err());
        assert!(f.transfer.deposit(f.single(),f.source.roles.agent_instance,2).is_err());
        assert_eq!(f.transfer.status().unwrap()["receivedChunks"],0);
        assert!(!f.transfer.status().unwrap().to_string().contains(&f.nonce));
        assert!(f.transfer.start(f.id,"local-uid:fixture".into(),f.source.clone()).is_err());
        assert_eq!(read(&f.transfer.path(f.id,"intent.json")).unwrap(),original);
    }
    #[test]
    fn pending_and_complete_template_both_reserve_other_writers_until_actual_handover() {
        let f=Fixture::new();let whole=format!("{}-BBBB","A".repeat(CHUNK_SIZE));
        for kind in [Subsystem::Network,Subsystem::Nm,Subsystem::Firewall,Subsystem::Configuration,Subsystem::Identity,Subsystem::Recovery] {
            assert!(Guard::acquire(&f.root,kind).is_err());
        }
        assert!(Guard::acquire(&f.root,Subsystem::NmOwnership).is_ok());
        assert_eq!(f.deposit(f.part(&whole[..CHUNK_SIZE],0,2,&whole)).unwrap()["state"],"STORED");
        assert!(f.deposit(f.part(&whole[..CHUNK_SIZE],0,2,&whole)).is_err());
        assert_eq!(f.deposit(f.part(&whole[CHUNK_SIZE..],1,2,&whole)).unwrap()["state"],"EXPORTED");
        let (binding,source)=f.transfer.ready(f.id,"local-uid:fixture").unwrap();assert!(source==f.source);
        f.transfer.validate_binding(&binding).unwrap();assert!(Guard::acquire(&f.root,Subsystem::Nm).is_err());
        assert!(f.deposit(f.part(&whole[CHUNK_SIZE..],1,2,&whole)).is_err());
        assert!(f.transfer.ready(f.id,"other-actor").is_err());
    }
    #[test]
    fn received_original_chunk_can_finish_local_receipts_without_recreating_its_bytes() {
        let f=Fixture::new();f.prefix(false);
        let path=f.transfer.path(f.id,"chunk-0.cipher");let before=fs::metadata(&path).unwrap().ino();
        assert!(f.deposit(f.single()).is_err());
        assert_eq!(f.transfer.recover(f.id,"local-uid:fixture").unwrap()["state"],"READY");
        assert_eq!(fs::metadata(path).unwrap().ino(),before);f.transfer.ready(f.id,"local-uid:fixture").unwrap();
        assert!(f.deposit(f.single()).is_err());
    }
    #[test]
    fn absent_original_chunk_stays_unknown_and_is_never_fabricated_or_reaccepted() {
        let f=Fixture::new();f.prefix(true);let path=f.transfer.path(f.id,"chunk-0.cipher");
        assert!(f.transfer.recover(f.id,"local-uid:fixture").unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));
        assert!(!path.exists());assert!(f.deposit(f.single()).is_err());
        assert!(Guard::acquire(&f.root,Subsystem::Network).is_err());
    }
    #[test]
    fn original_cancel_preserves_ready_proof_and_rejects_late_registered_chunks() {
        for ready in [false,true] {
            let f=Fixture::new();let proof=ready.then(||f.ready());
            assert!(f.transfer.cancel(f.id,"other-actor").is_err());
            assert_eq!(f.transfer.cancel(f.id,"local-uid:fixture").unwrap()["state"],"CANCELLED");
            assert!(f.deposit(f.single()).is_err());assert!(f.transfer.ready(f.id,"local-uid:fixture").is_err());
            if let Some(binding)=proof {f.transfer.validate_binding(&binding).unwrap();}
            assert!(Guard::acquire(&f.root,Subsystem::Network).is_ok());
        }
    }
    #[test]
    fn orphan_original_intent_can_only_be_cancelled_by_its_actor_without_exporting_again() {
        let f=Fixture::new();fs::remove_file(f.transfer.journal()).unwrap();
        assert!(Guard::acquire(&f.root,Subsystem::Network).is_err());
        assert!(f.transfer.cancel(f.id,"other-actor").is_err());
        assert_eq!(f.transfer.cancel(f.id,"local-uid:fixture").unwrap()["state"],"CANCELLED");
        assert!(f.deposit(f.single()).is_err());assert!(Guard::acquire(&f.root,Subsystem::Network).is_ok());
    }
    #[test]
    fn changed_or_linked_ciphertext_and_wrong_complete_hash_never_create_a_ready_lease() {
        let f=Fixture::new();let proof=f.ready();let path=f.transfer.path(f.id,"chunk-0.cipher");
        fs::write(&path,b"AAAA-CCCC").unwrap();assert!(f.transfer.validate_binding(&proof).is_err());
        fs::remove_file(&path).unwrap();let target=f.root.join("same-bytes");fs::write(&target,b"AAAA-BBBB").unwrap();
        std::os::unix::fs::symlink(&target,&path).unwrap();assert!(f.transfer.validate_binding(&proof).is_err());
        let g=Fixture::new();let mut bad=g.single();bad["templateSha256"]=json!("c".repeat(64));
        assert!(g.deposit(bad).is_err());assert!(g.transfer.ready(g.id,"local-uid:fixture").is_err());
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct Intent { schema_version:u8, operation_id:uuid::Uuid, actor:String, nonce:String, baseline:Baseline }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
enum Phase { ExportIntent, Depositing, Ready, Cancelled }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct Journal {
    schema_version:u8, operation_id:uuid::Uuid, intent_sha256:String, phase:Phase,
    manifest_sha256:Option<String>, next_chunk:usize, pending:Option<ChunkIntent>, receipt_sha256:Option<String>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct Manifest { schema_version:u8, operation_id:uuid::Uuid, revision:String, template_sha256:String, chunk_count:usize }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct ChunkIntent { index:usize, sha256:String, length:usize }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct ChunkReceipt { schema_version:u8, operation_id:uuid::Uuid, intent_sha256:String, manifest_sha256:String, chunk:ChunkIntent }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct Receipt { schema_version:u8, operation_id:uuid::Uuid, intent_sha256:String, manifest_sha256:String, template_sha256:String, chunk_count:usize }
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all="camelCase")]
struct Deposit { operation_id:String, revision:String, deposit_token:String, template_sha256:String, chunk_index:usize, chunk_count:usize, ciphertext_chunk:String }
pub(crate) enum Admission { Empty, Pending, Ready(Binding), Cancelled }
pub(crate) struct Transfer { root:PathBuf }

pub(crate) fn operation(value:&str)->Result<uuid::Uuid> {
    let id=uuid::Uuid::parse_str(value).context("INVALID_ARGUMENT: original template operation")?;
    ensure!(!id.is_nil() && id.to_string()==value,"INVALID_ARGUMENT: original template operation");Ok(id)
}
impl Transfer {
    pub(crate) fn new(root:&Path)->Self {Self{root:root.join("nm-template")}}
    fn journal(&self)->PathBuf {self.root.join("transaction.json")}
    fn path(&self,id:uuid::Uuid,suffix:&str)->PathBuf {self.root.join(format!("{id}.{suffix}"))}
    fn original(&self,j:&Journal)->Result<Intent> {
        let bytes=read(&self.path(j.operation_id,"intent.json"))?;
        ensure!(durable::hash(&bytes)==j.intent_sha256,"CONFLICT: original template intent changed");
        let i:Intent=serde_json::from_slice(&bytes)?;
        ensure!(i.schema_version==1 && i.operation_id==j.operation_id && !i.actor.is_empty() && i.actor.len()<=256
            && i.actor.bytes().all(|b|b.is_ascii_graphic()) && hex(&i.nonce,64),"CONFLICT: original template intent identity");
        i.baseline.validate()?;Ok(i)
    }
    fn load(&self)->Result<Option<(Journal,Intent)>> {
        if !private_directory(&self.root)? {return Ok(None);}
        if !self.journal().try_exists()? {
            ensure!(fs::read_dir(&self.root)?.next().is_none(),"OUTCOME_UNKNOWN: orphan original template evidence");
            return Ok(None);
        }
        let j:Journal=serde_json::from_slice(&read(&self.journal())?)?;
        ensure!(j.schema_version==1 && !j.operation_id.is_nil() && hex(&j.intent_sha256,64)
            && j.next_chunk<=CIPHER_LIMIT/CHUNK_SIZE,"CONFLICT: original template journal identity");
        let i=self.original(&j)?;
        if let Some(m)=self.manifest(&j,&i)? {
            ensure!(j.next_chunk<=m.chunk_count,"CONFLICT: template chunk progress");
            for index in 0..j.next_chunk {self.verify_chunk(&j,index,None)?;}
            if let Some(p)=&j.pending {
                ensure!(p.index==j.next_chunk && p.index<m.chunk_count && p.length>0 && p.length<=CHUNK_SIZE
                    && (p.index+1==m.chunk_count || p.length==CHUNK_SIZE) && hex(&p.sha256,64)
                    && j.phase==Phase::Depositing,"CONFLICT: original deposit pre-intent");
            }
            if j.receipt_sha256.is_some() {self.complete(&j,&m)?;}
        } else {
            ensure!(j.next_chunk==0 && j.pending.is_none() && j.receipt_sha256.is_none()
                && matches!(j.phase,Phase::ExportIntent|Phase::Cancelled),"CONFLICT: template manifest missing");
        }
        if !matches!(j.phase,Phase::Ready|Phase::Cancelled) {ensure!(j.receipt_sha256.is_none(),"CONFLICT: unexpected ready template receipt");}
        if j.phase==Phase::Ready {ensure!(j.receipt_sha256.is_some(),"CONFLICT: ready template receipt missing");}
        if j.phase==Phase::Cancelled {
            ensure!(read(&self.path(j.operation_id,"cancel.json"))?==self.cancel_bytes(&j)?,"CONFLICT: original cancellation receipt changed");
        }
        Ok(Some((j,i)))
    }
    fn manifest(&self,j:&Journal,i:&Intent)->Result<Option<Manifest>> {
        let Some(hash)=&j.manifest_sha256 else {return Ok(None)};
        ensure!(hex(hash,64),"CONFLICT: template manifest hash");
        let bytes=read(&self.path(j.operation_id,"manifest.json"))?;
        ensure!(durable::hash(&bytes)==*hash,"CONFLICT: original template manifest changed");
        let m:Manifest=serde_json::from_slice(&bytes)?;
        ensure!(m.schema_version==1 && m.operation_id==j.operation_id && m.revision==i.baseline.roles.roles.revision
            && hex(&m.template_sha256,64) && (1..=CIPHER_LIMIT/CHUNK_SIZE).contains(&m.chunk_count),
            "CONFLICT: template manifest identity");Ok(Some(m))
    }
    fn authorize(j:&Journal,i:&Intent,id:uuid::Uuid,actor:&str)->Result<()> {
        ensure!(j.operation_id==id && i.actor==actor,"FORBIDDEN: original template actor and operation required");Ok(())
    }
    fn chunk_receipt(j:&Journal,part:ChunkIntent)->Result<ChunkReceipt> {
        Ok(ChunkReceipt{schema_version:1,operation_id:j.operation_id,intent_sha256:j.intent_sha256.clone(),
            manifest_sha256:j.manifest_sha256.clone().context("CONFLICT: template manifest missing")?,chunk:part})
    }
    fn verify_chunk(&self,j:&Journal,index:usize,expected:Option<&ChunkIntent>)->Result<Vec<u8>> {
        let receipt:ChunkReceipt=serde_json::from_slice(&read(&self.path(j.operation_id,&format!("chunk-{index}.receipt.json")))?)?;
        let file=BoundFile::open(&self.path(j.operation_id,&format!("chunk-{index}.cipher")),CHUNK_SIZE as u64)?;
        ensure!(receipt.schema_version==1 && receipt.operation_id==j.operation_id && receipt.intent_sha256==j.intent_sha256
            && Some(&receipt.manifest_sha256)==j.manifest_sha256.as_ref() && receipt.chunk.index==index
            && receipt.chunk.length==file.bytes.len() && receipt.chunk.sha256==durable::hash(&file.bytes)
            && expected.is_none_or(|p|*p==receipt.chunk),"CONFLICT: original stored template chunk changed");
        Ok(file.bytes)
    }
    fn complete(&self,j:&Journal,m:&Manifest)->Result<Binding> {
        ensure!(j.next_chunk==m.chunk_count && j.pending.is_none(),"OUTCOME_UNKNOWN: original template is incomplete");
        let mut bytes=Vec::new();
        for index in 0..m.chunk_count {
            let part=self.verify_chunk(j,index,None)?;
            ensure!(!part.is_empty() && part.len()<=CHUNK_SIZE && (index+1==m.chunk_count || part.len()==CHUNK_SIZE),"CONFLICT: template chunk size");
            bytes.extend_from_slice(&part);
        }
        ensure!(bytes.len()<=CIPHER_LIMIT && durable::hash(&bytes)==m.template_sha256
            && bytes.iter().filter(|b|**b==b'-').count()==1
            && bytes.iter().all(|b|b.is_ascii_alphanumeric() || b"+/=-".contains(b)),"CONFLICT: complete original ciphertext hash/format");
        let receipt=self.ready_receipt(j,m)?;
        let stored=read(&self.path(j.operation_id,"receipt.json"))?;
        ensure!(stored==serde_json::to_vec(&receipt)? && j.receipt_sha256.as_deref()==Some(durable::hash(&stored).as_str()),
            "CONFLICT: original template receipt changed");
        Ok(Binding{operation_id:j.operation_id,intent_sha256:j.intent_sha256.clone(),manifest_sha256:receipt.manifest_sha256,
            template_sha256:m.template_sha256.clone(),receipt_sha256:durable::hash(&stored),chunk_count:m.chunk_count})
    }
    fn ready_receipt(&self,j:&Journal,m:&Manifest)->Result<Receipt> {
        Ok(Receipt{schema_version:1,operation_id:j.operation_id,intent_sha256:j.intent_sha256.clone(),
            manifest_sha256:j.manifest_sha256.clone().context("template manifest")?,template_sha256:m.template_sha256.clone(),chunk_count:m.chunk_count})
    }
    fn finish(&self,j:&mut Journal,m:&Manifest)->Result<()> {
        if j.next_chunk!=m.chunk_count {return Ok(());}
        let bytes=serde_json::to_vec(&self.ready_receipt(j,m)?)?;
        let path=self.path(j.operation_id,"receipt.json");
        if path.try_exists()? {let f=BoundFile::open(&path,LIMIT)?;ensure!(f.bytes==bytes,"CONFLICT: foreign template receipt");f.sync_exact()?;}
        else {durable::publish_new(&path,&bytes,FileMetadata::private())?;}
        j.receipt_sha256=Some(durable::hash(&bytes));self.complete(j,m)?;
        j.phase=Phase::Ready;durable::json(&self.journal(),j)
    }
    pub(in crate::nm) fn start(&self,id:uuid::Uuid,actor:String,baseline:Baseline)->Result<String> {
        ensure!(!id.is_nil() && !actor.is_empty() && actor.len()<=256 && actor.bytes().all(|b|b.is_ascii_graphic()),"INVALID_ARGUMENT: template identity");
        baseline.validate()?;ensure!(self.load()?.is_none(),"OUTCOME_UNKNOWN: query original template export");
        durable::directory(&self.root)?;
        let nonce=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
        let intent=Intent{schema_version:1,operation_id:id,actor,nonce:nonce.clone(),baseline};let bytes=serde_json::to_vec(&intent)?;
        durable::publish_new(&self.path(id,"intent.json"),&bytes,FileMetadata::private())?;
        durable::publish_new(&self.journal(),&serde_json::to_vec(&Journal{schema_version:1,operation_id:id,intent_sha256:durable::hash(&bytes),
            phase:Phase::ExportIntent,manifest_sha256:None,next_chunk:0,pending:None,receipt_sha256:None})?,FileMetadata::private())?;
        Ok(nonce)
    }
    pub(crate) fn deposit(&self,value:Value,agent:uuid::Uuid,epoch:u64)->Result<Value> {
        let p:Deposit=serde_json::from_value(value).context("INVALID_ARGUMENT: template deposit fields")?;let id=operation(&p.operation_id)?;
        let (mut j,i)=self.load()?.context("FORBIDDEN: original template export not admitted")?;
        ensure!(j.operation_id==id && agent==i.baseline.roles.agent_instance && epoch==i.baseline.roles.bridge_epoch
            && p.deposit_token==i.nonce && p.revision==i.baseline.roles.roles.revision,"FORBIDDEN: original registered template source required");
        ensure!(matches!(j.phase,Phase::ExportIntent|Phase::Depositing) && j.pending.is_none() && p.chunk_index==j.next_chunk,
            "OUTCOME_UNKNOWN: query original chunk; never repeat a deposit");
        ensure!(hex(&p.template_sha256,64) && (1..=CIPHER_LIMIT/CHUNK_SIZE).contains(&p.chunk_count)
            && p.chunk_index<p.chunk_count && !p.ciphertext_chunk.is_empty() && p.ciphertext_chunk.len()<=CHUNK_SIZE
            && (p.chunk_index+1==p.chunk_count || p.ciphertext_chunk.len()==CHUNK_SIZE)
            && p.ciphertext_chunk.bytes().all(|b|b.is_ascii_alphanumeric() || b"+/=-".contains(&b)),"INVALID_ARGUMENT: template chunk bounds");
        let m=Manifest{schema_version:1,operation_id:id,revision:p.revision,template_sha256:p.template_sha256,chunk_count:p.chunk_count};
        if let Some(prior)=self.manifest(&j,&i)? {ensure!(prior==m,"CONFLICT: original template manifest differs");}
        else {
            let bytes=serde_json::to_vec(&m)?;
            durable::publish_new(&self.path(id,"manifest.json"),&bytes,FileMetadata::private())?;
            j.manifest_sha256=Some(durable::hash(&bytes));
        }
        let part=ChunkIntent{index:p.chunk_index,length:p.ciphertext_chunk.len(),sha256:durable::hash(p.ciphertext_chunk.as_bytes())};
        j.phase=Phase::Depositing;j.pending=Some(part.clone());durable::json(&self.journal(),&j)?;
        durable::publish_new(&self.path(id,&format!("chunk-{}.cipher",p.chunk_index)),p.ciphertext_chunk.as_bytes(),FileMetadata::private())?;
        durable::publish_new(&self.path(id,&format!("chunk-{}.receipt.json",p.chunk_index)),&serde_json::to_vec(&Self::chunk_receipt(&j,part)?)?,FileMetadata::private())?;
        j.next_chunk+=1;j.pending=None;durable::json(&self.journal(),&j)?;self.finish(&mut j,&m)?;
        Ok(json!({"schemaVersion":1,"operationId":id,"templateSha256":m.template_sha256,"chunkIndex":p.chunk_index,
            "state":if j.phase==Phase::Ready {"EXPORTED"} else {"STORED"}}))
    }
    pub(crate) fn recover(&self,id:uuid::Uuid,actor:&str)->Result<Value> {
        if !self.journal().try_exists()? && self.path(id,"cancel.json").try_exists()? {
            let (mut j,_,_)=self.cancellable(id,actor)?;
            let f=BoundFile::open(&self.path(id,"cancel.json"),LIMIT)?;
            ensure!(f.bytes==self.cancel_bytes(&j)?,"CONFLICT: orphan cancellation receipt differs");f.sync_exact()?;
            j.phase=Phase::Cancelled;durable::publish_new(&self.journal(),&serde_json::to_vec(&j)?,FileMetadata::private())?;
            return self.status();
        }
        let (mut j,i)=self.load()?.context("NOT_FOUND: original template export")?;Self::authorize(&j,&i,id,actor)?;
        if j.phase!=Phase::Cancelled && self.path(id,"cancel.json").try_exists()? {
            let f=BoundFile::open(&self.path(id,"cancel.json"),LIMIT)?;
            ensure!(f.bytes==self.cancel_bytes(&j)?,"CONFLICT: original cancellation receipt differs");f.sync_exact()?;
            j.phase=Phase::Cancelled;j.pending=None;durable::json(&self.journal(),&j)?;return self.status();
        }
        if !matches!(j.phase,Phase::Ready|Phase::Cancelled) {
            if let Some(part)=j.pending.clone() {
                let data=BoundFile::open(&self.path(id,&format!("chunk-{}.cipher",part.index)),CHUNK_SIZE as u64)
                    .map_err(|_|anyhow::anyhow!("OUTCOME_UNKNOWN: original received chunk missing"))?;
                ensure!(data.bytes.len()==part.length && durable::hash(&data.bytes)==part.sha256,"CONFLICT: original received chunk differs");
                data.sync_exact()?;
                let bytes=serde_json::to_vec(&Self::chunk_receipt(&j,part.clone())?)?;
                let path=self.path(id,&format!("chunk-{}.receipt.json",part.index));
                if path.try_exists()? {let f=BoundFile::open(&path,LIMIT)?;ensure!(f.bytes==bytes,"CONFLICT: original chunk receipt differs");f.sync_exact()?;}
                else {durable::publish_new(&path,&bytes,FileMetadata::private())?;}
                j.next_chunk+=1;j.pending=None;durable::json(&self.journal(),&j)?;
            }
            if let Some(m)=self.manifest(&j,&i)? {self.finish(&mut j,&m)?;}
        }
        self.status()
    }
    pub(in crate::nm) fn ready(&self,id:uuid::Uuid,actor:&str)->Result<(Binding,Baseline)> {
        let (j,i)=self.load()?.context("NOT_FOUND: original template")?;Self::authorize(&j,&i,id,actor)?;
        ensure!(j.phase==Phase::Ready,"OUTCOME_UNKNOWN: original complete template not confirmed");
        let m=self.manifest(&j,&i)?.context("CONFLICT: template manifest missing")?;Ok((self.complete(&j,&m)?,i.baseline))
    }
    pub(crate) fn validate_binding(&self,expected:&Binding)->Result<()> {
        let (j,i)=self.load()?.context("CONFLICT: bound original template missing")?;
        let m=self.manifest(&j,&i)?.context("CONFLICT: bound template manifest missing")?;
        ensure!(&self.complete(&j,&m)?==expected,"CONFLICT: bound original template changed");Ok(())
    }
    pub(in crate::nm) fn confirmed_chunk(&self,expected:&Binding,index:usize)->Result<String> {
        let (j,i)=self.load()?.context("CONFLICT: original confirmed template missing")?;
        ensure!(j.phase==Phase::Ready,"CONFLICT: original template no longer ready");
        let m=self.manifest(&j,&i)?.context("CONFLICT: original template manifest missing")?;
        ensure!(&self.complete(&j,&m)?==expected && index<m.chunk_count,"CONFLICT: original confirmed chunk identity");
        Ok(String::from_utf8(self.verify_chunk(&j,index,None)?)?)
    }
    pub(crate) fn cancel(&self,id:uuid::Uuid,actor:&str)->Result<Value> {
        let (mut j,_,orphan)=self.cancellable(id,actor)?;
        // The ownership controller first proves no fence was dispatched. Retain
        // all original ciphertext/ready receipts even after cancellation.
        if j.phase==Phase::Cancelled {return self.status();}
        durable::publish_new(&self.path(id,"cancel.json"),&self.cancel_bytes(&j)?,FileMetadata::private())?;
        j.phase=Phase::Cancelled;j.pending=None;
        if orphan {durable::publish_new(&self.journal(),&serde_json::to_vec(&j)?,FileMetadata::private())?;}
        else {durable::json(&self.journal(),&j)?;}
        self.status()
    }
    fn cancellable(&self,id:uuid::Uuid,actor:&str)->Result<(Journal,Intent,bool)> {
        if private_directory(&self.root)? && !self.journal().try_exists()? {
            let allowed=[format!("{id}.intent.json"),format!("{id}.cancel.json")];
            for entry in fs::read_dir(&self.root)? {
                ensure!(allowed.iter().any(|name|entry.as_ref().is_ok_and(|e|e.file_name()==std::ffi::OsStr::new(name))),
                    "CONFLICT: foreign orphan template evidence; preserve state");
            }
            let bytes=read(&self.path(id,"intent.json"))?;
            let j=Journal{schema_version:1,operation_id:id,intent_sha256:durable::hash(&bytes),phase:Phase::ExportIntent,
                manifest_sha256:None,next_chunk:0,pending:None,receipt_sha256:None};
            let i=self.original(&j)?;Self::authorize(&j,&i,id,actor)?;return Ok((j,i,true));
        }
        let (j,i)=self.load()?.context("NOT_FOUND: original template")?;Self::authorize(&j,&i,id,actor)?;Ok((j,i,false))
    }
    fn cancel_bytes(&self,j:&Journal)->Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"schemaVersion":1,"operationId":j.operation_id,"intentSha256":j.intent_sha256,
            "state":"CANCELLED","readyReceiptSha256":j.receipt_sha256}))?)
    }
    pub(crate) fn status(&self)->Result<Value> {
        let Some((j,_))=self.load()? else {return Ok(json!({"schemaVersion":1,"state":"UNMANAGED"}));};
        Ok(json!({"schemaVersion":1,"operationId":j.operation_id,"state":j.phase,"receivedChunks":j.next_chunk}))
    }
    pub(crate) fn admission(&self)->Result<Admission> {
        let Some((j,i))=self.load()? else {return Ok(Admission::Empty)};
        Ok(match j.phase {
            Phase::Cancelled=>Admission::Cancelled,
            Phase::Ready=>Admission::Ready(self.complete(&j,&self.manifest(&j,&i)?.context("template manifest")?)?),
            _=>Admission::Pending,
        })
    }
}
