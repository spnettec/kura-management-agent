//! File-set compensation follows a proven CM inverse. It never releases writes
//! or starts Kura, and every removed active candidate is atomically retained.
use super::*;
use std::{collections::BTreeSet, os::unix::fs::DirBuilderExt};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Plan {
    pub id: String,
    pub(super) confirm_token: String,
    pub(super) archive_dir: String,
    source_journal_sha256: String,
    backup_manifest_sha256: String,
    expected: Vec<SnapshotFile>,
    pub issued: bool,
    moved: Vec<String>,
    pub applied: bool,
    pub receipt_sha256: Option<String>,
}
const RETENTION_NAME: &str = ".recovery-retained";
const RETENTION_MARKER: &[u8] = b"yofc.agent.snapshot-retention.v1\n";

pub(super) fn retained_directory(path: &std::path::Path) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o077 == 0,
        "CONFLICT: unsafe snapshot retention root"
    );
    let (marker, metadata) = durable::read(&path.join("owner"), 128)?;
    ensure!(
        marker == RETENTION_MARKER && metadata.uid == info.uid() && metadata.mode & 0o077 == 0,
        "CONFLICT: snapshot retention ownership marker changed"
    );
    Ok(())
}

impl Recovery {
    pub(super) fn retained_snapshot_path(&self, j: &Journal, target: &str) -> Result<PathBuf> {
        let live = self.0.root.join(target);
        let Some(plan) = j
            .inverse
            .as_ref()
            .and_then(|i| i.snapshot_set.as_ref())
            .filter(|p| p.issued)
        else {
            return Ok(live);
        };
        let inverse = j.inverse.as_ref().context("inverse missing")?;
        ensure!(
            target == j.target || target == inverse.target,
            "CONFLICT: unrelated retained artifact"
        );
        let archive = self
            .snapshot_archive(plan)?
            .join(live.file_name().context("retained name")?);
        let exists = |p: &std::path::Path| -> Result<bool> {
            match fs::symlink_metadata(p) {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e.into()),
            }
        };
        let (a, b) = (exists(&live)?, exists(&archive)?);
        ensure!(a != b, "CONFLICT: retained snapshot location is ambiguous");
        Ok(if a { live } else { archive })
    }
    pub(super) fn snapshot_archive(&self, plan: &Plan) -> Result<PathBuf> {
        ensure!(
            plan.id
                .strip_prefix("set-")
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
                && plan.archive_dir == format!("{RETENTION_NAME}/{}", plan.id),
            "CONFLICT: snapshot retention identity"
        );
        let root = self.snapshots()?.join(RETENTION_NAME);
        retained_directory(&root)?;
        let path = self.snapshots()?.join(&plan.archive_dir);
        let info = fs::symlink_metadata(&path)?;
        ensure!(
            info.is_dir()
                && info.uid() == unsafe { libc::geteuid() }
                && info.mode() & 0o077 == 0
                && info.dev() == fs::metadata(self.snapshots()?)?.dev(),
            "CONFLICT: snapshot retention directory"
        );
        Ok(path)
    }
    pub(super) fn snapshot_receipt(&self, plan: &Plan) -> PathBuf {
        self.0
            .state
            .join("receipts")
            .join(format!("{}.snapshots.json", plan.id))
    }
    fn verify_snapshot_backup(&self, j: &Journal) -> Result<String> {
        ensure!(
            j.schema_version == 2 && j.backup_ready && j.backup_dir == format!("backups/{}", j.id),
            "CONFLICT: original snapshot backup unavailable"
        );
        let dir = self.0.state.join(&j.backup_dir);
        let bytes = durable::read(&dir.join("manifest.json"), 1 << 20)?.0;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest.schema_version == 2 && manifest.files == j.base,
            "CONFLICT: snapshot backup manifest changed"
        );
        let mut names = BTreeSet::from(["manifest.json".to_owned()]);
        for file in &j.base {
            ensure!(
                safe_name(&file.name) && names.insert(file.name.clone()),
                "CONFLICT: snapshot backup identity"
            );
            let data = durable::read(&dir.join(&file.name), LIMIT_BYTES)?.0;
            ensure!(
                data.len() as u64 == file.size && durable::hash(&data) == file.sha256,
                "CONFLICT: snapshot backup data changed"
            );
        }
        let actual = fs::read_dir(&dir)?
            .map(|e| {
                e?.file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("snapshot backup encoding"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(actual == names, "CONFLICT: unknown snapshot backup entry");
        Ok(durable::hash(&bytes))
    }
    fn verify_snapshot_anchor(&self, j: &Journal, inverse: &Inverse, plan: &Plan) -> Result<()> {
        let bytes = durable::read(
            &self
                .0
                .state
                .join("receipts")
                .join(format!("{}.snapshot-source.json", plan.id)),
            1 << 20,
        )?
        .0;
        ensure!(
            durable::hash(&bytes) == plan.source_journal_sha256,
            "CONFLICT: snapshot source anchor changed"
        );
        let source: Journal = serde_json::from_slice(&bytes)?;
        let original = source
            .inverse
            .context("CONFLICT: snapshot source has no inverse")?;
        ensure!(
            source.id == j.id
                && source.base == j.base
                && source.target == j.target
                && source.sha256 == j.sha256
                && source.controlled_startup == j.controlled_startup
                && source.cm_application == j.cm_application
                && source.target_metadata == j.target_metadata
                && source.backup_dir == j.backup_dir
                && source.unit == j.unit
                && source.snapshot_validation == j.snapshot_validation
                && source.size == j.size
                && original.issued == inverse.issued
                && original.id == inverse.id
                && original.unit == inverse.unit
                && original.target == inverse.target
                && original.sha256 == inverse.sha256
                && original.base == inverse.base
                && original.startup == inverse.startup
                && original.application == inverse.application
                && original.parameters == inverse.parameters
                && original.source_application == inverse.source_application
                && original.source_partial == inverse.source_partial
                && original.source_journal_sha256 == inverse.source_journal_sha256
                && original.snapshot_set.is_none(),
            "CONFLICT: snapshot source identity changed"
        );
        Ok(())
    }
    fn verify_snapshot_evidence(&self, j: &Journal, inverse: &Inverse) -> Result<()> {
        self.verify_inverse_source_anchor(j, inverse)?;
        // The active inventory check applies before moving files; the source anchor
        // and all application sidecars remain mandatory after retention as well.
        ensure!(
            self.0.units.contains(&j.unit) && self.0.units.contains(&inverse.unit),
            "FORBIDDEN: snapshot units no longer allowed"
        );
        ensure!(
            self.source_proof(j)? == inverse.source_proof()?,
            "CONFLICT: snapshot forward evidence changed"
        );
        let startup = self
            .0
            .inverse_startup
            .as_ref()
            .context("FORBIDDEN: inverse profile disabled")?;
        startup.verify_prepared(
            &inverse.startup,
            &inverse.unit,
            &inverse.id,
            &self.0.root.join(&inverse.target),
            &inverse.sha256,
            &inverse.parameters,
        )?;
        let owner = j.target_metadata.context("snapshot owner missing")?;
        let actual = startup.application(&inverse.startup, &inverse.id, &inverse.sha256, owner)?;
        ensure!(
            Some(actual) == inverse.application
                && inverse
                    .application
                    .as_ref()
                    .and_then(|a| a.compensation.as_ref())
                    .is_some(),
            "CONFLICT: snapshot inverse evidence changed"
        );
        let (bytes, metadata) = durable::read(
            &self.retained_snapshot_path(j, &inverse.target)?,
            LIMIT_BYTES,
        )?;
        ensure!(
            durable::hash(&bytes) == inverse.sha256 && metadata == owner,
            "CONFLICT: retained inverse changed"
        );
        ensure!(
            durable::hash(&self.inverse_payload(j)?) == inverse.sha256,
            "CONFLICT: snapshot inverse source changed"
        );
        Ok(())
    }
    pub(super) fn verify_snapshot_set(
        &self,
        j: &Journal,
        plan: &Plan,
        restored: bool,
    ) -> Result<()> {
        let inverse = j.inverse.as_ref().context("CONFLICT: inverse missing")?;
        self.verify_snapshot_anchor(j, inverse, plan)?;
        ensure!(
            self.verify_snapshot_backup(j)? == plan.backup_manifest_sha256,
            "CONFLICT: snapshot backup fingerprint changed"
        );
        self.verify_snapshot_evidence(j, inverse)?;
        let archive = self.snapshot_archive(plan)?;
        if restored {
            ensure!(
                self.inventory()? == j.base,
                "CONFLICT: original snapshot set not restored"
            );
            let expected = [
                self.0.root.join(&j.target),
                self.0.root.join(&inverse.target),
            ]
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
            let actual = fs::read_dir(&archive)?
                .map(|e| Ok(e?.file_name().to_str().context("archive name")?.to_owned()))
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                actual == expected
                    && plan.moved.iter().cloned().collect::<BTreeSet<_>>() == expected,
                "CONFLICT: retained snapshot set incomplete"
            );
        } else {
            ensure!(
                !plan.issued
                    && self.inventory()? == plan.expected
                    && fs::read_dir(archive)?.next().is_none(),
                "CONFLICT: live snapshot set drifted before retention"
            );
            self.verify_inverse(j, inverse, true)?;
        }
        Ok(())
    }
    pub(super) fn recover_snapshot_set(&self, j: &mut Journal) -> Result<()> {
        let plan = j
            .inverse
            .as_ref()
            .and_then(|i| i.snapshot_set.clone())
            .context("snapshot plan missing")?;
        let proof: Result<()> = (|| {
            ensure!(
                j.state == State::AwaitingSnapshotCompletion && plan.issued && plan.applied,
                "CONFLICT: snapshot retention interrupted"
            );
            self.verify_snapshot_set(j, &plan, true)?;
            self.stopped(&j.unit)?;
            self.stopped(&j.inverse.as_ref().unwrap().unit)?;
            let bytes = durable::read(&self.snapshot_receipt(&plan), 1 << 20)?.0;
            ensure!(
                Some(durable::hash(&bytes)) == plan.receipt_sha256,
                "CONFLICT: snapshot receipt changed"
            );
            Ok(())
        })();
        if proof.is_err() {
            self.retain_inverse_failure(j)?;
        }
        ensure!(
            j.state == State::AwaitingSnapshotCompletion,
            "CONFLICT: snapshot retention requires explicit operator action"
        );
        Ok(())
    }
    pub async fn prepare_snapshot_set(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j=this.journal()?.context("CONFLICT: no recovery transaction")?;
            let inverse=j.inverse.as_ref().context("CONFLICT: no CM inverse")?;
            ensure!(inverse.id == id && inverse.confirm_token == token,"FORBIDDEN: inverse transaction/token");
            ensure!(matches!(j.state,State::AwaitingCompensationCompletion|State::RecoveryRequired)
                && inverse.issued && inverse.application.is_some() && inverse.snapshot_set.is_none(),
                "CONFLICT: snapshot set cannot be prepared");
            this.verify_inverse(&j,inverse,true)?;this.verify_snapshot_evidence(&j,inverse)?;
            let backup_manifest_sha256=this.verify_snapshot_backup(&j)?;
            let expected=this.inventory()?;let id=format!("set-{}",uuid::Uuid::new_v4());
            let parent=this.snapshots()?.join(RETENTION_NAME);
            match fs::symlink_metadata(&parent) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::DirBuilder::new().mode(0o700).create(&parent)?;
                    durable::publish_new(&parent.join("owner"),RETENTION_MARKER,FileMetadata::private())?;
                    durable::sync_directory(parent.parent().unwrap())?;
                }
                Ok(_) => retained_directory(&parent)?,
                Err(e) => return Err(e.into()),
            }
            retained_directory(&parent)?;
            let archive=parent.join(&id);fs::DirBuilder::new().mode(0o700).create(&archive)?;
            durable::sync_directory(&parent)?;
            let source=serde_json::to_vec(&j)?;
            let plan=Plan{id:id.clone(),confirm_token:uuid::Uuid::new_v4().to_string(),archive_dir:format!("{RETENTION_NAME}/{id}"),
                source_journal_sha256:durable::hash(&source),backup_manifest_sha256,expected,
                issued:false,moved:Vec::new(),applied:false,receipt_sha256:None};
            this.snapshot_archive(&plan)?; // Reject cross-filesystem retention before touching units or files.
            durable::publish_new(&this.0.state.join("receipts").join(format!("{id}.snapshot-source.json")),&source,FileMetadata::private())?;
            this.verify_snapshot_set(&j,&plan,false)?;
            let token=plan.confirm_token.clone();j.inverse.as_mut().unwrap().snapshot_set=Some(plan);
            this.state(&mut j,State::SnapshotSetPrepared)?;
            Ok(json!({"transactionId":id,"state":j.state,"sourceTransactionId":j.id,
                "inverseTransactionId":inverse_id(&j),"confirmToken":token,
                "restoredFileCount":j.base.len(),"retainedCandidateCount":2,"kuraRecoveryVerified":false}))
        }).await
    }
    pub async fn execute_snapshot_set(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j=this.journal()?.context("CONFLICT: no snapshot transaction")?;
            let inverse=j.inverse.clone().context("CONFLICT: no inverse")?;
            let mut plan=inverse.snapshot_set.clone().context("CONFLICT: no prepared snapshot set")?;
            ensure!(plan.id == id && plan.confirm_token == token,"FORBIDDEN: snapshot transaction/token");
            ensure!(j.state == State::SnapshotSetPrepared && !plan.issued,"CONFLICT: snapshot retention already attempted");
            this.verify_snapshot_set(&j,&plan,false)?;
            let result: Result<()>=(|| {
                this.state(&mut j,State::RestoringSnapshotSet)?;
                this.stop(&j.unit)?;this.stop(&inverse.unit)?;
                this.verify_snapshot_set(&j,&plan,false)?;
                this.stopped(&j.unit)?;this.stopped(&inverse.unit)?;
                plan.issued=true;j.inverse.as_mut().unwrap().snapshot_set=Some(plan.clone());this.persist(&j)?;
                let archive=this.snapshot_archive(&plan)?;
                for target in [&j.target,&inverse.target] {
                    let source=this.0.root.join(target);let name=source.file_name().context("snapshot name")?.to_str().context("snapshot encoding")?.to_owned();
                    durable::move_new(&source,&archive.join(&name))?;
                    plan.moved.push(name);j.inverse.as_mut().unwrap().snapshot_set=Some(plan.clone());this.persist(&j)?;
                }
                this.verify_snapshot_set(&j,&plan,true)?;
                this.stopped(&j.unit)?;this.stopped(&inverse.unit)?;
                let receipt=serde_json::to_vec(&json!({"schema":"yofc.agent.snapshot-set.v1","transactionId":plan.id,
                    "sourceTransactionId":j.id,"inverseTransactionId":inverse.id,"state":"SNAPSHOT_SET_RESTORED",
                    "restoredFileCount":j.base.len(),"retainedCandidateCount":plan.moved.len(),
                    "backupManifestSha256":plan.backup_manifest_sha256,"kuraRecoveryVerified":false,
                    "normalBootVerified":false,"awaitsExplicitCompletion":true}))?;
                durable::publish_new(&this.snapshot_receipt(&plan),&receipt,FileMetadata::private())?;
                plan.receipt_sha256=Some(durable::hash(&receipt));plan.applied=true;
                j.inverse.as_mut().unwrap().snapshot_set=Some(plan.clone());this.state(&mut j,State::AwaitingSnapshotCompletion)
            })();
            if result.is_err() {this.retain_inverse_failure(&mut j)?;
                anyhow::bail!("CONFLICT: snapshot retention incomplete; preserve state and query, do not resend");}
            Ok(json!({"transactionId":plan.id,"state":j.state,"restoredFileCount":j.base.len(),
                "retainedCandidateCount":plan.moved.len(),"kuraRecoveryVerified":false,"normalBootVerified":false,
                "awaitsExplicitCompletion":true}))
        }).await
    }
}
fn inverse_id(j: &Journal) -> &str {
    &j.inverse.as_ref().unwrap().id
}
