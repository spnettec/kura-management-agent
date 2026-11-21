//! Process-lifetime serialization of one original's effects. The persistent
//! anchor binds the lock inode; neither an UNKNOWN query nor restart recreates
//! a missing or replaced lock. This lease never grants system ownership.
use super::*;
use std::io::Write;

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Anchor {schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,lock:MarkerIdentity}

pub(super) struct Execution {lock:BoundFile,anchor:BoundFile,identity:MarkerIdentity}
impl Execution {
    pub(super) fn acquire(root:&Path,plan:&Plan,journal:&Journal)->Result<Self> {
        let path=root.join(format!("{}.startup-execution.lock",plan.operation_id));
        let anchor_path=root.join(format!("{}.startup-execution-identity.json",plan.operation_id));
        let expected=serde_json::to_vec(&json!({"schemaVersion":1,"operationId":plan.operation_id,"startupPlanSha256":journal.plan_sha256}))?;
        let (has_lock,has_anchor)=(present(&path)?,present(&anchor_path)?);
        ensure!(has_lock==has_anchor,"OUTCOME_UNKNOWN: original execution lock binding is incomplete; retain it for inspection");
        let lock=if has_lock {
            let lock=BoundFile::open(&path,4096)?;
            ensure!(unsafe{libc::flock(lock.file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0,
                "CONFLICT: original startup action is still executing");lock
        }else{
            let directory=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(root)?;
            let info=directory.metadata()?;
            ensure!(info.is_dir() && info.uid()==unsafe{libc::geteuid()} && info.mode()&0o077==0,
                "FORBIDDEN: private original execution directory required");
            let name=std::ffi::CString::new(path.file_name().context("execution filename")?.as_bytes())?;
            let fd=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,0o600)};
            ensure!(fd>=0,"OUTCOME_UNKNOWN: original execution lock creation uncertain; retain original evidence");
            let mut file=unsafe{File::from_raw_fd(fd)};
            ensure!(unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0,
                "CONFLICT: original startup execution lock unavailable");
            file.write_all(&expected)?;file.sync_all()?;directory.sync_all()?;
            let observed=file.metadata()?;
            let lock=BoundFile{path:path.clone(),directory,file,bytes:expected.clone(),observed};
            lock.verify_binding()?;
            let anchor=Anchor{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:journal.plan_sha256.clone(),lock:lock.marker()?};
            durable::publish_new(&anchor_path,&serde_json::to_vec(&anchor)?,FileMetadata::private())
                .context("OUTCOME_UNKNOWN: original execution inode binding publication uncertain")?;
            lock
        };
        ensure!(lock.bytes==expected,"CONFLICT: original startup execution lock belongs to another review");
        let anchor=BoundFile::open(&anchor_path,4096)?;let stored:Anchor=serde_json::from_slice(&anchor.bytes)?;
        ensure!(stored.schema_version==1 && stored.operation_id==plan.operation_id && stored.startup_plan_sha256==journal.plan_sha256
            && stored.lock==lock.marker()?,"CONFLICT: original execution lock inode was replaced");
        let result=Self{lock,anchor,identity:stored.lock};result.verify()?;Ok(result)
    }
    pub(super) fn verify(&self)->Result<()> {
        self.anchor.verify_binding()?;
        ensure!(self.lock.marker()?==self.identity,"CONFLICT: original execution lease changed during action");Ok(())
    }
}

impl Drop for Execution {
    fn drop(&mut self) {
        // A concurrently forked child can retain the open file description until exec.
        // The command owns the lease and releases it when its own work ends.
        unsafe { libc::flock(self.lock.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_action_releases_its_lock_while_a_descriptor_copy_is_open() -> Result<()> {
        let root = std::env::temp_dir().join(format!("startup-lease-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        let path = root.join("original.lock");
        let anchor_path = root.join("original.identity");
        durable::publish_new(&path, b"original", FileMetadata::private())?;
        durable::publish_new(&anchor_path, b"identity", FileMetadata::private())?;
        let lock = BoundFile::open(&path, 4096)?;
        let held_copy = lock.file.try_clone()?;
        assert_eq!(unsafe { libc::flock(lock.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let identity = lock.marker()?;
        let lease = Execution { lock, anchor: BoundFile::open(&anchor_path, 4096)?, identity };
        let next = File::open(&path)?;
        let acquire = || unsafe { libc::flock(next.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(acquire(), 0);
        drop(lease);
        let result = acquire();
        drop(held_copy);
        drop(next);
        fs::remove_dir_all(root)?;
        assert_eq!(result, 0, "a completed action must release ownership before a descriptor copy closes");
        Ok(())
    }
}
