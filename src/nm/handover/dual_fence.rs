//! Source-bound pair of writer barriers in the existing ownership transaction.
//! Presence suppresses a legacy writer;it never grants configuration ownership.
use super::*;

const FIREWALL_MARKER: &str = "firewall-owner-agent";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Origin {
    kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<MarkerIdentity>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Kind {
    Absent,
    Retained,
}

impl Origin {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            matches!((&self.kind, &self.identity), (Kind::Absent, None))
                || matches!((&self.kind,&self.identity),(Kind::Retained,Some(id)) if hex(&id.sha256,64)),
            "CONFLICT: original firewall fence source shape"
        );
        Ok(())
    }
}

impl Store {
    fn firewall_marker_path(&self) -> Result<PathBuf> {
        let path = self.marker.with_file_name(FIREWALL_MARKER);
        ensure!(
            path != self.marker,
            "FORBIDDEN: network/firewall fence paths alias"
        );
        let parent = fs::symlink_metadata(path.parent().context("firewall marker parent")?)?;
        ensure!(
            parent.is_dir()
                && parent.uid() == unsafe { libc::geteuid() }
                && parent.mode() & 0o022 == 0,
            "FORBIDDEN: unsafe firewall owner marker parent"
        );
        Ok(path)
    }

    pub(in crate::nm) fn observe_firewall_fence(&self) -> Result<Origin> {
        let path = self.firewall_marker_path()?;
        let origin = match fs::symlink_metadata(&path) {
            Ok(_) => Origin {
                kind: Kind::Retained,
                identity: Some(BoundFile::open(&path, 16384)?.marker()?),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Origin {
                kind: Kind::Absent,
                identity: None,
            },
            Err(e) => return Err(e.into()),
        };
        origin.validate()?;
        Ok(origin)
    }

    pub(super) fn require_original_firewall_fence(&self, plan: &Plan) -> Result<()> {
        if let Some(origin) = &plan.baseline.firewall_fence {
            ensure!(
                self.observe_firewall_fence()? == *origin,
                "CONFLICT: original firewall fence changed before dispatch"
            );
        }
        Ok(())
    }

    fn firewall_marker_bytes(journal: &Journal) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"schemaVersion":1,"kind":"yofc.firewall.owner.v1",
            "operationId":journal.operation_id,"planSha256":journal.plan_sha256}),
        )?)
    }

    pub(super) fn check_firewall_marker(
        &self,
        journal: &Journal,
        plan: &Plan,
    ) -> Result<Option<MarkerIdentity>> {
        let Some(origin) = &plan.baseline.firewall_fence else {
            return Ok(None);
        };
        origin.validate()?;
        let file = BoundFile::open(&self.firewall_marker_path()?, 16384)?;
        let identity = file.marker()?;
        match &origin.kind {
            Kind::Retained => ensure!(
                origin.identity.as_ref() == Some(&identity),
                "CONFLICT: retained firewall owner fence changed"
            ),
            Kind::Absent => ensure!(
                file.bytes == Self::firewall_marker_bytes(journal)?,
                "CONFLICT: firewall fence is not this original operation"
            ),
        }
        Ok(Some(identity))
    }

    pub(super) fn publish_firewall_fence(&self, journal: &Journal, plan: &Plan) -> Result<()> {
        let Some(origin) = &plan.baseline.firewall_fence else {
            return Ok(());
        };
        self.require_original_firewall_fence(plan)?;
        if matches!(origin.kind, Kind::Absent) {
            durable::publish_new(
                &self.firewall_marker_path()?,
                &Self::firewall_marker_bytes(journal)?,
                FileMetadata::private(),
            )
            .map_err(|_| {
                anyhow::anyhow!("OUTCOME_UNKNOWN: original firewall fence publication unconfirmed")
            })?;
        }
        // A retained barrier is pinned,never overwritten or claimed as owner
        // authority. Current Java drain and original owner proof remain required.
        self.check_firewall_marker(journal, plan)?;
        Ok(())
    }

    pub(super) fn require_pair_identity(&self, journal: &Journal, plan: &Plan) -> Result<()> {
        ensure!(
            journal.firewall_marker == self.check_firewall_marker(journal, plan)?,
            "CONFLICT: original firewall fence identity changed"
        );
        Ok(())
    }

    pub(super) fn require_lease_pair(
        &self,
        lease: &Lease,
        journal: &Journal,
        plan: &Plan,
    ) -> Result<()> {
        if plan.baseline.firewall_fence.is_some() {
            ensure!(
                plan.schema_version == if plan.baseline.native_transfer.is_some(){5}else{4}
                    && lease.schema_version == if plan.baseline.native_transfer.is_some(){5}else{4}
                    && lease.firewall_marker.is_some()
                    && lease.firewall_marker == journal.firewall_marker
                    && lease.firewall_marker == self.check_firewall_marker(journal, plan)?
                    && lease.startup_receipt_sha256.is_some()
                    && lease.owner_proof.is_some(),
                "CONFLICT: complete paired fence/startup lease proof required"
            );
        } else {
            ensure!(
                journal.firewall_marker.is_none() && lease.firewall_marker.is_none(),
                "CONFLICT: unexpected firewall fence in historical lease"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
impl Store {
    /// Generate a fresh historical schema3 record for compatibility tests. This
    /// is not reachable by a production admission or a retained operation.
    pub(in crate::nm) fn seed_historical_fenced_plan_fixture(
        &self,
        id: uuid::Uuid,
        actor: String,
        baseline: Baseline,
        binding: template::Binding,
    ) -> Result<Value> {
        ensure!(
            baseline.firewall_fence.is_none() && baseline.firewall_source.is_some(),
            "historical fixture baseline only"
        );
        let (original, source) =
            template::Transfer::new(self.root.parent().context("fixture state root")?)
                .ready(id, &actor)?;
        ensure!(
            original == binding && source == baseline,
            "historical fixture original template binding"
        );
        let prepared = self.plan_inner(id, actor, baseline, Some(binding))?;
        let (mut journal, plan) = self.load()?.unwrap();
        ensure!(plan.schema_version == 3, "historical fixture version");
        journal.state = State::FenceIntent;
        durable::json(&self.journal_path(), &journal)?;
        durable::publish_new(
            &self.marker,
            &Self::marker_bytes(&journal)?,
            FileMetadata::private(),
        )?;
        journal.marker = Some(self.check_marker(&journal)?);
        journal.state = State::Fenced;
        durable::json(&self.journal_path(), &journal)?;
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_change::{Guard, Subsystem};

    struct Fixture {
        root: PathBuf,
        store: Store,
        source: Baseline,
        id: uuid::Uuid,
        token: String,
    }
    impl Fixture {
        fn prepare(retained: bool, paired: bool) -> Self {
            let root =
                std::env::temp_dir().join(format!("nm-paired-fence-{}", uuid::Uuid::new_v4()));
            let parent = root.join("installed");
            Self::prepare_at(root, parent, retained, paired)
        }
        fn prepare_at(root: PathBuf, parent: PathBuf, retained: bool, paired: bool) -> Self {
            durable::directory(&root).unwrap();
            durable::directory(&parent).unwrap();
            let store = Store::relocated(&root, parent.join("network-owner-agent"));
            if retained {
                durable::publish_new(
                    &parent.join(FIREWALL_MARKER),
                    b"retained installation barrier\n",
                    FileMetadata::private(),
                )
                .unwrap();
            }
            let roles=roles::Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":roles::PID,"revision":"paired-source",
                "interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]})).unwrap();
            let firewall_source = roles::fixture_firewall_source(&roles);
            let origin = paired.then(|| store.observe_firewall_fence().unwrap());
            let source = Baseline {
                source_digest: Baseline::bind_pair_source(
                    &"a".repeat(64),
                    Some(&firewall_source),
                    origin.as_ref(),
                )
                .unwrap(),
                roles,
                profiles: vec![ProfileBinding {
                    interface: "eth0".into(),
                    profile_uuid: Some(uuid::Uuid::new_v4().to_string()),
                    origin_cas: Some("c".repeat(64)),
                }],
                firewall_digest: "b".repeat(64),
                automatic_nat: Value::Null,
                firewall_source: Some(firewall_source),
                firewall_fence: origin,
                native_transfer:None,
            };
            let id = uuid::Uuid::new_v4();
            let transfer = template::Transfer::new(&root);
            let nonce = transfer
                .start(id, "paired-actor".into(), source.clone())
                .unwrap();
            transfer.deposit(json!({"operationId":id,"revision":source.roles.roles.revision,"depositToken":nonce,
                "templateSha256":durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),source.roles.agent_instance,source.roles.bridge_epoch).unwrap();
            let (binding, _) = transfer.ready(id, "paired-actor").unwrap();
            let result = if paired {
                store
                    .plan_with_template(id, "paired-actor".into(), source.clone(), binding)
                    .unwrap()
            } else {
                store
                    .plan_inner(id, "paired-actor".into(), source.clone(), Some(binding))
                    .unwrap()
            };
            Self {
                root,
                store,
                source,
                id,
                token: result["confirmationToken"].as_str().unwrap().into(),
            }
        }
        fn fence(&self) -> Result<Value> {
            self.store
                .fence(&self.token, "paired-actor", || Ok(self.source.clone()))
        }
        fn intent(&self) -> (Journal, Plan) {
            let (mut journal, plan) = self.store.load().unwrap().unwrap();
            journal.state = State::FenceIntent;
            durable::json(&self.store.journal_path(), &journal).unwrap();
            (journal, plan)
        }
        fn publish_network(&self, journal: &Journal) {
            durable::publish_new(
                &self.store.marker,
                &Store::marker_bytes(journal).unwrap(),
                FileMetadata::private(),
            )
            .unwrap();
        }
    }

    #[test]
    fn unsafe_symlink_hardlink_or_public_firewall_fence_never_enters_dispatch() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for defect in ["symlink", "hardlink", "public"] {
            let f = Fixture::prepare(false, true);
            let path = f.store.firewall_marker_path().unwrap();
            let donor = f.root.join("protected-original");
            durable::publish_new(&donor, b"preserve donor", FileMetadata::private()).unwrap();
            match defect {
                "symlink" => symlink(&donor, &path).unwrap(),
                "hardlink" => fs::hard_link(&donor, &path).unwrap(),
                "public" => {
                    durable::publish_new(&path, b"public barrier", FileMetadata::private())
                        .unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => unreachable!(),
            }
            let before = read(&f.store.journal_path()).unwrap();
            assert!(f.store.observe_firewall_fence().is_err());
            assert!(f.fence().is_err());
            assert_eq!(read(&f.store.journal_path()).unwrap(), before);
            assert!(!f.store.marker.exists());
            assert_eq!(fs::read(donor).unwrap(), b"preserve donor");
        }
    }

    #[test]
    fn identical_firewall_marker_bytes_at_a_new_inode_revoke_the_original_pair() {
        let f = Fixture::prepare(false, true);
        f.fence().unwrap();
        let path = f.store.firewall_marker_path().unwrap();
        let bytes = fs::read(&path).unwrap();
        let replacement = f.root.join("replacement");
        durable::publish_new(&replacement, &bytes, FileMetadata::private()).unwrap();
        fs::rename(replacement, &path).unwrap();
        let journal = read(&f.store.journal_path()).unwrap();
        assert!(f.store.status().is_err());
        assert!(f.store.original(f.id, "paired-actor").is_err());
        assert!(
            f.store
                .recover(&f.token, "paired-actor", |_| panic!("no new action"))
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert_eq!(read(&f.store.journal_path()).unwrap(), journal);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an isolated empty Root-owned read-only mount"]
    fn installed_readonly_fence_destination_preserves_the_original_prepared_pair() {
        let mount = PathBuf::from(std::env::var_os("YOFC_READONLY_FENCE_TEST_MOUNT")
            .expect("isolated read-only mount used only for this test"));
        assert!(mount.is_absolute() && mount.canonicalize().unwrap() == mount);
        assert!(fs::read_dir(&mount).unwrap().next().is_none());
        let f = Fixture::prepare(false, true);
        let installed = Store::relocated(&f.root, mount.join("network-owner-agent"));
        let before = read(&f.store.journal_path()).unwrap();
        let refused = installed.fence(&f.token, "paired-actor", || Ok(f.source.clone())).unwrap_err();
        assert_eq!(refused.to_string(), "UNSUPPORTED: installed fence directory requires a paired Root publisher");
        assert!(fs::read_dir(&mount).unwrap().next().is_none());
        assert_eq!(read(&installed.journal_path()).unwrap(), before);
        assert_eq!(installed.status().unwrap()["state"], "PREPARED");
        assert_eq!(installed.original(f.id, "paired-actor").unwrap().unwrap()["state"], "PREPARED");
    }

    #[test]
    #[ignore = "fresh owned Rust pair/actual Java writer-lease fixture only;never replay a retained phase"]
    fn paired_fence_java_gate_fixture() {
        let root = PathBuf::from(
            std::env::var("YOFC_PAIRED_FENCE_V28_ROOT").expect("explicit owned fixture root"),
        );
        let phase = std::env::var("YOFC_PAIRED_FENCE_V28_PHASE")
            .expect("explicit prepare/fence/query phase");
        assert!(root.is_absolute());
        assert_eq!(root.canonicalize().unwrap(), root);
        let authorization = BoundFile::open(&root.join(".owned-paired-fence-v28"), 16384).unwrap();
        assert_eq!(authorization.bytes, b"YOFC_PAIRED_FENCE_V28\n");
        assert!(["prepare", "fence", "query"].contains(&phase.as_str()));
        let _once = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(format!("{phase}.invoked")))
            .unwrap();
        let world = root.join("world");
        let parent = world.join("home/framework");
        if phase == "prepare" {
            assert!(!world.exists());
            let f = Fixture::prepare_at(world, parent, false, true);
            assert!(!f.store.marker.exists());
            assert!(!f.store.firewall_marker_path().unwrap().exists());
            durable::publish_new(
                &root.join("prepare-result.json"),
                &serde_json::to_vec(
                    &json!({"state":"PREPARED","operationId":f.id,"normalAgentStarted":false}),
                )
                .unwrap(),
                FileMetadata::private(),
            )
            .unwrap();
        } else {
            let _guard = Guard::acquire(&world, Subsystem::NmOwnership).unwrap();
            let store = Store::relocated(&world, parent.join("network-owner-agent"));
            let (journal, plan) = store.load().unwrap().unwrap();
            let token = journal.token.clone();
            let source = plan.baseline.clone();
            let result = if phase == "fence" {
                store.fence(&token, "paired-actor", || Ok(source)).unwrap()
            } else {
                store
                    .recover(&token, "paired-actor", |_| {
                        panic!("original query must not probe or dispatch an owner")
                    })
                    .unwrap()
            };
            assert_eq!(result["state"], "FENCED");
            assert!(!store.artifact(journal.operation_id, "lease").exists());
            assert!(!store.root.join("confirmed.json").exists());
            durable::publish_new(&root.join(format!("{phase}-result.json")),&serde_json::to_vec(&json!({"state":"FENCED","operationId":journal.operation_id,
                "networkFenceSha256":durable::hash(&fs::read(&store.marker).unwrap()),"firewallFenceSha256":durable::hash(&fs::read(store.firewall_marker_path().unwrap()).unwrap()),
                "normalAgentStarted":false,"ownershipGranted":false})).unwrap(),FileMetadata::private()).unwrap();
        }
    }

    #[test]
    fn fresh_plan_binds_the_original_firewall_fence_before_export_and_uses_version_four() {
        for retained in [false, true] {
            let f = Fixture::prepare(retained, true);
            let (journal, plan) = f.store.load().unwrap().unwrap();
            assert_eq!(plan.schema_version, 4);
            assert!(journal.firewall_marker.is_none());
            let (binding, original) = template::Transfer::new(&f.root)
                .ready(f.id, "paired-actor")
                .unwrap();
            assert!(original == f.source);
            assert!(plan.template.as_ref() == Some(&binding));
            assert_ne!(
                f.source.source_digest,
                Baseline::bind_source(&"a".repeat(64), f.source.firewall_source.as_ref()).unwrap()
            );
            assert!(!f.store.marker.exists());
            assert!(!f.store.root.join("confirmed.json").exists());
        }
    }

    #[test]
    fn paired_fence_publishes_both_original_barriers_without_claiming_an_owner_or_changing_parent_permissions()
     {
        let f = Fixture::prepare(false, true);
        let parent = f.store.marker.parent().unwrap();
        let mode = fs::metadata(parent).unwrap().mode();
        let intent = read(&f.store.artifact(f.id, "intent")).unwrap();
        assert_eq!(f.fence().unwrap()["state"], "FENCED");
        let (journal, plan) = f.store.load().unwrap().unwrap();
        assert_eq!(fs::metadata(parent).unwrap().mode(), mode);
        assert_eq!(fs::metadata(&f.store.marker).unwrap().mode() & 0o777, 0o600);
        let firewall = f.store.firewall_marker_path().unwrap();
        assert_eq!(fs::metadata(&firewall).unwrap().mode() & 0o777, 0o600);
        assert_ne!(read(&firewall).unwrap(), read(&f.store.marker).unwrap());
        assert!(journal.firewall_marker == f.store.check_firewall_marker(&journal, &plan).unwrap());
        assert_eq!(read(&f.store.artifact(f.id, "intent")).unwrap(), intent);
        assert!(!f.store.artifact(f.id, "lease").exists());
        assert!(!f.store.root.join("confirmed.json").exists());
    }

    #[test]
    fn retained_firewall_barrier_is_pinned_without_overwrite_or_owner_adoption() {
        let f = Fixture::prepare(true, true);
        let path = f.store.firewall_marker_path().unwrap();
        let before = BoundFile::open(&path, 16384).unwrap();
        let identity = before.marker().unwrap();
        let bytes = before.bytes.clone();
        f.fence().unwrap();
        let after = BoundFile::open(&path, 16384).unwrap();
        assert_eq!(after.marker().unwrap(), identity);
        assert_eq!(after.bytes, bytes);
        let (journal, _) = f.store.load().unwrap().unwrap();
        assert_eq!(journal.firewall_marker, Some(identity));
        assert!(!f.store.artifact(f.id, "lease").exists());
    }

    #[test]
    fn partial_pair_with_only_original_firewall_marker_stays_unknown_and_never_publishes_network_marker_on_query()
     {
        let f = Fixture::prepare(false, true);
        let (journal, plan) = f.intent();
        f.store.publish_firewall_fence(&journal, &plan).unwrap();
        let before = read(&f.store.journal_path()).unwrap();
        let path = f.store.firewall_marker_path().unwrap();
        let marker = read(&path).unwrap();
        for _ in 0..2 {
            assert!(
                f.store
                    .recover(&f.token, "paired-actor", |_| panic!("no owner probe"))
                    .unwrap_err()
                    .to_string()
                    .starts_with("OUTCOME_UNKNOWN")
            );
            assert!(!f.store.marker.exists());
            assert_eq!(read(&f.store.journal_path()).unwrap(), before);
            assert_eq!(read(&path).unwrap(), marker);
        }
        assert!(f.fence().is_err());
        assert!(!f.store.marker.exists());
    }

    #[test]
    fn partial_pair_with_only_network_marker_never_reconstructs_the_missing_firewall_dispatch() {
        let f = Fixture::prepare(false, true);
        let (journal, _) = f.intent();
        f.publish_network(&journal);
        let before = read(&f.store.journal_path()).unwrap();
        assert!(
            f.store
                .recover(&f.token, "paired-actor", |_| panic!("no owner probe"))
                .unwrap_err()
                .to_string()
                .starts_with("OUTCOME_UNKNOWN")
        );
        assert!(!f.store.firewall_marker_path().unwrap().exists());
        assert_eq!(read(&f.store.journal_path()).unwrap(), before);
    }

    #[test]
    fn complete_original_pair_can_acknowledge_a_lost_fenced_journal_without_republishing_either_marker()
     {
        let f = Fixture::prepare(false, true);
        let (journal, plan) = f.intent();
        f.store.publish_firewall_fence(&journal, &plan).unwrap();
        f.publish_network(&journal);
        let network = BoundFile::open(&f.store.marker, 16384)
            .unwrap()
            .marker()
            .unwrap();
        let firewall = BoundFile::open(&f.store.firewall_marker_path().unwrap(), 16384)
            .unwrap()
            .marker()
            .unwrap();
        assert_eq!(
            f.store
                .recover(&f.token, "paired-actor", |_| panic!("no new owner action"))
                .unwrap()["state"],
            "FENCED"
        );
        assert_eq!(
            f.store
                .recover(&f.token, "paired-actor", |_| panic!("no new owner action"))
                .unwrap()["state"],
            "FENCED"
        );
        assert_eq!(
            BoundFile::open(&f.store.marker, 16384)
                .unwrap()
                .marker()
                .unwrap(),
            network
        );
        assert_eq!(
            BoundFile::open(&f.store.firewall_marker_path().unwrap(), 16384)
                .unwrap()
                .marker()
                .unwrap(),
            firewall
        );
    }

    #[test]
    fn changed_source_wrong_actor_or_token_refuses_before_any_fence_intent() {
        for defect in ["source", "actor", "token", "firewall-source"] {
            let f = Fixture::prepare(false, true);
            let before = read(&f.store.journal_path()).unwrap();
            if defect == "firewall-source" {
                durable::publish_new(
                    &f.store.firewall_marker_path().unwrap(),
                    b"unexpected barrier",
                    FileMetadata::private(),
                )
                .unwrap();
            }
            let mut source = f.source.clone();
            if defect == "source" {
                source.source_digest = "f".repeat(64);
            }
            let result = f.store.fence(
                if defect == "token" { "wrong" } else { &f.token },
                if defect == "actor" {
                    "wrong"
                } else {
                    "paired-actor"
                },
                || Ok(source),
            );
            assert!(result.is_err());
            assert_eq!(read(&f.store.journal_path()).unwrap(), before);
            assert!(!f.store.marker.exists());
            if defect != "firewall-source" {
                assert!(!f.store.firewall_marker_path().unwrap().exists());
            }
        }
    }

    #[test]
    fn changed_or_missing_fenced_barrier_is_never_recreated_or_hidden_as_unmanaged() {
        for network in [false, true] {
            let f = Fixture::prepare(false, true);
            f.fence().unwrap();
            let path = if network {
                f.store.marker.clone()
            } else {
                f.store.firewall_marker_path().unwrap()
            };
            fs::remove_file(&path).unwrap();
            let journal = read(&f.store.journal_path()).unwrap();
            assert!(f.store.status().is_err());
            assert!(
                f.store
                    .recover(&f.token, "paired-actor", |_| panic!("no dispatch"))
                    .is_err()
            );
            assert!(!path.exists());
            assert_eq!(read(&f.store.journal_path()).unwrap(), journal);
        }
    }

    #[test]
    fn before_fence_cancellation_preserves_a_retained_firewall_barrier_but_refuses_a_new_unreviewed_one()
     {
        let f = Fixture::prepare(true, true);
        let path = f.store.firewall_marker_path().unwrap();
        let before = BoundFile::open(&path, 16384).unwrap().marker().unwrap();
        f.store.cancel_before_fence(f.id, "paired-actor").unwrap();
        assert_eq!(
            f.store.original(f.id, "paired-actor").unwrap().unwrap()["state"],
            "CANCELLED"
        );
        assert_eq!(
            BoundFile::open(&path, 16384).unwrap().marker().unwrap(),
            before
        );
        assert!(!f.store.marker.exists());
        let f = Fixture::prepare(false, true);
        durable::publish_new(
            &f.store.firewall_marker_path().unwrap(),
            b"new unexpected fence",
            FileMetadata::private(),
        )
        .unwrap();
        assert!(f.store.cancel_before_fence(f.id, "paired-actor").is_err());
        assert!(!f.store.artifact(f.id, "receipt").exists());
    }

    #[test]
    fn complete_barriers_do_not_substitute_for_actual_owner_and_startup_lease_proof() {
        let f = Fixture::prepare(false, true);
        f.fence().unwrap();
        assert!(
            f.store
                .activate_inner(&f.token, "paired-actor", None, None, |_| Ok(()))
                .is_err()
        );
        assert_eq!(f.store.status().unwrap()["state"], "FENCED");
        assert!(!f.store.artifact(f.id, "lease").exists());
    }

    #[test]
    fn historical_single_firewall_source_plan_keeps_original_queries_bytes_and_safe_cancel_but_cannot_gain_a_new_single_fence()
     {
        let f = Fixture::prepare(false, false);
        let intent = read(&f.store.artifact(f.id, "intent")).unwrap();
        let value: Value = serde_json::from_slice(&intent).unwrap();
        assert_eq!(value["schemaVersion"], 3);
        assert!(value["baseline"].get("firewallFence").is_none());
        assert!(
            serde_json::to_value(f.store.load().unwrap().unwrap().0)
                .unwrap()
                .get("firewallMarker")
                .is_none()
        );
        assert_eq!(
            f.store.original(f.id, "paired-actor").unwrap().unwrap()["state"],
            "PREPARED"
        );
        assert!(
            f.fence()
                .unwrap_err()
                .to_string()
                .starts_with("UNSUPPORTED")
        );
        assert_eq!(read(&f.store.artifact(f.id, "intent")).unwrap(), intent);
        assert!(!f.store.marker.exists());
        assert!(!f.store.firewall_marker_path().unwrap().exists());
        f.store.cancel_before_fence(f.id, "paired-actor").unwrap();
        assert_eq!(
            f.store.original(f.id, "paired-actor").unwrap().unwrap()["state"],
            "CANCELLED"
        );
    }
}
