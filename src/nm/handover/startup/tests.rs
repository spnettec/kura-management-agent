use super::*;
use std::os::unix::fs::PermissionsExt;
mod file_recovery;
mod runtime_cases;

fn use_legacy_unit(path: &Path) {
    let bytes = fs::read_to_string(path).unwrap();
    fs::write(path, bytes.replace("yofc-kura-fixture.service","kura.service")).unwrap();
}

fn legacy_fixture() -> Fixture {
    let f = Fixture::new();
    let old_unit = f.root.join("yofc-kura-fixture.service");
    let new_unit = f.root.join("kura.service");
    fs::rename(&old_unit, &new_unit).unwrap();
    for path in [&f.installed.definition, &f.installed.systemctl, &f.root.join("unit-state")] {
        use_legacy_unit(path);
    }
    let mut config:Config=serde_json::from_slice(&fs::read(&f.installed.profile).unwrap()).unwrap();
    config.unit = "kura.service".into();
    config.unit_file = new_unit.clone();
    for file in &mut config.profile_files {
        if file.path==old_unit {file.path=new_unit.clone();}
    }
    config.unit_definition_sha256 = Profile::definition(&config,&fs::read_to_string(&f.installed.definition).unwrap()).unwrap();
    durable::json(&f.installed.profile,&config).unwrap();
    let unit=crate::system_control::inspect_unit(&f.installed.systemctl,&config.unit).unwrap();
    let stop=crate::system_control::inspect_stop_policy(&f.installed.systemctl,&config).unwrap();
    let profile=durable::hash(&fs::read(&f.installed.profile).unwrap());
    let receipt=legacy_source::Receipt::new(f.original.operation,f.original.plan.clone(),unit,891,
        profile,stop,"e".repeat(64),"f".repeat(64),f.original.baseline.roles.clone());
    legacy_source::bind(&f.store,&f.original,receipt).unwrap();
    f
}

fn prepare_legacy_fixture(f:&Fixture,bound:&legacy_source::Binding)->Result<Proposal> {
    proposal(&f.store,&f.marker,&f.original,"local-uid:0",&f.installed.profile,&f.installed.systemctl,Some(bound))
}

#[test]
fn legacy_bound_source_drives_original_stop_and_stopped_file_publication_without_java_report() {
    let f=legacy_fixture();
    let id=f.original.operation;
    let bound=legacy_source::Binding::open(&f.store,id).unwrap();
    let identity=bound.original_identity(&f.original).unwrap();
    let plan=prepare_legacy_fixture(&f,&bound).unwrap();
    assert!(!paths(&f.store,id).0.exists());
    let prepared=publish_proposal(&f.store,plan).unwrap();
    let token=prepared["confirmationToken"].as_str().unwrap();
    assert_eq!(prepared["schemaVersion"],5);
    assert_eq!(prepared["legacySourceReceiptSha256"],identity.sha256);
    assert!(!proof_path(&f.store,id).exists());
    assert!(matches!(association_begin(&f.store,&f.original,"local-uid:0",token,&f.installed.systemctl).unwrap(),
        AssociationStep::Observed(_)));
    assert!(stop::begin(&f.store,&f.original,"local-uid:0",token,&f.installed.systemctl).is_err());
    enable_stop(&f.installed,"success");
    use_legacy_unit(&f.installed.systemctl);
    let deadline=Instant::now()+Duration::from_secs(60);
    assert!(stop::arm_with_source(&f.store,&f.original,"local-uid:0","bad",stop::StopSource::Legacy(&bound),
        &f.installed.systemctl,deadline).is_err());
    let stopped=stop::arm_with_source(&f.store,&f.original,"local-uid:0",token,stop::StopSource::Legacy(&bound),
        &f.installed.systemctl,deadline).unwrap().execute().unwrap();
    assert_eq!(stopped["state"],"STOPPED");
    assert!(!proof_path(&f.store,id).exists());
    let path=f.store.join(format!("{id}.startup-stop-intent.json"));
    let intent:Value=serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(intent["schemaVersion"],2);
    assert_eq!(intent["legacySourceSha256"],identity.sha256);
    assert!(intent.get("association").is_none() && intent.get("spec").is_none());
    let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:0",token,&f.installed.systemctl).unwrap()
        else{panic!("fresh original legacy publication")};
    assert_eq!((*command).execute().unwrap()["state"],"FILES_PUBLISHED");
    assert_eq!(identity,bound.original_identity(&f.original).unwrap());
    assert_eq!(fs::read_to_string(&f.installed.calls).unwrap().lines().filter(|line|*line=="stop kura.service").count(),1);
}

#[test]
fn legacy_review_refuses_changed_process_and_does_not_rebuild_an_unknown_stop() {
    let f=legacy_fixture();
    let id=f.original.operation;
    let bound=legacy_source::Binding::open(&f.store,id).unwrap();
    let status=f.root.join("unit-state");
    let original_body=fs::read_to_string(&status).unwrap();
    fs::write(&status,original_body.replace("MainPID=4321","MainPID=4322")).unwrap();
    assert!(prepare_legacy_fixture(&f,&bound).is_err());
    assert!(!paths(&f.store,id).0.exists());
    fs::write(&status,original_body).unwrap();
    let prepared=publish_proposal(&f.store,prepare_legacy_fixture(&f,&bound).unwrap()).unwrap();
    let token=prepared["confirmationToken"].as_str().unwrap();
    enable_stop(&f.installed,"lost-ack");
    use_legacy_unit(&f.installed.systemctl);
    let attempt=||stop::arm_with_source(&f.store,&f.original,"local-uid:0",token,stop::StopSource::Legacy(&bound),
        &f.installed.systemctl,Instant::now()+Duration::from_secs(60));
    assert!(attempt().unwrap().execute().is_err());
    let readback=original(&f.store,id,&f.original.plan,Some("local-uid:0")).unwrap().unwrap();
    assert_eq!(readback["state"],"STOP_OUTCOME_UNKNOWN");
    assert!(attempt().err().unwrap().to_string().contains("never dispatch"));
    assert!(publication_begin(&f.store,&f.original,"local-uid:0",token,&f.installed.systemctl).is_err());
    assert_eq!(fs::read_to_string(&f.installed.calls).unwrap().lines().filter(|line|*line=="stop kura.service").count(),1);
}

#[test]
fn new_startup_publication_reserves_both_firewall_families_before_core_bootstrap() {
    let f=Fixture::new();f.published();let args=ordinary_profile::tokens(&fs::read(&f.installed.args).unwrap()).unwrap();
    let pids=property(&args,"kura.configuration.external.pids").unwrap().unwrap().split(',').collect::<BTreeSet<_>>();
    assert!(pids.contains("org.eclipse.kura.net.admin.NetworkConfigurationService"));
    assert!(pids.contains("org.eclipse.kura.net.admin.FirewallConfigurationService"));
    assert!(pids.contains("org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6"));
    assert!(pids.contains("org.example.Other") && pids.contains("org.example.Also"));
}
#[test]
fn historical_schema4_argument_contract_is_not_regenerated_with_new_firewall_reservations() {
    let f=Fixture::new();let prepared=f.prepare().unwrap();let (path,journal_path)=paths(&f.store,f.original.operation);
    let mut plan:Plan=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();let config:Config=serde_json::from_str(&plan.source_profile).unwrap();
    let (old_args,old_grant,_)=generated(&config,&fs::read_to_string(&f.installed.args).unwrap(),plan.operation_id).unwrap();
    plan.generated_arguments_version=None;plan.generated_args_sha256=Some(durable::hash(old_args.as_bytes()));plan.generated_profile=old_grant;
    let mut journal:Journal=serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();let bytes=serde_json::to_vec(&plan).unwrap();journal.plan_sha256=durable::hash(&bytes);
    durable::write(&path,&bytes,FileMetadata::private()).unwrap();durable::json(&journal_path,&journal).unwrap();
    let associated=f.associate();enable_stop(&f.installed,"success");
    stop::arm(&f.store,&f.original,"local-uid:fixture",associated["confirmationToken"].as_str().unwrap(),f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap().execute().unwrap();
    let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).unwrap()else{panic!("original legacy publication")};
    let published=(*command).execute().unwrap();assert_eq!(published["generatedArgumentsVersion"],1);
    assert_eq!(fs::read(&f.installed.args).unwrap(),old_args.as_bytes());assert_eq!(fs::read(path).unwrap(),bytes);
    let args=ordinary_profile::tokens(old_args.as_bytes()).unwrap();assert!(!property(&args,"kura.configuration.external.pids").unwrap().unwrap().contains("FirewallConfigurationService"));
}
#[test]
fn startup_argument_contract_cannot_be_stripped_or_replaced_without_original_review_binding() {
    let f=Fixture::new();f.prepare().unwrap();let (path,journal_path)=paths(&f.store,f.original.operation);
    let mut plan:Plan=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();assert_eq!(plan.generated_arguments_version,Some(3));
    plan.generated_arguments_version=None;durable::json(&path,&plan).unwrap();
    assert!(original(&f.store,f.original.operation,&f.original.plan,None).is_err());
    plan.generated_arguments_version=Some(4);let bytes=serde_json::to_vec(&plan).unwrap();let mut journal:Journal=serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();journal.plan_sha256=durable::hash(&bytes);
    durable::write(&path,&bytes,FileMetadata::private()).unwrap();durable::json(&journal_path,&journal).unwrap();
    assert!(original(&f.store,f.original.operation,&f.original.plan,None).unwrap_err().to_string().contains("argument generation contract binding"));
    assert!(fs::read_to_string(&f.installed.calls).unwrap().lines().all(|line|line.starts_with("show ")));
}
pub(in crate::nm) struct Installed {
    pub(in crate::nm) profile:PathBuf,
    pub(in crate::nm) systemctl:PathBuf,
    pub(in crate::nm) args:PathBuf,
    pub(in crate::nm) home:PathBuf,
    pub(in crate::nm) calls:PathBuf,
    definition:PathBuf,
}
pub(in crate::nm) fn install(root:&Path)->Installed {
    let home=root.join("ordinary-kura-home");durable::directory(&home.join("framework")).unwrap();
    let args=root.join("ordinary.jvm.args");let unit=root.join("yofc-kura-fixture.service");
    let profile=root.join("ordinary-profile.json");let calls=root.join("systemctl-calls");
    let definition=root.join("unit-definition");let status=root.join("unit-state");let systemctl=root.join("systemctl-fixture");
    let profile_id=format!("profile-{}",uuid::Uuid::new_v4());
    let body=format!("-Xmx64m\n-Dkura.home={}\n-Dkura.management.ordinary.profile.id={}\n-Dkura.management.ordinary.verification.enabled=true\n-Dkura.configuration.external.pids=org.example.Other,org.example.Also\n-Dkura.crypto.key=fixture-secret-must-not-leak\n",home.display(),profile_id);
    durable::write(&args,body.as_bytes(),FileMetadata::private()).unwrap();
    durable::write(&unit,b"fixture-only-unit-not-installed",FileMetadata::private()).unwrap();
    let mut config=Config{schema:1,profile_id,unit:"yofc-kura-fixture.service".into(),unit_file:unit.clone(),
        jvm_args_path:args.clone(),unit_definition_sha256:"0".repeat(64),timeout_seconds:30,valid_for_seconds:120,
        component_pids:vec!["ordinary.component".into()],check_ids:vec!["ordinary.check".into()],
        profile_files:vec![ordinary_profile::File{path:args.clone(),sha256:durable::hash(body.as_bytes())},
            ordinary_profile::File{path:unit.clone(),sha256:durable::hash(b"fixture-only-unit-not-installed")}],
        launcher_kind:ordinary_profile::Launcher::DirectJava,launcher_script_path:None};
    let text=format!("FragmentPath={}\nDropInPaths=\nExecStart={{ path=/usr/bin/java ; argv[]=/usr/bin/java @{} ; ignore_errors=no ; }}\nEnvironment=\nEnvironmentFiles=\nUnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS\nNeedDaemonReload=no\n",unit.display(),args.display());
    config.unit_definition_sha256=Profile::definition(&config,&text).unwrap();
    durable::json(&profile,&config).unwrap();durable::write(&definition,text.as_bytes(),FileMetadata::private()).unwrap();
    durable::write(&status,b"LoadState=loaded\nActiveState=active\nMainPID=4321\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState=disabled\n",FileMetadata::private()).unwrap();
    let policy=root.join("unit-stop-policy");durable::write(&policy,b"ExecStop=\nSlice=system.slice\nKillMode=control-group\nTimeoutStopUSec=3s\n",FileMetadata::private()).unwrap();
    let script=format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$1\" = show ] && [ \"$2\" = yofc-kura-fixture.service ] || exit 91\nif [ \"$3\" = --all ]; then cat '{}'; case \"$4\" in *TimeoutStopUSec*) cat '{}' ;; esac; else cat '{}'; fi\n",calls.display(),definition.display(),policy.display(),status.display());
    let mut metadata=FileMetadata::private();metadata.mode=0o700;durable::write(&systemctl,script.as_bytes(),metadata).unwrap();
    Installed{profile,systemctl,args,home,calls,definition}
}
pub(in crate::nm) fn enable_stop(installed:&Installed,mode:&str)->PathBuf {
    assert!(["success","lost-ack","no-op","source-drift"].contains(&mode));
    let root=installed.systemctl.parent().unwrap();let policy=root.join("unit-stop-policy");
    let status=root.join("unit-state");let inactive=root.join("unit-inactive");
    durable::write(&policy,b"ExecStop=\nSlice=system.slice\nKillMode=control-group\nTimeoutStopUSec=3s\n",FileMetadata::private()).unwrap();
    durable::write(&inactive,b"LoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nControlGroup=\nUnitFileState=disabled\n",FileMetadata::private()).unwrap();
    let script=format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$2\" = yofc-kura-fixture.service ] || exit 91\ncase \"$1\" in\nshow) if [ \"$3\" = --all ]; then cat '{}'; case \"$4\" in *TimeoutStopUSec*) cat '{}' ;; esac; else cat '{}'; fi ;;\nstop) [ '{}' = no-op ] || cp '{}' '{}'; [ '{}' != source-drift ] || printf '%s\\n' '-Xmx128m' >> '{}'; [ '{}' != lost-ack ] || exit 93 ;;\n*) exit 91 ;;\nesac\n",installed.calls.display(),installed.definition.display(),policy.display(),status.display(),mode,inactive.display(),status.display(),mode,installed.args.display(),mode);
    let mut metadata=FileMetadata::private();metadata.mode=0o700;durable::write(&installed.systemctl,script.as_bytes(),metadata).unwrap();policy
}
pub(in crate::nm) fn enable_stop_at(root:&Path,mode:&str)->PathBuf {
    let config:Config=serde_json::from_slice(&fs::read(root.join("ordinary-profile.json")).unwrap()).unwrap();
    let installed=Installed{profile:root.join("ordinary-profile.json"),systemctl:root.join("systemctl-fixture"),
        args:config.jvm_args_path,home:root.join("ordinary-kura-home"),calls:root.join("systemctl-calls"),definition:root.join("unit-definition")};
    enable_stop(&installed,mode)
}
pub(in crate::nm) fn enable_job_at(root:&Path)->PathBuf {
    let systemctl=root.join("systemctl-fixture");let base=root.join("systemctl-without-job");fs::copy(&systemctl,&base).unwrap();
    let job=root.join("unit-job");durable::write(&job,b"Job=\n",FileMetadata::private()).unwrap();
    let script=format!("#!/bin/sh\nif [ \"$1\" = show ] && [ \"$2\" = yofc-kura-fixture.service ] && [ \"$3\" = --all ] && [ \"$4\" = --property=Job ]; then cat '{}'; exit; fi\nexec '{}' \"$@\"\n",job.display(),base.display());
    let mut metadata=FileMetadata::private();metadata.mode=0o700;durable::write(&systemctl,script.as_bytes(),metadata).unwrap();job
}
pub(in crate::nm) fn enable_start_at(root:&Path,mode:&str) {
    assert!(["success","lost-ack","no-op","source-drift","stale-invocation","enablement"].contains(&mode));
    let config:Config=serde_json::from_slice(&fs::read(root.join("ordinary-profile.json")).unwrap()).unwrap();
    let active=root.join("unit-started");
    let invocation=if mode=="stale-invocation"{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}else{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    let enabled=if mode=="enablement"{"enabled"}else{"disabled"};
    let state=format!("LoadState=loaded\nActiveState=active\nMainPID=5432\nInvocationID={invocation}\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState={enabled}\n");
    durable::write(&active,state.as_bytes(),FileMetadata::private()).unwrap();
    let script=format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$2\" = yofc-kura-fixture.service ] || exit 91\ncase \"$1\" in\nshow) if [ \"$3\" = --all ]; then cat '{}'; case \"$4\" in *TimeoutStopUSec*) cat '{}' ;; esac; else cat '{}'; fi ;;\nstart) [ '{}' = no-op ] || cp '{}' '{}'; [ '{}' != source-drift ] || printf '%s\\n' '-Xmx128m' >> '{}'; [ '{}' != lost-ack ] || exit 93 ;;\n*) exit 91 ;;\nesac\n",
        root.join("systemctl-calls").display(),root.join("unit-definition").display(),root.join("unit-stop-policy").display(),root.join("unit-state").display(),
        mode,active.display(),root.join("unit-state").display(),mode,config.jvm_args_path.display(),mode);
    let mut metadata=FileMetadata::private();metadata.mode=0o700;durable::write(&root.join("systemctl-fixture"),script.as_bytes(),metadata).unwrap();
}
pub(in crate::nm) fn place_arguments_in_home(installed:&mut Installed) {
    let directory=installed.home.join("management");durable::directory(&directory).unwrap();let next=directory.join("ordinary.jvm.args");
    relocate_arguments(installed,next);
}
fn relocate_arguments(installed:&mut Installed,next:PathBuf) {
    let mut config:Config=serde_json::from_slice(&fs::read(&installed.profile).unwrap()).unwrap();
    let text=fs::read_to_string(&installed.definition).unwrap().replace(installed.args.to_str().unwrap(),next.to_str().unwrap());
    durable::move_new(&installed.args,&next).unwrap();
    for file in &mut config.profile_files {if file.path==installed.args{file.path=next.clone();}}
    config.jvm_args_path=next.clone();config.unit_definition_sha256=Profile::definition(&config,&text).unwrap();
    durable::json(&installed.profile,&config).unwrap();durable::write(&installed.definition,text.as_bytes(),FileMetadata::private()).unwrap();installed.args=next;
}
struct Fixture {root:PathBuf,store:PathBuf,marker:PathBuf,installed:Installed,original:Requirements}
impl Fixture {
    fn new()->Self {
        let root=std::env::temp_dir().join(format!("nm-startup-{}",uuid::Uuid::new_v4()));durable::directory(&root).unwrap();
        let store=root.join("nm-ownership");durable::directory(&store).unwrap();
        let marker=root.join("network-owner-agent");
        let installed=install(&root);
        let roles=roles::Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":roles::PID,"revision":"original-startup-fixture","interfaces":[]})).unwrap();
        let operation=uuid::Uuid::new_v4();let plan="a".repeat(64);
        durable::json(&marker,&Marker{schema_version:1,operation_id:operation,plan_sha256:plan.clone()}).unwrap();
        let identity=BoundFile::open(&marker,16384).unwrap().marker().unwrap();
        let original=Requirements{operation,plan,template:"b".repeat(64),state:State::Fenced,marker:identity,
            baseline:Baseline{source_digest:"d".repeat(64),roles,profiles:vec![ProfileBinding{interface:"eth0".into(),profile_uuid:None,origin_cas:None}],
                firewall_digest:"e".repeat(64),automatic_nat:Value::Null,native_transfer:None,firewall_fence:None,firewall_source:None}};
        Self{root,store,marker,installed,original}
    }
    fn prepare(&self)->Result<Value> {prepare(&self.store,&self.marker,&self.original,"local-uid:fixture",&self.installed.profile,&self.installed.systemctl)}
    fn change_args(&self,extra:&str) {
        let body=format!("{}{}\n",fs::read_to_string(&self.installed.args).unwrap(),extra);
        durable::write(&self.installed.args,body.as_bytes(),FileMetadata::private()).unwrap();
        let mut config:Config=serde_json::from_slice(&fs::read(&self.installed.profile).unwrap()).unwrap();
        for file in &mut config.profile_files {if file.path==self.installed.args{file.sha256=durable::hash(body.as_bytes());}}
        durable::json(&self.installed.profile,&config).unwrap();
    }
    fn association_witness(&self)->(roles::StartupAssociation,roles::Observation) {
        let (plan,journal)=load(&self.store,self.original.operation,&self.original.plan).unwrap().unwrap();
        let challenge=challenge(&plan,&journal).unwrap();let source=self.original.baseline.roles.clone();
        let mut report=challenge.spec.parameters();report["schemaVersion"]=json!(1);report["observerInstanceId"]=json!(uuid::Uuid::new_v4());
        report["profileId"]=json!(challenge.profile_id);report["processId"]=json!(challenge.pid);report["frameworkStartLevel"]=json!(6);report["ordinaryLoad"]=json!(true);
        (roles::StartupAssociation::new(source.agent_instance,source.bridge_epoch,report).unwrap(),source)
    }
    fn associate(&self)->Value {
        let (_,journal)=load(&self.store,self.original.operation,&self.original.plan).unwrap().unwrap();
        let step=association_begin(&self.store,&self.original,"local-uid:fixture",&journal.confirmation_token,&self.installed.systemctl).unwrap();
        let AssociationStep::Challenge(challenge)=step else{panic!("fresh fixture association")};
        association_finish(&self.store,&self.original,"local-uid:fixture",&journal.confirmation_token,&challenge,self.association_witness(),&self.installed.systemctl).unwrap()
    }
    fn stopped(&self)->Value {
        self.prepare().unwrap();let prepared=self.associate();enable_stop(&self.installed,"success");
        stop::arm(&self.store,&self.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),self.association_witness(),&self.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap().execute().unwrap()
    }
    fn published(&self)->Value {
        let stopped=self.stopped();
        let PublicationStep::Dispatch(command)=publication_begin(&self.store,&self.original,"local-uid:fixture",stopped["confirmationToken"].as_str().unwrap(),&self.installed.systemctl).unwrap()else{panic!("fresh publication")};
        (*command).execute().unwrap()
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}}
fn assert_execution_held_and_released<T>(f:&Fixture,command:T) {
    let path=f.store.join(format!("{}.startup-execution.lock",f.original.operation));
    let probe=File::open(&path).expect("admitted original command must own its execution lease");
    assert_ne!(unsafe{libc::flock(probe.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
    let before=fs::read(paths(&f.store,f.original.operation).1).unwrap();
    // Historical queries stay available while the ephemeral command is live.
    let observed=original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap();
    assert!(observed["state"].as_str().unwrap().contains("UNKNOWN"));
    assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),before);
    drop(command);
    assert_eq!(unsafe{libc::flock(probe.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
    assert_eq!(unsafe{libc::flock(probe.as_raw_fd(),libc::LOCK_UN)},0);
}
#[test]
fn startup_execution_lease_survives_admission_and_keeps_original_unknown_queries_available() {
    let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();enable_stop(&f.installed,"success");
    let token=prepared["confirmationToken"].as_str().unwrap();
    let command=stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
    assert_execution_held_and_released(&f,command);
    assert!(stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).is_err());

    let f=Fixture::new();let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();
    let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("new publication")};
    assert_execution_held_and_released(&f,command);
    assert!(matches!(publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap(),PublicationStep::Observed(_)));

    let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();enable_start_at(&f.root,"success");
    let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("new start")};
    assert_execution_held_and_released(&f,command);
    assert!(matches!(start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap(),StartStep::Observed(_)));
}
#[test]
fn startup_execution_lease_replacement_aborts_all_three_effects_without_reissuing_unknown() {
    for phase in ["stop","publication","start"] {
        let f=Fixture::new();
        let execute:Box<dyn FnOnce()->Result<Value>>=match phase {
            "stop"=>{
                f.prepare().unwrap();let prepared=f.associate();enable_stop(&f.installed,"success");
                let command=stop::arm(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
                Box::new(move ||command.execute())
            }
            "publication"=>{
                let stopped=f.stopped();
                let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",stopped["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).unwrap()else{panic!("new publication")};
                Box::new(move ||(*command).execute())
            }
            _=>{
                let published=f.published();enable_start_at(&f.root,"success");
                let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",published["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).unwrap()else{panic!("new start")};
                Box::new(move ||(*command).execute())
            }
        };
        let lock=f.store.join(format!("{}.startup-execution.lock",f.original.operation));let retained=lock.with_extension("retained");
        let bytes=fs::read(&lock).unwrap();fs::rename(&lock,&retained).unwrap();durable::write(&lock,&bytes,FileMetadata::private()).unwrap();
        let calls=fs::read(&f.installed.calls).unwrap();let arguments=fs::read(&f.installed.args).unwrap();
        let journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
        assert!(execute().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        let observed=original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap();
        assert!(observed["state"].as_str().unwrap().contains("UNKNOWN"));
        assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(fs::read(&f.installed.args).unwrap(),arguments);
        assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),journal);
        let (plan,journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
        assert!(execution::Execution::acquire(&f.store,&plan,&journal).is_err());
        assert_eq!(fs::read(lock).unwrap(),bytes);assert_eq!(fs::read(retained).unwrap(),bytes);
    }
}
#[test]
fn startup_execution_lease_missing_unsafe_or_foreign_binding_denies_new_publication_before_intent() {
    for fault in ["missing-lock","missing-anchor","replaced-lock","linked-lock","linked-anchor","unsafe-lock","foreign-anchor"] {
        let f=Fixture::new();let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();
        let lock=f.store.join(format!("{}.startup-execution.lock",f.original.operation));
        let anchor=f.store.join(format!("{}.startup-execution-identity.json",f.original.operation));
        match fault {
            "missing-lock"=>fs::rename(&lock,lock.with_extension("retained")).unwrap(),
            "missing-anchor"=>fs::rename(&anchor,anchor.with_extension("retained")).unwrap(),
            "replaced-lock"=>{let bytes=fs::read(&lock).unwrap();fs::rename(&lock,lock.with_extension("retained")).unwrap();durable::write(&lock,&bytes,FileMetadata::private()).unwrap();}
            "linked-lock"=>fs::hard_link(&lock,lock.with_extension("linked")).unwrap(),
            "linked-anchor"=>fs::hard_link(&anchor,anchor.with_extension("linked")).unwrap(),
            "unsafe-lock"=>fs::set_permissions(&lock,fs::Permissions::from_mode(0o644)).unwrap(),
            _=>{let mut value:Value=serde_json::from_slice(&fs::read(&anchor).unwrap()).unwrap();value["operationId"]=json!(uuid::Uuid::new_v4());durable::json(&anchor,&value).unwrap();}
        }
        let lock_before=fs::read(&lock).ok();let anchor_before=fs::read(&anchor).ok();let calls=fs::read(&f.installed.calls).unwrap();
        let args=fs::read(&f.installed.args).unwrap();let journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
        assert!(publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).is_err(),"{fault}");
        assert!(!f.store.join(format!("{}.startup-files-intent.json",f.original.operation)).exists());
        assert_eq!(fs::read(&lock).ok(),lock_before);assert_eq!(fs::read(&anchor).ok(),anchor_before);
        assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(fs::read(&f.installed.args).unwrap(),args);
        assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),journal);
    }
}
#[test]
fn startup_execution_lease_blocks_competing_admission_during_the_actual_external_stop() {
    let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();enable_stop(&f.installed,"success");
    let base=f.root.join("systemctl-base");fs::copy(&f.installed.systemctl,&base).unwrap();
    let entered=f.root.join("external-stop-entered");let release=f.root.join("external-stop-release");
    let script=format!("#!/bin/sh\nif [ \"$1\" = stop ]; then : > '{}'; n=0; while [ ! -f '{}' ]; do n=$((n+1)); [ \"$n\" -lt 200 ] || exit 94; sleep 0.02; done; fi\nexec '{}' \"$@\"\n",entered.display(),release.display(),base.display());
    let mut metadata=FileMetadata::private();metadata.mode=0o700;durable::write(&f.installed.systemctl,script.as_bytes(),metadata).unwrap();
    let command=stop::arm(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
    let worker=std::thread::spawn(move ||command.execute());
    for _ in 0..300 {if entered.exists(){break;}std::thread::sleep(Duration::from_millis(10));}
    assert!(entered.exists(),"bounded fixture stop must enter its external call");
    let (plan,journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
    assert!(execution::Execution::acquire(&f.store,&plan,&journal).err().unwrap().to_string().starts_with("CONFLICT"));
    let observed=original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap();
    assert_eq!(observed["state"],"STOP_OUTCOME_UNKNOWN");
    durable::write(&release,b"release only this synthetic external stop",FileMetadata::private()).unwrap();
    assert_eq!(worker.join().unwrap().unwrap()["state"],"STOPPED");
    let (plan,journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
    execution::Execution::acquire(&f.store,&plan,&journal).unwrap().verify().unwrap();
    assert_eq!(fs::read_to_string(&f.installed.calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),1);
}
#[test]
fn startup_execution_lease_also_serializes_lost_receipt_pointer_acknowledgement() {
    for phase in ["publication","start"] {
        let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();
        if phase=="start" {
            enable_start_at(&f.root,"success");
            let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("new start")};
            (*command).execute().unwrap();
        }
        let (plan,mut journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
        if phase=="publication"{journal.publication_receipt_sha256=None;}else{journal.start_receipt_sha256=None;}
        durable::json(&paths(&f.store,f.original.operation).1,&journal).unwrap();
        let lease=execution::Execution::acquire(&f.store,&plan,&journal).unwrap();
        let calls=fs::read(&f.installed.calls).unwrap();let before=fs::read(paths(&f.store,f.original.operation).1).unwrap();
        if phase=="publication"{assert!(publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).is_err());}
        else{assert!(start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).is_err());}
        original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap();
        assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),before);
        drop(lease);
        if phase=="publication"{assert!(matches!(publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap(),PublicationStep::Observed(_)));}
        else{assert!(matches!(start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap(),StartStep::Observed(_)));}
        assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    }
}
#[test]
fn startup_start_original_receipt_is_historical_and_repeated_queries_never_start_again_or_approve_adoption() {
    let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();
    enable_start_at(&f.root,"success");let arguments=fs::read(&f.installed.args).unwrap();let grant=fs::read(&f.installed.profile).unwrap();
    let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh start")};
    let started=(*command).execute().unwrap();assert_eq!(started["state"],"STARTED");assert_eq!(started["systemAdoptionVerified"],false);
    assert_eq!(started["start"]["receiptScope"],"historical-fixed-unit-start-only");assert_eq!(started["start"]["freshJvmAssociationRequired"],true);
    // Historical query must remain available when the unit later stops or its
    // definition is unavailable. It cannot convert this into fresh readiness.
    fs::remove_file(f.root.join("unit-state")).unwrap();fs::remove_file(f.root.join("unit-definition")).unwrap();
    let calls=fs::read(&f.installed.calls).unwrap();let journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
    let StartStep::Observed(repeated)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("query only")};
    assert_eq!(repeated,started);assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap(),started);
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),journal);
    assert_eq!(fs::read(&f.installed.args).unwrap(),arguments);assert_eq!(fs::read(&f.installed.profile).unwrap(),grant);
    assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),
        vec!["stop yofc-kura-fixture.service","start yofc-kura-fixture.service"]);
}
#[test]
fn startup_start_never_replays_unentered_or_lost_ack_intents_and_never_uses_a_later_active_unit_as_a_receipt() {
    for prefix in ["unentered","unpointed","lost-ack","no-op","source-drift","stale-invocation","enablement"] {
        let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();
        enable_start_at(&f.root,if ["unentered","unpointed"].contains(&prefix){"success"}else{prefix});
        let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh start")};
        if ["unentered","unpointed"].contains(&prefix) {
            drop(command);
            if prefix=="unpointed" {let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();journal.start_intent_sha256=None;durable::json(&path,&journal).unwrap();}
        }else{assert!((*command).execute().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));}
        let calls=fs::read(&f.installed.calls).unwrap();let journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
        for _ in 0..2 {
            let StartStep::Observed(status)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("no replay")};
            assert_eq!(status["state"],"START_OUTCOME_UNKNOWN");assert_eq!(status["systemAdoptionVerified"],false);
        }
        assert!(!start::paths(&f.store,f.original.operation).1.exists());assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
        assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),journal);
        assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|line.starts_with("start ")).count(),usize::from(!["unentered","unpointed"].contains(&prefix)));
    }
}
#[test]
fn startup_start_complete_original_receipt_can_acknowledge_a_lost_pointer_but_acknowledged_missing_evidence_is_never_recreated() {
    for missing in [false,true] {
        let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();enable_start_at(&f.root,"success");
        let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh start")};
        let started=(*command).execute().unwrap();let receipt=start::paths(&f.store,f.original.operation).1;let raw=fs::read(&receipt).unwrap();
        if missing {fs::remove_file(&receipt).unwrap();}else{
            let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();
            journal.start_intent_sha256=None;journal.start_receipt_sha256=None;durable::json(&path,&journal).unwrap();
        }
        let calls=fs::read(&f.installed.calls).unwrap();let outcome=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl);
        if missing {assert!(outcome.err().unwrap().to_string().contains("OUTCOME_UNKNOWN"));assert!(!receipt.exists());}else{
            let StartStep::Observed(status)=outcome.unwrap()else{panic!("settle existing receipt only")};assert_eq!(status,started);assert_eq!(fs::read(receipt).unwrap(),raw);
        }
        assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    }
}
#[test]
fn startup_start_refuses_changed_files_policy_enablement_existing_invocations_and_unknown_publication_before_any_start_intent() {
    for invalid in ["unpublished","unacknowledged","receipt-missing","same-body-inode","source-grant","fence","policy","enabled","running","historical"] {
        let f=Fixture::new();let prepared=if invalid=="historical"{f.prepare().unwrap()}else if invalid=="unpublished"{f.stopped()}else{f.published()};let token=prepared["confirmationToken"].as_str().unwrap();
        enable_start_at(&f.root,"success");
        match invalid {
            "unacknowledged"=>{let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();journal.publication_receipt_sha256=None;durable::json(&path,&journal).unwrap();}
            "receipt-missing"=>fs::remove_file(f.store.join(format!("{}.startup-files-receipt.json",f.original.operation))).unwrap(),
            "same-body-inode"=>durable::write(&f.installed.args,&fs::read(&f.installed.args).unwrap(),FileMetadata::private()).unwrap(),
            "source-grant"=>durable::write(&f.installed.profile,b"foreign",FileMetadata::private()).unwrap(),
            "fence"=>durable::write(&f.installed.home.join("framework/network-owner-agent"),b"foreign",FileMetadata::private()).unwrap(),
            "policy"=>{let path=f.root.join("unit-stop-policy");durable::write(&path,b"ExecStop=\nSlice=system.slice\nKillMode=process\nTimeoutStopUSec=3s\n",FileMetadata::private()).unwrap();}
            "enabled"=>{let path=f.root.join("unit-state");let body=fs::read_to_string(&path).unwrap().replace("UnitFileState=disabled","UnitFileState=enabled");durable::write(&path,body.as_bytes(),FileMetadata::private()).unwrap();}
            "running"=>fs::copy(f.root.join("unit-started"),f.root.join("unit-state")).map(|_|()).unwrap(),
            "historical"=>{
                let (path,journal_path)=paths(&f.store,f.original.operation);let mut plan:Plan=serde_json::from_slice(&BoundFile::open(&path,PLAN_LIMIT).unwrap().bytes).unwrap();
                plan.schema_version=3;plan.stop_policy=None;plan.generated_arguments_version=None;
                let config:Config=serde_json::from_str(&plan.source_profile).unwrap();
                let (old_args,old_grant,_)=generated(&config,&fs::read_to_string(&f.installed.args).unwrap(),plan.operation_id).unwrap();
                plan.generated_args_sha256=Some(durable::hash(old_args.as_bytes()));plan.generated_profile=old_grant;
                let raw=serde_json::to_vec(&plan).unwrap();durable::write(&path,&raw,FileMetadata::private()).unwrap();
                let mut journal:Journal=serde_json::from_slice(&read(&journal_path).unwrap()).unwrap();journal.plan_sha256=durable::hash(&raw);
                journal.schema_version=3;durable::json(&journal_path,&journal).unwrap();
            }
            _=>{},
        }
        let error=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).err().expect("invalid start must fail");
        if invalid=="historical" {assert!(error.to_string().starts_with("UNSUPPORTED"));}
        assert!(!start::paths(&f.store,f.original.operation).0.exists());assert!(!fs::read_to_string(&f.installed.calls).unwrap().lines().any(|line|line.starts_with("start ")));
    }
}
#[test]
fn startup_start_rechecks_original_stopped_authority_after_durable_admission_without_reconstructing_dispatch() {
    let f=Fixture::new();let published=f.published();let token=published["confirmationToken"].as_str().unwrap();enable_start_at(&f.root,"success");
    let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh start")};
    // An external start after admission must not cause a second start, even
    // though the prepared command still exists in memory.
    fs::copy(f.root.join("unit-started"),f.root.join("unit-state")).unwrap();
    assert!((*command).execute().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
    let StartStep::Observed(status)=start_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("original query")};
    assert_eq!(status["state"],"START_OUTCOME_UNKNOWN");assert!(!fs::read_to_string(&f.installed.calls).unwrap().lines().any(|line|line.starts_with("start ")));
}
fn alias_admission_refused(kind:&str) {
    let mut f=Fixture::new();
    if kind=="fence" {let next=f.root.join("firewall-owner-agent");relocate_arguments(&mut f.installed,next);}else{
        place_arguments_in_home(&mut f.installed);let alias=f.root.join("home-alias");std::os::unix::fs::symlink(&f.installed.home,&alias).unwrap();
        let path=alias.join("management/ordinary.jvm.args");let mut config:Config=serde_json::from_slice(&fs::read(&f.installed.profile).unwrap()).unwrap();
        config.profile_files.push(ordinary_profile::File{path,sha256:durable::hash(&fs::read(&f.installed.args).unwrap())});durable::json(&f.installed.profile,&config).unwrap();
    }
    let stopped=f.stopped();let args=fs::read(&f.installed.args).unwrap();
    assert!(publication_begin(&f.store,&f.original,"local-uid:fixture",stopped["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).is_err(),
        "mutable argument aliases must be refused before retaining or publishing any original source");
    assert!(!f.store.join(format!("{}.startup-files-intent.json",f.original.operation)).exists());assert_eq!(fs::read(&f.installed.args).unwrap(),args);
}
#[test]
fn startup_files_alias_between_arguments_and_a_retained_fence_is_refused_before_admission() {alias_admission_refused("fence");}
#[test]
fn startup_files_alias_of_arguments_through_a_pinned_ancestor_path_is_refused_before_admission() {alias_admission_refused("pinned");}
#[test]
fn startup_files_retain_kura_inode_and_metadata_publish_the_planned_generation_and_never_copy_key_bodies_to_agent_records() {
    let mut f=Fixture::new();place_arguments_in_home(&mut f.installed);
    fs::set_permissions(&f.installed.args,fs::Permissions::from_mode(0o640)).unwrap();
    let previous_fence=f.root.join("firewall-owner-agent");durable::write(&previous_fence,b"retained-original-fence",FileMetadata::private()).unwrap();
    let fence_image=Image::read(&previous_fence,16384).unwrap().0;
    let before=Image::read(&f.installed.args,ARGS_LIMIT).unwrap();let grant=fs::read(&f.installed.profile).unwrap();let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();
    let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh publication dispatch")};
    let completed=(*command).execute().unwrap();assert_eq!(completed["state"],"FILES_PUBLISHED");assert_eq!(completed["startupFilesChanged"],true);
    assert_eq!(completed["executionAvailable"],false);assert_eq!(completed["publication"]["profileSelectionCommitted"],false);assert_eq!(completed["systemAdoptionVerified"],false);
    let retained=fs::read_dir(f.installed.args.parent().unwrap()).unwrap().map(|entry|entry.unwrap().path()).find(|path|fs::metadata(path).unwrap().ino()==before.0.inode).unwrap();
    let retained_image=Image::read(&retained,ARGS_LIMIT).unwrap();assert_eq!(retained_image.1,before.1);assert_eq!(retained_image.0.metadata,before.0.metadata);assert_eq!(retained_image.0.device,before.0.device);
    let target=Image::read(&f.installed.args,ARGS_LIMIT).unwrap();assert_ne!(target.0.inode,before.0.inode);assert_eq!(target.0.metadata,before.0.metadata);
    let config:Config=serde_json::from_slice(&grant).unwrap();let (plan,_)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
    let (body,_,_)=generated_for(&plan,&config,std::str::from_utf8(&before.1).unwrap()).unwrap();assert_eq!(target.1,body.as_bytes());
    assert_eq!(fs::read(&f.installed.profile).unwrap(),grant);assert!(Image::read(&previous_fence,16384).unwrap().0==fence_image);
    for name in ["network-owner-agent","firewall-owner-agent"] {assert_eq!(fs::read(f.installed.home.join("framework").join(name)).unwrap(),fs::read(&f.marker).unwrap());}
    let new_grant=f.store.join(format!("{}.startup-profile.json",f.original.operation));let config:Config=serde_json::from_slice(&fs::read(new_grant).unwrap()).unwrap();assert_eq!(config.profile_id,format!("profile-{}",f.original.operation));
    for entry in fs::read_dir(&f.store).unwrap(){assert!(!String::from_utf8_lossy(&fs::read(entry.unwrap().path()).unwrap()).contains("fixture-secret-must-not-leak"));}
    let calls=fs::read(&f.installed.calls).unwrap();let journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
    let PublicationStep::Observed(repeated)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("query only")};
    assert_eq!(repeated,completed);assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap(),completed);
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),journal);
    assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),vec!["stop yofc-kura-fixture.service"]);
}
#[test]
fn startup_files_refuse_unstopped_drifted_symlinked_or_preexisting_destinations_before_publication_admission() {
    for invalid in ["no-stop","unit-running","arguments","argument-link","backup-link","profile-exists","new-fence","policy"] {
        let mut f=Fixture::new();place_arguments_in_home(&mut f.installed);
        let prepared=if invalid=="no-stop"{f.prepare().unwrap();f.associate()}else{f.stopped()};
        let config:Config=serde_json::from_slice(&fs::read(&f.installed.profile).unwrap()).unwrap();
        match invalid {
            "unit-running"=>durable::write(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=active\nMainPID=9999\nInvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState=disabled\n",FileMetadata::private()).unwrap(),
            "arguments"=>durable::write(&f.installed.args,b"changed externally",FileMetadata::private()).unwrap(),
            "argument-link"=>{let retained=f.installed.args.with_extension("foreign");fs::rename(&f.installed.args,&retained).unwrap();std::os::unix::fs::symlink(retained,&f.installed.args).unwrap();},
            "backup-link"=>{let path=config.jvm_args_path.parent().unwrap().join(format!(".ordinary.jvm.args.nm-before-{}",f.original.operation));std::os::unix::fs::symlink(&f.installed.args,path).unwrap();},
            "profile-exists"=>durable::write(&f.store.join(format!("{}.startup-profile.json",f.original.operation)),b"foreign",FileMetadata::private()).unwrap(),
            "new-fence"=>durable::write(&f.installed.home.join("framework/network-owner-agent"),b"foreign",FileMetadata::private()).unwrap(),
            "policy"=>{let path=f.root.join("unit-stop-policy");let body=fs::read_to_string(&path).unwrap().replace("3s","4s");durable::write(&path,body.as_bytes(),FileMetadata::private()).unwrap();},
            _=>{},
        }
        assert!(publication_begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).is_err());
        assert!(!f.store.join(format!("{}.startup-files-intent.json",f.original.operation)).exists());
        assert_eq!(fs::read_to_string(&f.installed.calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),usize::from(invalid!="no-stop"));
    }
}
#[test]
fn startup_files_original_prefixes_settle_only_complete_original_receipts_and_never_redispatch_uncertain_file_actions() {
    for prefix in ["unentered","final-unacknowledged","receipt-first","last-step-unacknowledged","acknowledged-receipt-missing","both-main-missing"] {
        let f=Fixture::new();let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();
        let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh publication")};
        let completed=if prefix=="unentered"{drop(command);None}else{Some((*command).execute().unwrap())};
        let intent=f.store.join(format!("{}.startup-files-intent.json",f.original.operation));let receipt=f.store.join(format!("{}.startup-files-receipt.json",f.original.operation));
        let journal_path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&read(&journal_path).unwrap()).unwrap();
        if ["final-unacknowledged","receipt-first","last-step-unacknowledged"].contains(&prefix){journal.publication_receipt_sha256=None;durable::json(&journal_path,&journal).unwrap();}
        if ["final-unacknowledged","last-step-unacknowledged","acknowledged-receipt-missing","both-main-missing"].contains(&prefix){fs::remove_file(&receipt).unwrap();}
        if prefix=="last-step-unacknowledged"{fs::remove_file(f.store.join(format!("{}.startup-files-step-5.json",f.original.operation))).unwrap();}
        if prefix=="both-main-missing"{fs::remove_file(intent).unwrap();}
        let arguments=fs::read(&f.installed.args).unwrap();let calls=fs::read(&f.installed.calls).unwrap();
        let result=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl);
        if ["acknowledged-receipt-missing","both-main-missing"].contains(&prefix){assert!(result.err().unwrap().to_string().contains("OUTCOME_UNKNOWN"));}
        else{
            let PublicationStep::Observed(value)=result.unwrap()else{panic!("retained publication must never dispatch again")};
            if ["final-unacknowledged","receipt-first"].contains(&prefix){assert_eq!(Some(value),completed);}else{assert_eq!(value["state"],"PUBLICATION_OUTCOME_UNKNOWN");assert!(value["startupFilesChanged"].is_null());}
        }
        assert_eq!(fs::read(&f.installed.args).unwrap(),arguments);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    }
}
#[test]
fn startup_files_descriptor_or_authority_changes_after_admission_do_not_publish_into_a_replaced_directory_or_retry() {
    for drift in ["parent","arguments","policy"] {
        let mut f=Fixture::new();place_arguments_in_home(&mut f.installed);let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();
        let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("fresh publication")};
        match drift {
            "parent"=>{let parent=f.installed.args.parent().unwrap();fs::rename(parent,parent.with_extension("retained")).unwrap();durable::directory(parent).unwrap();durable::write(&f.installed.args,b"foreign replacement must survive",FileMetadata::private()).unwrap();},
            "arguments"=>durable::write(&f.installed.args,b"external argument drift",FileMetadata::private()).unwrap(),
            _=>{let path=f.root.join("unit-stop-policy");let body=fs::read_to_string(&path).unwrap().replace("3s","4s");durable::write(&path,body.as_bytes(),FileMetadata::private()).unwrap();},
        }
        let arguments=fs::read(&f.installed.args).unwrap();assert!((*command).execute().unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));
        let calls=fs::read(&f.installed.calls).unwrap();
        let PublicationStep::Observed(value)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("no retry")};assert_eq!(value["state"],"PUBLICATION_OUTCOME_UNKNOWN");
        assert_eq!(fs::read(&f.installed.args).unwrap(),arguments);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert!(!f.installed.home.join("framework/network-owner-agent").exists());
    }
}
#[test]
fn startup_files_acknowledge_an_existing_original_stop_receipt_before_file_publication_without_another_stop() {
    let f=Fixture::new();let stopped=f.stopped();let token=stopped["confirmationToken"].as_str().unwrap();let path=paths(&f.store,f.original.operation).1;
    let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();let known=journal.stop_receipt_sha256.take();durable::json(&path,&journal).unwrap();
    let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("complete original stop proof")};
    assert_eq!((*command).execute().unwrap()["state"],"FILES_PUBLISHED");
    let journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();assert_eq!(journal.stop_receipt_sha256,known);
    assert_eq!(fs::read_to_string(&f.installed.calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),1);
}
#[test]
fn startup_stop_review_cannot_accept_a_different_but_still_bounded_effective_policy_after_preparation() {
    let f=Fixture::new();let policy=enable_stop(&f.installed,"success");f.prepare().unwrap();let prepared=f.associate();
    let text=fs::read_to_string(&policy).unwrap().replace("TimeoutStopUSec=3s","TimeoutStopUSec=4s");
    durable::write(&policy,text.as_bytes(),FileMetadata::private()).unwrap();
    assert!(stop::begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).is_err(),
        "the stop authority must be bound to the original reviewed effective policy,not any later bounded policy");
    assert!(!f.store.join(format!("{}.startup-stop-intent.json",f.original.operation)).exists());
    assert!(fs::read_to_string(&f.installed.calls).unwrap().lines().all(|line|line.starts_with("show ")));
}
#[test]
fn startup_stop_preserves_schema3_original_bytes_and_association_without_granting_new_stop_authority() {
    let f=Fixture::new();f.prepare().unwrap();let (intent,path)=paths(&f.store,f.original.operation);
    let mut plan:Plan=serde_json::from_slice(&read(&intent).unwrap()).unwrap();plan.schema_version=3;plan.stop_policy=None;plan.generated_arguments_version=None;
    let config:Config=serde_json::from_str(&plan.source_profile).unwrap();
    let (old_args,old_grant,_)=generated(&config,&fs::read_to_string(&f.installed.args).unwrap(),plan.operation_id).unwrap();
    plan.generated_args_sha256=Some(durable::hash(old_args.as_bytes()));plan.generated_profile=old_grant;
    let bytes=serde_json::to_vec(&plan).unwrap();durable::write(&intent,&bytes,FileMetadata::private()).unwrap();
    let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();journal.schema_version=3;journal.plan_sha256=durable::hash(&bytes);durable::json(&path,&journal).unwrap();
    let prepared=f.associate();let before=fs::read(&intent).unwrap();let journal=fs::read(&path).unwrap();let calls=fs::read(&f.installed.calls).unwrap();
    let result=stop::begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl);
    assert!(result.err().unwrap().to_string().contains("UNSUPPORTED"));
    assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap(),prepared);
    assert_eq!(fs::read(&intent).unwrap(),before);assert_eq!(fs::read(path).unwrap(),journal);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    assert!(!f.store.join(format!("{}.startup-stop-intent.json",f.original.operation)).exists());
}
fn assert_stop_budget_rejected(expire_during_recheck:bool) {
    let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();enable_stop(&f.installed,"success");
    let before_journal=fs::read(paths(&f.store,f.original.operation).1).unwrap();
    let before_args=fs::read(&f.installed.args).unwrap();let before_profile=fs::read(&f.installed.profile).unwrap();
    if expire_during_recheck {
        let script=fs::read_to_string(&f.installed.systemctl).unwrap();
        assert!(script.starts_with("#!/bin/sh\n"));
        let delayed=script.replacen("#!/bin/sh\n","#!/bin/sh\nsleep 0.1\n",1);
        let mut mode=FileMetadata::private();mode.mode=0o700;
        durable::write(&f.installed.systemctl,delayed.as_bytes(),mode).unwrap();
    }
    let now=std::time::Instant::now();
    let deadline=if expire_during_recheck {now+std::time::Duration::from_millis(50)}else{now-std::time::Duration::from_millis(1)};
    let error=stop::arm(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),
        f.association_witness(),&f.installed.systemctl,deadline).err().expect("expired budget must reject before stop intent");
    assert!(error.to_string().starts_with("TIMEOUT:"),"{error:#}");
    if expire_during_recheck {assert!(now.elapsed()>=std::time::Duration::from_millis(100));}
    assert_eq!(fs::read(paths(&f.store,f.original.operation).1).unwrap(),before_journal);
    assert_eq!(fs::read(&f.installed.args).unwrap(),before_args);assert_eq!(fs::read(&f.installed.profile).unwrap(),before_profile);
    for suffix in ["startup-stop-intent.json","startup-stop-receipt.json"] {
        assert!(!f.store.join(format!("{}.{suffix}",f.original.operation)).exists());
    }
    assert!(fs::read_to_string(&f.installed.calls).unwrap().lines().all(|line|line.starts_with("show ")));
}
#[test]
fn startup_stop_budget_already_expired_never_creates_intent_or_dispatches() {assert_stop_budget_rejected(false);}
#[test]
fn startup_stop_budget_expiring_during_full_recheck_never_creates_intent_or_dispatches() {assert_stop_budget_rejected(true);}

#[test]
fn startup_stop_uses_the_fixed_original_unit_once_and_retains_a_historical_receipt_without_publishing_startup_files() {
    let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();enable_stop(&f.installed,"success");
    let token=prepared["confirmationToken"].as_str().unwrap();let args=fs::read(&f.installed.args).unwrap();let grant=fs::read(&f.installed.profile).unwrap();
    assert!(matches!(stop::begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap(),AssociationStep::Challenge(_)));
    let command=stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
    let status=command.execute().unwrap();assert_eq!(status["state"],"STOPPED");assert_eq!(status["unitActionsIssued"],true);
    assert_eq!(status["executionAvailable"],false);assert_eq!(status["startupFilesChanged"],false);assert_eq!(status["stop"]["redispatchAllowed"],false);
    let calls=fs::read(&f.installed.calls).unwrap();
    let AssociationStep::Observed(repeated)=stop::begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap() else{panic!("must query original stop")};
    assert_eq!(repeated,status);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    assert!(stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).err().unwrap().to_string().contains("OUTCOME_UNKNOWN"));
    assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),1);
    assert_eq!(fs::read(&f.installed.args).unwrap(),args);assert_eq!(fs::read(&f.installed.profile).unwrap(),grant);
    assert!(!f.installed.home.join("framework/network-owner-agent").exists());
    for entry in fs::read_dir(&f.store).unwrap() {assert!(!String::from_utf8_lossy(&fs::read(entry.unwrap().path()).unwrap()).contains("fixture-secret-must-not-leak"));}
}
#[test]
fn startup_stop_checks_the_shared_full_cgroup_policy_before_any_intent_or_service_action() {
    for bad in ["KillMode=process","Slice=user.slice","TimeoutStopUSec=infinity","TimeoutStopUSec=181s","EnvironmentFiles=/unpinned/override"] {
        let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();let policy=enable_stop(&f.installed,"success");
        let mut text=fs::read_to_string(&policy).unwrap();let (key,_)=bad.split_once('=').unwrap();
        if text.lines().any(|line|line.starts_with(&format!("{key}="))){text=text.lines().map(|line|if line.starts_with(&format!("{key}=")){bad}else{line}).collect::<Vec<_>>().join("\n");}
        else {text.push_str(bad);text.push('\n');}
        durable::write(&policy,text.as_bytes(),FileMetadata::private()).unwrap();
        assert!(stop::begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).is_err());
        assert!(!f.store.join(format!("{}.startup-stop-intent.json",f.original.operation)).exists());
        assert!(fs::read_to_string(&f.installed.calls).unwrap().lines().all(|line|line.starts_with("show ")));
    }
}
#[test]
fn startup_stop_unknown_prefixes_or_missing_receipts_never_dispatch_or_manufacture_proof_from_an_inactive_unit() {
    for prefix in ["unentered","lost-ack","no-op","source-drift","missing-receipt","both-missing","receipt-first"] {
        let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();
        enable_stop(&f.installed,if ["lost-ack","no-op","source-drift"].contains(&prefix){prefix}else{"success"});
        let token=prepared["confirmationToken"].as_str().unwrap();let command=stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
        if prefix=="unentered"{drop(command);}else{
            let result=command.execute();if ["lost-ack","no-op","source-drift"].contains(&prefix){assert!(result.unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));}else{result.unwrap();}
        }
        let intent=f.store.join(format!("{}.startup-stop-intent.json",f.original.operation));let receipt=f.store.join(format!("{}.startup-stop-receipt.json",f.original.operation));
        if ["missing-receipt","both-missing"].contains(&prefix){fs::remove_file(&receipt).unwrap();}
        if prefix=="both-missing"{fs::remove_file(&intent).unwrap();}
        if prefix=="receipt-first"{
            let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();journal.stop_receipt_sha256=None;durable::json(&path,&journal).unwrap();
        }
        let calls=fs::read(&f.installed.calls).unwrap();let result=stop::begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl);
        if ["missing-receipt","both-missing"].contains(&prefix){assert!(result.err().unwrap().to_string().contains("OUTCOME_UNKNOWN"));}
        else {let AssociationStep::Observed(value)=result.unwrap()else{panic!("original intent must not produce another command")};assert_eq!(value["state"],if prefix=="receipt-first"{"STOPPED"}else{"STOP_OUTCOME_UNKNOWN"});}
        assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
        assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),usize::from(prefix!="unentered"));
    }
}
#[test]
fn startup_stop_fresh_admission_rejects_expiry_and_drift_after_arming_without_issuing_the_command() {
    for drift in ["arguments","unit","stop-policy"] {
        let f=Fixture::new();f.prepare().unwrap();let prepared=f.associate();let policy=enable_stop(&f.installed,"success");
        let token=prepared["confirmationToken"].as_str().unwrap();let command=stop::arm(&f.store,&f.original,"local-uid:fixture",token,f.association_witness(),&f.installed.systemctl,std::time::Instant::now()+std::time::Duration::from_secs(60)).unwrap();
        let path=match drift{"arguments"=>f.installed.args.clone(),"unit"=>f.root.join("unit-state"),_=>policy};
        let text=fs::read_to_string(&path).unwrap();let changed=match drift{"unit"=>text.replace("MainPID=4321","MainPID=9999"),"stop-policy"=>text.replace("3s","4s"),_=>format!("{text}-Xmx128m\n")};
        durable::write(&path,changed.as_bytes(),FileMetadata::private()).unwrap();assert!(command.execute().unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));
        assert!(fs::read_to_string(&f.installed.calls).unwrap().lines().all(|line|line.starts_with("show ")));
        let AssociationStep::Observed(value)=stop::begin(&f.store,&f.original,"local-uid:fixture",token,&f.installed.systemctl).unwrap()else{panic!("never arm again after drift")};assert_eq!(value["state"],"STOP_OUTCOME_UNKNOWN");
    }
    let f=Fixture::new();f.prepare().unwrap();
    let (intent,path)=paths(&f.store,f.original.operation);let mut plan:Plan=serde_json::from_slice(&read(&intent).unwrap()).unwrap();plan.expires_at_unix_ms=1;
    let bytes=serde_json::to_vec(&plan).unwrap();durable::write(&intent,&bytes,FileMetadata::private()).unwrap();
    let mut journal:Journal=serde_json::from_slice(&read(&path).unwrap()).unwrap();journal.plan_sha256=durable::hash(&bytes);durable::json(&path,&journal).unwrap();
    let prepared=f.associate();enable_stop(&f.installed,"success");
    assert!(stop::begin(&f.store,&f.original,"local-uid:fixture",prepared["confirmationToken"].as_str().unwrap(),&f.installed.systemctl).err().unwrap().to_string().contains("EXPIRED"));
    assert!(!f.store.join(format!("{}.startup-stop-intent.json",f.original.operation)).exists());
}
#[test]
fn generated_startup_proposal_preserves_all_other_reservations_and_secrets_without_installed_mutation() {
    let f=Fixture::new();let before_args=fs::read(&f.installed.args).unwrap();let before_profile=fs::read(&f.installed.profile).unwrap();
    let proposed=f.prepare().unwrap();assert_eq!(proposed["state"],"PREPARED");assert_eq!(proposed["executionAvailable"],false);
    assert_eq!(proposed["requiredReservedPids"],json!([roles::PID,
        "org.eclipse.kura.net.admin.FirewallConfigurationService",
        "org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6"]));
    assert_eq!(proposed["oldJvmAssociationVerified"],false);assert_eq!(proposed["startupFilesChanged"],false);
    assert!(!proposed.to_string().contains("fixture-secret-must-not-leak"));
    let (intent,journal)=paths(&f.store,f.original.operation);
    let plan:Plan=serde_json::from_slice(&read(&intent).unwrap()).unwrap();
    let config:Config=serde_json::from_str(&plan.generated_profile).unwrap();
    let source:Config=serde_json::from_str(&plan.source_profile).unwrap();
    let (generated_args,generated_profile,_)=generated_for(&plan,&source,std::str::from_utf8(&before_args).unwrap()).unwrap();
    assert_eq!(Some(durable::hash(generated_args.as_bytes())),plan.generated_args_sha256);
    assert_eq!(generated_profile,plan.generated_profile);assert!(plan.source_args.is_none() && plan.generated_args.is_none());
    let args=ordinary_profile::tokens(generated_args.as_bytes()).unwrap();
    let pids=property(&args,"kura.configuration.external.pids").unwrap().unwrap().split(',').collect::<BTreeSet<_>>();
    assert_eq!(pids,BTreeSet::from([roles::PID,"org.eclipse.kura.net.admin.FirewallConfigurationService","org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6","org.example.Other","org.example.Also"]));
    assert_eq!(plan.generated_arguments_version,Some(3));
    assert_eq!(config.profile_id,format!("profile-{}",f.original.operation));
    assert!(generated_args.contains("fixture-secret-must-not-leak"));assert!(generated_args.contains("-Xmx64m"));
    assert_eq!(property(&args,"kura.network.confirmed.provider").unwrap(),Some("nm-agent-v1"));
    assert_eq!(fs::read(&f.installed.args).unwrap(),before_args);assert_eq!(fs::read(&f.installed.profile).unwrap(),before_profile);
    assert!(plan.fences.iter().all(|file|file.before.is_none() && !file.path.exists()));
    assert_eq!(fs::metadata(intent).unwrap().mode()&0o777,0o600);assert_eq!(fs::metadata(journal).unwrap().mode()&0o777,0o600);
    let calls=fs::read_to_string(&f.installed.calls).unwrap();assert_eq!(calls.lines().count(),6);
    assert!(calls.lines().all(|line|line.starts_with("show ")));
}
#[test]
fn original_startup_query_is_actor_bound_redacted_and_never_reprepares_or_runs_a_unit_query() {
    let f=Fixture::new();let proposed=f.prepare().unwrap();let before_calls=fs::read(&f.installed.calls).unwrap();
    let public=original(&f.store,f.original.operation,&f.original.plan,None).unwrap().unwrap();assert!(public["confirmationToken"].is_null());
    assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap(),proposed);
    assert!(original(&f.store,f.original.operation,&f.original.plan,Some("other-actor")).is_err());
    assert!(original(&f.store,f.original.operation,&"f".repeat(64),None).is_err());
    assert!(f.prepare().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
    durable::write(&f.installed.args,b"later mutable drift",FileMetadata::private()).unwrap();
    assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap(),proposed,
        "query adjudicates retained preparation only; it does not approve later mutable startup state");
    assert_eq!(fs::read(&f.installed.calls).unwrap(),before_calls);
}
#[test]
fn ambiguous_provider_pid_and_home_inputs_refuse_before_any_startup_evidence() {
    for extra in ["-Dkura.network.confirmed.provider=unreviewed-provider","-Dkura.firewall.provider=unknown",
        "-Dkura.home=/another/home","-Dkura.configuration.external.pids=duplicate", "@indirect.args"] {
        let f=Fixture::new();f.change_args(extra);assert!(f.prepare().is_err());
        let (intent,journal)=paths(&f.store,f.original.operation);assert!(!intent.exists() && !journal.exists());
        assert!(!f.root.join("firewall-owner-agent").exists());
        assert!(!f.installed.home.join("framework/network-owner-agent").exists());
    }
}
#[test]
fn changed_effective_definition_and_orphaned_startup_evidence_never_publish_or_recreate_a_proposal() {
    let f=Fixture::new();let text=fs::read_to_string(&f.installed.definition).unwrap().replace("NeedDaemonReload=no","NeedDaemonReload=yes");
    durable::write(&f.installed.definition,text.as_bytes(),FileMetadata::private()).unwrap();assert!(f.prepare().is_err());
    assert!(!paths(&f.store,f.original.operation).0.exists());
    let f=Fixture::new();f.prepare().unwrap();let (intent,journal)=paths(&f.store,f.original.operation);
    let retained=fs::read(&intent).unwrap();let calls=fs::read(&f.installed.calls).unwrap();fs::remove_file(&journal).unwrap();
    assert!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
    assert!(f.prepare().is_err());assert!(!journal.exists());assert_eq!(fs::read(intent).unwrap(),retained);
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
}
#[test]
fn inline_jvm_override_cannot_make_generated_reservations_differ_from_the_effective_startup() {
    let f=Fixture::new();
    let text=fs::read_to_string(&f.installed.definition).unwrap().replace(" ; ignore_errors=", " -Dkura.configuration.external.pids=inline-override ; ignore_errors=");
    let mut config:Config=serde_json::from_slice(&fs::read(&f.installed.profile).unwrap()).unwrap();
    config.unit_definition_sha256=Profile::definition(&config,&text).unwrap();
    durable::json(&f.installed.profile,&config).unwrap();durable::write(&f.installed.definition,text.as_bytes(),FileMetadata::private()).unwrap();
    assert!(f.prepare().is_err(),"a pinned unit may still override a generated argument file; the NM proposal must refuse that layout");
    assert!(!paths(&f.store,f.original.operation).0.exists());
}
#[test]
fn packaged_startup_keeps_its_actual_home_and_refuses_later_controlled_property_overrides() {
    for override_provider in [false,true] {
        let f=Fixture::new();let bin=f.installed.home.join("bin");durable::directory(&bin).unwrap();
        let script=bin.join("start_kura_background.sh");let generator=bin.join("gen_config_ini.sh");
        let mut body=String::from("#!/bin/sh\n# YOFC-KURA-ORDINARY-JVM-ARGS-V1\nset -- \"@$KURA_JVM_ARGS_FILE\"\nnohup java \"$@\" \\\n        -Dkura.home=${DIR} \\\n        -jar fixed-launcher.jar\n");
        if override_provider {body=body.replace("-jar fixed-launcher.jar","-Dkura.network.confirmed.provider=another-provider -jar fixed-launcher.jar");}
        durable::write(&script,body.as_bytes(),FileMetadata::private()).unwrap();
        durable::write(&generator,b"reviewed fixture generator",FileMetadata::private()).unwrap();
        let mut config:Config=serde_json::from_slice(&fs::read(&f.installed.profile).unwrap()).unwrap();
        config.launcher_kind=ordinary_profile::Launcher::PackagedBackground;config.launcher_script_path=Some(script.clone());
        for file in [script.clone(),generator] {config.profile_files.push(ordinary_profile::File{sha256:durable::hash(&fs::read(&file).unwrap()),path:file});}
        let definition=fs::read_to_string(&f.installed.definition).unwrap();
        let before=definition.lines().find(|line|line.starts_with("ExecStart=")).unwrap();
        let text=definition.replace(before,&format!("ExecStart={{ path=/bin/sh ; argv[]=/bin/sh {} ; ignore_errors=no ; }}",script.display()))
            .replace("Environment=\n",&format!("Environment=KURA_JVM_ARGS_FILE={}\n",f.installed.args.display()));
        config.unit_definition_sha256=Profile::definition(&config,&text).unwrap();
        durable::json(&f.installed.profile,&config).unwrap();durable::write(&f.installed.definition,text.as_bytes(),FileMetadata::private()).unwrap();
        if override_provider {assert!(f.prepare().unwrap_err().to_string().contains("overrides generated"));assert!(!paths(&f.store,f.original.operation).0.exists());}
        else {assert_eq!(f.prepare().unwrap()["startupFilesChanged"],false);}
        assert_eq!(fs::read_to_string(script).unwrap(),body);
    }
}
#[test]
fn original_owner_marker_body_and_descriptor_identity_cannot_be_replaced_by_equal_looking_fences() {
    for same_bytes in [false,true] {
        let f=Fixture::new();let bytes=fs::read(&f.marker).unwrap();
        durable::write(&f.marker,if same_bytes{&bytes}else{b"foreign fixed fence"},FileMetadata::private()).unwrap();
        assert!(f.prepare().unwrap_err().to_string().contains("original fixed owner fence"));
        assert!(!paths(&f.store,f.original.operation).0.exists());
    }
}
#[test]
fn new_startup_journal_does_not_duplicate_a_kura_encryption_key_from_the_original_argument_file() {
    let f=Fixture::new();f.prepare().unwrap();
    let (intent,journal)=paths(&f.store,f.original.operation);
    for path in [intent,journal] {
        let bytes=fs::read(path).unwrap();
        assert!(!bytes.windows(b"fixture-secret-must-not-leak".len()).any(|part|part==b"fixture-secret-must-not-leak"),
            "a new agent startup record must not retain plaintext JVM secrets");
    }
}
#[test]
fn historical_inline_startup_queries_keep_the_original_schema_bytes_and_never_upgrade_or_redispatch() {
    let f=Fixture::new();let prepared=f.prepare().unwrap();assert_eq!(prepared["schemaVersion"],4);
    let (intent,journal_path)=paths(&f.store,f.original.operation);
    let mut plan:Plan=serde_json::from_slice(&fs::read(&intent).unwrap()).unwrap();
    let config:Config=serde_json::from_str(&plan.source_profile).unwrap();let source=fs::read_to_string(&f.installed.args).unwrap();
    let (args,grant,_)=generated(&config,&source,plan.operation_id).unwrap();plan.generated_profile=grant;plan.generated_arguments_version=None;
    plan.schema_version=1;plan.source_args=Some(source);plan.generated_args=Some(args);
    plan.generated_args_sha256=None;plan.kura_home=None;plan.source_roles_sha256=None;plan.stop_policy=None;
    let mut journal:Journal=serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal.schema_version=1;let bytes=serde_json::to_vec(&plan).unwrap();journal.plan_sha256=durable::hash(&bytes);
    durable::write(&intent,&bytes,FileMetadata::private()).unwrap();durable::json(&journal_path,&journal).unwrap();
    let before_journal=fs::read(&journal_path).unwrap();let calls=fs::read(&f.installed.calls).unwrap();
    let view=original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap();
    assert_eq!(view["schemaVersion"],1);assert_eq!(view["confirmationToken"],prepared["confirmationToken"]);
    assert!(!view.to_string().contains("fixture-secret-must-not-leak"));
    assert_eq!(fs::read(&intent).unwrap(),bytes);assert_eq!(fs::read(&journal_path).unwrap(),before_journal);
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    plan.schema_version=2;journal.schema_version=2;let mixed=serde_json::to_vec(&plan).unwrap();journal.plan_sha256=durable::hash(&mixed);
    durable::write(&intent,&mixed,FileMetadata::private()).unwrap();durable::json(&journal_path,&journal).unwrap();
    assert!(original(&f.store,f.original.operation,&f.original.plan,None).unwrap_err().to_string().contains("inline JVM secrets are forbidden"));
}
#[test]
fn historical_schema2_startup_remains_query_only_without_synthesizing_role_authority_or_a_new_probe() {
    let f=Fixture::new();f.prepare().unwrap();let (intent,journal_path)=paths(&f.store,f.original.operation);
    let mut plan:Plan=serde_json::from_slice(&fs::read(&intent).unwrap()).unwrap();plan.schema_version=2;plan.source_roles_sha256=None;plan.stop_policy=None;plan.generated_arguments_version=None;
    let config:Config=serde_json::from_str(&plan.source_profile).unwrap();let (args,grant,_)=generated(&config,&fs::read_to_string(&f.installed.args).unwrap(),plan.operation_id).unwrap();
    plan.generated_args_sha256=Some(durable::hash(args.as_bytes()));plan.generated_profile=grant;
    let mut journal:Journal=serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();journal.schema_version=2;
    let bytes=serde_json::to_vec(&plan).unwrap();journal.plan_sha256=durable::hash(&bytes);
    durable::write(&intent,&bytes,FileMetadata::private()).unwrap();durable::json(&journal_path,&journal).unwrap();
    let calls=fs::read(&f.installed.calls).unwrap();
    assert_eq!(original(&f.store,f.original.operation,&f.original.plan,Some("local-uid:fixture")).unwrap().unwrap()["schemaVersion"],2);
    assert!(association_begin(&f.store,&f.original,"local-uid:fixture",&journal.confirmation_token,&f.installed.systemctl).err().unwrap().to_string().starts_with("UNSUPPORTED"));
    assert_eq!(fs::read(intent).unwrap(),bytes);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    assert!(!proof_path(&f.store,f.original.operation).exists());
}

// Only the new Linux-owned namespace seeder can request this synthetic prefix.
#[cfg(target_os="linux")]
pub(in crate::nm) fn recovery_bootstrap_quarantine(command:Box<publication::recovery::Command>) {
    (*command).fixture_prefix(1,false).unwrap();
}

// A new, explicit cross-language fixture exports only the two actual published
// framework selections. No original JVM body, key, token or unit is exported.
#[test]
#[ignore="explicit new owned publication-to-SCR fixture;no production switch"]
fn writer_profile_published_properties_fixture() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let output=PathBuf::from(std::env::var_os("YOFC_WRITER_PROFILE_PROPERTIES_OUTPUT").expect("explicit owned output"));
    assert!(output.is_absolute());let parent=output.parent().unwrap();
    assert_eq!(fs::read(parent.join(".owned-writer-profile-export-v20")).unwrap(),b"owned cross-language startup proof v20\n");
    let f=Fixture::new();let published=f.published();
    let bytes=fs::read(&f.installed.args).unwrap();let args=ordinary_profile::tokens(&bytes).unwrap();
    let pids=property(&args,"kura.configuration.external.pids").unwrap().unwrap();
    let provider=property(&args,"kura.firewall.provider").unwrap().unwrap();
    let body=format!("kura.configuration.external.pids={pids}\nkura.firewall.provider={provider}\ngeneratedArgumentsVersion={}\ngeneratedArgsSha256={}\n",published["generatedArgumentsVersion"],durable::hash(&bytes));
    let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&output).unwrap();
    file.write_all(body.as_bytes()).unwrap();file.sync_all().unwrap();
    println!("published framework selections retained at {}",output.display());
}
