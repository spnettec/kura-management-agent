//! Original-bound generated ordinary startup proposal. This module deliberately
//! publishes private review evidence only; it never edits the installed profile,
//! creates a system fence, or dispatches a service action while preparing.
use super::*;
use crate::recovery::ordinary_profile::{self,Config,Profile};
use std::collections::BTreeSet;
mod stop;
mod execution;
pub(in crate::nm) use stop::Command as StopCommand;
mod publication;
pub(in crate::nm) use publication::recovery::Step as RecoveryStep;
pub(in crate::nm) struct RecoveryApproval {pub(in crate::nm) id:uuid::Uuid,pub(in crate::nm) token:String}
pub(in crate::nm) use publication::StepResult as PublicationStep;
mod profile;
mod start;
pub(in crate::nm) use start::Step as StartStep;
mod completion;
pub(super) mod runtime;
mod stopped;
pub(in crate::nm) use runtime::Challenge as CurrentRuntimeChallenge;
pub(in crate::nm) use stopped::Challenge as StoppedRuntimeChallenge;
pub(in crate::nm) use completion::{Challenge as CompletionChallenge,Step as CompletionStep,Witness as CompletionWitness};
pub(super) fn profile_marker(root:&Path,id:uuid::Uuid,parent:&str)->Result<Option<PathBuf>> {profile::marker(root,id,parent)}
pub(super) fn resolve_profile(root:&Path,id:uuid::Uuid,parent:&str,marker:&MarkerIdentity,path:&Path,source:&str)->Result<Option<super::OrdinarySelection>> {
    profile::resolve(root,id,parent,marker,path,source)
}

const ARGS_LIMIT:u64=256<<10;
const PLAN_LIMIT:u64=2<<20;
#[cfg(test)]
pub(in crate::nm) mod tests;
#[cfg(test)]
mod launch_argument_tests {
    use super::*;

    fn config() -> Config {
        Config {
            schema: 1,
            profile_id: "profile-11111111-1111-4111-8111-111111111111".into(),
            unit: "yofc-kura.service".into(), unit_file: "/etc/systemd/system/yofc-kura.service".into(),
            jvm_args_path: "/opt/kura/jvm.args".into(), unit_definition_sha256: "a".repeat(64),
            timeout_seconds: 30, valid_for_seconds: 600,
            component_pids: vec!["org.eclipse.kura.net.admin.NetworkConfigurationService".into()],
            check_ids: vec!["kura.network.status-observation".into()],
            profile_files: vec![ordinary_profile::File { path: "/opt/kura/jvm.args".into(), sha256: "b".repeat(64) },
                ordinary_profile::File { path: "/etc/systemd/system/yofc-kura.service".into(), sha256: "c".repeat(64) }],
            launcher_kind: ordinary_profile::Launcher::DirectJava, launcher_script_path: None,
        }
    }

    fn source(config: &Config, launcher: &str) -> String {
        format!("-Dkura.home=/opt/kura\n-Dkura.management.ordinary.profile.id={}\n-Dkura.management.ordinary.verification.enabled=true\n{launcher}", config.profile_id)
    }

    fn operation() -> uuid::Uuid { "22222222-2222-4222-8222-222222222222".parse().unwrap() }

    #[test]
    fn generated_vm_options_precede_jar_module_and_main_launchers() {
        for (launcher, selector) in [
            ("-jar\n/opt/kura/launcher.jar\n-consoleLog\n", "-jar"),
            ("--module-path\n/opt/kura/modules\n-m\nexample/app.Main\napp-value\n", "-m"),
            ("-cp\n/opt/kura/classes\nexample.Main\napp-value\n", "example.Main"),
        ] {
            let config = config();
            let (body, _, _) = generated_version(&config, &source(&config, launcher), operation(), 3).unwrap();
            let args = ordinary_profile::tokens(body.as_bytes()).unwrap();
            let main = args.iter().position(|value| value == selector).unwrap();
            for name in ["kura.management.ordinary.profile.id", "kura.configuration.external.pids", "kura.network.confirmed.provider", "kura.firewall.provider"] {
                let flag = args.iter().position(|value| value.starts_with(&format!("-D{name}="))).unwrap();
                assert!(flag < main, "{name} must be a JVM option before {selector}, not an application argument");
            }
        }
    }

    #[test]
    fn application_arguments_are_preserved_even_when_they_look_like_vm_properties() {
        let config = config();
        let launcher = "-jar\n/opt/kura/launcher.jar\n-Dkura.configuration.external.pids=application.literal\n";
        let (body, _, _) = generated_version(&config, &source(&config, launcher), operation(), 3).unwrap();
        let args = ordinary_profile::tokens(body.as_bytes()).unwrap();
        let main = args.iter().position(|value| value == "-jar").unwrap();
        assert_eq!(&args[main..], ["-jar", "/opt/kura/launcher.jar", "-Dkura.configuration.external.pids=application.literal"]);
    }

    #[test]
    fn observer_properties_after_main_never_authorize_a_startup_proposal() {
        let config = config();
        let source = format!("-Dkura.home=/opt/kura\n-jar\n/opt/kura/launcher.jar\n-Dkura.management.ordinary.profile.id={}\n-Dkura.management.ordinary.verification.enabled=true\n", config.profile_id);
        assert!(generated_version(&config, &source, operation(), 3).is_err());
    }

    #[test]
    fn packaged_jvm_only_argument_files_keep_their_existing_contract() {
        let config = config();
        let (body, _, _) = generated_version(&config, &source(&config, "-Xmx256m\n"), operation(), 3).unwrap();
        let args = ordinary_profile::tokens(body.as_bytes()).unwrap();
        assert!(args.contains(&"-Xmx256m".into()));
        assert!(args.contains(&"-Dkura.network.confirmed.provider=nm-agent-v1".into()));
    }

    #[test]
    fn historical_v1_v2_argument_bytes_are_not_rewritten_under_the_new_contract() {
        let config = config();
        for (version, expected) in [
            (1, "b5366efc86c0ba3da3cfe2df6e42546f952321a9d50af805216a3e21315c9c70"),
            (2, "15b5110edeb6b74fac43aaa13216118f42223a28022b35af6f2f52b022ff4529"),
        ] {
            let (body, _, _) = generated_version(&config, &source(&config, "-jar\n/opt/kura/launcher.jar\n"), operation(), version).unwrap();
            assert_eq!(durable::hash(body.as_bytes()), expected);
        }
    }
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Image {sha256:String,metadata:FileMetadata,device:u64,inode:u64,size:u64,ctime:i64,ctime_nanos:i64}
impl Image {
    fn read(path:&Path,limit:u64)->Result<(Self,Vec<u8>)> {
        let before=fs::symlink_metadata(path)?;
        let bytes=crate::controlled_startup::trusted_file(path,limit)?;
        let after=fs::symlink_metadata(path)?;
        ensure!(before.is_file() && after.is_file() && before.nlink()==1 && after.nlink()==1
            && before.dev()==after.dev() && before.ino()==after.ino() && before.len()==after.len()
            && before.ctime()==after.ctime() && before.ctime_nsec()==after.ctime_nsec()
            && FileMetadata::from_fs(&before)==FileMetadata::from_fs(&after) && after.len()==bytes.len() as u64,
            "CONFLICT: installed startup source changed during read");
        Ok((Self{sha256:durable::hash(&bytes),metadata:FileMetadata::from_fs(&after),device:after.dev(),
            inode:after.ino(),size:after.len(),ctime:after.ctime(),ctime_nanos:after.ctime_nsec()},bytes))
    }
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Fence {path:PathBuf,before:Option<Image>}
fn canonical(path:&Path)->bool {
    path.is_absolute() && path.components().all(|part|matches!(part,std::path::Component::RootDir|std::path::Component::Normal(_)))
}
fn fence(path:PathBuf)->Result<Fence> {
    ensure!(canonical(&path),"FORBIDDEN: fixed canonical startup fence required");
    let parent=fs::symlink_metadata(path.parent().context("startup fence parent")?)?;
    ensure!(parent.is_dir() && parent.mode()&0o022==0 && (parent.uid()==0 || parent.uid()==unsafe{libc::geteuid()}),
        "FORBIDDEN: trusted installed startup fence parent required");
    let before=match fs::symlink_metadata(&path) {
        Ok(_)=>Some(Image::read(&path,16384)?.0),
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>None,
        Err(error)=>return Err(error.into()),
    };Ok(Fence{path,before})
}
fn property<'a>(args:&'a[String],name:&str)->Result<Option<&'a str>> {
    let prefix=format!("-D{name}=");let values=args.iter().filter_map(|arg|arg.strip_prefix(&prefix)).collect::<Vec<_>>();
    ensure!(values.len()<=1,"FORBIDDEN: duplicate controlled startup property");Ok(values.first().copied())
}
fn require_argument_file_authority(config:&Config,definition:&str)->Result<()> {
    Profile::declaration(config,definition)?;
    if config.launcher_kind==ordinary_profile::Launcher::DirectJava {
        let start=definition.lines().find_map(|line|line.strip_prefix("ExecStart=")).context("CONFLICT: installed startup definition missing")?;
        let argv=start.split_once("argv[]=").context("CONFLICT: installed startup arguments missing")?.1
            .split_once(" ; ignore_errors=").context("CONFLICT: installed startup arguments unbounded")?.0;
        let words=argv.split_whitespace().collect::<Vec<_>>();
        ensure!(words.len()==2 && words[0].ends_with("/java") && words[1]==format!("@{}",config.jvm_args_path.display()),
            "UNSUPPORTED: generated NM startup requires all Java arguments in the pinned argument file");
    } else {
        let script=config.launcher_script_path.as_ref().context("CONFLICT: installed packaged launcher missing")?;
        let body=crate::controlled_startup::trusted_file(script,64<<10)?;
        let body=std::str::from_utf8(&body)?;
        ordinary_profile::packaged_launcher(config,body)?;
        let code=body.lines().filter(|line|!line.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n");
        let source=crate::controlled_startup::trusted_file(&config.jvm_args_path,ARGS_LIMIT)?;
        let args=ordinary_profile::tokens(&source)?;
        let vm=&args[..ordinary_profile::jvm_option_end(&args)?];
        let home=PathBuf::from(property(vm,"kura.home")?.context("CONFLICT: installed packaged home missing")?);
        ensure!(script.parent().and_then(Path::parent).context("CONFLICT: packaged launcher location")?.canonicalize()?==home.canonicalize()?,
            "UNSUPPORTED: packaged launcher must belong to the reviewed Kura home");
        for name in ["kura.configuration.external.pids","kura.network.confirmed.provider","kura.firewall.provider",
            "kura.management.ordinary.profile.id","kura.management.ordinary.verification.enabled"] {
            ensure!(!code.contains(&format!("-D{name}")),"UNSUPPORTED: packaged launcher overrides generated NM startup arguments");
        }
        for line in code.lines().filter(|line|line.contains("-Dkura.home")) {
            ensure!(matches!(line.trim(),"-Dkura.home=${DIR} \\"|"-Dkura.home=${DIR}"),
                "UNSUPPORTED: packaged launcher overrides the reviewed Kura home");
        }
    }
    Ok(())
}
fn generated(config:&Config,source:&str,operation:uuid::Uuid)->Result<(String,String,PathBuf)> {
    generated_version(config,source,operation,1)
}
fn generated_for(plan:&Plan,config:&Config,source:&str)->Result<(String,String,PathBuf)> {
    generated_version(config,source,plan.operation_id,plan.generated_arguments_version.unwrap_or(1))
}
fn generated_version(config:&Config,source:&str,operation:uuid::Uuid,version:u8)->Result<(String,String,PathBuf)> {
    ensure!(matches!(version,1..=3),"CONFLICT: unsupported original startup argument contract");
    Profile::config(config)?;
    let args=ordinary_profile::tokens(source.as_bytes())?;
    // Historical v1/v2 retain their original bytes. Only new v3 proposals
    // distinguish JVM options from launcher/application arguments.
    let split=if version==3 {ordinary_profile::jvm_option_end(&args)?}else{args.len()};
    let (vm,application)=args.split_at(split);
    ensure!(property(vm,"kura.management.ordinary.profile.id")?==Some(config.profile_id.as_str())
        && property(vm,"kura.management.ordinary.verification.enabled")?==Some("true"),
        "CONFLICT: original ordinary startup identity");
    ensure!(property(vm,"kura.network.confirmed.provider")?.is_none_or(|value|value=="nm-agent-v1")
        && property(vm,"kura.firewall.provider")?.is_none_or(|value|matches!(value,"legacy"|"agent")),
        "UNSUPPORTED: another startup provider requires an explicit migration");
    let home=PathBuf::from(property(vm,"kura.home")?.context("UNSUPPORTED: installed startup must explicitly bind kura.home")?);
    ensure!(canonical(&home),"FORBIDDEN: canonical installed Kura home required");
    let mut pids=BTreeSet::new();
    if let Some(value)=property(vm,"kura.configuration.external.pids")? {
        for pid in value.split(',').map(str::trim) {
            ensure!(!pid.is_empty() && pid.len()<=512 && !pid.chars().any(|ch|ch.is_control()||ch.is_whitespace())
                && pids.insert(pid.to_owned()),"FORBIDDEN: ambiguous original external PID reservation");
        }
    }
    pids.insert(roles::PID.into());
    if version>=2 {
        pids.insert("org.eclipse.kura.net.admin.FirewallConfigurationService".into());
        pids.insert("org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6".into());
    }
    ensure!(pids.len()<=128,"FORBIDDEN: startup reservation quota");
    let replaced=["kura.management.ordinary.profile.id","kura.configuration.external.pids","kura.network.confirmed.provider","kura.firewall.provider"];
    let mut next=vm.iter().filter(|arg|!replaced.iter().any(|name|arg.starts_with(&format!("-D{name}=")))).cloned().collect::<Vec<_>>();
    next.extend([format!("-Dkura.management.ordinary.profile.id=profile-{operation}"),
        format!("-Dkura.configuration.external.pids={}",pids.into_iter().collect::<Vec<_>>().join(",")),
        "-Dkura.network.confirmed.provider=nm-agent-v1".into(),"-Dkura.firewall.provider=agent".into()]);
    next.extend(application.iter().cloned());
    let body=next.into_iter().map(|arg|if arg.chars().any(char::is_whitespace){format!("\"{arg}\"\n")}else{format!("{arg}\n")}).collect::<String>();
    ensure!(body.len() as u64<=ARGS_LIMIT,"RESOURCE_EXHAUSTED: generated startup arguments");
    ordinary_profile::tokens(body.as_bytes())?;
    let target=target_grant(config,operation,&durable::hash(body.as_bytes()))?;
    Ok((body,target,home))
}
fn target_grant(config:&Config,operation:uuid::Uuid,args_sha256:&str)->Result<String> {
    ensure!(hex(args_sha256,64),"CONFLICT: generated argument digest");
    let mut target=config.clone();target.profile_id=format!("profile-{operation}");
    for file in &mut target.profile_files {if file.path==config.jvm_args_path {file.sha256=args_sha256.into();}}
    Profile::config(&target)?;serde_json::to_string(&target).map_err(Into::into)
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Plan {
    schema_version:u8,operation_id:uuid::Uuid,parent_plan_sha256:String,actor:String,token_sha256:String,
    source_path:PathBuf,source_profile:String,source_profile_digest:String,source_args_image:Image,
    // Only immutable historical schema1 queries may contain inline arguments.
    // New proposals retain hashes; no JVM key/password is copied into agent state.
    #[serde(default,skip_serializing_if="Option::is_none")]
    source_args:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    generated_args:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    generated_args_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    generated_arguments_version:Option<u8>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    kura_home:Option<PathBuf>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    source_roles_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    stop_policy:Option<crate::system_control::StopPolicy>,
    generated_profile:String,owner_marker:PathBuf,owner_marker_identity:MarkerIdentity,fences:Vec<Fence>,
    before_unit:crate::system_control::Unit,expires_at_unix_ms:u64,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Journal {
    schema_version:u8,operation_id:uuid::Uuid,parent_plan_sha256:String,plan_sha256:String,confirmation_token:String,state:String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    old_association_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    stop_intent_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    stop_receipt_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    publication_intent_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    publication_receipt_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    start_intent_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    start_receipt_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    completion_receipt_sha256:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    recovery:Option<RecoveryLink>,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct RecoveryLink {id:uuid::Uuid,plan_sha256:String}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct AssociationProof {schema_version:u8,startup_plan_sha256:String,spec:roles::StartupSpec,role_observation:roles::Observation,association:roles::StartupAssociation}
#[derive(Clone,PartialEq,Eq)]
pub(in crate::nm) struct AssociationChallenge {pub(in crate::nm) spec:roles::StartupSpec,pub(in crate::nm) profile_id:String,pub(in crate::nm) pid:u32}
pub(in crate::nm) enum AssociationStep {Observed(Value),Challenge(AssociationChallenge)}
pub(super) fn require_no_native_child(root:&Path,id:uuid::Uuid)->Result<()> {
    let prefix=format!("{id}.startup-");
    for entry in fs::read_dir(root)? {
        let entry=entry?;ensure!(!entry.file_name().to_string_lossy().starts_with(&prefix),
            "CONFLICT: original startup child/effect evidence must settle before a native change;retain its execution binding");
    }
    Ok(())
}

fn paths(root:&Path,id:uuid::Uuid)->(PathBuf,PathBuf) {
    (root.join(format!("{id}.startup-plan.json")),root.join(format!("{id}.startup-journal.json")))
}
fn present(path:&Path)->Result<bool> {
    match fs::symlink_metadata(path){Ok(_)=>Ok(true),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>Ok(false),Err(e)=>Err(e.into())}
}
fn argument_binding(plan:&Plan,config:&Config)->Result<(String,PathBuf)> {
    match plan.schema_version {
        1=>{
            ensure!(plan.generated_args_sha256.is_none() && plan.kura_home.is_none(),"CONFLICT: mixed historical startup argument shapes");
            let source=plan.source_args.as_ref().context("CONFLICT: historical startup source missing")?;
            let (args,grant,home)=generated(config,source,plan.operation_id)?;
            ensure!(plan.generated_args.as_ref()==Some(&args) && grant==plan.generated_profile
                && durable::hash(source.as_bytes())==plan.source_args_image.sha256,"CONFLICT: historical startup argument binding");
            Ok((durable::hash(args.as_bytes()),home))
        }
        2..=4=>{
            ensure!(plan.source_args.is_none() && plan.generated_args.is_none(),"CONFLICT: inline JVM secrets are forbidden in new startup evidence");
            let hash=plan.generated_args_sha256.as_ref().context("CONFLICT: generated startup digest missing")?;
            let home=plan.kura_home.as_ref().context("CONFLICT: startup Kura home missing")?;
            ensure!(hex(hash,64) && canonical(home) && target_grant(config,plan.operation_id,hash)?==plan.generated_profile,
                "CONFLICT: generated startup hash/grant binding");Ok((hash.clone(),home.clone()))
        }
        _=>anyhow::bail!("CONFLICT: unsupported startup argument schema"),
    }
}
fn validate(plan:&Plan,journal:&Journal)->Result<()> {
    ensure!(plan.generated_arguments_version.is_none() || (plan.schema_version==4 && matches!(plan.generated_arguments_version,Some(2|3))),
        "CONFLICT: startup argument generation contract binding");
    ensure!(journal.recovery.as_ref().is_none_or(|link|plan.schema_version==4 && !link.id.is_nil() && hex(&link.plan_sha256,64)),"CONFLICT: original recovery link binding");
    ensure!(matches!(plan.schema_version,1..=4) && journal.schema_version==plan.schema_version && !plan.operation_id.is_nil()
        && plan.operation_id==journal.operation_id && plan.parent_plan_sha256==journal.parent_plan_sha256
        && hex(&plan.parent_plan_sha256,64) && hex(&journal.plan_sha256,64) && hex(&journal.confirmation_token,32)
        && durable::hash(journal.confirmation_token.as_bytes())==plan.token_sha256
        && !plan.actor.is_empty() && plan.actor.len()<=256 && plan.actor.bytes().all(|ch|ch.is_ascii_graphic())
        && canonical(&plan.source_path) && canonical(&plan.owner_marker),
        "CONFLICT: original startup proposal identity");
    if plan.schema_version<3 {
        ensure!(plan.source_roles_sha256.is_none() && journal.old_association_sha256.is_none()
            && journal.stop_intent_sha256.is_none() && journal.stop_receipt_sha256.is_none() && journal.state=="PREPARED",
            "CONFLICT: historical startup proposal cannot gain a new association");
    } else {
        ensure!(plan.source_roles_sha256.as_deref().is_some_and(|value|hex(value,64))
            && match journal.state.as_str(){"PREPARED"=>journal.old_association_sha256.is_none(),"OLD_JVM_ASSOCIATED"=>journal.old_association_sha256.as_deref().is_some_and(|value|hex(value,64)),_=>false},
            "CONFLICT: original startup association phase");
    }
    if plan.schema_version<4 {
        ensure!(plan.stop_policy.is_none() && journal.stop_intent_sha256.is_none() && journal.stop_receipt_sha256.is_none()
            && journal.publication_intent_sha256.is_none() && journal.publication_receipt_sha256.is_none()
            && journal.start_intent_sha256.is_none() && journal.start_receipt_sha256.is_none() && journal.completion_receipt_sha256.is_none(),
            "CONFLICT: historical startup proposal cannot gain stop authority");
    } else {plan.stop_policy.as_ref().context("CONFLICT: reviewed startup stop policy missing")?.validate()?;}
    ensure!(journal.stop_intent_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && journal.stop_receipt_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && (journal.stop_intent_sha256.is_none() || journal.old_association_sha256.is_some())
        && (journal.stop_receipt_sha256.is_none() || journal.stop_intent_sha256.is_some()),
        "CONFLICT: original startup stop pointers");
    ensure!(journal.publication_intent_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && journal.publication_receipt_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && (journal.publication_intent_sha256.is_none() || journal.stop_receipt_sha256.is_some())
        && (journal.publication_receipt_sha256.is_none() || journal.publication_intent_sha256.is_some()),
        "CONFLICT: original startup publication pointers");
    ensure!(journal.start_intent_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && journal.start_receipt_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && (journal.start_intent_sha256.is_none() || journal.publication_receipt_sha256.is_some())
        && (journal.start_receipt_sha256.is_none() || journal.start_intent_sha256.is_some()),
        "CONFLICT: original startup start pointers");
    ensure!(journal.completion_receipt_sha256.as_deref().is_none_or(|hash|hex(hash,64))
        && (journal.completion_receipt_sha256.is_none() || journal.start_receipt_sha256.is_some()),
        "CONFLICT: original startup completion pointer");
    let marker=serde_json::to_vec(&Marker{schema_version:1,operation_id:plan.operation_id,plan_sha256:plan.parent_plan_sha256.clone()})?;
    ensure!(plan.owner_marker_identity.sha256==durable::hash(&marker),"CONFLICT: original startup owner fence identity");
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    Profile::config(&config)?;
    let mut hashes=vec![durable::hash(plan.source_profile.as_bytes())];hashes.extend(config.profile_files.iter().map(|file|file.sha256.clone()));
    let (_,home)=argument_binding(plan,&config)?;
    ensure!(durable::hash(hashes.join("\n").as_bytes())==plan.source_profile_digest && hex(&plan.source_args_image.sha256,64)
        && config.profile_files.iter().any(|file|file.path==config.jvm_args_path && file.sha256==plan.source_args_image.sha256)
        && plan.before_unit.unit==config.unit && plan.before_unit.running()
        && plan.fences.iter().map(|file|file.path.clone()).collect::<Vec<_>>()==[
            plan.owner_marker.parent().context("owner marker parent")?.join("firewall-owner-agent"),
            home.join("framework/network-owner-agent"),home.join("framework/firewall-owner-agent")],
        "CONFLICT: generated startup proposal changed");Ok(())
}
fn value(root:&Path,plan:&Plan,journal:&Journal,include_token:bool)->Result<Value> {
    let config:Config=serde_json::from_str(&plan.generated_profile)?;
    let source:Config=serde_json::from_str(&plan.source_profile)?;let (args_sha256,_)=argument_binding(plan,&source)?;
    let mut value=json!({"schemaVersion":plan.schema_version,"operationId":plan.operation_id,"parentPlanSha256":plan.parent_plan_sha256,
        "state":journal.state,"planSha256":journal.plan_sha256,"unit":config.unit,"profileId":config.profile_id,
        "sourceProfileDigest":plan.source_profile_digest,"generatedArgumentsSha256":args_sha256,
        "generatedProfileSha256":durable::hash(plan.generated_profile.as_bytes()),"reservedPid":roles::PID,
        "generatedArgumentsVersion":plan.generated_arguments_version.unwrap_or(1),
        "requiredReservedPids":if matches!(plan.generated_arguments_version,Some(2|3)){vec![roles::PID,"org.eclipse.kura.net.admin.FirewallConfigurationService","org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6"]}else{vec![roles::PID]},
        "stopPolicySha256":plan.stop_policy.as_ref().map(|policy|&policy.definition_sha256),
        "confirmedProvider":"nm-agent-v1","firewallProvider":"agent","expiresAtUnixMs":plan.expires_at_unix_ms,
        "fences":plan.fences.iter().map(|file|json!({"path":file.path,"action":if file.before.is_some(){"retain-and-recheck"}else{"create-only"}})).collect::<Vec<_>>(),
        "oldJvmAssociationVerified":journal.old_association_sha256.is_some(),"associationReceiptSha256":journal.old_association_sha256,
        "associationScope":"historical-jvm-unit-profile-only","freshAssociationRequiredBeforeStop":true,
        "executionAvailable":false,"unitActionsIssued":false,"startupFilesChanged":false,
        "systemAdoptionVerified":false});
    if include_token {value["confirmationToken"]=json!(journal.confirmation_token);}
    if let Some(status)=stop::status(root,plan,journal)? {
        value["state"]=status["state"].clone();value["stop"]=status;value["unitActionsIssued"]=json!(true);
    }
    if let Some(status)=publication::status(root,plan,journal)? {
        value["state"]=status["state"].clone();value["startupFilesChanged"]=if status["receiptSha256"].is_string(){json!(true)}else{Value::Null};
        value["startupFilesMayHaveChanged"]=json!(true);value["publication"]=status;
    }
    if let Some(status)=start::status(root,plan,journal)? {
        value["state"]=status["state"].clone();value["start"]=status;
    }
    if let Some(status)=completion::status(root,plan,journal)? {
        value["state"]=status["state"].clone();value["completion"]=status;
    }
    if let Some(status)=publication::recovery::status(root,plan,journal,include_token)? {value["fileRecovery"]=status;}
    Ok(value)
}
fn load(root:&Path,id:uuid::Uuid,parent:&str)->Result<Option<(Plan,Journal)>> {
    let (intent,path)=paths(root,id);
    let (has_intent,has_journal)=(present(&intent)?,present(&path)?);
    if !has_intent && !has_journal {return Ok(None);}
    ensure!(has_intent && has_journal,"OUTCOME_UNKNOWN: original startup proposal evidence is incomplete");
    let raw=BoundFile::open(&intent,PLAN_LIMIT)?.bytes;
    let plan:Plan=serde_json::from_slice(&raw)?;let journal:Journal=serde_json::from_slice(&read(&path)?)?;
    ensure!(durable::hash(&raw)==journal.plan_sha256 && plan.operation_id==id && plan.parent_plan_sha256==parent,
        "CONFLICT: original startup proposal binding");validate(&plan,&journal)?;
    let proof=proof(root,&plan,&journal)?;
    ensure!(journal.old_association_sha256.is_none() || proof.is_some(),"OUTCOME_UNKNOWN: original startup association receipt missing");
    stop::status(root,&plan,&journal)?;
    publication::status(root,&plan,&journal)?;
    start::status(root,&plan,&journal)?;
    completion::status(root,&plan,&journal)?;
    publication::recovery::status(root,&plan,&journal,false)?;
    Ok(Some((plan,journal)))
}
pub(super) fn original(root:&Path,id:uuid::Uuid,parent:&str,actor:Option<&str>)->Result<Option<Value>> {
    let Some((plan,journal))=load(root,id,parent)? else{return Ok(None)};
    if let Some(actor)=actor {ensure!(actor==plan.actor,"FORBIDDEN: original startup actor required");}
    value(root,&plan,&journal,actor.is_some()).map(Some)
}
pub(super) fn prepare(root:&Path,owner_marker:&Path,original:&Requirements,actor:&str,source:&Path,systemctl:&Path)->Result<Value> {
    let (intent,path)=paths(root,original.operation);
    ensure!(!present(&intent)? && !present(&path)?,
        "OUTCOME_UNKNOWN: query the original startup proposal; never prepare it again");
    let owner_file=BoundFile::open(owner_marker,16384)?;
    ensure!(owner_file.bytes==serde_json::to_vec(&Marker{schema_version:1,operation_id:original.operation,plan_sha256:original.plan.clone()})?
        && owner_file.marker()?==original.marker,"CONFLICT: startup source is not the original fixed owner fence");
    let (config,fingerprint,raw)=Profile::new(source.into())?.inputs()?;
    let (args_image,args)=Image::read(&config.jvm_args_path,ARGS_LIMIT)?;
    let source_args=String::from_utf8(args)?;
    let (generated_args,generated_profile,home)=generated_version(&config,&source_args,original.operation,3)?;
    let definition=||->Result<String>{
        let output=crate::process::run(systemctl,&["show",&config.unit,"--all",&format!("--property={}",ordinary_profile::UNIT_FIELDS)],None,Duration::from_secs(5))?;
        ensure!(output.status.success(),"CONFLICT: actual installed startup profile unavailable");
        let text=String::from_utf8(output.stdout)?;require_argument_file_authority(&config,&text)?;Ok(text)
    };
    let first_definition=definition()?;
    let stop_policy=crate::system_control::inspect_stop_policy(systemctl,&config)?;
    let before=crate::system_control::inspect_unit(systemctl,&config.unit)?;
    ensure!(before.running(),"CONFLICT: the reviewed Kura startup unit must be running");
    let fences=vec![fence(owner_marker.parent().context("network owner marker parent")?.join("firewall-owner-agent"))?,
        fence(home.join("framework/network-owner-agent"))?,fence(home.join("framework/firewall-owner-agent"))?];
    let token=uuid::Uuid::new_v4().simple().to_string();
    let plan=Plan{schema_version:4,operation_id:original.operation,parent_plan_sha256:original.plan.clone(),actor:actor.into(),
        token_sha256:durable::hash(token.as_bytes()),source_path:source.into(),source_profile:String::from_utf8(raw)?,
        source_profile_digest:fingerprint.clone(),source_args:None,source_args_image:args_image.clone(),generated_args:None,
        generated_args_sha256:Some(durable::hash(generated_args.as_bytes())),generated_arguments_version:Some(3),kura_home:Some(home),
        source_roles_sha256:Some(digest(&serde_json::to_value(&original.baseline.roles.roles)?)?),stop_policy:Some(stop_policy.clone()),generated_profile,
        owner_marker:owner_marker.into(),owner_marker_identity:original.marker.clone(),fences,before_unit:before.clone(),
        expires_at_unix_ms:std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64+config.valid_for_seconds*1000};
    ensure!(Profile::new(source.into())?.inputs()?.1==fingerprint && Image::read(&config.jvm_args_path,ARGS_LIMIT)?.0==args_image
        && definition()?==first_definition && crate::system_control::inspect_unit(systemctl,&config.unit)?==before
        && crate::system_control::inspect_stop_policy(systemctl,&config)?==stop_policy
        && plan.fences.iter().map(|file|fence(file.path.clone())).collect::<Result<Vec<_>>>()?==plan.fences,
        "CONFLICT: installed startup source changed during preparation");
    owner_file.verify_binding()?;
    let bytes=serde_json::to_vec(&plan)?;ensure!(bytes.len() as u64<=PLAN_LIMIT,"RESOURCE_EXHAUSTED: startup proposal quota");
    let journal=Journal{schema_version:4,operation_id:plan.operation_id,parent_plan_sha256:plan.parent_plan_sha256.clone(),
        plan_sha256:durable::hash(&bytes),confirmation_token:token,state:"PREPARED".into(),old_association_sha256:None,
        stop_intent_sha256:None,stop_receipt_sha256:None,publication_intent_sha256:None,publication_receipt_sha256:None,
        start_intent_sha256:None,start_receipt_sha256:None,completion_receipt_sha256:None,recovery:None};validate(&plan,&journal)?;
    durable::publish_new(&intent,&bytes,FileMetadata::private())?;
    durable::publish_new(&path,&serde_json::to_vec(&journal)?,FileMetadata::private())?;
    value(root,&plan,&journal,true)
}
fn challenge(plan:&Plan,journal:&Journal)->Result<AssociationChallenge> {
    ensure!(matches!(plan.schema_version,3|4),"UNSUPPORTED: historical startup proposals are query-only");
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    // A stable, unpredictable challenge belongs to this original child. Pure
    // JVM reads need no remote-write dispatch or business-health callback.
    let nonce=durable::hash(format!("{}\n{}\nnetwork-startup-old-jvm-association-v1",journal.plan_sha256,journal.confirmation_token).as_bytes());
    Ok(AssociationChallenge{spec:roles::StartupSpec::new(plan.operation_id,journal.plan_sha256.clone(),nonce)?,profile_id:config.profile_id,pid:plan.before_unit.pid})
}
fn proof_path(root:&Path,id:uuid::Uuid)->PathBuf {root.join(format!("{id}.startup-old-jvm.json"))}
fn proof(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<String>> {
    let path=proof_path(root,plan.operation_id);
    if !present(&path)? {return Ok(None);}
    let bytes=read(&path)?;let hash=durable::hash(&bytes);
    let data:AssociationProof=serde_json::from_slice(&bytes)?;let expected=challenge(plan,journal)?;
    ensure!(data.schema_version==1 && data.startup_plan_sha256==journal.plan_sha256 && data.spec==expected.spec
        && plan.source_roles_sha256.as_deref()==Some(digest(&serde_json::to_value(&data.role_observation.roles)?)?.as_str())
        && journal.old_association_sha256.as_ref().is_none_or(|known|known==&hash),"CONFLICT: original startup association receipt binding");
    data.association.require(&data.spec,&expected.profile_id,expected.pid,&data.role_observation)?;Ok(Some(hash))
}
fn recheck(plan:&Plan,systemctl:&Path)->Result<()> {
    let (config,fingerprint,_)=Profile::new(plan.source_path.clone())?.inputs()?;
    ensure!(fingerprint==plan.source_profile_digest && Image::read(&config.jvm_args_path,ARGS_LIMIT)?.0==plan.source_args_image
        && crate::system_control::inspect_unit(systemctl,&config.unit)?==plan.before_unit
        && plan.fences.iter().map(|item|fence(item.path.clone())).collect::<Result<Vec<_>>>()?==plan.fences,
        "CONFLICT: installed startup source/unit changed before JVM association");
    let output=crate::process::run(systemctl,&["show",&config.unit,"--all",&format!("--property={}",ordinary_profile::UNIT_FIELDS)],None,Duration::from_secs(5))?;
    ensure!(output.status.success(),"CONFLICT: startup unit definition unavailable");require_argument_file_authority(&config,&String::from_utf8(output.stdout)?)?;
    ensure!(BoundFile::open(&plan.owner_marker,16384)?.marker()?==plan.owner_marker_identity,"CONFLICT: original startup fence changed");Ok(())
}
fn authorized(root:&Path,original:&Requirements,actor:&str,token:&str)->Result<(Plan,Journal)> {
    let (plan,journal)=load(root,original.operation,&original.plan)?.context("NOT_FOUND: original startup proposal missing")?;
    ensure!(plan.actor==actor && token==journal.confirmation_token && hex(token,32),"FORBIDDEN: original startup actor/token required");Ok((plan,journal))
}
pub(super) fn association_begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<AssociationStep> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    let expected=challenge(&plan,&journal)?;
    if let Some(hash)=proof(root,&plan,&journal)? {
        if journal.old_association_sha256.is_none() {
            let receipt=BoundFile::open(&proof_path(root,plan.operation_id),LIMIT)?;
            ensure!(durable::hash(&receipt.bytes)==hash,"CONFLICT: original startup association receipt changed before acknowledgement");
            receipt.sync_exact()?;
            journal.old_association_sha256=Some(hash);journal.state="OLD_JVM_ASSOCIATED".into();
            durable::json(&paths(root,plan.operation_id).1,&journal)?;
        }
        return Ok(AssociationStep::Observed(value(root,&plan,&journal,true)?));
    }
    publication::recovery::forward_allowed(root,&plan,&journal)?;
    recheck(&plan,systemctl)?;Ok(AssociationStep::Challenge(expected))
}
pub(super) fn association_finish(root:&Path,original:&Requirements,actor:&str,token:&str,expected:&AssociationChallenge,
    witness:(roles::StartupAssociation,roles::Observation),systemctl:&Path)->Result<Value> {
    let (observed,role_observation)=witness;
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    publication::recovery::forward_allowed(root,&plan,&journal)?;
    ensure!(challenge(&plan,&journal)?==*expected && plan.source_roles_sha256.as_deref()==Some(digest(&serde_json::to_value(&role_observation.roles)?)?.as_str()),
        "CONFLICT: original startup association challenge or CM roles changed");
    observed.require(&expected.spec,&expected.profile_id,expected.pid,&role_observation)?;recheck(&plan,systemctl)?;
    ensure!(!present(&proof_path(root,plan.operation_id))?,"OUTCOME_UNKNOWN: query the original startup association receipt");
    let bytes=serde_json::to_vec(&AssociationProof{schema_version:1,startup_plan_sha256:journal.plan_sha256.clone(),spec:expected.spec.clone(),role_observation,association:observed})?;
    durable::publish_new(&proof_path(root,plan.operation_id),&bytes,FileMetadata::private())
        .context("OUTCOME_UNKNOWN: original startup association publication")?;
    journal.old_association_sha256=Some(durable::hash(&bytes));journal.state="OLD_JVM_ASSOCIATED".into();
    durable::json(&paths(root,plan.operation_id).1,&journal).context("OUTCOME_UNKNOWN: original startup association journal")?;
    value(root,&plan,&journal,true)
}
pub(super) fn stop_begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<AssociationStep> {
    stop::begin(root,original,actor,token,systemctl)
}
pub(super) fn stop_arm(root:&Path,original:&Requirements,actor:&str,token:&str,
    witness:(roles::StartupAssociation,roles::Observation),systemctl:&Path,deadline:std::time::Instant)->Result<StopCommand> {
    stop::arm(root,original,actor,token,witness,systemctl,deadline)
}
pub(super) fn publication_begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<PublicationStep> {
    publication::begin(root,original,actor,token,systemctl)
}
pub(super) fn start_begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<StartStep> {
    start::begin(root,original,actor,token,systemctl)
}
pub(super) fn completion_begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<CompletionStep> {
    completion::begin(root,original,actor,token,systemctl)
}
pub(super) fn completion_finish(root:&Path,original:&Requirements,actor:&str,token:&str,expected:&CompletionChallenge,witness:CompletionWitness,systemctl:&Path)->Result<Value> {
    completion::finish(root,original,actor,token,expected,witness,systemctl)
}
pub(super) fn activation_challenge(root:&Path,original:&Requirements,systemctl:&Path)->Result<CompletionChallenge> {
    completion::activation_challenge(root,original,systemctl)
}
pub(super) fn activation_finish(root:&Path,original:&Requirements,expected:&CompletionChallenge,witness:&CompletionWitness,systemctl:&Path)->Result<String> {
    completion::activation_finish(root,original,expected,witness,systemctl)
}
pub(super) fn runtime_challenge(root:&Path,original:&Requirements,systemctl:&Path)->Result<CurrentRuntimeChallenge> {
    runtime::challenge(root,original,systemctl)
}
pub(super) fn runtime_is_stopped(root:&Path,original:&Requirements,systemctl:&Path)->Result<bool> {
    stopped::hint(root,original,systemctl)
}
pub(super) fn stopped_runtime_challenge(root:&Path,original:&Requirements,systemctl:&Path)->Result<StoppedRuntimeChallenge> {
    stopped::challenge(root,original,systemctl)
}
pub(super) fn stopped_runtime_finish(root:&Path,original:&Requirements,expected:&StoppedRuntimeChallenge,systemctl:&Path)->Result<String> {
    stopped::finish(root,original,expected,systemctl)
}
pub(super) fn runtime_finish(root:&Path,original:&Requirements,expected:&CurrentRuntimeChallenge,witness:&CompletionWitness,systemctl:&Path)->Result<String> {
    runtime::finish(root,original,expected,witness,systemctl)
}
pub(super) fn require_lease(root:&Path,id:uuid::Uuid,parent:&str,template:&str,roles:&roles::ConfigurationRoles,hash:&str)->Result<()> {
    completion::require_lease(root,id,parent,template,roles,hash)
}
pub(super) fn recovery_prepare(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid,systemctl:&Path)->Result<Value> {
    publication::recovery::prepare(root,original,actor,token,id,systemctl)
}
pub(super) fn recovery_original(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid)->Result<Value> {
    publication::recovery::original(root,original,actor,token,id)
}
pub(super) fn recovery_cancel(root:&Path,original:&Requirements,actor:&str,token:&str,approval:&RecoveryApproval)->Result<Value> {
    publication::recovery::cancel(root,original,actor,token,approval.id,&approval.token)
}
pub(super) fn recovery_begin(root:&Path,original:&Requirements,actor:&str,token:&str,approval:&RecoveryApproval,systemctl:&Path)->Result<RecoveryStep> {
    publication::recovery::begin(root,original,actor,token,approval.id,&approval.token,systemctl)
}
