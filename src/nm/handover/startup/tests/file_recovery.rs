use super::*;
fn job_observation(f:&Fixture)->PathBuf {enable_job_at(&f.root)}
fn publication_prefix(f:&Fixture,prefix:&str)->String {
    let stopped=if prefix=="published"{f.published()}else{f.stopped()};let token=stopped["confirmationToken"].as_str().unwrap().to_string();
    if prefix!="published" {
        let PublicationStep::Dispatch(command)=publication_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).unwrap()else{panic!("fresh original publication")};drop(command);
        if prefix!="unentered" {
            let (plan,_)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
            let source=fs::read_to_string(&f.installed.args).unwrap();let config:Config=serde_json::from_str(&plan.source_profile).unwrap();
            fs::rename(&f.installed.args,backup_path(f)).unwrap();
            if prefix=="planned-unacknowledged" {
                let (body,_,_)=generated_for(&plan,&config,&source).unwrap();durable::write(&f.installed.args,body.as_bytes(),plan.source_args_image.metadata).unwrap();
            }
        }
    }
    job_observation(f);token
}
fn backup_path(f:&Fixture)->PathBuf {f.installed.args.with_file_name(format!(".{}.nm-before-{}",f.installed.args.file_name().unwrap().to_str().unwrap(),f.original.operation))}
fn original_records(f:&Fixture)->std::collections::BTreeMap<String,Vec<u8>> {
    fs::read_dir(&f.store).unwrap().map(|entry|entry.unwrap().path()).filter(|path|{
        let name=path.file_name().unwrap().to_str().unwrap();name.contains(".startup-files-") || name.contains(".startup-stop-") || name.contains(".startup-start-") || name.ends_with(".startup-plan.json")
    }).map(|path|(path.file_name().unwrap().to_str().unwrap().into(),fs::read(path).unwrap())).collect()
}
fn prepare(f:&Fixture,token:&str,id:uuid::Uuid)->Value {recovery_prepare(&f.store,&f.original,"local-uid:fixture",token,id,&f.installed.systemctl).unwrap()}
fn approval(value:&Value)->RecoveryApproval {RecoveryApproval{id:uuid::Uuid::parse_str(value["recoveryId"].as_str().unwrap()).unwrap(),token:value["confirmationToken"].as_str().unwrap().into()}}
fn recovery_path(f:&Fixture,id:uuid::Uuid,suffix:&str)->PathBuf {f.store.join(format!("{}.startup-recovery-{id}.{suffix}.json",f.original.operation))}
#[test]
fn file_recovery_restores_absent_and_planned_arguments_keeps_both_preimages_and_never_resolves_original_unknown() {
    for prefix in ["unentered","retained","planned-unacknowledged","published"] {
        let f=Fixture::new();let token=publication_prefix(&f,prefix);let before=original_records(&f);
        let original_state=original(&f.store,f.original.operation,&f.original.plan,None).unwrap().unwrap()["state"].clone();
        let old_backup=if backup_path(&f).exists(){Some(Image::read(&backup_path(&f),ARGS_LIMIT).unwrap())}else{None};
        let planned=if ["planned-unacknowledged","published"].contains(&prefix){Some(Image::read(&f.installed.args,ARGS_LIMIT).unwrap())}else{None};
        let reviewed=prepare(&f,&token,uuid::Uuid::new_v4());let approval=approval(&reviewed);
        assert_eq!(reviewed["state"],"PREPARED");assert!(!recovery_path(&f,approval.id,"intent").exists());
        let RecoveryStep::Dispatch(command)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("one new compensation")};
        let restored=(*command).execute().unwrap();assert_eq!(restored["state"],"ARGUMENTS_RESTORED");assert_eq!(restored["originalUnknownCleared"],false);
        assert_eq!(restored["systemAdoptionVerified"],false);assert_eq!(original_records(&f),before);
        let (plan,journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
        let args=Image::read(&f.installed.args,ARGS_LIMIT).unwrap();assert_eq!(args.0.sha256,plan.source_args_image.sha256);
        if let Some((image,body))=old_backup {assert!(Image::read(&backup_path(&f),ARGS_LIMIT).unwrap()==(image,body));}
        else{assert!(!backup_path(&f).exists());assert!(args.0==plan.source_args_image);}
        let quarantine=f.installed.args.with_file_name(format!(".{}.nm-recovered-{}",f.installed.args.file_name().unwrap().to_str().unwrap(),approval.id));
        if let Some((image,body))=planned {let retained=Image::read(&quarantine,ARGS_LIMIT).unwrap();assert!(retained.0.inode==image.inode && retained.1==body);}
        else{assert!(!quarantine.exists());}
        assert_eq!(original(&f.store,f.original.operation,&f.original.plan,None).unwrap().unwrap()["state"],original_state);
        assert!(f.marker.exists());assert!(publication::recovery::forward_allowed(&f.store,&plan,&journal).is_err());
        let selected=resolve_profile(&f.store,f.original.operation,&f.original.plan,&f.original.marker,&f.installed.profile,&durable::hash(plan.source_profile.as_bytes())).unwrap().unwrap();
        assert_eq!(selected.selected_arguments_sha256,plan.source_args_image.sha256);assert_eq!(selected.raw,plan.source_profile.as_bytes());
        let calls=fs::read(&f.installed.calls).unwrap();let journals=original_records(&f);
        fs::remove_file(f.root.join("unit-state")).unwrap();fs::remove_file(f.root.join("unit-definition")).unwrap();
        let RecoveryStep::Observed(repeated)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("receipt-only original query")};
        assert_eq!(repeated,restored);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(original_records(&f),journals);
        for file in fs::read_dir(&f.store).unwrap(){let file=file.unwrap().path();if file.is_file(){assert!(!String::from_utf8_lossy(&fs::read(file).unwrap()).contains("fixture-secret-must-not-leak"));}}
    }
}
#[test]
fn file_recovery_review_cancel_history_and_missing_link_never_silently_unblock_forward_actions() {
    let f=Fixture::new();let token=publication_prefix(&f,"published");let id=uuid::Uuid::new_v4();let review=prepare(&f,&token,id);let first=approval(&review);
    assert!(start_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).is_err());
    let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();journal.recovery=None;durable::json(&path,&journal).unwrap();
    let before=fs::read(recovery_path(&f,id,"plan")).unwrap();let observed=recovery_original(&f.store,&f.original,"local-uid:fixture",&token,id).unwrap();assert_eq!(observed["linked"],false);
    assert!(start_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).is_err());
    assert!(recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&first,&f.installed.systemctl).is_err());
    assert_eq!(prepare(&f,&token,id),review);assert_eq!(fs::read(recovery_path(&f,id,"plan")).unwrap(),before);
    let calls=fs::read(&f.installed.calls).unwrap();assert_eq!(recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&first).unwrap()["state"],"CANCELLED");
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    let second=prepare(&f,&token,uuid::Uuid::new_v4());let second=approval(&second);
    let calls=fs::read(&f.installed.calls).unwrap();
    assert!(recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&first).is_err());
    recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&second).unwrap();
    let (plan,journal)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();publication::recovery::forward_allowed(&f.store,&plan,&journal).unwrap();
    assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    fs::remove_file(recovery_path(&f,id,"cancel")).unwrap();
    assert!(start_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).is_err());
    assert!(!f.store.join(format!("{}.startup-start-intent.json",f.original.operation)).exists());
}
#[test]
fn file_recovery_refuses_foreign_backups_links_jobs_start_intents_and_unacknowledged_stops_before_review() {
    for fault in ["backup-replaced","backup-missing","backup-linked","backup-symlink","arguments-foreign","arguments-linked","arguments-symlink","marker-replaced","job-active","job-missing","job-duplicate","stop-missing","start-intent"] {
        let f=Fixture::new();let token=publication_prefix(&f,"published");
        match fault {
            "backup-replaced"=>{let path=backup_path(&f);let bytes=fs::read(&path).unwrap();fs::rename(&path,path.with_extension("retained")).unwrap();durable::write(&path,&bytes,FileMetadata::private()).unwrap();}
            "backup-missing"=>fs::rename(backup_path(&f),backup_path(&f).with_extension("retained")).unwrap(),
            "backup-linked"=>fs::hard_link(backup_path(&f),backup_path(&f).with_extension("linked")).unwrap(),
            "backup-symlink"=>{let path=backup_path(&f);let kept=path.with_extension("retained");fs::rename(&path,&kept).unwrap();std::os::unix::fs::symlink(&kept,&path).unwrap();}
            "arguments-foreign"=>durable::write(&f.installed.args,b"-Xmx123m\n",FileMetadata::private()).unwrap(),
            "arguments-linked"=>fs::hard_link(&f.installed.args,f.installed.args.with_extension("linked")).unwrap(),
            "arguments-symlink"=>{let kept=f.installed.args.with_extension("retained");fs::rename(&f.installed.args,&kept).unwrap();std::os::unix::fs::symlink(&kept,&f.installed.args).unwrap();}
            "marker-replaced"=>{let bytes=fs::read(&f.marker).unwrap();fs::rename(&f.marker,f.marker.with_extension("retained")).unwrap();durable::write(&f.marker,&bytes,FileMetadata::private()).unwrap();}
            "job-active"=>durable::write(&f.root.join("unit-job"),b"Job=125\n",FileMetadata::private()).unwrap(),
            "job-missing"=>durable::write(&f.root.join("unit-job"),b"",FileMetadata::private()).unwrap(),
            "job-duplicate"=>durable::write(&f.root.join("unit-job"),b"Job=\nJob=\n",FileMetadata::private()).unwrap(),
            "stop-missing"=>fs::remove_file(f.store.join(format!("{}.startup-stop-receipt.json",f.original.operation))).unwrap(),
            _=>{
                // Admission alone, without executing start, permanently excludes
                // this file-only recovery. A later inactive unit is no receipt.
                let base=f.root.join("systemctl-without-job");enable_start_at(&f.root,"success");fs::copy(&f.installed.systemctl,&base).unwrap();
                let StartStep::Dispatch(command)=start_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).unwrap()else{panic!("start intent")};drop(command);
            }
        }
        let id=uuid::Uuid::new_v4();let before=original_records(&f);let args=fs::read(&f.installed.args).unwrap();
        assert!(recovery_prepare(&f.store,&f.original,"local-uid:fixture",&token,id,&f.installed.systemctl).is_err(),"{fault}");
        assert!(!recovery_path(&f,id,"plan").exists());assert_eq!(original_records(&f),before);assert_eq!(fs::read(&f.installed.args).unwrap(),args);
    }
}
#[test]
fn file_recovery_rechecks_changed_inputs_and_authority_before_its_own_once_only_intent() {
    for fault in ["args","backup","job","unit","enablement","policy","fence","parent","token","actor"] {
        // A separate parent keeps private recovery records and grant paths
        // stable when this fixture replaces only the arguments directory.
        let mut f=Fixture::new();if fault=="parent"{place_arguments_in_home(&mut f.installed);}
        let token=publication_prefix(&f,"published");let review=prepare(&f,&token,uuid::Uuid::new_v4());let mut approval=approval(&review);
        match fault {
            "args"=>durable::write(&f.installed.args,b"foreign changed args",FileMetadata::private()).unwrap(),
            "backup"=>{let path=backup_path(&f);let body=fs::read(&path).unwrap();fs::rename(&path,path.with_extension("retained")).unwrap();durable::write(&path,&body,FileMetadata::private()).unwrap();}
            "job"=>durable::write(&f.root.join("unit-job"),b"Job=2\n",FileMetadata::private()).unwrap(),
            "unit"=>durable::write(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=active\nMainPID=4321\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState=disabled\n",FileMetadata::private()).unwrap(),
            "enablement"=>{let file=f.root.join("unit-state");let text=fs::read_to_string(&file).unwrap().replace("disabled","enabled");durable::write(&file,text.as_bytes(),FileMetadata::private()).unwrap();}
            "policy"=>durable::write(&f.root.join("unit-stop-policy"),b"ExecStop=\nSlice=system.slice\nKillMode=control-group\nTimeoutStopUSec=4s\n",FileMetadata::private()).unwrap(),
            "fence"=>{let path=f.installed.home.join("framework/network-owner-agent");let body=fs::read(&path).unwrap();fs::rename(&path,path.with_extension("retained")).unwrap();durable::write(&path,&body,FileMetadata::private()).unwrap();}
            "parent"=>{let parent=f.installed.args.parent().unwrap();let kept=parent.with_extension("retained");fs::rename(parent,&kept).unwrap();durable::directory(parent).unwrap();for entry in fs::read_dir(&kept).unwrap(){let entry=entry.unwrap();fs::copy(entry.path(),parent.join(entry.file_name())).unwrap();}}
            "token"=>approval.token="0".repeat(32),_=>{},
        }
        let before=original_records(&f);let args=fs::read(&f.installed.args).unwrap();
        assert!(recovery_begin(&f.store,&f.original,if fault=="actor"{"other-actor"}else{"local-uid:fixture"},&token,&approval,&f.installed.systemctl).is_err(),"{fault}");
        assert!(!recovery_path(&f,approval.id,"intent").exists());assert_eq!(original_records(&f),before);assert_eq!(fs::read(&f.installed.args).unwrap(),args);
    }
}
#[test]
fn file_recovery_admitted_but_unentered_intent_is_unknown_and_never_cancelled_or_reissued() {
    let f=Fixture::new();let token=publication_prefix(&f,"published");let review=prepare(&f,&token,uuid::Uuid::new_v4());let approval=approval(&review);
    let RecoveryStep::Dispatch(command)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("new compensation")};
    assert!(recovery_prepare(&f.store,&f.original,"local-uid:fixture",&token,uuid::Uuid::new_v4(),&f.installed.systemctl).is_err());drop(command);
    let args=fs::read(&f.installed.args).unwrap();let calls=fs::read(&f.installed.calls).unwrap();let before=original_records(&f);
    for _ in 0..2 {
        let RecoveryStep::Observed(value)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("never redispatch")};
        assert_eq!(value["state"],"RECOVERY_OUTCOME_UNKNOWN");
        assert!(recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&approval).is_err());
    }
    assert_eq!(fs::read(&f.installed.args).unwrap(),args);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(original_records(&f),before);
}
#[test]
fn file_recovery_partial_effects_and_receipt_prefixes_are_retained_without_replay_or_legacy_profile_fallback() {
    for (count,unacknowledged) in [(1,false),(1,true),(2,false),(2,true)] {
        let f=Fixture::new();let token=publication_prefix(&f,"published");let review=prepare(&f,&token,uuid::Uuid::new_v4());let approval=approval(&review);
        let RecoveryStep::Dispatch(command)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("fresh compensation")};
        (*command).fixture_prefix(count,unacknowledged).unwrap();
        let args=fs::read(&f.installed.args).ok();let backup=Image::read(&backup_path(&f),ARGS_LIMIT).unwrap();let calls=fs::read(&f.installed.calls).unwrap();
        let records=original_records(&f);let RecoveryStep::Observed(state)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("never replay a partial recovery")};
        assert_eq!(state["state"],"RECOVERY_OUTCOME_UNKNOWN");assert_eq!(fs::read(&f.installed.args).ok(),args);
        assert!(Image::read(&backup_path(&f),ARGS_LIMIT).unwrap()==backup);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);assert_eq!(original_records(&f),records);
        let (plan,_)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
        assert!(resolve_profile(&f.store,f.original.operation,&f.original.plan,&f.original.marker,&f.installed.profile,&durable::hash(plan.source_profile.as_bytes())).is_err());
        assert!(!recovery_path(&f,approval.id,"receipt").exists());assert!(recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&approval).is_err());
    }
}
#[test]
fn file_recovery_existing_receipt_only_acknowledges_its_pointer_and_never_recreates_missing_acknowledged_evidence() {
    let f=Fixture::new();let token=publication_prefix(&f,"published");let review=prepare(&f,&token,uuid::Uuid::new_v4());let approval=approval(&review);
    let RecoveryStep::Dispatch(command)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("new recovery")};(*command).execute().unwrap();
    let path=recovery_path(&f,approval.id,"journal");let mut ledger:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();ledger["state"]=json!("EXECUTING");ledger["receiptSha256"]=Value::Null;durable::json(&path,&ledger).unwrap();
    durable::write(&f.installed.args,b"foreign later material must survive a historical receipt query",FileMetadata::private()).unwrap();
    let calls=fs::read(&f.installed.calls).unwrap();let args=fs::read(&f.installed.args).unwrap();
    let RecoveryStep::Observed(value)=recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).unwrap()else{panic!("metadata acknowledgement only")};
    assert_eq!(value["state"],"ARGUMENTS_RESTORED");assert_eq!(fs::read(&f.installed.args).unwrap(),args);assert_eq!(fs::read(&f.installed.calls).unwrap(),calls);
    let (plan,_)=load(&f.store,f.original.operation,&f.original.plan).unwrap().unwrap();
    assert!(resolve_profile(&f.store,f.original.operation,&f.original.plan,&f.original.marker,&f.installed.profile,&durable::hash(plan.source_profile.as_bytes())).is_err());
    fs::remove_file(recovery_path(&f,approval.id,"receipt")).unwrap();
    assert!(recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).err().unwrap().to_string().starts_with("OUTCOME_UNKNOWN"));
    assert!(!recovery_path(&f,approval.id,"receipt").exists());assert_eq!(fs::read(&f.installed.args).unwrap(),args);
}
#[test]
fn file_recovery_expiry_and_unlinked_partial_evidence_refuse_admission_without_discarding_history() {
    let f=Fixture::new();let token=publication_prefix(&f,"published");let review=prepare(&f,&token,uuid::Uuid::new_v4());let approval=approval(&review);
    let path=recovery_path(&f,approval.id,"plan");let mut plan:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();plan["expiresAtUnixMs"]=json!(0);durable::json(&path,&plan).unwrap();
    let hash=durable::hash(&fs::read(&path).unwrap());let path=recovery_path(&f,approval.id,"journal");let mut ledger:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();ledger["reviewSha256"]=json!(hash);durable::json(&path,&ledger).unwrap();
    let path=paths(&f.store,f.original.operation).1;let mut journal:Journal=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();journal.recovery.as_mut().unwrap().plan_sha256=hash;durable::json(&path,&journal).unwrap();
    assert!(recovery_begin(&f.store,&f.original,"local-uid:fixture",&token,&approval,&f.installed.systemctl).is_err());assert!(!recovery_path(&f,approval.id,"intent").exists());
    recovery_cancel(&f.store,&f.original,"local-uid:fixture",&token,&approval).unwrap();
    let orphan=uuid::Uuid::new_v4();durable::json(&recovery_path(&f,orphan,"plan"),&json!({"partial":"unacknowledged original review remains"})).unwrap();
    assert!(recovery_prepare(&f.store,&f.original,"local-uid:fixture",&token,uuid::Uuid::new_v4(),&f.installed.systemctl).is_err());
    assert!(start_begin(&f.store,&f.original,"local-uid:fixture",&token,&f.installed.systemctl).is_err());assert!(recovery_path(&f,orphan,"plan").exists());
}
