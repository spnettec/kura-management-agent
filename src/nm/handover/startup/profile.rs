//! Read the one original startup generation, not a second selector registry.
use super::*;
pub(super) fn marker(root:&Path,id:uuid::Uuid,parent:&str)->Result<Option<PathBuf>> {
    Ok(load(root,id,parent)?.map(|(plan,_)|plan.owner_marker))
}
pub(super) fn resolve(root:&Path,id:uuid::Uuid,parent:&str,marker:&MarkerIdentity,path:&Path,source:&str)->Result<Option<super::super::OrdinarySelection>> {
    let Some((plan,journal))=load(root,id,parent)?else{return Ok(None)};
    ensure!(plan.owner_marker_identity==*marker,"CONFLICT: original profile/parent marker binding");
    if durable::hash(plan.source_profile.as_bytes())!=source {
        ensure!(path!=plan.source_path,"CONFLICT: original ordinary grant anchor was changed");return Ok(None);
    }
    if publication::status(root,&plan,&journal)?.is_none(){return Ok(None);}
    ensure!(plan.schema_version>=4,"UNSUPPORTED: historical startup has no selected generation");
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    if let Some(raw)=publication::recovery::selected(root,&plan,&journal)? {
        return Ok(Some(super::super::OrdinarySelection{raw,unit:config.unit,arguments_path:config.jvm_args_path,
            source_arguments_sha256:plan.source_args_image.sha256.clone(),selected_arguments_sha256:plan.source_args_image.sha256}));
    }
    let raw=publication::selected_raw(root,&plan,&journal)?;
    let (target,_)=argument_binding(&plan,&config)?;
    Ok(Some(super::super::OrdinarySelection{raw,unit:config.unit,arguments_path:config.jvm_args_path,
        source_arguments_sha256:plan.source_args_image.sha256,selected_arguments_sha256:target}))
}
