//! Additional administrator authority for accepting an already-applied forward
//! recovery source. It never authorizes an upload, inverse, health or release.
use super::*;

#[derive(Clone)]
pub(super) struct Profile(PathBuf);
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    schema: u32,
    source: String,
    accept_applied_forward_source: bool,
    normal_startup_authority_sha256: String,
}
impl Profile {
    pub(super) fn new(path: PathBuf) -> Result<Self> {
        let this = Self(path);
        this.read()?;
        Ok(this)
    }
    fn read(&self) -> Result<(Config, Vec<u8>)> {
        ensure!(
            self.0.is_absolute(),
            "FORBIDDEN: absolute forward normal grant required"
        );
        let (bytes, metadata) = durable::read(&self.0, 32 << 10)?;
        let parent = fs::symlink_metadata(self.0.parent().context("forward normal parent")?)?;
        ensure!(
            metadata.mode & 0o077 == 0
                && (metadata.uid == 0 || metadata.uid == unsafe { libc::geteuid() })
                && parent.is_dir()
                && parent.mode() & 0o022 == 0,
            "FORBIDDEN: private forward normal grant required"
        );
        let config: Config = serde_json::from_slice(&bytes)?;
        ensure!(
            config.schema == 1
                && config.source == "applied-forward"
                && config.accept_applied_forward_source
                && config.normal_startup_authority_sha256.len() == 64
                && config
                    .normal_startup_authority_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "FORBIDDEN: explicit applied-forward authority required"
        );
        Ok((config, bytes))
    }
    pub(super) fn inputs(&self, normal_authority: &str) -> Result<(String, Vec<u8>)> {
        let (config, bytes) = self.read()?;
        ensure!(
            config.normal_startup_authority_sha256 == normal_authority,
            "CONFLICT: approved normal startup authority changed"
        );
        Ok((durable::hash(&bytes), bytes))
    }
}
