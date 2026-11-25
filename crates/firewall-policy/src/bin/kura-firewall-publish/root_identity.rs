//! Kernel filesystem-object observations. These do not authorize a Root migration.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::fs::File;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectIdentity {
    filesystem_type: u64,
    filesystem_id: String,
    handle_type: i32,
    handle: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootIdentity {
    root: ObjectIdentity,
    journal: ObjectIdentity,
}

impl RootIdentity {
    pub fn observe(root: &File, journal: &File) -> Result<Self> {
        Ok(Self {
            root: object(root).context("UNSUPPORTED_ROOT_IDENTITY: root filesystem object")?,
            journal: object(journal).context("UNSUPPORTED_ROOT_IDENTITY: journal filesystem object")?,
        })
    }
}

#[cfg(target_os = "linux")]
fn object(file: &File) -> Result<ObjectIdentity> {
    use std::{io, mem, os::fd::AsRawFd};
    const CAPACITY: usize = 128;
    #[repr(C)]
    struct Handle {
        size: u32,
        kind: i32,
        bytes: [u8; CAPACITY],
    }
    unsafe extern "C" {
        fn name_to_handle_at(
            fd: libc::c_int,
            path: *const libc::c_char,
            handle: *mut Handle,
            mount_id: *mut libc::c_int,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
    let mut filesystem = mem::MaybeUninit::<libc::statfs>::zeroed();
    // Both calls operate on held directory descriptors. Mount IDs and st_dev
    // are deliberately absent from this observation; neither is persistent.
    let status = unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) };
    ensure!(status == 0, "fstatfs failed: {}", io::Error::last_os_error());
    let filesystem = unsafe { filesystem.assume_init() };
    let mut handle = Handle { size: CAPACITY as u32, kind: 0, bytes: [0; CAPACITY] };
    let mut mount_id = 0;
    let status = unsafe {
        name_to_handle_at(file.as_raw_fd(), c"".as_ptr(), &mut handle, &mut mount_id, libc::AT_EMPTY_PATH)
    };
    ensure!(status == 0, "name_to_handle_at failed: {}", io::Error::last_os_error());
    ensure!((1..=CAPACITY).contains(&(handle.size as usize)), "Invalid kernel file handle size");
    let fsid = unsafe {
        std::slice::from_raw_parts(
            (&filesystem.f_fsid as *const libc::fsid_t).cast::<u8>(),
            mem::size_of::<libc::fsid_t>(),
        )
    };
    ensure!(fsid.iter().any(|byte| *byte != 0), "Filesystem identity is unavailable");
    Ok(ObjectIdentity {
        filesystem_type: filesystem.f_type as u64,
        filesystem_id: super::hex(fsid),
        handle_type: handle.kind,
        handle: super::hex(&handle.bytes[..handle.size as usize]),
    })
}

#[cfg(not(target_os = "linux"))]
fn object(_: &File) -> Result<ObjectIdentity> {
    anyhow::bail!("Kernel file handles require Linux")
}

