//! Provision the local history directory without trusting writable or linked ancestors.
use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};
use std::{
    ffi::{c_char, c_void, CString},
    fs::{self, DirBuilder},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

extern "C" {
    fn geteuid() -> u32;
    fn acl_get_link_np(path: *const c_char, kind: i32) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
    fn acl_free(object: *mut c_void) -> i32;
}

// Deny all allow entries: an ACL may grant access that ordinary mode bits do not show.
// Deny entries, such as the standard macOS home-directory deny-delete entry, are harmless.
fn no_acl_allow(path: &Path) -> ResultType<()> {
    let name =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| anyhow!("invalid directory"))?;
    let acl = unsafe { acl_get_link_np(name.as_ptr(), 0x100) }; // ACL_TYPE_EXTENDED
    if acl.is_null() {
        return if io::Error::last_os_error().raw_os_error() == Some(2) {
            Ok(())
        } else {
            Err(anyhow!("cannot inspect directory ACL"))
        };
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                acl_free(self.0);
            }
        }
    }
    let _acl = Acl(acl);
    let mut entry = std::ptr::null_mut();
    let mut which = 0; // ACL_FIRST_ENTRY
    loop {
        match unsafe { acl_get_entry(acl, which, &mut entry) } {
            0 => {
                let mut tag = 0;
                if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != 2 {
                    // ACL_EXTENDED_DENY
                    bail!("directory ACL is not restrictive");
                }
                which = -1; // ACL_NEXT_ENTRY
            }
            // Darwin reports EINVAL when there are no more entries.
            -1 if io::Error::last_os_error().raw_os_error() == Some(22) => return Ok(()),
            _ => bail!("cannot inspect directory ACL"),
        }
    }
}

fn inspect(path: &Path, uid: u32, private: bool) -> ResultType<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| anyhow!("cannot inspect directory"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
        || (private && metadata.uid() != uid)
    {
        bail!("directory is not protected");
    }
    no_acl_allow(path)
}

fn validate_ancestors(path: &Path, uid: u32) -> ResultType<()> {
    if !path.is_absolute() {
        bail!("directory is not absolute");
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => bail!("invalid directory path"),
        }
        inspect(&current, uid, false)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != uid {
        bail!("home directory has wrong owner");
    }
    Ok(())
}

fn create_private(parent: &Path, name: &str, uid: u32) -> ResultType<PathBuf> {
    let path = parent.join(name);
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => bail!("cannot create protected directory"),
    }
    inspect(&path, uid, true)?;
    Ok(path)
}

pub(super) fn history(home: &Path) -> ResultType<PathBuf> {
    let uid = unsafe { geteuid() };
    if uid == 0 {
        bail!("interactive user required");
    }
    validate_ancestors(home, uid)?;
    let library = home.join("Library");
    inspect(&library, uid, false)?;
    let support = library.join("Application Support");
    inspect(&support, uid, false)?;
    let app_name = if cfg!(feature = "hoen-mac-dev") {
        "HoenRemoteDev"
    } else {
        "HoenRemote"
    };
    let app = create_private(&support, app_name, uid)?;
    let host = create_private(&app, "host", uid)?;
    Ok(create_private(&host, "history", uid)?.join("outbox.sqlite"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn creates_private_directory_and_rejects_writable_or_linked_paths() {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hoen-private-dir-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());
        fs::create_dir(base.join("Library")).unwrap();
        fs::create_dir(base.join("Library/Application Support")).unwrap();
        let output = history(&base).expect("protected history directory");
        assert_eq!(output.file_name().unwrap(), "outbox.sqlite");
        let history_dir = output.parent().unwrap();
        assert_eq!(fs::metadata(history_dir).unwrap().mode() & 0o077, 0);
        fs::set_permissions(history_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(history(&base).is_err());
        fs::set_permissions(history_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(history_dir)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(history(&base).is_err());
        fs::remove_dir(history_dir).unwrap();
        symlink(&base, history_dir).unwrap();
        assert!(history(&base).is_err());
    }
}
