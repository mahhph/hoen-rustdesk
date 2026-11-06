//! Encrypted enrollment material. Provision each protected directory separately for its OS identity.
//! DPAPI user scope does not cross the interactive-user/LocalSystem boundary. The installer must
//! provision a local directory owned by that identity with a protected, exclusive DACL. Never put
//! plaintext credentials in RustDesk configuration, logs, process arguments or environment.
use std::fmt;

pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Viewer,
    HostService,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidInput,
    WrongIdentity,
    UnprotectedPath,
    Unavailable,
    CorruptOrWrongPurpose,
    Unsupported,
}
/// Opaque secret material; callers define and version their serialized enrollment bundle.
pub struct Secret(Vec<u8>);
impl Secret {
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, StoreError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            for byte in &mut bytes {
                unsafe { std::ptr::write_volatile(byte, 0) }
            }
            return Err(StoreError::InvalidInput);
        }
        Ok(Self(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
// Deliberately no Debug, Display, Clone or serialization implementation on Secret.
pub trait CredentialStore {
    fn read(&self) -> Result<Secret, StoreError>;
    fn write(&self, secret: &Secret) -> Result<(), StoreError>;
}

#[cfg(target_os = "macos")]
#[path = "macos_credentials.rs"]
mod macos_store;
#[cfg(target_os = "macos")]
pub(crate) use macos_store::MacStore;
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential store: {:?}", self)
    }
}

#[cfg(windows)]
mod windows_store {
    use super::{CredentialStore, Purpose, Secret, StoreError, MAX_SECRET_BYTES};
    use std::{
        ffi::OsStr,
        fs::File,
        io::{Read, Write},
        mem::size_of,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        path::{Component, Path, PathBuf, Prefix},
        ptr::null_mut,
        sync::atomic::{AtomicU64, Ordering},
    };
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{
                CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
            },
            Security::{Authorization::*, Cryptography::*, *},
            Storage::FileSystem::*,
            System::Threading::{
                GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
            },
        },
    };
    const MAGIC: &[u8; 8] = b"HOENDP01";
    static TEMP_ID: AtomicU64 = AtomicU64::new(0);
    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }
    fn entropy(role: Purpose) -> &'static [u8] {
        match role {
            Purpose::Viewer => b"hoen-enrollment-v1-viewer",
            Purpose::HostService => b"hoen-enrollment-v1-host-service",
        }
    }
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
    struct Identity {
        _token_data: Vec<usize>,
        sid: PSID,
    }
    fn identity(purpose: Purpose) -> Result<Identity, StoreError> {
        unsafe {
            let mut impersonation = HANDLE::default();
            match OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut impersonation) {
                Ok(()) => {
                    let _handle = Handle(impersonation);
                    return Err(StoreError::WrongIdentity);
                }
                Err(e) if e.code().0 as u32 == 0x800703f0 => {} // ERROR_NO_TOKEN
                Err(_) => return Err(StoreError::Unavailable),
            }
            let mut raw = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)
                .map_err(|_| StoreError::Unavailable)?;
            let token = Handle(raw);
            let mut len = 0;
            let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut len);
            if len == 0 || len > 65536 {
                return Err(StoreError::Unavailable);
            }
            let mut data =
                vec![0usize; (len as usize + size_of::<usize>() - 1) / size_of::<usize>()];
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(data.as_mut_ptr().cast()),
                len,
                &mut len,
            )
            .map_err(|_| StoreError::Unavailable)?;
            let sid = (*(data.as_ptr() as *const TOKEN_USER)).User.Sid;
            let system = IsWellKnownSid(sid, WinLocalSystemSid).as_bool();
            if (purpose == Purpose::HostService) != system {
                return Err(StoreError::WrongIdentity);
            }
            Ok(Identity {
                _token_data: data,
                sid,
            })
        }
    }
    fn descriptor(id: &Identity, inheritable: bool) -> Result<Local, StoreError> {
        unsafe {
            let mut sid_string = PWSTR::null();
            ConvertSidToStringSidW(id.sid, &mut sid_string).map_err(|_| StoreError::Unavailable)?;
            let sid_owner = Local(sid_string.0.cast());
            let sid = sid_string
                .to_string()
                .map_err(|_| StoreError::Unavailable)?;
            let flags = if inheritable { "OICI" } else { "" };
            let text = wide(OsStr::new(&format!("O:{sid}D:P(A;{flags};FA;;;{sid})")));
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(|_| StoreError::Unavailable)?;
            drop(sid_owner);
            Ok(Local(sd.0))
        }
    }
    unsafe fn protected(
        handle: HANDLE,
        id: &Identity,
        directory: bool,
        require_inheritance: bool,
    ) -> Result<(), StoreError> {
        unsafe {
            let mut owner = PSID::default();
            let mut acl = null_mut();
            let mut raw = PSECURITY_DESCRIPTOR::default();
            if GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut acl),
                None,
                Some(&mut raw),
            ) != ERROR_SUCCESS
            {
                return Err(StoreError::UnprotectedPath);
            }
            let _descriptor = Local(raw.0);
            if owner.0.is_null() || acl.is_null() || EqualSid(owner, id.sid).is_err() {
                return Err(StoreError::UnprotectedPath);
            }
            let mut control = 0;
            let mut revision = 0;
            GetSecurityDescriptorControl(raw, &mut control, &mut revision)
                .map_err(|_| StoreError::UnprotectedPath)?;
            if control & SE_DACL_PROTECTED.0 == 0 {
                return Err(StoreError::UnprotectedPath);
            }
            let mut info = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .map_err(|_| StoreError::UnprotectedPath)?;
            if info.AceCount != 1 {
                return Err(StoreError::UnprotectedPath);
            }
            let mut ace = null_mut();
            GetAce(acl, 0, &mut ace).map_err(|_| StoreError::UnprotectedPath)?;
            let a = &*(ace as *const ACCESS_ALLOWED_ACE);
            if a.Header.AceType != 0
                || (!directory && a.Header.AceFlags != 0)
                || (directory && a.Header.AceFlags & !0x03 != 0)
                || (require_inheritance && a.Header.AceFlags & 0x03 != 0x03)
                || (a.Mask & FILE_ALL_ACCESS.0 != FILE_ALL_ACCESS.0)
                || EqualSid(PSID((&a.SidStart as *const u32 as *mut u32).cast()), id.sid).is_err()
            {
                return Err(StoreError::UnprotectedPath);
            }
            Ok(())
        }
    }
    unsafe fn no_reparse(handle: HANDLE, directory: bool) -> Result<(), StoreError> {
        unsafe {
            let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
            .map_err(|_| StoreError::UnprotectedPath)?;
            if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
                || (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
            {
                return Err(StoreError::UnprotectedPath);
            }
            Ok(())
        }
    }
    // Hold all directory components without delete sharing throughout each operation so a path
    // component cannot be swapped after validation. Remote/relative/reparse paths are rejected.
    fn hold_chain(path: &Path) -> Result<Vec<Handle>, StoreError> {
        if !path.is_absolute()
            || !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(StoreError::UnprotectedPath);
        }
        let mut current = PathBuf::new();
        let mut handles = Vec::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let name = wide(current.as_os_str());
            let h = unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    READ_CONTROL.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            }
            .map_err(|_| StoreError::UnprotectedPath)?;
            let h = Handle(h);
            unsafe {
                no_reparse(h.0, true)?;
            }
            handles.push(h);
        }
        Ok(handles)
    }
    fn hold_directories(
        path: &Path,
        id: &Identity,
        require_inheritance: bool,
    ) -> Result<Vec<Handle>, StoreError> {
        let handles = hold_chain(path)?;
        let leaf = handles.last().ok_or(StoreError::UnprotectedPath)?;
        unsafe {
            protected(leaf.0, id, true, require_inheritance)?;
        }
        Ok(handles)
    }
    /// Validate an existing leaf without changing its ownership or ACL.
    pub fn validate_directory(path: &Path, purpose: Purpose) -> Result<(), StoreError> {
        let id = identity(purpose)?;
        let _handles = hold_directories(path, &id, false)?;
        Ok(())
    }
    /// For SQLite and similar users: require OI and CI so children inherit owner-only access.
    pub fn validate_inheritable_directory(path: &Path, purpose: Purpose) -> Result<(), StoreError> {
        let id = identity(purpose)?;
        let _handles = hold_directories(path, &id, true)?;
        Ok(())
    }
    /// Create only a new leaf with a protected, owner-only inheritable DACL. Existing leaves
    /// are validated without changing their ACL. All parent directories must already exist.
    pub fn provision_directory(path: &Path, purpose: Purpose) -> Result<(), StoreError> {
        let id = identity(purpose)?;
        if path.file_name().is_none() {
            return Err(StoreError::UnprotectedPath);
        }
        let parent = path.parent().ok_or(StoreError::UnprotectedPath)?;
        let _parents = hold_chain(parent)?;
        let sd = descriptor(&id, true)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let name = wide(path.as_os_str());
        match unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&sa)) } {
            Ok(()) => {}
            Err(e) if e.code().0 as u32 == 0x800700b7 => {} // ERROR_ALREADY_EXISTS
            Err(_) => return Err(StoreError::Unavailable),
        }
        let _leaf = hold_directories(path, &id, false)?;
        Ok(())
    }
    fn crypto(input: &[u8], purpose: Purpose, protect: bool) -> Result<Vec<u8>, StoreError> {
        if input.is_empty() || input.len() > MAX_SECRET_BYTES + 8192 {
            return Err(StoreError::InvalidInput);
        }
        unsafe {
            let data = CRYPT_INTEGER_BLOB {
                cbData: input.len() as u32,
                pbData: input.as_ptr() as *mut u8,
            };
            let e = entropy(purpose);
            let entropy = CRYPT_INTEGER_BLOB {
                cbData: e.len() as u32,
                pbData: e.as_ptr() as *mut u8,
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            let result = if protect {
                CryptProtectData(
                    &data,
                    PCWSTR::null(),
                    Some(&entropy),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            } else {
                CryptUnprotectData(
                    &data,
                    None,
                    Some(&entropy),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            result.map_err(|_| {
                if protect {
                    StoreError::Unavailable
                } else {
                    StoreError::CorruptOrWrongPurpose
                }
            })?;
            if out.pbData.is_null() {
                return Err(StoreError::Unavailable);
            }
            let guard = Local(out.pbData.cast());
            let n = out.cbData as usize;
            if n == 0 || n > MAX_SECRET_BYTES + 8192 {
                if !protect {
                    for i in 0..n {
                        std::ptr::write_volatile(out.pbData.add(i), 0);
                    }
                }
                return Err(StoreError::Unavailable);
            }
            let bytes = std::slice::from_raw_parts(out.pbData, n).to_vec();
            if !protect {
                for i in 0..n {
                    std::ptr::write_volatile(out.pbData.add(i), 0);
                }
            }
            drop(guard);
            Ok(bytes)
        }
    }
    fn file_name(role: Purpose) -> &'static str {
        match role {
            Purpose::Viewer => "viewer.dpapi",
            Purpose::HostService => "service.dpapi",
        }
    }
    /// The directory must already be provisioned with a protected, sole-owner DACL.
    /// Current-user DPAPI is used for viewer; LocalSystem current-user DPAPI for service.
    pub struct ProtectedStore {
        directory: PathBuf,
        purpose: Purpose,
    }
    impl ProtectedStore {
        pub fn open(directory: &Path, purpose: Purpose) -> Result<Self, StoreError> {
            let id = identity(purpose)?;
            let _dirs = hold_directories(directory, &id, false)?;
            Ok(Self {
                directory: directory.to_path_buf(),
                purpose,
            })
        }
        fn open_existing(&self, id: &Identity) -> Result<Option<File>, StoreError> {
            let path = self.directory.join(file_name(self.purpose));
            let w = wide(path.as_os_str());
            let h = match unsafe {
                CreateFileW(
                    PCWSTR(w.as_ptr()),
                    GENERIC_READ.0 | READ_CONTROL.0,
                    FILE_SHARE_READ,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            } {
                Ok(h) => h,
                Err(e) if e.code().0 as u32 == 0x80070002 => return Ok(None),
                Err(_) => return Err(StoreError::Unavailable),
            };
            let h = Handle(h);
            unsafe {
                no_reparse(h.0, false)?;
                protected(h.0, id, false, false)?;
            }
            let raw = h.0 .0;
            std::mem::forget(h);
            Ok(Some(unsafe { File::from_raw_handle(raw) }))
        }
    }
    impl CredentialStore for ProtectedStore {
        fn read(&self) -> Result<Secret, StoreError> {
            let id = identity(self.purpose)?;
            let _dirs = hold_directories(&self.directory, &id, false)?;
            let mut file = self.open_existing(&id)?.ok_or(StoreError::Unavailable)?;
            if file.metadata().map_err(|_| StoreError::Unavailable)?.len()
                > (MAX_SECRET_BYTES + 8192) as u64
            {
                return Err(StoreError::InvalidInput);
            }
            let mut encrypted = Vec::new();
            file.read_to_end(&mut encrypted)
                .map_err(|_| StoreError::Unavailable)?;
            if !encrypted.starts_with(MAGIC) {
                return Err(StoreError::CorruptOrWrongPurpose);
            }
            Secret::new(crypto(&encrypted[MAGIC.len()..], self.purpose, false)?)
        }
        fn write(&self, secret: &Secret) -> Result<(), StoreError> {
            let id = identity(self.purpose)?;
            let _dirs = hold_directories(&self.directory, &id, false)?;
            // Reject an existing unprotected or reparse target before replacement.
            drop(self.open_existing(&id)?);
            let data = crypto(secret.expose(), self.purpose, true)?;
            let sd = descriptor(&id, false)?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            let tmp = self.directory.join(format!(
                ".hoen-{}-{}.tmp",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let tmpw = wide(tmp.as_os_str());
            let h = unsafe {
                CreateFileW(
                    PCWSTR(tmpw.as_ptr()),
                    GENERIC_WRITE.0 | READ_CONTROL.0,
                    FILE_SHARE_READ,
                    Some(&sa),
                    CREATE_NEW,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            }
            .map_err(|_| StoreError::Unavailable)?;
            let h = Handle(h);
            let result = (|| {
                unsafe {
                    no_reparse(h.0, false)?;
                    protected(h.0, &id, false, false)?;
                }
                let raw = h.0 .0;
                std::mem::forget(h);
                let mut file = unsafe { File::from_raw_handle(raw) };
                file.write_all(MAGIC)
                    .and_then(|_| file.write_all(&data))
                    .and_then(|_| file.sync_all())
                    .map_err(|_| StoreError::Unavailable)?;
                drop(file);
                let dest = wide(self.directory.join(file_name(self.purpose)).as_os_str());
                unsafe {
                    MoveFileExW(
                        PCWSTR(tmpw.as_ptr()),
                        PCWSTR(dest.as_ptr()),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                }
                .map_err(|_| StoreError::Unavailable)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(tmp);
            }
            result
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn crypto_roundtrip_wrongpurpose_and_tamper() {
            let plain = b"synthetic test credential";
            let encrypted = crypto(plain, Purpose::Viewer, true).unwrap();
            assert_eq!(crypto(&encrypted, Purpose::Viewer, false).unwrap(), plain);
            assert_eq!(
                crypto(&encrypted, Purpose::HostService, false),
                Err(StoreError::CorruptOrWrongPurpose)
            );
            let mut bad = encrypted;
            let i = bad.len() / 2;
            bad[i] ^= 0x80;
            assert_eq!(
                crypto(&bad, Purpose::Viewer, false),
                Err(StoreError::CorruptOrWrongPurpose)
            );
        }
        #[test]
        fn protected_file_roundtrip_replace_and_tamper() {
            let id = identity(Purpose::Viewer).unwrap();
            let sd = descriptor(&id, false).unwrap();
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            let path = std::env::temp_dir().join(format!(
                "hoen-synthetic-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let w = wide(path.as_os_str());
            unsafe {
                CreateDirectoryW(PCWSTR(w.as_ptr()), Some(&sa)).unwrap();
            }
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0.join("viewer.dpapi"));
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            let _cleanup = Cleanup(path.clone());
            let store = ProtectedStore::open(&path, Purpose::Viewer).unwrap();
            store
                .write(&Secret::new(b"first synthetic".to_vec()).unwrap())
                .unwrap();
            assert_eq!(store.read().unwrap().expose(), b"first synthetic");
            store
                .write(&Secret::new(b"second synthetic".to_vec()).unwrap())
                .unwrap();
            assert_eq!(store.read().unwrap().expose(), b"second synthetic");
            let target = path.join(file_name(Purpose::Viewer));
            let mut encrypted = std::fs::read(&target).unwrap();
            let i = encrypted.len() / 2;
            encrypted[i] ^= 1;
            std::fs::write(&target, encrypted).unwrap();
            assert!(matches!(
                store.read(),
                Err(StoreError::CorruptOrWrongPurpose)
            ));
        }
        #[test]
        fn provision_leaf_is_inheritable_idempotent_and_refuses_unsafe_existing() {
            let path = std::env::temp_dir().join(format!(
                "hoen-provision-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0.join("protected").join("sidecar.tmp"));
                    let _ = std::fs::remove_dir(self.0.join("unsafe"));
                    let _ = std::fs::remove_dir(self.0.join("protected"));
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            std::fs::create_dir(&path).unwrap();
            let _cleanup = Cleanup(path.clone());
            let target = path.join("protected");
            provision_directory(&target, Purpose::Viewer).unwrap();
            validate_directory(&target, Purpose::Viewer).unwrap();
            validate_inheritable_directory(&target, Purpose::Viewer).unwrap();
            provision_directory(&target, Purpose::Viewer).unwrap();
            // SQLite sidecars have no explicit descriptor: Windows must inherit only the owner ACE.
            let sidecar = target.join("sidecar.tmp");
            std::fs::write(&sidecar, b"synthetic").unwrap();
            let id = identity(Purpose::Viewer).unwrap();
            let name = wide(sidecar.as_os_str());
            let h = Handle(unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    READ_CONTROL.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
                .unwrap()
            });
            unsafe {
                let mut owner = PSID::default();
                let mut acl = null_mut();
                let mut raw = PSECURITY_DESCRIPTOR::default();
                assert_eq!(
                    GetSecurityInfo(
                        h.0,
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        Some(&mut owner),
                        None,
                        Some(&mut acl),
                        None,
                        Some(&mut raw)
                    ),
                    ERROR_SUCCESS
                );
                let _sd = Local(raw.0);
                assert!(EqualSid(owner, id.sid).is_ok());
                let mut info = ACL_SIZE_INFORMATION::default();
                GetAclInformation(
                    acl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
                .unwrap();
                assert_eq!(info.AceCount, 1);
                let mut ace = null_mut();
                GetAce(acl, 0, &mut ace).unwrap();
                let a = &*(ace as *const ACCESS_ALLOWED_ACE);
                assert_eq!(a.Header.AceType, 0);
                assert_ne!(a.Header.AceFlags & 0x10, 0);
                assert!(
                    EqualSid(PSID((&a.SidStart as *const u32 as *mut u32).cast()), id.sid).is_ok()
                );
            }
            drop(h);
            let missing = path.join("missing").join("leaf");
            assert!(provision_directory(&missing, Purpose::Viewer).is_err());
            assert!(!missing.exists());
            let unsafe_leaf = path.join("unsafe");
            std::fs::create_dir(&unsafe_leaf).unwrap();
            assert!(provision_directory(&unsafe_leaf, Purpose::Viewer).is_err());
            assert!(unsafe_leaf.is_dir());
        }
        #[test]
        fn existing_noninheritable_directory_is_not_rewritten() {
            let id = identity(Purpose::Viewer).unwrap();
            let sd = descriptor(&id, false).unwrap();
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            let path = std::env::temp_dir().join(format!(
                "hoen-existing-{}-{}",
                std::process::id(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let name = wide(path.as_os_str());
            unsafe {
                CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&sa)).unwrap();
            }
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            let _cleanup = Cleanup(path.clone());
            provision_directory(&path, Purpose::Viewer).unwrap();
            validate_directory(&path, Purpose::Viewer).unwrap();
            assert!(validate_inheritable_directory(&path, Purpose::Viewer).is_err());
        }
        #[test]
        fn unsafe_directory_is_refused() {
            assert!(ProtectedStore::open(Path::new("relative"), Purpose::Viewer).is_err());
            assert!(ProtectedStore::open(&std::env::temp_dir(), Purpose::Viewer).is_err());
        }
    }
}
#[cfg(windows)]
pub use windows_store::{
    provision_directory, validate_directory, validate_inheritable_directory, ProtectedStore,
};
