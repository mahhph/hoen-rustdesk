//! LocalSystem-only one-shot machine bootstrap reader. No paths come from the blob.
//! The caller owns semantic validation, existing-enrollment precedence and durable
//! host enrollment. Keep the pending object alive until after protected read-back.
use super::credentials::{CredentialStore, Secret, StoreError, MAX_SECRET_BYTES};

#[cfg(windows)]
mod windows_bootstrap {
    use super::*;
    use std::{
        ffi::{c_void, OsStr},
        fs::File,
        io::Read,
        mem::size_of,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Component, Path, PathBuf, Prefix},
        ptr::null_mut,
    };
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_READ, HANDLE, HLOCAL},
            Security::{Authorization::*, Cryptography::*, *},
            Storage::FileSystem::*,
            System::Com::CoTaskMemFree,
            UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG},
        },
    };
    const ENTROPY: &[u8] = b"remote-desktop-bootstrap-v1";
    const MAX_CIPHER: usize = MAX_SECRET_BYTES + 8192;
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }
    fn directory() -> Result<PathBuf, StoreError> {
        let ptr =
            unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KNOWN_FOLDER_FLAG(0), None) }
                .map_err(|_| StoreError::Unavailable)?;
        let value = unsafe { ptr.to_string() }.map_err(|_| StoreError::Unavailable);
        unsafe {
            CoTaskMemFree(Some(ptr.0.cast()));
        }
        Ok(PathBuf::from(value?)
            .join("Remote Desktop Service")
            .join("bootstrap"))
    }
    fn is_missing(error: &windows::core::Error) -> bool {
        matches!(error.code().0 as u32, 0x80070002 | 0x80070003)
    }
    unsafe fn check_type(h: HANDLE, directory: bool) -> Result<(), StoreError> {
        let mut a = FILE_ATTRIBUTE_TAG_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                h,
                FileAttributeTagInfo,
                (&mut a as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        }
        .map_err(|_| StoreError::UnprotectedPath)?;
        if a.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || (a.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
        {
            return Err(StoreError::UnprotectedPath);
        }
        Ok(())
    }
    unsafe fn protected(h: HANDLE, directory: bool) -> Result<(), StoreError> {
        unsafe {
            let mut owner = PSID::default();
            let mut acl = null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            if GetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut acl),
                None,
                Some(&mut sd),
            ) != ERROR_SUCCESS
            {
                return Err(StoreError::UnprotectedPath);
            }
            let _sd = Local(sd.0);
            if owner.0.is_null()
                || acl.is_null()
                || !(IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
                    || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool())
            {
                return Err(StoreError::UnprotectedPath);
            }
            let (mut control, mut revision) = (0, 0);
            GetSecurityDescriptorControl(sd, &mut control, &mut revision)
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
            if info.AceCount != 2 {
                return Err(StoreError::UnprotectedPath);
            }
            let (mut system, mut admins) = (false, false);
            for i in 0..2 {
                let mut ace = null_mut();
                GetAce(acl, i, &mut ace).map_err(|_| StoreError::UnprotectedPath)?;
                if ace.is_null() {
                    return Err(StoreError::UnprotectedPath);
                }
                let header = &*(ace as *const ACE_HEADER);
                let expected_flags = if directory { 3 } else { 0 };
                if header.AceType != 0
                    || header.AceFlags != expected_flags
                    || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
                {
                    return Err(StoreError::UnprotectedPath);
                }
                let a = &*(ace as *const ACCESS_ALLOWED_ACE);
                let sid = PSID((&a.SidStart as *const u32 as *mut u32).cast());
                if !IsValidSid(sid).as_bool() || a.Mask & FILE_ALL_ACCESS.0 != FILE_ALL_ACCESS.0 {
                    return Err(StoreError::UnprotectedPath);
                }
                if IsWellKnownSid(sid, WinLocalSystemSid).as_bool() && !system {
                    system = true;
                } else if IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() && !admins {
                    admins = true;
                } else {
                    return Err(StoreError::UnprotectedPath);
                }
            }
            if !system || !admins {
                return Err(StoreError::UnprotectedPath);
            }
            Ok(())
        }
    }
    fn hold_chain(path: &Path) -> Result<Option<Vec<Handle>>, StoreError> {
        if !path.is_absolute()
            || !matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(StoreError::UnprotectedPath);
        }
        let mut partial = PathBuf::new();
        let mut handles = Vec::new();
        for part in path.components() {
            partial.push(part.as_os_str());
            if matches!(part, Component::Prefix(_)) {
                continue;
            }
            let name = wide(partial.as_os_str());
            let h = match unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    READ_CONTROL.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            } {
                Ok(h) => h,
                Err(e) if is_missing(&e) => return Ok(None),
                Err(_) => return Err(StoreError::UnprotectedPath),
            };
            let h = Handle(h);
            unsafe {
                check_type(h.0, true)?;
            }
            // Both fixed private descendants must be protected, not just the leaf.
            if partial == path || partial == path.parent().ok_or(StoreError::UnprotectedPath)? {
                unsafe {
                    protected(h.0, true)?;
                }
            }
            handles.push(h);
        }
        Ok(Some(handles))
    }
    fn unprotect(data: &[u8]) -> Result<Secret, StoreError> {
        if data.is_empty() || data.len() > MAX_CIPHER {
            return Err(StoreError::InvalidInput);
        }
        unsafe {
            let input = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let entropy = CRYPT_INTEGER_BLOB {
                cbData: ENTROPY.len() as u32,
                pbData: ENTROPY.as_ptr() as *mut u8,
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|_| StoreError::CorruptOrWrongPurpose)?;
            if out.pbData.is_null() {
                return Err(StoreError::Unavailable);
            }
            let _guard = Local(out.pbData.cast());
            let n = out.cbData as usize;
            let bytes = if n > 0 && n <= MAX_SECRET_BYTES {
                Some(std::slice::from_raw_parts(out.pbData, n).to_vec())
            } else {
                None
            };
            for i in 0..n {
                std::ptr::write_volatile(out.pbData.add(i), 0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            Secret::new(bytes.ok_or(StoreError::InvalidInput)?)
        }
    }
    #[derive(serde_derive::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        schema_version: u32,
        client: ClientFields,
        config: ConfigFields,
    }
    #[derive(serde_derive::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ClientFields {
        url: serde::de::IgnoredAny,
        fingerprint: serde::de::IgnoredAny,
        environment: serde::de::IgnoredAny,
        token: serde::de::IgnoredAny,
    }
    #[derive(serde_derive::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConfigFields {
        identity: serde::de::IgnoredAny,
        display_name: serde::de::IgnoredAny,
        mailbox_ca_pem: serde::de::IgnoredAny,
        #[serde(default)]
        adapter_id: Option<serde::de::IgnoredAny>,
        #[serde(default)]
        network_id: Option<serde::de::IgnoredAny>,
        local_address: serde::de::IgnoredAny,
        listen_port: serde::de::IgnoredAny,
    }
    fn validate_shape(secret: &Secret) -> Result<(), StoreError> {
        let d: Document = serde_json::from_slice(secret.expose())
            .map_err(|_| StoreError::CorruptOrWrongPurpose)?;
        if d.schema_version != 1 {
            return Err(StoreError::CorruptOrWrongPurpose);
        }
        let _ = (
            d.client.url,
            d.client.fingerprint,
            d.client.environment,
            d.client.token,
            d.config.identity,
            d.config.display_name,
            d.config.mailbox_ca_pem,
            d.config.adapter_id,
            d.config.network_id,
            d.config.local_address,
            d.config.listen_port,
        );
        Ok(())
    }
    /// Retains the exact validated file and its ancestor handles; it cannot be
    /// replaced between read and handle-based deletion.
    pub struct PendingBootstrap {
        _directories: Vec<Handle>,
        file: File,
        secret: Secret,
    }
    impl PendingBootstrap {
        pub fn secret(&self) -> &Secret {
            &self.secret
        }
        /// Invoke after the supplied enrollment has been durably written. A protected
        /// read-back must match exactly before this specific bootstrap file is removed.
        pub fn finalize(
            self,
            store: &impl CredentialStore,
            expected: &Secret,
        ) -> Result<(), StoreError> {
            super::super::credentials::ensure_system()?;
            let actual = store.read()?;
            if actual.expose() != expected.expose() {
                return Err(StoreError::CorruptOrWrongPurpose);
            }
            let h = HANDLE(self.file.as_raw_handle());
            unsafe {
                check_type(h, false)?;
                protected(h, false)?;
            }
            let info = FILE_DISPOSITION_INFO {
                DeleteFile: true.into(),
            };
            unsafe {
                SetFileInformationByHandle(
                    h,
                    FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            }
            .map_err(|_| StoreError::Unavailable)?;
            Ok(())
        }
    }
    /// None means the fixed bootstrap file or its private directories are absent.
    /// All identity, access, ACL, format and DPAPI failures return an error.
    pub fn load_pending() -> Result<Option<PendingBootstrap>, StoreError> {
        super::super::credentials::ensure_system()?;
        let path = directory()?;
        let Some(dirs) = hold_chain(&path)? else {
            return Ok(None);
        };
        let name = wide(path.join("enrollment.dpapi").as_os_str());
        let h = match unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_READ.0 | READ_CONTROL.0 | 0x0001_0000,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        } {
            Ok(h) => h,
            Err(e) if is_missing(&e) => return Ok(None),
            Err(_) => return Err(StoreError::Unavailable),
        };
        let h = Handle(h);
        unsafe {
            check_type(h.0, false)?;
            protected(h.0, false)?;
        }
        let raw = h.0 .0;
        std::mem::forget(h);
        let mut file = unsafe { File::from_raw_handle(raw) };
        let size = file.metadata().map_err(|_| StoreError::Unavailable)?.len();
        if size == 0 || size > MAX_CIPHER as u64 {
            return Err(StoreError::InvalidInput);
        }
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)
            .map_err(|_| StoreError::Unavailable)?;
        let secret = unprotect(&encrypted)?;
        validate_shape(&secret)?;
        Ok(Some(PendingBootstrap {
            _directories: dirs,
            file,
            secret,
        }))
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rejects_invalid_shape() {
            let s =
                Secret::new(br#"{"schema_version":2,"client":{},"config":{}}"#.to_vec()).unwrap();
            assert_eq!(validate_shape(&s), Err(StoreError::CorruptOrWrongPurpose));
            assert_eq!(
                unprotect(b"not dpapi").err(),
                Some(StoreError::CorruptOrWrongPurpose)
            );
        }
        #[test]
        fn rejects_non_system_caller() {
            if super::super::super::credentials::ensure_system().is_err() {
                assert!(matches!(load_pending(), Err(StoreError::WrongIdentity)));
            }
        }
        #[test]
        fn machine_scope_roundtrip_and_tamper() {
            let plaintext=br#"{"schema_version":1,"client":{"url":"x","fingerprint":"x","environment":"x","token":"x"},"config":{"identity":"x","display_name":"x","mailbox_ca_pem":"x","adapter_id":"x","network_id":"x","local_address":"x","listen_port":1}}"#;
            unsafe {
                let input = CRYPT_INTEGER_BLOB {
                    cbData: plaintext.len() as u32,
                    pbData: plaintext.as_ptr() as *mut u8,
                };
                let entropy = CRYPT_INTEGER_BLOB {
                    cbData: ENTROPY.len() as u32,
                    pbData: ENTROPY.as_ptr() as *mut u8,
                };
                let mut out = CRYPT_INTEGER_BLOB::default();
                CryptProtectData(
                    &input,
                    PCWSTR::null(),
                    Some(&entropy),
                    None,
                    None,
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                    &mut out,
                )
                .unwrap();
                let _guard = Local(out.pbData.cast());
                let mut encrypted =
                    std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
                let secret = unprotect(&encrypted).unwrap();
                assert_eq!(secret.expose(), plaintext);
                validate_shape(&secret).unwrap();
                let i = encrypted.len() / 2;
                encrypted[i] ^= 1;
                assert_eq!(
                    unprotect(&encrypted).err(),
                    Some(StoreError::CorruptOrWrongPurpose)
                );
            }
        }
    }
}
#[cfg(windows)]
pub use windows_bootstrap::{load_pending, PendingBootstrap};
