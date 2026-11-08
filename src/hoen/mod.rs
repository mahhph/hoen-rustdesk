//! Mailbox-mode integration. Legacy connections do not use these entry points.
pub(crate) mod authorization;
pub(crate) mod bootstrap;
pub(crate) mod credentials;
pub(crate) mod enrollment;
pub(crate) mod handshake;
pub(crate) mod history_worker;
pub(crate) mod host;
pub(crate) mod lan_contract;
#[cfg(windows)]
pub(crate) mod local_proof;
pub(crate) mod mailbox_worker;
#[cfg(target_os = "macos")]
pub(crate) mod macos_directory;
#[cfg(target_os = "macos")]
pub(crate) mod macos_display_wake;
#[cfg(target_os = "macos")]
pub(crate) mod macos_namespace;
#[cfg(target_os = "macos")]
mod macos_private_dir;
pub(crate) mod machine_bootstrap;
pub(crate) mod network;
pub(crate) mod runtime;
pub(crate) mod transport;
