//! Mailbox-mode integration. Legacy connections do not use these entry points.
pub(crate) mod authorization;
pub(crate) mod credentials;
pub(crate) mod enrollment;
pub(crate) mod handshake;
pub(crate) mod history_worker;
pub(crate) mod host;
pub(crate) mod mailbox_worker;
pub(crate) mod network;
pub(crate) mod network_monitor;
pub(crate) mod runtime;
pub(crate) mod transport;
