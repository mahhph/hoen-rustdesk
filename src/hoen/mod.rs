//! Mailbox-mode integration. Legacy connections do not use these entry points.
pub(crate) mod authorization;
pub(crate) mod credentials;
pub(crate) mod handshake;
pub(crate) mod history_worker;
pub(crate) mod mailbox_worker;
pub(crate) mod network;
pub(crate) mod transport;
