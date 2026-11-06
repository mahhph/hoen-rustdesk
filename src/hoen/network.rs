//! Socket binding checks. Peer authorization comes from the encrypted mailbox proof.
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub local_address: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    MissingPolicy,
    InvalidPolicy,
    BindingMismatch,
}

fn valid_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

pub fn verify_binding(policy: Option<&Policy>, local: SocketAddr) -> Result<(), Denied> {
    let policy = policy.ok_or(Denied::MissingPolicy)?;
    if !valid_address(policy.local_address) {
        return Err(Denied::InvalidPolicy);
    }
    if policy.local_address != local.ip() {
        return Err(Denied::BindingMismatch);
    }
    Ok(())
}

pub fn admit_socket(
    policy: Option<&Policy>,
    local: SocketAddr,
    _peer: SocketAddr,
) -> Result<(), Denied> {
    verify_binding(policy, local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_rejects_missing_invalid_or_different_local_address() {
        let local: SocketAddr = "192.168.1.3:42830".parse().unwrap();
        assert_eq!(verify_binding(None, local), Err(Denied::MissingPolicy));
        assert_eq!(
            verify_binding(
                Some(&Policy {
                    local_address: "0.0.0.0".parse().unwrap(),
                }),
                local,
            ),
            Err(Denied::InvalidPolicy)
        );
        assert_eq!(
            verify_binding(
                Some(&Policy {
                    local_address: "192.168.1.4".parse().unwrap(),
                }),
                local,
            ),
            Err(Denied::BindingMismatch)
        );
    }

    #[test]
    fn mailbox_transport_does_not_reject_a_peer_by_network_path() {
        let local: SocketAddr = "192.168.1.3:42830".parse().unwrap();
        let policy = Policy {
            local_address: local.ip(),
        };
        for peer in ["192.168.1.4:5000", "10.8.0.2:5000", "203.0.113.8:5000"] {
            assert_eq!(
                admit_socket(Some(&policy), local, peer.parse().unwrap()),
                Ok(())
            );
        }
    }
}
