//! LAN v2 wire validation. Transport authentication and server transactions remain mandatory.
use hbb_common::serde_json;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_BODY: usize = 4096;
pub const MAX_COUNTER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    AliasConflict,
    IdentityConflict,
    LeaseSuperseded,
    SequenceStale,
    SequenceConflict,
    UpgradeRequired,
    HostOffline,
    HostDisabled,
    MailboxUnreachable,
    CertificateInvalid,
    BrokerUnavailable,
    PermissionMissing,
    ListenerBindFailed,
    HistoryDelayed,
}

pub trait Validate {
    fn validate(&self) -> Result<(), ErrorCode>;
}

pub fn parse<T: DeserializeOwned + Validate>(bytes: &[u8]) -> Result<T, ErrorCode> {
    if bytes.len() > MAX_BODY {
        return Err(ErrorCode::InvalidRequest);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    value.validate()?;
    Ok(value)
}

fn require(valid: bool) -> Result<(), ErrorCode> {
    if valid { Ok(()) } else { Err(ErrorCode::InvalidRequest) }
}

fn uuid(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) { b == b'-' }
        else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }
    }) && matches!(value.as_bytes()[14], b'1'..=b'8')
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role { Client, Host, Both }

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint { pub address: IpAddr, pub port: u16 }
impl Validate for Endpoint {
    fn validate(&self) -> Result<(), ErrorCode> {
        let valid = match self.address {
            IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        };
        require(valid && self.port != 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Registration {
    pub alias: String,
    pub role: Role,
    pub public_key_fingerprint: String,
    pub endpoint: Option<Endpoint>,
}
impl Validate for Registration {
    fn validate(&self) -> Result<(), ErrorCode> {
        require(!self.alias.is_empty() && self.alias.len() <= 64 && self.alias.trim() == self.alias
            && self.alias.bytes().all(|b| (0x20..=0x7e).contains(&b)))?;
        require(self.public_key_fingerprint.len() == 64
            && self.public_key_fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))?;
        match (&self.role, &self.endpoint) {
            (Role::Client, None) => Ok(()),
            (Role::Host | Role::Both, Some(endpoint)) => endpoint.validate(),
            _ => Err(ErrorCode::InvalidRequest),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LeaseCreate {
    pub request_id: String,
    pub expected_generation: u64,
}
impl Validate for LeaseCreate {
    fn validate(&self) -> Result<(), ErrorCode> {
        require(uuid(&self.request_id) && self.expected_generation < MAX_COUNTER)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Heartbeat {
    pub generation: u64,
    pub sequence: u64,
    pub endpoint: Option<Endpoint>,
    pub listener_ready: bool,
    pub capability_ready: bool,
    pub build_id: String,
    pub error_code: Option<ErrorCode>,
}
impl Validate for Heartbeat {
    fn validate(&self) -> Result<(), ErrorCode> {
        require((1..=MAX_COUNTER).contains(&self.generation) && (1..=MAX_COUNTER).contains(&self.sequence))?;
        require(!self.build_id.is_empty() && self.build_id.len() <= 64
            && self.build_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))?;
        if let Some(endpoint) = &self.endpoint { endpoint.validate()?; }
        require(!self.listener_ready || self.endpoint.is_some())?;
        require(!self.capability_ready || self.listener_ready)
    }
}

/// Compare validated updates for one current lease. The caller must check actor and lease ID first.
/// Duplicate means return the saved response, never extend expiry.
pub fn compare_update(current: &Heartbeat, incoming: &Heartbeat) -> Result<bool, ErrorCode> {
    current.validate()?;
    incoming.validate()?;
    if incoming.generation != current.generation { return Err(ErrorCode::LeaseSuperseded); }
    if incoming.sequence < current.sequence { return Err(ErrorCode::SequenceStale); }
    if incoming.sequence == current.sequence {
        return if incoming == current { Ok(false) } else { Err(ErrorCode::SequenceConflict) };
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_wire_cases_accept_only_valid_requests() {
        let cases: serde_json::Value = serde_json::from_str(include_str!("../../contracts/lan-v2/wire-cases.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let bytes = match case["raw"].as_str() {
                Some(raw) => raw.as_bytes().to_vec(),
                None => serde_json::to_vec(&case["body"]).unwrap(),
            };
            let accepted = match case["kind"].as_str().unwrap() {
                "registration" => parse::<Registration>(&bytes).is_ok(),
                "leaseCreate" => parse::<LeaseCreate>(&bytes).is_ok(),
                "heartbeat" => parse::<Heartbeat>(&bytes).is_ok(),
                other => panic!("unknown fixture {other}"),
            };
            assert_eq!(accepted, case["valid"].as_bool().unwrap(), "{}", case["name"]);
        }
    }

    #[test]
    fn duplicate_and_old_updates_cannot_refresh_or_replace_current_state() {
        let first = Heartbeat { generation: 2, sequence: 3, endpoint: None, listener_ready: false,
            capability_ready: false, build_id: "test".into(), error_code: Some(ErrorCode::ListenerBindFailed) };
        assert_eq!(compare_update(&first, &first), Ok(false));
        let mut next = first.clone();
        next.generation = 1;
        assert_eq!(compare_update(&first, &next), Err(ErrorCode::LeaseSuperseded));
        next.generation = 2; next.sequence = 2;
        assert_eq!(compare_update(&first, &next), Err(ErrorCode::SequenceStale));
        next.sequence = 3; next.build_id = "changed".into();
        assert_eq!(compare_update(&first, &next), Err(ErrorCode::SequenceConflict));
        next.sequence = 4;
        assert_eq!(compare_update(&first, &next), Ok(true));
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        assert_eq!(parse::<LeaseCreate>(&vec![b' '; MAX_BODY + 1]), Err(ErrorCode::InvalidRequest));
    }
}
