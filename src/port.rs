//! Transaction boundary between a gateway spool and its locally commissioned adapter.
use crate::{config::Config, store::accept, *};
use rusqlite::{Transaction, params};
use spora_core::{digest, to_b64, valid_id};
use std::path::Path;
pub fn bundle(handle: &str, p: &Transfer) -> Result<Vec<u8>> {
    let data = p.bytes()?;
    require(valid_id(handle), INVALID)?;
    require(data.len() + HEADER <= BUNDLE_MAX, "TOO_LARGE")?;
    let mut b = vec![1];
    b.extend(hex::decode(handle).map_err(|_| Error(INVALID))?);
    b.extend(hex::decode(&p.delivery_id).map_err(|_| Error(INVALID))?);
    b.extend(p.expires_at_ms.to_be_bytes());
    b.extend((data.len() as u32).to_be_bytes());
    b.extend(data);
    Ok(b)
}
pub fn unpack(b: &[u8]) -> Result<Transfer> {
    require(
        (HEADER + 1..=BUNDLE_MAX).contains(&b.len()) && b[0] == 1,
        INVALID,
    )?;
    let data = &b[HEADER..];
    let n = u32::from_be_bytes(b[41..45].try_into().unwrap()) as usize;
    require(n == data.len(), INVALID)?;
    Ok(Transfer {
        route_handle: hex::encode(&b[1..17]),
        delivery_id: hex::encode(&b[17..33]),
        expires_at_ms: i64::from_be_bytes(b[33..41].try_into().unwrap()),
        envelope_sha256: digest(data),
        envelope_b64url: to_b64(data),
        allowed_paths: vec!["ip".into()],
        priority: "interactive".into(),
    })
}
#[derive(Debug, Clone)]
pub struct Ack {
    pub hash: String,
    pub accepted: i64,
    pub expiry: i64,
}

pub fn accept_bundle(
    tx: &Transaction,
    config: &Config,
    dir: &Path,
    peer: &str,
    tid: &str,
    bytes: &[u8],
    now: i64,
) -> Result<Ack> {
    require(
        config
            .principals
            .get(peer)
            .is_some_and(|p| p.role == "peer"),
        "FORBIDDEN",
    )?;
    let put = unpack(bytes)?;
    let (_, s) = accept(tx, config, dir, peer, tid, &put, now)?;
    Ok(Ack {
        hash: digest(bytes),
        accepted: s.accepted_at_ms,
        expiry: s.expires_at_ms,
    })
}
// The immutable spool already holds the envelope and route. Keep the digest of the
// installed bundle so a receipt can be bound to this exact job after a restart.
pub(crate) fn install_outbound(
    tx: &Transaction,
    peer: &str,
    tid: &str,
    bytes: &[u8],
    priority: &str,
) -> Result<()> {
    let hash = digest(bytes);
    let old: Option<String> = tx.query_row(
        "SELECT bundle_hash FROM spool WHERE peer=?1 AND tid=?2 AND priority=?3 AND eligible",
        params![peer, tid, priority],
        |r| r.get(0),
    )?;
    if let Some(existing) = old {
        return require(existing == hash, CONFLICT);
    }
    tx.execute(
        "UPDATE spool SET bundle_hash=?3,rf_due=accepted WHERE peer=?1 AND tid=?2",
        params![peer, tid, hash],
    )?;
    Ok(())
}
