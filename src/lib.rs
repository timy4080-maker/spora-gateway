pub mod config;
pub mod fake;
pub mod network;
pub mod port;
pub mod store;

use serde::{Deserialize, Serialize};
use spora_core::{MAX_ENVELOPE, digest, from_b64, valid_id};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self("STORAGE_UNAVAILABLE")
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("STORAGE_UNAVAILABLE")
    }
}
pub fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(code)) }
}
pub const BUNDLE_MAX: usize = 4096;
pub const HEADER: usize = 45;
pub const CHUNK: usize = 105;
pub const MAX_ATTEMPTS: i64 = 16;
pub const INVALID: &str = "INVALID_ARGUMENT";
pub const CONFLICT: &str = "IDEMPOTENCY_CONFLICT";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub route_handle: String,
    pub delivery_id: String,
    pub envelope_b64url: String,
    pub envelope_sha256: String,
    pub expires_at_ms: i64,
    pub allowed_paths: Vec<String>,
    pub priority: String,
}
impl Transfer {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        require(
            valid_id(&self.route_handle)
                && valid_id(&self.delivery_id)
                && self.expires_at_ms >= 0
                && self.expires_at_ms <= 9_007_199_254_740_991,
            INVALID,
        )?;
        require(
            paths_valid(&self.allowed_paths)
                && matches!(self.priority.as_str(), "interactive" | "control"),
            INVALID,
        )?;
        require(
            self.envelope_b64url.len() <= MAX_ENVELOPE.div_ceil(3) * 4,
            "TOO_LARGE",
        )?;
        let data = from_b64(&self.envelope_b64url).map_err(|_| Error(INVALID))?;
        require(!data.is_empty() && data.len() <= MAX_ENVELOPE, "TOO_LARGE")?;
        require(digest(&data) == self.envelope_sha256, INVALID)?;
        Ok(data)
    }
}
pub fn paths_valid(p: &[String]) -> bool {
    !p.is_empty()
        && p.len() <= 2
        && p.iter().all(|x| x == "ip" || x == "meshcore")
        && (p.len() == 1 || p[0] != p[1])
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub gateway_id: String,
    pub transfer_id: String,
    pub route_handle: String,
    pub delivery_id: String,
    pub envelope_sha256: String,
    pub accepted_at_ms: i64,
    pub expires_at_ms: i64,
    pub custody_state: String,
    pub forward_state: String,
    pub radio_eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at_ms: Option<i64>,
}
pub fn hash_token(token: &str) -> Result<String> {
    let raw = from_b64(token).map_err(|_| Error("UNAUTHENTICATED"))?;
    require(raw.len() == 32, "UNAUTHENTICATED")?;
    Ok(digest(&raw))
}
