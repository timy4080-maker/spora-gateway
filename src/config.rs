use crate::{Error, INVALID, Result, paths_valid, require};
use serde::{Deserialize, Serialize};
use spora_core::valid_id;
use std::collections::{BTreeMap, HashSet};
use subtle::ConstantTimeEq;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub gateway_id: String,
    pub max_bytes: u64,
    pub max_records: u32,
    pub principals: BTreeMap<String, Principal>,
    pub routes: BTreeMap<String, Route>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub role: String,
    pub token_hash: String,
    pub max_bytes: u64,
    pub max_records: u32,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub owner: String,
    pub paths: Vec<String>,
    pub priorities: Vec<String>,
    pub target: Target,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Relay {
        service: String,
        queue: String,
        generation: String,
        ip: Endpoint,
    },
    Peer {
        peer: String,
        remote_handle: String,
        ip: Option<Endpoint>,
    },
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub origin: String,
    pub ca_sha256: String,
    pub token_hash: String,
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Endpoint {
    fn verify(&self) -> Result<()> {
        let u = reqwest::Url::parse(&self.origin).map_err(|_| Error(INVALID))?;
        require(
            u.scheme() == "https"
                && u.host().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none()
                && hash(&self.ca_sha256)
                && hash(&self.token_hash),
            INVALID,
        )
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        require(
            valid_id(&self.gateway_id)
                && self.max_records > 0
                && self.max_records <= 10_000
                && self.max_bytes > 0
                && self.max_bytes <= 67_108_864,
            INVALID,
        )?;
        let mut tokens = HashSet::new();
        for (id, p) in &self.principals {
            require(
                valid_id(id)
                    && id != &self.gateway_id
                    && matches!(p.role.as_str(), "peer" | "client")
                    && hash(&p.token_hash)
                    && tokens.insert(&p.token_hash)
                    && p.max_records > 0
                    && p.max_bytes > 0,
                INVALID,
            )?;
        }
        for (id, r) in &self.routes {
            let owner = self.principals.get(&r.owner).ok_or(Error(INVALID))?;
            require(
                valid_id(id)
                    && paths_valid(&r.paths)
                    && !r.priorities.is_empty()
                    && r.priorities
                        .iter()
                        .all(|p| p == "interactive" || p == "control"),
                INVALID,
            )?;
            match &r.target {
                Target::Peer {
                    peer,
                    remote_handle,
                    ip,
                } => {
                    require(
                        owner.role == "client"
                            && valid_id(peer)
                            && peer != &self.gateway_id
                            && valid_id(remote_handle)
                            && self.principals.get(peer).is_some_and(|p| p.role == "peer"),
                        "POLICY_DENIED",
                    )?;
                    require(ip.is_some() == r.paths.iter().any(|p| p == "ip"), INVALID)?;
                    if let Some(ep) = ip {
                        ep.verify()?
                    }
                }
                Target::Relay {
                    service,
                    queue,
                    generation,
                    ip,
                } => {
                    require(
                        valid_id(service)
                            && valid_id(queue)
                            && valid_id(generation)
                            && r.paths == ["ip"],
                        INVALID,
                    )?;
                    ip.verify()?
                }
            }
        }
        Ok(())
    }
    pub fn authenticate(&self, bearer: &str) -> Result<String> {
        let h = crate::hash_token(bearer)?;
        self.principals
            .iter()
            .find(|(_, p)| bool::from(h.as_bytes().ct_eq(p.token_hash.as_bytes())))
            .map(|(id, _)| id.clone())
            .ok_or(Error("UNAUTHENTICATED"))
    }
}
