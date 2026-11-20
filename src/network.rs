use crate::{
    config::{Config, Endpoint, Target},
    store::{Job, Store, fault},
    *,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as Param, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use reqwest::Client;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use spora_core::{MAX_ENVELOPE, MessagePut, RETENTION_MS, StorageReceipt, digest, new_id, now_ms};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
struct App {
    dir: PathBuf,
    config: Arc<Config>,
    slots: Arc<tokio::sync::Semaphore>,
}
pub async fn disk<T: Send + 'static>(
    dir: PathBuf,
    f: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || f(&mut Store::open(&dir)?))
        .await
        .map_err(|_| Error("STORAGE_UNAVAILABLE"))?
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let s = match self.0 {
            "UNAUTHENTICATED" => 401,
            "FORBIDDEN" | "POLICY_DENIED" => 403,
            "NOT_FOUND" | "NO_ROUTE" => 404,
            "IDEMPOTENCY_CONFLICT" => 409,
            "EXPIRED" => 410,
            "TOO_LARGE" => 413,
            "QUOTA_EXCEEDED" | "RATE_LIMITED" => 429,
            "BROKEN_RESTORE" | "STORAGE_UNAVAILABLE" | "TEMPORARILY_UNAVAILABLE" => 503,
            _ => 400,
        };
        let code = if self.0 == "BROKEN_RESTORE" {
            "STORAGE_UNAVAILABLE"
        } else {
            self.0
        };
        let retry = matches!(s, 429 | 503);
        let mut body = json!({"request_id":new_id(),"code":code,"retryable":retry});
        if retry {
            body["retry_after_ms"] = json!(1000)
        }
        (StatusCode::from_u16(s).unwrap(), Json(body)).into_response()
    }
}
fn bearer(s: &App, h: &HeaderMap) -> Result<String> {
    let (scheme, token) = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .ok_or(Error("UNAUTHENTICATED"))?;
    require(
        scheme.eq_ignore_ascii_case("Bearer") && token.len() == 43,
        "UNAUTHENTICATED",
    )?;
    s.config.authenticate(token)
}
async fn cap(State(s): State<App>) -> Json<Value> {
    Json(
        json!({"service_id":s.config.gateway_id,"roles":["gateway"],"contract_version":"0.1.0","max_envelope_bytes":MAX_ENVELOPE,"max_retention_ms":RETENTION_MS,"radio_bundle_max_bytes":BUNDLE_MAX}),
    )
}
async fn submit(
    State(s): State<App>,
    Param(id): Param<String>,
    h: HeaderMap,
    p: std::result::Result<Json<Transfer>, JsonRejection>,
) -> Result<Response> {
    let owner = bearer(&s, &h)?;
    let _slot = s
        .slots
        .try_acquire()
        .map_err(|_| Error("TEMPORARILY_UNAVAILABLE"))?;
    let Json(p) = p.map_err(|e| {
        Error(if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            "TOO_LARGE"
        } else {
            INVALID
        })
    })?;
    let (new, v) = disk(s.dir, move |db| db.put(&owner, &id, &p, now_ms())).await?;
    Ok((
        if new {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(v),
    )
        .into_response())
}
async fn status(
    State(s): State<App>,
    Param(id): Param<String>,
    h: HeaderMap,
) -> Result<Json<Status>> {
    let owner = bearer(&s, &h)?;
    let _slot = s
        .slots
        .try_acquire()
        .map_err(|_| Error("TEMPORARILY_UNAVAILABLE"))?;
    Ok(Json(
        disk(s.dir, move |db| db.status(&owner, &id, now_ms())).await?,
    ))
}
async fn cancel(
    State(s): State<App>,
    Param(id): Param<String>,
    h: HeaderMap,
) -> Result<Json<Status>> {
    let owner = bearer(&s, &h)?;
    let _slot = s
        .slots
        .try_acquire()
        .map_err(|_| Error("TEMPORARILY_UNAVAILABLE"))?;
    Ok(Json(
        disk(s.dir, move |db| db.cancel(&owner, &id, now_ms())).await?,
    ))
}

pub async fn serve(
    dir: PathBuf,
    secrets: PathBuf,
    listen: SocketAddr,
    cert: &Path,
    key: &Path,
    manual_workers: bool,
) -> anyhow::Result<()> {
    let config = Arc::new(Store::open(&dir)?.config.clone());
    let app = Router::new()
        .route("/v1/capabilities", get(cap))
        .route("/v1/transfers/{id}", put(submit).get(status))
        .route("/v1/transfers/{id}/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(131072))
        .with_state(App {
            dir: dir.clone(),
            config,
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
        });
    let chain = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or(Error(INVALID))?;
    let tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    if !manual_workers {
        tokio::spawn(async move {
            let mut maintenance = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = maintenance.tick() => {
                        let result = disk(dir.clone(), |store| {
                            store.gc(now_ms())?;
                            store.consume_events(now_ms())?;
                            Ok(())
                        }).await;
                        if let Err(error) = result {
                            eprintln!("maintenance: {}", error.0);
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(150)) => {
                        if let Err(error) = forward(&dir,&secrets).await {
                            eprintln!("forward: {}",error.0);
                        }
                    }
                }
            }
        });
    }
    axum_server::bind_rustls(
        listen,
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
    )
    .serve(app.into_make_service())
    .await?;
    Ok(())
}

fn credentials(ep: &Endpoint, secrets: &Path) -> Result<(Client, String)> {
    let pem = std::fs::read(secrets.join(format!("{}.pem", ep.ca_sha256)))?;
    require(digest(&pem) == ep.ca_sha256, "POLICY_DENIED")?;
    let t = std::fs::read_to_string(secrets.join(format!("{}.token", ep.token_hash)))?;
    let t = t.trim();
    require(hash_token(t)? == ep.token_hash, "FORBIDDEN")?;
    let ca = reqwest::Certificate::from_pem(&pem).map_err(|_| Error(INVALID))?;
    let client = Client::builder()
        .no_proxy()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(ca)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| Error(INVALID))?;
    Ok((client, t.to_owned()))
}
const TEMP: Error = Error("TEMPORARILY_UNAVAILABLE");
async fn body(mut r: reqwest::Response) -> Result<Value> {
    let mut b = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|_| TEMP)? {
        require(b.len() + chunk.len() <= 131072, "TOO_LARGE")?;
        b.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&b).map_err(|_| Error(INVALID))
}
#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    retryable: bool,
    delay: i64,
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self {
            code: e.0,
            retryable: matches!(e.0, "STORAGE_UNAVAILABLE" | "TEMPORARILY_UNAVAILABLE"),
            delay: 1000,
        }
    }
}
async fn send(
    dir: &Path,
    secrets: &Path,
    target: &Target,
    j: &Job,
) -> std::result::Result<bool, Failure> {
    let (ep, service, role) = match target {
        Target::Relay { ip, service, .. } => (ip, service, "relay"),
        Target::Peer {
            ip: Some(ip), peer, ..
        } => (ip, peer, "gateway"),
        _ => return Err(Error("NO_ROUTE").into()),
    };
    let (http, token) = credentials(ep, secrets)?;
    let origin = ep.origin.trim_end_matches('/');
    let cap = http
        .get(format!("{origin}/v1/capabilities"))
        .send()
        .await
        .map_err(|_| TEMP)?;
    require(cap.status() == StatusCode::OK, "TEMPORARILY_UNAVAILABLE")?;
    let cap = body(cap).await?;
    require(
        cap["service_id"] == *service
            && cap["contract_version"] == "0.1.0"
            && cap["roles"]
                .as_array()
                .is_some_and(|r| r.iter().any(|v| v == role)),
        "POLICY_DENIED",
    )?;
    if role == "gateway" {
        let peer = service.clone();
        let wait = disk(dir.into(), move |s| {
            s.change(now_ms(), |tx, _, _| {
                let now = now_ms();
                let since: Option<Option<i64>> = tx
                    .query_row("SELECT since FROM ip_health WHERE peer=?1", [&peer], |r| {
                        r.get(0)
                    })
                    .optional()?;
                match since {
                    Some(None) => {
                        tx.execute(
                            "UPDATE ip_health SET since=?2 WHERE peer=?1",
                            rusqlite::params![peer, now],
                        )?;
                        Ok(30_000)
                    }
                    Some(Some(t)) => Ok((t + 30_000 - now).max(0)),
                    None => Ok(0),
                }
            })
        })
        .await?;
        if wait > 0 {
            return Err(Failure {
                code: "LINK_UNAVAILABLE",
                retryable: true,
                delay: wait,
            });
        }
    }
    let p = &j.put;
    let req = match target {
        Target::Relay {
            queue, generation, ..
        } => http
            .put(format!(
                "{origin}/v1/queues/{queue}/messages/{}",
                p.delivery_id
            ))
            .json(&MessagePut {
                generation: generation.clone(),
                envelope_b64url: p.envelope_b64url.clone(),
                envelope_sha256: p.envelope_sha256.clone(),
                expires_at_ms: p.expires_at_ms,
            }),
        Target::Peer { remote_handle, .. } => {
            let mut remote = p.clone();
            remote.route_handle = remote_handle.clone();
            remote.allowed_paths = vec!["ip".into()];
            http.put(format!("{origin}/v1/transfers/{}", j.tid))
                .json(&remote)
        }
    };
    let r = req.bearer_auth(token).send().await.map_err(|_| TEMP)?;
    let status = r.status();
    let value = body(r).await?;
    if !matches!(status, StatusCode::OK | StatusCode::CREATED) {
        let known = [
            "EXPIRED",
            "QUOTA_EXCEEDED",
            "RATE_LIMITED",
            "STORAGE_UNAVAILABLE",
            "TEMPORARILY_UNAVAILABLE",
            "QUEUE_SUSPENDED",
            "IDEMPOTENCY_CONFLICT",
            "FORBIDDEN",
            "UNAUTHENTICATED",
            "RETENTION_LIMIT",
            "GENERATION_MISMATCH",
            "POLICY_DENIED",
            "TOO_LARGE",
        ];
        let code = known
            .into_iter()
            .find(|c| value["code"] == *c)
            .unwrap_or(INVALID);
        return Err(Failure {
            code,
            retryable: matches!(
                code,
                "QUOTA_EXCEEDED"
                    | "RATE_LIMITED"
                    | "STORAGE_UNAVAILABLE"
                    | "TEMPORARILY_UNAVAILABLE"
            ),
            delay: value["retry_after_ms"].as_i64().unwrap_or(1000),
        });
    }
    let now = now_ms();
    match target {
        Target::Peer { remote_handle, .. } => {
            let s: Status = serde_json::from_value(value).map_err(|_| Error(INVALID))?;
            require(
                s.gateway_id == *service
                    && s.transfer_id == j.tid
                    && s.route_handle == *remote_handle
                    && s.delivery_id == p.delivery_id
                    && s.envelope_sha256 == p.envelope_sha256
                    && s.expires_at_ms == p.expires_at_ms
                    && s.accepted_at_ms > 0
                    && s.accepted_at_ms <= now + 30_000
                    && s.accepted_at_ms < s.expires_at_ms
                    && s.custody_state == "stored",
                INVALID,
            )?;
            Ok(true)
        }
        Target::Relay {
            queue, generation, ..
        } => {
            require(
                matches!(value["state"].as_str(), Some("stored" | "consumed")),
                INVALID,
            )?;
            let r: StorageReceipt =
                serde_json::from_value(value["receipt"].clone()).map_err(|_| Error(INVALID))?;
            require(
                r.service_id == *service
                    && r.queue_id == *queue
                    && r.generation == *generation
                    && r.delivery_id == p.delivery_id
                    && r.envelope_sha256 == p.envelope_sha256
                    && r.expires_at_ms == p.expires_at_ms
                    && r.accepted_at_ms > 0
                    && r.accepted_at_ms <= now + 30_000
                    && r.accepted_at_ms < r.expires_at_ms
                    && r.seq
                        .parse::<u64>()
                        .is_ok_and(|s| s > 0 && s.to_string() == r.seq),
                INVALID,
            )?;
            Ok(false)
        }
    }
}
pub async fn forward(dir: &Path, secrets: &Path) -> Result<bool> {
    let j = disk(dir.into(), |s| {
        let Some(j) = s.claim(None, now_ms())? else {
            return Ok(None);
        };
        let t = s.config.routes[&j.put.route_handle].target.clone();
        Ok(Some((j, t)))
    })
    .await?;
    let Some((j, target)) = j else {
        return Ok(false);
    };
    match send(dir, secrets, &target, &j).await {
        Ok(peer) => {
            fault("after-upstream-put");
            disk(dir.into(), move |s| s.record_fact(&j, peer, now_ms())).await?;
        }
        Err(e) => {
            disk(dir.into(), move |s| {
                if e.code == "TEMPORARILY_UNAVAILABLE"
                    && let Target::Peer { peer, .. } = target
                {
                    s.change(now_ms(), |tx, _, _| {
                        let sql = "INSERT INTO ip_health VALUES(?1,NULL)
                                 ON CONFLICT(peer) DO UPDATE SET since=NULL";
                        tx.execute(sql, [peer])?;
                        Ok(())
                    })?;
                }
                s.failed(&j, false, e.code, e.retryable, now_ms(), e.delay)
            })
            .await?;
        }
    };
    Ok(true)
}
