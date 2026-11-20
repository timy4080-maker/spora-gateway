use crate::{
    BUNDLE_MAX, CONFLICT, Error, HEADER, INVALID, MAX_ATTEMPTS, Result, Status, Transfer,
    config::{Config, Target},
    require,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use spora_core::{DEDUP_MS, RETENTION_MS, new_id, to_b64, valid_id};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Store {
    pub config: Config,
    pub(crate) db: Connection,
    witness: Connection,
    pub(crate) dir: PathBuf,
    _lock: File,
}
fn setup(c: &Connection) -> Result<()> {
    c.busy_timeout(Duration::from_secs(5))?;
    let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    c.execute_batch(
        "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA max_page_count=131072;",
    )?;
    require(
        mode == "wal"
            && c.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))? == 2
            && c.query_row("PRAGMA max_page_count", [], |r| r.get::<_, i64>(0))? == 131072,
        "STORAGE_UNAVAILABLE",
    )
}
fn exists_db(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?)
}
pub(crate) fn fault(label: &str) {
    if std::env::var("SPORA_GATEWAY_LAB_CRASH").as_deref() == Ok(label) {
        std::process::exit(86)
    }
}
impl Store {
    pub fn init(dir: &Path, config: &Config) -> Result<()> {
        config.validate()?;
        std::fs::create_dir(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.join("store.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let mut c = Connection::open(dir.join("gateway.db"))?;
        setup(&c)?;
        let tx = c.transaction()?;
        tx.execute_batch(include_str!("schema.sql"))?;
        let epoch = new_id();
        tx.execute(
            "INSERT INTO meta(id,config,epoch) VALUES(1,?1,?2)",
            params![
                serde_json::to_string(config).map_err(|_| Error(INVALID))?,
                epoch
            ],
        )?;
        tx.commit()?;
        let w = Connection::open(dir.join("witness.db"))?;
        setup(&w)?;
        w.execute_batch("CREATE TABLE witness(epoch TEXT PRIMARY KEY, revision INTEGER NOT NULL)")?;
        w.execute("INSERT INTO witness VALUES(?1,0)", [epoch])?;
        #[cfg(unix)]
        {
            File::open(dir)?.sync_all()?;
            if let Some(parent) = dir.canonicalize()?.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    }
    pub fn open(dir: &Path) -> Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("store.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let db = exists_db(&dir.join("gateway.db"))?;
        setup(&db)?;
        require(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? == 1,
            "UNSUPPORTED_VERSION",
        )?;
        let (j, epoch, rev): (String, String, i64) = db.query_row(
            "SELECT config,epoch,revision FROM meta WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let witness = exists_db(&dir.join("witness.db"))?;
        setup(&witness)?;
        let high: Option<i64> = witness
            .query_row(
                "SELECT revision FROM witness WHERE epoch=?1",
                [&epoch],
                |r| r.get(0),
            )
            .optional()?;
        require(high.is_some_and(|v| v <= rev), "BROKEN_RESTORE")?;
        if high != Some(rev) {
            witness.execute("UPDATE witness SET revision=?1", [rev])?;
        }
        let config =
            serde_json::from_str::<Config>(&j).map_err(|_| Error("STORAGE_UNAVAILABLE"))?;
        config.validate()?;
        Ok(Self {
            config,
            db,
            witness,
            dir: dir.to_owned(),
            _lock: lock,
        })
    }
    pub fn install_route(
        &mut self,
        handle: &str,
        route: crate::config::Route,
        now: i64,
    ) -> Result<()> {
        if let Some(current) = self.config.routes.get(handle) {
            return require(*current == route, CONFLICT);
        }
        let mut next = self.config.clone();
        next.routes.insert(handle.to_owned(), route);
        next.validate()?;
        let json = serde_json::to_string(&next).map_err(|_| Error(INVALID))?;
        self.change(now, |tx, _, _| {
            tx.execute("UPDATE meta SET config=?1", [json])?;
            Ok(())
        })?;
        self.config = next;
        Ok(())
    }
    pub fn backup(&self, path: &Path) -> Result<()> {
        let _file = OpenOptions::new().create_new(true).write(true).open(path)?;
        self.db
            .backup(rusqlite::MAIN_DB, path, rusqlite::backup::NO_PROGRESS)?;
        Ok(())
    }
    pub(crate) fn change<T>(
        &mut self,
        now: i64,
        f: impl FnOnce(&Transaction, &Config, &Path) -> Result<T>,
    ) -> Result<T> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high: i64 = tx.query_row("SELECT high_time FROM meta", [], |r| r.get(0))?;
        require(
            now > 0 && now >= high.saturating_sub(30_000),
            "TEMPORARILY_UNAVAILABLE",
        )?;
        let before = tx.total_changes();
        let value = f(&tx, &self.config, &self.dir)?;
        if tx.total_changes() > before || high + 30_000 < now {
            let rev:i64=tx.query_row("UPDATE meta SET revision=revision+1,high_time=max(high_time,?1) RETURNING revision",[now],|r|r.get(0))?;
            fault("before-store-commit");
            tx.commit()?;
            fault("after-store-commit");
            self.witness
                .execute("UPDATE witness SET revision=?1", [rev])?;
        } else {
            tx.commit()?;
        }
        Ok(value)
    }
    pub fn put(
        &mut self,
        owner: &str,
        tid: &str,
        p: &Transfer,
        now: i64,
    ) -> Result<(bool, Status)> {
        self.change(now, |tx, c, dir| accept(tx, c, dir, owner, tid, p, now))
    }
    pub fn status(&self, owner: &str, tid: &str, now: i64) -> Result<Status> {
        status(&self.db, &self.config, owner, tid, now)
    }
    pub fn cancel(&mut self, owner: &str, tid: &str, now: i64) -> Result<Status> {
        self.change(now, |tx, c, _| {
            tx.execute(
                "UPDATE spool SET state='cancelled',rf_due=NULL,ip_due=NULL,last_error=NULL
             WHERE owner=?1 AND tid=?2 AND state IN ('pending','blocked')",
                params![owner, tid],
            )?;
            status(tx, c, owner, tid, now)
        })
    }
    pub fn gc(&mut self, now: i64) -> Result<()> {
        self.change(now, |tx, _, _| {
            tx.execute("DELETE FROM spool WHERE expiry<=?1", [now - DEDUP_MS])?;
            tx.execute(
                "UPDATE spool SET data=NULL,ip_due=NULL,rf_due=NULL WHERE expiry<=?1 AND data
             IS NOT NULL",
                [now],
            )?;
            clear_partials(tx, now)?;
            Ok(())
        })
    }
}
pub(crate) fn clear_partials(tx: &Transaction, now: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM partial WHERE touched<=?1 OR created<=?2",
        params![now - 600_000, now - 1_800_000],
    )?;
    Ok(())
}
pub(crate) fn accept(
    tx: &Transaction,
    c: &Config,
    dir: &Path,
    owner: &str,
    tid: &str,
    p: &Transfer,
    now: i64,
) -> Result<(bool, Status)> {
    require(valid_id(tid), INVALID)?;
    let principal = c.principals.get(owner).ok_or(Error("FORBIDDEN"))?;
    let route = c
        .routes
        .get(&p.route_handle)
        .filter(|r| r.owner == owner)
        .ok_or(Error("FORBIDDEN"))?;
    let data = p.bytes()?;
    let peer_ingress = principal.role == "peer";
    let mut paths = p.allowed_paths.clone();
    paths.sort();
    if peer_ingress {
        paths = vec!["ip".to_string()]
    } else {
        require(
            paths.iter().all(|v| route.paths.contains(v)) && route.priorities.contains(&p.priority),
            "POLICY_DENIED",
        )?;
    }
    let paths = paths.join(",");
    let priority = if peer_ingress {
        &route.priorities[0]
    } else {
        &p.priority
    };
    if let Some((old_route, delivery, expires, old_paths, prio, old_bytes)) = tx
        .query_row(
            "SELECT route,delivery,expiry,paths,priority,data FROM spool WHERE owner=?1 AND
             tid=?2",
            params![owner, tid],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?
    {
        require(expires > now, "EXPIRED")?;
        require(
            old_route == p.route_handle
                && delivery == p.delivery_id
                && expires == p.expires_at_ms
                && paths == old_paths
                && prio == *priority
                && old_bytes.as_ref() == Some(&data),
            CONFLICT,
        )?;
        return Ok((false, status(tx, c, owner, tid, now)?));
    }
    require(p.expires_at_ms > now, "EXPIRED")?;
    require(p.expires_at_ms - now <= RETENTION_MS, "RETENTION_LIMIT")?;
    let peer = match &route.target {
        Target::Peer { peer, .. } => Some(peer),
        _ => None,
    };
    let eligible =
        peer.is_some() && paths.contains("meshcore") && data.len() <= BUNDLE_MAX - HEADER;
    let ip = paths.contains("ip");
    require(ip || eligible, "TOO_LARGE")?;
    if let Some(peer) = peer {
        require(
            !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM spool WHERE peer=?1 AND tid=?2)",
                params![peer, tid],
                |r| r.get(0),
            )?,
            CONFLICT,
        )?;
    }
    let (count, bytes, own_count, own_bytes, records): (u32, i64, u32, i64, u32) = tx.query_row(
        "SELECT count(*) FILTER(WHERE expiry>?2),coalesce(sum(length(data))
             FILTER(WHERE expiry>?2),0),count(*) FILTER(WHERE owner=?1 AND
             expiry>?2),coalesce(sum(length(data)) FILTER(WHERE owner=?1 AND
             expiry>?2),0),count(*) FROM spool",
        params![owner, now],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    require(
        count < c.max_records
            && own_count < principal.max_records
            && bytes as u64 + data.len() as u64 <= c.max_bytes
            && own_bytes as u64 + data.len() as u64 <= principal.max_bytes
            && records < 20_000,
        "QUOTA_EXCEEDED",
    )?;
    require(
        fs2::available_space(dir)? > 16_777_216 + data.len() as u64,
        "STORAGE_UNAVAILABLE",
    )?;
    let insert = "INSERT INTO spool(owner,tid,route,delivery,digest,expiry,accepted,
                  paths,priority,data,eligible,peer,ip_due)
                VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)";
    tx.execute(
        insert,
        params![
            owner,
            tid,
            p.route_handle,
            p.delivery_id,
            p.envelope_sha256,
            p.expires_at_ms,
            now,
            paths,
            priority,
            data,
            eligible,
            peer,
            ip.then_some(now)
        ],
    )?;
    if eligible
        && let Target::Peer {
            peer,
            remote_handle,
            ..
        } = &route.target
    {
        let bytes = crate::port::bundle(remote_handle, p)?;
        crate::port::install_outbound(tx, peer, tid, &bytes, priority)?;
    }
    Ok((true, status(tx, c, owner, tid, now)?))
}
fn status(db: &Connection, c: &Config, owner: &str, tid: &str, now: i64) -> Result<Status> {
    require(valid_id(tid), INVALID)?;
    let sql = "SELECT route,delivery,digest,accepted,expiry,state,eligible,last_error,
                coalesce(min(ip_due,rf_due),ip_due,rf_due)
             FROM spool WHERE owner=?1 AND tid=?2";
    db.query_row(sql, params![owner, tid], |r| {
        let expiry: i64 = r.get(4)?;
        let live = expiry > now;
        let state: String = r.get(5)?;
        Ok(Status {
            gateway_id: c.gateway_id.clone(),
            transfer_id: tid.into(),
            route_handle: r.get(0)?,
            delivery_id: r.get(1)?,
            envelope_sha256: r.get(2)?,
            accepted_at_ms: r.get(3)?,
            expires_at_ms: expiry,
            custody_state: if live { "stored" } else { "expired" }.into(),
            forward_state: if !live && matches!(state.as_str(), "pending" | "blocked") {
                "expired".into()
            } else {
                state
            },
            radio_eligible: r.get(6)?,
            last_error: r.get(7)?,
            next_attempt_at_ms: if live { r.get(8)? } else { None },
        })
    })
    .optional()?
    .ok_or(Error("NOT_FOUND"))
}
#[derive(Clone)]
pub struct Job {
    pub owner: String,
    pub tid: String,
    pub put: Transfer,
    pub tries: i64,
}
impl Store {
    pub fn claim(&mut self, peer: Option<&str>, now: i64) -> Result<Option<Job>> {
        self.change(now, |tx, _, _| {
            let (due, tries) = if peer.is_some() {
                ("rf_due", "rf_tries")
            } else {
                ("ip_due", "ip_tries")
            };
            let sql = format!(
                "SELECT owner,tid,route,delivery,digest,expiry,paths,priority,data,{tries} FROM
             spool WHERE state='pending' AND expiry>?1 AND {due}<=?1 AND (?2 IS NULL OR
             peer=?2) ORDER BY {due},accepted,tid LIMIT 1"
            );
            let job = tx
                .query_row(&sql, params![now, peer], |r| {
                    Ok(Job {
                        owner: r.get(0)?,
                        tid: r.get(1)?,
                        put: Transfer {
                            route_handle: r.get(2)?,
                            delivery_id: r.get(3)?,
                            envelope_sha256: r.get(4)?,
                            expires_at_ms: r.get(5)?,
                            allowed_paths: r
                                .get::<_, String>(6)?
                                .split(',')
                                .map(String::from)
                                .collect(),
                            priority: r.get(7)?,
                            envelope_b64url: to_b64(&r.get::<_, Vec<u8>>(8)?),
                        },
                        tries: r.get::<_, i64>(9)? + 1,
                    })
                })
                .optional()?;
            if let Some(j) = &job {
                // Reserve the attempt before crossing the process boundary. A crash spends the lease.
                tx.execute(
                    &format!("UPDATE spool SET {tries}=?3,{due}=?4 WHERE owner=?1 AND tid=?2"),
                    params![j.owner, j.tid, j.tries, now + 30_000],
                )?;
                if j.tries > MAX_ATTEMPTS {
                    stop_lane(tx, j, peer.is_some(), "RETRY_BUDGET_EXHAUSTED")?;
                    return Ok(None);
                }
            }
            Ok(job)
        })
    }
    pub fn failed(
        &mut self,
        j: &Job,
        radio: bool,
        code: &'static str,
        retryable: bool,
        now: i64,
        delay: i64,
    ) -> Result<()> {
        self.change(now, |tx, _, _| {
            let (due, tries) = if radio {
                ("rf_due", "rf_tries")
            } else {
                ("ip_due", "ip_tries")
            };
            if retryable && j.tries < MAX_ATTEMPTS {
                tx.execute(
                    &format!(
                        "UPDATE spool SET {due}=?3,last_error=?4 WHERE owner=?1 AND tid=?2 AND
             state='pending' AND {tries}=?5"
                    ),
                    params![
                        j.owner,
                        j.tid,
                        now + delay.clamp(1000, 300_000),
                        code,
                        j.tries
                    ],
                )?;
            } else {
                stop_lane(
                    tx,
                    j,
                    radio,
                    if retryable {
                        "RETRY_BUDGET_EXHAUSTED"
                    } else {
                        code
                    },
                )?;
            }
            Ok(())
        })
    }
    pub fn record_fact(&mut self, j: &Job, peer: bool, now: i64) -> Result<()> {
        self.change(now, |tx, _, _| fact(tx, &j.owner, &j.tid, peer, now))
    }
    pub fn resume(&mut self, owner: &str, tid: &str, now: i64) -> Result<Status> {
        self.change(now, |tx, c, _| {
            tx.execute(
                "UPDATE spool SET state='pending',ip_due=CASE WHEN instr(paths,'ip')>0 THEN ?3
             END,rf_due=CASE WHEN eligible THEN ?3
             END,rf_tries=0,ip_tries=0,last_error=NULL WHERE owner=?1 AND tid=?2 AND
             expiry>?3 AND state='blocked'",
                params![owner, tid, now],
            )?;
            status(tx, c, owner, tid, now)
        })
    }
}
fn stop_lane(tx: &Transaction, j: &Job, rf: bool, code: &str) -> Result<()> {
    let (due, other, tries) = if rf {
        ("rf_due", "ip_due", "rf_tries")
    } else {
        ("ip_due", "rf_due", "ip_tries")
    };
    tx.execute(
        &format!(
            "UPDATE spool SET {due}=NULL,last_error=?3,state=CASE WHEN {other} IS NULL THEN
             'blocked' ELSE 'pending' END WHERE owner=?1 AND tid=?2 AND state='pending' AND
             {tries}=?4"
        ),
        params![j.owner, j.tid, code, j.tries],
    )?;
    Ok(())
}
pub(crate) fn fact(tx: &Transaction, owner: &str, tid: &str, peer: bool, now: i64) -> Result<()> {
    let (col, state) = if peer {
        ("peer_fact", "peer_stored")
    } else {
        ("relay_fact", "relay_stored")
    };
    tx.execute(
        &format!(
            "UPDATE spool SET {col}=coalesce({col},?3), state=CASE WHEN state IN
             ('pending','blocked') AND expiry>?3 THEN ?4 ELSE state
             END,ip_due=NULL,rf_due=NULL,last_error=NULL WHERE owner=?1 AND tid=?2"
        ),
        params![owner, tid, now, state],
    )?;
    Ok(())
}
