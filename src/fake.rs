//! Local fault harness. Chunks are process-local test values, never RF datagrams.
use crate::{
    config::Target,
    store::{Job, Store, clear_partials, fact},
    *,
};
use rusqlite::{OptionalExtension, params};
use spora_core::{digest, valid_id};
use std::path::Path;

pub use crate::port::{Ack, bundle, unpack};
pub struct Fragment<'a> {
    pub tid: &'a str,
    pub hash: &'a str,
    pub total: usize,
    pub index: usize,
    pub data: &'a [u8],
}
impl Store {
    pub fn receive_fragment(&mut self, peer: &str, f: &Fragment, now: i64) -> Result<Option<Ack>> {
        require(
            valid_id(f.tid) && f.hash.len() == 64 && f.hash.bytes().all(|b| b.is_ascii_hexdigit()),
            INVALID,
        )?;
        require((HEADER + 1..=BUNDLE_MAX).contains(&f.total), "TOO_LARGE")?;
        let count = f.total.div_ceil(CHUNK);
        require(
            f.index < count && f.data.len() == CHUNK.min(f.total - f.index * CHUNK),
            INVALID,
        )?;
        self.change(now, |tx, c, dir| {
            require(
                c.principals.get(peer).is_some_and(|p| p.role == "peer"),
                "FORBIDDEN",
            )?;
            if let Some(ack) = tx
                .query_row(
                    "SELECT hash,accepted,expiry FROM ack WHERE peer=?1 AND tid=?2",
                    params![peer, f.tid],
                    |r| {
                        Ok(Ack {
                            hash: r.get(0)?,
                            accepted: r.get(1)?,
                            expiry: r.get(2)?,
                        })
                    },
                )
                .optional()?
            {
                require(ack.expiry > now, "EXPIRED")?;
                require(ack.hash == f.hash, CONFLICT)?;
                return Ok(Some(ack));
            }
            clear_partials(tx, now)?;
            if let Some((h, n)) = tx
                .query_row(
                    "SELECT hash,total FROM partial WHERE peer=?1 AND tid=?2",
                    params![peer, f.tid],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional()?
            {
                require(h == f.hash && n == f.total as i64, CONFLICT)?;
            } else {
                let (all, own): (u8, u8) = tx.query_row(
                    "SELECT count(*),count(*) FILTER(WHERE peer=?1) FROM partial",
                    [peer],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                require(all < 16 && own < 4, "QUOTA_EXCEEDED")?;
                tx.execute(
                    "INSERT INTO partial VALUES(?1,?2,?3,?4,?5,?5)",
                    params![peer, f.tid, f.hash, f.total as i64, now],
                )?;
            }
            if let Some(old) = tx
                .query_row(
                    "SELECT data FROM fragments WHERE peer=?1 AND tid=?2 AND idx=?3",
                    params![peer, f.tid, f.index as i64],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?
            {
                require(old == f.data, CONFLICT)?;
                return Ok(None);
            }
            tx.execute(
                "INSERT INTO fragments VALUES(?1,?2,?3,?4)",
                params![peer, f.tid, f.index as i64, f.data],
            )?;
            tx.execute(
                "UPDATE partial SET touched=?3 WHERE peer=?1 AND tid=?2",
                params![peer, f.tid, now],
            )?;
            let have: i64 = tx.query_row(
                "SELECT count(*) FROM fragments WHERE peer=?1 AND tid=?2",
                params![peer, f.tid],
                |r| r.get(0),
            )?;
            if have < count as i64 {
                return Ok(None);
            }
            let mut b = Vec::with_capacity(f.total);
            let mut q =
                tx.prepare("SELECT data FROM fragments WHERE peer=?1 AND tid=?2 ORDER BY idx")?;
            for piece in q.query_map(params![peer, f.tid], |r| r.get::<_, Vec<u8>>(0))? {
                b.extend(piece?)
            }
            require(digest(&b) == f.hash, CONFLICT)?;
            let ack = crate::port::accept_bundle(tx, c, dir, peer, f.tid, &b, now)?;
            tx.execute(
                "INSERT INTO ack VALUES(?1,?2,?3,?4,?5)",
                params![peer, f.tid, f.hash, ack.accepted, ack.expiry],
            )?;
            tx.execute(
                "DELETE FROM partial WHERE peer=?1 AND tid=?2",
                params![peer, f.tid],
            )?;
            Ok(Some(ack))
        })
    }
    fn store_ack(&mut self, peer: &str, j: &Job, expected: &str, a: &Ack, now: i64) -> Result<()> {
        self.change(now, |tx, _, _| {
            require(
                a.hash == expected
                    && a.expiry == j.put.expires_at_ms
                    && a.accepted > 0
                    && a.accepted < a.expiry
                    && a.accepted <= now + 30_000,
                INVALID,
            )?;
            let valid: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM spool WHERE owner=?1 AND tid=?2
                 AND peer=?3 AND bundle_hash=?4 AND expiry=?5)",
                params![j.owner, j.tid, peer, a.hash, a.expiry],
                |r| r.get(0),
            )?;
            require(valid, "FORBIDDEN")?;
            let sql = "INSERT OR IGNORE INTO events(owner,tid,hash,accepted,expiry)
                     VALUES(?1,?2,?3,?4,?5)";
            tx.execute(sql, params![j.owner, j.tid, a.hash, a.accepted, a.expiry])?;
            Ok(())
        })
    }
    pub fn consume_events(&mut self, now: i64) -> Result<usize> {
        self.change(now, |tx, _, _| {
            let mut q = tx.prepare(
                "SELECT seq,owner,tid FROM events WHERE seq>(SELECT cursor FROM progress) ORDER
             BY seq LIMIT 100",
            )?;
            let rows = q
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            for (seq, owner, tid) in &rows {
                fact(tx, owner, tid, true, now)?;
                tx.execute("UPDATE progress SET cursor=?1", [seq])?;
            }
            if let Some((seq, _, _)) = rows.last() {
                tx.execute("DELETE FROM events WHERE seq<=?1", [seq])?;
            }
            Ok(rows.len())
        })
    }
}
#[derive(Default)]
pub struct Channel {
    pub reverse: bool,
    pub duplicate: bool,
    pub limit: Option<usize>,
    pub drop_ack: bool,
    pub disconnected: bool,
}
#[derive(serde::Serialize, Default)]
pub struct Step {
    pub frames: usize,
    pub transmissions: usize,
    pub bundle_bytes: usize,
    pub peer_stored: bool,
}
pub fn step(from: &Path, to: &Path, ch: &Channel, now: i64) -> Result<Step> {
    require(from.canonicalize()? != to.canonicalize()?, INVALID)?;
    let other = Store::open(to)?.config.gateway_id.clone();
    let mut a = Store::open(from)?;
    a.consume_events(now)?;
    let source = a.config.gateway_id.clone();
    let Some(j) = a.claim(Some(&other), now)? else {
        return Ok(Step::default());
    };
    let Target::Peer { remote_handle, .. } = &a.config.routes[&j.put.route_handle].target else {
        return Err(Error("NO_ROUTE"));
    };
    let b = bundle(remote_handle, &j.put)?;
    let h = digest(&b);
    drop(a);
    let count = b.len().div_ceil(CHUNK);
    let mut stats = Step {
        frames: count,
        bundle_bytes: b.len(),
        ..Default::default()
    };
    let mut ack = None;
    if !ch.disconnected {
        let mut receiver = Store::open(to)?;
        for n in 0..ch.limit.unwrap_or(count).min(count) {
            let i = if ch.reverse { count - 1 - n } else { n };
            let f = Fragment {
                tid: &j.tid,
                hash: &h,
                total: b.len(),
                index: i,
                data: &b[i * CHUNK..((i + 1) * CHUNK).min(b.len())],
            };
            for _ in 0..if ch.duplicate { 2 } else { 1 } {
                stats.transmissions += 1;
                match receiver.receive_fragment(&source, &f, now) {
                    Ok(reply) => {
                        if reply.is_some() {
                            ack = reply;
                        }
                    }
                    Err(e) => {
                        drop(receiver);
                        let retry = matches!(
                            e.0,
                            "QUOTA_EXCEEDED" | "STORAGE_UNAVAILABLE" | "TEMPORARILY_UNAVAILABLE"
                        );
                        Store::open(from)?.failed(&j, true, e.0, retry, now, 1000)?;
                        return Err(e);
                    }
                }
            }
        }
    }
    let mut a = Store::open(from)?;
    if let Some(ack) = ack.filter(|_| !ch.drop_ack) {
        a.store_ack(&other, &j, &h, &ack, now)?;
        crate::store::fault("after-radio-event");
        a.consume_events(now)?;
        stats.peer_stored = true;
    } else {
        a.failed(&j, true, "LINK_UNAVAILABLE", true, now, 1000)?;
    }
    Ok(stats)
}
