use spora_core::{DEDUP_MS, RETENTION_MS, digest, new_id, to_b64};
use spora_gateway::{config::*, fake::*, store::Store, *};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
const NOW: i64 = 1_800_000_000_000;
fn id(n: u8) -> String {
    hex::encode([n; 16])
}
fn ep() -> Endpoint {
    Endpoint {
        origin: "https://127.0.0.1:7777".into(),
        ca_sha256: digest(b"ca"),
        token_hash: digest(b"token"),
    }
}
fn principal(n: u8, role: &str) -> Principal {
    Principal {
        role: role.into(),
        token_hash: digest(&[n; 32]),
        max_bytes: 67_108_864,
        max_records: 10_000,
    }
}
fn config(a: u8, b: u8) -> Config {
    Config {
        gateway_id: id(a),
        max_bytes: 67_108_864,
        max_records: 10_000,
        principals: BTreeMap::from([
            (id(9), principal(9, "client")),
            (id(b), principal(b, "peer")),
        ]),
        routes: BTreeMap::from([
            (
                id(4),
                Route {
                    owner: id(9),
                    paths: vec!["ip".into(), "meshcore".into()],
                    priorities: vec!["interactive".into()],
                    target: Target::Peer {
                        peer: id(b),
                        remote_handle: id(5),
                        ip: Some(ep()),
                    },
                },
            ),
            (
                id(5),
                Route {
                    owner: id(b),
                    paths: vec!["ip".into()],
                    priorities: vec!["control".into()],
                    target: Target::Relay {
                        service: id(6),
                        queue: id(7),
                        generation: id(8),
                        ip: ep(),
                    },
                },
            ),
        ]),
    }
}
fn put(size: usize) -> Transfer {
    let d = vec![0xab; size];
    Transfer {
        route_handle: id(4),
        delivery_id: new_id(),
        envelope_b64url: to_b64(&d),
        envelope_sha256: digest(&d),
        expires_at_ms: NOW + 80_000,
        allowed_paths: vec!["meshcore".into()],
        priority: "interactive".into(),
    }
}
fn init(root: &Path, name: &str, c: Config) -> PathBuf {
    let p = root.join(name);
    Store::init(&p, &c).unwrap();
    p
}
struct Pair {
    _root: TempDir,
    a: PathBuf,
    b: PathBuf,
}
impl Pair {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let a = init(root.path(), "a", config(1, 2));
        let b = init(root.path(), "b", config(2, 1));
        Self { _root: root, a, b }
    }
}
fn open(p: &Path) -> Store {
    Store::open(p).unwrap()
}
#[test]
fn boundaries_and_namespaces() {
    let pair = Pair::new();
    let mut a = open(&pair.a);
    let small = put(4051);
    let b = bundle(&id(5), &small).unwrap();
    assert_eq!(b.len(), 4096);
    assert_eq!(b.len().div_ceil(CHUNK), 40);
    assert_eq!(unpack(&b).unwrap().envelope_b64url, small.envelope_b64url);
    let mut trailing = b.clone();
    trailing.push(0);
    assert!(unpack(&trailing).is_err());
    assert_eq!(
        a.put(&id(9), &id(10), &put(4052), NOW).unwrap_err().0,
        "TOO_LARGE"
    );
    let mut ip = put(65536);
    ip.allowed_paths.push("ip".into());
    assert!(!a.put(&id(9), &id(10), &ip, NOW).unwrap().1.radio_eligible);
    assert_eq!(
        a.put(&id(9), &id(11), &put(65537), NOW).unwrap_err().0,
        "TOO_LARGE"
    );
    assert_eq!(
        a.put(&id(2), &id(11), &small, NOW).unwrap_err().0,
        "FORBIDDEN"
    );
    assert_eq!(a.cancel(&id(2), &id(10), NOW).unwrap_err().0, "NOT_FOUND");
    let mut priority = small.clone();
    priority.priority = "control".into();
    assert_eq!(
        a.put(&id(9), &id(12), &priority, NOW).unwrap_err().0,
        "POLICY_DENIED"
    );
    let mut invalid = config(1, 2);
    invalid.routes.get_mut(&id(4)).unwrap().owner = id(2);
    assert_eq!(invalid.validate().unwrap_err().0, "POLICY_DENIED");
}
#[test]
fn custody_survives_disconnect_partial_restart_and_lost_ack() {
    let pair = Pair::new();
    let tid = id(13);
    let p = put(1954);
    assert!(open(&pair.a).put(&id(9), &tid, &p, NOW).unwrap().0);
    for (i, ch) in [
        Channel {
            disconnected: true,
            ..Default::default()
        },
        Channel {
            reverse: true,
            duplicate: true,
            limit: Some(5),
            ..Default::default()
        },
        Channel {
            drop_ack: true,
            ..Default::default()
        },
    ]
    .iter()
    .enumerate()
    {
        let s = step(&pair.a, &pair.b, ch, NOW + i as i64 * 2000).unwrap();
        assert!(!s.peer_stored);
        assert_eq!(s.frames, 20);
        assert_eq!(
            open(&pair.a)
                .status(&id(9), &tid, NOW)
                .unwrap()
                .forward_state,
            "pending"
        );
        if i < 2 {
            assert_eq!(
                open(&pair.b).status(&id(1), &tid, NOW).unwrap_err().0,
                "NOT_FOUND"
            );
        }
    }
    let before = open(&pair.b).status(&id(1), &tid, NOW + 5000).unwrap();
    assert_eq!(before.forward_state, "pending");
    assert!(
        step(&pair.a, &pair.b, &Channel::default(), NOW + 6000)
            .unwrap()
            .peer_stored
    );
    assert_eq!(
        open(&pair.b).status(&id(1), &tid, NOW + 7000).unwrap(),
        before
    );
    let mut a = open(&pair.a);
    let stored = a.status(&id(9), &tid, NOW + 7000).unwrap();
    assert_eq!(stored.forward_state, "peer_stored");
    assert_eq!(stored.custody_state, "stored");
    assert!(!a.put(&id(9), &tid, &p, NOW + 7500).unwrap().0);
}
#[test]
fn concurrent_ip_and_channel_converge_even_with_different_peer_metadata() {
    let pair = Pair::new();
    let bpath = pair.b.clone();
    let tid = id(14);
    let p = put(230);
    let b = bundle(&id(5), &p).unwrap();
    let h = digest(&b);
    let mut ip = unpack(&b).unwrap();
    ip.priority = "control".into();
    let ip0 = ip.clone();
    let tid0 = tid.clone();
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = ready.clone();
    let thread = std::thread::spawn(move || {
        other.wait();
        open(&bpath).put(&id(1), &tid0, &ip0, NOW).unwrap().1
    });
    ready.wait();
    let mut ack = None;
    for (i, data) in b.chunks(CHUNK).enumerate() {
        ack = open(&pair.b)
            .receive_fragment(
                &id(1),
                &Fragment {
                    tid: &tid,
                    hash: &h,
                    total: b.len(),
                    index: i,
                    data,
                },
                NOW,
            )
            .unwrap();
    }
    let s = thread.join().unwrap();
    assert_eq!(ack.unwrap().accepted, s.accepted_at_ms);
    let mut store = open(&pair.b);
    assert_eq!(
        store.claim(None, NOW).unwrap().unwrap().put.delivery_id,
        p.delivery_id
    );
    assert!(store.claim(None, NOW + 1).unwrap().is_none());
    ip.expires_at_ms += 1;
    assert_eq!(
        store.put(&id(1), &tid, &ip, NOW + 2).unwrap_err().0,
        CONFLICT
    );
}
#[test]
fn admission_expiry_tombstones_and_cancel_preserve_custody() {
    let root = TempDir::new().unwrap();
    let mut c = config(1, 2);
    c.principals.get_mut(&id(9)).unwrap().max_records = 1;
    let path = init(root.path(), "gw", c);
    let mut a = open(&path);
    let p = put(20);
    let tid = id(15);
    let mut old = p.clone();
    old.expires_at_ms = NOW;
    assert_eq!(a.put(&id(9), &tid, &old, NOW).unwrap_err().0, "EXPIRED");
    old.expires_at_ms = NOW + RETENTION_MS + 1;
    assert_eq!(
        a.put(&id(9), &tid, &old, NOW).unwrap_err().0,
        "RETENTION_LIMIT"
    );
    assert!(a.put(&id(9), &tid, &p, NOW).unwrap().0);
    a.cancel(&id(9), &tid, NOW).unwrap();
    assert_eq!(
        a.put(&id(9), &new_id(), &p, NOW + 1).unwrap_err().0,
        "QUOTA_EXCEEDED"
    );
    assert!(a.claim(Some(&id(2)), NOW + 1).unwrap().is_none());
    assert_eq!(
        a.put(&id(9), &tid, &p, NOW + 1).unwrap().1.custody_state,
        "stored"
    );
    assert_eq!(
        a.put(&id(9), &id(99), &p, NOW - 30_001).unwrap_err().0,
        "TEMPORARILY_UNAVAILABLE"
    );
    a.gc(p.expires_at_ms).unwrap();
    assert_eq!(
        a.status(&id(9), &tid, p.expires_at_ms)
            .unwrap()
            .custody_state,
        "expired"
    );
    assert_eq!(
        a.put(&id(9), &tid, &p, p.expires_at_ms).unwrap_err().0,
        "EXPIRED"
    );
    a.gc(p.expires_at_ms + DEDUP_MS).unwrap();
    assert_eq!(
        a.status(&id(9), &tid, p.expires_at_ms + DEDUP_MS)
            .unwrap_err()
            .0,
        "NOT_FOUND"
    );
}
#[test]
fn partial_capacity_content_and_idle_collection() {
    let pair = Pair::new();
    let mut b = open(&pair.b);
    let p = put(230);
    let bytes = bundle(&id(5), &p).unwrap();
    let h = digest(&bytes);
    for n in 20..25 {
        let tid = id(n);
        let f = Fragment {
            tid: &tid,
            hash: &h,
            total: bytes.len(),
            index: 0,
            data: &bytes[..CHUNK],
        };
        let r = b.receive_fragment(&id(1), &f, NOW);
        if n == 24 {
            assert_eq!(r.unwrap_err().0, "QUOTA_EXCEEDED");
            assert!(
                b.receive_fragment(&id(1), &f, NOW + 600_000)
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(r.unwrap().is_none());
            assert!(b.receive_fragment(&id(1), &f, NOW + 1).unwrap().is_none());
            let bad = Fragment {
                data: &[0; CHUNK],
                ..f
            };
            assert_eq!(
                b.receive_fragment(&id(1), &bad, NOW + 1).unwrap_err().0,
                CONFLICT
            );
        }
    }
}
#[test]
fn retry_budget_and_late_fact_after_cancel() {
    let pair = Pair::new();
    let mut a = open(&pair.a);
    let mut p = put(9);
    p.expires_at_ms = NOW + RETENTION_MS;
    p.allowed_paths.push("ip".into());
    let tid = id(16);
    a.put(&id(9), &tid, &p, NOW).unwrap();
    let ip = a.claim(None, NOW).unwrap().unwrap();
    for n in 0..MAX_ATTEMPTS {
        let t = NOW + n * 2000;
        let j = a.claim(Some(&id(2)), t).unwrap().unwrap();
        a.failed(&j, true, "LINK_UNAVAILABLE", true, t, 1000)
            .unwrap();
    }
    assert!(a.claim(Some(&id(2)), NOW + 32_000).unwrap().is_none());
    a.cancel(&id(9), &tid, NOW + 32_000).unwrap();
    a.record_fact(&ip, true, NOW + 32_001).unwrap();
    assert_eq!(
        a.status(&id(9), &tid, NOW + 32_002).unwrap().forward_state,
        "cancelled"
    );
}
#[test]
fn old_snapshot_refused_missing_store_never_recreated() {
    let p = Pair::new();
    let snap = p._root.path().join("snapshot");
    open(&p.a).backup(&snap).unwrap();
    open(&p.a).put(&id(9), &id(8), &put(12), NOW).unwrap();
    std::fs::copy(&snap, p.a.join("gateway.db")).unwrap();
    assert!(matches!(Store::open(&p.a), Err(Error("BROKEN_RESTORE"))));
    let missing = p._root.path().join("absent");
    assert!(Store::open(&missing).is_err());
    assert!(!missing.exists());
}

#[test]
fn route_handles_are_append_only() {
    let pair = Pair::new();
    let mut a = open(&pair.a);
    let r = a.config.routes[&id(4)].clone();
    a.install_route(&id(44), r.clone(), NOW).unwrap();
    a.install_route(&id(44), r.clone(), NOW + 1).unwrap();
    let mut changed = r;
    changed.priorities.push("control".into());
    assert_eq!(
        a.install_route(&id(44), changed, NOW + 2).unwrap_err().0,
        CONFLICT
    );
    drop(a);
    assert!(open(&pair.a).config.routes.contains_key(&id(44)));
}

#[test]
fn commit_crashes_keep_the_original_custody_promise() {
    if let Some(path) = std::env::var_os("GATEWAY_TEST_CHILD_DIR") {
        let mut transfer = put(18);
        transfer.delivery_id = id(80);
        open(Path::new(&path))
            .put(&id(9), &id(81), &transfer, NOW)
            .unwrap();
        panic!("fault point did not terminate the child");
    }
    for (point, stored) in [("before-store-commit", false), ("after-store-commit", true)] {
        let pair = Pair::new();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commit_crashes_keep_the_original_custody_promise",
            ])
            .env("GATEWAY_TEST_CHILD_DIR", &pair.a)
            .env("SPORA_GATEWAY_LAB_CRASH", point)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(86));
        let mut a = open(&pair.a);
        assert_eq!(a.status(&id(9), &id(81), NOW + 100).is_ok(), stored);
        let mut transfer = put(18);
        transfer.delivery_id = id(80);
        let (created, status) = a.put(&id(9), &id(81), &transfer, NOW + 100).unwrap();
        assert_ne!(created, stored);
        assert_eq!(status.accepted_at_ms, if stored { NOW } else { NOW + 100 });
    }
}

#[test]
fn normalized_bundle_matches_the_contract_vector() {
    // docs/contracts/v0.1/fixtures.json, radio.bundle (Spora 79261ae).
    let wire=hex::decode("013030303030303030303030303030303020202020202020202020202020202020000001a1d4fe5480000000080102030405060708").unwrap();
    let decoded = unpack(&wire).unwrap();
    assert_eq!(decoded.route_handle, id(0x30));
    assert_eq!(decoded.delivery_id, id(0x20));
    assert_eq!(decoded.expires_at_ms, 1794574800000);
    assert_eq!(decoded.envelope_b64url, to_b64(&[1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(bundle(&decoded.route_handle, &decoded).unwrap(), wire);
    assert_eq!(
        digest(&wire),
        "2307dd1b5ecd55fd5536539cf8441fb088e5f28ce1a230e7f61075b0181cc23e"
    );
}
#[test]
fn event_survives_exit_before_gateway_applies_it() {
    let pair = Pair::new();
    let now = spora_core::now_ms();
    let mut p = put(200);
    p.expires_at_ms = now + 90_000;
    let tid = id(79);
    open(&pair.a).put(&id(9), &tid, &p, now).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_spora-gateway"))
        .arg("fake-step")
        .arg("--from")
        .arg(&pair.a)
        .arg("--to")
        .arg(&pair.b)
        .env("SPORA_GATEWAY_LAB_CRASH", "after-radio-event")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(86));
    let mut a = open(&pair.a);
    assert_eq!(
        a.status(&id(9), &tid, now).unwrap().forward_state,
        "pending"
    );
    assert_eq!(a.consume_events(spora_core::now_ms()).unwrap(), 1);
    assert_eq!(a.consume_events(spora_core::now_ms()).unwrap(), 0);
    assert_eq!(
        a.status(&id(9), &tid, now).unwrap().forward_state,
        "peer_stored"
    );
}
