CREATE TABLE meta(
    id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, epoch TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0, high_time INTEGER NOT NULL DEFAULT 0
);

-- The spool row is also the forward job. Each permitted lane reserves its own attempt.
CREATE TABLE spool(
    owner TEXT NOT NULL, tid TEXT NOT NULL, route TEXT NOT NULL, delivery TEXT NOT NULL,
    digest TEXT NOT NULL, expiry INTEGER NOT NULL, accepted INTEGER NOT NULL,
    paths TEXT NOT NULL, priority TEXT NOT NULL, data BLOB, eligible INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', last_error TEXT,
    ip_due INTEGER, ip_tries INTEGER NOT NULL DEFAULT 0,
    rf_due INTEGER, rf_tries INTEGER NOT NULL DEFAULT 0,
    peer TEXT, bundle_hash TEXT, peer_fact INTEGER, relay_fact INTEGER,
    PRIMARY KEY(owner,tid), UNIQUE(peer,tid)
);
CREATE INDEX due_ip ON spool(ip_due);
CREATE INDEX due_rf ON spool(peer,rf_due);
CREATE INDEX deadlines ON spool(expiry);
CREATE TABLE partial(
    peer TEXT NOT NULL, tid TEXT NOT NULL, hash TEXT NOT NULL, total INTEGER NOT NULL,
    created INTEGER NOT NULL, touched INTEGER NOT NULL, PRIMARY KEY(peer,tid)
);
CREATE TABLE fragments(
    peer TEXT NOT NULL, tid TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL,
    PRIMARY KEY(peer,tid,idx), FOREIGN KEY(peer,tid) REFERENCES partial ON DELETE CASCADE
);
CREATE TABLE ack(
    peer TEXT NOT NULL, tid TEXT NOT NULL, hash TEXT NOT NULL, accepted INTEGER NOT NULL,
    expiry INTEGER NOT NULL, PRIMARY KEY(peer,tid),
    FOREIGN KEY(peer,tid) REFERENCES spool(owner,tid) ON DELETE CASCADE
);
CREATE TABLE events(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, tid TEXT NOT NULL,
    hash TEXT NOT NULL, accepted INTEGER NOT NULL, expiry INTEGER NOT NULL,
    UNIQUE(owner,tid), FOREIGN KEY(owner,tid) REFERENCES spool ON DELETE CASCADE
);
CREATE TABLE progress(id INTEGER PRIMARY KEY CHECK(id=1), cursor INTEGER NOT NULL);
INSERT INTO progress VALUES(1,0);
CREATE TABLE ip_health(peer TEXT PRIMARY KEY, since INTEGER);
PRAGMA user_version=1;
