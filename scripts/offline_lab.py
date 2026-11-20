"""Two SEC-01 clients, two gateways and two local TLS Relays. Synthetic traffic only."""

import argparse
import base64
from contextlib import ExitStack
import hashlib
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


def uid():
    return uuid.uuid4().hex


def token():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def token_hash(value):
    return sha(base64.urlsafe_b64decode(value + "="))


def command(*args, env=None, expect=0):
    result = subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, env=env, timeout=75
    )
    if result.returncode != expect:
        raise RuntimeError(
            f"{Path(str(args[0])).name} {args[1]} exit {result.returncode}: {result.stderr}"
        )
    return result.stdout


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def origin(p):
    return f"https://127.0.0.1:{p}"


def request(p, tls, method, path, payload=None, bearer=None):
    conn = HTTPSConnection("127.0.0.1", p, context=tls, timeout=5)
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    try:
        conn.request(
            method,
            path,
            body=None if payload is None else json.dumps(payload),
            headers=headers,
        )
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, json.loads(data) if data else None
    finally:
        conn.close()


class Service:
    def __init__(self, stack, p, args, tls):
        self.p, self.args, self.tls, self.proc = p, args, tls, None
        stack.callback(self.stop)
        self.start()

    def start(self):
        self.proc = subprocess.Popen(
            [str(a) for a in self.args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        last = None
        for _ in range(150):
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.args[0]} exited during startup")
            try:
                last = request(self.p, self.tls, "GET", "/v1/capabilities")[0]
                if last == 200:
                    return
            except OSError as err:
                last = err
            time.sleep(0.04)
        raise TimeoutError(f"service startup: {last}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)


class LocalClientPort:
    """Test-only bridge for the existing SEC-01 CLI. Direct message PUTs are never proxied.
    Queue setup and local receive use the adjacent Relay. A write offers the immutable
    envelope to the sender Gateway and reports C-03 unavailable to the SEC-01 IP worker.
    """

    def __init__(self, stack, relay, tls):
        self.relay, self.tls, self.offers, self.binding = relay, tls, [], None
        port_state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle_api(self):
                n = int(self.headers.get("content-length", 0))
                assert 0 <= n <= 131072
                payload = json.loads(self.rfile.read(n)) if n else None
                bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
                path = self.path.split("/")
                if (
                    self.command == "PUT"
                    and len(path) == 6
                    and path[1:3] == ["v1", "queues"]
                    and path[4] == "messages"
                ):
                    binding = port_state.binding
                    assert (
                        binding
                        and path[3] == binding["queue"]
                        and bearer == binding["write"]
                    )
                    assert payload["generation"] == binding["generation"]
                    delivery = path[5]
                    tid = uuid.uuid5(
                        uuid.NAMESPACE_OID, binding["handle"] + delivery
                    ).hex
                    offer = {
                        k: payload[k]
                        for k in ("envelope_b64url", "envelope_sha256", "expires_at_ms")
                    }
                    offer.update(
                        route_handle=binding["handle"],
                        delivery_id=delivery,
                        allowed_paths=["meshcore"],
                        priority="interactive",
                    )
                    code, status = request(
                        binding["gw"],
                        port_state.tls,
                        "PUT",
                        "/v1/transfers/" + tid,
                        offer,
                        binding["token"],
                    )
                    assert code in (200, 201) and status["custody_state"] == "stored"
                    port_state.offers.append((tid, offer))
                    code, result = (
                        503,
                        {
                            "code": "TEMPORARILY_UNAVAILABLE",
                            "request_id": uid(),
                            "retryable": True,
                            "retry_after_ms": 1000,
                        },
                    )
                else:
                    # SEC-01 provisioning, capabilities, local fetch and consumption only.
                    allowed = (
                        (
                            self.command == "GET"
                            and (
                                self.path == "/v1/capabilities"
                                or self.path.startswith("/v1/queues/")
                            )
                        )
                        or (self.command == "POST" and self.path == "/v1/queues")
                        or (
                            self.command == "PUT" and self.path.endswith("/consumption")
                        )
                    )
                    assert allowed
                    code, result = request(
                        port_state.relay,
                        port_state.tls,
                        self.command,
                        self.path,
                        payload,
                        bearer,
                    )
                data = b"" if result is None else json.dumps(result).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Spora-Test-Only", "SPORA_SYNTHETIC_ONLY_V1")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_PUT = do_POST = do_GET = handle_api

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(server.server_close)
        stack.callback(server.shutdown)


def certificates(root, openssl):
    ca, cak, cert, key = [
        root / n for n in ("ca.pem", "ca.key", "server.pem", "server.key")
    ]
    command(
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=Spora-GW-lab-CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        cak,
        "-out",
        ca,
    )
    csr = root / "server.csr"
    command(
        openssl,
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        key,
        "-out",
        csr,
    )
    ext = root / "server.ext"
    ext.write_text(
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n"
    )
    command(
        openssl,
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        ca,
        "-CAkey",
        cak,
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        ext,
        "-out",
        cert,
    )
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ca, cert, key, ctx


def lab(args, root, stack):
    ca, cert, key, tls = certificates(root, args.openssl)
    gateway, client, relay = args.gateway, args.client, args.relay
    secrets_dir = root / "secrets"
    secrets_dir.mkdir()
    cahash = sha(ca.read_bytes())
    (secrets_dir / (cahash + ".pem")).write_bytes(ca.read_bytes())

    def secret_file(value):
        h = token_hash(value)
        (secrets_dir / (h + ".token")).write_text(value, encoding="ascii")
        return h

    def sec(n, *cmd):
        return json.loads(
            command(
                client,
                "--profile",
                root / ("client" + str(n)),
                "--allow-test-key",
                *cmd,
            )
        )

    sides = []
    for n in range(2):
        r = root / ("relay" + str(n))
        command(relay, "init", "--data-dir", r, "--test-only")
        rc = json.loads((r / "relay.json").read_text())
        provision = root / ("provision" + str(n))
        provision.write_text(rc["provisioning_token"])
        rp = port()
        rs = Service(
            stack,
            rp,
            [
                relay,
                "serve",
                "--data-dir",
                r,
                "--listen",
                f"127.0.0.1:{rp}",
                "--admin-listen",
                f"127.0.0.1:{port()}",
                "--test-only",
                "--tls-cert",
                cert,
                "--tls-key",
                key,
            ],
            tls,
        )
        adapter = LocalClientPort(stack, rp, tls)
        identity = sec(n, "init")
        sec(
            n,
            "queue",
            "--endpoint",
            adapter.endpoint,
            "--provisioning-token-file",
            provision,
        )
        sides.append(
            dict(
                id=uid(),
                client_id=uid(),
                identity=identity,
                gwport=port(),
                relay=rs,
                port=adapter,
                owner_token=token(),
                peer_token=token(),
                outbound=uid(),
                inbound=uid(),
                dir=root / ("gw" + str(n)),
            )
        )
    conversation = uid()
    for i, side in enumerate(sides):
        other = sides[1 - i]
        inv = root / f"offer{i}.json"
        sec(
            i,
            "invite",
            "--request",
            uid(),
            "--for-fingerprint",
            other["identity"]["fingerprint"],
            "--output",
            inv,
        )
        sec(
            1 - i,
            "import",
            "--invitation",
            inv,
            "--expected-fingerprint",
            side["identity"]["fingerprint"],
            "--conversation",
            conversation,
        )
        side["route"] = json.loads(inv.read_text())["body"]["routes"][0]["route"]
    for i, s in enumerate(sides):
        o = sides[1 - i]
        route = s["route"]

        def principal(role, t):
            return dict(
                role=role,
                token_hash=token_hash(t),
                max_bytes=67108864,
                max_records=10000,
            )

        endpoint = dict(
            origin=origin(s["relay"].p),
            ca_sha256=cahash,
            token_hash=secret_file(route["write_token"]),
        )
        routes = {
            s["outbound"]: dict(
                owner=s["client_id"],
                paths=["meshcore"],
                priorities=["interactive"],
                target=dict(
                    kind="peer", peer=o["id"], remote_handle=o["inbound"], ip=None
                ),
            ),
            s["inbound"]: dict(
                owner=o["id"],
                paths=["ip"],
                priorities=["interactive"],
                target=dict(
                    kind="relay",
                    service=route["service_id"],
                    queue=route["queue_id"],
                    generation=route["generation"],
                    ip=endpoint,
                ),
            ),
        }
        cfg = dict(
            gateway_id=s["id"],
            max_bytes=67108864,
            max_records=10000,
            principals={
                s["client_id"]: principal("client", s["owner_token"]),
                o["id"]: principal("peer", s["peer_token"]),
            },
            routes=routes,
        )
        cfgfile = root / f"gateway{i}.json"
        cfgfile.write_text(json.dumps(cfg))
        command(gateway, "init", "--dir", s["dir"], "--config", cfgfile)
        s["gw"] = Service(
            stack,
            s["gwport"],
            [
                gateway,
                "serve",
                "--manual-workers",
                "--dir",
                s["dir"],
                "--secrets",
                secrets_dir,
                "--listen",
                f"127.0.0.1:{s['gwport']}",
                "--cert",
                cert,
                "--key",
                key,
            ],
            tls,
        )
        o["port"].binding = dict(
            queue=o["route"]["queue_id"],
            write=o["route"]["write_token"],
            generation=o["route"]["generation"],
            handle=s["outbound"],
            gw=s["gwport"],
            token=s["owner_token"],
        )

    def state(s, tid, bearer):
        code, v = request(
            s["gwport"], tls, "GET", "/v1/transfers/" + tid, bearer=bearer
        )
        assert code == 200
        return v

    def fake(s, o, *flags):
        return json.loads(
            command(gateway, "fake-step", "--from", s["dir"], "--to", o["dir"], *flags)
        )

    def forward(s, *extra, **kwargs):
        return command(
            gateway,
            "forward",
            "--dir",
            s["dir"],
            "--secrets",
            secrets_dir,
            *extra,
            **kwargs,
        )

    def offer(i):
        dst = sides[1 - i]
        assert sec(i, "dispatch") == 0
        assert len(dst["port"].offers) == 1
        return dst["port"].offers[0]

    a, b = sides
    sec(
        0,
        "send",
        "--request",
        uid(),
        "--peers",
        b["identity"]["device"]["id"],
        "--text",
        "GATEWAY-01 artificial offline message",
    )
    b["relay"].stop()
    tid, p = offer(0)
    assert forward(a).strip() == "false"
    assert (
        request(
            a["gwport"], tls, "GET", "/v1/transfers/" + tid, bearer=a["peer_token"]
        )[0]
        == 404
    )
    assert request(a["gwport"], tls, "GET", "/v1/transfers/" + tid)[0] == 401
    assert (
        fake(a, b, "--reverse", "--duplicate", "--limit", "3")["peer_stored"] is False
    )
    a["gw"].stop()
    b["gw"].stop()
    a["gw"].start()
    b["gw"].start()
    time.sleep(1.1)
    lost = fake(a, b, "--reverse", "--drop-ack")
    assert (
        not lost["peer_stored"]
        and state(b, tid, b["peer_token"])["forward_state"] == "pending"
    )
    assert state(a, tid, a["owner_token"])["forward_state"] == "pending"
    assert (
        forward(b).strip() == "true"
        and state(b, tid, b["peer_token"])["forward_state"] == "pending"
    )
    time.sleep(1.1)
    sent = fake(a, b, "--duplicate")
    assert (
        sent["peer_stored"]
        and state(a, tid, a["owner_token"])["forward_state"] == "peer_stored"
    )
    assert sec(0, "status")["processed_receipts"] == 0
    b["relay"].start()
    # Kill immediately after the actual Relay PUT and before the gateway records its result.
    forward(
        b,
        env={**os.environ, "SPORA_GATEWAY_LAB_CRASH": "after-upstream-put"},
        expect=86,
    )
    assert state(b, tid, b["peer_token"])["forward_state"] == "pending"
    assert sec(1, "fetch") == 1 and sec(1, "consume") == 1 and sec(1, "apply") == 1
    assert sec(1, "receipts") == 1
    back_id, _ = offer(1)
    assert back_id != tid
    assert fake(b, a, "--disconnected")["peer_stored"] is False
    assert sec(0, "fetch") == 0 and sec(0, "status")["processed_receipts"] == 0
    time.sleep(1.1)
    receipt = fake(b, a, "--reverse")
    assert receipt["peer_stored"] and forward(a).strip() == "true"
    assert sec(0, "fetch") == 1 and sec(0, "consume") == 1 and sec(0, "apply") == 1
    assert sec(0, "status")["processed_receipts"] == 1
    # The same delivery is retried after lease expiry. Relay already consumed the only copy.
    due = state(b, tid, b["peer_token"])["next_attempt_at_ms"]
    time.sleep(max(0, (due - time.time() * 1000) / 1000) + 0.08)
    assert (
        forward(b).strip() == "true"
        and state(b, tid, b["peer_token"])["forward_state"] == "relay_stored"
    )
    assert sec(1, "fetch") == 0 and sec(1, "status")["message_count"] == 1
    assert state(a, tid, a["owner_token"])["custody_state"] == "stored"
    # A separate path-policy scenario uses only synthetic opaque bytes over C-05.
    # Install a second route without changing the radio-only message route.
    dual = uid()
    peer_endpoint = dict(
        origin=origin(b["gwport"]),
        ca_sha256=cahash,
        token_hash=secret_file(b["peer_token"]),
    )
    dual_config = dict(
        owner=a["client_id"],
        paths=["ip", "meshcore"],
        priorities=["interactive"],
        target=dict(
            kind="peer", peer=b["id"], remote_handle=b["inbound"], ip=peer_endpoint
        ),
    )
    routefile = root / "dual.json"
    routefile.write_text(json.dumps(dual_config))
    command(
        gateway,
        "install-route",
        "--dir",
        a["dir"],
        "--handle",
        dual,
        "--file",
        routefile,
    )

    def raw_offer(size, paths):
        raw = bytes([0x55]) * size
        return dict(
            route_handle=dual,
            delivery_id=uid(),
            envelope_sha256=sha(raw),
            envelope_b64url=base64.urlsafe_b64encode(raw).decode().rstrip("="),
            expires_at_ms=int(time.time() * 1000) + 180000,
            allowed_paths=paths,
            priority="interactive",
        )

    def submit_raw(transfer, body):
        return request(
            a["gwport"], tls, "PUT", "/v1/transfers/" + transfer, body, a["owner_token"]
        )

    t, both = uid(), raw_offer(230, ["ip", "meshcore"])
    assert submit_raw(t, both)[0] == 201
    b["gw"].stop()
    assert forward(a).strip() == "true"
    assert not fake(a, b, "--limit", "1")["peer_stored"]
    b["gw"].start()
    time.sleep(1.1)
    assert forward(a).strip() == "true"
    waiting = state(a, t, a["owner_token"])
    assert (
        waiting["forward_state"] == "pending"
        and waiting["last_error"] == "LINK_UNAVAILABLE"
    )
    assert fake(a, b, "--reverse")["peer_stored"]
    canonical = state(b, t, b["peer_token"])
    duplicate = dict(
        both, route_handle=b["inbound"], allowed_paths=["ip"], priority="control"
    )
    assert request(
        b["gwport"], tls, "PUT", "/v1/transfers/" + t, duplicate, b["peer_token"]
    ) == (200, canonical)
    assert submit_raw(uid(), raw_offer(4052, ["meshcore"]))[0] == 413
    ip_only, large = uid(), raw_offer(4052, ["ip", "meshcore"])
    code, large_status = submit_raw(ip_only, large)
    assert code == 201 and not large_status["radio_eligible"]
    assert forward(a).strip() == "true" and not fake(a, b)["peer_stored"]
    barrier = state(a, ip_only, a["owner_token"])
    assert barrier["forward_state"] == "pending" and barrier[
        "next_attempt_at_ms"
    ] > int(time.time() * 1000)
    time.sleep(
        max(0, (barrier["next_attempt_at_ms"] - time.time() * 1000) / 1000) + 0.1
    )
    assert forward(a).strip() == "true"
    assert state(a, ip_only, a["owner_token"])["forward_state"] == "peer_stored"
    assert state(b, ip_only, b["peer_token"])["delivery_id"] == large["delivery_id"]
    return {
        "channel": "in-process synthetic chunks; no inter-gateway IP route",
        "gateway_count": 2,
        "local_tls_relays": 2,
        "sec01_client_profiles": 2,
        "test_messages_applied": 1,
        "authenticated_processing_receipts": 1,
        "messages_after_retry": 1,
        "data": {
            "envelope_bytes": sent["bundle_bytes"] - 45,
            "bundle_bytes": sent["bundle_bytes"],
            "fragments": sent["frames"],
        },
        "receipt": {
            "envelope_bytes": receipt["bundle_bytes"] - 45,
            "bundle_bytes": receipt["bundle_bytes"],
            "fragments": receipt["frames"],
        },
        "faults": [
            "reordered and duplicate chunks",
            "partial assembly and both gateway processes restarted",
            "lost peer stored acknowledgement",
            "destination relay offline",
            "gateway exited after real relay PUT",
            "return path down",
            "retry after receiver consumed relay copy",
        ],
        "extra_path_policy_checks": [
            "C-05 TLS peer address binding",
            "radio and IP normalize to one peer transfer",
            "IP service recovery hold of 30 seconds",
            "4052-byte envelope goes only over permitted IP",
        ],
        "rf_measurements": False,
        "hardware_acceptance": "pending",
    }


def main():
    p = argparse.ArgumentParser()
    for key in ("gateway", "client", "relay"):
        p.add_argument(
            "--" + key, type=lambda path: Path(path).resolve(), required=True
        )
    p.add_argument("--openssl", default="openssl")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    with (
        tempfile.TemporaryDirectory(prefix="spora-gateway-") as tmp,
        ExitStack() as stack,
    ):
        result = lab(args, Path(tmp), stack)
    report = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
