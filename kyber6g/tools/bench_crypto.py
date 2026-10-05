"""Cost of every cryptographic operation the link uses, measured on THIS machine.

    python -m kyber6g.tools.bench_crypto [-n 300] [-o crypto_<host>.json] [--ref-ssh kyber-pi]

Runs on the Raspberry Pi (the UAV node) and on the ground station; needs only the link's own libraries (liboqs,
cryptography). Nothing is simulated or scaled: every figure is the wall time of the real call, taken with
time.perf_counter_ns() after a warm-up, and EVERY sample is written to the output file (the plots are drawn from
those samples, not from numbers typed into a script).

What is measured
  primitives     ML-KEM-1024 keygen / encapsulate / decapsulate, X25519 keygen / exchange, ML-DSA-87 keygen / sign /
                 verify, SHA-256 of a transcript, the HKDF key schedule, HMAC (Finished), one epoch-key rotation
  variants       algorithms the link does NOT use, for the design comparison in simulation/: ML-KEM-512 / -768,
                 ML-DSA-44 / -65, Ed25519
  aead           AES-256-GCM and ChaCha20-Poly1305, seal and open, payloads from 64 B to 64 KiB (33 B of AAD, as in a
                 video record)
  record         the record layer itself (Session.seal / Session.open: header, lock, replay window, AEAD), 1100 B
  handshake      the full 1.5-RTT handshake, the 1-RTT Cached RapidRekey and the PQ ratchet, both roles run in this
                 process, each step timed on its own (no network: the link measurement adds that, see bench_link)
  at_rest        sealing one 4 MiB recording segment and one 200 kB photo (.k6grec / .k6gimg), and opening them
  wire           sizes in bytes of every handshake message and the per-record overhead (computed, not timed)

Clock: a duration is only as good as the clock that measured it. The clock of the WSL virtual machine on the
project's laptop was measured to run 8-11 % slow, so durations taken there come out too SHORT by that much. With
--ref-ssh HOST the rate of this machine's monotonic clock is measured against HOST's clock (before, during and
after the run) and stored as `clock.local_per_reference_second`; the samples themselves stay raw. A reader of the
file divides by that rate. On a machine with a sound clock (the Pi) no reference is needed.
"""
import argparse
import json
import os
import platform
import shlex
import statistics
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import cryptography
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..crypto import handshake as hs
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.record import HDR_LEN, Session
from ..crypto.suites import get_suite
from ..transport import framing, jsonmsg
from ..transport.link import CONTROL_CHUNK, b64e, control_records
from . import sshopts

UAV_ID, GCS_ID = b"UAV-BNCH", b"GCS-BNCH"
CFG = SimpleNamespace(rotate_seconds=3600.0, rotate_packets=1 << 30, epoch_grace_seconds=3.0, replay_window=2048)


class RefClock:
    """Another machine's clock, read over one persistent SSH connection (a round trip of a few milliseconds)."""

    PROG = "import sys,time\nfor _ in sys.stdin:\n    sys.stdout.write(repr(time.time())+chr(10)); sys.stdout.flush()\n"

    def __init__(self, host):
        self.host = host
        self.p = subprocess.Popen(sshopts.ssh_base(host) + ["python3 -u -c " + shlex.quote(self.PROG)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.points = []
        self.sample()                                   # also fails early if the host cannot be reached

    def sample(self):
        """One (local monotonic time, reference time, round trip) point: the best of 7 exchanges."""
        best = None
        for _ in range(7):
            a = time.monotonic()
            self.p.stdin.write("\n"); self.p.stdin.flush()
            line = self.p.stdout.readline()
            b = time.monotonic()
            if not line:
                raise RuntimeError(f"reference clock on {self.host} did not answer")
            if best is None or b - a < best[2]:
                best = ((a + b) / 2, float(line), b - a)
        self.points.append(best)
        return best

    def rate(self):
        """Seconds of THIS machine's monotonic clock per second of the reference clock, first point to last."""
        (l0, r0, _), (l1, r1, _) = self.points[0], self.points[-1]
        return (l1 - l0) / (r1 - r0) if r1 > r0 else None

    def close(self):
        try:
            self.p.stdin.close(); self.p.wait(timeout=3)
        except Exception:
            self.p.kill()


class Bench:
    def __init__(self, n, ref=None):
        self.n, self.ref = n, ref
        self.results = {}

    def run(self, name, fn, n=None, reps=1, setup=None, group="primitives", note=None, bytes_per_call=None):
        """Time `fn(arg)` (arg = what `setup()` returned, made new for every sample and not timed). `reps` calls
        make one sample for operations of a few microseconds (the sample is the mean of those calls)."""
        n = n or self.n
        pc = time.perf_counter_ns
        for _ in range(max(3, min(20, n // 10))):       # warm-up: caches, CPU frequency, lazy initialisation
            arg = setup() if setup else None
            for _ in range(reps):
                fn(arg)
        samples = []
        for _ in range(n):
            arg = setup() if setup else None
            t0 = pc()
            for _ in range(reps):
                fn(arg)
            samples.append((pc() - t0) / reps)
        self.results[name] = {"group": group, "n": n, "calls_per_sample": reps, "samples_ns": [round(s, 1) for s in samples],
                              "median_us": round(statistics.median(samples) / 1e3, 3), "mean_us": round(statistics.fmean(samples) / 1e3, 3),
                              **({"note": note} if note else {}), **({"bytes_per_call": bytes_per_call} if bytes_per_call else {})}
        if self.ref and len(self.results) % 12 == 0:
            self.ref.sample()
        return samples


def x25519_pub(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def environment():
    def read(p):
        try:
            return Path(p).read_text().strip()
        except OSError:
            return None
    cpuinfo = read("/proc/cpuinfo") or ""
    field = lambda key: next((l.split(":", 1)[1].strip() for l in cpuinfo.splitlines() if l.lower().startswith(key)), None)
    feats = (field("features") or field("flags") or "").split()
    temp = read("/sys/class/thermal/thermal_zone0/temp")
    try:
        from cryptography.hazmat.backends.openssl import backend
        openssl = backend.openssl_version_text()
    except Exception:
        openssl = None
    return {"host": platform.node(), "machine": platform.machine(), "platform": platform.platform(),
            "python": platform.python_version(), "liboqs": oqs.oqs_version(), "liboqs_python": oqs.oqs_python_version(),
            "cryptography": cryptography.__version__, "openssl": openssl,
            "cpu_model": field("model name") or field("model") or field("hardware"), "cpu_count": os.cpu_count(),
            # AES / carry-less multiply instructions: with them AES-GCM runs in hardware, without them in plain software
            "cpu_has_aes": "aes" in feats, "cpu_has_pmull_or_clmul": "pmull" in feats or "pclmulqdq" in feats,
            "cpu_freq_khz": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"),
            "governor": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            "temp_c": round(int(temp) / 1000, 1) if temp and temp.isdigit() else None, "loadavg": list(os.getloadavg())}


def primitives(b: Bench):
    suite = get_suite(1)
    kem = oqs.KeyEncapsulation(suite.kem)
    ek = kem.generate_keypair()
    enc = oqs.KeyEncapsulation(suite.kem)
    ct, _ = enc.encap_secret(ek)
    b.run("ML-KEM-1024 keygen", lambda _: kem.generate_keypair())
    ek = kem.generate_keypair()
    ct, _ = enc.encap_secret(ek)
    b.run("ML-KEM-1024 encapsulate", lambda _: enc.encap_secret(ek))
    b.run("ML-KEM-1024 decapsulate", lambda _: kem.decap_secret(ct))

    peer = x25519_pub(x25519.X25519PrivateKey.generate())
    priv = x25519.X25519PrivateKey.generate()
    b.run("X25519 keygen", lambda _: x25519_pub(x25519.X25519PrivateKey.generate()))
    b.run("X25519 exchange", lambda _: priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer)))

    sig = oqs.Signature(suite.sig)
    b.run("ML-DSA-87 keygen", lambda _: sig.generate_keypair())
    pk = sig.generate_keypair()
    msg = os.urandom(len(hs.LBL_CH) + hs.CH_FIXED.size + hs.X25519_LEN + suite.kem_ek_len)        # what a ClientHello signs
    s = sig.sign(msg)
    # signing uses rejection sampling: its time varies from call to call by design, hence a distribution, not a number
    b.run("ML-DSA-87 sign", lambda m: sig.sign(m), setup=lambda: os.urandom(len(msg)), note=f"message of {len(msg)} B, new for every call")
    b.run("ML-DSA-87 verify", lambda _: idm.verify(suite.sig, msg, s, pk))

    transcript = os.urandom(len(msg) + len(s) + hs.SH_FIXED.size + hs.X25519_LEN + suite.kem_ct_len)
    b.run("SHA-256 transcript hash", lambda _: ks.sha256(hs.LBL_TH, transcript), reps=20, bytes_per_call=len(transcript))
    th, ikm, sid = os.urandom(32), os.urandom(64), os.urandom(8)
    b.run("HKDF key schedule (session secrets)", lambda _: ks.derive_session(th, ikm, 1, sid), reps=10)
    secrets = ks.derive_session(th, ikm, 1, sid)
    b.run("record keys for 6 streams x 2 directions", lambda _: Session(secrets, suite, "uav", CFG), reps=5)
    b.run("HMAC-SHA256 (Finished)", lambda _: ks.hmac256(secrets.finished_client, th), reps=50)
    chain = ks.EpochChain(secrets.chain_key(ks.STREAM_VIDEO, ks.DIR_U2G))
    b.run("epoch rotation (chain step + new AEAD key)", lambda _: (chain.advance(), suite.aead_cls(chain.key())), reps=10)
    kem.free(); enc.free()


def variants(b: Bench):
    """Primitives the link does NOT use, measured on the same machine in the same way: the smaller ML-KEM and ML-DSA
    parameter sets and a classical signature. They are the inputs of the design comparison in simulation/ (what a
    handshake would cost with another choice of algorithms); the link itself always runs suite 0x0001 / 0x0002.
    Returns their key, ciphertext and signature sizes."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sizes = {}
    for name in ("ML-KEM-512", "ML-KEM-768"):
        kem, enc = oqs.KeyEncapsulation(name), oqs.KeyEncapsulation(name)
        b.run(f"{name} keygen", lambda _: kem.generate_keypair(), group="variants")
        ek = kem.generate_keypair()
        ct, _ = enc.encap_secret(ek)
        b.run(f"{name} encapsulate", lambda _: enc.encap_secret(ek), group="variants")
        b.run(f"{name} decapsulate", lambda _: kem.decap_secret(ct), group="variants")
        sizes[name] = {"encapsulation_key": len(ek), "ciphertext": len(ct)}
        kem.free(); enc.free()
    for name, kem_name in (("ML-DSA-44", "ML-KEM-512"), ("ML-DSA-65", "ML-KEM-768")):
        sig = oqs.Signature(name)
        b.run(f"{name} keygen", lambda _: sig.generate_keypair(), group="variants")
        pk = sig.generate_keypair()
        n = len(hs.LBL_CH) + hs.CH_FIXED.size + hs.X25519_LEN + sizes[kem_name]["encapsulation_key"]   # what a ClientHello would sign
        msg = os.urandom(n)
        s = sig.sign(msg)
        b.run(f"{name} sign", lambda m: sig.sign(m), setup=lambda: os.urandom(n), group="variants", note=f"message of {n} B, new for every call")
        b.run(f"{name} verify", lambda _: idm.verify(name, msg, s, pk), group="variants")
        sizes[name] = {"public_key": len(pk), "signature": len(s)}
    sk = ed25519.Ed25519PrivateKey.generate()
    pk, msg = sk.public_key(), os.urandom(len(hs.LBL_CH) + hs.CH_FIXED.size + hs.X25519_LEN)
    s = sk.sign(msg)
    b.run("Ed25519 keygen", lambda _: ed25519.Ed25519PrivateKey.generate().public_key(), group="variants", reps=5)
    b.run("Ed25519 sign", lambda _: sk.sign(msg), group="variants", reps=5)
    b.run("Ed25519 verify", lambda _: pk.verify(s, msg), group="variants", reps=5)
    sizes["Ed25519"] = {"public_key": 32, "signature": len(s)}
    return sizes


def aead(b: Bench):
    aad = os.urandom(HDR_LEN + 9)                       # a video record: 24-byte header + 9-byte extension
    for name, cls in (("AES-256-GCM", AESGCM), ("ChaCha20-Poly1305", ChaCha20Poly1305)):
        a = cls(os.urandom(32))
        for size in (64, 256, 1100, 4096, 16384, 65536):
            pt, nonce = os.urandom(size), os.urandom(12)
            ct = a.encrypt(nonce, pt, aad)
            reps = max(1, min(200, 60000 // size))
            b.run(f"{name} seal {size} B", lambda _: a.encrypt(nonce, pt, aad), reps=reps, group="aead", bytes_per_call=size)
            b.run(f"{name} open {size} B", lambda _: a.decrypt(nonce, ct, aad), reps=reps, group="aead", bytes_per_call=size)


def record_layer(b: Bench):
    th, ikm, sid = os.urandom(32), os.urandom(64), os.urandom(8)
    payload, ext = os.urandom(1100), os.urandom(9)
    for suite_id in (1, 2):
        suite = get_suite(suite_id)
        tx = Session(ks.derive_session(th, ikm, suite_id, sid), suite, "uav", CFG)
        rx = Session(ks.derive_session(th, ikm, suite_id, sid), suite, "gcs", CFG)
        b.run(f"record seal 1100 B ({suite.aead_name})", lambda _: tx.seal(ks.STREAM_VIDEO, payload, ext), reps=50, group="record",
              bytes_per_call=1100, note="Session.seal: header, per-stream lock, AEAD")
        # every record can be opened once (replay window): a batch of fresh records per sample, sealed outside the timing
        it = iter(())

        def batch():
            nonlocal it
            it = iter([tx.seal(ks.STREAM_VIDEO, payload, ext) for _ in range(50)])
        b.run(f"record open 1100 B ({suite.aead_name})", lambda _: rx.open(next(it)), reps=50, setup=batch, group="record",
              bytes_per_call=1100, note="Session.open: header, replay window, AEAD")


def receive_path(b: Bench, keydir: Path):
    """What one video record costs the ground station's receive thread: finding the session, the replay window, the
    AEAD open and the video sink's reassembly of the frame (the H.264 decoder runs in another process and is not
    part of it). ONE thread does this for every UAV, so this cost bounds how many video streams a ground station can
    take; it is the input of the swarm model in simulation/. Run over a real pair of link objects (handshake over
    loopback), the records then handed to the receive function directly, 300 per sample (25 frames of 12 records)."""
    from ..config import LinkConfig
    from ..ground.video_sink import VIDEO_EXT, VideoSink
    from ..transport.link import GcsLink, UavLink
    cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, cached_rekey_interval_s=0, pq_ratchet_interval_s=0,
                     uav_id=UAV_ID.decode(), gcs_id=GCS_ID.decode())
    upk, gpk = (keydir / "uav_ML-DSA-87.pk").read_bytes(), (keydir / "gcs_ML-DSA-87.pk").read_bytes()
    gcs = GcsLink(cfg, idm.load_identity(keydir, "gcs", GCS_ID), {UAV_ID: upk}, bind=("127.0.0.1", 0))
    sink = VideoSink(clock_offset=lambda: 0.0)
    sink._emit = lambda *a, **k: None                                  # no decoder process: the sink's own work only
    gcs.on_message = lambda stream, ext, pt, meta: sink.on_chunk(ext, pt) if stream == ks.STREAM_VIDEO else None
    uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": gcs.sock.getsockname()[1]}), idm.load_identity(keydir, "uav", UAV_ID),
                  gpk, lambda: b"\x00" * 8)
    gcs.start(); uav.start()
    try:
        deadline = time.monotonic() + 15
        while (uav.state != "UP" or not gcs.link_up()) and time.monotonic() < deadline:
            time.sleep(0.05)
        if uav.state != "UP":
            raise RuntimeError("the loopback link did not come up")
        addr, fid, per = gcs.uav_addr, 0, 12
        samples, pc = [], time.perf_counter_ns
        for i in range(-3, max(30, b.n // 3)):
            pkts = []
            for _ in range(25):
                fid += 1
                for j in range(per):
                    body = (os.urandom(8) if j == 0 else b"") + os.urandom(1100 - (8 if j == 0 else 0))
                    pkts.append(uav.session.seal(ks.STREAM_VIDEO, body, VIDEO_EXT.pack(fid, j, per, 1 if fid % 30 == 1 else 0)))
            t0 = pc()
            for p in pkts:
                gcs._on_record(p, addr)
            dt = (pc() - t0) / len(pkts)
            if i >= 0:
                samples.append(dt)
        name = "receive path per video record (session lookup, replay window, open, frame reassembly)"
        b.results[name] = {"group": "record", "n": len(samples), "calls_per_sample": 300, "samples_ns": [round(s, 1) for s in samples],
                           "median_us": round(statistics.median(samples) / 1e3, 3), "mean_us": round(statistics.fmean(samples) / 1e3, 3),
                           "bytes_per_call": 1100, "note": "GcsLink._on_record + VideoSink.on_chunk, decoder not included"}
    finally:
        uav.stop(); gcs.stop()


def handshakes(b: Bench, keydir: Path):
    upk, gpk = idm.generate_identity(keydir, "uav"), idm.generate_identity(keydir, "gcs")
    uav, gcs = idm.load_identity(keydir, "uav", UAV_ID), idm.load_identity(keydir, "gcs", GCS_ID)
    mob = b"\x00" * 8
    steps = {k: [] for k in ("full: UAV builds ClientHello", "full: GCS answers (ServerHello)", "full: UAV verifies, derives, Finished",
                             "full: GCS checks Finished", "cached: UAV builds request", "cached: GCS answers", "cached: UAV verifies, Finished",
                             "cached: GCS checks Finished", "ratchet: UAV builds request", "ratchet: GCS answers", "ratchet: UAV finishes")}
    pc = time.perf_counter_ns
    wire = {}
    for i in range(-3, b.n):                            # three unrecorded rounds first
        server = hs.ServerHandshake(gcs, {UAV_ID: upk})
        t0 = pc(); ch = hs.ClientHandshake(uav, gpk, 1, mob); hello = ch.client_hello(); t1 = pc()
        sh = server.process_client_hello(hello); t2 = pc()
        c, cf = ch.process_server_hello(sh); t3 = pc()
        s, *_ = server.process_client_finished(cf); t4 = pc()
        cache = hs.RekeyCache(300)
        cache.put(UAV_ID, s, mob, 1)
        t5 = pc(); req = hs.build_rekey_request(UAV_ID, c, mob); t6 = pc()
        mtype, resp, new_s, _ = hs.server_process_rekey(cache, server, req); t7 = pc()
        new_c, rcf = hs.client_process_rekey_resp(req, c, resp); t8 = pc()
        server.process_client_finished(rcf); t9 = pc()
        init = hs.PQRatchetInitiator(1, 1); r_req = {"t": "ratchet_req", "rid": 1, "x": b64e(init.x_pub), "ek": b64e(init.ek)}; t10 = pc()
        x_s, ct, new_sid, _ = hs.pq_ratchet_respond(new_s, 1, init.x_pub, init.ek); t11 = pc()
        init.finish(new_c, x_s, ct, new_sid); t12 = pc()
        if i < 0:
            continue
        for k, v in zip(steps, (t1 - t0, t2 - t1, t3 - t2, t4 - t3, t6 - t5, t7 - t6, t8 - t7, t9 - t8, t10 - t9, t11 - t10, t12 - t11)):
            steps[k].append(v)
        if not wire:
            r_resp = {"t": "ratchet_resp", "rid": 1, "x": b64e(x_s), "ct": b64e(ct), "sid": new_sid.hex()}
            dg = lambda mtype_, body: [len(f) for f in framing.fragment(mtype_, body)]
            ctl = lambda m: [HDR_LEN + len(ext) + len(chunk) + 16 for ext, chunk in control_records(json.dumps(m, separators=(",", ":")).encode())]
            wire = {"full handshake": {"ClientHello": {"bytes": len(hello), "datagrams": dg(hs.MSG_CLIENT_HELLO, hello)},
                                       "ServerHello": {"bytes": len(sh), "datagrams": dg(hs.MSG_SERVER_HELLO, sh)},
                                       "ClientFinished": {"bytes": len(cf), "datagrams": dg(hs.MSG_CLIENT_FINISHED, cf)}},
                    "cached rekey": {"RekeyRequest": {"bytes": len(req), "datagrams": dg(hs.MSG_REKEY_REQ, req)},
                                     "RekeyResponse": {"bytes": len(resp), "datagrams": dg(hs.MSG_REKEY_RESP, resp)},
                                     "ClientFinished": {"bytes": len(rcf), "datagrams": dg(hs.MSG_CLIENT_FINISHED, rcf)}},
                    # the ratchet travels inside the session as sealed control records (JSON, base64)
                    "pq ratchet": {"request": {"bytes": len(json.dumps(r_req, separators=(",", ":"))), "datagrams": ctl(r_req)},
                                   "response": {"bytes": len(json.dumps(r_resp, separators=(",", ":"))), "datagrams": ctl(r_resp)}},
                    "parts": {"ML-KEM-1024 encapsulation key": get_suite(1).kem_ek_len, "ML-KEM-1024 ciphertext": get_suite(1).kem_ct_len,
                              "X25519 public key": hs.X25519_LEN, "ML-DSA-87 signature": len(ch.sig), "ML-DSA-87 public key (pinned, not sent)": len(upk),
                              "Finished MAC": hs.FIN_LEN, "handshake fragment header": framing.HS_HDR.size},
                    "record": {"header": HDR_LEN, "tag": 16, "video extension": 9, "json extension": jsonmsg.EXT.size,
                               "payload per video record": 1100, "control chunk": CONTROL_CHUNK, "udp_ip_headers": 28}}
    for k, v in steps.items():
        b.results[k] = {"group": "handshake", "n": len(v), "calls_per_sample": 1, "samples_ns": v,
                        "median_us": round(statistics.median(v) / 1e3, 3), "mean_us": round(statistics.fmean(v) / 1e3, 3)}
    return wire


def at_rest(b: Bench, keydir: Path):
    """Stored photos and recordings. Format 2 is what the system writes: the content key wrapped with ML-KEM-1024
    AND X25519, the file signed by the UAV with ML-DSA-87 (recording/sealing.py). Format 1 (ML-KEM-1024 alone, no
    signature) is measured beside it: the difference is what the hybrid wrap and the signature cost."""
    import hashlib

    from ..recording.photos import open_image, seal_image
    ek = idm.generate_recording_kem(keydir)
    dk = idm.load_recording_dk(keydir)
    x_pk = idm.generate_recording_x25519(keydir)
    x_sk = idm.load_recording_xsk(keydir)
    uav = idm.load_identity(keydir, "uav", UAV_ID)                 # made by handshakes()
    upk = (keydir / "uav_ML-DSA-87.pk").read_bytes()
    a = AESGCM(os.urandom(32))
    seg, aad = os.urandom(4 << 20), os.urandom(41)
    ct = a.encrypt(b"\x00" * 12, seg, aad)
    n = max(10, b.n // 10)
    b.run("recording segment seal 4 MiB (AES-256-GCM)", lambda _: a.encrypt(b"\x00" * 12, seg, aad), n=n, group="at_rest", bytes_per_call=len(seg))
    b.run("recording segment open 4 MiB (AES-256-GCM)", lambda _: a.decrypt(b"\x00" * 12, ct, aad), n=n, group="at_rest", bytes_per_call=len(seg))
    b.run("SHA-256 of 4 MiB (the digest the UAV signs)", lambda _: hashlib.sha256(seg).digest(), n=n, group="at_rest", bytes_per_call=len(seg))
    sec = os.urandom(375_000)                                      # one second of 3 Mbit/s video = one segment
    ct1 = a.encrypt(b"\x00" * 12, sec, aad)
    m = max(30, b.n // 3)
    b.run("recording segment seal 375 kB, one second of 3 Mbit/s video (AES-256-GCM)", lambda _: a.encrypt(b"\x00" * 12, sec, aad),
          n=m, group="at_rest", bytes_per_call=len(sec))
    b.run("recording segment open 375 kB, one second of 3 Mbit/s video (AES-256-GCM)", lambda _: a.decrypt(b"\x00" * 12, ct1, aad),
          n=m, group="at_rest", bytes_per_call=len(sec))
    meta = {"width": 1280, "height": 720}
    for size in (50_000, 200_000, 1_000_000, 3_000_000):          # a 720p frame ... a full-resolution 5 MP still
        jpeg = b"\xff\xd8" + os.urandom(size - 2)
        label = f"{size // 1000} kB" if size < 1_000_000 else f"{size // 1_000_000} MB"
        k = m if size <= 200_000 else max(10, m // 4)
        s1 = seal_image(ek, jpeg, meta)
        s2 = seal_image(ek, jpeg, meta, x25519_pk=x_pk, signer=uav)
        b.run(f"photo seal {label}, format 1 (ML-KEM-1024, AES-256-GCM)", lambda _: seal_image(ek, jpeg, meta),
              n=k, group="at_rest", bytes_per_call=size)
        b.run(f"photo open {label}, format 1 (ML-KEM-1024, AES-256-GCM)", lambda _: open_image(s1, dk),
              n=k, group="at_rest", bytes_per_call=size)
        b.run(f"photo seal {label}, format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature)",
              lambda _: seal_image(ek, jpeg, meta, x25519_pk=x_pk, signer=uav), n=k, group="at_rest", bytes_per_call=size,
              note=f"file: {len(s2)} B for {size} B of JPEG (format 1: {len(s1)} B)")
        b.run(f"photo open {label}, format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature verified)",
              lambda _: open_image(s2, dk, x25519_sk=x_sk, signer_pk=upk), n=k, group="at_rest", bytes_per_call=size)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-n", type=int, default=300, help="samples per operation (default 300)")
    ap.add_argument("-o", "--out", help="output file (default crypto_<host>.json in the current directory)")
    ap.add_argument("--ref-ssh", help="ssh host whose clock is the reference for this machine's clock rate")
    a = ap.parse_args()
    import tempfile
    keydir = Path(tempfile.mkdtemp(prefix="k6g_bench_"))
    ref = RefClock(a.ref_ssh) if a.ref_ssh else None
    env0, t_start = environment(), time.time()
    pc0 = time.perf_counter_ns()
    overhead = []
    for _ in range(20000):                              # what one pair of timer calls costs here
        t0 = time.perf_counter_ns(); overhead.append(time.perf_counter_ns() - t0)
    b = Bench(a.n, ref)
    primitives(b)
    variant_sizes = variants(b)
    aead(b)
    record_layer(b)
    wire = handshakes(b, keydir)
    at_rest(b, keydir)
    try:
        receive_path(b, keydir)
    except Exception as e:                                    # e.g. no loopback sockets in a sandbox: everything else stands
        print(f"receive path not measured: {type(e).__name__}: {e}")
    elapsed = (time.perf_counter_ns() - pc0) / 1e9
    clock = {"reference": None, "local_per_reference_second": 1.0}
    if ref:
        ref.sample()
        clock = {"reference": a.ref_ssh, "local_per_reference_second": round(ref.rate(), 6),
                 "points_local_reference_rtt": [[round(l, 6), round(r, 6), round(rtt * 1000, 3)] for l, r, rtt in ref.points],
                 "note": "durations in this file are raw; true duration = raw / local_per_reference_second"}
        ref.close()
    out = {"tool": "kyber6g.tools.bench_crypto", "started": t_start, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start)),
           "duration_s": round(elapsed, 1), "samples_per_operation": a.n, "environment": env0, "environment_end": environment(),
           "timer_overhead_ns_median": statistics.median(overhead), "clock": clock, "wire": wire,
           "variant_sizes": variant_sizes, "results": b.results}
    path = Path(a.out or f"crypto_{platform.node()}.json")
    path.write_text(json.dumps(out))
    for p in keydir.glob("**/*"):
        if p.is_file():
            p.unlink()
    rate = clock["local_per_reference_second"]
    print(f"{platform.node()} ({env0['machine']}, {env0['cpu_model']}), {a.n} samples per operation, {elapsed:.0f} s"
          + (f", clock rate against {a.ref_ssh}: {rate:.4f} (medians below are corrected)" if ref else ""))
    for name, r in b.results.items():
        extra = f"   {r['bytes_per_call'] * 8 / (r['median_us'] / rate):8.1f} Mbit/s" if r.get("bytes_per_call") else ""
        print(f"  {name:58s} {r['median_us'] / rate:10.2f} us{extra}")
    print(f"-> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
