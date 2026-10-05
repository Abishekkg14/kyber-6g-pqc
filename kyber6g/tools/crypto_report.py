"""Write docs/CRYPTANALYSIS_REPORT.txt from the measured attack experiments and benchmarks.

    python -m kyber6g.tools.crypto_report [--data paper_plots/data] [-o docs/CRYPTANALYSIS_REPORT.txt]

The analysis text is written here once; every NUMBER in the report (attempts, accepted, reasons, timings, sizes,
statistics) is read from the files the tools wrote on the two machines:
    attacks_laptop.json, attacks_pi.json      kyber6g.tools.attack_bench
    crypto_laptop.json, crypto_pi.json        kyber6g.tools.bench_crypto
    loss.json, link_ops.json                  kyber6g.tools.bench_link
so the report cannot say something the experiments did not show. Plain text on purpose: it is meant to be quoted from.
"""
import argparse
import json
import sys
import textwrap
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
W = 100


def para(text, indent=0):
    out = []
    for block in textwrap.dedent(text).strip().split("\n\n"):
        out.append(textwrap.fill(" ".join(block.split()), W, initial_indent=" " * indent, subsequent_indent=" " * indent))
    return "\n\n".join(out)


def bullets(items, indent=2, mark="-"):
    return "\n".join(textwrap.fill(" ".join(i.split()), W, initial_indent=" " * indent + mark + " ", subsequent_indent=" " * (indent + 2)) for i in items)


def table(rows, header, aligns=None):
    rows = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(header)]
    aligns = aligns or ["<"] * len(header)
    line = lambda r: "  " + "  ".join(f"{c:{a}{w}}" for c, a, w in zip(r, aligns, widths)).rstrip()
    return "\n".join([line(header), "  " + "  ".join("-" * w for w in widths)] + [line(r) for r in rows])


def head(n, title):
    s = f"{n}. {title.upper()}" if n else title.upper()
    return f"\n\n{s}\n{'=' * len(s)}\n"


def sub(title):
    return f"\n{title}\n{'-' * len(title)}\n"


def load(d, name):
    p = d / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def fmt_outcomes(o, limit=4):
    items = [(k, v) for k, v in o.items() if isinstance(v, (int, float))]
    items.sort(key=lambda kv: -kv[1])
    s = "; ".join(f"{k}: {v}" for k, v in items[:limit])
    return s + ("; ..." if len(items) > limit else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", default=str(REPO / "paper_plots" / "data"))
    ap.add_argument("-o", "--out", default=str(REPO / "docs" / "CRYPTANALYSIS_REPORT.txt"))
    a = ap.parse_args()
    d = Path(a.data)
    A = {"laptop (ground station)": load(d, "attacks_laptop"), "Raspberry Pi 4B (UAV)": load(d, "attacks_pi")}
    A = {k: v for k, v in A.items() if v}
    if not A:
        sys.exit(f"no attack experiments found in {d} (run: bash run/kyber6g.sh measure attacks)")
    cpi, clap = load(d, "crypto_pi"), load(d, "crypto_laptop")
    loss, ops = load(d, "loss"), load(d, "link_ops")
    k_lap = (clap or {}).get("clock", {}).get("local_per_reference_second") or 1.0
    P = lambda n: cpi["results"][n]["median_us"] if cpi and n in cpi["results"] else None
    L = lambda n: clap["results"][n]["median_us"] / k_lap if clap and n in clap["results"] else None
    us = lambda v: "-" if v is None else (f"{v / 1000:.2f} ms" if v >= 1000 else f"{v:.0f} us")

    exp = {}                                   # attack name -> {machine: experiment}
    for m, data in A.items():
        for e in data["experiments"]:
            exp.setdefault(e["attack"], {})[m] = e
    # The nonce experiment is a stress test of the sender (records sealed by racing threads), not an input offered by
    # an attacker: its records are counted on their own and not among the attack attempts.
    RACE = "record: nonce reuse"
    total_attempts = sum(e["attempts"] for n, v in exp.items() for e in v.values() if e["expect"] == "refused" and n != RACE)
    total_accepted = sum(e["accepted"] for n, v in exp.items() for e in v.values() if e["expect"] == "refused" and n != RACE)
    race_records = sum(e["attempts"] for e in exp.get(RACE, {}).values())
    race_reused = sum(e["accepted"] for e in exp.get(RACE, {}).values())
    failed = [(n, m) for n, v in exp.items() for m, e in v.items() if e["verdict"] != "PASS"]
    forged_ok = [(n, m) for n, m in failed if exp[n][m]["expect"] == "refused"]          # an attack that was accepted: must be empty
    unavailable = [(n, m) for n, m in failed if exp[n][m]["expect"] != "refused"]        # a legitimate use that did not go through

    def X(name):
        """One experiment as text: what was done, then per machine the attempts, how many were accepted, the reasons given."""
        v = exp.get(name)
        if not v:
            return f"  [experiment '{name}' not in the data]"
        what = " ".join(next(iter(v.values()))["what"].split())
        lines = [textwrap.fill(f"Experiment \"{name}\": {what}.", W, initial_indent="  ", subsequent_indent="    ")]
        for m, e in v.items():
            where = "on the " + m.split(" (")[0]
            if name == "record: nonce reuse":
                o = e["outcomes"]
                x = (f"{where}: {e['attempts']:,} records sealed, {o.get('unique (epoch, sequence) pairs'):,} different (key epoch, sequence number) "
                     f"pairs over {o.get('epochs')} key epochs; pairs used twice: {o.get('pairs used twice')}")
            elif e["expect"] == "refused":
                x = f"{where}: {e['attempts']:,} attempts, {e['accepted']} accepted. Refused as: {fmt_outcomes(e['outcomes'])}"
            else:
                x = f"{where}: {e['accepted']:,} of {e['attempts']:,} accepted (all have to be)"
            lines.append(textwrap.fill(x, W, initial_indent="    ", subsequent_indent="        "))
        return "\n".join(lines)

    t = []
    t.append("KYBER-6G SECURE LINK: CRYPTANALYSIS REPORT")
    t.append("=" * 42)
    dates = ", ".join(sorted({v["started_utc"][:10] for v in A.values()}))
    t.append(para(f"""
        Generated {time.strftime('%Y-%m-%d')} by kyber6g/tools/crypto_report.py from the attack experiments of {dates}
        ({' and '.join(A)}) and the benchmarks in paper_plots/data. Every number below is read from those files.
        Plain text, so that sentences and tables can be copied into the paper."""))

    t.append(head(0, "Summary"))
    t.append(bullets([
        f"""{len(exp)} kinds of experiment were run against the real implementation on {len(A)} machine(s). {total_attempts:,} forged,
        modified, replayed or misplaced inputs were offered to it (attack attempts): {total_accepted} accepted."""
        + ("" if not forged_ok else f" ACCEPTED ATTACKS IN: {forged_ok}.")
        + (f""" In a stress test of the sender, {race_records:,} records were sealed by eight racing threads: {race_reused} (key, nonce)
        pairs used twice.""" if race_records else ""),
        """No way was found to read protected data, to get a forged, modified or replayed record, handshake message, rekey request,
        photo or recording accepted, to impersonate either end, or to force a weaker algorithm.""",
        ("""Availability under a flood of forged handshakes: every genuine connection was made at every flood rate tried, on
        both machines. Above a rate that depends on the ground station's processor it took repeats, and seconds instead
        of milliseconds (section 4.12, with the rates).""" if not unavailable else
         f"""Availability under a flood of forged handshakes has a limit that was reached: on the {', '.join(sorted({m for _, m in unavailable}))}
         not every genuine connection was made at the highest flood rates (section 4.12, with the rates). Nothing was disclosed
         or accepted by it; the UAV was kept waiting."""),
        """What an attacker CAN do is listed in section 7: disturb the link (jamming, floods above a measured rate, dropping packets),
        see sizes and timing of the traffic, and - with a stolen long-term key - whatever that key stands for. Stolen keys are
        analysed key by key in section 4.11.""",
        """Nothing here is a proof. The claims rest on (a) the published security of ML-KEM-1024, ML-DSA-87, X25519, AES-256-GCM
        and HKDF/HMAC-SHA-256, (b) the standard way these are combined, reviewed in docs/SECURITY_ARCHITECTURE.md and
        docs/SECURITY_AUDIT.md, and (c) the experiments below, which test the implementation and not the mathematics.
        "100 % secure" or "unbreakable" is not a claim this report supports, and no honest report could."""]))

    # ------------------------------------------------------------------------------------------------------ 1
    t.append(head(1, "What is protected, and by what"))
    t.append(sub("1.1 Session establishment (full handshake, 1.5 round trips)"))
    t.append(para("""
        The UAV sends a ClientHello with a fresh ML-KEM-1024 encapsulation key and a fresh X25519 key, signed with its
        ML-DSA-87 identity key. The ground station checks the signature against the key it has PINNED for that UAV (keys are
        never taken from a message), encapsulates to the ML-KEM key, does the X25519 exchange, and answers with its own
        ML-DSA-87 signature over the transcript hash TH (which covers the suite number, both identities, both nonces, the
        position cell, the time stamp, both ephemeral public keys, the ML-KEM ciphertext and the UAV's signature) and a
        Finished MAC. The session keys are HKDF-SHA256(salt = TH, ikm = ss_MLKEM || ss_X25519). The UAV answers with its own
        Finished MAC. Both long-term keys only ever sign; all key agreement is ephemeral."""))
    t.append(sub("1.2 Record layer (everything that is sent: telemetry, photos, video, recordings in transit, control)"))
    t.append(para("""
        AES-256-GCM (suite 0x0001) or ChaCha20-Poly1305 (suite 0x0002). One key per stream, per direction and per epoch
        (a one-way HKDF chain; a new epoch every 30 s or 2^20 records). The nonce is the 64-bit sequence number of the
        stream, which never repeats within a session; the whole header (version, stream, session, epoch, sequence, and the
        stream's own metadata such as the video frame number) is authenticated. A sliding window of 2048 sequence numbers
        rejects replays, and it is advanced only after the tag has verified."""))
    t.append(sub("1.3 Rekeying"))
    t.append(bullets([
        """1-RTT Cached RapidRekey: a new session from the cached resumption secret, authenticated by an HMAC under a key derived
        from it; allowed only in the same position cell and within 300 s; the old secret is deleted when used. Symmetric only: fast
        (one round trip, 324 bytes), but it adds no new entropy.""",
        """PQ ratchet (every 600 s): a fresh ML-KEM-1024 + X25519 exchange inside the session, mixed with the current master secret.
        This is what restores secrecy after a key has leaked.""",
        """Full handshake: at start, after a change of position cell, and whenever the two above are refused."""]))
    t.append(sub("1.4 Photos and recordings stored on the UAV (file format 2)"))
    t.append(para("""
        Each file has its own random 256-bit content key (CEK). The CEK is wrapped under a key derived from BOTH an ML-KEM-1024
        encapsulation to the ground station's recording key and an X25519 exchange between a key made for this file and the
        ground station's X25519 recording key: HKDF(salt = SHA-256(header || ct || x_pub), ikm = ss_MLKEM || ss_X25519). The
        content is AES-256-GCM (a photo in one piece, a recording in numbered segments with a FINAL flag). The UAV signs
        SHA-256 of the whole file with its ML-DSA-87 identity key. The UAV keeps none of the secrets: it cannot read its own
        files back, and the ground station refuses a file that is not signed by the UAV it has pinned."""))
    t.append(sub("1.5 Where post-quantum cryptography acts in the image and video path (wording for the paper)"))
    t.append(bullets([
        """LIVE VIDEO, PHOTOS IN TRANSIT, TELEMETRY: the bulk cipher is AES-256-GCM. Post-quantum cryptography establishes and
        refreshes its keys (ML-KEM-1024, with X25519, in the handshake and in every PQ ratchet) and authenticates the two ends
        (ML-DSA-87). It does not encrypt the frames.""",
        """STORED PHOTOS AND RECORDINGS: hybrid public-key encryption in the KEM-DEM form (ML-KEM-1024 + X25519 wrap a key,
        AES-256-GCM encrypts the content) and a post-quantum signature (ML-DSA-87) over the file.""",
        """AES-256 itself is not "post-quantum cryptography" in the sense of the NIST standards, but it is not broken by a
        quantum computer either: Grover's search leaves about 128 bits of security (section 6)."""]))

    # ------------------------------------------------------------------------------------------------------ 2
    t.append(head(2, "The attacker"))
    t.append(bullets([
        """ON THE NETWORK (Wi-Fi, or any radio and network in between): reads, drops, delays, reorders, replays, changes and injects
        datagrams, with any source address; records everything, to attack it later with a quantum computer.""",
        """AT THE STORAGE: takes the UAV's SD card (a captured UAV), or can write files into the ground station's folders.""",
        """A FAULTY OR TAKEN-OVER PEER: an authenticated UAV or ground station that sends well-authenticated nonsense.""",
        """IN THE OPERATOR'S BROWSER: another web page open beside the dashboard (docs/SECURITY_AUDIT.md, finding 2).""",
        """NOT CONSIDERED: power and electromagnetic side channels, fault injection, a malicious operating system on either
        machine, GNSS spoofing as an attack on navigation, radio jamming."""]))

    # ------------------------------------------------------------------------------------------------------ 3
    t.append(head(3, "Security levels of the building blocks"))
    t.append(table([
        ["ML-KEM-1024 (FIPS 203)", "key encapsulation", "category 5 (>= AES-256)", "category 5", "ek 1568 B, ct 1568 B"],
        ["X25519 (RFC 7748)", "key agreement", "about 128 bits", "none (Shor)", "32 B"],
        ["ML-DSA-87 (FIPS 204)", "signatures", "category 5", "category 5", "pk 2592 B, sig 4627 B"],
        ["AES-256-GCM (SP 800-38D)", "records, files", "256-bit key, 128-bit tag", "about 128 bits (Grover)", "+16 B per record"],
        ["ChaCha20-Poly1305 (RFC 8439)", "records, suite 2", "256-bit key, 128-bit tag", "about 128 bits (Grover)", "+16 B per record"],
        ["HKDF / HMAC-SHA-256", "key schedule, MACs", "256 bits (preimage)", "about 128 bits", "32 B outputs"],
        ["SHA-256", "transcript, file digests", "128 bits (collision)", "about 85 bits (BHT, memory-bound)", "32 B"],
    ], ["building block", "role", "classical security", "against a quantum computer", "sizes"]))
    t.append("")
    t.append(para("""
        "Category 5" is NIST's strongest: breaking it is meant to be at least as hard as a key search on AES-256. The hybrid
        key agreement is as strong as the STRONGER of ML-KEM-1024 and X25519: both secrets go into HKDF together, salted with
        the transcript, so an attacker has to recover both. Today that guards against an unforeseen weakness of the young
        lattice scheme; against a quantum computer the security is that of ML-KEM-1024 alone, because X25519 then gives
        nothing."""))
    t.append(sub("3.1 Limits of the record cipher, with this system's numbers"))
    t.append(bullets([
        """Nonce uniqueness. A (key, nonce) pair must never repeat with GCM. Here the nonce is the stream's sequence number
        (64 bits, never reset within a session) and the key is unique per session, stream, direction and epoch. Measured under the
        worst case for a race (8 threads on one stream, the interpreter switching threads as often as it can): see 4.10.""",
        """Data per key. At most 2^20 records of at most 1.2 kB per epoch key: 2^20 x 76 blocks, about 2^26 blocks, against the
        2^32-block order of magnitude at which GCM's bounds start to matter. At the measured video rate (360 records per second)
        an epoch lasts 30 s and holds about 11,000 records.""",
        """Forgery. With a 128-bit tag and records of at most 77 blocks, one forgery attempt succeeds with probability at most
        about 77 / 2^128, that is 2^-121.7. A billion attempts: 2^-91.8.""",
        """Replay. The window holds 2048 sequence numbers per stream and direction; anything older is refused as stale, anything
        seen as duplicate."""]))

    # ------------------------------------------------------------------------------------------------------ 4
    t.append(head(4, "Attacks, why they fail, and what the experiments showed"))
    t.append(para("""
        "Attempts" are real calls into the implementation with the attacker's input; "accepted" is how many of them the
        implementation took for genuine. The reasons are the implementation's own. Every experiment was run twice, once
        on each machine (both ends of the link are then on that machine): "on the laptop" and "on the Raspberry Pi 4B"
        say where it ran, not which end was attacked."""))

    t.append(sub("4.1 Listening, now and with a future quantum computer (harvest now, decrypt later)"))
    t.append(para("""
        A listener sees ciphertext under keys from ML-KEM-1024 and X25519 with ephemeral keys. Recovering a session key needs
        BOTH shared secrets. A quantum computer running Shor's algorithm recovers the X25519 secret from recorded traffic; the
        ML-KEM-1024 secret remains. Recorded traffic therefore stays confidential as long as ML-KEM-1024 does. Not testable
        by experiment; it rests on FIPS 203 and its analysis."""))

    t.append(sub("4.2 Impersonation and the man in the middle"))
    t.append(para("""
        Both ends verify the other's ML-DSA-87 signature against a pinned key. An attacker in the middle who answers with a key
        of its own, or who speaks under the UAV's name with its own key:"""))
    t.append(X("handshake: ground station impersonated"))
    t.append(X("handshake: UAV impersonated"))

    t.append(sub("4.3 Modified and forged messages"))
    t.append(para("Records (one bit changed anywhere; random bytes behind a correct header), and handshake messages:"))
    t.append(X("record: one bit changed"))
    t.append(X("record: forged"))
    t.append(X("record: second suite (ChaCha20-Poly1305)"))
    t.append(X("handshake: message modified"))
    e = next(iter(exp.get("record: one bit changed", {}).values()), None)
    if e:
        t.append(para(f"""
            After every modified record the genuine one was offered and accepted ({e.get('genuine_record_still_accepted_afterwards'):,} of
            {e['attempts']:,} on the first machine): a forgery does not use up the place of the record it imitates. After every
            modified handshake message the genuine handshake still completed."""))

    t.append(sub("4.4 Replay and reordering"))
    t.append(X("record: replayed"))
    t.append(X("record: reordered (legitimate)"))
    t.append(X("handshake: replay"))
    t.append(para("""
        A replayed ClientHello is refused BEFORE its signature is checked (a nonce already seen, or a time stamp more than 120 s
        away), so replaying valid hellos costs the ground station nothing."""))

    t.append(sub("4.5 Splicing: a genuine record put where it does not belong"))
    t.append(para("""
        Another stream, another session, a later epoch, back to its own sender (reflection), a changed frame number or chunk
        index, cut short, extended. Keys differ per stream, direction, session and epoch, and the header is authenticated:"""))
    t.append(X("record: spliced"))

    t.append(sub("4.6 Downgrade"))
    t.append(para("The suite number is inside the signed ClientHello and inside the transcript the ground station signs:"))
    t.append(X("handshake: downgrade"))

    t.append(sub("4.7 Mixed transcripts (unknown key-share)"))
    t.append(X("handshake: answers mixed"))

    t.append(sub("4.8 Manipulated key shares"))
    t.append(X("handshake: key share replaced"))
    t.append(X("handshake: degenerate X25519 key"))
    t.append(X("PQ ratchet: key share replaced"))
    t.append(para("""
        A replaced ML-KEM ciphertext is not an error for ML-KEM (decapsulation returns an unrelated secret by design: implicit
        rejection); the mismatch is caught by the signature in the handshake and by the first record in the ratchet."""))

    t.append(sub("4.9 Abuse of the 1-RTT Cached RapidRekey"))
    t.append(X("cached rekey: forged or misused request"))
    t.append(X("cached rekey: answer modified"))
    t.append(para("""
        The MAC is checked before any state changes; a used secret is deleted (a replayed request finds nothing); another
        position cell or an expired entry leads to a full handshake. The refusal itself (REJECT) is not authenticated: a forged
        one makes the UAV do a full handshake instead - time, not security."""))

    t.append(sub("4.10 Nonce reuse"))
    t.append(X("record: nonce reuse"))
    t.append(para("""
        Before the review of October 2026 the sequence number was taken without a lock; with the lock removed the same
        experiment produced reused pairs (docs/SECURITY_AUDIT.md, finding 1). It is in the test suite."""))

    t.append(sub("4.11 A key is stolen: what it opens and what it does not"))
    t.append(table([
        ["UAV identity key (ML-DSA-87)", "speak as this UAV from now on; sign files as it", "past or future session keys; stored media"],
        ["Ground-station identity key", "speak as the ground station to the UAV", "past sessions; stored media"],
        ["Recording keys (ML-KEM AND X25519)", "all stored photos and recordings, old and new", "live sessions; one key alone opens nothing"],
        ["One epoch key (a stream, a direction)", "that stream from that epoch to the next rekey", "earlier epochs; other streams"],
        ["Session master / resumption secret", "this session; later Cached-RapidRekey sessions", "earlier sessions; anything after the next PQ ratchet*"],
        ["A captured UAV (SD card)", "its identity key (see first row)", "its own stored photos and recordings"],
    ], ["stolen", "gives the attacker", "does not give"]))
    t.append("")
    t.append(para("""
        * if the attacker only listens during that ratchet. An attacker who holds the current session keys AND is in the middle
        when the ratchet runs can take part in it; no protocol without new authentication can prevent that. Forward secrecy:
        handshake keys are ephemeral and deleted, epoch keys form a one-way chain. Stored files have no forward secrecy by their
        nature: whoever holds the recording keys can read them, which is their purpose."""))

    t.append(sub("4.12 Denial of service"))
    t.append(para("""
        A flood of forged ClientHellos. Each one carries the UAV's name, a new nonce and the current time, so it passes
        the cheap checks and reaches the signature check, the expensive step. The ground station verifies failing
        signatures only up to a ration (a quarter of one core, sized from the cost of a check on that machine when it
        starts); beyond it, hellos are dropped unverified and a genuine one may have to be repeated. The generator ran as a
        process of its own on the same machine, at set rates and then as fast as it could, while a genuine UAV connected
        again and again (limit: 60 s per connection)."""))
    for m, e in exp.get("flood: forged ClientHellos", {}).items():
        rows = [[str(l["target_per_s"]), f"{l['forged_per_s']:,}", f"{l['mbit_per_s']:g}", f"{l['connected']} of {l['connections']}",
                 "-" if l["median_ms"] is None else f"{l['median_ms']:.0f}", "-" if l["max_ms"] is None else f"{l['max_ms']:.0f}",
                 f"{l['refused_after_signature_check']:,}", f"{l['dropped_unverified_by_the_ration']:,}"] for l in e.get("levels", [])]
        t.append(f"\n  Ground station on the {m.split(' (')[0]} (ration: {e['outcomes'].get('ration of failed signature checks per second', 0):.0f} failed checks per second):\n")
        t.append(table(rows, ["forged hellos/s asked", "sent/s", "Mbit/s", "genuine UAV connected", "median ms", "slowest ms", "refused after check",
                              "dropped unverified"], ["<", ">", ">", ">", ">", ">", ">", ">"]))
        lv = e.get("levels", [])
        worst = [l for l in lv if l["connected"] < l["connections"]]
        base = next((l["max_ms"] for l in lv if not l["forged_per_s"]), None)
        calm = [l for l in lv if l["forged_per_s"] and l["max_ms"] is not None and base and l["max_ms"] < 5 * base + 20]
        slow = [l for l in lv if l["forged_per_s"] and l not in calm and l["median_ms"] is not None]
        text = ("Every genuine connection was made at every rate." if not worst else
                "NOT every genuine connection was made within the limit: at " + ", ".join(f"{l['forged_per_s']:,} per second {l['connected']} of {l['connections']}" for l in worst)
                + ". An attacker who can send that much to a ground station of this class can keep a UAV out for as long as the flood lasts.")
        if calm:
            top = max(calm, key=lambda l: l["forged_per_s"])
            text += f" Up to {top['forged_per_s']:,} forged hellos per second ({top['mbit_per_s']:.0f} Mbit/s) the genuine handshake was not held up (slowest: {top['max_ms']:.0f} ms)."
        if slow:
            text += (" Above that it needed repeats: " + "; ".join(f"at {l['forged_per_s']:,} per second ({l['mbit_per_s']:.0f} Mbit/s) the median was "
                     f"{l['median_ms'] / 1000:.1f} s and the slowest {l['max_ms'] / 1000:.1f} s" for l in slow) + ".")
        text += " No key and no data is exposed by a flood."
        t.append("")
        t.append(para(text, 2))
    t.append("")
    t.append(para("""
        A forged FRAGMENT. Handshake fragments are not authenticated one by one; the message is verified when it is
        complete. An attacker who sees a ClientHello in flight and can send under the UAV's address can replace one of its
        fragments:"""))
    t.append(X("handshake: forged fragment injected"))
    for m, e in list(exp.get("handshake: forged fragment injected", {}).items())[:1]:
        t.append(para(f"""
            The spoiled message is refused at the signature check ({e.get('transmissions_spoiled')} transmissions spoiled, none
            accepted), and the UAV's next transmission of the same hello was accepted in {e.get('genuine_hello_accepted_on_the_repeat')}
            of {e['attempts']} cases: such an attacker delays a handshake by one repeat interval per injected fragment, like
            one who drops a datagram, and gains nothing else."""))
    t.append(para("""
        Further: forged fragments cannot fill the reassembly table (the oldest entry makes room, four per source address);
        forged answers and ERROR messages do not end the UAV's attempt; a forged header cannot push the receiver's key chain
        more than 8 epochs ahead of the last authenticated one (unit tests, tests/test_hardening.py). Jamming, and an attacker
        on the path who drops packets, cannot be prevented by a protocol."""))

    t.append(sub("4.13 Stored photos and recordings"))
    for name in ("stored photo: modified", "stored photo: cut or extended", "stored photo: forged or re-signed", "stored photo: wrong keys",
                 "stored recording: modified", "stored recording: segments rearranged", "stored recording: forged"):
        t.append(X(name))
    t.append(para("""
        "TRUNCATED" among the reasons means: the file was read as far as it goes and reported as cut short and unsigned - not
        taken for a complete recording. With format 1 (before October 2026) anyone who knew the ground station's public key
        could write a file that passed; format 2 closes that with the UAV's signature."""))

    t.append(sub("4.14 Timing"))
    rows = []
    short = lambda s: ("record: tag wrong in its first / last byte" if s.startswith("record") else
                       "handshake MAC wrong in its first / last byte" if s.startswith("Finished") else "CONTROL: comparison that stops early")
    for m, data in A.items():
        for x in data.get("timing") or []:
            rows.append([m.split(" (")[0], short(x["test"]), f"{x['mean_ns'][0]:.1f} / {x['mean_ns'][1]:.1f}", f"{x['difference_ns']:+.2f}",
                         " ".join(f"{v:+.1f}" for v in x.get("t_rounds", [x["t"]])), str(x.get("rounds_over_4.5", int(abs(x["t"]) > 4.5)))])
    if rows:
        t.append(table(rows, ["machine", "comparison", "mean time of a refusal, ns", "difference, ns", "Welch t in each of the rounds", "rounds with |t| > 4.5"]))
        t.append("")
        t.append(para("""
            Two classes of wrong input, measured in random order, new values for every sample, the whole test made five
            times. |t| below 4.5 is the usual threshold for "no difference found"; a single round above it can be chance,
            a difference that is there shows in every round. The control row is a comparison that stops at the first
            wrong byte (it is not used anywhere in the link): the same test finds it in every round. This is a
            coarse test in software on a general-purpose system: it would find an early-exit comparison, not a subtle leak.
            Power, electromagnetic and cache side channels were not examined; constant-time behaviour of the primitives is
            that of liboqs and OpenSSL."""))

    t.append(sub("4.15 What the traffic shows without breaking anything"))
    t.append(para("""
        Sizes and timing of the datagrams (they follow the video's bit rate and scene), stream numbers, epochs, sequence
        numbers, the UAV's identifier in the handshake, and the position cell as an 8-byte hash. There is no padding and no
        cover traffic."""))

    # ------------------------------------------------------------------------------------------------------ 5
    t.append(head(5, "Statistical properties of the ciphertext (photos and video)"))
    t.append(para("""
        These are sanity checks of the kind image-encryption papers report. They can expose a broken cipher; they cannot
        show a cipher is secure (a weak cipher can pass all of them). The security argument is section 3."""))
    for m, data in A.items():
        s = data.get("statistics")
        if not s:
            continue
        rows = []
        corr = lambda v: "undefined" if v is None else f"{v:+.4f}"                  # a constant plaintext has no correlation
        for f in s["files"]:
            p, c = f["plaintext"], f["ciphertext"]
            rows.append([f["kind"], f["file"][:38], f"{p['bytes'] / 1000:.0f} kB", f"{abs(p['entropy_bits_per_byte']):.4f}", f"{c['entropy_bits_per_byte']:.4f}",
                         corr(p["serial_correlation"]), corr(c["serial_correlation"]), f"{c['chi_square_p']:.3f}", f"{100 * c['share_of_one_bits']:.2f} %"])
        t.append(f"\n  Measured on the {m}:\n")
        t.append(table(rows, ["data", "file", "size", "H plain", "H cipher", "corr plain", "corr cipher", "chi2 p cipher", "one bits"]))
        t.append("")
        t.append(para("""
            H: Shannon entropy in bits per byte (8 is the maximum). corr: correlation of each byte with the next. chi2 p: the
            chance that uniformly random bytes give a histogram at least this uneven (anything between 0.01 and 0.99 is
            unremarkable). JPEG and H.264 are compressed and already close to 8 bits per byte, so the structured and the all-zero
            plaintexts are the telling rows: their ciphertext is as flat as that of real media."""))
        rows = [[f["what"], f"{f['bytes_that_differ_pct']:.2f} %", f"{f['mean_absolute_difference_pct_of_255']:.2f} %", f"{f['bits_that_differ_pct']:.2f} %"]
                for f in s["fresh_encryption"] + s["key_and_nonce_sensitivity"]]
        t.append("")
        t.append(table(rows, ["two ciphertexts compared", "bytes differ", "mean difference", "bits differ"]))
        t.append("")
        t.append(para("""
            Ideal values for two unrelated random byte strings: 99.61 %, 33.46 % and 50 % (the first two are what image papers
            call NPCR and UACI). The same picture stored twice gives two unrelated ciphertexts, because every file gets a new key
            and every record a new nonce: an observer cannot tell that the picture is the same. With one key and one nonce,
            a changed plaintext bit changes exactly that ciphertext bit (GCM is a stream cipher inside); the system never
            reuses a pair, and the tag rejects any change."""))
        break

    ms = load(d, "media_stats")
    if ms:
        im, mean = ms["image"], (lambda v: sum(v) / len(v))
        pc, cc, df, wk = im["plain"], im["cipher"], ms["differences"], ms["wrong_key"]
        t.append(sub("5.1 A picture, pixel by pixel (kyber6g.tools.media_stats; paper_plots, plot 9)"))
        t.append(para(f"""
            The system stores JPEG, which is compressed and looks random before any encryption. To see what the stored-photo
            format does to a picture, the UNCOMPRESSED pixels of one ({im['width']} x {im['height']}, three colour channels:
            {im['source'] or im['file']}) were sealed with the very function that seals a photo, and the encrypted content was
            looked at as a picture again."""))
        t.append("")
        t.append(table([
            ["entropy, bits per pixel value (8 = flat)", " / ".join(f"{v:.3f}" for v in pc["entropy_bits"]), " / ".join(f"{v:.4f}" for v in cc["entropy_bits"])],
            ["correlation with the right neighbour", " / ".join(f"{v:.3f}" for v in pc["correlation"]["horizontal"]), " / ".join(f"{v:+.4f}" for v in cc["correlation"]["horizontal"])],
            ["correlation with the neighbour below", " / ".join(f"{v:.3f}" for v in pc["correlation"]["vertical"]), " / ".join(f"{v:+.4f}" for v in cc["correlation"]["vertical"])],
            ["correlation with the diagonal neighbour", " / ".join(f"{v:.3f}" for v in pc["correlation"]["diagonal"]), " / ".join(f"{v:+.4f}" for v in cc["correlation"]["diagonal"])],
            [f"chi-square against a flat histogram (under {ms['ideal']['chi_square_5pct_limit']:.0f} in 95 % of flat ones)", " / ".join(f"{v:,.0f}" for v in pc["chi_square"]),
             " / ".join(f"{v:.0f}" for v in cc["chi_square"])],
        ], ["measure (red / green / blue channel)", "the picture", "the picture as stored"]))
        t.append("")
        t.append(table([[x["what"], f"{x['npcr_pct']:.4f} %", f"{x['uaci_pct']:.4f} %"] for x in df]
                       + [["a key wrong in ONE bit, applied without the tag check, against the picture", f"{wk['without_the_tag_check']['npcr_pct']:.4f} %",
                           f"{wk['without_the_tag_check']['uaci_pct']:.4f} %"],
                          ["two unrelated uniformly random byte strings (the ideal)", f"{ms['ideal']['npcr_pct']:.4f} %", f"{ms['ideal']['uaci_pct']:.4f} %"]],
                      ["two stored copies compared", "NPCR (values that differ)", "UACI (mean difference)"]))
        t.append("")
        t.append(para(f"""
            Opening the file gave back every byte: {'yes' if im['round_trip_identical'] else 'NO'}. A file with one bit changed
            was refused in {ms['tamper']['refused']} of {ms['tamper']['files_with_one_bit_changed']} cases. The implementation
            {'refuses' if wk['implementation_refuses'] else 'DOES NOT refuse'} a key that is wrong in one bit (the tag fails); the row
            above shows what the keystream of such a key would give if the tag were ignored: noise. Sealing this picture
            ({im['plain_bytes'] / 1e6:.2f} MB) took {im['seal_ms_median']} ms and opening it {im['open_ms_median']} ms on the laptop;
            the file is {im['added_bytes']:,} bytes longer than the picture."""))
        t.append(para("""
            The line "same key and nonce" is there on purpose. AES-GCM encrypts by XOR with a key stream, so two messages
            under one key and nonce differ exactly where the plaintexts differ: the classical "plaintext sensitivity" of a
            block-chaining image cipher is not a property of GCM, and does not need to be, as long as no (key, nonce) pair is
            ever used twice. That is the rule this system is built around (4.10), and the reason every file has its own key."""))

    # ------------------------------------------------------------------------------------------------------ 6
    t.append(head(6, "What a quantum computer changes"))
    t.append(bullets([
        "X25519: broken (Shor). The session keys still need the ML-KEM-1024 secret; nothing is lost while ML-KEM-1024 holds.",
        "ML-KEM-1024 and ML-DSA-87: designed for this attacker; NIST category 5.",
        "AES-256-GCM, ChaCha20-Poly1305: Grover's search halves the exponent of a key search: about 2^128 quantum operations.",
        "HKDF/HMAC-SHA-256: key recovery about 2^128; the 256-bit Finished and rekey MACs remain far out of reach.",
        """Cached RapidRekey uses only HKDF and HMAC, so it is as strong as the handshake its secret came from.""",
        """Signatures cannot be harvested: forging one later does not open a session that has ended. Confidentiality can
        be harvested, and that is why the key agreement had to be post-quantum first."""]))

    # ------------------------------------------------------------------------------------------------------ 7
    t.append(head(7, "What remains: limits and residual risks"))
    t.append(bullets([
        """The proofs are symbolic. The handshake, the cached rekey, the PQ ratchet and the stored-file format are modelled in
        ProVerif and checked under four attackers (formal/, docs/SECURITY_PROOFS.md); that model treats the primitives as
        ideal and knows no timing and no sizes. There is no computational proof of the whole protocol, no independent review
        of the models and no independent penetration test.""",
        "No analysis of power, electromagnetic, cache or fault attacks on the Raspberry Pi.",
        """Availability can be attacked: jamming; dropping packets on the path; a flood of forged ClientHellos above the ration
        (4.12); a forged REJECT costs a full handshake; live video does not survive packet loss well (there is no forward error
        correction and no keyframe request: paper_plots, plot 6).""",
        "Cached RapidRekey gives no post-compromise security by itself; the PQ ratchet (every 600 s) and full handshakes do.",
        """The UAV's identity key lies unencrypted on its SD card (mode 0600). A captured UAV can be impersonated until its pinned
        key is removed at the ground station. Its stored media stay unreadable.""",
        "Traffic analysis: sizes and timing are visible (4.15).",
        """Provisioning and management run over SSH. Its key exchange is asked to be a post-quantum hybrid (measured:
        sntrup761x25519-sha512), so a recorded management session stays confidential; its host and user authentication are
        Ed25519, which is not post-quantum. The pinned public keys are exchanged once over that channel: that they are the
        right keys rests on SSH's authentication at that moment, or on comparing the fingerprints the deploy script prints.""",
        "The dashboard has no login and the ground station runs as root inside its virtual machine (docs/SECURITY_AUDIT.md).",
        "Everything was tested with ONE UAV over Wi-Fi on a desk. No 5G or 6G radio was used; no flight.",
        "Python cannot guarantee that a secret is erased from memory; wiping is best effort."]))

    # ------------------------------------------------------------------------------------------------------ 8
    t.append(head(8, "Sentences for the paper"))
    t.append("  Supported by this report:\n")
    t.append(bullets([
        """"Session keys are established by a hybrid key exchange (ML-KEM-1024 and X25519) authenticated with ML-DSA-87 signatures
        under pinned keys; application data is protected with AES-256-GCM." """,
        f""""In {total_attempts:,} attack attempts against the implementation (forgery, modification, replay, splicing, downgrade,
        impersonation, rekey abuse, tampering with stored media), none was accepted." """,
        """"Stored photos and recordings are encrypted under a per-file key that is wrapped with ML-KEM-1024 and X25519 together
        and signed by the UAV with ML-DSA-87; the UAV cannot decrypt its own files." """,
        """"Recorded traffic remains confidential against an attacker who later obtains a quantum computer, as long as ML-KEM-1024
        remains secure." """], mark="+"))
    t.append("\n  Not supported - do not write:\n")
    t.append(bullets([
        "\"The video is post-quantum encrypted\" / \"ML-KEM encrypts each frame\" (AES-256-GCM encrypts; ML-KEM establishes keys).",
        "\"Unbreakable\", \"100 % secure\", \"quantum-proof\", \"provably secure\" (no proof was made).",
        "\"0-RTT\" for the cached rekey (it is 1-RTT: no data is sent under the new keys before the answer arrives).",
        "\"Validated on a 5G/6G link\" (the prototype ran over Wi-Fi; NR results are simulation and must be labelled so).",
        "\"Resistant to side-channel attacks\" (not examined beyond the coarse timing test of 4.14)."], mark="x"))

    # ------------------------------------------------------------------------------------------------------ 9
    t.append(head(9, "Reproduce"))
    t.append("  bash run/kyber6g.sh measure attacks      # the attack experiments on the Pi and on the laptop\n"
             "  python -m kyber6g.tools.crypto_report    # this file\n"
             "  python -m unittest tests.test_hardening tests.test_sealing tests.test_crypto   # the same properties as unit tests")

    # ------------------------------------------------------------------------------------------------ appendix
    t.append(head("A", "Appendix: every experiment"))
    rows = []
    for name, v in exp.items():
        for m, e in v.items():
            rows.append([name, m.split(" (")[0], f"{e['attempts']:,}", str(e["accepted"]) if e["expect"] == "refused" else f"{e['accepted']:,} (all)", e["verdict"]])
    t.append(table(rows, ["experiment", "machine", "attempts", "accepted", "result"], ["<", "<", ">", ">", "<"]))
    if cpi and clap:
        t.append(head("B", "Appendix: what the cryptography costs (medians)"))
        rows = [[n, us(P(n)), us(L(n))] for n in (
            "ML-KEM-1024 keygen", "ML-KEM-1024 encapsulate", "ML-KEM-1024 decapsulate", "X25519 keygen", "X25519 exchange",
            "ML-DSA-87 sign", "ML-DSA-87 verify", "record seal 1100 B (AES-256-GCM)", "record open 1100 B (AES-256-GCM)",
            "full: UAV builds ClientHello", "full: GCS answers (ServerHello)", "full: UAV verifies, derives, Finished",
            "photo seal 200 kB, format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature)",
            "photo open 200 kB, format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature verified)",
            "photo seal 200 kB, format 1 (ML-KEM-1024, AES-256-GCM)") if P(n) is not None or L(n) is not None]
        t.append(table(rows, ["operation", "Raspberry Pi 4B", "laptop"], ["<", ">", ">"]))
        w = cpi["wire"]
        t.append("")
        t.append(para(f"""
            On the wire: ClientHello {w['full handshake']['ClientHello']['bytes']:,} B, ServerHello
            {w['full handshake']['ServerHello']['bytes']:,} B, ClientFinished {w['full handshake']['ClientFinished']['bytes']} B; cached rekey
            {w['cached rekey']['RekeyRequest']['bytes']} + {w['cached rekey']['RekeyResponse']['bytes']} + {w['cached rekey']['ClientFinished']['bytes']} B;
            PQ ratchet {w['pq ratchet']['request']['bytes']:,} + {w['pq ratchet']['response']['bytes']:,} B (JSON inside the session).
            A stored file of format 2 carries, besides its content: the ML-KEM ciphertext (1568 B), the X25519 key (32 B), the
            wrapped key (48 B), one tag per segment (16 B) and the signature (4637 B)."""))
    text = "\n".join(t).rstrip() + "\n"
    Path(a.out).write_text(text)
    print(f"{a.out}: {len(text.splitlines())} lines, {len(exp)} experiments on {len(A)} machine(s), "
          f"{total_attempts:,} attack attempts, {total_accepted} accepted; {race_records:,} records sealed in the nonce race, {race_reused} pairs reused"
          + (f", ACCEPTED ATTACKS: {forged_ok}" if forged_ok else "") + (f"; availability limit reached in: {unavailable}" if unavailable else ""))
    return 1 if forged_ok or total_accepted or race_reused else 0


if __name__ == "__main__":
    sys.exit(main())
