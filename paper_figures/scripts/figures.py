#!/usr/bin/env python3
"""The figures of the paper, described with figlib (fourth version: pastel components with dark outlines in the
manner of the figures4papers schematics; pictures and pictograms, few words).
Every label states something the implementation does (kyber6g/crypto, kyber6g/transport, kyber6g/recording,
kyber6g/ground) or, for the evaluation workflow, something the repository documents. Coordinates are draw.io units."""
from figlib import (ACC_KEY, ACC_SYM, FS_L, FS_M, FS_MIN, FS_S, GCS_C, GCS_F, GLYPH_COLOUR, GREY, INK, KEY_F, LINE, PALE, SYM_F, THR_C, THR_F,
                    UAV_C, UAV_F, W1, W2, WHITE, Fig, col, measure, small, var)

SUP32 = f'0<sup style="font-size:{FS_MIN}px;line-height:0">32</sup>'


def icon(f, role, cx, y, label=None, size=28, fs=FS_M, bold=False, colour=None, lw=90):
    """A pictogram centred at cx with its label underneath. A bold label is a name: it wears the pictogram's colour."""
    colour = colour or GLYPH_COLOUR.get(role, INK)
    f.glyph(role, cx - size / 2, y, size, colour)
    if label:
        lines = label.count("<br>") + 1
        f.text(cx - lw / 2, y + size + 1, lw, 1.2 * fs * lines + 1, label, fs=fs, bold=bold, valign="top", colour=colour if bold else INK)


def P(f, x, y, label, colour=ACC_KEY, fs=FS_S, h=16, centre=False):
    """A pill just wide enough for its label; returns its width. With centre=True, x is the middle."""
    w = round(measure(f"<b>{label}</b>", fs)[0] + 14, 1)
    f.pill(x - w / 2 if centre else x, y, w, h, label, colour, fs)
    return w


def pill_row(f, cx, y, items, gap=5, fs=FS_S, h=16):
    """Pills side by side, the row centred on cx. items: (label, colour)."""
    widths = [round(measure(f"<b>{t}</b>", fs)[0] + 14, 1) for t, _ in items]
    x = cx - (sum(widths) + gap * (len(items) - 1)) / 2
    for (t, c), w in zip(items, widths):
        f.pill(x, y, w, h, t, c, fs)
        x += w + gap


def boxes_on_frame(f, x, y, w, h):
    """Two outline boxes on a frame picture: the idea of a detection overlay (schematic, not a detector output)."""
    f.cell(x + 0.20 * w, y + 0.37 * h, 0.17 * w, 0.25 * h, fill="none", stroke=THR_C, sw=1.6)
    f.cell(x + 0.29 * w, y + 0.60 * h, 0.12 * w, 0.18 * h, fill="none", stroke=THR_C, sw=1.6)


def fig01_system_overview():
    W, H = W2, 262.0
    f = Fig("fig01_system_overview", W, H, "System overview: what travels between the UAV and the ground station, and how it is protected")
    # who is who
    f.glyph("uav", 6, 4, 34)
    f.text(46, 5, 150, 15, "UAV node", fs=FS_L, bold=True, align="left", colour=UAV_C)
    f.text(46, 21, 150, 13, "Raspberry Pi 4B, camera, GNSS", fs=FS_S, align="left")
    f.glyph("laptop", 552, 4, 34)
    f.text(592, 5, 126, 15, "Ground station", fs=FS_L, bold=True, align="left", colour=GCS_C)
    f.text(592, 21, 126, 13, "laptop, operator", fs=FS_S, align="left")
    f.glyph("adversary", 346, 2, 26)
    f.text(279, 28, 160, 13, "<i>untrusted Wi-Fi / IP network</i>", fs=FS_S, colour=THR_C)
    # the secure link on both sides
    bx, bw, gx, by, bh = 180, 88, 450, 62, 172
    for x, tint in ((bx, UAV_F), (gx, GCS_F)):
        f.box(x, by, bw, bh, fill=tint)
    yl = [78, 118, 164, 210]                                    # lanes: keys, video, telemetry, control
    f.glyph("lock", bx + bw / 2 - 11, 130, 22)
    f.pill(bx + 8, 156, bw - 16, 17, "AES-256-GCM", ACC_SYM, fs=FS_S)
    f.text(bx, 176, bw, 24, "one key per stream<br>and direction", fs=FS_S)
    f.glyph("unlock", gx + bw / 2 - 11, 130, 22)
    f.pill(gx + 8, 156, bw - 16, 17, "AES-256-GCM", ACC_SYM, fs=FS_S)
    f.text(gx, 176, bw, 24, "replay window,<br>tag check", fs=FS_S)
    cx0, cx1 = bx + bw, gx
    mid = (cx0 + cx1) / 2
    # lane 0: session establishment
    f.edge([(cx0, yl[0]), (cx1, yl[0])], "key", "both")
    pill_row(f, mid, 43, [("ML-KEM-1024", ACC_KEY), ("X25519", ACC_KEY), ("ML-DSA-87", ACC_KEY)], gap=3)
    f.text(cx0, yl[0] + 2, cx1 - cx0, 13, "<i>session keys, mutual authentication</i>", fs=FS_S)
    # lane 1: video
    y = yl[1]
    f.glyph("camera", 4, y - 12, 24)
    f.pic("frame.jpg", 34, y - 15.75, 56, 31.5)
    f.box(106, y - 11, 56, 22, "H.264", fs=FS_M)
    f.edge([(90, y), (106, y)])
    f.edge([(162, y), (bx, y)])
    f.pic("cipher.png", mid - 20, y - 11.25, 40, 22.5)
    f.edge([(cx0, y), (mid - 20, y)])
    f.edge([(mid + 20, y), (cx1, y)])
    f.text(cx0 + 4, y - 15, 60, 13, "<i>video</i>", fs=FS_S, align="left")
    f.pic("frame.jpg", 562, y - 15.75, 56, 31.5)
    boxes_on_frame(f, 562, y - 15.75, 56, 31.5)
    f.edge([(gx + bw, y), (562, y)])
    f.text(624, y - 13, 94, 26, "live view,<br>object detection", fs=FS_M, align="left")
    # lane 2: telemetry, images, status
    y = yl[2]
    f.glyph("gnss", 4, y - 12, 24)
    f.text(34, y - 13, 110, 26, "position (1 Hz),<br>photos, status", fs=FS_M, align="left")
    f.edge([(118, y), (bx, y)], fat=True)
    f.pic("cipher.png", mid - 20, y - 11.25, 40, 22.5)
    f.edge([(cx0, y), (mid - 20, y)])
    f.edge([(mid + 20, y), (cx1, y)])
    f.text(cx0 + 4, y - 15, 66, 13, "<i>telemetry</i>", fs=FS_S, align="left")
    f.glyph("database", 566, y - 12, 24)
    f.edge([(gx + bw, y), (562, y)], attach=False)
    f.text(596, y - 13, 120, 26, "stored, checked<br>(SQLite, SHA-256)", fs=FS_M, align="left")
    # lane 3: control (ground to air)
    y = yl[3]
    f.glyph("operator", 566, y - 12, 24)
    f.text(596, y - 7, 120, 14, "operator commands", fs=FS_M, align="left")
    f.edge([(562, y), (gx + bw, y)], "cmd", attach=False)
    f.pic("cipher.png", mid - 20, y - 11.25, 40, 22.5)
    f.edge([(cx1, y), (mid + 20, y)], "cmd")
    f.edge([(mid - 20, y), (cx0, y)], "cmd")
    f.text(cx1 - 64, y - 15, 60, 13, "<i>control</i>", fs=FS_S, align="right")
    f.edge([(bx, y), (118, y)], "cmd", attach=False)
    f.glyph("command", 4, y - 12, 24)
    f.text(34, y - 13, 84, 26, "camera, record,<br>rekey", fs=FS_M, align="left")
    f.legend(200, 250, [("flow", "data in AEAD records"), ("cmd", "commands"), ("key", "key establishment")])
    return f


def fig02_threat_model():
    W, H = W1, 364.0
    f = Fig("fig02_threat_model", W, H, "Threat model and the countermeasure for each threat")
    icon(f, "uav", 26, 2, "UAV", size=30, bold=True, lw=52)
    icon(f, "laptop", W - 26, 2, "GCS", size=30, bold=True, lw=52)
    f.edge([(48, 17), (W - 48, 17)], "flow", "both", attach=False)
    f.glyph("adversary", W / 2 - 14, 24, 28)
    f.text(W / 2 - 100, 53, 200, 24, "<i>network adversary: reads, drops, replays,<br>modifies, injects, stores for later</i>", fs=FS_S, colour=THR_C)
    rows = [("eye", "Eavesdropping", "store now, decrypt later"), ("mask", "Impersonation", "man in the middle"),
            ("replay", "Replay", "duplicates, reordering"), ("edit", "Tampering", "modify, inject"),
            ("downgrade", "Downgrade", "weaker algorithm suite"), ("key_off", "Key compromise", "past and future traffic"),
            ("sd", "Seized UAV", "stored photos, video"), ("file_lock", "Forged file", "planted recording"),
            ("packet", "Handshake flood", "forged ClientHellos")]
    y0, pitch, xa = 90, 30, 136
    for i, (g, name, sub) in enumerate(rows):
        y = y0 + pitch * i
        f.glyph(g, 4, y + 3, 20, THR_C)
        f.text(29, y, 104, 26, f"<b>{name}</b><br>{small(sub)}", fs=FS_M, align="left")
        f.edge([(xa - 9, y + 13), (xa, y + 13)], attach=False)

    def pills(i, items, note=None):
        x, y = xa + 4, y0 + pitch * i + 5
        for label, colour in items:
            w = round(measure(f"<b>{label}</b>", FS_S)[0] + 10, 1)
            f.pill(x, y, w, 16, label, colour, fs=FS_S)
            x += w + 3
        if note:
            f.text(x + 1, y, W - x - 1, 16, note, fs=FS_S, align="left")

    pills(0, [("ML-KEM-1024", ACC_KEY), ("X25519", ACC_KEY), ("AES-256-GCM", ACC_SYM)])
    pills(1, [("ML-DSA-87", ACC_KEY)], "pinned keys, Finished MACs")
    y = y0 + pitch * 2
    for k in range(14):                                          # a piece of the sliding window: seen / not seen
        f.cell(xa + 4 + 7 * k, y + 8, 7, 10, fill=ACC_SYM if k in (0, 1, 2, 3, 5, 6, 9) else WHITE)
    f.text(xa + 106, y + 5, 96, 16, "window of 2048", fs=FS_S, align="left")
    pills(3, [("GCM tag", ACC_SYM)], "over header and payload")
    pills(4, [("ML-DSA-87", ACC_KEY)], "signs the suite identifier")
    pills(5, [("epoch chain", ACC_SYM), ("PQ ratchet", ACC_KEY)], "fresh secrets")
    pills(6, [("ML-KEM-1024", ACC_KEY), ("X25519", ACC_KEY)], "wrap the file key")
    pills(7, [("ML-DSA-87", ACC_KEY)], "signs every stored file")
    pills(8, [("ration", ACC_SYM)], "of signature checks, answer cache")
    return f


def fig03_handshake():
    W, H = W2, 300.0
    f = Fig("fig03_handshake", W, H, "Hybrid post-quantum handshake (1.5 round trips)")
    xu, xg = 118.0, 600.0
    icon(f, "uav", xu, 2, "UAV", size=28, bold=True, lw=50)
    icon(f, "laptop", xg, 2, "GCS", size=28, bold=True, lw=50)
    for x in (xu, xg):
        f.edge([(x, 48), (x, 294)], "rule", dashed=True, attach=False)
    ss = lambda s: var("ss", s)
    TH = "<i>TH</i>"

    def fields(x, y, items):
        """A message drawn as its fields: plain cells for values, pills for public-key material and MACs."""
        for label, kind in items:
            if kind == "cell":
                w = round(measure(label, FS_S)[0] + 10, 1)
                f.cell(x, y, w, 15, label)
            else:
                w = P(f, x, y - 0.5, label, ACC_KEY if kind == "pq" else ACC_SYM)
            x += w + 4
        return x

    # 1 ClientHello
    f.pic("lattice.svg", 4, 50, 46, 32.2, border=None)
    f.pic("curve.svg", 58, 50, 46, 32.2, border=None)
    f.text(0, 84, 112, 24, "fresh ML-KEM-1024 and<br>X25519 key pairs", fs=FS_S)
    y = 78
    f.text(xu + 8, y - 21, 62, 14, "ClientHello", fs=FS_M, bold=True, align="left")
    fields(xu + 74, y - 21, [("suite", "cell"), ("UAV ID", "cell"), (var("N", "C"), "cell"), ("cell", "cell"), ("time", "cell"),
                             ("X25519 key", "pq"), ("ML-KEM key", "pq"), ("ML-DSA-87 sig.", "pq")])
    f.edge([(xu, y), (xg, y)], attach=False)
    # 2 ServerHello
    f.text(xg + 8, 92, 110, 48, "verify the signature<br>(pinned UAV key),<br>encapsulate, derive<br>keys, sign", fs=FS_S, align="left", valign="top")
    y = 160
    f.text(xg - 70, y - 21, 62, 14, "ServerHello", fs=FS_M, bold=True, align="right")
    fields(xu + 8, y - 21, [("session ID", "cell"), (var("N", "S"), "cell"), ("X25519 key", "pq"), ("ML-KEM ciphertext", "pq"),
                            ("ML-DSA-87 sig.", "pq"), ("MAC", "sym")])
    f.edge([(xg, y), (xu, y)], attach=False)
    # 3 ClientFinished
    f.text(0, 172, xu - 8, 48, "verify the signature<br>(pinned GCS key),<br>decapsulate, derive<br>keys, check the MAC", fs=FS_S, align="right", valign="top")
    y = 238
    f.text(xu + 8, y - 21, 76, 14, "ClientFinished", fs=FS_M, bold=True, align="left")
    fields(xu + 90, y - 21, [("session ID", "cell"), ("MAC", "sym")])
    f.edge([(xu, y), (xg, y)], attach=False)
    f.text(xg + 8, 226, 110, 24, "check the MAC:<br>session confirmed", fs=FS_S, align="left", valign="top")
    # keys
    f.glyph("key", xu + 120, 250, 20)
    f.text(xu + 144, 253, 300, 15, f"session keys = HKDF({ss('KEM')} || {ss('X')}, salt = {TH})", fs=FS_M, align="left")
    f.edge([(xu, 284), (xg, 284)], "flow", "both", attach=False)
    f.text(xu, 270, xg - xu, 13, "<i>application records under AES-256-GCM</i>", fs=FS_S)
    return f


def fig04_key_schedule():
    W, H = W1, 352.0
    f = Fig("fig04_key_schedule", W, H, "Key schedule: from the two shared secrets to the per-stream epoch keys")
    # the two shared secrets
    f.pic("lattice.svg", 22, 2, 60, 42, border=None)
    f.pic("curve.svg", 126, 2, 60, 42, border=None)
    P(f, 52, 45, "ML-KEM-1024", ACC_KEY, centre=True)
    P(f, 156, 45, "X25519", ACC_KEY, centre=True)
    f.op("concat", 104, 90)
    f.edge([(52, 61), (52, 90), (96.5, 90)], "key")
    f.edge([(156, 61), (156, 90), (111.5, 90)], "key")
    f.text(57, 64, 40, 13, var("ss", "KEM"), fs=FS_S, align="left")
    f.text(161, 64, 30, 13, var("ss", "X"), fs=FS_S, align="left")
    # transcript hash
    f.glyph("file", 258, 2, 24)
    f.text(284, 2, 56, 24, "handshake<br>transcript", fs=FS_S, align="left")
    P(f, 270, 44, "SHA-256", ACC_SYM, centre=True)
    f.edge([(270, 27), (270, 44)], attach=False)
    # extract, expand
    f.pill(52, 112, 104, 18, "HKDF-Extract", ACC_SYM)
    f.edge([(104, 97.5), (104, 112)], "key")
    f.text(109, 98, 30, 12, "<i>IKM</i>", fs=FS_S, align="left")
    f.edge([(270, 60), (270, 121), (156, 121)])
    f.text(176, 107, 80, 12, "<i>TH</i> as salt", fs=FS_S)
    f.pill(52, 152, 104, 18, "HKDF-Expand", ACC_SYM)
    f.edge([(104, 130), (104, 152)], "key")
    f.text(109, 134, 30, 12, "<i>PRK</i>", fs=FS_S, align="left")
    f.text(164, 149, 170, 24, "<i>label: purpose, suite,<br>session ID</i>", fs=FS_S, align="left")
    # first-level secrets
    yk = 198
    icon(f, "keys", 40, yk, "Finished keys", size=22, fs=FS_S, lw=80)
    icon(f, "key", 124, yk, "master secret", size=22, fs=FS_S, lw=80)
    icon(f, "refresh", 262, yk, "resumption secret<br>(cached rekey)", size=22, fs=FS_S, lw=110)
    f.edge([(84, 170), (84, 184), (40, 184), (40, yk - 2)], "key", attach=False)
    f.edge([(124, 170), (124, yk - 2)], "key", attach=False)
    f.edge([(138, yk + 11), (248, yk + 11)], "key", attach=False)
    # one chain per stream and direction
    yc = 262
    f.box(33, yc, 274, 28)
    x = 39
    for name, w in (("control", 44), ("telemetry", 52), ("image", 38), ("video", 36), ("recording", 54), ("status", 38)):
        f.cell(x, yc + 6, w, 16, name, fill=PALE if name == "video" else WHITE)
        x += w
    f.edge([(124, 237), (124, yc)], "key", attach=False)
    f.text(132, 247, 190, 12, "<i>one chain per stream and direction</i>", fs=FS_S, align="left")
    # the epoch chain of one stream
    ye = 312
    for i, cx in enumerate((70, 160, 250)):
        icon(f, "key", cx, ye, var("key", str(i)), size=20, fs=FS_S, lw=50)
    f.edge([(203, yc + 22), (203, yc + 37), (70, yc + 37), (70, ye - 2)], "key")
    for a in (84, 174):
        f.edge([(a, ye + 10), (a + 62, ye + 10)], "key", attach=False)
        f.text(a, ye - 5, 62, 12, "30 s", fs=FS_S)
    f.text(268, ye - 2, 72, 24, "<i>old value<br>erased</i>", fs=FS_S, align="left")
    return f


def fig05_session_lifecycle():
    W, H = W2, 212.0
    f = Fig("fig05_session_lifecycle", W, H, "Session lifecycle: link states and the key-refresh schedule")
    # ---- (a) link states on the UAV (UavLink._manage)
    it = lambda s: f"<i>{s}</i>"
    f.box(6, 44, 68, 24, "DOWN", bold=True)
    f.box(136, 44, 100, 24, "HANDSHAKING", bold=True, fill=KEY_F)
    f.box(298, 44, 94, 24, "CONFIRMING", bold=True, fill=KEY_F)
    f.box(136, 116, 100, 24, "RECOVERING", bold=True, fill=THR_F)
    f.pill(311, 116, 68, 24, "UP", UAV_C, fs=FS_M)
    f.edge([(74, 56), (136, 56)]);                               f.text(76, 42, 58, 12, it("start, retry"), fs=FS_S)
    f.edge([(236, 56), (298, 56)]);                              f.text(238, 42, 58, 12, it("keys set"), fs=FS_S)
    f.edge([(345, 68), (345, 116)], fat=False);                           f.text(351, 80, 60, 24, it("first valid<br>record"), fs=FS_S, align="left")
    f.edge([(311, 128), (236, 128)]);                            f.text(238, 131, 72, 12, it("5 s silence"), fs=FS_S)
    f.text(262, 150, 166, 24, it("rekey, PQ ratchet, change of cell:<br>new session in place, link stays up"), fs=FS_S)
    f.edge([(186, 116), (186, 68)], fat=False);                           f.text(192, 80, 70, 24, it("rekey, else<br>handshake"), fs=FS_S, align="left")
    f.edge([(156, 68), (156, 86), (40, 86), (40, 68)]);          f.text(58, 88, 80, 12, it("failed"), fs=FS_S)
    f.edge([(345, 44), (345, 26), (40, 26), (40, 44)]);          f.text(120, 12, 150, 12, it("no confirmation in 5 s"), fs=FS_S)
    f.panel("a", 5, 0, "Link states on the UAV")
    # ---- (b) key refresh in an established session (LinkConfig defaults)
    x0, t0, t1 = 424.0, 512.0, 700.0
    X = lambda t: t0 + (t1 - t0) * t / 600
    rows = [("Full handshake", 30, [0], ACC_KEY, 10, 2.0), ("Epoch rotation", 56, range(30, 601, 30), LINE, 6, 1.33),
            ("Cached rekey", 82, range(120, 601, 120), ACC_SYM, 10, 2.0), ("PQ ratchet", 108, [600], ACC_KEY, 10, 2.0)]
    for name, y, times, colour, tall, width in rows:
        f.text(x0, y - 12, 84, 13, name, fs=FS_M, align="left")
        f.edge([(t0, y), (t1, y)], "rule", attach=False)
        for t in times:
            f.edge([(X(t), y), (X(t), y - tall)], "plain", "none", colour=colour, width=width, attach=False, jump=False, curved=False)
    for t in range(0, 601, 120):
        f.text(X(t) - 20, 112, 40, 12, f"{t} s" if t == 600 else str(t), fs=FS_S)
    notes = [("epoch rotation", ACC_SYM, "one-way HKDF chain, no messages"), ("1-RTT Cached RapidRekey", ACC_SYM, "resumption secret, HMAC"),
             ("PQ ratchet", ACC_KEY, "fresh ML-KEM-1024 + X25519")]
    for i, (name, colour, how) in enumerate(notes):
        y = 132 + 20 * i
        w = P(f, x0, y, name, colour)
        f.text(x0 + w + 5, y, W - x0 - w - 5, 16, how, fs=FS_S, align="left")
    f.panel("b", x0, 0, "Key refresh in one session (default intervals)")
    return f


def fig06_record_layer():
    W, H = W1, 256.0
    f = Fig("fig06_record_layer", W, H, "Sealing one chunk into an AEAD record")
    # plain chunk -> xor -> ciphertext
    f.text(4, 3, 72, 13, "Encoded frame", fs=FS_M)
    f.pic("frame.jpg", 4, 18, 72, 40.5)
    f.op("slice", 100, 38)
    f.edge([(76, 38), (92.5, 38)])
    f.text(112, 12, 80, 13, "chunks ≤ 1100 B", fs=FS_S)
    for i in range(3):
        f.cell(122 + 20 * i, 29, 18, 18, fill=PALE)
    f.edge([(107.5, 38), (122, 38)])
    f.op("xor", 214, 38)
    f.edge([(180, 38), (206.5, 38)])
    f.pic("cipher.png", 256, 18, 72, 40.5)
    f.edge([(221.5, 38), (256, 38)])
    f.text(256, 3, 72, 13, "Ciphertext", fs=FS_M)
    # keystream
    f.pill(164, 86, 100, 20, "AES-256 (CTR)", ACC_SYM)
    f.edge([(214, 86), (214, 45.5)])
    f.text(219, 60, 54, 13, "<i>keystream</i>", fs=FS_S, align="left")
    f.glyph("key", 6, 83, 26)
    f.text(34, 81, 60, 13, "epoch key", fs=FS_M, align="left")
    f.edge([(34, 96), (164, 96)], "key")
    # nonce
    f.glyph("counter", 6, 127, 26)
    f.text(3, 154, 60, 13, "sequence no.", fs=FS_S, align="left")
    f.op("concat", 84, 140)
    f.text(72, 107, 24, 13, SUP32, fs=FS_S)
    f.edge([(84, 121), (84, 132.5)], "plain")
    f.edge([(32, 140), (76.5, 140)])
    f.edge([(91.5, 140), (190, 140), (190, 106)])
    f.text(112, 126, 40, 13, "<i>nonce</i>", fs=FS_S)
    # tag
    f.pill(232, 166, 64, 20, "GHASH", ACC_SYM)
    f.edge([(288, 58.5), (288, 166)])
    f.cell(104, 168, 76, 16, "header, ext")
    f.edge([(180, 176), (232, 176)])
    f.text(190, 162, 34, 13, "<i>AAD</i>", fs=FS_S)
    # the record on the wire
    y = 214
    f.text(4, y - 15, 200, 13, "Record = one UDP datagram", fs=FS_M, align="left")
    f.cell(4, y, 86, 22, "header", fs=FS_M)
    f.cell(90, y, 44, 22, "ext", fs=FS_M)
    f.cell(134, y, 150, 22, "ciphertext", fs=FS_M, fill=SYM_F)
    f.cell(284, y, 52, 22, "tag", fs=FS_M, fill=SYM_F)
    f.edge([(264, 186), (264, 200), (310, 200), (310, y)])
    f.text(4, y + 24, 130, 13, "authenticated, in clear", fs=FS_S, italic=True)
    f.text(134, y + 24, 202, 13, "encrypted and authenticated", fs=FS_S, italic=True)
    return f


def fig07_video_pipeline():
    W, H = W2, 172.0
    f = Fig("fig07_video_pipeline", W, H, "Live video from the camera to the decoded frame on the ground station")
    # ---- UAV row, left to right
    y = 50.0
    f.glyph("camera", 6, y - 13, 26, UAV_C)
    f.text(4, y + 14, 60, 13, "UAV", fs=FS_M, bold=True, align="left", colour=UAV_C)
    for k in range(3):                                           # a short stack of frames
        f.pic("frame.jpg", 42 + 6 * k, y - 25.5 + 6 * k, 48, 27)
    f.text(34, 8, 80, 13, "1280 × 720, 30 fps", fs=FS_S)
    f.box(118, y - 11, 84, 22, "H.264 encoder")
    f.edge([(102, y), (118, y)])
    f.text(204, 22, 80, 13, "<i>IDR every 30 frames</i>", fs=FS_S)
    for k, name in enumerate("IPPP"):
        f.cell(218 + 14 * k, y - 9, 14, 18, name, fill=PALE if name == "I" else WHITE, bold=name == "I")
    f.edge([(202, y), (218, y)])
    f.op("slice", 298, y)
    f.edge([(274, y), (290.5, y)])
    f.text(306, 22, 76, 13, "chunks ≤ 1100 B", fs=FS_S)
    for k in range(4):
        f.cell(320 + 13 * k, y - 7, 13, 14, fill=PALE)
    f.edge([(305.5, y), (320, y)])
    w = P(f, 392, y - 9, "AES-256-GCM", ACC_SYM, fs=FS_M, h=18)
    f.edge([(372, y), (392, y)])
    f.glyph("lock", 392 + w / 2 - 8, y - 28, 16)
    xe = 392 + w
    f.text(xe + 12, 22, 110, 13, "UDP datagrams", fs=FS_S)
    for k in range(3):
        f.pic("cipher.png", xe + 22 + 32 * k, y - 8, 28, 15.75)
    f.edge([(xe, y), (xe + 22, y)])
    xa = 650.0
    f.glyph("antenna", xa - 14, y - 14, 28)
    f.edge([(xe + 114, y), (xa - 16, y)], attach=False)
    f.text(xe - 30, y + 13, 200, 13, "<i>capture time travels inside the ciphertext</i>", fs=FS_S)
    # ---- the hop
    y2 = 132.0
    f.edge([(xa, y + 16), (xa, y2 - 16)], attach=False)
    f.glyph("wifi", xa + 22, 81, 20)
    f.text(xa + 4, y + 16, 14, y2 - y - 32, "<i>Wi-Fi/IP</i>", fs=FS_S, rotate=True)
    # ---- GCS row, right to left
    f.glyph("antenna", xa - 14, y2 - 14, 28)
    px = 528.0
    w = P(f, px, y2 - 9, "AES-256-GCM", ACC_SYM, fs=FS_M, h=18)
    f.glyph("unlock", px + w / 2 - 8, y2 - 28, 16)
    f.edge([(xa - 16, y2), (px + w, y2)], attach=False)
    for k, name in enumerate("3142"):                            # chunks arrive out of order
        f.cell(456 + 13 * k, y2 - 7, 13, 14, name, fs=FS_MIN)
    f.edge([(px, y2), (508, y2)])
    f.box(352, y2 - 11, 88, 22, "reorder, 150 ms")
    f.edge([(456, y2), (440, y2)])
    f.box(244, y2 - 11, 92, 22, "H.264 decoder")
    f.edge([(352, y2), (336, y2)])
    f.pic("frame.jpg", 166, y2 - 17.5, 62, 35)
    boxes_on_frame(f, 166, y2 - 17.5, 62, 35)
    f.edge([(244, y2), (228, y2)])
    f.glyph("monitor", 112, y2 - 13, 26)
    f.edge([(166, y2), (142, y2)], attach=False)
    f.text(4, y2 - 13, 104, 26, col("<b>GCS</b>", GCS_C) + "<br>live view, detector", fs=FS_M, align="right")
    f.text(244, y2 + 13, 196, 13, "<i>incomplete frame: wait for the next IDR</i>", fs=FS_S)
    return f


def fig08_perception_hitl():
    W, H = W2, 206.0
    f = Fig("fig08_perception_hitl", W, H, "Perception and the operator loop on the ground station")
    it = lambda s: f"<i>{s}</i>"
    yt, yb, ym = 40.0, 124.0, 84.0
    f.pic("frame.jpg", 6, ym - 20.25, 72, 40.5)
    f.text(4, ym + 22, 80, 24, "decoded frame,<br>capture time", fs=FS_S)
    # finder (top) and detector (bottom)
    f.edge([(78, ym), (104, ym), (104, yt), (126, yt)], attach=False)
    f.edge([(78, ym), (104, ym), (104, yb), (126, yb)], attach=False)
    f.glyph("search", 130, yt - 13, 26)
    f.text(160, yt - 13, 110, 26, "<b>Finder</b><br>" + small("OWLv2, text query"), fs=FS_M, align="left")
    f.box(288, yt - 11, 110, 22, small("shown after 2 passes"))
    f.edge([(256, yt), (288, yt)], attach=False)
    f.glyph("detect", 130, yb - 13, 26)
    f.text(160, yb - 13, 110, 26, "<b>Detector</b><br>" + small("YOLOE-11s or 11L"), fs=FS_M, align="left")
    f.box(288, yb - 11, 60, 22, "ByteTrack")
    f.edge([(256, yb), (288, yb)], attach=False)
    f.box(362, yb - 11, 64, 22, "label vote")
    f.edge([(348, yb), (362, yb)])
    f.glyph("database", 307, yb + 24, 22)
    f.edge([(318, yb + 11), (318, yb + 23)], attach=False)
    f.text(332, yb + 28, 110, 13, "tracks, detections", fs=FS_S, align="left")
    # overlay
    ox = 446.0
    f.pic("frame.jpg", ox, ym - 20.25, 72, 40.5)
    boxes_on_frame(f, ox, ym - 20.25, 72, 40.5)
    f.edge([(398, yt), (ox + 36, yt), (ox + 36, ym - 20.25)])
    f.edge([(426, yb), (ox + 36, yb), (ox + 36, ym + 20.25)])
    f.text(ox + 44, yt - 7, 110, 26, it("boxes placed by<br>capture time"), fs=FS_S, align="left")
    # operator
    px = 580.0
    f.edge([(ox + 72, ym), (px - 18, ym)], attach=False)
    icon(f, "operator", px, ym - 15, "operator", size=30, bold=True, lw=60)
    icon(f, "uav", 682, ym - 14, "UAV", size=28, bold=True, lw=50)
    f.edge([(px + 18, ym), (664, ym)], "cmd", attach=False)
    f.text(px + 18, ym - 28, 66, 26, it("commands,<br>AEAD"), fs=FS_S)
    # teaching
    f.edge([(px, ym + 32), (px, 190), (143, 190), (143, yb + 15)], "cmd", attach=False)
    f.glyph("tap", 474, 168, 18)
    f.glyph("teach", 216, 168, 18)
    f.text(240, 174, 230, 13, it("TEACH: a drawn box becomes a visual prompt"), fs=FS_S)
    return f


def fig09_recording_at_rest():
    """Stored photos and recordings, file format 2 (kyber6g/recording/sealing.py, photos.py, recorder.py)."""
    W, H = W1, 372.0
    f = Fig("fig09_recording_at_rest", W, H, "Stored photos and recordings: written and signed on the UAV, readable only on the ground station")
    f.text(4, 2, 40, 14, "UAV", fs=FS_M, bold=True, align="left", colour=UAV_C)
    # photo or frames -> segments -> ciphertext -> file
    y = 34.0
    f.glyph("photo", 3, y - 9, 18)
    f.glyph("film", 21, y - 9, 18)
    f.op("slice", 55, y)
    f.edge([(39, y), (47.5, y)], attach=False)
    f.text(46, 8, 90, 13, "photo, or segments", fs=FS_S)
    for k in range(3):
        f.cell(71 + 13 * k, y - 7, 13, 14, fill=PALE)
    f.edge([(62.5, y), (71, y)])
    f.pill(128, y - 9, 86, 18, "AES-256-GCM", ACC_SYM)
    f.edge([(110, y), (128, y)])
    f.pic("cipher.png", 232, y - 13.5, 48, 27)
    f.edge([(214, y), (232, y)])
    icon(f, "sd", 316, y - 13, "file", size=26, fs=FS_S, lw=40)
    f.edge([(280, y), (301, y)], attach=False)
    # content key
    yk = 88.0
    f.glyph("random", 160, yk - 11, 22)
    f.edge([(171, yk - 12), (171, y + 9)], "key", attach=False)
    f.text(40, yk - 12, 116, 24, "<i>CEK</i>: 32 random bytes,<br>one per file, never stored", fs=FS_S, align="right")
    f.pill(212, yk - 9, 86, 18, "AES-256-GCM", ACC_SYM)
    f.edge([(184, yk), (212, yk)], "key", attach=False)
    f.glyph("file_key", 308, yk - 11, 22)
    f.edge([(298, yk), (307, yk)], "key", attach=False)
    f.text(274, yk + 12, 56, 13, "wrapped <i>CEK</i>", fs=FS_S)
    # key-encryption key from BOTH shared secrets
    ym = 142.0
    f.pic("lattice.svg", 6, ym - 19, 46, 32.2, border=None)
    w1 = P(f, 58, ym - 12, "ML-KEM-1024", ACC_KEY)
    f.text(58, ym + 6, 112, 13, "Encaps(<i>ek</i> of the GCS)", fs=FS_S, align="left")
    yx = ym + 46
    f.pic("curve.svg", 6, yx - 19, 46, 32.2, border=None)
    w2 = P(f, 58, yx - 12, "X25519", ACC_KEY)
    f.text(58, yx + 6, 150, 13, "new key × <i>X25519 key</i> of the GCS", fs=FS_S, align="left")
    xc, yc = 196.0, ym + 23
    f.op("concat", xc, yc)
    f.edge([(58 + w1, ym - 4), (xc, ym - 4), (xc, yc - 7.5)], "key")
    f.edge([(58 + w2, yx - 4), (xc, yx - 4), (xc, yc + 7.5)], "key")
    f.text(150, ym - 18, 40, 12, var("ss", "KEM"), fs=FS_S)
    f.text(120, yx - 18, 40, 12, var("ss", "X"), fs=FS_S)
    f.pill(224, yc - 9, 52, 18, "HKDF", ACC_SYM)
    f.edge([(xc + 7.5, yc), (224, yc)], "key")
    f.edge([(262, yc - 9), (262, yk + 9)], "key")
    f.text(267, ym - 22, 30, 12, "<i>KEK</i>", fs=FS_S, align="left")
    f.text(214, yx + 6, 124, 13, "<i>ct</i>, new key: file header", fs=FS_S, align="left")
    # signature of the UAV over the whole file
    ys = 238.0
    f.glyph("file_lock", 6, ys - 11, 22)
    f.text(2, ys + 12, 44, 13, "whole file", fs=FS_S)
    w3 = P(f, 52, ys - 9, "SHA-256", ACC_SYM, h=18)
    f.edge([(28, ys), (52, ys)], attach=False)
    x4 = 52 + w3 + 16
    w4 = P(f, x4, ys - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(52 + w3, ys), (x4, ys)])
    f.text(x4 - 14, ys + 11, w4 + 28, 13, "UAV identity key", fs=FS_S)
    f.glyph("signature", x4 + w4 + 20, ys - 11, 22)
    f.edge([(x4 + w4, ys), (x4 + w4 + 19, ys)], attach=False)
    f.text(x4 + w4 + 46, ys - 13, W - (x4 + w4 + 46) - 4, 26, "signature, last<br>part of the file", fs=FS_S, align="left")
    # ground station
    yr = 280.0
    f.edge([(6, yr), (W - 6, yr)], "rule", dashed=True, attach=False)
    f.text(4, yr - 15, W - 8, 13, "<i>the UAV keeps no key that can decrypt a finished file</i>", fs=FS_S)
    f.text(4, yr + 4, 40, 14, "GCS", fs=FS_M, bold=True, align="left", colour=GCS_C)
    yv = 306.0
    f.glyph("file_lock", 46, yv - 11, 22)
    wv = P(f, 90, yv - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(68, yv), (90, yv)], attach=False)
    f.text(90 + wv + 8, yv - 13, 190, 26, "verify with the pinned UAV key;<br>a file without that signature is refused", fs=FS_S, align="left")
    yg = 348.0
    f.glyph("keys", 4, yg - 10, 20)
    xp = 36.0
    wa = P(f, xp, yg - 9, "ML-KEM-1024", ACC_KEY, h=18)
    wb = P(f, xp + wa + 3, yg - 9, "X25519", ACC_KEY, h=18)
    f.edge([(24, yg), (xp, yg)], "key", attach=False)
    f.edge([(100, yv + 9), (100, yg - 9)])
    x2 = xp + wa + 3 + wb + 10
    f.pill(x2, yg - 9, 42, 18, "HKDF", ACC_SYM)
    f.edge([(xp + wa + 3 + wb, yg), (x2, yg)], "key")
    x3 = x2 + 42 + 10
    w3 = P(f, x3, yg - 9, "AES-256-GCM", ACC_SYM, h=18)
    f.edge([(x2 + 42, yg), (x3, yg)], "key")
    xo = max(x3 + w3 + 12, 311.0)
    f.glyph("photo", xo, yg - 20, 18)
    f.glyph("play", xo, yg + 1, 18)
    f.edge([(x3 + w3, yg), (xo - 1, yg)], attach=False)
    f.text(110, yg - 26, 90, 12, "<i>signature valid</i>", fs=FS_S, align="left")
    f.text(x3 - 8, yg + 11, w3 + 16, 12, "unwrap, decrypt", fs=FS_S)
    return f


def fig10_evaluation_workflow():
    """simulation/README.md: calibrate from measurements, check against the measurements left out, then the NR cell."""
    W, H = W2, 182.0
    f = Fig("fig10_evaluation_workflow", W, H, "Evaluation workflow: the prototype is measured, the measurements calibrate and check the simulation")
    it = lambda s: f"<i>{s}</i>"
    ym = 66.0
    # prototype
    f.text(6, 4, 170, 15, "Prototype (measured)", fs=FS_L, bold=True, colour=ACC_KEY)
    f.box(6, 24, 170, 92, fill=KEY_F)
    icon(f, "uav", 42, 34, "Raspberry Pi 4B", size=30, fs=FS_S, lw=72)
    icon(f, "laptop", 140, 34, "laptop", size=30, fs=FS_S, lw=60)
    f.glyph("wifi", 81, 38, 20)
    f.edge([(60, 60), (122, 60)], "flow", "both", attach=False)
    f.text(8, 92, 166, 24, it("the real link over Wi-Fi:<br>liboqs, OpenSSL, camera"), fs=FS_S)
    # what is measured -> calibration
    f.edge([(176, ym), (198, ym)], attach=False)
    icon(f, "timer", 216, ym - 14, "computing steps,<br>round trips,<br>frame sizes", size=28, fs=FS_S, lw=84)
    f.edge([(234, ym), (262, ym)], attach=False)
    icon(f, "tune", 280, ym - 14, "calibration<br>file", size=28, fs=FS_S, lw=60)
    f.edge([(298, ym), (322, ym)], attach=False)
    # simulation: two links, one protocol model
    f.text(322, 4, 262, 15, "Simulation (ns-3, 5G-LENA)", fs=FS_L, bold=True, colour=GREY)
    f.box(322, 24, 262, 92, fill=PALE)
    icon(f, "wifi", 356, 32, "replica of<br>the test bed", size=24, fs=FS_S, lw=66)
    f.glyph("cell_tower", 498, 30, 26)
    for x, y in ((446, 34), (468, 60), (536, 60), (556, 34)):
        f.glyph("uav", x, y, 16)
    f.text(444, 78, 136, 13, "5G NR cell, 1 to 64 UAVs", fs=FS_S)
    f.text(326, 96, 254, 13, it("the link's own messages, fragments and timers"), fs=FS_S)
    f.edge([(402, 34), (402, 88)], "rule", attach=False)
    # results
    icon(f, "scale", 652, 22, "validation", size=28, fs=FS_S, lw=90)
    f.edge([(584, 36), (634, 36)], attach=False)
    icon(f, "chart", 652, 86, "swarm size, storm,<br>speed, ablations", size=28, fs=FS_S, lw=110)
    f.edge([(584, 100), (634, 100)], attach=False)
    # the measurements that were left out of the calibration are what the replica is checked against
    f.edge([(90, 116), (90, 166), (700, 166), (700, 36), (672, 36)], attach=False)
    f.text(100, 151, 590, 13, it("left out of the calibration and used as the check: the duration of every session operation, and everything measured under packet loss"),
           fs=FS_S, align="left")
    return f


def fig11_media_protection():
    """Where post-quantum cryptography acts on the way of a picture: live video (keys from the hybrid handshake) and
    stored photos / recordings (hybrid key wrap, signature). kyber6g/uav/main.py, kyber6g/recording/, kyber6g/ground/main.py."""
    W, H = W2, 266.0
    f = Fig("fig11_media_protection", W, H, "Protection of pictures and video: where the post-quantum algorithms act")
    it = lambda s: f"<i>{s}</i>"
    f.glyph("uav", 6, 2, 30)
    f.text(42, 3, 150, 15, "UAV node", fs=FS_L, bold=True, align="left", colour=UAV_C)
    f.glyph("laptop", 560, 2, 30)
    f.text(596, 3, 122, 15, "Ground station", fs=FS_L, bold=True, align="left", colour=GCS_C)
    # ---- lane 1: live video. Keys come from the handshake / PQ ratchet (top, middle)
    y = 92.0
    xk = 359.0
    pill_row(f, xk, 26, [("ML-KEM-1024", ACC_KEY), ("X25519", ACC_KEY), ("ML-DSA-87", ACC_KEY)], gap=3)
    f.text(xk - 130, 44, 260, 13, it("handshake and PQ ratchet: session keys, both ends authenticated"), fs=FS_S)
    f.text(4, y - 36, 120, 13, "<b>Live video</b>", fs=FS_M, align="left")
    f.glyph("camera", 4, y - 12, 24)
    f.pic("frame.jpg", 34, y - 15.75, 56, 31.5)
    f.box(104, y - 11, 46, 22, "H.264")
    f.edge([(90, y), (104, y)])
    f.op("slice", 168, y)
    f.edge([(150, y), (160.5, y)])
    for k in range(3):
        f.cell(184 + 12 * k, y - 7, 12, 14, fill=PALE)
    f.edge([(175.5, y), (184, y)])
    xa = 236.0
    f.pill(xa, y - 9, 84, 18, "AES-256-GCM", ACC_SYM)
    f.edge([(220, y), (xa, y)])
    for k in range(3):
        f.pic("cipher.png", 340 + 30 * k, y - 8, 26, 14.6)
    f.edge([(xa + 84, y), (340, y)])
    xb = 440.0
    f.pill(xb, y - 9, 84, 18, "AES-256-GCM", ACC_SYM)
    f.edge([(426, y), (xb, y)])
    f.box(536, y - 11, 80, 22, "H.264 decoder")
    f.edge([(xb + 84, y), (536, y)])
    f.pic("frame.jpg", 626, y - 15.75, 56, 31.5)
    f.edge([(616, y), (626, y)])
    f.glyph("monitor", 688, y - 12, 24)
    f.text(330, y + 10, 110, 13, it("one record per datagram"), fs=FS_S)
    # the session keys reach both ends
    f.edge([(xk - 60, 58), (xk - 60, 66), (xa + 42, 66), (xa + 42, y - 9)], "key")
    f.edge([(xk + 60, 58), (xk + 60, 66), (xb + 42, 66), (xb + 42, y - 9)], "key")
    f.text(xa + 46, 68, 70, 12, it("epoch keys"), fs=FS_S, align="left")
    # ---- lane 2: stored photo or recording. The steps are spaced so that the lane ends where lane 1 ends.
    y = 180.0
    g = 15.0

    def hybrid(x):
        """ML-KEM-1024 over X25519: the two halves of the hybrid wrap of a file key. Returns the width."""
        w = round(measure("<b>ML-KEM-1024</b>", FS_S)[0] + 14, 1)
        f.pill(x, y - 17, w, 16, "ML-KEM-1024", ACC_KEY, FS_S)
        f.pill(x, y + 1, w, 16, "X25519", ACC_KEY, FS_S)
        return w

    def caption(x, w, s):
        tw = measure(it(s), FS_S)[0] + 4
        f.text(x + w / 2 - tw / 2, y + 19, tw, 13, it(s), fs=FS_S)

    f.text(4, y - 40, 200, 13, "<b>Photo or recording, stored</b>", fs=FS_M, align="left")
    f.glyph("photo", 4, y - 10, 20)
    f.glyph("film", 26, y - 10, 20)
    xa2 = 46 + g
    wa2 = P(f, xa2, y - 9, "AES-256-GCM", ACC_SYM, h=18)
    f.edge([(47, y), (xa2, y)], attach=False)
    f.glyph("random", xa2 + wa2 / 2 - 10, y + 17, 20)
    f.edge([(xa2 + wa2 / 2, y + 17), (xa2 + wa2 / 2, y + 9)], "key", "end", attach=False)
    f.text(xa2 + wa2 / 2 - 40, y + 38, 80, 13, it("file key (random)"), fs=FS_S)
    # wrap and sign
    x1 = xa2 + wa2 + g
    wk = hybrid(x1)
    f.edge([(xa2 + wa2, y), (x1, y)], attach=False)
    caption(x1, wk, "wrap the file key")
    x2 = x1 + wk + g
    ws = P(f, x2, y - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(x1 + wk, y), (x2, y)], attach=False)
    caption(x2, ws, "sign the file")
    xs = x2 + ws + g
    icon(f, "sd", xs + 12, y - 12, ".k6gimg<br>.k6grec", size=24, fs=FS_S, lw=48)
    f.edge([(x2 + ws, y), (xs - 1, y)], attach=False)
    # over the link (inside AEAD records, with retransmission)
    xt = xs + 24 + g
    for k in range(2):
        f.pic("cipher.png", xt + 30 * k, y - 7.3, 26, 14.6)
    f.edge([(xs + 25, y), (xt, y)], attach=False)
    f.text(xt + 28 - 42, y - 24, 84, 13, it("fetched over the link"), fs=FS_S)
    # ground station: verify, unwrap, decrypt
    x5 = xt + 56 + g
    wv = P(f, x5, y - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(xt + 56, y), (x5, y)])
    caption(x5, wv, "verify: pinned key")
    x6 = x5 + wv + g
    wk2 = hybrid(x6)
    f.edge([(x5 + wv, y), (x6, y)], attach=False)
    caption(x6, wk2, "unwrap the file key")
    x7 = x6 + wk2 + g
    wa7 = P(f, x7, y - 9, "AES-256-GCM", ACC_SYM, h=18)
    f.edge([(x6 + wk2, y), (x7, y)], attach=False)
    xo = x7 + wa7 + g
    f.glyph("photo", xo, y - 20, 18)
    f.glyph("play", xo, y + 2, 18)
    f.edge([(x7 + wa7, y), (xo - 1, y)], attach=False)
    f.text(4, 236, W - 8, 13, it("blue: post-quantum and hybrid public-key steps (establish, wrap, sign) · violet: AES-256-GCM encrypts every frame, photo and segment"),
           fs=FS_S)
    f.legend(250, 256, [("flow", "pictures and video"), ("key", "key material")])
    return f


def fig12_simulation_setup():
    """simulation/ns3/k6g-swarm-sim.cc: the two links the protocol model runs on."""
    W, H = W2, 214.0
    f = Fig("fig12_simulation_setup", W, H, "The two simulated links: a replica of the test bed, and a 5G NR cell")
    it = lambda s: f"<i>{s}</i>"
    # ---- (a) replica of the test bed
    f.box(6, 22, 262, 150, fill=PALE)
    icon(f, "uav", 44, 40, "one UAV", size=30, fs=FS_S, lw=60)
    icon(f, "laptop", 230, 40, "ground station", size=30, fs=FS_S, lw=74)
    f.glyph("wifi", 127, 34, 20)
    f.edge([(62, 62), (212, 62)], "flow", "both", attach=False)
    f.text(70, 66, 134, 13, it("as measured over Wi-Fi"), fs=FS_S)
    rows_a = [("timer", "a message of 1 to 6 datagrams: as long as measured"),
              ("packet", "each datagram is lost with the set probability, both ways"),
              ("chip", "computing times: drawn from the measurements")]
    for i, (g, t) in enumerate(rows_a):
        yy = 100 + 23 * i
        f.glyph(g, 12, yy, 18)
        f.text(34, yy + 2, 232, 14, t, fs=FS_S, align="left")
    f.panel("a", 6, 3, "Replica of the test bed: the check")
    f.text(6, 176, 262, 13, it("compared with the measured operations and loss runs"), fs=FS_S)
    # ---- (b) NR cell
    x0 = 284.0
    f.box(x0, 22, 428, 150, fill=PALE)
    cx = x0 + 124
    f.glyph("cell_tower", cx - 17, 90, 34)
    f.text(cx - 40, 126, 80, 13, "gNB, 25 m mast", fs=FS_S)
    for dx, yy in ((-104, 92), (-108, 58), (-72, 70), (-56, 44), (-12, 54), (30, 44), (58, 70), (96, 54)):
        f.glyph("uav", cx + dx - 9, yy, 18)
    f.text(x0 + 6, 26, 160, 13, it("1 to 64 UAVs, 60 to 120 m above ground"), fs=FS_S, align="left")
    f.edge([(cx - 104, 146), (cx + 104, 146)], "plain", "both", attach=False, width=1.0)
    f.text(cx - 60, 149, 120, 13, "within 400 m (or 0.25 to 4 km)", fs=FS_S)
    # the cell's parameters, then core network and ground station at the height of the gNB
    xr = x0 + 250
    for i, t in enumerate(("3.5 GHz, 100 MHz, TDD (30 kHz)", "line of sight (3GPP urban macro)",
                           "one beam at a time, proportional fair", "HARQ, unacknowledged RLC")):
        f.text(xr, 33 + 13 * i, 174, 13, t, fs=FS_S, align="left")
    xn, yn = x0 + 300, 107.0
    icon(f, "cloud", xn, yn - 14, "core network", size=28, fs=FS_S, lw=70)
    f.edge([(cx + 19, yn), (xn - 15, yn)], "flow", "both", attach=False)
    icon(f, "laptop", xn + 86, yn - 14, "ground station", size=28, fs=FS_S, lw=76)
    f.edge([(xn + 15, yn), (xn + 71, yn)], "flow", "both", attach=False)
    f.text(xn + 16, yn - 15, 54, 13, "1 ms", fs=FS_S)
    f.panel("b", x0, 3, "5G NR cell (5G-LENA): what the test bed cannot show")
    f.text(x0, 176, 428, 13, it("every UAV streams video and runs the session operations; radio and core are simulated"), fs=FS_S)
    return f


def msg_fields(f, x, y, items):
    """A message drawn as its fields: plain cells for values, blue pills for public-key material, grey pills for MACs."""
    for label, kind in items:
        if kind == "cell":
            w = round(measure(label, FS_S)[0] + 10, 1)
            f.cell(x, y, w, 15, label)
        else:
            w = P(f, x, y - 0.5, label, ACC_KEY if kind == "pq" else ACC_SYM)
        x += w + 4
    return x


def fig13_rekey_flows():
    """The two ways a running session gets new keys, message by message. kyber6g/crypto/handshake.py: build_rekey_request,
    server_process_rekey, client_process_rekey_resp (cached rekey); PQRatchetInitiator, pq_ratchet_respond, _pq_mix (ratchet).
    Datagram and byte counts: paper_plots/tables/plot03_wire_bytes.csv."""
    W, H = W2, 282.0
    f = Fig("fig13_rekey_flows", W, H, "New keys for a running session: 1-RTT Cached RapidRekey and PQ ratchet")
    it = lambda s: f"<i>{s}</i>"
    ss = lambda s: var("ss", s)
    TH = "<i>TH</i>"
    y1, y2, y3 = 96.0, 162.0, 220.0
    lanes = ((30.0, 335.0), (385.0, 690.0))
    for xu, xg in lanes:
        icon(f, "uav", xu, 2, "UAV", size=28, bold=True, lw=40)
        icon(f, "laptop", xg, 2, "GCS", size=28, bold=True, lw=40)
        for x in (xu, xg):
            f.edge([(x, 48), (x, 238)], "rule", dashed=True, attach=False)
    # ---- (a) 1-RTT Cached RapidRekey: symmetric only
    xu, xg = lanes[0]
    f.text(xu + 8, y1 - 21, 44, 14, "Request", fs=FS_M, bold=True, align="left")
    msg_fields(f, xu + 54, y1 - 21, [("UAV ID", "cell"), ("session ID", "cell"), ("cell", "cell"), (var("N", "C"), "cell"), ("time", "cell"), ("MAC", "sym")])
    f.edge([(xu, y1), (xg, y1)], attach=False)
    f.text(xg - 206, y1 + 4, 200, 24, it("entry younger than 300 s, same cell, MAC valid:<br>derive the new keys, delete the old secret"), fs=FS_S, align="right",
           valign="top")
    f.text(xg - 62, y2 - 21, 56, 14, "Response", fs=FS_M, bold=True, align="right")
    msg_fields(f, xu + 8, y2 - 21, [("session ID", "cell"), ("new ID", "cell"), (var("N", "S"), "cell"), ("MAC", "sym")])
    f.edge([(xg, y2), (xu, y2)], attach=False)
    f.text(xu + 8, y2 + 4, 170, 12, it("derive the same keys, check the MAC"), fs=FS_S, align="left", valign="top")
    f.text(xu + 8, y3 - 21, 50, 14, "Finished", fs=FS_M, bold=True, align="left")
    msg_fields(f, xu + 60, y3 - 21, [("new ID", "cell"), ("MAC", "sym")])
    f.edge([(xu, y3), (xg, y3)], attach=False)
    f.text(xg - 176, y3 + 4, 170, 12, it("check the MAC: session confirmed"), fs=FS_S, align="right", valign="top")
    f.glyph("key", xu + 30, 242, 18)
    f.text(xu + 52, 244, 260, 14, f"new keys = HKDF(resumption secret, salt = {TH})", fs=FS_S, align="left")
    f.panel("a", 30, H - 16, "1-RTT Cached RapidRekey: symmetric only, 324 bytes")
    # ---- (b) PQ ratchet: a fresh hybrid exchange inside the session
    xu, xg = lanes[1]
    f.pic("lattice.svg", xu + 8, 50, 30, 21, border=None)
    f.pic("curve.svg", xu + 42, 50, 30, 21, border=None)
    f.text(xu + 78, 54, 190, 13, it("fresh ML-KEM-1024 and X25519 key pairs"), fs=FS_S, align="left")
    f.text(xu + 8, y1 - 21, 44, 14, "Request", fs=FS_M, bold=True, align="left")
    msg_fields(f, xu + 54, y1 - 21, [("request ID", "cell"), ("X25519 key", "pq"), ("ML-KEM key", "pq")])
    f.edge([(xu, y1), (xg, y1)], attach=False)
    f.text(xg - 176, y1 + 4, 170, 12, it("encapsulate, X25519 exchange, derive"), fs=FS_S, align="right", valign="top")
    f.text(xg - 52, y2 - 21, 46, 14, "Answer", fs=FS_M, bold=True, align="right")
    msg_fields(f, xu + 8, y2 - 21, [("X25519 key", "pq"), ("ML-KEM ciphertext", "pq"), ("new ID", "cell")])
    f.edge([(xg, y2), (xu, y2)], attach=False)
    f.text(xu + 8, y2 + 4, 170, 12, it("decapsulate, X25519 exchange, derive"), fs=FS_S, align="left", valign="top")
    f.glyph("key", xu + 26, 188, 18)
    f.text(xu + 48, 190, 250, 14, f"new master = HKDF({ss('KEM')} || {ss('X')} || old master, salt = {TH})", fs=FS_S, align="left")
    f.edge([(xu, 230), (xg, 230)], "flow", "both", attach=False)
    f.text(xu, 215, xg - xu, 13, it("records under the new keys; the link stays up"), fs=FS_S)
    f.panel("b", 385, H - 16, "PQ ratchet: fresh ML-KEM-1024 + X25519, 4,757 bytes")
    return f


def fig14_hello_admission():
    """What a ClientHello has to pass at the ground station, in the order the code applies it: GcsLink._on_handshake
    (answer cache, ration) in kyber6g/transport/link.py, Reassembler in transport/framing.py, and
    ServerHandshake.process_client_hello in kyber6g/crypto/handshake.py (identity, nonce, time, signature, half-open
    sessions). The two times are the measured medians of an ML-DSA-87 verification (paper_plots, plot 1)."""
    W, H = W1, 304.0
    f = Fig("fig14_hello_admission", W, H, "Admission of a ClientHello at the ground station: cheap checks first, the costly step rationed")
    it = lambda s: f"<i>{s}</i>"
    xl, xt = 22.0, 42.0                                           # the flow line, and where the words start
    rows = [(4, "packet", "ClientHello arrives", "6 fragments; the sender's address proves nothing"),
            (44, "hash", "Reassembly", "128 partial messages; a full table drops its oldest"),
            (84, "refresh", "The same hello within 10 s?", "yes: the stored answer is sent again"),
            (124, "counter", "Ration left?", "a quarter of one core for failed checks; empty: dropped"),
            (164, "fingerprint", "UAV known, nonce new, time within 120 s?", "no: refused, at no cost"),
            (204, "signature", None, "fails: refused, and one unit of the ration is used"),
            (250, "keys", None, "encapsulate, derive, sign; 64 half-open sessions at most")]
    for i, (y, glyph, name, how) in enumerate(rows):
        f.glyph(glyph, xl - 11, y, 22)
        if name:
            f.text(xt, y - 1, 272, 13, f"<b>{name}</b>", fs=FS_M, align="left")
        f.text(xt, y + 12, 272, 12, it(how), fs=FS_S, align="left")
        if i:
            f.edge([(xl, rows[i - 1][0] + 23), (xl, y - 1)], attach=False)
    # the two rows that do public-key work
    y = rows[5][0]
    w = P(f, xt, y - 3, "ML-DSA-87", ACC_KEY)
    f.text(xt + w + 5, y - 3, 200, 16, "verify (pinned key): 0.08 ms, 0.45 ms on a Pi", fs=FS_S, align="left")
    y = rows[6][0]
    x = xt
    for label in ("ML-KEM-1024", "X25519", "ML-DSA-87"):
        x += P(f, x, y - 3, label, ACC_KEY) + 4
    f.text(x + 1, y - 3, 70, 16, "<b>ServerHello</b>", fs=FS_M, align="left")
    # along the right edge: which of the steps cost what
    xr = 320.0
    # (no word of two or three letters in a label that stands on its side: the build tells an upright word from a
    # rotated one by the shape of its box, and cannot for so short a word)
    for y0, y1, label in ((rows[1][0], rows[4][0] + 24, "without public-key work"), (rows[5][0] - 4, rows[6][0] + 24, "public-key work")):
        f.edge([(xr, y0), (xr, y1)], "rule", attach=False)
        f.text(xr + 3, y0, 13, y1 - y0, label, fs=FS_S, rotate=True)
    f.text(2, H - 17, W - 4, 13, it("a genuine hello never uses the ration: only checks that fail do"), fs=FS_S)
    return f


def fig15_audio_sealing():
    """Sealed audio: kyber6g/audio/quaver.py (AudioSealer, SealerTree), kyber6g/audio/store.py, kyber6g/uav/main.py
    (_audio_live_run) and kyber6g/ground/audio_desk.py. The frames of the encoder are sealed once, block by block; the
    same sealed blocks go to the card and onto the link."""
    W, H = W2, 326.0
    f = Fig("fig15_audio_sealing", W, H, "Sealed audio: sealed once on the UAV, for its card and for the link; opened only on the ground station")
    it = lambda s: f"<i>{s}</i>"
    f.glyph("uav", 6, 2, 30)
    f.text(42, 3, 150, 15, "UAV node", fs=FS_L, bold=True, align="left", colour=UAV_C)
    f.text(42, 19, 300, 13, it("the prototype has no microphone: a file stands in for it"), fs=FS_S, align="left")
    # ---- lane A: sound -> frames -> one block -> sealed block -> card and link
    y = 76.0
    f.glyph("mic", 4, y - 12, 24)
    f.pic("wave.svg", 32, y - 10, 60, 20, border=None)
    f.box(104, y - 11, 50, 22, "encoder")
    f.edge([(92, y), (104, y)])
    f.op("slice", 172, y)
    f.edge([(154, y), (164.5, y)])
    for k in range(8):
        f.cell(188 + 9 * k, y - 7, 9, 14, fill=PALE)
    f.edge([(179.5, y), (188, y)])
    f.text(170, y - 24, 90, 12, "8 frames, 0.21 s", fs=FS_S)
    xb = 280.0
    f.cell(xb, y - 7, 22, 14)
    f.cell(xb + 22, y - 7, 56, 14, fill=PALE)
    f.cell(xb + 78, y - 7, 18, 14)
    f.edge([(260, y), (xb, y)])
    f.text(xb - 8, y - 24, 112, 12, "one block, one size", fs=FS_S)
    f.text(xb - 22, y + 9, 140, 12, it("time, place · frames · padding"), fs=FS_S)
    xa = 394.0
    f.pill(xa, y - 9, 86, 18, "AES-256-GCM", ACC_SYM)
    f.edge([(xb + 96, y), (xa, y)])
    xs = 498.0
    f.cell(xs, y - 7, 14, 14, it("c"), fs=FS_MIN)
    f.pic("cipher.png", xs + 14, y - 7, 44, 14)
    f.cell(xs + 58, y - 7, 14, 14, it("t"), fs=FS_MIN)
    f.edge([(xa + 86, y), (xs, y)])
    f.text(xs - 32, y + 9, 136, 12, it("commitment · ciphertext · tag"), fs=FS_MIN)
    xo = 614.0
    f.glyph("sd", xo, y - 44, 24)
    f.text(xo + 28, y - 44, 72, 24, "card:<br>written", fs=FS_S, align="left")
    f.glyph("antenna", xo, y + 20, 24)
    f.text(xo + 28, y + 20, 72, 24, "link: sent<br>once", fs=FS_S, align="left")
    f.edge([(xs + 72, y), (592, y), (592, y - 32), (xo - 1, y - 32)], attach=False)
    f.edge([(xs + 72, y), (592, y), (592, y + 32), (xo - 1, y + 32)], attach=False)
    # ---- lane K: the clip key, its wrap for the ground station, the key tree
    yk = 134.0
    f.text(4, yk - 12, 94, 24, it("clip key:<br>32 random bytes"), fs=FS_S, align="right")
    f.glyph("random", 102, yk - 11, 22)
    w1 = P(f, 148, yk - 9, "ML-KEM-1024", ACC_KEY, h=18)
    w2 = P(f, 148 + w1 + 3, yk - 9, "X25519", ACC_KEY, h=18)
    f.edge([(124, yk), (148, yk)], "key", attach=False)
    f.text(148 + w1 + w2 + 9, yk - 12, 110, 24, it("wrapped for the GCS:<br>head of the clip"), fs=FS_S, align="left")
    f.box(xa + 8, yk - 11, 70, 22, "key tree", fill=KEY_F)
    f.edge([(xa + 43, yk - 11), (xa + 43, y + 9)], "key")
    f.text(xa + 49, y + 24, 130, 12, f"{var('K', 'i')}: a key for this block only", fs=FS_S, align="left")
    f.edge([(113, yk + 11), (113, yk + 24), (xa + 43, yk + 24), (xa + 43, yk + 11)], "key")
    f.text(130, yk + 27, 300, 12, it("the UAV keeps only the nodes that lead to blocks still to come"), fs=FS_S)
    # ---- lane S: one signature over all blocks
    ys = 200.0
    for k in range(6):
        f.pic("cipher.png", 4 + 22 * k, ys - 7, 20, 14)
    f.text(4, ys + 9, 130, 12, it("all blocks, each with its number"), fs=FS_S, align="left")
    w3 = P(f, 152, ys - 9, "SHA-256", ACC_SYM, h=18)
    f.edge([(134, ys), (152, ys)])
    x2 = 152 + w3 + 14
    f.box(x2, ys - 11, 74, 22, "Merkle root", fill=SYM_F)
    f.edge([(152 + w3, ys), (x2, ys)])
    x3 = x2 + 74 + 14
    w4 = P(f, x3, ys - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(x2 + 74, ys), (x3, ys)])
    f.text(x3 - 14, ys + 11, w4 + 28, 12, "UAV identity key", fs=FS_S)
    f.glyph("signature", x3 + w4 + 18, ys - 11, 22)
    f.edge([(x3 + w4, ys), (x3 + w4 + 17, ys)], attach=False)
    f.text(x3 + w4 + 46, ys - 13, 230, 26, "one signature for the whole clip: the end of the file,<br>and of the live clip", fs=FS_S, align="left")
    # ---- the ground station
    yr = 232.0
    f.edge([(6, yr), (W - 6, yr)], "rule", dashed=True, attach=False)
    f.glyph("laptop", 6, yr + 5, 26)
    f.text(38, yr + 9, 150, 15, "Ground control station", fs=FS_L, bold=True, align="left", colour=GCS_C)
    yg = 292.0
    f.glyph("antenna", 4, yg - 11, 22)
    for k in range(3):
        f.pic("cipher.png", 36 + 22 * k, yg - 7, 20, 14)
    f.edge([(27, yg), (36, yg)], attach=False)
    wk = round(measure("<b>ML-KEM-1024</b>", FS_S)[0] + 14, 1)
    xh = 116.0
    f.pill(xh, yg - 17, wk, 16, "ML-KEM-1024", ACC_KEY, FS_S)
    f.pill(xh, yg + 1, wk, 16, "X25519", ACC_KEY, FS_S)
    f.edge([(100, yg), (xh, yg)], attach=False)
    f.text(xh - 14, yg + 19, wk + 28, 12, it("unwrap the clip key"), fs=FS_S)
    x5 = xh + wk + 14
    w5 = P(f, x5, yg - 9, "AES-256-GCM", ACC_SYM, h=18)
    f.edge([(xh + wk, yg), (x5, yg)], attach=False)
    f.text(x5 - 10, yg + 11, w5 + 20, 12, it("open each block"), fs=FS_S)
    x6 = x5 + w5 + 14
    f.glyph("speaker", x6, yg - 11, 22)
    f.edge([(x5 + w5, yg), (x6 - 1, yg)], attach=False)
    f.text(x6 + 26, yg - 12, 62, 24, "heard as it<br>comes in", fs=FS_S, align="left")
    x7 = x6 + 26 + 64
    w7 = P(f, x7, yg - 9, "SHA-256", ACC_SYM, h=18)
    w8 = P(f, x7 + w7 + 3, yg - 9, "ML-DSA-87", ACC_KEY, h=18)
    f.edge([(x6 + 78, yg), (x7, yg)], attach=False)
    f.text(x7 - 20, yg + 11, w7 + w8 + 43, 12, it("every block under the signed root"), fs=FS_S)
    x8 = x7 + w7 + w8 + 3 + 16
    f.glyph("file_lock", x8, yg - 11, 22)
    f.edge([(x7 + w7 + w8 + 3, yg), (x8 - 1, yg)], attach=False)
    f.text(x8 + 26, yg - 12, 120, 24, "stored: the same bytes<br>as on the card", fs=FS_S, align="left")
    # blocks lost on the air come from the card, by number
    f.glyph("sd", x7 + w7 / 2 - 10, yg - 50, 20)
    f.edge([(x7 + w7 / 2, yg - 29), (x7 + w7 / 2, yg - 9)], attach=False)
    f.text(x7 + w7 / 2 + 14, yg - 51, 240, 24, "blocks lost on the air are asked for again by number<br>and come from the UAV's card", fs=FS_S, align="left")
    return f


def fig16_audio_clip():
    """One sealed clip (kyber6g/audio/quaver.py): head, blocks, root record, signature; the key tree (KeyTree, block_keys)
    that gives every block its key, and the hash tree (Frontier, merkle_levels) that one signature covers."""
    W, H = W2, 266.0
    f = Fig("fig16_audio_clip", W, H, "One sealed clip: a key tree gives every block its own key, a hash tree puts every block under one signature")
    it = lambda s: f"<i>{s}</i>"
    yb, hb = 120.0, 18.0                                         # the clip as a strip of cells
    f.cell(130, yb, 64, hb, "head", fs=FS_S)
    kinds = ["description", "audio", "audio", "audio", "audio", "audio", "summary", "padding"]
    cx = [224 + 50 * k for k in range(8)]
    for k, kind in enumerate(kinds):
        f.cell(200 + 50 * k, yb, 48, hb, it(kind), fs=FS_MIN, fill=PALE if kind == "audio" else WHITE)
    f.cell(604, yb, 40, hb, "root", fs=FS_S)
    f.cell(648, yb, 64, hb, "signature", fs=FS_S)
    # ---- the key tree, above
    f.text(4, 1, 96, 24, it("clip key:<br>32 random bytes"), fs=FS_S, align="right")
    f.glyph("random", 104, 2, 22)
    f.pill(377, 4, 44, 18, "HKDF", ACC_SYM)
    f.edge([(126, 13), (377, 13)], "key", attach=False)
    root = f.op("dot", 399, 38, 7, ACC_KEY)
    f.edge([(399, 22), (399, 34.5)], "key")
    l1 = [(299, 62), (499, 62)]
    l2 = [(249, 86), (349, 86), (449, 86), (549, 86)]
    for x, yy in l1 + l2:
        f.op("dot", x, yy, 7, ACC_KEY)
    for (px, py), kids in (((399, 38), l1), (l1[0], l2[:2]), (l1[1], l2[2:])):
        for (qx, qy) in kids:
            f.edge([(px + (3.5 if qx > px else -3.5), py), (qx, py), (qx, qy - 3.5)], "key", "none")
    for i, (px, py) in enumerate(l2):
        for qx in (cx[2 * i], cx[2 * i + 1]):
            f.edge([(px + (3.5 if qx > px else -3.5), py), (qx, py), (qx, yb)], "key")
    for k in range(8):
        f.text(cx[k] + 3, 102, 20, 12, var("K", k), fs=FS_S, align="left")
    f.text(508, 6, 206, 24, it("key tree: a node gives every key below it<br>and no other; the UAV forgets as it goes"), fs=FS_S, align="left")
    wk = round(measure("<b>ML-KEM-1024</b>", FS_S)[0] + 14, 1)
    xw = 162 - wk / 2
    f.pill(xw, 64, wk, 16, "ML-KEM-1024", ACC_KEY, FS_S)
    f.pill(xw, 82, wk, 16, "X25519", ACC_KEY, FS_S)
    f.edge([(115, 24), (115, 44), (162, 44), (162, 64)], "key", attach=False)
    f.edge([(162, 98), (162, yb)], "key", attach=False)
    f.text(4, 68, xw - 10, 24, it("wrapped for the<br>ground station"), fs=FS_S, align="right")
    # ---- the hash tree, below
    yl = 162.0
    for k in range(8):
        f.op("dot", cx[k], yl, 7, LINE)
        f.edge([(cx[k], yb + hb), (cx[k], yl - 3.5)])
    m2 = [(249, 186), (349, 186), (449, 186), (549, 186)]
    m1 = [(299, 210), (499, 210)]
    top = (399, 234)
    for x, yy in m2 + m1 + [top]:
        f.op("dot", x, yy, 7, LINE)
    for i, (px, py) in enumerate(m2):
        for qx in (cx[2 * i], cx[2 * i + 1]):
            f.edge([(qx, yl + 3.5), (qx, py), (px + (3.5 if qx > px else -3.5), py)], "flow", "none")
    for (px, py), kids in ((m1[0], m2[:2]), (m1[1], m2[2:]), (top, m1)):
        for (qx, qy) in kids:
            f.edge([(qx, qy + 3.5), (qx, py), (px + (3.5 if qx > px else -3.5), py)], "flow", "none")
    f.op("dot", 624, 234, 7, LINE)
    f.edge([(402.5, 234), (620.5, 234)], "flow", "none")
    f.edge([(624, 230.5), (624, yb + hb)])
    ws = round(measure("<b>ML-DSA-87</b>", FS_S)[0] + 14, 1)
    f.pill(680 - ws / 2, 156, ws, 16, "ML-DSA-87", ACC_KEY, FS_S)
    f.edge([(627.5, 234), (680, 234), (680, 172)])
    f.edge([(680, 156), (680, yb + hb)], fat=False)
    f.text(404, 240, 214, 12, it("hash tree: every block and its place"), fs=FS_S, align="left")
    # ---- one block, enlarged
    f.text(4, 150, 190, 12, "<b>One block</b> (all have this size)", fs=FS_S, align="left")
    yz = 166.0
    f.cell(4, yz, 14, 16, it("c"), fs=FS_MIN)
    f.cell(18, yz, 50, 16, it("time, place"), fs=FS_MIN)
    f.cell(68, yz, 52, 16, it("8 frames"), fs=FS_MIN, fill=PALE)
    f.cell(120, yz, 30, 16, it("zeros"), fs=FS_MIN)
    f.cell(150, yz, 22, 16, it("tag"), fs=FS_MIN)
    f.pill(18, yz + 20, 132, 15, "AES-256-GCM, its own key", ACC_SYM, FS_MIN)
    f.text(4, yz + 39, 196, 24, it("c: commitment to the block's key; a key<br>handed out later is checked against it"), fs=FS_S, align="left")
    f.legend(250, H - 8, [("key", "keys"), ("flow", "hashes (SHA-256)")])
    return f


def fig17_audio_excerpt():
    """Release of an excerpt (quaver.make_excerpt, verify_excerpt; audio_desk.excerpt): the sealed blocks a..b, the
    key-tree nodes that cover exactly a..b, the hashes that prove their place, the UAV's signature."""
    W, H = W2, 206.0
    f = Fig("fig17_audio_excerpt", W, H, "An excerpt for a third party: the keys of seconds a to b and of nothing else, verified with the UAV's public key alone")
    it = lambda s: f"<i>{s}</i>"
    # ---- the ground station holds the clip
    f.glyph("laptop", 6, 2, 28)
    f.text(38, 3, 160, 15, "Ground control station", fs=FS_M, bold=True, align="left", colour=GCS_C)
    f.text(38, 18, 160, 12, it("holds the clip and its key"), fs=FS_S, align="left")
    ys = 72.0
    for k in range(12):
        inside = 5 <= k <= 8
        f.cell(10 + 15 * k, ys - 8, 14, 16, fill=SYM_F if inside else WHITE, stroke=ACC_SYM if inside else LINE, sw=1.6 if inside else 1.0)
    f.text(10, ys - 26, 179, 12, "the sealed clip, block by block", fs=FS_S)
    f.edge([(85, ys + 15), (144, ys + 15)], "plain", "both", attach=False, width=1.0)
    f.text(60, ys + 19, 110, 12, it("seconds a to b"), fs=FS_S)
    f.glyph("keys", 12, 128, 20)
    f.text(36, 126, 170, 24, "its own keys and the clip key<br>never leave it", fs=FS_S, align="left")
    f.glyph("lock", 12, 164, 20)
    f.text(36, 162, 176, 24, "every other block stays sealed: its key<br>cannot be worked out from those released", fs=FS_S, align="left")
    # ---- what is handed over
    bx, bw = 232.0, 196.0
    f.box(bx, 30, bw, 150, dashed=True)
    f.text(bx, 34, bw, 13, "<b>Excerpt</b>", fs=FS_M)
    rows = [(62, None, "the sealed blocks a to b"), (92, "key", "the key-tree nodes that cover<br>exactly a to b"),
            (124, "hash", "hashes that prove their place<br>in the clip"), (156, "signature", "head, root and signature<br>of the UAV")]
    for yy, glyph, label in rows:
        if glyph is None:
            for k in range(4):
                f.pic("cipher.png", bx + 8 + 13 * k, yy - 7, 12, 14)
        elif glyph == "key":
            f.glyph("key", bx + 12, yy - 10, 20, ACC_KEY)
            f.glyph("key", bx + 34, yy - 10, 20, ACC_KEY)
        else:
            f.glyph(glyph, bx + 22, yy - 10, 20)
        f.text(bx + 64, yy - 12, bw - 68, 24, label, fs=FS_S, align="left")
    f.edge([(190, ys), (bx, ys)])
    # ---- anyone can check it
    vx = 476.0
    f.glyph("scale", vx, 2, 28)
    f.text(vx + 32, 3, 208, 15, "Anyone with the UAV's public key", fs=FS_M, bold=True, align="left")
    f.text(vx + 32, 18, 208, 12, it("no secret is needed to verify"), fs=FS_S, align="left")
    f.edge([(bx + bw, 100), (vx - 6, 100)], attach=False)
    steps = [(54, "ML-DSA-87", ACC_KEY, "the root is the UAV's"), (84, "SHA-256", ACC_SYM, "these are blocks a to b of that clip"),
             (114, "HMAC-SHA-256", ACC_SYM, "each key is the block's own"), (144, "AES-256-GCM", ACC_SYM, "open them")]
    for i, (yy, alg, colour, what) in enumerate(steps):
        f.tag(i + 1, vx + 7, yy)
        w = P(f, vx + 18, yy - 8, alg, colour)
        f.text(vx + 18 + w + 5, yy - 7, 236 - (18 + w + 5), 14, what, fs=FS_S, align="left")
    yo = 178.0
    f.glyph("speaker", vx + 2, yo - 10, 20)
    f.glyph("clock", vx + 26, yo - 10, 20)
    f.glyph("position", vx + 50, yo - 10, 20)
    f.text(vx + 76, yo - 12, 160, 24, "what was said, and when and where<br>the UAV recorded it", fs=FS_S, align="left")
    return f


def fig18_architecture():
    """The architecture of the whole system, lane by lane (after the block diagram of the project): what each side
    runs (kyber6g/uav/main.py, kyber6g/ground/main.py) and how each stream crosses the link (kyber6g/transport/link.py)."""
    W, H = W2, 378.0
    f = Fig("fig18_architecture", W, H, "Architecture: the streams of the UAV node, the secure link on both sides, and what the ground station does with each")
    it = lambda s: f"<i>{s}</i>"
    two = lambda a, b: f"{a}<br>{small(b)}"
    f.glyph("uav", 6, 2, 30)
    f.text(42, 3, 140, 15, "UAV node", fs=FS_L, bold=True, align="left", colour=UAV_C)
    f.text(42, 19, 140, 13, "Raspberry Pi 4B", fs=FS_S, align="left")
    f.glyph("laptop", 516, 2, 30)
    f.text(552, 3, 164, 15, "Ground control station", fs=FS_L, bold=True, align="left", colour=GCS_C)
    f.text(552, 19, 164, 13, "laptop, operator in the loop", fs=FS_S, align="left")
    bx, gx, bw = 184.0, 430.0, 78.0
    by, bh = 64.0, 278.0
    mid = (bx + bw + gx) / 2
    f.glyph("adversary", mid - 11, 2, 22)
    f.text(bx + bw - 30, 24, gx - bx - bw + 60, 12, it("untrusted network: read, drop, replay, modify, inject"), fs=FS_S, colour=THR_C)
    # ---- the secure link, on both sides
    for x, glyph, tint in ((bx, "lock", UAV_F), (gx, "unlock", GCS_F)):
        f.box(x, by, bw, bh, fill=tint)
        f.text(x, by + 8, bw, 13, "<b>Secure link</b>", fs=FS_S)
        f.glyph(glyph, x + bw / 2 - 10, by + 82, 20)
        f.pill(x + 3, by + 106, bw - 6, 16, "AES-256-GCM", ACC_SYM, FS_S)
        f.text(x, by + 124, bw, 24, "AEAD records,<br>replay window", fs=FS_S)
        f.pill(x + 17, by + 160, bw - 34, 16, "HKDF", ACC_SYM, FS_S)
        f.text(x, by + 178, bw, 24, "key schedule,<br>per-stream keys", fs=FS_S)
        f.glyph("ratchet", x + bw / 2 - 10, by + 210, 20)
        f.text(x, by + 232, bw, 24, "epochs, rekey,<br>ratchet", fs=FS_S)
    c0, c1 = bx + bw, gx
    # ---- key establishment
    yk = 98.0
    pill_row(f, mid, 42, [("ML-KEM-1024", ACC_KEY), ("X25519", ACC_KEY), ("ML-DSA-87", ACC_KEY)], gap=3)
    f.edge([(c0, yk), (c1, yk)], "key", "both")
    f.text(c0, yk - 15, c1 - c0, 12, it("hybrid PQ handshake, cached rekey"), fs=FS_S)
    # ---- the streams, UAV to ground
    lanes = [(134.0 + 32 * k, name) for k, name in enumerate(("video", "recording file", "image", "audio", "telemetry", "status"))]
    for y, name in lanes:
        f.pic("cipher.png", mid - 16, y - 9, 32, 18)
        f.edge([(c0, y), (mid - 16, y)])
        f.edge([(mid + 16, y), (c1, y)])
        f.text(c0 + 4, y - 14, 60, 12, it(name), fs=FS_S, align="left")
    # UAV side: acquisition and processing
    f.text(4, 46, 176, 12, it("acquisition and processing"), fs=FS_S, align="left")
    y = lanes[0][0]
    f.glyph("camera", 4, y - 12, 24)
    f.text(32, y - 13, 62, 26, two("Camera", "720p, 30 fps"), fs=FS_M, align="left")
    f.box(104, y - 13, 68, 26, two("H.264 encoder", "3 Mbit/s"), fs=FS_S)
    f.edge([(94, y), (104, y)], attach=False)
    f.edge([(172, y), (bx, y)], fat=True)
    y = lanes[1][0]
    f.glyph("sd", 127, y - 11, 22)
    f.edge([(138, lanes[0][0] + 13), (138, y - 11)], attach=False)
    f.edge([(150, y), (bx, y)], attach=False, fat=True)
    f.text(4, y - 13, 118, 26, two("Recorder", "encrypted, SD card"), fs=FS_M, align="right")
    for (y, _), glyph, a_, b_, x1 in ((lanes[2], "photo", "Still capture", "JPEG, up to 5 MP", 116), (lanes[3], "mic", "Audio sealer", "clips on the SD card", 124),
                                      (lanes[4], "gnss", "GNSS receiver", "position, 1 Hz", 112),
                                      (lanes[5], "motion", "Status, motion watch", "health · what moves in view", 152)):
        f.glyph(glyph, 4, y - 12, 24)
        f.text(32, y - 13, x1 - 34, 26, two(a_, b_), fs=FS_M, align="left")
        f.edge([(x1, y), (bx, y)], attach=False, fat=True)
    # ground side: decryption, storage and analytics
    sx = gx + bw + 18
    f.text(sx, 46, W - sx - 4, 12, it("decryption, storage and analytics"), fs=FS_S, align="left")
    sinks = [("play", "Video sink, detector, finder", "reorder, decode · YOLOE, OWLv2"), ("film", "Recordings", "decrypted on the GCS only"),
             ("image", "Image store", "SHA-256 verified"), ("speaker", "Audio desk", "verify, open, release excerpts"),
             ("database", "Telemetry store", "SQLite")]
    for (y, _), (glyph, a_, b_) in zip(lanes, sinks):
        f.glyph(glyph, sx, y - 12, 24)
        f.edge([(gx + bw, y), (sx - 1, y)], attach=False, fat=True)
        f.text(sx + 28, y - 13, W - sx - 32, 26, two(a_, b_), fs=FS_M, align="left")
    # the dashboard takes the status and gives the commands
    yd, yc = lanes[5][0], lanes[5][0] + 32
    f.glyph("monitor", sx, yd - 12, 24)
    f.text(sx + 28, yd - 13, W - sx - 32, 26, two("Dashboard", "operator: live view, commands"), fs=FS_M, align="left")
    f.edge([(gx + bw, yd), (sx - 1, yd)], attach=False, fat=True)
    f.edge([(sx + 12, yd + 13), (sx + 12, yc), (gx + bw, yc)], "cmd", attach=False)
    f.pic("cipher.png", mid - 16, yc - 9, 32, 18)
    f.edge([(c1, yc), (mid + 16, yc)], "cmd")
    f.edge([(mid - 16, yc), (c0, yc)], "cmd")
    f.text(c1 - 64, yc - 14, 60, 12, it("control"), fs=FS_S, align="right")
    f.glyph("command", 4, yc - 12, 24)
    f.text(32, yc - 13, 100, 26, two("Commands", "camera, recorder, link"), fs=FS_M, align="left")
    f.edge([(bx, yc), (134, yc)], "cmd", attach=False)
    f.glyph("wifi", mid - 108, by + bh + 3, 16)
    f.text(mid - 88, by + bh + 5, 200, 12, it("Wi-Fi, IP, UDP datagrams of at most 1472 bytes"), fs=FS_S, align="left")
    f.legend(190, H - 8, [("flow", "data in AEAD records"), ("cmd", "control"), ("key", "key establishment")])
    return f


def fig19_motion_watch():
    """The motion watch on the UAV (kyber6g/camera/motion.py) and where its reports go (uav/main.py on_motion,
    ground/main.py _motion). The five pictures are computed by the watch itself from the aerial photograph
    (make_illustrations.motion): a camera that shifts and turns between two looks, one small target drawn in."""
    W, H = W2, 214.0
    f = Fig("fig19_motion_watch", W, H, "Motion watch on the UAV: the camera's own movement is taken out before two looks are compared; what moved is reported as text over the secure link")
    it = lambda s: f"<i>{s}</i>"
    f.glyph("camera", 6, 2, 28, UAV_C)
    f.text(38, 3, 150, 15, "Camera of the UAV", fs=FS_M, bold=True, align="left", colour=UAV_C)
    f.text(38, 18, 250, 12, it("a small second picture beside the video, 8 looks a second"), fs=FS_S, align="left")
    pw, ph, yp = 96.0, 54.0, 62.0
    xs = [8.0, 112.0, 242.0, 364.0, 486.0]
    names = ["motion_prev.png", "motion_now.png", "motion_diff_raw.png", "motion_diff_fit.png", "motion_found.png"]
    heads = ["previous look", "this look", "their difference", "movement taken out", "what moved"]
    for x, name, head in zip(xs, names, heads):
        f.pic(name, x, yp, pw, ph)
        f.text(x - 6, yp - 15, pw + 12, 12, head, fs=FS_S)
    ym = yp + ph / 2
    f.edge([(xs[1] + pw, ym), (xs[2], ym)], attach=False)
    f.edge([(xs[2] + pw, ym), (xs[3], ym)], attach=False)
    f.edge([(xs[3] + pw, ym), (xs[4], ym)], attach=False)
    yn = yp + ph + 6
    f.tag(1, xs[0] + 7, yn + 7)
    f.text(xs[0] + 16, yn, 204, 26, "tiles of the two looks are correlated:<br>shift, turn and zoom of the camera", fs=FS_S, align="left", valign="top")
    f.text(xs[2] - 8, yn, pw + 16, 26, it("every edge of the<br>scene differs"), fs=FS_S, valign="top")
    f.tag(2, xs[3] - 3, yn + 7)
    f.text(xs[3] + 6, yn, 112, 26, "previous look put<br>onto this one", fs=FS_S, align="left", valign="top")
    f.tag(3, xs[4] - 3, yn + 7)
    f.text(xs[4] + 6, yn, 108, 26, "above the noise,<br>twice in a row", fs=FS_S, align="left", valign="top")
    # ---- the report and where it goes
    rx, rw = 606.0, 106.0
    f.box(rx, yp - 4, rw, ph + 8, dashed=True)
    f.text(rx, yp, rw, 13, "<b>Report</b>", fs=FS_S)
    f.text(rx + 2, yp + 15, rw - 4, 36, "where, how strong,<br>since when: a few<br>hundred bytes of text", fs=FS_S)
    f.edge([(xs[4] + pw, ym), (rx, ym)], attach=False)
    yl = 158.0
    f.edge([(rx + rw / 2, yp + ph + 4), (rx + rw / 2, yl - 4)], attach=False)
    f.glyph("lock", rx + 4, yl - 2, 20)
    f.pill(rx + 28, yl, rw - 30, 16, "AES-256-GCM", ACC_SYM, FS_S)
    f.text(rx - 6, yl + 19, rw + 12, 12, it("status stream of the link"), fs=FS_S)
    # ---- what the operator sees, and the two things the watch can be armed for
    yb = 172.0
    f.glyph("monitor", 8, yb - 11, 22)
    f.text(34, yb - 12, 150, 24, "Ground station: dashed boxes<br>on the live view, event log", fs=FS_S, align="left")
    f.glyph("photo", 204, yb - 11, 22)
    f.text(230, yb - 12, 150, 24, "PHOTO ON MOTION: a sealed<br>photo when movement begins", fs=FS_S, align="left")
    f.glyph("motion", 400, yb - 11, 22)
    f.text(426, yb - 12, 170, 24, "SENTRY: the camera watches,<br>no video is sent, only the reports", fs=FS_S, align="left")
    return f


FIGURES = [fig01_system_overview, fig02_threat_model, fig03_handshake, fig04_key_schedule, fig05_session_lifecycle, fig06_record_layer,
           fig07_video_pipeline, fig08_perception_hitl, fig09_recording_at_rest, fig10_evaluation_workflow, fig11_media_protection,
           fig12_simulation_setup, fig13_rekey_flows, fig14_hello_admission, fig15_audio_sealing, fig16_audio_clip,
           fig17_audio_excerpt, fig18_architecture, fig19_motion_watch]
