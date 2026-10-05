"""GNSS telemetry from gpsd (7Semi L89 multi-GNSS over USB/NMEA).

gpsd owns the serial device and publishes normalised JSON (TPV/SKY), so the
LCD, the telemetry sender and diagnostic tools can share the receiver.
Synthetic data is available only as an explicit test mode and is always
labelled source="SYNTHETIC".
"""
import collections
import json
import math
import socket
import threading
import time

GNSS_IDS = {0: "GPS", 1: "SBAS", 2: "Galileo", 3: "BeiDou", 4: "IMES", 5: "QZSS", 6: "GLONASS", 7: "NavIC"}
FIX_NAMES = {0: "UNKNOWN", 1: "NO FIX", 2: "2D", 3: "3D"}


class GnssState:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"source": "L89/gpsd", "connected": False, "device": None, "mode": 0, "fix": "NO DATA",
                     "time": None, "lat": None, "lon": None, "alt_m": None, "alt_msl_m": None,
                     "speed_mps": None, "track_deg": None, "climb_mps": None, "eph_m": None, "epv_m": None,
                     "hdop": None, "vdop": None, "pdop": None, "sats_used": 0, "sats_seen": 0,
                     "constellations": {}, "last_update": None, "nmea_sentences": 0,
                     "satellites": [], "ttff_s": None, "first_fix_at": None, "receiver_start": time.time()}

    def snapshot(self, with_sats=False):
        with self.lock:
            d = dict(self.data, constellations=dict(self.data["constellations"]))
            d["satellites"] = list(self.data["satellites"]) if with_sats else len(self.data["satellites"])
            return d

    def update(self, **kw):
        with self.lock:
            self.data.update(kw)


def _num(v):
    return None if v is None or (isinstance(v, float) and math.isnan(v)) else v


class GpsdReader(threading.Thread):
    def __init__(self, state: GnssState, host="127.0.0.1", port=2947):
        super().__init__(name="gnss", daemon=True)
        self.state, self.host, self.port = state, host, port
        self.running = True
        self.bad_lines = 0
        self._gsv_acc = {}
        self._gsv_sats = {}
        self._used = {}
        self._rate = collections.deque()
        self._talkers = {}
        self._txt = collections.deque(maxlen=6)

    def run(self):
        while self.running:
            try:
                with socket.create_connection((self.host, self.port), timeout=5) as s:
                    # JSON (TPV/SKY) plus raw NMEA: gpsd omits satellites without az/el from SKY,
                    # GSV still reports them (with C/N0) while the almanac is downloading
                    s.sendall(b'?WATCH={"enable":true,"json":true,"nmea":true};\n')
                    self.state.update(connected=True)
                    buf = b""
                    s.settimeout(5)
                    while self.running:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            try:
                                self._on_line(line)
                            except Exception as e:
                                # A sentence the receiver garbled in a way its checksum did not catch ("1.2.3" as an
                                # azimuth), or a gpsd report of an unexpected shape, costs that one line. It used to
                                # end this thread: position and satellite data then stopped for the rest of the flight.
                                self.bad_lines += 1
                                self.state.update(gnss_parse_errors=self.bad_lines,
                                                  gnss_last_parse_error=f"{type(e).__name__}: {e}"[:80])
                        if len(buf) > 65536:              # no line is this long: do not keep collecting it
                            buf = b""
            except OSError:
                pass
            self.state.update(connected=False)
            time.sleep(2)

    # NB: not named `_handle` — Python 3.13's threading.Thread uses that attribute internally.
    def _on_line(self, line: bytes):
        line = line.strip()
        if line.startswith(b"$"):
            self._nmea(line)
            return
        try:
            m = json.loads(line)
        except ValueError:
            return
        if not isinstance(m, dict):
            return
        cls = m.get("class")
        if cls == "DEVICES":
            devs = m.get("devices", [])
            if devs:
                self.state.update(device=devs[0].get("path"), driver=devs[0].get("driver"))
        elif cls == "TPV":
            mode = int(m.get("mode", 0))
            if mode >= 2 and (_num(m.get("lat")) is None or _num(m.get("lon")) is None):
                # gpsd can say "3D" in a report that carries no position (seen once in 172,806 fix rows: the first
                # report after the receiver had stalled for 58 s). A fix is a position: without one this is none.
                mode = 1
            if mode >= 2 and self.state.data["ttff_s"] is None:
                # time to first fix, measured from when this process started listening
                now = time.time()
                self.state.update(ttff_s=round(now - self.state.data["receiver_start"], 1), first_fix_at=now)
            self.state.update(mode=mode, fix=FIX_NAMES.get(mode, str(mode)), time=m.get("time"),
                              lat=_num(m.get("lat")) if mode >= 2 else None,
                              lon=_num(m.get("lon")) if mode >= 2 else None,
                              # alt_m is height above mean sea level (what people expect; GGA altitude).
                              # Ellipsoid height differs by the geoid undulation (about -88 m in south India).
                              alt_m=_num(m.get("altMSL", m.get("alt", m.get("altHAE")))) if mode >= 3 else None,
                              alt_msl_m=_num(m.get("altMSL")) if mode >= 3 else None,
                              alt_hae_m=_num(m.get("altHAE")) if mode >= 3 else None,
                              geoid_sep_m=_num(m.get("geoidSep")) if mode >= 3 else None,
                              speed_mps=_num(m.get("speed")), track_deg=_num(m.get("track")),
                              climb_mps=_num(m.get("climb")), eph_m=_num(m.get("eph")), epv_m=_num(m.get("epv")),
                              last_update=time.time())
        elif cls == "SKY":
            sats = m.get("satellites") or []
            cons = {}
            for sat in sats:
                name = GNSS_IDS.get(sat.get("gnssid"), "?")
                c = cons.setdefault(name, {"seen": 0, "used": 0})
                c["seen"] += 1
                c["used"] += 1 if sat.get("used") else 0
            used = m.get("uSat", sum(1 for s in sats if s.get("used")))
            self.state.update(hdop=_num(m.get("hdop")), vdop=_num(m.get("vdop")), pdop=_num(m.get("pdop")),
                              sats_used=used)
            if not self._gsv_sats:
                # fall back to gpsd's list only when no raw GSV is available
                compact = [[GNSS_IDS.get(s.get("gnssid"), "?"), s.get("svid", s.get("PRN")), _num(s.get("az")),
                            _num(s.get("el")), _num(s.get("ss")), 1 if s.get("used") else 0] for s in sats]
                self.state.update(sats_seen=m.get("nSat", len(sats)), constellations=cons, satellites=compact)


    # ------------------------------------------------------------- raw NMEA
    def _nmea(self, line: bytes):
        try:
            txt = line.decode("ascii")
        except UnicodeDecodeError:
            return
        if "*" not in txt:
            return
        body, cks = txt[1:].rsplit("*", 1)
        x = 0
        for ch in body:
            x ^= ord(ch)
        if f"{x:02X}" != cks[:2].upper():
            return                                         # corrupted sentence
        self.state.data["nmea_sentences"] += 1
        now = time.time()
        self._rate.append(now)
        while self._rate and now - self._rate[0] > 5:
            self._rate.popleft()
        f = body.split(",")
        tag = f[0]
        self._talkers[tag[:2]] = self._talkers.get(tag[:2], 0) + 1
        if tag.endswith("RMC") and len(f) >= 10:
            self._rmc(f)
        elif tag.endswith("GGA") and len(f) >= 10:
            q = int(f[6]) if f[6].isdigit() else None
            self.state.update(gga_quality=q, gga_quality_name=GGA_QUALITY.get(q, str(q)),
                              gga_sats=int(f[7]) if f[7].isdigit() else None,
                              nmea_rate_hz=round(len(self._rate) / 5, 1), talkers=dict(self._talkers))
        elif tag.endswith("TXT") and len(f) >= 5:
            self._txt.append(f"{time.strftime('%H:%M:%S')} {','.join(f[4:])}"[:80])
            self.state.update(receiver_text=list(self._txt))
        elif tag.endswith("GSV") and len(f) >= 4:
            self._gsv(tag[:2], f)
        elif tag.endswith("GSA") and len(f) >= 15:
            sys_id = f[18] if len(f) >= 19 else None
            cons = NMEA_SYS.get(sys_id) or TALKER.get(tag[:2])
            used = {int(p) for p in f[3:15] if p.isdigit()}
            if cons:
                self._used[cons] = used
                self._publish()
        elif tag == "PQTMANTENNASTATUS":
            self.state.update(antenna_status_raw=",".join(f[1:]))

    def _rmc(self, f):
        """Receiver UTC and navigation status. The receiver keeps time before it
        has a position, so this is useful even with no fix; it is only trusted
        (utc_valid) once the receiver reports a status or mode other than void."""
        t, status, date = f[1], f[2], f[9]
        mode = f[12][:1] if len(f) > 12 and f[12] else None
        utc = None
        if len(t) >= 6 and len(date) == 6 and t[:6].isdigit() and date.isdigit():
            utc = f"20{date[4:6]}-{date[2:4]}-{date[0:2]}T{t[0:2]}:{t[2:4]}:{t[4:]}Z"
        upd = {"receiver_utc": utc, "rmc_status": "VALID" if status == "A" else "VOID",
               "nmea_rate_hz": round(len(self._rate) / 5, 1),
               "nav_mode": RMC_MODE.get(mode, mode), "utc_valid": bool(utc) and (status == "A" or mode not in (None, "N"))}
        if utc:
            try:
                import calendar
                rx = calendar.timegm(time.strptime(utc[:19], "%Y-%m-%dT%H:%M:%S"))
                upd["receiver_minus_system_s"] = round(rx + float("0" + t[6:]) - time.time(), 2)
            except ValueError:
                pass
        self.state.update(**upd)

    def _gsv(self, talker, f):
        try:
            total, num = int(f[1]), int(f[2])
        except ValueError:
            return
        cons = TALKER.get(talker, talker)
        # NMEA 4.11: a trailing signal-id field follows the satellite blocks when (len-4) % 4 == 1
        sig = f[-1] if (len(f) - 4) % 4 == 1 else "?"
        key = (cons, sig)
        if num == 1:
            self._gsv_acc[key] = []
        acc = self._gsv_acc.setdefault(key, [])
        blocks = f[4:len(f) - ((len(f) - 4) % 4)]
        for i in range(0, len(blocks) - 3, 4):
            prn, el, az, snr = blocks[i:i + 4]
            if prn.isdigit():
                acc.append((int(prn), float(az) if az else None, float(el) if el else None, float(snr) if snr else None))
        if num == total:
            self._gsv_sats[key] = (time.time(), acc)
            self._publish()

    def _publish(self):
        now = time.time()
        best = {}
        for (cons, sig), (ts, sats) in list(self._gsv_sats.items()):
            if now - ts > 5:
                continue
            for prn, az, el, snr in sats:
                k = (cons, prn)
                prev = best.get(k)
                if prev is None or (snr or 0) > (prev[4] or 0):   # strongest band per satellite
                    best[k] = [cons, prn, az, el, snr, 1 if prn in self._used.get(cons, ()) else 0]
        sats = sorted(best.values(), key=lambda r: (r[0], r[1]))
        cons_count = {}
        for r in sats:
            c = cons_count.setdefault(r[0], {"seen": 0, "used": 0})
            c["seen"] += 1
            c["used"] += r[5]
        upd = {"satellites": sats, "sats_seen": len(sats), "constellations": cons_count}
        if (self.state.data.get("mode") or 0) < 2:
            upd["sats_used"] = sum(r[5] for r in sats)
        self.state.update(**upd)


GGA_QUALITY = {0: "INVALID", 1: "GPS FIX", 2: "DGPS", 3: "PPS", 4: "RTK FIXED", 5: "RTK FLOAT", 6: "ESTIMATED (DR)",
               7: "MANUAL", 8: "SIMULATION"}
RMC_MODE = {"N": "NO FIX", "A": "AUTONOMOUS", "D": "DIFFERENTIAL", "E": "ESTIMATED", "M": "MANUAL", "S": "SIMULATOR",
            "F": "RTK FLOAT", "R": "RTK FIXED", "P": "PRECISE"}
TALKER = {"GP": "GPS", "GL": "GLONASS", "GA": "Galileo", "GB": "BeiDou", "BD": "BeiDou", "GI": "NavIC",
          "IR": "NavIC", "GQ": "QZSS", "QZ": "QZSS", "GN": "GNSS"}
NMEA_SYS = {"1": "GPS", "2": "GLONASS", "3": "Galileo", "4": "BeiDou", "5": "QZSS", "6": "NavIC"}


class SyntheticGnss(threading.Thread):
    """TEST MODE ONLY. Never used unless gnss_synthetic=true in the config."""

    def __init__(self, state: GnssState):
        super().__init__(name="gnss-synthetic", daemon=True)
        self.state = state
        state.update(source="SYNTHETIC", connected=True)

    def run(self):
        t0 = time.time()
        while True:
            t = time.time() - t0
            self.state.update(mode=3, fix="3D", time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                              lat=12.9716 + 0.0005 * math.sin(t / 30), lon=79.1586 + 0.0005 * math.cos(t / 30),
                              alt_m=90.0, speed_mps=1.5, track_deg=(t * 3) % 360, sats_used=9, sats_seen=14,
                              hdop=0.9, vdop=1.2, pdop=1.5, last_update=time.time())
            time.sleep(1)
