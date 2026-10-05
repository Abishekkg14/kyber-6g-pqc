"""Rotating status screens on the 16x2 LCD, driven by live state.

Runs in its own thread at a low fixed rate so I2C writes never block the
camera, crypto or telemetry paths. If the LCD disappears (I2C error) the
manager keeps retrying in the background and the rest of the system runs on.
"""
import threading
import time

from .lcd import REC_DOT


def _f(v, fmt, none="--"):
    return none if v is None else format(v, fmt)


def screens(st: dict):
    g = st.get("gnss", {})
    link = st.get("link", {})
    cam = st.get("camera", {})
    state = link.get("state", "DOWN")
    linkword = "SECURE" if state == "UP" else state[:10]
    fix = g.get("fix", "NO DATA")
    yield ("KYBER-6G", f"LINK: {linkword}")
    yield (f"GPS: {fix}"[:16], f"SAT: {g.get('sats_used', 0)}/{g.get('sats_seen', 0)}")
    yield (f"LAT:{_f(g.get('lat'), '.5f', ' NO FIX')}", f"LON:{_f(g.get('lon'), '.5f', ' NO FIX')}")
    yield (f"ALT: {_f(g.get('alt_m'), '.1f')}m", f"SPD: {_f(g.get('speed_mps'), '.1f')}m/s")
    live = "ON" if cam.get("live") else "OFF"
    rec = " REC" if cam.get("recording") else ""
    yield (f"CAM: {live}{rec}"[:16], f"{st.get('aead', 'AES-GCM')}: ON" if state == "UP" else "AEAD: IDLE")
    yield ("PQC: ML-KEM", "REKEY: ACTIVE" if state == "UP" else "REKEY: WAIT")
    mode = cam.get("mode", "NORMAL")
    yield (f"MODE: {mode}"[:16], "IR: AUTO(LDR)" if mode == "NIGHT" else f"TEMP: {_f(st.get('system', {}).get('temp_c'), '.1f')}C")


def hms(seconds):
    s = int(seconds or 0)
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def pages(st: dict):
    """Normal rotation, or camcorder layout while recording: line 1 is a
    blinking REC dot plus the running time, line 2 rotates the status."""
    normal = list(screens(st))
    cam = st.get("camera", {})
    if not cam.get("recording"):
        return normal
    dot = REC_DOT if int(time.time() * 2) % 2 == 0 else " "
    top = f"{dot}REC {hms(cam.get('recording_elapsed_s'))}"
    mb = (cam.get("recording_bytes") or 0) / 1e6
    ticker = [f"SIZE: {mb:.1f}MB ENC"] + [l for p in normal for l in p if l != "KYBER-6G"]
    return [(top, t) for t in ticker]


class DisplayManager(threading.Thread):
    def __init__(self, get_state, bus=1, addr=0x27, screen_s=2.5):
        super().__init__(name="lcd", daemon=True)
        self.get_state = get_state
        self.bus, self.addr, self.screen_s = bus, addr, screen_s
        self.lcd = None
        self.ok = False
        self.error = None
        self.updates = 0
        self.running = True
        self.flash = None

    def show_now(self, l1, l2, seconds=2.0):
        self.flash = (l1, l2, time.time() + seconds)

    def run(self):
        idx = 0
        while self.running:
            try:
                if self.lcd is None:
                    from .lcd import Lcd
                    self.lcd = Lcd(self.bus, self.addr)
                if self.flash and self.flash[2] > time.time():
                    self.lcd.show(self.flash[0], self.flash[1])
                    time.sleep(0.25)
                    continue
                pg = pages(self.get_state())
                l1, l2 = pg[idx % len(pg)]
                deadline = time.time() + self.screen_s
                while time.time() < deadline and self.running:
                    self.lcd.show(l1, l2)            # refresh values within a page
                    self.updates += 1
                    self.ok, self.error = True, None
                    time.sleep(0.5)
                    pg = pages(self.get_state())
                    l1, l2 = pg[idx % len(pg)]
                idx += 1
            except Exception as e:                   # LCD unplugged / I2C error
                self.ok, self.error = False, f"{type(e).__name__}: {e}"
                self.lcd = None
                time.sleep(3)
