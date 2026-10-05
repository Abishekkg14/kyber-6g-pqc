"""HD44780 16x2 LCD behind a PCF8574 I2C backpack (4-bit mode).

Pin mapping of the common backpack: P0=RS P1=RW P2=EN P3=backlight P4..P7=D4..D7.
"""
import threading
import time

BL, EN, RS = 0x08, 0x04, 0x01
REC_DOT = "\x00"                       # custom CGRAM glyph 0: filled circle (camcorder REC dot)
_GLYPHS = {0: (0b00000, 0b01110, 0b11111, 0b11111, 0b11111, 0b01110, 0b00000, 0b00000)}


class Lcd:
    def __init__(self, bus: int = 1, addr: int = 0x27):
        from smbus2 import SMBus
        self.addr = addr
        self.bus = SMBus(bus)
        self.backlight = BL
        self.lock = threading.Lock()
        self._shown = ["", ""]
        self.init()

    def _wr(self, b):
        self.bus.write_byte(self.addr, b | self.backlight)

    def _pulse(self, b):
        self._wr(b | EN); time.sleep(0.0005)
        self._wr(b & ~EN); time.sleep(0.0001)

    def _nib(self, n, rs):
        b = (n & 0xF0) | rs
        self._wr(b)
        self._pulse(b)

    def _send(self, v, rs=0):
        self._nib(v & 0xF0, rs)
        self._nib((v << 4) & 0xF0, rs)

    def init(self):
        with self.lock:
            time.sleep(0.05)
            for _ in range(3):
                self._nib(0x30, 0); time.sleep(0.005)
            self._nib(0x20, 0)
            for c in (0x28, 0x0C, 0x06, 0x01):
                self._send(c); time.sleep(0.002)
            for loc, rows in _GLYPHS.items():
                self._send(0x40 | (loc << 3))
                for r in rows:
                    self._send(r, RS)
            self._shown = ["", ""]

    def show(self, line1: str, line2: str):
        """Writes only lines that changed (each line write ~50 ms on I2C)."""
        with self.lock:
            for row, text in enumerate((line1, line2)):
                text = text[:16].ljust(16)
                if text == self._shown[row]:
                    continue
                self._send(0x80 | (0x40 if row else 0x00))
                for ch in text:
                    o = ord(ch)
                    self._send(o if 32 <= o < 127 or o < len(_GLYPHS) else ord("?"), RS)
                self._shown[row] = text
