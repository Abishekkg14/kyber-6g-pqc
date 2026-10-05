# Kyber-6G multimodal secure HITL link: test report

**Date:** 2026-10-03 (rounds 1 to 4), 2026-10-04 (round 5, §14: security review and first measurement campaign; round 6, §15: attack experiments, signed hybrid file format, the measurement campaign **whose figures are the ones to quote**, and the simulation; its last tests, §15.7 and §15.8, ran into the early hours of 2026-10-05)

**Setup:** Raspberry Pi 4 Model B Rev 1.5 (UAV) ↔ laptop running WSL2 Ubuntu 22.04 (GCS), over the same Wi-Fi network.

**Policy:** every value below was measured in this session. Anything that could not be tested is marked **NOT TESTED** with the reason. Nothing is fabricated or estimated without being labelled.

## 1. Environment

| | UAV (Pi) | GCS (laptop) |
|---|---|---|
| OS | Debian 13 (trixie), kernel 6.18.34+rpt-rpi-v8 aarch64 | WSL2 Ubuntu 22.04 (mirrored networking) |
| Python | 3.13.5 (venv `~/kyber6g_venv`, with system site-packages) | 3.10.12 (`pqc_server_env`) |
| liboqs / liboqs-python | 0.16.0 / 0.16.0 | 0.16.0 / 0.16.0 |
| cryptography / OpenSSL | 50.0.1 / 4.0.2 | 50.0.1 / 4.0.2 |
| Camera stack | picamera2 0.3.37 (apt), libcamera, rpicam-apps | — |
| GNSS | gpsd 3.25 (apt), gpsd-clients | — |
| Video decode | — | ffmpeg 4.4.2 |
| CPU crypto features | `fp asimd evtstrm crc32 cpuid` (**no AES/PMULL**) | x86-64 with AES-NI |
| Hardware RNG | `fe104000.rng` (iproc-rng200), active | — |

**Installed on the Pi (apt):** `python3-picamera2 gpsd gpsd-clients python3-gps python3-serial python3-psutil i2c-tools python3-smbus2 ffmpeg`.

**Installed into the new venv:** `liboqs-python==0.16.0 cryptography==50.0.1`.

**System changes on the Pi:**
- I2C enabled via `raspi-config`.
- gpsd configured for the L89 by its stable `/dev/serial/by-id` path.
- Persistent journal enabled.
- Passwordless sudo added for `abishekkg14`, by the user.

## 2. Hardware test report

### CAMERA: **PASS** (focus and IR control: see notes)

| Check | Result |
|---|---|
| CSI detection | Initially **FAIL**: "No cameras available!". **Fixed** by reseating the ribbon and rebooting. Now: `ov5647 [2592x1944 10-bit GBRG] (/base/soc/i2c0mux/i2c@1/ov5647@36)` |
| Sensor modes | 640×480 @ 62.5 fps, 1296×972 @ 46.34 fps, 1920×1080 @ 32.81 fps (a **centre crop** of the sensor), 2592×1944 @ 15.63 fps |
| Still capture | PASS: 2592×1944 JPEG, 883 KB (rpicam test), 523 KB (app); app capture time 2.23–2.28 s including exposure settling |
| Video capture | PASS: `rpicam-vid` 720p30 H.264 High at **30.00 fps** (168 frames in 5.57 s), 1080p30 at 30.00 fps |
| Hardware H.264 encoder | PASS: `/dev/video11` (VideoCore). In-app 720p30 at 3 Mbit/s: 30.0 fps; 1080p30 at 6 Mbit/s: 30.1 fps |
| Orientation | The camera is mounted inverted. A 180° transform is applied (verified visually in the live view) |
| Normal (visible light) image | PASS. With libcamera's default tuning the colours show a strong magenta cast (R/G 2.25, B/G 1.83) because the OV5647 (F) has **no IR-cut filter**. **Fixed in the third round** with libcamera's NoIR tuning (`ov5647_noir.json`, loaded by the app): R/G 0.99, B/G 1.00 (§12.2) |
| IR LEDs (850 nm) | **PASS (visual only):** the user observed them lit. They are switched by their own light-dependent resistors and are **not software-controllable**, so there is no IR on/off API |
| Night mode (software) | PASS: exposure 33 ms → **60 ms**, frame rate allowed down to **16.7 fps**, saturation 0 (greyscale), AWB off; night still captured (mean luma 191). Return to normal: 33 ms, about 28–30 fps |
| Focus | **NOT TESTED:** a manual lens ring needs physical adjustment. A sharpness score (Laplacian variance) is reported with every capture and by the `focus` command (current values 55–109) |

### GNSS (7Semi L89): **PASS** since the first round: this table is the first-round (indoor, cold start) result, **superseded**: with the antenna outdoors the receiver reached a **3D fix with 9–11 satellites used / 22–23 tracked, HDOP 1.1–1.7, ±23 m estimated error** (see §12.3 and the live dashboard)

| Check | Result |
|---|---|
| lsusb | `1a86:55d3 QinHeng Electronics USB Single Serial` |
| Serial device | `/dev/ttyACM0` (`/dev/serial/by-id/usb-1a86_USB_Single_Serial_5B44000415-if00`), 9600 baud |
| NMEA output | PASS: GNRMC, GNGGA, GNGSA, GNGLL, GNVTG, GPGSV (GPS), GAGSV (Galileo), **GIGSV (NavIC)**, plus Quectel proprietary PQTMA |
| gpsd | PASS: active; TPV/SKY JSON received by the app |
| Fix status | **NO FIX.** The receiver date reads 1980-01-06, meaning a cold start; the antenna is indoors |
| Satellites | **0 seen / 0 used** |
| Lat / lon / alt / speed / course / UTC / DOP | **NOT AVAILABLE** (no fix). The live map shows nothing. **No synthetic coordinates were used** |

### LCD (16×2, PCF8574 backpack): **PASS** (with an electrical caveat)

| Check | Result |
|---|---|
| Wiring | Initially on the wrong end of the header (pins 35–40), so nothing appeared on I2C. **Fixed:** GND pin 6, VCC pin 4 (5 V), SDA pin 3, SCL pin 5 |
| Voltage | At 3.3 V the backpack answered, but no characters were visible at any contrast setting. Moved to 5 V **at the user's choice**. **Caveat:** the backpack's pull-ups (assumed 4.7 kΩ) to 5 V, combined with the Pi's 1.8 kΩ to 3.3 V, put SDA/SCL at about 3.7–3.8 V (calculated, **not measured**), which is above the Pi's 3.3 V rating. The fix is to remove the two pull-ups or add a BSS138 level shifter |
| I2C address | 0x27 on bus 1 |
| Initialisation / display | PASS after the user fitted the missing `LED` backlight jumper and adjusted contrast |
| Repeated updates | PASS: about 47.5 ms per line write; live rotating status screens (link, GNSS, lat/lon, alt/speed, camera/AEAD, PQC/rekey, mode/temp); the update counter rises continuously |

### NETWORK: **PASS**

| Check | Result |
|---|---|
| Pi IP | wlan0 10.88.242.240/24, Wi-Fi signal −50 dBm |
| SSH | PASS: ed25519 key authentication (alias `kyber-pi`); no password stored anywhere |
| Pi ↔ laptop | ICMP RTT 4–12 ms, 0% loss; in-app control RTT 5.2–11.5 ms |
| UDP | PASS: Pi → WSL `10.88.242.139:14600` through the Windows firewall (probe datagrams counted by the GCS) |
| Path MTU finding | UDP datagrams **larger than 1472 bytes are dropped** on WSL (0/5 delivered, even on loopback). The design keeps every datagram under the MTU |

### POWER: **PASS** after a change

- On laptop USB power: undervoltage at boot (`throttled=0x50000`) and one **spontaneous reboot**.
- On a wall adapter: `0x0`, with no undervoltage since.

## 3. Cryptographic micro-benchmarks (Pi 4)

| Operation | Median | p95 |
|---|---|---|
| ML-KEM-1024 keygen / encaps / decaps | 0.141 / 0.125 / 0.129 ms | 0.147 / 0.127 / 0.130 ms |
| ML-KEM-768 keygen / encaps / decaps | 0.111 / 0.093 / 0.092 ms | — |
| ML-DSA-87 sign / verify (4627-byte signature) | 0.703 / 0.440 ms | 1.490 / 0.448 ms |
| ML-DSA-65 sign / verify | 0.635 / 0.272 ms | — |
| X25519 keygen + exchange | 0.341 ms | 0.348 ms |
| AES-256-GCM, 1200-byte / 64 KiB records | 46.1 / 58.6 MB/s | — |
| ChaCha20-Poly1305, 1200-byte / 64 KiB records | 129.7 / 306.5 MB/s | — |
| Recording AES-256-GCM (1 s segments, in app) | 39.6–45.0 MB/s | — |

## 4. Protocol measurements over the real Wi-Fi link

| Measurement | Value |
|---|---|
| Full hybrid handshake (Pi wall clock, includes Wi-Fi) | 42.2, 33.7, 28.9, 49.3 ms (4 runs) |
| GCS handshake compute | 0.8–1.0 ms (6.7 ms on the first, cold run) |
| 1-RTT Cached RapidRekey (Pi, includes RTT) | **9.85 ms**; new session; 0 video frames lost during it |
| PQ ratchet (fresh ML-KEM-1024 + X25519) | **10.86 ms** on the Pi (round trip); 0.99 ms GCS compute; 0 frames lost; 0 authentication failures |
| Telemetry (1 Hz) latency, GNSS read → decrypted at GCS | 7.8 ms median (clock offset corrected by an NTP-style exchange) |
| Authentication failures / replay drops during normal operation | 0 / 0 |

## 5. Feature tests on the real hardware

### Feature 1: secure telemetry + LCD: **PASS** (no fix available)
- Pipeline: L89 → gpsd → JSON → AES-256-GCM → UDP → GCS decrypt → dashboard.
- 1 Hz, continuous. Sequence gaps appeared only across deliberate app restarts.
- Values shown are real gpsd output (NO FIX, 0 satellites).
- The LCD shows live link, GNSS, camera and PQC status screens.

### Feature 2: secure image pipeline: **PASS**

| Capture | Size | Encrypted chunks | Transfer + verify | Integrity |
|---|---|---|---|---|
| 1280×720 during live video (capture 294 ms) | 115 KB | 105 | 58 ms | SHA-256 PASS |
| 2592×1944 full sensor (capture 2.28 s) | 523 KB | 487 | 247 ms | SHA-256 PASS |
| 1280×720 in night mode (dashboard) | not recorded | not recorded | 19 ms | SHA-256 PASS |
| 1280×720 in night mode (standalone camera test, no transfer) | 53 KB | — | — | — |

Live video lost no frames during the image transfer made while streaming (row 1).

### Feature 3: live secure video: **PASS**

| | 720p30, 3 Mbit/s | 1080p30, 6 Mbit/s |
|---|---|---|
| Encoder fps (Pi) / decoded fps (GCS) | 30.0 / 30.0–30.1 | 30.1 / 30.3 |
| Received bitrate | 3004–3048 kbit/s | 6042 kbit/s |
| Pi sensor-exposure-start → encoded | 66.5–71.5 ms (includes 33 ms exposure) | — |
| Capture → decrypted at GCS (median) | 78.3–79.1 ms | 115.2 ms |
| GCS decode (ffmpeg, median) | 40.8–41.7 ms | 43.7 ms |
| **Capture → decoded frame, end to end (median)** | **119.4–121 ms** | **162.1 ms** |
| AES-GCM seal + sendto per chunk (Pi, Python) | 165–174 µs | 165.5 µs |
| Frames lost / chunk loss | 0 / 0.00% (936 frames in one run) | 0 |
| Pi CPU (whole app) | 8.3% | 11.6% |

**Not included:** the browser's MJPEG rendering time after decode (a few ms; not measured).

**Latency method:** capture time comes from libcamera's SensorTimestamp, mapped to wall clock. The Pi–GCS clock offset comes from a min-RTT ping exchange over the secure control channel. Per-frame decode time is from ffmpeg's in/out FIFO.

### Manual recording: **PASS**
- **Run 1** (12.26 s, while live): 361 frames, 13 segments, encryption 100 ms in total (45 MB/s). Live continued at 29.7 fps with 0 frames lost; Pi CPU 4.1%, 54 °C.
  - Transferred 4.52 MB in 2.18 s.
  - **Decrypt PASS** on the GCS (ML-KEM unwrap + all segments authenticated) in 12.2 ms.
  - MP4 produced.
  - **Bug found:** only 340 of 361 frames decoded, because the recording started mid-GOP.
- **Run 2, after the fix** (8.15 s): 27 frames before the first IDR skipped by design; 214 frames, 8 segments, 39.6 MB/s. Decrypt PASS. **214 of 214 frames decodable** (ffprobe), with no remux warnings.
- No plaintext is written on the Pi. Unit tests confirm a plaintext sample does not appear in the `.k6grec` file.

### Night vision: **PASS** (software mode)
See §2 CAMERA. IR illumination is automatic, by hardware.

### Live + recording at the same time from one encode: **PASS**
Both sinks received frames from the single `FanoutOutput`. In the standalone camera test, frame counts differed only by frames sent before the recorder attached.

## 6. Automated tests (`python -m unittest discover -s tests -t .`)

**41 tests. PASS on the laptop (16.8 s) and PASS on the Pi (17.1 s).**

| Area | Tests |
|---|---|
| Primitives | HKDF RFC 5869 test case 1 (exact vector), ML-KEM-768/1024 round trip + implicit rejection, X25519, ML-DSA-87 sign/verify, label separation |
| Replay | Window accept / duplicate / stale |
| Record layer | All streams both ways; tampering with header, payload or tag (6 positions); reorder accepted, duplicate rejected; wrong session; forged session ID gives auth-fail; malformed packets; epoch rotation with nonce uniqueness across 23 packets / 5 epochs; old epoch retired after grace; forged far-future epoch rejected without advancing the chain; nonce format |
| Handshake | Agreement (both suites); wrong pinned GCS key; unknown or forged UAV; replayed ClientHello; tampered ServerHello; bad ClientFinished; Cached Rekey: success and one-way, STALE_MOBILITY, forged MAC leaves state unchanged, replay rejected; PQ ratchet agreement; mobility-cell quantisation |
| Link (real UDP on loopback, lossy proxy) | Handshake plus data both ways; handshake under **25% random loss**; **5 injected replays of a captured record rejected as duplicate**; Cached Rekey + PQ ratchet with session switch; **recovery after link blocked**; change of mobility cell forces a full handshake |
| Media | Recording round trip with no plaintext at rest; tamper detected; truncation detected; wrong GCS key rejected; image transfer with NACK recovery under **20% loss**; video reorder within jitter; loss waits for the next IDR |

## 7. Failure and robustness tests

| Case | Result |
|---|---|
| Packet corruption | **PASS** (unit + loopback): auth-fail, nothing delivered |
| Replayed packet | **PASS** (loopback, real UDP): rejected as duplicate; stale beyond the window |
| Missing / reordered packets | **PASS**: video jitter buffer and IDR resync; image NACKs; handshake retransmission with alternating fragment order |
| Wrong key / wrong session ID / invalid tag | **PASS** (unit + loopback) |
| Forged handshake (wrong ML-DSA key) | **PASS** (unit): rejected |
| **Receiver (GCS) restart** | **PASS on real hardware, twice.** The Pi detected the timeout (5 s), retried with backoff, Cached Rekey got a MISS, and it fell back to a full handshake. Link UP about 4 s after the GCS came back; live video resumed from the next IDR |
| GPS disconnect (gpsd stopped for 8 s) | **PASS on hardware:** telemetry continued with `connected: false`, and reconnected automatically. *Physical USB unplug: NOT TESTED* |
| Camera unavailable (camera held by another process at start) | **PASS on hardware:** app starts, link and telemetry run, camera commands return a clear error; full recovery after release. *Physical ribbon unplug while running: **NOT TESTED** (unsafe while powered)* |
| LCD disconnect | **NOT TESTED** (needs physical unplugging). The code catches I2C errors and retries every 3 s without affecting other threads |
| Interrupted Wi-Fi | Link-block recovery **PASS on loopback** (unit). On the real Wi-Fi link: **NOT TESTED** directly, to avoid cutting the SSH session to the Pi; receiver restart (above) exercised the same recovery path |
| Active attacks injected over the real Wi-Fi | **NOT PERFORMED.** Replay, tamper, forged-session and malformed-packet rejection were validated over real UDP sockets on loopback (§6) |

## 8. End-to-end demonstration status

| # | Item | Status |
|---|---|---|
| 1 | PQC handshake | **PASS** (ML-KEM-1024 + X25519, ML-DSA-87, pinned keys) |
| 2 | Secure telemetry | **PASS** (GNSS fix NOT AVAILABLE) |
| 3 | LCD telemetry display | **PASS** |
| 4 | Image capture / encryption | **PASS** |
| 5 | Live video | **PASS** (720p and 1080p) |
| 6 | Manual recording | **PASS** (after the pre-IDR fix) |
| 7 | Night vision | **PASS** (software mode; IR is automatic) |
| 8 | Key rotation | **PASS** (epochs, Cached RapidRekey, PQ ratchet) |
| 9 | Replay protection | **PASS** (unit + loopback; counters show 0 false rejections on the real link) |
| 10 | Recovery from network interruption | **PASS** (GCS restart on hardware; link block on loopback) |

## 9. Defects found and fixed during testing

1. **AEAD nonce-reuse risk on the GCS** (two `Session` objects for one set of secrets). Caught in review before the first run; fixed with one object per set of secrets.
2. **Handshake fragments not combinable across retransmissions** (random fragment ID). Fixed with a content-derived ID plus alternating fragment order.
3. **Datagrams over 1472 bytes dropped** (PQ ratchet messages about 2.2 KB). Fixed with AEAD-protected fragmentation of control messages.
4. **UAV link timeout while idle** (the GCS sent no traffic). Fixed with heartbeat acknowledgements.
5. **GNSS thread crash on Python 3.13** (a method named `_handle` shadowed `threading.Thread._handle`). Renamed.
6. **Encoder timestamps relative to the first frame.** Fixed by adding back `encoder.firsttimestamp` and mapping to wall clock.
7. **Display latency misreported as about 1.1 s:** ffmpeg's `-fflags nobuffer` discarded the probed first GOP, which misaligned frame pairing. Removed the flag; real decode lag is about 42 ms.
8. **Video receiver could anchor on a P-frame.** It now starts only at a complete IDR.
9. **Recordings attached mid-GOP had undecodable leading frames.** The recorder now starts at the first IDR.

## 10. Second round (same day): startup, storage, AI, GIS dashboard

### What was wrong ("cannot start / cannot fetch")
- The ground station from the first round had been started as **a background task of the assistant's session**. When that task hit its time limit, the server was killed, so the dashboard could no longer fetch anything.
- **Fix:**
  - **Laptop:** an independent launcher, `run/Kyber6G.bat` (copied to the Desktop), plus `run/kyber6g.sh` (start/stop/status/logs/deploy/test/pipeline). **Verified:** the Desktop launcher started the ground station, and the link came up with video at 29.9 fps.
  - **Pi:** the UAV app is now a systemd service, `kyber6g-uav`, enabled at boot with `Restart=always`. **Verified:** active and enabled.

### GNSS (antenna moved outdoors): at that moment still **NO FIX**, but receiving (later reached a 3D fix: §12.3)
- The receiver has decoded the correct UTC date and time from the satellites.
- It tracks **1, then 3 GPS satellites** (PRN 10, 28, 32) at **26–38 dB-Hz** C/N0. Azimuth/elevation are not available yet (almanac still downloading).
- `$PQTMANTENNASTATUS,1,0,1` is reported. Its fields are recorded raw and not interpreted, because the field meanings were not verified.
- **Finding:** gpsd omits satellites without az/el from its SKY reports. The reader now also parses raw NMEA GSV/GSA (checksum-verified), so tracked satellites and their C/N0 appear on the dashboard and in the database.
- (First-round statement, superseded) fix-dependent analytics were **NOT TESTED** at that time. Later the same day the receiver got a 3D fix: the dashboard then showed CEP50/CEP95 8.44/19.55 m, 2DRMS 23.1 m, 99 % fix availability over the last 60 min, from 7000+ stored fix rows (§12.3). The unit tests (synthetic ring giving CEP50 = 5.00 m, 2DRMS = 10.0 m) remain.

### Automated tests: **53 on the laptop (all pass), 52 + 1 skipped on the Pi**
New tests cover:
- JSON fragmentation;
- analytics (haversine, CEP/2DRMS, fix availability, density grid);
- the NMEA parser, using real L89 sentences and a bad checksum;
- SQLite store and CSV/GeoJSON/KML exports;
- **YOLOv8n detection of "person" and "bus"** on the Ultralytics reference image. This one is skipped on the Pi, which has no ML stack.

### End-to-end pipeline test (`run/kyber6g.sh pipeline`): **27 PASS, 0 FAIL** in 45.2 s, live hardware

| Check | Measured |
|---|---|
| Link / UAV status / camera / LCD / power | UP, status age 1.0 s, ov5647, LCD updating (167 updates), `0x0` |
| Telemetry stored in SQLite | 8 rows in 10 s (1 Hz with DB-writer batching); median latency 17.1 ms |
| Live video | 30.0 fps, 3006 kbit/s, 0 of 348 frames lost, **capture→decoded 123.4 ms** (network+crypto 78.3, decode 44.9) |
| Object detection | **10.0 fps, 50.9 ms/frame** (YOLOv8n, CPU, 4 threads); one track confirmed during the run (classified "cat"; reported as produced, not verified against ground truth) |
| Image | 180 KB, SHA-256 PASS, 0.091 s; served from disk and recorded in the DB |
| Recording during live | 226 frames, 8 segments, AES-GCM 45.8 MB/s; fetched; decrypt PASS in 7.8 ms; **226/226 frames decodable** |
| Night mode | exposure 98.2 ms at 10.05 fps, then restored |
| Cached RapidRekey / PQ ratchet | 10.89 ms / 12.43 ms (UAV, includes RTT); new sessions; **0 frames lost** |
| Exports | CSV, GeoJSON (0 features: no fix yet), KML, SQLite snapshot: all valid |
| Security counters over the run | auth-fail 0, duplicate 0, stale 0, wrong-session 0, malformed 0 |

**Software added on the GCS:** venv `/root/kyber6g_gcs_venv` (1.4 GB) with torch 2.14.1+cpu, ultralytics 8.4.171, opencv-python-headless 5.0.0, liboqs-python 0.16.0, cryptography 50.0.1. Ultralytics downloaded `yolov8n.pt` (official release) and auto-installed `lap` for the tracker.

## 12. Third round: dashboard glitch, detection quality, stored-data audit, robustness

### 12.1 Dashboard "scrolls down like a glitch": root cause found and fixed (**PASS**, measured)
- **Root cause.** Every chart was a responsive Chart.js canvas (`maintainAspectRatio:false`) placed directly in a flowing panel with no fixed-height parent. Chart.js then resizes the canvas to its container and the container grows with the canvas, so the page keeps getting taller on the TELEMETRY, SECURITY and DATA tabs. On top of that the whole dashboard rewrote its DOM once per second: re-created thumbnails have height 0 until decoded (page jumps), a log that always scrolled itself to the bottom, a telemetry table that pushed its rows down by one every second, a map that cleared and re-added 600 polylines every second.
- **Fix.** Every chart sits in a fixed 230 px `.chartbox`; DOM is rewritten only when the generated HTML changed (`setHTML`); thumbnails have a fixed 16:9 box; lists have fixed heights; tiles and key/value rows are one line (ellipsis + tooltip); logs auto-scroll only when you are at the bottom; the data table pauses while the mouse is over it or it is scrolled; map layers, sky plot and charts redraw only when their data changed; the page reloads itself when the dashboard files on the server change (a stale open tab cannot keep running old code).
- **Measured in the browser (1280×800, 22 s per tab, live data):** TELEMETRY page height constant at 3542 px, chart boxes 230 px each; SECURITY 1431 px; DATA 1508 px; MISSION layout-shift score 0.0000, 0 shifts, scroll position unchanged.
- **Overlay boxes** (separate problem: boxes lagging and jittering). Each box is now smoothed with an alpha-beta filter and moved to where the object should be in the frame being shown (the detector reports the capture time of the frame it analysed). Simulation with realistic detector noise (1 % of the frame, 5 fps detector, 0.4 s latency, `tests/js/boxtracker_sim.js`): mean error vs the true position **22 px vs 31 px** for a swaying object, **83 px vs 123 px** for a fast one, **67 px vs 75 px** with a 2 fps detector; a still object jitters **0.51 px/frame vs 1.11**. Labels are black on a solid colour, never overlap, and a track's label is a confidence-weighted vote with hysteresis (no cup↔mug flicker).

### 12.2 Other defects found and fixed in this round
| # | Finding | Fix | Verified |
|---|---|---|---|
| 1 | **Mobility-cell flapping.** The cached-rekey context is a 0.001° (≈111 m) cell; with ±23 m of GNSS noise a UAV resting near a cell edge flipped cells and re-handshook 4 times in 2 min (`link RECOVERING mobility cell changed`) | `MobilityTracker`: the cell only changes after the position is 0.3 cell beyond the old edge | unit test (500 jittered fixes around an edge → no flip; a 5-cell move → changes) |
| 2 | Altitude was stored as ellipsoid height (−62 m) | `alt_m` is now MSL; ellipsoid height and geoid separation stored separately; 1476 legacy rows repaired (backup kept, old value in `alt_hae_m`) | audit |
| 3 | Detection track ids restarted at 1 on every run, so the `tracks` table merged unrelated objects across runs | database ids are `run·10⁷ + generation·10⁵ + id` | unit test |
| 4 | Telemetry sequence numbers restart with the UAV app; duplicates looked like replays | the UAV sends a boot id; audit checks uniqueness per boot | audit: 0 duplicates in 9 boots |
| 5 | Text-embedding cache made with YOLOE-11s was reused for 11L (embeddings pass through a model-specific adapter): every score ≈ 0.02 | cache keyed by weights | live check |
| 6 | A bad query string (`?minutes=abc`) killed the request without a response; an oversize POST left an unread body on a keep-alive connection | clean 400 / 413 JSON, connection closed | `tests/test_http_api.py` (5 tests) |
| 7 | Camera had a magenta cast (no IR-cut filter): R/G 2.25, B/G 1.83 | libcamera's `ov5647_noir.json` tuning: R/G 0.99, B/G 1.00 | measured on the Pi, frame inspected |

### 12.3 Stored-data audit (`python -m kyber6g.tools.data_audit --pi kyber-pi`): **27 PASS, 0 WARN, 0 FAIL**
SQLite integrity ok; 7025 fix rows all with valid coordinates, none stored without a fix, none synthetic; no impossible jumps (>60 m/s) in 7015 fixes; satellite C/N0 within range; 30 244 detection boxes valid; all 260 track snapshots exist; all 9 images match their SHA-256; the 3 recordings on the GCS decrypt and are complete; no credentials in events, `ground.log` or the UAV journal; private keys 0600 on both machines; the 8 media files on the UAV are 0600 and real `K6GREC01`/`K6GIMG01` containers; no empty orphan recordings; SD card 31 % used.

### 12.4 Object recognition: "it cannot even find a pencil or a screwdriver" (measured; `python -m kyber6g.tools.detect_bench`)
**Why it failed.** The real-time detector was an open-vocabulary YOLO (YOLOE) prompted with the words "pencil" and "screwdriver". Measured, that does not work, for any model size or generation.

**Test set** (all on the laptop CPU, 12 logical cores, no GPU): 11 pencil and 14 screwdriver photos from Wikimedia Commons (titles in `tests/data_detect_bench_titles.json`); **8 real camera frames with a pencil held up** (taken before the NoIR colour tuning, so pink); 25 negatives (20 everyday scenes, the 2 Ultralytics samples, 3 real camera frames without the object); 8 "hard" negatives (pens, a brush, chopsticks). Score = highest confidence of the target word per image. AUC = how well the score separates positives from negatives (0.5 = chance, 1.0 = perfect). "Pencil" positives are the 11 photos + 8 camera frames pooled (19).

| Model (text prompt, 120-word everyday vocabulary) | s / image | pencil AUC | pencil found @ 0.2 (false hits in 25) | screwdriver AUC | screwdriver found @ 0.2 (false) |
|---|---|---|---|---|---|
| YOLOE-11s | 0.84 | 0.44 | 0/19 (1) | 0.50 | 0/14 (0) |
| YOLOE-11L | 0.51 | 0.49 | 4/19 (3) | 0.50 | 0/14 (0) |
| YOLOE-26s | 0.22 | 0.54 | 1/19 (1) | 0.46 | 0/14 (0) |
| YOLOE-26m | 0.55 | 0.50 | 2/19 (2) | 0.49 | 0/14 (1) |
| **OWLv2 base @ 960 px** | 5.95 | 0.86 | 11/19 (7) | **1.00** | **14/14** (1) |
| **OWLv2 base @ 640 px** (finder default) | **1.73** | **0.88** | 11/19 (6) | **1.00** | **14/14** (1) |
| OWLv2 640 px, int8 dynamic quantisation | 1.22 | 0.70 | 1/19 | 0.78 | 0/14 |
| OWLv2 480 px, int8 | 0.70 | 0.72 | 0/19 | 0.62 | 0/14 |
| OWL-ViT v1 (B/32, 768 px) | 2.02 | 0.65 | 10/19 (1) | 1.00 | 11/14 (0), but 5/8 pens/chopsticks fire |
| YOLO-World v2 s / l, Grounding DINO tiny | not benchmarked in full: YOLO-World scored ≤ 0.14 on the 8 camera frames in a first check (and ≈ 0 for the words on a live frame); Grounding DINO did not finish 66 images × 2 prompts in 13 minutes on this CPU and was stopped | | | | |

**What the numbers say**
- Text-prompted YOLOE is at chance for both words. This is the reason you saw no pencil and no screwdriver. It is a property of the model's training vocabulary, not a configuration error (11s, 11L, 26s and 26m all measured; the text-embedding cache bug in §12.2 is separate and was fixed before the 11L row was produced).
- **OWLv2 finds them in clear photos**: screwdriver 14/14 (AUC 1.00); pencil 11/11 of the photos at a score ≥ 0.49. A threshold of 0.35 at 640 px keeps all of these, with 4 false pencil hits in 25 scenes (2 at 0.40, 0 at 0.50); a box is only shown if the score is ≥ 0.50, or the hit repeats on a second pass.
- 640 px gives the same recall as 960 px at 3× the speed. int8 quantisation destroys OWLv2's accuracy. OWL-ViT v1 is not faster in practice and confuses pens/chopsticks with both words.
- **Not solved:** on the 8 real camera frames the pencil scores 0.04–0.16 with every text-prompted model, including OWLv2 (also after gray-world or measured channel correction, greyscale, prompt ensembles and cropping). A thin pencil in dim, IR-lit 720p video is outside what these models recognise from a word.
- **Visual prompts work where words fail**: one box drawn on the live video (TEACH) made YOLOE-11L find that pencil in **7 of 7** other frames (scores 0.59–0.94) with no false "pencil" on three other images, in an earlier same-session test. Prototypes built from public photos instead of the camera did not transfer: pencil 3/11 held-out photos and 0/8 camera frames, and the screwdriver prototype fired on pencils, pens and chopsticks (0.87–0.99). They were therefore **not shipped**.
- **What the dashboard now does:** the real-time detector keeps ~120 everyday classes; the **FINDER** (OWLv2 @ 640 px, background thread, one look every 4 s by default, boxes held and extrapolated) looks for the words you give it (default: pencil, screwdriver) and shows a "weak signal" hint below the threshold; **TEACH** adapts to your own object in your own camera. Every finder pass (best score per word) is stored in the `finder_passes` table, and frames that scored ≥ 0.18 are kept in `~/kyber6g_ground/finder_candidates/` so the threshold can be tuned on real footage.
- **NOT TESTED:** a physical pencil and screwdriver held in front of the camera with the new NoIR tuning, through the dashboard. The numbers above are on public photos and on older (pink) camera frames. If a held pencil does not appear, use TEACH once, and send the candidate frames for tuning.
- Cost: the finder takes about 2.5 s of CPU per look; while it runs the real-time detector drops from ~5.5 fps to ~2.7 fps. Dashboard selector: ECO 10 s / BALANCED 4 s / CONTINUOUS.

### 12.5 Automated tests and the end-to-end run (this round)
- **Laptop: 89 tests, all pass** (`python -m unittest discover -s tests -t .`; ~65–85 s including the real detector, OWLv2 finder, teach-by-example and the photo-feed end-to-end test). **Pi: 82 pass, 7 skipped** (the ML-only tests: the Pi has no torch/OpenCV).
- New this round: detector profiles, label voting, teach/forget (with a real YOLOE-11L visual prompt), database-id uniqueness, store migration, finder logic and decoding (real OWLv2 on a photo), candidate frames, HTTP layer robustness (oversize body, bad JSON, bad query strings, traversal, teach with bad images), overlay box tracking simulation, dashboard script syntax and DOM-id consistency, camcorder LCD layout, encrypted photo store (round trip, tamper, wrong key, traversal), recorder status and orphan cleanup, NMEA RMC/GGA/TXT, mobility-cell hysteresis, clock-offset filter, scheduling and UDP counters.
- **End-to-end pipeline on the live hardware** (`bash run/kyber6g.sh pipeline`; 42 PASS checks incl. the new ones: finder running, detection feed validity, label stability, photo stored encrypted on the Pi → fetched → decrypted → same SHA-256, REC timer advancing, second REC refused without an orphan file, stored-data audit): see the last run in the table below.

| Check | Measured in the last full run |
|---|---|
| Overall | **42 PASS, 0 FAIL in 64.7 s** (final run, finder enabled, detector running) |
| Video | 30.1 fps, 2.77 Mbit/s; 1 frame lost of 334 in the first 12 s (check allows ≤ 1 %); capture→decoded **107.7 ms** median (network + crypto 50.3 ms, decode 57.1 ms). Earlier runs: 30.2–30.4 fps, capture→decoded 96–121 ms |
| Photo stored on the Pi | `.k6gimg` written, listed (6 photos on the UAV), fetched, decrypted in 5.0 ms, same SHA-256 as the live copy |
| Recording | 226 frames, 8 segments, 48.4 MB/s AES-GCM on the Pi; decrypt PASS; **226/226 frames decodable**; REC elapsed 4.1 → 7.1 s with size and frame count advancing; a second start is refused without an orphan file |
| Rekeying | 1-RTT Cached RapidRekey 17.7 ms, PQ ratchet 25.9 ms (UAV side, includes the round trip); 1 frame lost of ~180 during the rekey window (limit 1.5 %); authentication failures / replays: 0 |
| Telemetry | 10 rows in 10 s, latency 6.6 ms median, GNSS 3D fix (6 of 23 satellites used) |
| Detector | general profile, 120 classes, 1.65 fps with the finder running, labels stable (0 of 4 tracks changed label in 12 s), detection feed frame age 2.06 s with the finder running |
| Finder | OWLv2 @ 640 px, 60 passes, 3.2 s per look while competing with the detector, no errors |
| Stored-data audit | 27 PASS, 0 WARN, 0 FAIL |

Per-rekey probe (finder OFF, 8 cached rekeys): 0 frames lost of 1249, every rekey switched the session. The finder-ON counterpart of this probe was interrupted before it finished, so it is **NOT TESTED** in that exact form; the 32-rekey measurement in §12.6 covers both settings.

### 12.6 Robustness findings from the end-to-end run
1. **The finder starved the video receiver.** With the finder running, 12 frames were lost during the rekeys in the first run. Isolated: finder OFF → 0 lost in 1502 frames (with and without rekeys); finder ON → 24 lost in 752 frames **with no rekey at all**. The kernel's UDP counter `RcvbufErrors` was 267 and the socket buffer was only 425 KB (`net.core.rmem_max` = 212 992 in WSL). **Fixes:** the two ML worker threads lower their own priority (detector nice 5, finder nice 10, `ground/sched.py`), the launcher raises `net.core.rmem_max` to 8 MB for this boot of WSL (`run/kyber6g.sh`; the socket now really gets its 4 MB request), the finder is duty-cycled (one look per 4 s), background browser tabs stop pulling the MJPEG stream, and the SECURITY tab now shows the receive buffer and kernel drop counter. After the fixes: 0 frames lost in 4 × 25 s windows (finder on/off, with and without a cached rekey + PQ ratchet). **Residual, measured honestly:** over 32 further rekeys (16 cached, 16 PQ) with finder on/off, 12 of 5809 frames (0.2 %) were lost, in 5 of the 32 cycles (never more than 8 frames, i.e. one keyframe interval is enough to recover); in an instrumented run no GCS drop counter moved and the UAV reported no send failures, which points to ordinary Wi-Fi/UDP loss (no retransmission by design), not to the rekey itself. The pipeline check therefore allows up to 1.5 % loss during a rekey window instead of demanding exactly 0.
2. **Clock offset gate froze.** The GCS only accepted a ping/pong sample if its RTT was < 1.5× the best RTT ever seen, so after one very good sample the offset was never refreshed; telemetry latency read **−52 ms**. Replaced by an NTP-style filter (lowest-RTT sample of the last 30 s); unit test with lopsided samples and drifting clocks.
3. **Pipeline check bug:** the telemetry-rate check compared a fresh database count with a value cached up to several seconds earlier (read −32 rows in 10 s on a loaded machine). Both reads now use the same fresh endpoint.
4. **Detector rate display** averaged over a pause (0.54 fps right after the stream restarted); now over the last 5 s.
5. **Real-time detector cost of the finder:** 4.5 fps alone → 2.1 fps with the finder at one look per 4 s (ECO 10 s / CONTINUOUS selectable in the dashboard).

## 13. Fourth round: complete system test (encryption pipeline, ML features, dashboard, failure cases)

Everything in this section was measured on 2026-10-03 between 20:05 and 23:50 on the live hardware. Tools: the unit tests, `run/kyber6g.sh pipeline`, the new `run/kyber6g.sh ui-test` (headless Chromium 153 driven by Playwright), and scripted soak / crash / restart runs.

### 13.1 Results at a glance

| Test | Result |
|---|---|
| Unit tests, laptop | **127 run, all pass** (60.9 s; real YOLOE / OWLv2 models, node for the overlay simulation) |
| Unit tests, Pi | **119 run, all pass, 7 skipped** (the ML-only tests; the Pi has no torch / OpenCV) |
| End-to-end pipeline on the live hardware | **41 PASS, 1 FAIL** in 83.5 s, and in the last run (on the instance started by the Desktop launcher) **43 PASS, 1 FAIL** in 74.9 s. Every encryption, media and ML check passes. The one FAIL is the clock of this laptop's WSL VM (§13.2 no. 1): first as the new check "ground-station clock steady" (drift 9.09 %), and in the last run, where WSL had just been restarted and the clock check passed (drift 0.01 %), as a capture→decoded latency of −61.6 ms because the clock went slow again while the run was in progress. It is an environment fault that the test now reports instead of silently printing impossible latencies; the pipeline was changed afterwards to re-check the clock at that point (not re-run) |
| Dashboard in a real browser (`ui-test`) | **94 PASS, 0 FAIL**: no layout shift on any of the 5 tabs at 1366×768 and 1920×1080 with live video running, long-text stress, no JavaScript error, every control exercised (§13.3) |
| Crash / restart recovery with a dashboard page open | **14 of 14 PASS** (§13.4) |
| Soak: 5.5 min live video + detector + finder + 6 Mbit/s recording, 250 MB fetched | 1 frame lost of 15,566; no thread, file-handle or memory growth on either machine; recording rolled over into 2 parts, 9,941 of 9,941 frames decrypted (§13.5) |
| Stored-data audit | 27 PASS, 0 WARN, 0 FAIL |
| The 46-minute, 1.04 GB recording that could not be fetched | copied and decrypted: **PASS**, complete, 2,790 segments, 83,697 frames, 2,789.9 s MP4 |

### 13.2 Defects found, with the measurement that showed them, and the fix

| # | Symptom / measurement | Cause | Fix (and test) |
|---|---|---|---|
| 1 | Video "32.7–34.5 fps" from a 30 fps camera; telemetry latency between −2,390 ms and +2,566 ms; the pipeline passed "capture→decoded −367 ms" | The **clock of the WSL VM runs 8.33 % slow** (45.28 s per 49.4 s of Pi time) and the host steps it forward by ~2.9 s every ~35 s. First noticed after a wake-up from Modern Standby. Switching the kernel clock source to `hyperv_clocksource_tsc_page` did not change the rate (tried, reverted). A restarted WSL VM was right at first (+0.1 % 40 s after boot, 0.01 % a minute later) and **8.3 % slow again about two minutes after boot**, once live video and inference were running; it stayed slow through 3.5 idle minutes. **Root cause not determined** (host CPU / Hyper-V timekeeping on this laptop) | Not fixable from the application, so it is made harmless and visible: frame rate, bit rate and all detection/overlay timing now use the **camera's capture clock**; the clock offset is a fitted line (offset + drift) that adopts a step at once (`ClockSync`, 3 unit tests); the SECURITY tab, the latency tiles (*APPROX*), the pipeline, the launcher and `kyber6g.sh clock` report it. Measured with the clock slow: 30.0 fps, network+crypto 60–90 ms, capture→decoded 118–140 ms, telemetry latency −1…17 ms; for about half a minute after the rate changes the latency estimates can be off by ~100 ms. **The clock itself is still wrong on this laptop** |
| 2 | Finder model took **124–128 s** to load; one core at 94 % with no video; dashboard sluggish before LIVE | From start-up until the first video frame both ML workers spun in a tight loop (the wait condition was already true: no picture yet, but sequence number 0 ≠ −1) and starved every other thread of the interpreter lock | The workers block until there is a frame (`sched.next_frame`). Measured after: **3 % CPU idle, finder loaded in 4.0 s** |
| 3 | A video frame lost and "new computer mouse #1" announced again every ~35 s | Ages were measured on the wall clock: every clock step made the half-received frame look 2.9 s old (lost) and looked like a 2.5 s pause to the tracker (reset) | All intervals use the monotonic clock (video sink, detector, finder, transfers); unit test with a stepped clock |
| 4 | "92,966 frames lost" after the laptop had been in standby for 43 minutes | The sink walked through every missing frame number and counted each as lost | A jump of more than 90 frames is one *stream gap*: resynchronise at the next keyframe. Also covers a UAV restart (frame numbers start at 0 again) without pressing LIVE. Unit test |
| 5 | After a crash the ground station was back only after **95.5 s**; 4.0 GB and 4.7 GB `wsl-crash-*.dmp` files in the Windows temp folder | WSL's crash handler captured the 1.4 GB process (and its keys) before the restart could begin | Both applications mark themselves non-dumpable (`no_core_dumps`); the launcher restarts a crashed ground station. Measured after: **answering again 4.2 s after the crash**. The two existing dump files were left in place (8.7 GB, they contain key material): delete them |
| 6 | A 46-minute recording (1.04 GB) was listed with a FETCH button; fetching would have read it into the Pi's 1.8 GB of RAM twice, and the receiver refuses anything over 256 MB | No size limit on the sender, no limit on recording length | The UAV refuses with a clear message *before* reading the file; the list marks it *TOO LARGE*; `kyber6g.sh pull` copies and decrypts it. New recordings roll over into independent parts of 192 MiB (each with its own key and FINAL segment). Transfers are abandoned when they **stall** (30 s without a new chunk) instead of after a fixed 120 s. Unit tests + live: 201.8 MB part fetched in 105.9 s (15.2 Mbit/s), integrity and decrypt PASS |
| 7 | RTT 352 ms while a recording was being closed | UAV commands ran in the link's receive thread | Commands run on a worker thread; a flood gets "UAV busy". Unit tests |
| 8 | PQ ratchet could be refused for ever | Request and answer are single datagrams; one lost answer left the attempt "in flight" permanently | The request is repeated, the GCS answers a repeat with the same answer (one new session, not two), an unanswered attempt expires after 3 s. Unit test |
| 9 | SECURITY tab: "handshakes ok 96" after 2 real handshakes | Every cached rekey was also counted as a full handshake on the GCS | Counted separately (unit test). |
| 10 | One bad database row would drop a batch of up to hundreds; a value SQLite cannot bind would end the writer thread | Only `sqlite3.Error` was caught | Failed batches are retried row by row; any exception is survived and shown (`last_error`). The same for every background loop on both machines (stats, transfers, telemetry, status, link manager, housekeeping, detector, finder): an error is logged and the loop continues. Unit tests |
| 11 | Recorded video could not be scrubbed; every preview downloaded the whole file | No HTTP byte ranges | `Range` requests (206) and chunked file serving; checked by `ui-test` |
| 12 | 48 tracebacks in the log; non-object JSON bodies killed the handler | Closed browser connections treated as errors; `[1,2]` has no `.get` | Quiet handling of closed connections; 400 for wrong-shaped bodies (unit test) |
| 13 | Dashboard: `IndexSizeError … source width is 0` on every tab change; table sort ignored while the pointer was on the table; header pills shifting by a few pixels when "9/23" became "10/23"; status lines that would wrap (and move everything below) when their text got longer; large empty panels on three tabs; MEDIA empty after a restart; page dead without internet access to three CDNs | see left | Heat layer guarded; sort forced; fixed-width pills; fixed-height status lines with the full text as tooltip; panels fill their columns; gallery and operator settings restored from disk; fonts and libraries served locally (`static/vendor`, 1.7 MB): only map tiles need the network (verified: the page requested `127.0.0.1:8600` and the tile server only, and worked with everything else blocked) |
| 14 | After STOP the tiles still showed "30.3 fps", "AI 1.6 FPS", objects "person: 1" | Rates were only updated when a frame arrived | Rates read 0 and the AI pill reads IDLE when nothing is being received / analysed (unit tests, `ui-test`) |
| 15 | APPLY 640×480 would keep showing 1280×720 (ffmpeg rescales silently to the first size) | One decoder process for all streams | A new SPS (or ▶ LIVE) starts a fresh decoder with its own queue; `ui-test` checks the picture really is 640×480, then 1280×720 |
| 16 | Telemetry around the 43-minute standby: 2,548 of 2,570 samples stored (2,536 of them delivered afterwards as backfill), **22 missing in one gap**; around the 9-minute standby 533 of 533 | The UAV only notices a dead link after 5 s of silence; what it sent in that window was gone, not buffered | The samples of that window are queued again when the link is declared down, and the GCS drops a sample it already has (same UAV start time and number, also across a GCS restart). Unit test: every sample exactly once across a simulated loss. **Not re-measured with a real standby after the fix** |

### 13.3 Dashboard, measured in a real browser (`bash run/kyber6g.sh ui-test`)

- Method: headless Chromium, live video on. Per tab and at three scroll positions (top / middle / bottom, 8 s each): the browser's own Layout Instability entries (any element that moves without user input), position and size of every panel 4× per second, document height, scroll position. Then every status line, heading note, tile and table value is filled with a 990-character text at once and the panels are measured again.
- Result at 1366×768 and 1920×1080, all five tabs: **0 layout shifts, constant page height, no panel moved, no horizontal overflow, long texts move nothing, 0 JavaScript errors.**
- Controls exercised through the page, all PASS: ▶ LIVE (picture moving, 20–31 fps shown), detection boxes drawn and inside the picture, ◘ PHOTO (SHA-256 verified, shown in MEDIA), ● REC (indicator and timer advance; second REC refused; SAVE; SAVE with nothing recording), NIGHT / DAY, FOCUS, APPLY 640×480 and back, AI off/on, BOXES, SERVER-DRAWN, profile FAST, FIND with own words, back to GENERAL, confidence, FINDER off / on with words, **TEACH** (one box on the frozen picture → ACCURATE runs with the taught class → FORGET), cached rekey and PQ ratchet buttons (new session, link stays up), telemetry table and sort, charts, map, SET HOME, sky plot, 3D map, list / fetch / decrypt a stored photo and a recording, the recording loads in the page's player, database and Pi panels, all six exports, ■ STOP (NO SIGNAL shown, rates 0).
- **Limit:** this is Chromium in software rendering (14–17 animation frames per second), not the operator's own browser window; the in-app browser of the assistant was hidden and cannot measure this.

### 13.4 Failure and recovery (dashboard page open, live video running)

| Event | Measured |
|---|---|
| Ground station killed with SIGSEGV | page shows "not reachable" after 0.1 s and NO SIGNAL (not a frozen picture); the launcher has it answering again after **4.2 s**; secure link re-established after 4.7 s (one full handshake); the **same page** shows moving video again 5.7 s after the crash, no reload |
| UAV service restarted on the Pi | page shows NO SIGNAL after 4.3 s; link and status back after 6.4 s; the page says "press ▶ LIVE"; LIVE works |
| Laptop in Modern Standby (unplanned, twice: 9 and 43 minutes; Windows event log) | link UP 3 s after wake-up by cached rekey / handshake; the 201.8 MB transfer that was in progress was reported as *FAILED: stalled*; the telemetry the UAV buffered meanwhile was delivered afterwards: 533 of 533 and 2,548 of 2,570 samples (§13.2 no. 16) |
| Wi-Fi stall of about 5–7 s (once, during start/stop cycles; cause not determined, Wi-Fi power save is on on the Pi) | UAV declared link timeout and recovered with a cached rekey 2 s later; the GCS counted one extra handshake |
| 6 rekeys under live video (3 cached, 3 PQ) | 0 frames lost of 399; cached rekey 11.7–14.5 ms, PQ ratchet 12.1–13.2 ms (UAV side, including the round trip) |

### 13.5 Soak and resources

- 5.5 min: live 1280×720 at 6 Mbit/s + real-time detector + finder + recording. Video 30.0 fps throughout, **1 frame lost of 15,566**, 3 late chunks.
- Recording: 9,941 frames in 2 parts (201.8 MB + 48.3 MB). Both fetched over the secure link while live video kept running at 30.0 fps (105.9 s and 24.2 s, 15–16 Mbit/s), SHA-256 PASS, decrypt PASS (655 ms / 269 ms), 8,010 + 1,931 = **9,941 frames, match**.
- Ground station: 64 threads and 15 open files before, during and after; memory 1,361 → 1,663 MB after the two large transfers and 1,855–1,872 MB after one more complete 202 MB fetch plus one that the standby interrupted (transfer buffers kept by the allocator). On the Pi the same repeat did not add memory: 291 MB before and after the complete repeat fetch.
- Pi: open files 63 idle → 80–81 while streaming → **63 again after 6 start/stop cycles**; 15 ↔ 18 threads; 60.8 °C peak, never throttled.

### 13.6 How trustworthy are the real-time detector's labels? (measured)

128 labelled photos (COCO128; 697 labelled objects of classes the 120-word vocabulary covers), run exactly as the dashboard runs the detector. A box is *correct* if its word maps to a COCO class and it overlaps (IoU ≥ 0.5) a labelled object of that class; *wrong* if no such object is there or it sits on an object of another class; boxes with words COCO has no label for (lamp, shelf, hat …) cannot be judged and are left out of the precision.

| Profile | Threshold | Correct | Wrong | Precision | Objects found (recall) |
|---|---|---|---|---|---|
| GENERAL (YOLOE-11s, 640 px) | 0.25 (old default) | 311 | 173 | 64.3 % | 44.6 % |
| GENERAL | **0.40 (new default)** | 264 | 88 | **75.0 %** | 37.9 % |
| GENERAL | 0.50 | 224 | 57 | 79.7 % | 32.1 % |
| ACCURATE (YOLOE-11L, 512 px) | 0.30 (old default) | 341 | 122 | 73.7 % | 48.9 % |
| ACCURATE | **0.40 (new default)** | 308 | 81 | **79.2 %** | 44.2 % |
| ACCURATE | 0.50 | 271 | 50 | 84.4 % | 38.9 % |

- At the old default more than a third of the judged labels were wrong. Raising the threshold to 0.40 halves the wrong labels (173 → 88) and keeps 85 % of the correct ones.
- ACCURATE at 0.40 finds as many objects as GENERAL did at 0.25 with fewer than half the wrong labels, but next to the FINDER it analyses **1.6–1.8 frames/s** on this CPU against 2.8–3.3 for GENERAL, so GENERAL (at 0.40) stays the start-up profile and ACCURATE is one click away (`detector_profile` in the ground configuration).
- This is a general-photo benchmark, not the UAV camera: on the camera's own scenes (a ceiling, a cloth on a line, hangers) the low-confidence labels were wrong more often ("bird", "umbrella", "lamp" at 0.26–0.36), which is what the higher threshold removes.

### 13.7 NOT TESTED, and what is left

- **The WSL clock is still running about 8 % slow on this laptop**, and a WSL restart did not last (right for about two minutes, see §13.2 no. 1). Cause not determined; a time daemon that can discipline large rate errors inside WSL (for example chrony against the Hyper-V clock device) would be the place to fix it and was **not** set up. Until then latency figures are estimates and timestamps written by the ground station (`rx_ts`, event times) can be up to ~3 s behind; times stamped by the UAV are not affected.
- The telemetry fix for the moment a link dies (§13.2 no. 16) and the pipeline's second clock check were made after the last full runs: covered by unit tests, **not re-run on the hardware**.
- A physical pencil / screwdriver in front of the camera: still **NOT TESTED** (§12.4).
- The dashboard in the operator's own browser window (GPU rendering): **NOT TESTED** by measurement, only in headless Chromium.
- SD card really full, a real write error during a recording: **NOT TESTED** on hardware (unit-tested with a simulated error and a simulated free-space value).
- Operation with the internet physically disconnected: **NOT TESTED**; tested with every host except the ground station blocked in the browser, and with the ML libraries switched to their local files.
- The 5–7 s Wi-Fi stall seen once: cause **not determined**.
- A recording longer than one part was tested live with two parts; more than two parts only in the unit test.

## 14. Fifth round (2026-10-04): security review, hardening, measurement campaign for the paper

Three things were done in this round, in this order: the whole present system was read for vulnerabilities and hardened (`docs/SECURITY_AUDIT.md`: 18 findings, all fixed, with regression and fuzz tests); the hardened system was deployed to the Pi and tested again; a measurement campaign was run on it for the plots of the paper (`paper_plots/`: every sample, the scripts, the plots and their tables). Conditions of the campaign: 2026-10-04, about 06:30 to 07:05, Wi-Fi at 5 GHz (channel 48, about −65 dBm at the Pi), camera 1280×720 at 30 fps and 3 Mbit/s, a dark room (about 3 lux), one UAV, on a desk.

**Which clock.** The laptop's WSL clock still runs slow (rate 0.917 to 0.922 of real time during the campaign). Durations of handshakes, rekeys and round trips were therefore timed **on the Pi**; values timed on the laptop were divided by the clock rate measured against the Pi in the same run, and the raw values are kept in the data files.

### 14.1 Results at a glance

| Test | Result |
|---|---|
| Unit tests, laptop | **185 run, all pass** (67.3 s; 95.3 s when repeated beside 1080p video and the ACCURATE detector) |
| Unit tests, Pi | **177 run, all pass, 8 skipped**: 4 need the detection models or OpenCV, 3 need node.js (the dashboard's scripts), 1 needs root. The code on the Pi was compared with the repository by hash: identical |
| of these, new in this round | 58 in `tests/test_hardening.py`: regression tests for the findings of the review, and fuzz tests (4,000 random and mutated datagrams to each end of a running link; 1,500 random authenticated control messages; 3,000 mutations of a genuine record; truncations and bit changes of the handshake messages and of stored recordings and photos) |
| End-to-end pipeline on the live hardware, hardened system | **40 PASS, 1 FAIL**, twice (77.5 s and 79.8 s; the second run after the last deployment, made with the repository's own `kyber6g.sh deploy`). The FAIL is the laptop's WSL clock again (drift 11.1 % in both runs, §13.2 no. 1). Stored photo and recording fetched and decrypted, PASS. Video frames lost during the 6 rekeys of the test: 0 of 391 in the first run; **3 of 479 (0.63 %) in the second**, all in the round in which the PQ ratchet took 2.7 s instead of about 14 ms, that is, its own datagrams were lost too (a stall of the radio link, signal −70 dBm at the time; the limit of the check is 1.5 %) |
| Dashboard in a real browser (`ui-test`), hardened system, Content-Security-Policy enforced | **93 PASS, 0 FAIL**, no policy violation and no JavaScript error reported by the browser; every control exercised as in §13.3 (link counters when it ended: 1 full handshake, 10 cached rekeys, 5 PQ ratchets, nothing rejected). One check had nothing to check: no object was in view of the camera (dark room), so no detection box was drawn |
| Stored-data audit | **31 PASS, 1 WARN, 0 FAIL**. The audit now also checks the modes of the key, pinned-key and media directories on both machines and the confinement of the UAV service. The WARN is a defect this round found (§14.4 no. 1) |
| Session operations during live video (campaign) | **450 of 450 succeeded** (150 full handshakes, 150 cached rekeys, 150 PQ ratchets), **0 of 4,313 video frames lost** |
| 13 minutes of live video with automatic rekeying (campaign) | 23,401 frames, **3 lost**; 7 cached rekeys, 1 PQ ratchet, 19 epoch rotations |
| Static checks of the code and its dependencies | `docs/SECURITY_AUDIT.md` §4 |

### 14.2 What the review changed (summary; details and tests in `docs/SECURITY_AUDIT.md`)

- **Record layer:** the sequence number, which is the AEAD nonce, was taken without a lock; two threads sealing on one stream could use one number. Reproduced with the lock removed and the interpreter forced to switch threads as often as it can: 1,738 of 32,000 records reused a number on the laptop (Python 3.10), 0 of 32,000 at the normal switching interval, 0 of 64,000 on the Pi (Python 3.13). Now one lock per stream.
- **Dashboard:** it accepted commands from any web page open in the operator's browser and could be read through DNS rebinding. Now every request is checked (Host, Sec-Fetch-Site, Origin, content type) and the page carries a Content-Security-Policy. Checked on the running station: foreign Host 403, foreign Origin 403, `text/plain` command 415.
- **Availability of the handshake:** 32 forged fragments per 5 s filled the reassembly table; one forged datagram per second with the UAV's address used up its hello quota; one unverifiable answer ended an attempt on the UAV. All three removed; tested over real sockets with three forged answers per genuine datagram.
- **On disk:** key, pinned-key and media directories are 0700, media files 0600 from the first byte; the recording and photo parsers report damage as one error type.
- **UAV service:** confined by systemd (no new privileges, read-only file system except the two media directories, private `/tmp`).
- No way was found for an outsider to obtain session keys, to get a forged or replayed record accepted, or to impersonate either end.

### 14.3 Measurement campaign (all values measured; n and the distributions are in `paper_plots/tables/`)

| Quantity | n | Result |
|---|---|---|
| ML-KEM-1024 key generation / encapsulation / decapsulation, Pi | 300 each | 0.116 / 0.126 / 0.130 ms (median) |
| ML-DSA-87 signing / verification, Pi | 300 each | 0.741 ms (5th to 95th percentile 0.537 to 1.437) / 0.455 ms |
| X25519 key generation / key agreement, Pi | 300 each | 0.100 / 0.260 ms |
| The same operations on the laptop | 300 each | 3.2 to 8.4 times faster |
| **Full handshake** (1.5-RTT), timed on the UAV, over Wi-Fi, live video running | 150 | median **22.9 ms**, 95th percentile 31.6 ms, maximum 39.9 ms |
| **1-RTT Cached RapidRekey** | 150 | median **9.1 ms**, 95th percentile 15.7 ms, maximum 18.6 ms |
| **PQ ratchet** | 150 | median **14.0 ms**, 95th percentile 22.1 ms, maximum 52.6 ms |
| Computing inside those medians (in-process benchmark of the same steps) | 300 | full handshake 2.33 ms on the Pi + 0.43 ms on the laptop; cached rekey 0.15 + 0.05 ms; PQ ratchet 0.92 + 0.15 ms. The rest is the radio and waiting for it |
| Bytes on the wire, headers included | counted | full handshake 13,106 bytes in 13 datagrams (9,254 of them the two signatures, 3,136 ML-KEM); PQ ratchet 4,757 bytes in 5; cached rekey 324 bytes in 3 |
| AEAD on the Pi, 1,100-byte payload | 300 samples of 54 calls | AES-256-GCM 363 Mbit/s, ChaCha20-Poly1305 1,013 Mbit/s (the Pi has no AES instructions); whole record layer, seal: 32.1 µs and 16.6 µs |
| Round trip on the same path | 150 / 600 | ICMP 7.6 ms median; secure control message 8.8 ms median, 0 of 600 lost |
| Capture → decoded picture, 720p30 | medians | 126 ms = 70 (camera and H.264 encoder) + 1.8 (sealing and sending the 12 records of a frame) + 3.8 (radio, one way) + 50 (decoder). The ground station's own estimate in the same run: 125 ms |
| 13 minutes of live video (780 s) | 23,401 frames | 3 frames lost, all at 769.5 s in a radio stall, none at a rekey or an epoch rotation; Pi CPU 8.3 % (median), 46 to 52 °C, never throttled |
| Stored recording fetched over the link (7.19 MB) | 5 | 16.4 Mbit/s (one run 14.1), SHA-256 PASS and decrypt PASS five times |
| Photo taken, fetched and checked (about 210 kB) | 10 | 0.10 s each, SHA-256 PASS ten times |
| Pi CPU: idle / live video / live video and encrypted recording | 180 / 1,320 / 240 samples | 0.7 % / 8.3 % / 6.0 % (median) |

These replace the first-round figures of §3 and §4 wherever they differ: those came from a few runs each (the full handshake from four: 28.9 to 49.3 ms).

**Packet loss** was injected on the Pi with an nftables rule that drops datagrams at random in both directions; the loss given is the one counted by the rule. Per level: about 41 s of video, 10 operations of each kind requested, 3 photos requested. The three operation columns read "completed, of those the UAV started" (from the UAV's own log).

| Datagrams lost (counted) | Video frames complete | Video frames decoded | Full handshakes | Cached rekeys | PQ ratchets | Requests that never reached the UAV | Photos received intact |
|---|---|---|---|---|---|---|---|
| 0 % | 100 % | 100 % | 10 of 10 | 10 of 10 | 10 of 10 | 0 of 30 | 3 of 3 |
| 0.45 % | 94.8 % | 41.5 % | 10 of 10 | 10 of 10 | 10 of 10 | 0 of 30 | 3 of 3 |
| 0.97 % | 88.8 % | 13.9 % | 9 of 9 | 10 of 10 | 10 of 10 | 1 of 30 | 3 of 3 |
| 1.78 % | 81.7 % | 5.8 % | 10 of 10 | 10 of 10 | 10 of 10 | 0 of 30 | 3 of 3 |
| 5.26 % | 57.1 % | 0.2 % | 10 of 10 | 10 of 10 | 8 of 8 | 2 of 30 | 2 of 3 |
| 10.0 % | 34.8 % | 0 % | 9 of 9 | 9 of 9 | 9 of 9 | 3 of 30 | 3 of 3 |
| 20.2 % | 12.0 % | 0 % | 7 of 9 | 9 of 9 | 4 of 6 | 6 of 30 | 3 of 3 |

- **The session survives loss.** Of the 198 operations the UAV started, 194 completed; the four that did not were timeouts at 20 % (2 full handshakes, 2 PQ ratchets). Retransmission costs time: the median full handshake took 1.2 s at 5 % and 10 % and 2.4 s at 20 %, against 23 ms without loss. The link never went down and there was no authentication failure.
- **A command from the ground station is sent once.** 12 of the 210 requests never reached the UAV, and for 7 more the UAV did the work but its acknowledgement was lost, so the ground station reported "timeout waiting for UAV acknowledgement" 19 times. The operator has to press again; commands are **not repeated automatically**.
- **Photos:** 20 of 21 arrived, every one intact (missing chunks are asked for again); one request at 5 % got no answer.
- **Live video is the weak point.** A frame is 12 datagrams, so 0.45 % datagram loss already damages 5 % of the frames, and after a damaged frame the receiver shows nothing until the next keyframe: 41.5 % of the frames were shown at 0.45 % loss, 5.8 % at 1.78 %. A keyframe request and forward error correction are **not implemented**.

### 14.4 Defects found in this round besides the findings of the review

| # | Symptom / measurement | Cause | Fix (and test) |
|---|---|---|---|
| 1 | Stored-data audit: 4 of 79 stored images no longer match their database row | Photo files were named by the second; the loss test took photos faster than that. In four pairs the second picture replaced the first, on the UAV's card and in the ground station's folder | Names carry milliseconds and the store never overwrites (unit test). **The four replaced pictures are lost**; their rows stay in the database, so the audit keeps warning about them |
| 2 | After a browser test or a pipeline test the detector was off (and stayed off across restarts), a test object was still taught, the camera was stopped | The tests changed the operator's settings and did not put them back; a run that was interrupted left more behind | Both tests restore the detector, finder and camera settings they found |
| 3 | Browser test: 15 checks failed with "EvalError … unsafe-eval" | The new Content-Security-Policy forbids `eval`, which the test tool's own wait function uses inside the page. The dashboard itself was not affected | The tool polls with plain evaluations instead |
| 4 | Found when comparing the Pi with the repository: nothing in the repository installed the Pi's service file or set the directory modes the hardened code insists on; both had been done by hand | `kyber6g.sh deploy` only copied the code and restarted the service. A Pi set up from the repository alone would have kept an old, unconfined unit | `kyber6g.sh deploy` now sets the modes, byte-compiles the code (the confined service may not write any) and installs the unit file when it differs, keeping the one it replaces. Run for real: service active, link up in under a second, exposure rating 3.8; afterwards every Python file, script and the unit file on the Pi had the same SHA-256 as in the repository |
| 5 | After the browser test the operator's word list for the CUSTOM profile was the test's (cup, bottle, person) | The test put back the profile but not the word list | It puts back both; the request was tried against the running station. **This last change was made after the final browser-test run and has not been through a full run** |

### 14.5 NOT TESTED in this round

- **Energy.** No power meter was used; there is no measured energy figure for any operation. The energy values of the earlier simulation study are model values.
- **Glass-to-glass latency** (scene to screen). The budget above ends at the decoded picture.
- **Loss in bursts, delay and jitter.** Only random, independent drops were injected; no test at range or behind obstacles.
- **More than one UAV, a UAV in flight, any radio other than Wi-Fi.** No 5G or 6G radio has been used at any point.
- **The comparison "hardware against ns-3 simulation"** of the earlier study is not a measurement of anything: its simulated column is computed from the hardware column (`README.md`, status note). It was not repeated; no ns-3 run was made in this round.
- Formal verification, side channels, an independent penetration test (`docs/SECURITY_AUDIT.md` §7).
- The Pi's pending operating-system updates (108 packages, 14 from the security archive) were **not installed**.
- The items of §13.7 that need the operator (a pencil or screwdriver in front of the camera, the dashboard in the operator's own browser window, a really full SD card, the internet unplugged) are unchanged.

## 15. Sixth round (2026-10-04, afternoon): attack experiments, file format 2, final measurement campaign, simulation

After round 5 the implementation was attacked by experiment instead of read (`docs/CRYPTANALYSIS_REPORT.txt`), which brought five more findings (`docs/SECURITY_AUDIT.md` §8, findings 19 to 23). They were fixed, the stored-file format was replaced by a signed hybrid one, the Pi's operating system was updated, and **the whole measurement campaign was repeated on the final code**. The numbers of this section replace those of §14.3 wherever they differ. Conditions: 2026-10-04, 14:33 to 15:13 (primitives, idle, transfers, timeline, loss) and 17:02 to 17:14 (round trips and session operations, repeated after the last change to the link code); Wi-Fi at 5 GHz, same access point; camera 1280×720 at 30 fps and 3 Mbit/s, a dark room (2 to 4 lux), one UAV, on a desk; detector (GENERAL profile) and finder running on the ground station.

**Which clock.** Durations of session operations and round trips are timed on the Pi. The laptop's WSL clock ran between 0.999 and 1.019 of the Pi's rate during the runs; every value timed on the laptop is divided by the rate measured in the same run, and the raw values are kept.

### 15.1 Results at a glance

| Test | Result |
|---|---|
| Unit tests, laptop (final code) | **211 run, all pass**, none skipped (83 s). 26 more than in round 5: 18 in `tests/test_sealing.py` (file format 2: hybrid wrap, signature, every way of damaging or forging a file), 2 for the change of position cell, 1 for the flood ration, 5 for the video path of the ground station (§15.5 no. 8 and 9: a slow decoder makes the picture skip, the detectors yield and slow down, a delimiter behind every frame, the real decoder gives each picture before the next frame arrives) |
| Unit tests, Pi (final code, after the last deployment) | **203 run, all pass, 8 skipped** (51 s): 4 need the detection models or OpenCV, 3 need node.js, 1 needs root. The 85 files that are deployed (`kyber6g/`, `tests/`, `deploy/uav.json`) are byte for byte the repository's. Service active, 0 restarts, confinement rating 3.8 |
| Attack experiments (`bash run/kyber6g.sh measure attacks`), on the Pi and on the laptop | **27 kinds of experiment PASS on both machines; 339,084 attack attempts, 0 accepted**; 192,000 records sealed by racing threads, no nonce used twice (§15.3) |
| Session operations during live video | **450 of 450 succeeded** (150 full handshakes, 150 cached rekeys, 150 PQ ratchets); 1 of 4,071 video frames lost during them |
| 13 minutes of live video with automatic rekeying | 23,485 frames, **10 lost** (single frames, none at a rekey or an epoch rotation); 7 cached rekeys, 1 PQ ratchet, 19 epoch rotations |
| Stored recording (format 2) fetched and opened | 5 of 5: SHA-256 PASS, signature PASS, decrypt PASS |
| Photos taken, fetched and checked | 10 of 10 in the transfer test, 21 of 21 in the loss test |
| End-to-end pipeline on the live hardware (final code, §15.8) | **42 PASS, 1 FAIL** in 75 s. The one failure is the laptop's clock, not the link (the WSL clock ran 5.9 % fast against the UAV's, with jumps: §13.2). 0 of 338 frames lost in 12 s, the decoder never behind; three cached rekeys (8.4 to 9.8 ms) and three PQ ratchets (12.3 to 14.8 ms) with 0 of 347 frames lost; photo and recording stored, fetched, verified, decrypted; no record rejected |
| Stored-data audit | **35 PASS, 2 WARN, 0 FAIL**. New checks in this round: recordings and photos carry the UAV's ML-DSA-87 signature (verified against the pinned key), both recording keys are present, no classical-only public-key algorithm in the code, the SSH key exchange to the Pi is a post-quantum hybrid. The two warnings: the four photos replaced in round 5 (§14.4 no. 1), and one telemetry row from the second in which the GNSS receiver acquired its fix (8 satellites "used" against 7 "seen": the receiver's two reports were not of the same second) |
| Dashboard in a real browser (`ui-test`, final code, §15.8) | **93 PASS, 0 FAIL** in 10 minutes: five tabs at two window sizes with no layout shift and no overflow, every control pressed (live, photo, recording, modes, resolution, detector profiles, finder, teach and forget, cached rekey, PQ ratchet, exports, stored photos and recordings fetched and decrypted), no script error, no failed request, no HTTP error |
| Camera after the operating-system update (Waveshare RPi Camera (F), OV5647) | detected, 1280×720 and 1920×1080 at 30 fps, photo at 2592×1944, NORMAL and NIGHT mode: PASS |
| Simulation: replica of the test bed against the measurements (§15.6) | full handshake 23.1 ms simulated against 23.2 measured, cached rekey 9.1 against 9.0, **PQ ratchet 16.3 against 14.1** (16 % too slow); video frames complete under loss within 0.8 points at six loss rates. 1,830 runs, none failed |

### 15.2 Measurement campaign on the final code (all values measured; n and the distributions are in `paper_plots/tables/`)

| Quantity | n | Result |
|---|---|---|
| ML-KEM-1024 key generation / encapsulation / decapsulation, Pi | 300 each | 0.116 / 0.126 / 0.131 ms (median) |
| ML-DSA-87 signing / verification, Pi | 300 each | 0.768 ms (5th to 95th percentile 0.540 to 1.638) / 0.455 ms |
| X25519 key generation / key agreement, Pi | 300 each | 0.101 / 0.261 ms |
| The same operations on the laptop | 300 each | 3.2 to 8.4 times faster |
| **Full handshake** (1.5-RTT), timed on the UAV, over Wi-Fi, live video running | 150 | median **23.2 ms**, 95th percentile 30.8 ms, maximum 44.9 ms |
| **1-RTT Cached RapidRekey** | 150 | median **9.0 ms**, 95th percentile 17.3 ms, maximum 95.0 ms |
| **PQ ratchet** | 150 | median **14.1 ms**, 95th percentile 22.0 ms, maximum 187 ms |
| Where the time goes, timed **inside the operations themselves** (new in this round) | 150 each | full handshake: UAV 8.2 ms, ground station 1.9 ms, link and waiting 13.2 ms. Cached rekey: 2.3 / 0.3 / 6.5 ms. PQ ratchet: 3.1 / 1.9 / 9.1 ms |
| The same computing steps alone in a benchmark loop | 300 | full handshake 2.31 ms on the Pi + 0.41 ms on the laptop; cached rekey 0.16 + 0.05 ms; PQ ratchet 0.93 + 0.15 ms |
| Bytes on the wire, headers included | counted | full handshake 13,106 bytes in 13 datagrams; PQ ratchet 4,757 bytes in 5; cached rekey 324 bytes in 3 |
| AEAD on the Pi, 1,100-byte payload | 300 samples | AES-256-GCM 360 Mbit/s, ChaCha20-Poly1305 1,012 Mbit/s (the Pi has no AES instructions); whole record layer, seal: 31.9 µs and 16.4 µs |
| Round trip on the same path | 150 / 600 / 300 | ICMP 7.7 ms median; secure control message on the UAV's timer 8.2 ms, 0 of 600 lost; the same message sent right after a command from the ground station 6.6 ms |
| Capture → decoded picture, 720p30 (measured again at 23:05, after the decoder was changed: §15.5 no. 9) | medians of 240 samples, 3,592 frames, none lost | **91 ms** = 69 (camera and H.264 encoder) + 1.8 (sealing and sending the 12 records of a frame) + 3.8 (radio, one way) + 16 (decoder). The ground station's own estimate in the same run: 95 ms |
| Live video, cost of protection on the Pi | 783 s | 356 records per second, 155 µs each to seal and send: 5.5 % of one core. Bytes added: record header and tag 4.6 %, UDP and IP headers 2.7 % |
| 13 minutes of live video (783 s) | 23,485 frames | 10 frames lost; Pi CPU 8.7 % (median), 53 °C (median), 57.5 °C at most, never throttled |
| Stored recording fetched over the link (7.37 MB, 587 frames) | 5 | 16.4 to 16.6 Mbit/s (one run 14.5) |
| Photo sealed on the Pi, format 2 (hybrid wrap, signature) | 100 / 25 | 3.4 ms (50 kB), 8.1 ms (200 kB), 32 ms (1 MB), 92 ms (3 MB); format 1: 1.6, 5.3, 25, 71 ms |
| Photo opened on the laptop, format 2 (signature verified first) | 100 / 25 | 0.31, 0.50, 1.9, 4.9 ms |
| Bytes a stored file gains | counted | format 2: 6,761 (signature trailer 4,637, ML-KEM ciphertext 1,568); format 1: 1,947 |
| Pi CPU: idle / live video / live video and encrypted recording | 180 / 1,319 / 241 samples | 1.0 % / 8.7 % / 6.0 % (median) |

**Two things this campaign showed that round 5 had not.**

- **The computing inside an operation is slower than a benchmark of it.** Round 5 put the benchmark times of the steps (2.3 ms on the Pi for a full handshake) beside the measured duration and called the rest "the radio". Timed inside the running programs, the same two steps take 6.4 ms on a Pi that is encoding video (2.8 times as long), installing the new session takes another 1.7 ms, and the ground station needs 1.9 ms, not 0.4. The link itself accounts for 13.2 ms of the 23.2.
- **An exchange started by a command is faster than one started on a timer.** A probe message the UAV sends on its own timer comes back after 8.2 ms (median); the same message sent right after a command from the ground station arrived comes back after 6.6 ms (the radio of the Pi is awake, the ground station's thread is running). The session operations of the campaign are all started by a command, so the second number is the one that belongs to them; the simulation's delay model uses it (`simulation/README.md` §2).

**The decoder's share of the latency budget was wrong in the campaign as first reported, and has been measured again.** The 13-minute run reported 17 ms for the decoder (93 ms in all). The decoder then held every frame until the next one arrived, so a picture appeared one frame period (33 ms) after that; in the ground-station process of that run the pictures were paired with the capture time of the following frame, which hid it (§15.5 no. 9). Round 5 had measured the same decoder at 50 ms (126 ms in all), which was right. The decoder was changed so that it no longer holds frames, and the budget above is from a run on that code: 16 ms beside the GENERAL detector and the finder, 8 ms with both paused.

**Packet loss**, injected and counted as in §14.3. Per level: about 41 s of video, 10 operations of each kind requested, 3 photos requested. The three operation columns read "completed, of those the UAV started".

| Datagrams lost (counted) | Video frames complete | Video frames decoded | Full handshakes | Cached rekeys | PQ ratchets | Commands acknowledged | Photos received intact |
|---|---|---|---|---|---|---|---|
| 0 % | 100 % | 99.9 % | 10 of 10 | 10 of 10 | 10 of 10 | 30 of 30 | 3 of 3 |
| 0.55 % | 93.6 % | 35.2 % | 10 of 10 | 10 of 10 | 10 of 10 | 30 of 30 | 3 of 3 |
| 1.01 % | 88.6 % | 19.6 % | 10 of 10 | 10 of 10 | 10 of 10 | 29 of 30 | 3 of 3 |
| 2.07 % | 78.9 % | 3.0 % | 9 of 9 | 10 of 10 | 10 of 10 | 28 of 30 | 3 of 3 |
| 4.76 % | 59.5 % | 0.6 % | 9 of 9 | 9 of 9 | 10 of 10 | 26 of 30 | 3 of 3 |
| 10.4 % | 33.3 % | 0 % | 10 of 10 | 10 of 10 | 8 of 8 | 24 of 30 | 3 of 3 |
| 19.9 % | 13.3 % | 0 % | 7 of 8 | 4 of 6 | 7 of 7 | 16 of 30 | 3 of 3 |

- **The session survives loss.** Of the 196 operations the UAV started, 193 completed; the three that did not were timeouts at 19.9 % (1 full handshake, 2 cached rekeys). Retransmission costs time: the median full handshake took 1.2 s at 10 % and 2.4 s at 20 %, against 23 ms without loss; up to 5 % loss the medians of all three operations stayed where they are without loss. The link never went down and there was no authentication failure.
- **A command from the ground station is still sent once**: 27 of 210 were not acknowledged (the request or its acknowledgement was lost) and have to be sent again by the operator.
- **Photos:** 21 of 21 arrived intact (missing chunks are asked for again); a transfer took 0.1 s without loss and up to 1.6 s at 10 to 20 %.
- **Live video is the weak point**, as in §14.3: a frame is 12 datagrams, 0.55 % datagram loss damages 6.4 % of the frames, and after a damaged frame nothing is shown until the next keyframe (35 % of the frames shown at 0.55 % loss, 3 % at 2 %). A keyframe request and forward error correction are **not implemented**; what they would give is simulated (`simulation/README.md`, plot 16) and labelled as such.

### 15.3 Attack experiments (`kyber6g/tools/attack_bench.py`; full account in `docs/CRYPTANALYSIS_REPORT.txt`)

| What was tried | Attempts (per machine) | Accepted |
|---|---|---|
| Records: one bit changed, forged, replayed, spliced into another stream or session, second suite | see report §4.3 to 4.5 | 0 |
| Handshake: either end impersonated, messages modified, replayed, mixed between two handshakes, suite downgraded, key shares replaced, degenerate X25519 key | §4.2, 4.3, 4.6 to 4.8 | 0 |
| 1-RTT Cached RapidRekey: forged, replayed and misused requests, modified answers | §4.9 | 0 |
| PQ ratchet: key share replaced | §4.8 | 0 |
| Stored photos and recordings: modified, cut, extended, segments rearranged, forged, re-signed with another key, opened with one of the two keys wrong | §4.13 | 0 |
| **All of the above** | **169,542** | **0** (both machines: 339,084, 0) |
| Nonce reuse (a stress test of the sender, not an attacker's input): 8 threads sealing on one stream while the key rotates | 96,000 records sealed (192,000 on both) | no (key, nonce) pair used twice |
| Forged fragment injected into a ClientHello in flight | 200 | 0 accepted; 100 transmissions spoiled, the repeat accepted in 200 of 200 cases |
| Flood of forged ClientHellos, 0 to 10,324 per second | §4.12 | every genuine connection made; see below |
| Timing of the MAC comparison and of a failing tag check (Welch's *t*, 5 rounds on each machine) | §4.14 | largest \|*t*\| 2.7 (threshold 4.5); a deliberately leaking comparison as control: \|*t*\| from 116 to 1,706, found in every round |

**Flood.** The ration of failing signature checks is a quarter of one core: 3,274 per second on the laptop, 561 on the Pi. With the ground station on the laptop a genuine UAV connected in 5 to 7 ms under up to 3,000 forged hellos per second (156 Mbit/s), and in 2.4 s at 10,324 per second. With the Pi in the role of the ground station: 10 to 29 ms up to 300 per second; 1.2 s (median) at 1,000, 8.6 s at 3,000, 10 s at 4,860 per second, the slowest connection 33 s. **A flood above the ration delays the connection; it was never prevented, and nothing was disclosed or accepted.**

**Statistics of the ciphertext** (`kyber6g/tools/media_stats.py`; a public-domain aerial picture, 768 × 768, sealed as a stored photo): entropy 7.41 / 6.91 / 5.98 bits per byte (R / G / B) before, 7.9997 after; correlation of neighbouring pixels 0.92 to 0.97 before, 0.000 after; χ² of the byte histogram 233 to 285 (limit 293 at 5 %); NPCR 99.61 %, UACI 33.45 % between two sealings of the same picture (expected for random data: 99.61 and 33.46); 200 of 200 modified files refused. These say the ciphertext looks random, which every sound cipher achieves; they are not evidence of security by themselves (the report, §5).

### 15.4 What was changed in this round

- **File format 2** for stored photos and recordings: the file key is wrapped under ML-KEM-1024 **and** X25519, and the UAV signs the file with ML-DSA-87; the ground station verifies the signature before it uses its own keys (findings 21, 22). Format 1 is still read.
- **A change of position cell** no longer interrupts the stream: the handshake it needs is made in place (finding 19).
- **The flood ration** follows from the cost of a check on the machine (finding 20).
- **SSH** between laptop and Pi (deploy, service control, measurements) uses a post-quantum hybrid key exchange, `sntrup761x25519-sha512` (finding 23); the stored-data audit checks it.
- **The UAV times the phases of its own operations** and the ground station its time on each request; both are in the operation log and in `paper_plots/data/link_ops.json`.
- **Operating system of the Pi:** 88 packages updated (all 14 from the security archive); 19 held back (kernel, firmware, bootloader, Wi-Fi firmware, camera applications), because they change the boot chain or the camera stack and want someone next to the Pi.
- **Repository:** the legacy prototype, the old simulation scripts and their plots were removed from the working tree (they remain in the git history); documents that describe them are in `docs/legacy/`.

### 15.5 Defects found in this round

| # | Symptom / measurement | Cause | Fix |
|---|---|---|---|
| 1 | Findings 19 to 23 of the security review | `docs/SECURITY_AUDIT.md` §8 | fixed, with tests |
| 2 | The attack bench reported the flood test as failed on the Pi (7 of 8, then 35 of 36 connections) | The flood generator ran in the same Python interpreter as the ground station under test and took its processor time; 30 s were allowed per connection | The generator is a process of its own, the rate is set, 60 s are allowed. 36 of 36 on both machines. The long connection times on the Pi at high rates are real and reported |
| 3 | Timing test on the Pi: *t* = −22 for the MAC comparison | The two classes of input used two fixed buffers; their different places in memory were measured, not the comparison | Fresh buffers for every sample, five rounds, and a control that does leak (found: \|*t*\| ≥ 116) |
| 4 | A command the UAV refuses (recording with a full card, a photo that no longer exists) was logged as an ERROR with a traceback | An expected refusal was handled as a fault | Logged as a WARNING with the reason |
| 5 | The first replica of the test bed in the simulation predicted the cached rekey and the PQ ratchet slower than measured | Its link delays came from round-trip probes sent on the UAV's timer; the operations are started by a command, and such an exchange is faster (§15.2) | The delay model uses probes started by a command, with the ground station's own time on the probe removed. What remains is in §15.6 |
| 6 | Titles and labels of a plot ran beyond the page edge, and the build did not notice | The build measured the page and the fonts, not whether text reaches beyond the figure | `plotlib.save` measures every text against the figure and the build fails on any that is cut; it also reports any two texts that lie on top of each other |
| 7 | The headline number of the attack experiments (531,084 "attempts") was too large | It added the 192,000 records that the nonce stress test seals to the inputs an attacker sent | Counted apart: 339,084 attack attempts, none accepted; 192,000 records sealed in the race, no nonce used twice (plot 10, the report, every document) |
| 8 | The live picture fell up to 20 s behind the camera for about a minute, every 2.7 minutes (pipeline test: decoder latency 5.3 s, 7 of 338 frames lost in one round) | The laptop's firmware runs the processor at 17 % of its speed when it gets too hot (§15.7). In the ground station, frames waited for the decoder in a queue limited by number (120 frames) and not by time | A frame that has waited 1 s is given up with everything behind it and decoding starts again at the next keyframe; the detector and the finder start nothing while the decoder is behind, and run slower afterwards (§15.7). Measured in the same condition: the picture stays within 2.0 s of the camera |
| 9 | **Every picture was shown one frame late (33 ms at 30 fps), and in the campaign of §15.2 the ground station reported its decoder latency 33 ms too small** | ffmpeg's H.264 parser knows that a frame has ended only when the next one begins, so each frame waited in the decoder for its successor. Pictures are paired with the capture time of their frame by counting; in the ground-station process of the campaign the count was off by one (pictures out equal to frames in, which a decoder that holds a frame cannot give), so each picture carried the capture time of the frame after it. How the count came to be off was not found (12 runs of the old decoder with a recording of the Pi's encoder: paced, in a burst, after a pause, after a restart of the stream, after a lost frame; all gave one picture per frame) | An access unit delimiter is written behind every frame (the picture comes 8 ms after its own frame instead of 8 ms after the next one), ffmpeg passes pictures through without its constant-frame-rate logic, and a capture time whose picture never came is dropped after a second instead of being given to the next picture. The latency budget was measured again (§15.2) |
| 10 | Pipeline test and browser test reported failures when the operator had paused the detector (3 each) | Both assumed the detector to be running | They switch it on for the test and put the operator's setting back |
| 11 | The browser test ended with an exception instead of a result (`Page.screenshot: Timeout 30000ms exceeded`) | A screenshot of the layout sweep was taken while the processor was throttled (no. 8) | The screenshot gets 60 s, and a screenshot that fails is reported, not fatal |

### 15.6 Simulation (everything in this subsection is simulated, not measured)

The earlier simulation study was withdrawn (its "simulated" values were the hardware values plus random numbers). It was replaced by a simulation of the implemented protocol in ns-3.42 with 5G-LENA: `simulation/README.md` has the model, the calibration and every result; `paper_plots/` the figures (plots 11 to 16). In short:

- **1,830 runs** in seven studies, 3 h 5 min on ten cores; no run failed; the library ran with its assertions enabled. In the 480 runs with an NR cell (9,160 simulated UAVs) every UAV got its session and none fell silent.
- **The model is checked against the measurements of §15.2 that it was not built from.** A simulated replica of the Wi-Fi test bed gives 23.1 ms for the full handshake (measured 23.2), 9.1 ms for the cached rekey (measured 9.0) and **16.3 ms for the PQ ratchet (measured 14.1: 16 % too slow, cause not found)**. Video under loss: frames complete within 0.8 points of the measured share at all six loss rates, frames given to the decoder within 2.6 points.
- **Simulated 5G NR cell (3.5 GHz, 100 MHz; a model, not a measurement):** with up to 64 UAVs streaming video in an uplink-heavy cell the full handshake stays at 23 to 30 ms (median) and at least 99.7 % of the frames reach the decoder; a downlink-heavy cell carries 32 such UAVs and is overloaded by 48 (the uplink capacity for video is the limit, not the session protocol). 64 UAVs that start at the same instant all have their session after 156 ms. A UAV at 30 m/s makes 15 handshakes a minute, each 26 ms, without losing a frame. From 250 m to 4 km the operations take the same time.
- **Ablations (simulated):** against a classical X25519/Ed25519 handshake the implemented suite costs 10 ms per handshake on the Wi-Fi link and 27 times the bytes; the X25519 half of the hybrid costs 1.2 ms. Combining the fragments of repeated handshake messages raises the share of handshakes that complete at 20 % loss from 29 % to 83 %. With the fixed repeat timers of the implementation 95 % of the full handshakes are done within 1.2 s at 1 % loss; a timer of three round trips (not implemented) would make that 61 ms. A keyframe on request and one parity datagram per frame (neither is implemented) would raise the usable video at 2 % loss from 6 % to 80 %.
- **How far the runs can be repeated:** test-bed runs byte for byte (11 of 11 sampled, with a rebuilt simulator). NR runs only with the program that made them: another build of the same source changes single runs by up to 5.5 % and the medians reported here by 0.9 % at most (two whole studies, 130 runs, made again: `simulation/results/rebuild_check.json`). The cause is inside ns-3 or the NR library and was not located.
- **Under loss the replica is checked for its steps, not to the millisecond:** 89 of the 163 operations measured under loss lie inside the simulated 5th-to-95th-percentile band (nine in ten would if it were exact).
- **Key-refresh schedule (measured, `paper_plots/tables/table_rekey_schedule.csv`):** an hour of the implemented schedule (24 cached rekeys, 6 PQ ratchets) costs 36 kB and 80 ms of computing on the UAV; a full handshake at each of those instants would cost 393 kB and 247 ms.

Found while building the simulation, each of which would have given wrong numbers that look plausible: the NR library's UE has no retransmission timer for its buffer status report (UAVs fell silent for the rest of a run after one lost block; patched), its frequency-division scheduler put all UAVs under one beam (7 % of the uplink blocks undecodable; the time-division scheduler is used), the first replica used link delays from probes that are slower than the operations they stood for (§15.2), the first analysis judged the video of an overloaded cell by the frames that arrived ("96 % complete" where 3 % of the frames sent were usable), and the first version of the alternative repeat timer took its round-trip time also from repeated exchanges and ran away (corrected; its 100 runs were made again). `simulation/README.md` §6 has all nine.

### 15.7 The ground station on a laptop that overheats (measured, evening of 4 October)

During the last test runs the live picture stalled about every 2.7 minutes. The cause was the laptop, not the link, and it showed two faults of the ground station (§15.5 no. 8 and 9).

**What the laptop does.** Windows' own counters, read every 5 s beside the ground station's state: the processor's speed (`% Processor Performance`) falls from 100 to 140 % of nominal to **17 %** when the ACPI thermal zone reads 86 to 89 °C, stays there for 40 to 55 s until the zone has cooled to about 75 °C, and comes back. Windows applies no limit of its own in that time (`% Passive Limit` 100, `Throttle Reasons` 0): the clamp is the firmware's. Mains power, power plan "Balanced". In the afternoon the same laptop ran the 13-minute campaign in the default configuration without one such episode (largest decoder time 63 ms). By the evening, after the simulation sweep had kept ten cores busy for three hours and the detectors had run all day:

| The ground station is | Processor use (Windows, all 12 logical cores) | Temperature and clamps |
|---|---|---|
| stopped | 5 to 9 % (other programs) | cools to 57 °C within 3.5 minutes |
| showing live video, detector and finder paused | 9 to 11 % | 75 to 77 °C, steady over 7 minutes, no clamp; 11,717 frames, all shown, none lost |
| running the GENERAL detector and the finder (the default) | 55 to 85 % | from 58 °C: 73 °C after 2.5 minutes, no clamp in a 2-minute run. From 77 °C: clamp after 188 s |
| running the ACCURATE detector and the finder (the operator's setting) | 60 to 80 % | a clamp every 158 to 179 s: about 105 s at full speed, 50 s at 17 % |
| the same with both at half their rate | 30 to 75 % | the same, a clamp every 158 to 179 s |

A processor at a sixth of its speed decodes 720p video at about 7 frames a second; nothing keeps real time on it. What the software can do is stay live and stop heating.

**What the ground station did, before and after.**

| | Before | After the changes of this round |
|---|---|---|
| The picture during a clamp | up to **20 s behind** the camera (120 frames waiting for the decoder) | **at most 2.0 s behind**; it runs at about 7 frames a second and skips |
| A 7-minute capture with the ACCURATE detector and the finder (two clamps) | not measured as a whole | 12,373 frames arrived complete, 9,888 shown (80 %); 1,484 given up because the decoder was behind, 1,002 skipped until the next keyframe; 18 lost on the way (0.15 %) |
| The secure link | up, no failed operation | up, no failed operation |
| Detector and finder | went on at full rate, and took the processor from the decoder | start nothing while the decoder is behind; afterwards they run slower (below). Seen on the real machine once: the clamp at 22:57 halved their rate |

The time-bounded queue (a frame that has waited 1 s is given up with everything behind it) is what keeps the picture live. Slowing the detectors is what is meant to stop the heating: every episode halves their rate once more (1/2, 1/4, 1/8), ten minutes without an episode raise it one step again, and a raise that is followed by an episode doubles the wait before the next one (`kyber6g/ground/sched.py`). The first step was seen on the real machine; the further steps and the waits are covered by unit tests only, because the laptop did not clamp again once it had rested:

**After an hour of rest: 20 minutes in the operator's configuration, no clamp** (5 October, 01:20 to 01:40; ACCURATE detector and finder, NIGHT mode at 1920×1080, 15 falling to 10 frames a second with the exposure). 81 to 83 °C throughout, the processor at full speed in all 229 samples. 17,304 frames arrived complete and 16,568 were shown; the decoder was never behind (largest decoder time 83 ms, median 39 ms for these larger pictures); the detectors ran at full rate. The link was UP in every one of 239 samples, made 10 cached rekeys and 2 PQ ratchets, none failed, and rejected no record. 65 frames (0.37 %) were lost on the way, and each cost the picture until the next keyframe (737 frames in all): the Wi-Fi signal at the Pi was −76 dBm in this run, against −61 dBm during the campaign.

**What this means for the results of this report.** The campaign of §15.2 was run in the afternoon, without clamps (its decoder times show none). The measurements of the evening that needed a quiet machine (the latency budget, the pipeline and browser tests of §15.8) were made after the laptop had cooled, with the Windows counters logged beside them. **On the evening of 4 October, after three hours of simulation on ten cores and a day of detection, the laptop could not run the detector and the finder for more than a few minutes without a clamp; after an hour of rest it ran the heaviest configuration for 20 minutes without one. That is a property of this machine's cooling, not of the protocol or of the Pi, whose processor stayed at 52 to 60 °C and never throttled.** Not tested: whether cleaning the laptop's cooling or a power mode without turbo removes the clamps (no system setting of the laptop was changed).

### 15.8 Verification runs on the final code

5 October 2026, 01:01 to 01:16, one test after the other and nothing else running; the ground station had been started on the final code at 23:04 and was not restarted. The laptop had rested for an hour: 63 °C at the start, 82 °C at the end, **no clamp** in these 16 minutes (Windows counters logged every 5 s beside the tests). Default configuration: GENERAL detector and finder running, NORMAL mode, 1280×720 at 30 frames a second.

| Test | Result |
|---|---|
| Unit tests on the laptop | 211 run, all pass, none skipped (83 s) |
| Deployment, then unit tests on the Pi | 203 run, all pass, 8 skipped (51 s) |
| Is the Pi's code the repository's? | 85 of 85 deployed files byte for byte the same (`kyber6g/`, `tests/`, `deploy/uav.json`) |
| End-to-end pipeline (`run/kyber6g.sh pipeline`) | 42 PASS, 1 FAIL (the laptop's clock: 5.9 % fast against the UAV's, 239 jumps, offset −0.8 s). Frames lost: 0 of 338, then 0 of 347 during six rekeys. Decoder behind: never. Capture to decoded picture 97 ms (an estimate while the clock is unsteady; network and sealing 84, decoder 12.5). Cached rekeys 8.4, 9.2, 9.8 ms; PQ ratchets 12.3, 14.8, 13.4 ms. Records rejected: none |
| Dashboard in a headless browser (`run/kyber6g.sh ui-test`) | 93 PASS, 0 FAIL; no script error, no failed request, no HTTP error |
| Stored-data audit (`run/kyber6g.sh audit`) | 35 PASS, 2 WARN, 0 FAIL (the two warnings of §15.1) |
| Ground station's log since its start | no error, no warning, no traceback; the decoder was never behind, the detectors never slowed down |
| Pi's service since its start | active, 0 restarts, never throttled, 60 °C; three warnings, all commands the tests sent in order to be refused (a second start of a recording, a stop without one) |
| Link at the end | UP; 2 full handshakes (the second after the deployment restarted the UAV's service), 68 cached rekeys, 15 PQ ratchets since 23:04, none failed; no record rejected. The only drops: 2 answers to round-trip probes discarded as implausible (`bad-pong`), which a step of the laptop's clock between a probe and its answer produces |
| Repository | `git fsck` clean; nothing committed (228 tracked files deleted in the working tree: the earlier prototype, simulation scripts, plots and ns-3 module; 3 modified; the new system in 14 untracked entries) |

The clock failure is real and is not new: the clock of the WSL virtual machine runs at the wrong rate after the laptop has slept (§13.2). It makes the ground station's latency figures estimates and nothing else; every duration in §15.2 is timed on the Pi or corrected with the rate measured in the same run.

### 15.9 NOT TESTED in this round

- **Energy.** No power meter; no measured energy figure for any operation.
- **Glass-to-glass latency.** The budget ends at the decoded picture.
- **Loss in bursts, delay and jitter on the real link.** Only random, independent drops were injected.
- **More than one UAV, a UAV in flight, any radio other than Wi-Fi.** These exist in the simulation only; no 5G or 6G radio has been used at any point.
- **A flood from another machine over the radio.** The flood generator ran on the same machine as the ground station under test (over the loopback interface).
- **The 19 held packages of the Pi** (kernel, firmware, bootloader, Wi-Fi firmware, camera applications) were not installed.
- Formal verification, physical side channels, fault injection, an independent penetration test.
- The items of §13.7 that need the operator are unchanged.

## 16. Seventh round (2026-10-05): sealed audio

The system was given an audio path: the UAV seals audio, keeps it on its card and sends it to the ground station. The scheme (QUAVER, `kyber6g/audio/`) was designed against the gaps of six published audio-encryption schemes; the design, the attack experiments and the limits are in `docs/AUDIO_CRYPTANALYSIS_REPORT.txt`, the architecture in `docs/SECURITY_ARCHITECTURE.md` §9c. **The Raspberry Pi has no microphone.** A file copied into its inbox (`bash run/kyber6g.sh audio-put FILE`, over SSH with a post-quantum hybrid key exchange) stands in for one: it is sealed frame by frame, for the live path at the speed a microphone would deliver it, and removed afterwards. Everything below was measured on the final code on 5 October 2026 between 04:34 and 05:15, on the same two machines and the same Wi-Fi link as before.

### 16.1 Results at a glance

| Test | Result |
|---|---|
| Unit tests, laptop (final code) | **255 run, all pass**, none skipped (81 s). 44 are new, in `tests/test_audio.py`: framing of MP3 and PCM streams, the key tree and the hash tree, sealing and opening, every way of damaging or forging a clip, excerpts, the UAV's store and chain, the live path with lost and changed blocks, the repeated request for missing blocks |
| Unit tests, Pi (final code, after the last deployment) | **247 run, all pass, 8 skipped** (53 s; the same 8 as before). The 93 deployed files are byte for byte the repository's. Service active, 0 restarts, confinement rating 3.8 with the audio directory added to what it may write |
| The operator's sample (37.5 s, MP3, 256 kbit/s) sealed on the Pi, fetched, opened | 1,436 frames in 192 blocks of 6,764 bytes; 1,305,369 bytes for 1,200,378 (+8.7 %); sealed in 57 ms; fetched in 0.67 s (1,187 records); signature and chain PASS, opened in 24 ms, **SHA-256 of the opened file equal to the sample's**; the plain file gone from the Pi, the clip there with mode 0600 |
| The same sample sent while it is sealed | 192 of 192 blocks arrived on the air, none fetched again; stored 37.6 s after its start (the clip lasts 37.5 s), signature PASS, byte for byte the sample; in the runs of §16.3 without loss a listener got the whole sample while it came in |
| Attack experiments on sealed audio, on the Pi and on the laptop (§16.4) | **46 kinds PASS on both machines: 12,646 attack attempts, 0 accepted, 0 exceptions other than the promised refusal**; 6 controls, 216 of 216 as they must be |
| Twelve clips sent while they were sealed, with 0 to 20 % of the datagrams dropped (§16.3) | **12 of 12 completed from the UAV's card and verified, byte for byte the source**; 892 blocks fetched again |
| End-to-end pipeline on the live hardware (final code, §16.6) | **52 PASS, 1 FAIL** in 91 s. The failure is the laptop's clock again (2.0 % fast against the UAV's, 53 jumps), not the link. 10 of the checks are new and about audio: source copied, sealed, listed, checked by the UAV against its own signature, fetched and opened byte for byte, served, an excerpt verified with the public key alone, a live clip complete and verified, the live stream heard whole |
| Dashboard in a real browser (final code, §16.6) | **104 PASS, 0 FAIL** in 10 minutes. 11 of the checks are new: the SEALED AUDIO panel's five controls, the opened clip in the page's player, the excerpt, the live clip and its status line; the MEDIA tab with the new panel does not move, at both window sizes |
| Stored-data audit (final code) | **41 PASS, 2 WARN, 0 FAIL**. 6 checks are new: the 46 clips at the ground station are signed by the pinned UAV key, whole, and open to the files kept beside them; their chain has no break; the 49 clips on the UAV's card verify against the UAV's own signature (checked on the UAV, no secret); no plain audio is left there; its audio directories are 0700. The two warnings are the old ones (§15.1) |

### 16.2 What was built

- **`kyber6g/audio/framing.py`**: cuts an MPEG audio stream (layers I to III, MPEG-1/2/2.5) or a PCM WAVE file into its frames without decoding it; what is not a frame (an ID3 tag, the WAVE header) is kept, so that the pieces give the file back byte for byte.
- **`kyber6g/audio/quaver.py`**: the format. Blocks of one size, a key per block from an HMAC-SHA-256 key tree grown from the clip key, a commitment per block, AES-256-GCM, a Merkle tree and one ML-DSA-87 signature, the clip key wrapped with ML-KEM-1024 and X25519; the sealer's tree, which forgets; opening; recovery of a clip cut off by a power loss; excerpts.
- **`kyber6g/audio/store.py`** (UAV): the inbox, sealing a source as a clip, the chain of clips, closing clips a power loss cut off, the blocks a ground station asks for again.
- **`kyber6g/ground/audio_desk.py`**: clips from the card; clips that come in live (played block by block, completed from the card, stored when every block is under the signed root); excerpts, each verified here the way its receiver would.
- **UAV commands** `list_audio`, `record_audio` (with `live`), `stop_audio`, `fetch_audio`, `audio_blocks`, `check_audio`; a stream of its own on the link (7, "audio"); the dashboard's SEALED AUDIO panel; `audio-put` in `run/kyber6g.sh`; the confined service may write `~/kyber6g_audio`.
- **Tools**: `kyber6g/tools/audio_bench.py` (attacks, cost, statistics, live loss), `audio_report.py`; the pipeline test, the browser test and the stored-data audit cover audio; `bash run/kyber6g.sh measure audio`.
- **Paper**: plots 17 to 20 (`paper_plots/`), figures 15 to 18 (`paper_figures/`; 18 is the architecture of the whole system).

### 16.3 Measurements (all values measured; the files are `paper_plots/data/audio_*.json`, the tables `paper_plots/tables/plot17_*` to `plot20_*`)

| Quantity | Result |
|---|---|
| Sealing a clip on the Pi (128 kbit/s, 8 frames a block) | 1 s of audio in 4.8 ms, 1 min in 89 ms, 15 min in 1.25 s: about 700 times faster than it is spoken, 10.8 to 11.6 MB/s. Per clip: hybrid key wrap 0.65 ms, signature 0.76 ms. Per block of 3,420 bytes: 176 µs |
| Verifying and opening it on the laptop | 1 min in 12.6 ms, 15 min in 171 ms; the signature and Merkle check alone (no key needed) 2.7 ms and 28.6 ms |
| Bytes added | 6.7 kB once (head 1,999, root record 45, signature 4,637), 76 bytes a block, and padding. At a constant 128 kbit/s: 93 % for 1 s, 9.0 % for 1 min, 3.4 % for 15 min. 16-bit PCM at 16 kHz: 4.3 %. The sample at a variable bit rate: 195 % (every frame padded to the largest) |
| Frames per block (60 s at 128 kbit/s) | 1: 165 % added, one datagram a block; 2: 33 %, one; 4: 11.4 %, two; 8: 9.0 %, four; 16: 13.4 %, seven |
| An excerpt of a 10-minute clip (2,944 blocks) | 1 s: 31.7 kB, 0.3 % of the clip, at most 5 keys; 1 min: 996 kB, at most 11 keys; 5 min: 49 % of the clip, at most 16 keys. Made in 22 ms, verified with the public key in 0.6 to 46 ms (laptop) |
| The sample as 16-bit PCM, sealed: statistics of the stored bytes | entropy 7.9999 bits per byte (the sound 6.83), correlation of neighbouring samples -0.0015 (0.985), χ² of the byte histogram 284 (limit 293), spectral flatness 0.561 (white noise 0.56); two sealings differ in 99.61 % of their bytes; no 16-byte piece occurs twice (690 in the sound). A sanity check, not evidence of security |
| Three recordings of 30 s (silence, speech, music) sealed with the frame cap set | the same size (553,881 bytes), block size (3,420) and number of blocks (160) |
| Clip sent while it is sealed, 8 frames a block (7 datagrams): share of blocks that arrived on the air | 100 % without loss, 90 % at 1.0 %, 84 % at 2.2 %, 74 % at 4.6 %, 50 % at 10.6 %, 22 % at 20.0 % of the datagrams dropped (the uplink loss the rule's counters report) |
| The same with 1 frame a block (1 datagram) | 100 %, 99.0 %, 98.2 %, 94.8 %, 89.3 %, 81.5 % (at 0, 1.0, 1.8, 4.8, 11.4 and 20.1 % of the datagrams dropped) |
| Heard by a listener while it came in (missing blocks skipped) | 8 frames a block: 100, 90.0, 84.7, 74.4, 50.4, 22.3 % of the audio; 1 frame: 100, 99.0, 98.2, 94.7, 89.5, 81.5 % |
| Completion | all 12 clips stored within 37.4 to 46.0 s of their start (the clip lasts 37.5 s), verified against the signed root, byte for byte the source; 892 blocks fetched again; in 2 runs the request for them had to be made twice |

### 16.4 Attack experiments (`kyber6g/tools/audio_bench.py attacks`; full account in `docs/AUDIO_CRYPTANALYSIS_REPORT.txt` §5)

| Group | What was tried | Attempts on both machines | Accepted |
|---|---|---|---|
| Stored clip | one bit changed anywhere and in each of the 14 parts of the file; blocks exchanged, repeated, removed, added; the clip cut short; blocks, root record or head of another clip; signed again or made by another key; opened with other recipient keys; header rewritten; a cut-off clip passed as complete | 4,602 | 0 |
| Excerpt | one bit changed; said to be other blocks; a block exchanged; another key passed off for a block; the proof of one clip with the blocks of another; cut short or extended; an excerpt of a recording the UAV never made; the released keys tried on every other block (5,124 of the attempts) | 7,650 | 0 |
| Live clip | blocks changed on the air in four ways; a wrong repair; the signature of another clip | 314 | 0 |
| Chain | a clip deleted, replaced by another with its number, taken from another chain | 60 | 0 (each reported) |
| Keys and shape | a key, commitment, leaf or tag used twice among 5,280 blocks of 120 clips; three different recordings told apart by their sizes | 20 | 0 |

Timing of a refusal: the time to refuse a clip does not depend on where it was changed (first, middle or last block: 10.06 to 10.08 ms on the Pi, 1.66 to 1.67 ms on the laptop; the differences, 0.02 and 0.006 ms, are smaller than those between two series of the same case).

### 16.5 Defects found in this round, with the measurement that showed each

1. **The answer to `list_audio` carried a number where the dashboard expects a list.** The sources waiting in the inbox were listed, and then overwritten by their count. Found by the new pipeline check (`TypeError: 'int' object is not iterable`); the dashboard's table would have failed the same way with a file waiting. Fixed (`AudioStore.listing`), unit-tested.
2. **The page asked for the live stream before the clip had begun.** The UAV answers "started" before the clip's head has crossed the link; the request for `/audio_live?tag=…` then found no such clip and got 404. The pipeline test heard 0 of 48,527 bytes. Fixed: a clip asked for by its tag is waited for (8 s at most); unit-tested.
3. **The block size followed the recording.** It was F times the largest frame of the stream: silence at 32 kbit/s gave blocks of 1,100 bytes, music of 3,420. Found while writing the experiment that compares them. Fixed by a setting (`audio_frame_cap`, the encoder's largest frame); the default (no cap) is the same for constant-bit-rate and PCM sources and is documented as a limit for variable ones; both cases are experiments in the report (§5.9).
4. **The sealer kept the root of the key tree for the whole clip**, from which every block key follows: a UAV taken while it records would have given up the blocks it had already sealed. Found when writing down what each stolen key gives. Fixed: `SealerTree` keeps only the nodes that lead to blocks still to come; unit-tested against the full tree for every leaf. Sealing costs the same (89 ms for a minute on the Pi before and after).
5. **The request for missing blocks was made once.** Like every command it is one message. In the second run of the loss experiment 2 of 12 clips (8 frames a block, at 5 % and at 20 % loss) stayed incomplete: the request, or its acknowledgement, had been lost, and for 25 s the ground station's worker thread waited for it. (In the first run all 12 had completed, by luck.) Fixed: the request is sent without waiting and made again after 6, 12, 24 … seconds, up to six times; unit-tested with lost requests. Third run, on the fixed code: 12 of 12, two of them after a second request.
6. **The timing experiment measured where a buffer lay in memory.** With one buffer per case, kept for all runs, the cases differed by 10 % on the laptop and in the opposite direction on the Pi, while the same buffer measured twice agreed to 0.3 %. With a new buffer for every measurement the differences are 0.006 ms (laptop) and 0.019 ms (Pi), smaller than between two series of the same case.
7. **The audit's check of the clips on the Pi did nothing, silently.** The cryptographic library prints a line on standard output when it is loaded; the audit took that line for the result and skipped the checks. Noticed because the number of passed checks rose by three where six had been added. Fixed (the last line is the result).
8. **A finished live clip stayed in memory** until three later ones had pushed it out. Its blocks are released 60 s after it is stored; unit-tested.
9. **A unit test compared two times of a few milliseconds by their ratio** and failed once while the detector loaded the laptop (`test_operations_on_request_are_timed_and_logged`). The assertion now checks what it means (the parts do not add up to more than the whole).

### 16.6 Verification runs on the final code

5 October 2026, 04:56 to 05:11, one test after the other; the ground station had been started on the final code at 04:32 and was not restarted. Laptop 59 to 77 °C, no clamp in 184 samples of the Windows counters. Default configuration: GENERAL detector and finder running, NORMAL mode, 1280×720 at 30 frames a second.

| Test | Result |
|---|---|
| Unit tests on the laptop | 255 run, all pass, none skipped (81 s) |
| Deployment, then unit tests on the Pi | 247 run, all pass, 8 skipped (53 s) |
| Is the Pi's code the repository's? | 93 of 93 deployed files byte for byte the same |
| End-to-end pipeline | 52 PASS, 1 FAIL (the laptop's clock: 2.0 % fast against the UAV's, 53 jumps, offset -1.0 s). Frames lost: 0 of 352, then 0 of 341 during six rekeys. Cached rekeys 5.9, 7.0, 8.5 ms; PQ ratchets 8.5, 15.7, 15.1 ms. Audio: a tone of 6 s sealed on the Pi in 5.8 ms (232 frames, 32 blocks of 1,748 bytes), fetched in 0.03 s, signature and chain PASS, opened in 3.2 ms, byte for byte the source; an excerpt of seconds 1 to 3 (28,278 of 62,617 bytes, 4 keys) verified with the public key alone; live: 32 of 32 blocks on the air, the listener's stream identical. Records rejected: none |
| Dashboard in a headless browser | 104 PASS, 0 FAIL; no script error, no failed request, no HTTP error |
| Stored-data audit | 41 PASS, 2 WARN, 0 FAIL |
| Ground station's log since its start | no error, no warning, no traceback in 218 lines; the decoder was never behind |
| Pi's service since its start | active, 0 restarts, never throttled, 52 °C, confinement 3.8; three warnings, all commands the tests sent in order to be refused |
| Link at the end | UP; 2 full handshakes (the second after the deployment restarted the UAV's service), 16 cached rekeys, 6 PQ ratchets since 04:32, none failed; no record rejected, nothing dropped |
| Repository | `git fsck` clean; nothing committed (228 tracked files deleted in the working tree, 3 modified, the present system in 16 untracked entries) |

### 16.7 NOT TESTED in this round

- **A microphone.** No capture from a sound card, no live encoder; the capture time and position in each block are those of the sealing of a file. Everything about "live" audio is a file read at the speed of speech.
- **A live clip longer than 37.5 s, two clips at once, audio under loss together with live video** (the video was off in the loss runs; without injected loss the pipeline and browser tests ran audio beside live video).
- **Loss in bursts.** Only random, independent drops were injected.
- **A listener who does not name the clip** (`/audio_live` without a tag) gets the clip that began last, which in the first moment after a start is still the one before; the dashboard names the clip.
- **An excerpt verified by an independent implementation**, or by a person outside the project.
- **The page's player with a loudspeaker.** The browser test runs without a sound device; it checks that the player loaded the stream.
- **A formal proof of the scheme, an independent review, side channels** other than the time of a refusal.
- **Where the sample comes from and under what licence it may be reproduced.** The project owner states that it is a free sample audio (statement of 5 October 2026). Its source and the text of its licence were not looked up here: name them in the paper if its waveform or spectrogram is printed (plot 17).

## 17. Eighth round (2026-10-05, afternoon and evening): proofs and known answers, the motion watch, figures and plots in a new style

The task of this round: read two web pages on whether drones carry microphones and say what follows for the audio
feature; add motion detection on the UAV node; have evidence behind every claim about the post-quantum part, for all
kinds of data; bring the web page up to date; redraw the paper's figures and plots in the style of
`github.com/ChenLiu-1996/figures4papers`; test everything again.

### 17.1 Results at a glance

| What | Result |
|---|---|
| Protocol models (ProVerif 2.05, `formal/`) | 46 runs of five models under four attackers, every one as expected; 177 queries: 100 claims proved, 77 that must be false are false (45 "can this state be reached", 32 with the decisive scheme broken or key leaked); 30 s |
| Known-answer tests (`kyber6g.tools.pq_conformance`) | 162 of 162 on the Raspberry Pi and on the laptop: 150 NIST ACVP vectors for ML-KEM-1024 and ML-DSA-87 (key generation, encapsulation, decapsulation, the key checks of FIPS 203 §7, signing, verification), 10 for the classical primitives, 2 that the library's random generator was put back |
| Self-test at every start | ground station 18 checks in 35 ms, UAV 16 checks in 19 ms; a failure stops the program |
| Motion watch, generated scenes (10 scenes a case, 320 looks) | a moving target of 8 pixels is found in every look from a contrast of 8 grey levels in day noise and 16 in night noise; nothing moves: 1 region in 3,200 looks at medium sensitivity, 10 in 3,200 at high; all rows together: 25 false regions in 30,400 looks |
| Motion watch, the UAV's own camera (targets drawn in on the UAV) | a lit room (472 lux) with people in it, three captures of 44 looks in each camera mode, all used: the target (8 pixels, 2 pixels a look) is found in 91 (NORMAL) and 94 (NIGHT) of 102 looks at a contrast of 4 and in all 102 from 6 on; at every size from 3 pixels and every speed from 0.2 to 4 pixels a look: 102 of 102; imitated pans of 1, 2 and 3 pixels a look are measured as 0.99, 1.97 and 2.98; regions with no target drawn in: 13 and 18 in 102 looks at medium sensitivity |
| Motion watch, cost on the UAV (watch off and on in turns, live 720p30) | Pi CPU 9.1 % of four cores without it, 11.8 % with it; 31 ms a look at 8 looks a second; 0 of 7,303 video frames lost; camera 30.0 frames a second either way |
| The real scene left to itself for 5.4 minutes (a lit room, people in it) | 12 movements; a region in 1,323 of 2,619 looks; 2,320 reports received by the ground station; 0 errors |
| Figures and plots | 19 diagrams and 22 plots redrawn in one style (Arial, the palette and the axes of figures4papers); the diagrams drawn again on 6 October after that repository's schematics (pastel components with dark outlines, block arrows, §17.6); every build check passes |
| Web page (`kyber6g-website/`) | rewritten: every number and picture comes from the repository's results |
| Day/night switch of the camera (found by the operator on 6 October, §17.5) | fixed: 22 of 22 switches, 9 of 9 photos, a recording across two switches and 60 switches in a row right on the real system |
| Automated tests on the final code | 310 unit tests on the laptop, 302 on the Pi (9 of them skipped there), 314 and 306 after the fix of 6 October: all pass; the Pi's code is the repository's (102 of 102 files identical); end-to-end pipeline on the live hardware 58 PASS, 3 FAIL (the laptop's clock; the watch's self-test in the lamp-lit room, §17.4; one stored telemetry row, §17.5); dashboard in a headless browser 111 PASS, 0 FAIL; stored-data audit 40 PASS, 2 WARN, 1 FAIL (that row) |

### 17.2 What was built

* **`formal/`**: ProVerif models of the full handshake, the 1-RTT Cached RapidRekey, the PQ ratchet (three models:
  both ends, a listener, an active attacker) and the stored-file format; four attacker libraries (nothing broken,
  X25519 broken, ML-KEM broken, both); leak scenarios; `run.py`, which states the expected outcome of every query,
  runs everything and fails if one outcome is not the expected one. The queries that must fail are there on purpose:
  a model in which nothing can be attacked proves nothing.
* **`kyber6g/tools/pq_conformance.py`** with `tests/data_acvp_fips203_204.json.gz`: NIST's own vectors against the
  library in use, with the vectors' random values fed into liboqs through its hook for a caller's generator (key
  generation and signing are randomised; without that only decapsulation and verification could be compared).
* **`kyber6g/crypto/selftest.py`**, run by both programs when they start; **length checks** of every key before
  liboqs sees it (`identity.sized`); **`kyber6g/tools/cbom.py`** (bill of materials, CycloneDX 1.6);
  **`tests/test_pq.py`**; **`docs/SECURITY_PROOFS.md`** (assumptions, seven statements with their arguments, the
  evidence for each, what is not proved).
* **The motion watch**: `kyber6g/camera/motion.py` (the steps are in its first lines), `motion_eval.py` (scoring with
  targets whose position is known), the camera service's second, small picture stream and its thread, the UAV's
  reports, events, sentry mode and photo on motion, the ground station's validation and display, the dashboard's
  controls and overlay, `kyber6g/tools/motion_bench.py`, `tests/test_motion.py`.
* **`docs/AUDIO_ON_A_UAV.md`**: what the two pages say (camera drones normally carry no microphone, because the
  rotors drown out what one would want to hear; neither describes a noise-cancelling method that makes an on-board
  microphone usable in flight), when sealed audio from a UAV makes sense all the same, and the exceptions.
* **The web page**, **plots 21 and 22**, **figure 19**, and the new style of all figures and plots (§17.6).

### 17.3 The post-quantum part: what stands behind each claim

| Claim | Evidence |
|---|---|
| ML-KEM-1024 and ML-DSA-87 as used are the standardised algorithms | 150 ACVP vectors pass on both machines; liboqs reports them as "FIPS203" and "FIPS204"; the key checks of FIPS 203 §7.2 and §7.3 give NIST's verdict on all 20 of its test keys, valid and invalid |
| A session's keys are secret if X25519 **or** ML-KEM-1024 holds | ProVerif: secrecy proved with nothing broken, with X25519 broken, with ML-KEM broken; the attack is found with both broken. Test: with one real shared secret and anything in place of the other, the session's master secret is never obtained. Argument: `SECURITY_PROOFS.md`, Theorem 1 |
| Each end knows whom it talks to | ProVerif: injective agreement both ways (the UAV's on the ground station in all four columns; the ground station's on the UAV and the key, in all but "both broken") |
| The cached rekey moves the keys on, and does not heal | ProVerif: secrecy and agreement with the old secret intact, also if the next secret leaks later; attack found in every column if the old secret had leaked before |
| The PQ ratchet heals | ProVerif: after a leak of the old master secret, an attacker who only listens does not learn the new keys (proved in three columns; attack found with both broken); an attacker who is active during the ratchet does (attack found) |
| A stored photo, recording or audio clip is secret, also after the UAV is captured, also with one of the two recording keys stolen | ProVerif: proved in the columns where the other scheme holds; attack found where it does not, and with both keys stolen. 24,680 attempts on photos, 5,884 on recordings and 4,602 on audio clips (both machines together) to get a changed or forged file opened: none (§15.3, §16.4) |
| What is opened was sealed by the pinned UAV | ProVerif: proved in all four columns (ML-DSA-87 is not broken by any of the four attackers) |
| Live video, telemetry, status, motion reports and commands are records under session keys | the record layer's argument is Theorem 5; 300,000 forged, changed, replayed and spliced records refused (§15.3). Telemetry and motion reports are never written to the UAV's card |

Three properties of the design that were stated in words before are now shown by a tool, with a trace: the cached
rekey does not heal; the ratchet heals only against a listener; authentication is post-quantum only, not hybrid.

### 17.4 The motion watch: measurements

**Generated scenes** (`motion_bench synthetic`, 10 scenes a case; everything about them is known, so every region
is either a hit or a false alarm). A target of 8 × 10.7 pixels moving 2 pixels a look, picture 320 × 180, 8 looks a
second:

| Varied | Found in (% of looks) |
|---|---|
| Contrast, day noise (grey levels of 255) | 3: 0; 4: 4; 6: 88; 8 and more: 100 |
| Contrast, night noise | up to 8: 0; 12: 31; 16 and more: 100 |
| Contrast, day noise, sensitivity low / high | low: 8: 27; 12: 94; 16: 99; 25: 100. High: 3: 3; 4: 46; 6 and more: 100 |
| Width of the target, day / night noise (contrast 25) | day: 100 from 3 pixels on. Night: 3: 55; 4: 95; 6 and more: 100 |
| Speed (pixels a look) | 0.1: 62; 0.2 to 6: 100; 10: 68 |
| Camera pans (target 4 pixels a look faster) | up to 2 pixels a look: 100; 4: 95; 8: 67; 12: 42. With a turn of 0.3° a look as well: 100, 100, 100, 98, 93, 60, 40 |

Nothing moves (regions reported in 320 looks; medium / high sensitivity): still, day noise 0 / 0; still, night noise
0 / 0; lamp flicker of 5 % 0 / 0; exposure wandering by 2 % a look 0 / 3; pan of 2.3 pixels a look 0 / 0; pan of 6.5
with shake 0 / 0; pan with a turn of 0.3° a look 0 / 2; pan with a zoom of 0.5 % a look 1 / 5; dim flat scene with
row noise 0 / 0; the same with a pan 0 / 0.

**The UAV's own camera** (`motion_bench camera`): the watch's self-test takes 44 looks of the small picture into
memory on the UAV, draws a target of known size, contrast and speed into them, and counts; the pictures are never
stored or sent. Three captures in each camera mode, all used. The scene was a lit room (about 600 lux) with people
in it: a region that touches no drawn target is something that moved there, or a false alarm, and cannot be told
apart afterwards.

| Case (102 looks in each mode) | NORMAL mode | NIGHT mode |
|---|---|---|
| Light, gain, exposure | 472 lux, 2.69, 30 ms | 472 lux, 2.69, 30 ms (in this light the mode differs by its grey picture only) |
| Nothing drawn in: regions at low / medium / high sensitivity | 1 / 13 / 61 | 5 / 18 / 57 |
| Target of 8 pixels, 2 pixels a look, contrast 4 | found in 91 (25, 34, 32 of 34 in the three captures) | 94 (26, 34, 34) |
| ... contrast 6, 8, 12, 16, 25, 40 | 102 each | 102 each |
| ... contrast 4, 6, 8, 12 at high sensitivity | 102 each | 102 each |
| Width 3, 4, 6, 12, 16 pixels (contrast 25) | 102 each | 102 each |
| Speed 0.2, 0.4, 0.8, 4 pixels a look | 102 each | 102 each |
| Speed 8 pixels a look | 93 (34, 29, 30) | 93 (34, 29, 30) |
| A dark target (contrast -25) | 102 | 102 |
| Imitated pan of 1 / 2 / 3 pixels a look, nothing drawn in: regions | 0 / 0 / 0 | 5 / 2 / 1 |
| ... the pan as the watch measured it (pixels a look) | 0.99 / 1.97 / 2.98, known in 102 of 102 looks | 0.99 / 1.97 / 2.97, known in 102 of 102 |
| Pan of 2 with the UAV said to be under way: regions | 0 | 5 |
| Target moving 6 pixels a look while the camera pans 2 | found in 94 (34, 27, 33) | 94 (34, 27, 33) |

The room was not dark when this was measured, so these rows say nothing about the camera at high gain: for that
there are the generated scenes with night noise above, and the limit in §17.8. The regions with nothing drawn in
are what a person at a desk in the picture produces, plus whatever false alarms there were; at the same moment the
ground station's detector reported a person in that part of the picture.

**Cost** (`motion_bench cost`: the watch switched off and on in turns, four stretches of 30 s each way, live 720p at
30 frames a second; then six of each session operation, 1.2 s apart):

| Quantity (median of the stretches) | Watch off | Watch on |
|---|---|---|
| Pi CPU, share of all four cores | 9.1 % | 11.8 % |
| Processor clock (the governor's choice) | 800 MHz | 1,800 MHz |
| One look of the watch | - | 31 ms |
| Camera frames a second | 30.0 | 30.0 |
| Video frames lost at the ground station | 0 of 3,686 | 0 of 3,617 |
| AES-256-GCM for one video chunk on the UAV | 149 µs | 94 µs |
| Full handshake / cached rekey / PQ ratchet at the UAV (24 each) | 21.9 / 9.6 / 15.1 ms | 21.1 / 8.1 / 11.0 ms |

The other work gets quicker with the watch on, not slower: the Pi's "ondemand" governor runs the processor at 0.8 GHz
under the video alone and at 1.8 GHz once the watch adds its 2.7 points of load. The watch costs CPU time (about a
ninth of one core), not speed of the link.

**The scene left to itself** (`motion_bench quiet`, 5.4 minutes, NORMAL mode, 605 lux, people in the room): 12
movements (events), a region in 1,323 of 2,619 looks, "the picture as a whole changed" in 181 looks, 2,320 reports
received by the ground station, no error of the watch; one look took 33.8 ms (longest 35.7 ms). At the same time the
ground station's detector named a person and a chair in the same part of the picture.

**A scene in which the watch is blind** (found at 23:20 on 5 October by the pipeline's self-test, after the room's
main light had been switched off: a lamp, 89 lux). The target drawn into the camera's pictures was found in 0 of 26
looks, for both targets, in NORMAL and in NIGHT mode; no false region either. The watch said "the picture as a
whole changed" in 27 of 30 looks. To see why, the UAV service was stopped and 36 consecutive small pictures were
compared on the Pi (numbers only; the pictures are not kept):

| Camera setting | Pictures 1 or 2 frames apart: pattern in what is left (0 = noise, 1 = the two show different things) | Pictures 100 ms apart | The watch on these pictures |
|---|---|---|---|
| NORMAL, 30 frames a second, exposure 33.2 ms | 0.93 | 0.08 | "whole picture changed" in 35 of 36 looks |
| NORMAL, exposure 30.0 ms (three periods of a lamp's 100 Hz flicker) | 0.94 | 0.16 | 35 of 36 |
| NORMAL, exposure 20.0 ms (one period of the mains) | 0.95 | 0.12 | 35 of 36 |
| NIGHT, exposure 80.0 or 90.0 ms (whole periods of the mains) | 0.83 to 0.94 | not sampled (no two pictures 100 ms apart) | 35 of 36 |
| NIGHT, exposure 99.9 ms, frames 100.0 ms apart | 0.06 to 0.09 | 0.06 | 0 of 36: undisturbed |

Exposure time and gains were the same in all 36 pictures of a capture, so the camera's own control is not the
cause. An exposure of whole periods of the mains did not help, and the change is not the same along a row (the
ratio of two pictures is 0.89 to 1.05 in the columns 60 to 180 and 1.00 in the right half), so it is not the
banding of a flickering lamp under the rolling shutter either. What the pictures show is a part of the scene
(strongest around columns 60 to 180 and rows 120 to 150 of the 320 × 180 picture) whose brightness changes by up to
a tenth and comes back every 100 ms: something in the room changes ten times a second, or at a multiple of that
(the shadow of a fan, the light of a screen: not identified). The watch's
rule "what is left after subtraction has a pattern: the two pictures show different things" then holds in every
look and nothing is reported. It is blind there, not wrong. A change of light over a part of the picture would
have to be taken out the way a band along the rows is; that is not built.

The last line of the table was then met on the running system: at 23:47 the camera's own control had settled on
99.9 ms in NIGHT mode (10 frames a second), and the self-test found the target in 26 of 26 looks for both targets,
twice; without a target the watch reported 20 and 25 regions in 26 looks (the part of the scene that changes), and
"the picture as a whole changed" in none. In NORMAL mode in the same light, three minutes earlier: 0 of 26.

### 17.5 Defects found in this round, with the measurement that showed each

| Defect | How it showed | Fix |
|---|---|---|
| A short key was filled with zeros by the liboqs binding | reading the binding while writing the key checks | lengths checked before the library sees a key (`SECURITY_AUDIT.md` finding 27) |
| No check of the libraries at start | review | self-test at every start (finding 28) |
| **A target of medium contrast was found less often than a fainter one** (night noise: 62 % of the looks at contrast 12, 52 % at 16; on the real camera at 11 lux: 90 of 102 at contrast 6, 61 at contrast 8) | the first benchmark's curve was not monotonic | the comparison with the picture of a second ago had been closed wherever the comparison of neighbouring looks lit up now and then. Replaced by a rule on three pictures (differs from the picture of a second ago and, in the same direction, from that of half a second ago), which also keeps the place a thing has left from being reported. Now 31 % and 100 % |
| **A camera movement in a dim scene was not measured, and what was lit in the room was reported as moving** (real camera, NIGHT mode, 11 lux, an imitated pan of 2 pixels a look: 95 regions in 102 looks) | the on-camera self-test of the first campaign | the camera's movement is now also measured on pictures a quarter and an eighth of the size, where the sensor's noise is averaged away, and believed if edges in three parts of the picture show it or if the rest of the picture, outside the places that changed strongly, moves the same way (a test with a known error rate, whose evidence adds up over the looks of a pan). On a generated scene that reproduces the failure (a nearly empty dark room with a lit thing, the camera panning 2 pixels a look): 126 regions in 128 looks before, 0 in 192 after; the pan is measured in 192 of 192 looks |
| On a small picture a single thing in an empty scene was taken for a pan | new tests on 192 × 120 pictures (found in 25 of 96 looks) | the tiles' verdict "the camera moved" needs three tiles in agreement, not two (83 of 96) |
| The on-camera benchmark used only captures in which nothing else had moved | with people in the room no capture was left; and the rule would have hidden false alarms | every capture is used; regions without a drawn target are reported as what they are; the plot shows the median of the captures and their range |
| The cost benchmark timed a PQ ratchet at 450 ms | five of every six ratchets in the first run | the tool asked for ratchets 0.4 s apart; a ratchet within half a second of the one before is answered only when the UAV repeats its request. Spaced 1.2 s apart, as in the link measurements: 15 ms |
| The "quiet" phase stopped with "the watch is not watching" | first campaign | the UAV's status is a second or two behind a change of settings; the tool now waits for it |
| Sealing looked faster with the watch on | the cost table | not a defect: the governor's clock (the table above). The processor's clock is now in the UAV's status |
| The ground station and all running jobs were lost three times | WSL shut down each time the assistant's session was restarted, because the ground station had been started from that session | started as a process of its own; the user's launcher (`Kyber6G.bat`) is not affected |
| **One stored telemetry row says "3D fix" and has no position** (1 of 174,335 fix rows; 5 October, receiver time 08:03:15 UTC) | the stored-data audit of the final run | gpsd's first report after the receiver had stood still for 58 s (four rows carry the same receiver time, the next one is 08:04:13). Nothing was invented: the row was stored without coordinates, and the map, the track and the analyses skip such a row. The reader on the UAV now takes a report that says "fix" and carries no position as no fix (`telemetry/gnss.py`, test added). The row stays in the database as it was received, so the audit keeps failing on this one row |
| **The stored-data audit stopped half-way** with an exception (`TypeError`), and nothing after its telemetry checks was checked (photos, recordings, audio, files, the UAV's files) | the same run: the audit printed 10 lines where it used to print over 40 | its check for impossible jumps of the position computed a distance from that row without coordinates. Such rows are counted as a failure by the check before it and are now left out of the distance (`tools/data_audit.py`) |
| **The motion watch found nothing in a lamp-lit room at night** (89 lux, after the main light had been switched off: 0 of 26 looks with the target found, for both targets, no false region; 40 minutes earlier in the same room at 481 lux: 26 of 26) | the pipeline's self-test on the camera, in the last run | not repaired: a limit, measured and described in §17.4 and §17.8. One remedy was tried and taken out again because the measurement did not support it: an exposure of whole periods of the mains (libcamera's flicker avoidance, with 10 ms and with 20 ms) changed nothing |

**Found by the operator on 6 October, after the round above: the DAY button did not bring the colour back.**

| Defect | How it showed | Fix |
|---|---|---|
| **After NIGHT at 1920 × 1080, DAY left the live picture grey**, however often it was pressed (9 times in the log, every one acknowledged; the status said NORMAL, the exposure was that of NORMAL, and no pixel of the picture had any colour) | the operator, on the dashboard; then measured on the camera with the service stopped | A request for a mode's controls reaches the running camera whole only as long as the camera has been started once since the program began (13 of 13 switches). After any stop and start, which every change of the video settings is, it arrives in part: exposure yes, colour and white balance no (8 of 12 switches wrong; 5 of 9 still wrong with the request repeated on five frames). A camera that is started with the mode among its start controls is in it from the first frame (10 of 10). So the mode is now part of every configuration, a switch on a camera that has been restarted before restarts it once more (the picture is in the new mode within 0.4 s of the command), and once a second the camera's own report of a frame is held against the mode, with a restart if they disagree; the status says whether the mode arrived (`camera/camera.py`, `_request_mode`, `_check_mode`) |
| **A restart of the camera could fail with "KeyError: 24" and leave it off** (once in 20 restarts in the first test of the fix) | the hardware test | picamera2 clears away old buffers when the camera is configured and when a frame of the configuration before is given back; the motion watch gave such a frame back at that moment. Both now happen under one lock; a restart that fails is tried once more; a mode switch on a camera that should run and does not starts it. 60 switches in a row afterwards, none refused |
| **A photo taken with the stream stopped ignored NIGHT, and in DAY came out blue once the mode did arrive** (red at a tenth of green in the worst one) | the hardware test of the fix; no such photo had been taken before (0 of 161 stored photos) | the same cause for the first half. For the second: the automatic white balance, started anew with the camera, overshoots and needs about 4 s (blue gain 1.37 to 1.52 where 1.07 is right, 1.2 s after the start). A photo in DAY mode now takes the white balance the stream had settled on (if it ran within 10 minutes), otherwise it waits for the automatic one to stand still |
| **"The recent recordings are not displayed on the MEDIA page"** (the operator, 6 October) | the recordings were on the UAV's card: 30 of its 73 had never been fetched, the operator's two of that night among them. The page showed a recording only after LIST ON UAV and FETCH & DECRYPT had been pressed for it, nothing on it said so, and it showed the newest 10 recordings and 16 photos only | a recording saved with ◼ SAVE is fetched and decrypted by itself if it is at most 64 MB (`auto_fetch_mb`; a larger one keeps its button); the page asks for the list of the card by itself (when MEDIA is opened, when a recording has been saved, every half minute), newest first, with "here" or "on the Pi only" on every row; SHOW ALL lists every photo and every decrypted recording the ground station holds, newest first (`/api/media`). Checked in a headless browser, by what is in the page: 13 of 13 (among them: 170 of 170 photos and 46 of 46 recordings listed in order; a recording made in the test arrived by itself 1.7 s after SAVE and stood first) |

Measured on the real system after the fix, through the ground station as the operator uses it, the picture taken
from its stream each time (numbers only): 22 of 22 steps right (mode switches and changes of the video settings,
among them every sequence that had failed and two presses in quick succession); 9 of 9 photos in the right mode,
the 4 DAY photos with the stream stopped within 0.02 of the stream's colour balance; a recording across two
switches, 397 of 397 frames decoded; 60 switches
one after the other, 60 accepted, the camera right after them and the motion watch still watching. No error in the
UAV's journal, no restart of its service. Unit tests after the fix: 314 on the laptop, 306 on the Pi (9 skipped
there), all pass; the Pi's code is the repository's (102 of 102 files).

### 17.6 Figures and plots in a new style

All 19 diagrams and 22 plots were redrawn in the house style of `github.com/ChenLiu-1996/figures4papers` (its
plotting scripts and its design notes were read; none of its code is used): Arial in place of Times New Roman;
black axes without the top and right spines; no grid; legends without a frame; bars with square ends and a black
outline; its palette (blue `#0F4D92` for what the paper is about, red `#B64342` for what it is compared with, teal
and violet for a third and fourth series, greys for context and for what is simulated). The sizes stay those of a
journal column (90 and 190 mm), with that repository's proportions of text to axes set at the final size. The style
is set in two places only (`paper_plots/scripts/plotlib.py`, `paper_figures/scripts/figlib.py`).

Arial is wider than Times: 9 of the 22 plots and 10 of the 19 diagrams had text that no longer fitted, which the
two build checks reported; panel titles went from 9 to 8 pt, and texts in 6 plots and 10 diagrams were shortened
or moved. After that: 22 plots, 0 with problems; 19 diagrams, 0 problems; fonts in every PDF Arial only,
embedded; widths 90.00 and 190.00 mm; smallest text 6.5 pt. The palette's four series colours stay apart under the
three kinds of colour-blindness and for full colour vision and stand out of the page (`paper_plots/checks/palette.txt`;
its closest pair, teal and violet under deuteranopia, is in the band that needs a second sign, which every series
has: its own marker, line style and hatch).

**The diagrams, a second time (6 October 2026).** The restyling above had given the 19 diagrams that repository's
font and colours and left their drawing as it was: thin pale boxes, blue connectors, dark filled pills. That is not
what its architecture figures look like. Its schematics (ImmunoStruct, RNAGenScape, VIGIL, Dispersion) were then
looked at one by one and the style library (`paper_figures/scripts/figlib.py`) was rewritten after them: every
component a rounded box with a pastel fill and a dark outline; six families of colour (UAV green, ground station
cream, public-key step blue, symmetric step violet, adversary red, neutral grey), the bold titles and pictograms in
the strong colour of their family; thin black arrows for data and short block arrows from one stage to the next;
bold letters for the parts of a figure. The layouts and the words are the same. Measured on the new build: 19
figures, 0 problems; widths 90.00 and 190.00 mm; Arial only, embedded; text 6.5 to 9 pt; 220 connectors drawn by
draw.io as designed and 86 block arrows; 50 raster placements, 626 ppi or more; text on the pastel fills 12.2 : 1
or more. All 19 PNGs were looked at. A build check added for this style (a text may not run across the outline of
a box) is what the dark outlines made necessary: two lines of figure 12 had run over their frame since they were
written, unseen while the outline was pale; they were shortened. In greyscale the pastel fills are nearly the same
light grey, so the families are told apart there by words and pictograms only (`paper_figures/README.md`).

### 17.7 Verification runs on the final code

All on 5 October 2026, on the two machines of the test bed, the UAV node streaming to the ground station.

| Run | Result |
|---|---|
| Unit tests, laptop (23:40) | 310 run, all pass (95 s) |
| Unit tests, Raspberry Pi (23:43) | 302 run, all pass; 9 of them skipped there (127 s) |
| Is the code on the Pi the repository's? (after the last deploy) | 102 of 102 files identical (SHA-256) |
| Pipeline on the live hardware, 23:03: room lit (481 lux), default settings | **58 PASS, 3 FAIL.** (1) The laptop's clock: 9.1 % slow, 205 jumps (the WSL machine, not the link). (2) "Video frame rate" read 0.0 at the moment the test asked: no complete frame had arrived for 2 s, while 305 frames arrived in those 12 s with 1 lost and the log shows 30.0 frames a second every 5 s before and after. The laptop had just run both unit-test suites; the cause was not established, and it did not happen in the two runs after it. (3) The stored-data audit (below). The watch's self-test on the camera: 26 of 26 and 26 of 26 looks |
| Pipeline, 23:19: lamp only (87 lux), the operator's settings | **58 PASS, 3 FAIL**: the clock; the watch's self-test on the camera, 0 of 26 and 0 of 26 (§17.4); the audit. Frame rate 30.0, 0 of 374 frames lost |
| Pipeline, 23:45: the final code, lamp only (92 lux) | **58 PASS, 3 FAIL**: the same three. Frame rate 30.0; 0 of 373 frames lost; 0 of 389 lost during 6 rekeys; photo, recording and audio clip sealed on the UAV, fetched, verified and opened; both start-up self-tests of the cryptography passed (18 and 16 checks) |
| Dashboard in a headless browser (23:05 to 23:16) | **111 PASS, 0 FAIL**, the motion controls among them (MOTION, sensitivity, SENTRY, PHOTO ON MOTION). The one failure of the run before (the test's own last step, putting the operator's settings back) did not happen again, nor when its five commands were sent by hand twice |
| Stored-data audit (23:47), after its repair (§17.5) | **40 PASS, 2 WARN, 1 FAIL.** The failure: one fix row without a position among 176,071 (§17.5). The warnings are the two old ones (§15.1): four photos of 4 October whose files do not match the database's hash, and one telemetry row from the second in which the receiver got its fix |
| Ground station's log since it was started (21:17 to 23:16) | no error, no traceback; the video decoder fell behind 6 times (a busy machine; frames are then skipped, not lost on the link) |
| The link since the ground station was started (21:17 to 23:48) | 105 full handshakes, none failed; 177 cached rekeys; 119 PQ ratchets; no record rejected; 40 ratchet requests turned away by the rate limit (the cost benchmark's first run asked for them 0.4 s apart, §17.5) |
| UAV service | active, not restarted by systemd, not throttled, 53.5 °C; confinement score 3.8 |
| Repository | `git fsck`: clean. Nothing of this round is committed |

The dashboard test ran on the code as it was at 23:00; after it only `tools/data_audit.py` (a laptop tool) changed.

### 17.8 NOT TESTED in this round

- **Flight.** The UAV node has not flown: no vibration, no real camera movement, no rotor noise, no energy.
- **The motion watch on real targets.** Targets were drawn into generated scenes and into the camera's own
  pictures; no person, vehicle or animal was tracked against a ground truth. Camera movement was imitated (a
  generated camera for the scenes, a sliding window for the real pictures; whole pixels only on the real camera).
- **The corrected camera-movement measurement on the real camera in the dark.** The failure was seen at 11 lux in the
  afternoon; when the correction was deployed the room was lit (about 600 lux), where the imitated pans were measured
  from the start. In the dark it is covered by the generated scene that reproduces the failure, not by the camera.
- **A slow pan over a nearly empty scene with one bright thing** (half a pixel a look): the thing is still reported
  as moving in about a sixth of the looks of the generated case (34 regions in 192 looks). Unless the GNSS says the
  UAV is under way, in which case nothing is reported.
- **A scene of which a part changes its brightness all the time** (measured on 5 October at 89 lux, §17.4: a region
  changing by up to a tenth ten times a second). The watch reports nothing there: 0 of 26 looks. FAILED, not repaired.
- **Parallax** (a near, still thing passed by a moving camera), **rotation and zoom in a dim scene**, **a scene with
  several lights that sways by a fraction of a pixel**.
- **A computational proof of the whole protocol**, side channels, fault attacks, an independent review of the models.
  The literature references in `SECURITY_PROOFS.md` and `AUDIO_ON_A_UAV.md` were written from memory and are marked
  so: check each before citing it.
- **A microphone.** A file still stands in for it.
- **The web page in browsers other than headless Chromium**, and on a server.

## 11. Reproduce

```bash
# laptop (WSL)
python -m kyber6g.tools.provision gcs
bash deploy/deploy_pi.sh kyber-pi
python -m unittest discover -s tests -t .
python -m kyber6g.ground.main            # dashboard: http://127.0.0.1:8600
# Pi
cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -m kyber6g.uav.main -c deploy/uav.json
~/kyber6g_venv/bin/python -m kyber6g.tools.hwtest_camera   # standalone camera/recorder test

# round 5 (laptop, with the Pi's service running)
bash run/kyber6g.sh deploy       # code, modes and the confined service on the Pi
bash run/kyber6g.sh test         # unit tests (the same suite runs on the Pi in ~/kyber6g_app)
bash run/kyber6g.sh pipeline     # end-to-end test on the live hardware
bash run/kyber6g.sh ui-test      # dashboard in a headless browser (about 15 min)
bash run/kyber6g.sh audit        # stored data, keys and permissions on both machines
bash run/kyber6g.sh measure      # measurement campaign of §14.3 (about 40 min) -> paper_plots/data
bash run/kyber6g.sh plots        # plots and tables -> paper_plots/

# round 6 (laptop, with the Pi's service running)
bash run/kyber6g.sh measure          # the whole campaign of §15.2, attack experiments included (about an hour)
bash run/kyber6g.sh measure attacks  # only the attack experiments of §15.3, on the Pi and on the laptop
bash run/kyber6g.sh measure latency  # only the two minutes of live video behind the latency budget (plot 7b)
bash run/kyber6g.sh report           # docs/CRYPTANALYSIS_REPORT.txt from the experiments
bash run/kyber6g.sh simulate         # §15.6: calibrate from the measurements, build, run every study, draw plots 11 to 16
bash run/kyber6g.sh plots            # all plots and tables, with the build checks

# round 7 (laptop, with the Pi's service running): sealed audio
bash run/kyber6g.sh audio-put FILE   # an audio file into the Pi's inbox: it stands in for a microphone
bash run/kyber6g.sh measure audio    # §16.3 and §16.4: attacks and cost on both machines, statistics, live clips under loss (about 15 min)
bash run/kyber6g.sh report           # docs/AUDIO_CRYPTANALYSIS_REPORT.txt (and docs/CRYPTANALYSIS_REPORT.txt)
bash run/kyber6g.sh plots            # plots 17 to 20 with the rest

# round 8 (laptop, with the Pi's service running): proofs, known answers, the motion watch
bash run/kyber6g.sh formal           # §17.3: the ProVerif models under the four attackers (about 30 s; needs ProVerif 2.05)
bash run/kyber6g.sh measure pq       # §17.3: known-answer tests on both machines, the models, the bill of materials
bash run/kyber6g.sh measure motion   # §17.4: generated scenes, the camera's own pictures, the cost, the scene left to itself (about 40 min)
bash run/kyber6g.sh plots            # plots 21 and 22 with the rest
python3 paper_figures/scripts/build.py   # the nineteen diagrams
python3 kyber6g-website/scripts/build_data.py && (cd kyber6g-website && npm run build)   # the web page
```
