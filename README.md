# Kyber-6G: a post-quantum secure link for UAV video, telemetry and control

[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20(ML--DSA)-brightgreen.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![ns-3 3.42](https://img.shields.io/badge/ns--3-3.42-blue.svg)](https://www.nsnam.org/)
[![5G-LENA NR v3.3](https://img.shields.io/badge/5G--LENA-v3.3-orange.svg)](https://5g-lena.cttc.es/)

A Raspberry Pi 4B (the UAV node: camera, GNSS receiver, status display) and a ground control station exchange
**live H.264 video, photos, telemetry, recordings and operator commands** over a link whose sessions are established
with **ML-KEM-1024 + X25519** (hybrid), authenticated with **ML-DSA-87**, and whose data is encrypted with
**AES-256-GCM**. Photos and recordings stored on the UAV are encrypted under a per-file key that is wrapped with
ML-KEM-1024 + X25519 and signed with ML-DSA-87. **Audio** is sealed on the UAV in blocks of one size, each under a key
of its own, under one ML-DSA-87 signature; the same sealed blocks are stored and sent, and the ground station can
release the keys of an excerpt, and of nothing else, to a third party who verifies it with the UAV's public key
(`kyber6g/audio/`, `docs/AUDIO_CRYPTANALYSIS_REPORT.txt`). A **motion watch** runs on the UAV node itself: it takes the
camera's own movement out of the picture and reports what still moves, as text inside the secure link
(`kyber6g/camera/motion.py`); naming what is seen is done at the ground station, by a detector and an operator.

Four kinds of result are kept apart everywhere in this repository:

| Kind | What | Where |
|---|---|---|
| **Measured** | the prototype on real hardware, over Wi-Fi | `paper_plots/` (plots 1 to 10, 17 to 20 and the coloured parts of 21), `docs/TEST_REPORT.md` |
| **Attacked** | 27 kinds of attack experiment against the link and the stored files, 46 against sealed audio, on the real implementation | `docs/CRYPTANALYSIS_REPORT.txt`, `docs/AUDIO_CRYPTANALYSIS_REPORT.txt` |
| **Proved and checked** | the protocols modelled in ProVerif under four attackers (nothing broken, X25519 broken, ML-KEM broken, both); written reductions for the components; NIST's known-answer vectors on both machines; a self-test of the cryptography at every start | [`formal/`](formal/README.md), `docs/SECURITY_PROOFS.md`, `paper_plots/` (plot 22), `docs/CBOM.json` |
| **Simulated** | what the test bed cannot show: many UAVs, a 5G NR cell, movement, range, other algorithms; and generated scenes for the motion watch | `simulation/`, `paper_plots/` (plots 11 to 16, the grey parts of 21) |

**What this is not.** The prototype runs over **Wi-Fi/IP**; no 5G or 6G radio has been used at any point, and the NR
cell exists in the simulation only. ML-KEM and ML-DSA establish, wrap and sign; they do not encrypt the video or the
audio: AES-256-GCM does. The rekey is a **1-RTT** Cached RapidRekey, not 0-RTT. The proofs are **symbolic** (ideal
primitives) plus reductions for the components: there is no computational proof of the whole protocol, and nothing
here is "unbreakable". The Raspberry Pi has **no microphone**: a file put into its inbox stands in for one
(`docs/AUDIO_ON_A_UAV.md` says when a UAV has sound worth sealing at all). The UAV **has not flown**.

## Where things are

| Path | Contents |
|---|---|
| [`kyber6g/`](kyber6g/) | the implementation: `crypto/`, `transport/`, `camera/`, `recording/`, `audio/`, `uav/`, `ground/` (with the dashboard), `tools/` |
| [`run/`](run/), [`deploy/`](deploy/) | `kyber6g.sh` (start, deploy, test, measure, report, simulate, plots), the one-click launcher, the Pi's confined service |
| [`tests/`](tests/) | unit, regression and fuzz tests (run on both machines) |
| [`formal/`](formal/README.md) | ProVerif models of the handshake, the cached rekey, the PQ ratchet and the stored-file format, the four attackers, the runner and its results |
| [`docs/`](docs/README.md) | security architecture, security review, **security proofs**, **two cryptanalysis reports (plain text: the link and stored files; sealed audio)**, the cryptographic bill of materials, test report, literature notes; `legacy/` holds documents of the earlier study |
| [`paper_figures/`](paper_figures/README.md) | nineteen diagrams for the paper (draw.io sources, PDF, EPS, PNG) |
| [`paper_plots/`](paper_plots/README.md) | twenty-two plots for the paper, every measurement behind them, the scripts and the build checks |
| `audio encryption/` | the sample that stands in for a microphone, and the six published audio-encryption papers the audio scheme was set against. Neither is in git: the papers are their publishers' copyright, and the sample is a third party's recording whose licence to pass it on has not been confirmed. `KYBER6G_AUDIO=<any audio file>` repeats the audio measurements with another one |
| [`simulation/`](simulation/README.md) | calibration from the measurements, the ns-3 simulator source, the studies, the raw results, the analysis |
| `ns-3-dev/` | the ns-3.42 tree with 5G-LENA v3.3 the simulator is built in (its build directories are not in git) |
| [`kyber6g-website/`](kyber6g-website/README.md) | a web page of the project as it is now: every number and picture on it is taken from this repository's results by `scripts/build_data.py` (the earlier study's page and data were removed on 5 October 2026) |
| `elsarticle/` | the journal's LaTeX template |

## Results at a glance

**Measured** on 4 October 2026, sealed audio on 5 October (`docs/TEST_REPORT.md` §15 and §16; every sample is in `paper_plots/data/`). Times are
medians, timed on the UAV, over Wi-Fi, with live 720p30 video running:

| Measurement | Value |
|---|---|
| Full PQ handshake (1.5-RTT) | 23.2 ms, 95 % within 30.8 ms (150 runs, all succeeded) |
| 1-RTT Cached RapidRekey | 9.0 ms, 95 % within 17.3 ms (150 runs, all succeeded) |
| PQ ratchet | 14.1 ms, 95 % within 22.0 ms (150 runs, all succeeded) |
| Where a full handshake's time goes (timed inside the running programs) | UAV 8.2 ms, ground station 1.9 ms, link and waiting 13.2 ms |
| Bytes on the wire: full handshake / PQ ratchet / cached rekey | 13,106 (13 datagrams) / 4,757 (5) / 324 (3) |
| Video frames lost during those 450 operations | 1 of 4,071 |
| 13 minutes of 720p30 live video with automatic rekeying | 10 of 23,485 frames lost (single frames, none at a key change) |
| Cost of protecting the live video on the Pi | 356 records per second, 155 µs each: 5.5 % of one core; 7.3 % more bytes |
| 720p30 video, sensor → decoded picture | 91 ms: 69 camera and encoder, 6 sealing, sending and radio, 16 decoder |
| Round trip of a control message through the secure link | 8.2 ms on the UAV's own timer, 6.6 ms right after a command (ICMP echo: 7.7 ms) |
| Stored photo of 200 kB: sealed on the Pi / opened on the laptop | 8.1 ms / 0.5 ms (hybrid key wrap, signature); 6,761 bytes added to the file |
| Live video under packet loss | 35 % of the frames shown at 0.55 % datagram loss, 3 % at 2.1 %: after a damaged frame the receiver waits for the next keyframe. A keyframe request and forward error correction are not implemented |
| Session operations under packet loss | 193 of the 196 the UAV started completed, at up to 20 % loss; the link stayed up |
| Photos under packet loss | 21 of 21 received intact |
| Sealed audio (5 October 2026): one minute of 128 kbit/s audio sealed on the Pi / verified and opened on the laptop | 89 ms on the Pi (674 times faster than it is spoken; 9.0 % more bytes) / 12.6 ms |
| Sealed audio sent while it is sealed, with up to 20 % of the datagrams dropped | 12 of 12 clips of 37.5 s completed from the UAV's card and verified against the signed root, byte for byte the source (892 blocks fetched again). Heard live at 20 % loss: 81 % of the audio with one datagram per block, 22 % with seven |
| An excerpt of a 10-minute clip for a third party | one second of it is a bundle of 31.7 kB (0.3 % of the clip) with at most 5 of the clip's 2,944 block keys; verified with the UAV's public key alone in 0.6 ms |
| Motion watch on the UAV node (5 October 2026), beside live 720p30 video | 2.7 points of the Pi's four cores (9.1 % to 11.8 %), 31 ms a look at 8 looks a second, 0 of 7,303 video frames lost |
| Motion watch: a moving target of 8 pixels, generated scenes (simulated) | found in every look from a contrast of 8 grey levels of 255 in day noise and 16 in night noise; nothing moving: 1 region in 3,200 looks |
| Motion watch: the same target drawn into the camera's own pictures, lit room | found in 102 of 102 looks from a contrast of 6 on; imitated pans of 1 to 3 pixels a look measured to within 0.03 pixel |
| Protocol models in ProVerif, four attackers (5 October 2026) | 46 runs, 177 queries, all as expected: 100 claims proved, 77 that must be false are false |
| Known-answer tests: NIST ACVP vectors for ML-KEM-1024 and ML-DSA-87, RFC vectors for the rest | 162 of 162 on the Raspberry Pi and on the laptop |
| Automated tests on the final code (5 and 6 October 2026) | 314 unit tests on the laptop and 306 on the Pi (9 of them skipped there), all pass; end-to-end pipeline on the live hardware 58 PASS, 3 FAIL (the laptop's own clock; the motion watch's self-test in a lamp-lit room; one stored GNSS row without a position: none of them a check of the link); dashboard in a headless browser 111 PASS, 0 FAIL; stored-data audit 40 PASS, 2 WARN, 1 FAIL (that row) |

Not measured: energy, glass-to-glass latency, more than one UAV, flight, any radio other than Wi-Fi.

**Attacked** (`docs/CRYPTANALYSIS_REPORT.txt`; `bash run/kyber6g.sh measure attacks` and `report`): 339,084 attempts
on the Pi and the laptop to get a forged, modified, replayed or spliced record, handshake message, rekey request,
key share, photo or recording accepted, to impersonate either end, or to force a weaker algorithm: **none accepted**.
In a stress test of the sender, 192,000 records were sealed by eight racing threads without a nonce used twice.
A flood of forged handshakes delays a connection above a rate that depends on the ground station's processor
(3,000 per second on the laptop, 300 on a Pi) and never prevented one. The security review that went with it
(`docs/SECURITY_AUDIT.md`) has 28 findings (three of them from the audio path, two from the pass that added the proofs), all fixed. What an attacker *can* do (jam, flood, drop, observe sizes
and timing, use a stolen key) is in §7 of the report. None of this is a proof.

**Sealed audio, attacked** (`docs/AUDIO_CRYPTANALYSIS_REPORT.txt`; `bash run/kyber6g.sh measure audio` and `report`):
12,646 changed, re-ordered, borrowed, forged, re-signed or mislabelled clips, live blocks and excerpts were offered to
the implementation on the Pi and the laptop: **none accepted**, and no exception other than the one refusal the code
promises. The keys released with an excerpt were tried on every other block of the clip (5,124 attempts): none opened.
Silence, speech and music of the same length give sealed clips of the same size, block size and block count. On 37.5 s
of real audio the stored bytes have 7.9999 bits of entropy per byte and no correlation between neighbouring samples
(-0.0015; the sound: 0.985). What can still be learnt without a key (that a clip exists, when it was written, its size
to within about 12 %) and the limits (the ground station's recording keys open everything sealed to them; a file stands
in for the microphone) are in §10 of that report. It also sets the scheme against six published audio-encryption
schemes and says what in it is new and what is not: the building blocks are all known, and "new" is claimed, to our
knowledge only, for their combination.

**Proved and checked** (`docs/SECURITY_PROOFS.md`, `formal/RESULTS.md`; `bash run/kyber6g.sh formal` and `measure pq`):
the handshake, the cached rekey, the PQ ratchet and the stored-file format are modelled in ProVerif and checked under
four attackers (nothing broken, X25519 broken, ML-KEM broken, both): 46 runs, 177 queries, every one with the outcome
expected of it. **100 claims are proved** for any number of sessions, among them that a session and a stored photo,
recording or audio clip stay secret with either of the two key exchanges broken; **77 that must be false are false**,
among them every claim with both broken. The models also show what the design does not give: the cached rekey does
not heal a session whose secret had leaked, the PQ ratchet heals only against an attacker who does no more than
listen, and authentication rests on ML-DSA-87 alone. The libraries give NIST's known answers (ACVP vectors for FIPS
203 and FIPS 204) and the RFCs' on both machines: 162 of 162; both programs repeat a self-test at every start (18
checks at the ground station, 16 on the UAV) and stop if it fails. The model is symbolic: ideal primitives, no timing,
no sizes; the computational arguments are for the components, not for the protocol as a whole.

**The motion watch** (`docs/TEST_REPORT.md` §17.4, plot 21; `bash run/kyber6g.sh measure motion`): on generated scenes
(10 scenes a case, everything known) a moving target of 8 pixels is found in every look from a contrast of 8 grey
levels of 255 in the noise of a bright picture and 16 in that of a dim one, at speeds from 0.2 to 6 pixels a look, and
in 95 % of the looks while the camera pans 4 pixels a look; with nothing moving, 1 region was reported in 3,200 looks
at medium sensitivity and 10 at high. On the UAV's own camera in a lit room (472 lux; targets drawn into its pictures on the UAV, three captures in each mode, all used) the target is found in all 102 looks from a contrast of 6 on, at every size from 3 pixels and from 0.2 to 4 pixels a look; imitated pans of 1 to 3 pixels a look are measured to within 0.03 pixel; with nothing drawn in, 13 (NORMAL) and 18 (NIGHT) regions were reported in 102 looks, in a room with people in it. The watch costs the Pi 2.7 points of its four
cores (9.1 % to 11.8 % with live 720p30 video; 31 ms a look, 8 looks a second) and no video frame (0 of 7,303 lost).
**Where it failed:** the same evening, with the room lit by a lamp only (89 lux), the drawn target was found in 0 of
26 looks, with no false region: a part of the scene changed its brightness by up to a tenth ten times a second, and
the watch then says "the picture as a whole changed" and reports nothing (the measurement is in §17.4; not repaired).
It has not been tried on real targets against a ground truth, nor in flight; its other blind spots are in "Limits".

**Simulated** (`simulation/README.md`): the implemented protocol in ns-3.42 with 5G-LENA, calibrated with the
measurements above; 1,830 runs, none failed. A replica of the test bed reproduces what it was not built from: full
handshake 23.1 ms (measured 23.2), cached rekey 9.1 (9.0), PQ ratchet 16.3 (14.1: 16 % too slow, cause not found),
video frames complete under loss within 0.8 points at six loss rates. In a simulated 5G NR cell (3.5 GHz, 100 MHz;
**a model, not a measurement**) 64 UAVs that stream video keep the full handshake at 23 to 30 ms in an uplink-heavy
cell, and a downlink-heavy cell is overloaded by 48 of them: the uplink's capacity for video is the limit, not the
session protocol. 64 UAVs that start at the same instant all have their session after 156 ms. Ablations: the hybrid
post-quantum suite costs 10 ms per handshake and 27 times the bytes of a classical one; combining the fragments of
repeated messages raises the share of handshakes that complete at 20 % loss from 29 % to 83 %; a repeat timer of
three round trips (not implemented) would cut the time within which 95 % of the full handshakes are done at 1 % loss
from 1.2 s to 61 ms; a keyframe on request and one parity datagram per frame (not implemented) would raise the
usable video at 2 % loss from 6 % to 80 %. NR runs repeat bit for bit only with the program that made them; a rebuild
moved the reported medians by less than 1 %.

## The secure link (`kyber6g/`)

```
 L89 GNSS ─ gpsd ──┐                       ┌─► telemetry dashboard + map
 OV5647 ─ ISP ─ H.264 (VideoCore HW) ─┬────┤   (GCS: decrypt → reorder → ffmpeg decode → MJPEG)
                   │                  └─► encrypted recorder (.k6grec: file key wrapped with ML-KEM-1024 + X25519,
 16×2 LCD ◄─ live status               │                      file signed with ML-DSA-87, on the SD card)
 audio (a file stands in for a microphone) ─► sealed clips (.k6gaud: a key per block, one signature, on the SD card
                   │                           and, block by block, onto the link)
                   └──► Kyber-6G link: ML-KEM-1024+X25519 / ML-DSA-87 → HKDF-SHA256 → per-stream,
                        per-direction, per-epoch AES-256-GCM keys → MTU-safe UDP over Wi-Fi/IP
```

Where public-key cryptography is used, and with what (`docs/SECURITY_ARCHITECTURE.md` §12):

| Where | Algorithms | Post-quantum? |
|---|---|---|
| Full handshake: session keys / both ends prove who they are | ML-KEM-1024 + X25519 / ML-DSA-87, keys pinned | yes, hybrid / yes |
| PQ ratchet: fresh secrets inside a session | ML-KEM-1024 + X25519 | yes, hybrid |
| 1-RTT Cached RapidRekey | none (HKDF, HMAC-SHA-256) | inherits from the handshake |
| Stored photos and recordings: wrap the file key / origin of the file | ML-KEM-1024 + X25519 / ML-DSA-87 | yes, hybrid / yes |
| Sealed audio: wrap the clip key / one signature over the Merkle root of all blocks, also what an excerpt is verified with | ML-KEM-1024 + X25519 / ML-DSA-87 | yes, hybrid / yes |
| Management channel (deploy, service control, measurements over SSH) | key exchange `sntrup761x25519-sha512`; host and user keys Ed25519 | key exchange yes, hybrid; authentication **no** (OpenSSH has no post-quantum signature) |
| Everything that is sent or stored | AES-256-GCM (ChaCha20-Poly1305 as suite 2) | symmetric, 256-bit keys |

| Size (bytes) | ML-KEM-1024 | X25519 | ML-DSA-87 |
|---|---|---|---|
| Public key | 1,568 | 32 | 2,592 |
| Ciphertext / signature | 1,568 | — | 4,627 |

### Hardware and wiring

| Part | Connection |
|---|---|
| Waveshare RPi Camera (F): OV5647, 5 MP, manual focus, about 50° FOV, two 850 nm IR boards | CSI **CAMERA** port; ribbon contacts face the HDMI ports. IR LEDs switch themselves on with their light sensors (**not software-controlled**). No IR-cut filter, so daytime colours show a magenta cast |
| 7Semi L89 multi-GNSS (GPS / NavIC / GLONASS / BeiDou / Galileo / QZSS, L1/L5) | USB → `/dev/ttyACM0` (9600 baud NMEA) → gpsd |
| 16×2 LCD with PCF8574 backpack (I2C 0x27) | GND→pin 6, VCC→pin 4 (5 V), SDA→pin 3, SCL→pin 5. Pin 1 is the end **away** from the USB ports. The `LED` jumper must be fitted. **Caveat:** at 5 V the backpack's pull-ups raise SDA/SCL above 3.3 V; a BSS138 level shifter, or removing the two pull-ups, is the safe fix |
| Power | Official 5.1 V / 3 A supply. Laptop USB caused undervoltage and a reboot |

### Start it (one click)

- **Laptop:** double-click **`Kyber6G.bat`** (on the Desktop; the source is `run/Kyber6G.bat`). It:
  - makes sure the UAV service is running on the Pi;
  - checks the WSL clock against the Pi's (see the note below);
  - starts the ground station in that window, and starts it again by itself if it ever crashes;
  - opens **http://127.0.0.1:8600** as soon as the dashboard answers.

  Closing the window stops the ground station.

  **Clock note:** on the test laptop the clock inside WSL runs at the wrong speed most of the time (measured: 8.3 % slow, with Windows pushing it forward by ~2.9 s every ~35 s). The launcher says so when it starts. Video, detection boxes and frame rates are timed on the camera's clock and work either way; latency figures are then estimates (marked *APPROX*), and times stamped by the laptop can be up to 3 s off. Restarting WSL (`wsl --shutdown`) made the clock right for about two minutes only; the cause is not determined (see `docs/TEST_REPORT.md` §13.2). `bash run/kyber6g.sh clock` shows the current drift.
- **Pi:** nothing to do. The `kyber6g-uav` systemd service starts at boot and restarts itself on failure. Logs: `journalctl -u kyber6g-uav`.
- **Everything else goes through `run/kyber6g.sh`** (inside WSL):

  ```bash
  bash run/kyber6g.sh status
  ```

  Other commands: `start` · `stop` · `restart` · `logs` · `uav-status` · `uav-logs` · `uav-restart` · `deploy` (push code to the Pi) · `test` · `pipeline` (end-to-end test on the live hardware) · `ui-test` (drives the dashboard in a headless browser) · `audit` · `clock` · `pull NAME` (copy and decrypt a recording that is too large to fetch over the link) · `audio-put FILE` (copy an audio file into the Pi's inbox: it stands in for a microphone and is sealed there) · `measure` (the measurement campaign for the paper's plots, about 110 minutes; `measure attacks` runs only the attack experiments, `measure audio` only those on sealed audio, `measure pq` the known-answer tests on both machines, `measure motion` those of the motion watch) · `report` (writes `docs/CRYPTANALYSIS_REPORT.txt` and `docs/AUDIO_CRYPTANALYSIS_REPORT.txt` from the experiments) · `formal` (runs the ProVerif models under the four attackers and compares every query with its expected outcome) · `conformance` (NIST's known-answer vectors against the libraries on this machine) · `cbom` (writes the cryptographic bill of materials) · `simulate` (calibrate, build and run the simulation studies; `simulate list`, `simulate analyze`, `simulate <study>`) · `plots` (draw all plots and check them).

### Dashboard (Minecraft-style GUI)

| Tab | Contents |
|---|---|
| MISSION | Live decrypted video with a **camcorder REC indicator** (blinking ● REC hh:mm:ss, size, frames) and the detection overlay: real-time **YOLOE / YOLOv8 + ByteTrack** boxes (stable labels, boxes extrapolated onto the frame being shown) plus the **FINDER** (OWLv2 / Grounding DINO) for named objects such as pencil or screwdriver, and **TEACH** (draw a box around any object once). The **motion watch** of the UAV node: dashed amber boxes tagged MOVING around what moves, a banner while something does, and its controls (MOTION on/off, sensitivity, SENTRY: watch without live video, PHOTO ON MOTION: a sealed photo when something starts to move). Counts per class, unique tracks, "recently spotted" snapshots, mini map, event log, hotbar (LIVE / STOP / REC / SAVE / PHOTO / DAY / NIGHT / FOCUS / AI) |
| TELEMETRY | GIS map (Esri satellite / OSM street) with the speed-coloured track, heatmap, 100/250/500/1000 m range rings around home, accuracy circle and geotagged detections; fix and accuracy tiles (TTFF, fix availability, CEP50/CEP95/2DRMS, distance, speeds, MSL altitude, DOP, distance from home); **GNSS receiver panel** (receiver UTC, RMC/GGA status, satellites with C/N0, antenna, NMEA rate, plain-language diagnosis when there is no fix); sky plot; C/N0 per satellite; constellation chart; altitude/speed and satellites/DOP time series; **3D block density map** (three.js); sortable telemetry data table (pauses while you read it); CSV / GeoJSON / KML exports |
| SECURITY | Session, suite, handshake/rekey timings, PQ ratchets, per-stream key epochs, rejected-packet counters, RTT chart, link events, the result of the **self-test of the cryptography** that each program ran when it started (ground station and UAV), and the state of this computer's clock against the UAV's |
| MEDIA | Verified images, **photos stored encrypted on the Pi** (list → fetch → decrypt), detection snapshots, encrypted recordings (fetch → decrypt → play, with seeking). The newest 16 photos and 10 recordings are shown; **SHOW ALL** lists every photo and every decrypted recording the ground station holds, newest first. A recording saved with ◼ SAVE is fetched and decrypted by itself if it is at most 64 MB (`auto_fetch_mb`); the list of the recordings on the Pi's card fills by itself, newest first, and marks which are here already and which are on the Pi only. A recording rolls over into a new file every 192 MB so each part stays fetchable; older files over 256 MB are marked *TOO LARGE* (use `kyber6g.sh pull`). **Sealed audio**: list the clips on the Pi, seal the source waiting in its inbox, fetch → verify → open → play, seal and send live (heard as it comes in), and cut an excerpt for a third party |
| DATA | SQLite database counts and full-DB download, detections CSV, video/AI performance and Pi system charts (incl. free space on the SD card), stored events |

The dashboard needs no internet: fonts and libraries (Leaflet, Chart.js, three.js) are served by the ground station from `kyber6g/ground/static/vendor/`. Only the map background tiles come from the network. It recovers by itself from a restart of the ground station or of the UAV (the video stream is reopened, no page reload), keeps the image/recording gallery and the operator's detector, finder and reference-point settings across restarts, and never moves its layout when values change (checked by `ui-test`).

### Data storage and backend (GCS)

- **Storage:** `~/kyber6g_ground/kyber6g.db` (SQLite, WAL mode, single writer thread). Tables: telemetry, satellites, detections, tracks, images, recordings, link_stats, video_stats, system_stats, events, runs.
- **Files:** images, decrypted recordings, detection snapshots and pipeline reports go in `~/kyber6g_ground/{images,recordings,detections,exports}`; audio in `~/kyber6g_ground/audio` (opened clips), `audio/sealed` (the clips as they are on the UAV's card) and `audio/excerpts`.
- **Store-and-forward:** while the link is down, the Pi buffers up to 2 h of telemetry and sends it after recovery, flagged `backfill`.
- **GNSS:** gpsd JSON plus raw NMEA (GSV/GSA, checksum-verified). Satellites appear with their signal strength (C/N0) as soon as they are tracked, before their azimuth/elevation are known.
- **Motion watch (on the UAV, no video needed):** `kyber6g/camera/motion.py` looks at a 320 × 180 copy of the camera picture 8 times a second (NumPy/SciPy, no model), measures the camera's own movement and takes it out, and reports what still moves as a few hundred bytes of text in the status stream: it works with the live video off (SENTRY) and when video frames are lost. It says *that* something moves and where, not *what* it is. `motion` with `selftest` draws targets of known size, contrast and speed into the camera's own pictures on the UAV (in memory; only counts leave it) and says how many were found in this light. Steps, limits and measurements: the module's first lines, `docs/TEST_REPORT.md` §17, `paper_plots` plot 21.
- **AI (on the GCS, on the decrypted frames, newest frame only, no backlog):**
  - **Real-time detector** (profiles: GENERAL YOLOE-11s ≈ 5 fps · ACCURATE YOLOE-11L ≈ 3 fps · FAST YOLOv8n COCO-80 ≈ 10 fps · OPEN 4585 classes · CUSTOM your own words) with ByteTrack. Labels are a confidence-weighted vote per track, new objects are confirmed after 3 hits, geotagged and snapshotted. Database ids are unique across runs.
  - **TEACH:** draw one box around any object on the frozen live frame and name it; YOLOE-11L uses it as a *visual prompt* (kept in `models/taught.json`, up to 8 examples per name).
  - **FINDER:** OWLv2 (640 px) in a background thread, looking for the words you give it (default *pencil, screwdriver*), one look every 4 s (ECO / BALANCED / CONTINUOUS). Every pass and every confirmed object is stored; weak signals are shown as hints and saved as candidate frames.
  - **Why two of them:** on a 66-image test the text-prompted YOLOE models were at chance for *pencil* and *screwdriver* (AUC ≈ 0.5), OWLv2 found 14/14 screwdrivers and 11/11 pencils in clear photos; none of the text models found the pencil in the dim IR camera frames, a visual prompt did. Numbers and caveats: `docs/TEST_REPORT.md` §12.4.
- **Stored-data audit:** `bash run/kyber6g.sh audit` checks SQLite integrity, coordinates, ordering, boxes, snapshots, images (SHA-256), recordings (decrypt), file permissions, secrets in logs, and the encrypted files on the Pi.
- **API:** `/api/state`, `/api/series`, `/api/telemetry` (`?latest=N`), `/api/tracks`, `/api/events`, `/api/db`, `/api/media` (every photo and decrypted recording held, newest first), `/api/detections/latest`, `/api/export/{telemetry.csv,telemetry.geojson,telemetry.kml,satellites.csv,detections.csv,db}`, `/video.mjpg`, `/video_annotated.mjpg`, `/audio/<file>`, `/audio/excerpts/<file>`, `/audio_live?tag=` (a live clip as it is opened); commands (`POST /api/cmd`): UAV commands (among them `list_audio`, `record_audio`, `fetch_audio`, `check_audio`, and `motion`: enabled, sensitivity, hz, sentry, photo, selftest, trace) plus `detector` (profile, vocab, conf, imgsz, enhance, teach, forget), `finder` (enabled, words, threshold, period), `set_home`, `audio_excerpt` (name, t0, t1).

### Install from scratch

```bash
# Pi (once)
sudo apt install -y python3-picamera2 python3-scipy gpsd gpsd-clients python3-gps python3-serial python3-psutil i2c-tools python3-smbus2 ffmpeg
sudo raspi-config nonint do_i2c 0
#   /etc/default/gpsd: DEVICES="/dev/serial/by-id/usb-1a86_USB_Single_Serial_<id>-if00"  GPSD_OPTIONS="-n"

# GCS / laptop (WSL): ground venv (crypto + ML), keys, then deploy (code + Pi venv + UAV keys + PUBLIC key exchange)
python3 -m venv /root/kyber6g_gcs_venv && /root/kyber6g_gcs_venv/bin/pip install "liboqs-python==0.16.0" "cryptography==50.0.1" pillow "scipy==1.15.3"
#   scipy: the motion watch's tests and benchmark on the laptop (the same version as the Pi's python3-scipy)
#   optional, for `bash run/kyber6g.sh formal` only: ProVerif 2.05 (apt install ocaml-nox ocaml-findlib; build from the Inria archive; see formal/README.md)
/root/kyber6g_gcs_venv/bin/pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
/root/kyber6g_gcs_venv/bin/pip install ultralytics transformers && /root/kyber6g_gcs_venv/bin/pip uninstall -y opencv-python && /root/kyber6g_gcs_venv/bin/pip install opencv-python-headless
#   models download on first use into ~/kyber6g_ground/models (YOLOE, MobileCLIP) and the Hugging Face cache (OWLv2, ~0.6 GB)
python -m kyber6g.tools.provision gcs
bash deploy/deploy_pi.sh kyber-pi            # ssh alias or user@host
bash run/kyber6g.sh deploy                   # installs the confined systemd service on the Pi (deploy/kyber6g-uav.service) and starts it;
                                             # the same command pushes later code changes

# run
python -m kyber6g.ground.main                                                    # GCS; dashboard http://127.0.0.1:8600
ssh kyber-pi 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -m kyber6g.uav.main -c deploy/uav.json'   # UAV

# tests (run on both machines)
python -m unittest discover -s tests -t .
# real-browser dashboard test (laptop; test tooling only, not needed to run the system)
/root/kyber6g_gcs_venv/bin/pip install playwright && /root/kyber6g_gcs_venv/bin/python -m playwright install --with-deps chromium
bash run/kyber6g.sh ui-test
```

Set the GCS IP in `deploy/uav.json` (`link.gcs_host`). On WSL with mirrored networking that is the Windows host's LAN IP. UDP port 14600 must be reachable from the Pi.

**Dashboard** (local only): Start/Stop live · Start/Stop recording · Capture image · Normal / Night vision · resolution/fps/bitrate · 1-RTT Cached RapidRekey · PQ ratchet · list / fetch & decrypt recordings · security, GNSS (with map), camera and system panels · event log.

**Decrypt a recording manually** (GCS only): `python -m kyber6g.tools.decrypt_recording rec.k6grec -o out.mp4`

### Modules

| Path | Purpose |
|---|---|
| `kyber6g/crypto/` | `suites` (agility), `keyschedule` (HKDF labels, epoch chain), `handshake` (hybrid handshake, Cached RapidRekey, PQ ratchet), `record` (AEAD record layer, nonces, AAD), `replay` (sliding window), `identity` (pinned ML-DSA keys), `secure_bytes` (zeroisation) |
| `kyber6g/transport/` | `link` (UAV/GCS session management, recovery, heartbeats, time sync), `framing` (handshake fragmentation), `blob` (reliable encrypted image/recording transfer) |
| `kyber6g/camera/` | Picamera2 service: one H.264 encode fanned out to live + recorder; stills; night mode; NoIR colour tuning. `motion.py`: the motion watch (camera movement from tile phase correlation and, in dim scenes, from pictures a quarter and an eighth of the size; difference with a noise threshold that sets itself; a test of whether "the rest of the picture moves too" that tells a camera passing a lamp from a lamp that moves); `motion_eval.py`: scoring with targets whose position is known (generated scenes, and the camera's own pictures) |
| `kyber6g/crypto/selftest.py` | the self-test both programs run when they start (known answers for every primitive, a NIST vector for ML-KEM key generation, sign/verify and encapsulate/decapsulate with the machine's own keys); a failure stops the program |
| `kyber6g/tools/pq_conformance.py`, `cbom.py` | NIST's ACVP known-answer vectors for ML-KEM-1024 and ML-DSA-87 (and RFC vectors for the classical parts) against the libraries in use; the cryptographic bill of materials `docs/CBOM.json` (CycloneDX 1.6), generated from the code |
| `kyber6g/tools/motion_bench.py` | the measurements of the motion watch: generated scenes, the camera's own pictures, what the watch costs the UAV, the real scene left to itself |
| `formal/` | ProVerif models and `run.py`, which runs them under the four attackers and compares every query with the outcome that is expected of it (`formal/RESULTS.md`) |
| `kyber6g/recording/` | `sealing.py`: file format 2 (file key wrapped with ML-KEM-1024 + X25519, file signed with ML-DSA-87); `.k6grec` encrypted segmented recorder and decryptor; `photos.py`: `.k6gimg` encrypted photo store on the UAV (only the GCS can open it, and it checks the UAV's signature first) |
| `kyber6g/audio/` | sealed audio (QUAVER): `framing.py` cuts an MP3 or PCM stream into its frames without decoding it; `quaver.py` is the format (blocks of one size, key tree, commitments, Merkle tree, one signature, excerpt release); `store.py` is the UAV's clip store and chain |
| `kyber6g/ground/audio_desk.py` | the ground station's side: clips from the card, clips that come in live (played as they come, completed from the card, stored when every block is under the signed root), excerpts |
| `kyber6g/tools/audio_bench.py`, `audio_report.py` | attack experiments, cost, ciphertext statistics and live-loss runs for sealed audio, and the generator of `docs/AUDIO_CRYPTANALYSIS_REPORT.txt` |
| `kyber6g/ground/detector.py`, `finder.py` | real-time detector profiles (general / accurate / fast / open / custom, TEACH by example) and the slower accurate FINDER |
| `kyber6g/ground/static/boxtracker.js` | overlay box smoothing/extrapolation (unit-tested under node: `tests/js/boxtracker_sim.js`) |
| `kyber6g/tools/data_audit.py` | audits everything stored on the GCS and the UAV (SQLite, images, recordings, permissions, no secrets) |
| `kyber6g/tools/ui_test.py` | drives the real dashboard in headless Chromium: layout shifts per tab (browser Layout Instability API), long-text stress, JS errors, and every control (live, photo, record, modes, resolution, detector profiles, FIND, FINDER, TEACH, rekeys, media fetch, exports) |
| `kyber6g/tools/pipeline_test.py` | end-to-end test of the running system through the GCS API (about 40 checks, writes a JSON report) |
| `kyber6g/tools/bench_crypto.py`, `bench_link.py` | the measurements behind `paper_plots/`: primitives, AEAD and record layer on both machines; session operations, round trips, a long run, packet loss and transfers on the live link (`bash run/kyber6g.sh measure`) |
| `kyber6g/tools/attack_bench.py`, `crypto_report.py`, `media_stats.py` | the attack experiments against the real implementation (run on both machines), the generator of `docs/CRYPTANALYSIS_REPORT.txt`, and the statistics of an encrypted picture |
| `kyber6g/tools/sshopts.py` | the SSH options every tool and script uses to reach the Pi: post-quantum hybrid key exchange first |
| `tests/test_hardening.py`, `tests/test_sealing.py`, `tests/test_audio.py` | regression tests for the findings of the security review, fuzz tests of the link, the handshake messages and the stored-file parsers; the signed hybrid file format; sealed audio (framing, the two trees, every way of damaging or forging a clip, excerpts, the live path with loss) |
| `tests/test_pq.py`, `tests/test_motion.py` | the post-quantum part (known answers, key checks, that a session and a stored file need BOTH secrets, that signed messages of different kinds cannot be confused, the bill of materials, the self-test); the motion watch (still and moving camera, flicker, exposure, the two faults the first measurements brought out, settings, reports) |
| `simulation/` | `calibrate.py` (measurements and implementation → calibration file), `ns3/k6g-swarm-sim.cc` (the simulator), `run_sweep.py` (the studies, in parallel), `analyze.py` (plots 11 to 16 and their tables) |
| `kyber6g/telemetry/` | gpsd client (TPV/SKY), with a labelled synthetic test mode |
| `kyber6g/lcd/` | HD44780/PCF8574 driver + non-blocking rotating status screens |
| `kyber6g/uav/`, `kyber6g/ground/` | UAV and GCS applications; dashboard (`ground/static/index.html`) |
| `kyber6g/tools/` | `provision`, `decrypt_recording`, `hwtest_camera` |
| `docs/SECURITY_ARCHITECTURE.md` | Protocol, key schedule, nonces, replay, rekeying (including exactly what Cached RapidRekey does **not** provide), recordings, limitations |
| `docs/RESEARCH_REFERENCES.md` | How each of the 150 local papers was used or rejected |
| `docs/TEST_REPORT.md` | Hardware report and all measurements, including NOT TESTED items |
| `docs/SECURITY_AUDIT.md` | Security and robustness review (October 2026): 28 findings, fixes, tests, residual risks |
| `docs/SECURITY_PROOFS.md` | What is proved, under which assumptions and by what: the hybrid combiner, the handshake, the cached rekey, the PQ ratchet, the record layer, stored files, sealed audio; the evidence for each claim; what is not proved |
| `docs/AUDIO_ON_A_UAV.md` | Whether a UAV can record sound at all: what the rotors do to a microphone, the cases in which sealed audio from a UAV makes sense, the exceptions, the wording for the paper |
| `docs/CRYPTANALYSIS_REPORT.txt` | Plain text, for the paper: what is protected and by what, the attacker, every attack tried with its outcome on both machines, ciphertext statistics, quantum resistance, limits |
| `docs/AUDIO_CRYPTANALYSIS_REPORT.txt` | Plain text, for the paper: where six published audio-encryption schemes fall short, the sealed-audio scheme, every attack tried on it, statistics, cost, loss on the real link, limits, what is new and what is not |
| `paper_plots/`, `paper_figures/` | Plots (with their measurement data and scripts) and diagrams for the paper |

### Troubleshooting

| Symptom | Fix |
|---|---|
| `rpicam-hello --list-cameras` reports "No cameras available" | Power off; reseat the ribbon (CAMERA port, contacts toward HDMI) and the camera's small sensor connector; reboot. Never hot-plug the ribbon |
| LCD backlight on but no text | Turn the contrast trimmer. At 3.3 V this LCD showed no text at any setting |
| LCD background dark blue | The `LED` jumper is missing |
| `i2cdetect` shows nothing | Wires at the wrong end of the header (pin 1 is away from the USB ports) |
| GNSS `NO FIX`, 0 satellites | Give the antenna sky view; cold start takes several minutes |
| Pi reboots / `vcgencmd get_throttled` ≠ 0x0 | Use a 5.1 V / 3 A supply |
| Video stalls after a large control message | Keep every datagram ≤ 1472 B. IP-fragmented UDP is dropped on WSL; the code already fragments at the application layer |
| Dashboard looks stale or glitchy after an update | Reload the page once (Ctrl+F5). Newer versions reload themselves when the dashboard files change |
| Pencil / screwdriver not boxed | The FINDER needs a clear, close, well-lit view and about 4 s; lower its score box (default 0.35) to see weaker hits, or TEACH the object once from the live view. A "weak signal" hint shows what it almost saw |
| Live boxes slow (≈ 3 fps) | The FINDER shares the CPU: choose ECO or turn FINDER off |
| Link `DOWN` | Check UDP 14600 reaches the GCS, and that the pinned keys in `~/.kyber6g/peers/` match the other side's fingerprints (`deploy_pi.sh` prints them). The ground station's log says why it refused a ClientHello; "time stamp is N s away from this clock" means the two clocks differ by more than 120 s. The UAV takes handshake answers only from the address in `link.gcs_host` |
| The UAV service does not start: `PermissionError` naming `~/.kyber6g` | The key directory must be private (mode 0700) and its keys not writable by group or others; the confined service cannot change that itself. `bash run/kyber6g.sh deploy` sets the modes |
| Dashboard answers `403 host not allowed` | It was opened under a name other than `localhost` or an IP address. Add the name to `http_allowed_hosts` in the ground configuration. `403 cross-site request refused` and `415` mean the request did not come from the dashboard page itself |
| SECURITY tab: "PC clock … % SLOW", latency tiles say APPROX, impossible latencies | The clock of the WSL VM runs at the wrong speed (`bash run/kyber6g.sh clock` shows by how much). The video, the boxes and the frame rate do not depend on it; only latency figures and laptop-side timestamps do. `wsl --shutdown` in Windows resets it, but on the test laptop it was slow again within two minutes; cause not determined |
| A recording is listed as *TOO LARGE* | It is over the 256 MB limit of one transfer (made before recordings rolled over into 192 MB parts). `bash run/kyber6g.sh pull rec_….k6grec` copies the encrypted file and decrypts it on the laptop |
| REC refused: "SD card almost full" | Less than 500 MB free on the Pi. Delete old `~/kyber6g_recordings/*.k6grec` on the Pi (a running recording is closed cleanly at 250 MB free) |
| Large `wsl-crash-*.dmp` files in `%LOCALAPPDATA%\Temp\wsl-crashes` | Crash dumps WSL made of earlier ground-station crashes (several GB each, and they contain key material). Delete them. The ground station and the UAV app now mark themselves non-dumpable, so new ones are not written |

## Limits, stated plainly

- **Wi-Fi, one UAV, on a desk.** Everything measured was measured that way. More UAVs, a cellular radio, movement
  and range exist in the simulation only, and the simulation is a model (one cell, line of sight, no interference
  from neighbouring cells).
- **Live video does not survive packet loss well**: a damaged frame blanks the picture until the next keyframe.
- **A flood of forged handshakes** above the rates given above delays a connection; jamming and an attacker who
  drops packets cannot be stopped by a protocol.
- **A captured UAV can be impersonated** until its pinned key is removed at the ground station; what is stored on
  its card stays unreadable.
- **The proofs are symbolic.** ProVerif treats the primitives as ideal and knows no timing and no sizes; the
  computational arguments are for the components. There is no computational proof of the whole protocol, no
  side-channel or fault analysis, no independent review of the models and no independent penetration test.
  Authentication is post-quantum only (ML-DSA-87), not hybrid; SHA-256 is used where CNSA 2.0 asks for SHA-384.
- **No microphone.** A file put into the Pi's inbox stands in for one and is sealed frame by frame at the speed a
  microphone would deliver it; capture from a sound card and a live encoder were not tested. In flight, next to the
  rotors, a plain microphone would record the rotors (`docs/AUDIO_ON_A_UAV.md`).
- **The UAV has not flown.** No vibration, no real camera movement, no rotor noise.
- **The motion watch says that something moves, not what.** It was scored with drawn targets (in generated scenes
  and in the camera's own pictures) and with imitated camera movement. It cannot tell a near, still thing passed by
  a moving camera from a thing that moves (parallax), nor one bright thing in an otherwise empty picture that is
  passed slowly from one that moves by itself: there the camera is taken to stand still, unless the GNSS says the
  UAV is under way, in which case nothing is reported. Something that fills most of the picture counts as "the
  picture changed", not as a thing. And while a part of the scene keeps changing its brightness (measured: a lamp-lit
  room at 89 lux, a region changing by up to a tenth ten times a second) it reports nothing at all: found 0 of 26.
- **Energy was not measured.**
- The Raspberry Pi's kernel, firmware, bootloader, Wi-Fi firmware and camera applications (19 packages) are held at
  their current versions; everything else on it is up to date (`docs/SECURITY_AUDIT.md`, residual risk 9).
- The literature references in `docs/SECURITY_PROOFS.md` and `docs/AUDIO_ON_A_UAV.md` were written from memory and
  are marked so: check each before citing it.

## License

MIT, as stated by the authors. (A `LICENSE` file is not in the repository yet.)
