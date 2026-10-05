# Plots for the paper

Twenty-two plots and their tables, in groups that must not be mixed up:

* **Plots 1 to 10 are measured.** Every number in them was measured on the real system on 4 October 2026: the
  Raspberry Pi 4B (UAV node) and the ground station (laptop) talking over Wi-Fi through the secure link in `kyber6g/`,
  or the two machines running the cryptographic code and the attack experiments. The measurement tools write every
  sample to `data/`, and `scripts/make_plots.py` draws from those files only. Where a model appears (one curve in
  plot 6) it is labelled as such and drawn next to the measurement.
* **Plots 17 to 20 are measured as well**, on 5 October 2026: sealed audio (`kyber6g/audio/`) on the same two
  machines and over the same link. The Raspberry Pi has no microphone; a file stood in for it.
* **Plots 11 to 16 are simulated.** They come from `../simulation/` (ns-3 with 5G-LENA, calibrated with the
  measurements) and show what the test bed cannot: many UAVs, a 5G NR cell, movement, range, other algorithms, other
  design choices. Plot 11 is the check of that simulation against the measurements. Every simulated panel says so.
* **Plot 21 (the motion watch) is both, and says which is which**: generated scenes in grey (everything about them is
  known, so a detector can be scored exactly), the UAV's own camera in colour (targets drawn into its pictures on
  the UAV), and what the watch costs the UAV, measured. 5 October 2026.
* **Plot 22 is neither measured nor simulated: it is what was proved and what was checked.** The outcome of every
  ProVerif run (`../formal/`), claim by claim and attacker by attacker, and the known-answer tests of the libraries
  on both machines.

The diagrams of the paper are in [`../paper_figures/`](../paper_figures/README.md); the plots use the same typeface
(Arial), sizes (90 mm and 190 mm) and palette. The look of both follows the scripts and design notes of
[figures4papers](https://github.com/ChenLiu-1996/figures4papers) (see "Style" below).

## Files

| Path | Content |
|---|---|
| `exported_pdf/`, `exported_eps/`, `exported_png/` | Each plot as vector PDF, EPS and 600 dpi PNG |
| `tables/` | The numbers of each plot as CSV (`plotNN_*.csv`) and the tables that are not plots (`table_*.csv`) |
| `data/` | Raw measurement files (JSON, every sample, with a `provenance` block: time, software, hardware, camera settings, clock check); `data/media/` holds the three pictures of plot 9; `audio_*.json` are the files behind plots 17 to 20 |
| `scripts/` | `make_plots.py` (draws plots 1 to 10), `audio_plots.py` (plots 17 to 20), `assurance_plots.py` (plots 21 and 22), `plotlib.py` (common style, also used by `../simulation/analyze.py` for plots 11 to 16), `build.py` (draws everything and checks it) |
| `checks/` | `build_report.md` (measured page sizes, fonts, smallest text), `palette.txt` (colour-vision check), `gray/` (grey-scale previews), `plot_summary.json`, `sim_summary.json`, `text_cut_off.json` |

## The measured plots

| File | Width | Suggested caption |
|---|---|---|
| `plot01_crypto_primitives` | 190 mm | Cost of the cryptographic operations on the Raspberry Pi 4B and on the ground station (300 calls each; marker: median, bar: 5th to 95th percentile). |
| `plot02_handshake_latency` | 190 mm | (a) Time to a new session, measured at the UAV over the Wi-Fi link while video is streaming: full 1.5-RTT handshake, 1-RTT Cached RapidRekey and PQ ratchet, 150 operations each. (b) Median time split into computation on each node, timed inside the operations, and the remainder. |
| `plot03_wire_bytes` | 90 mm | Bytes on the wire per session operation, both directions, and what they consist of. |
| `plot04_aead_throughput` | 190 mm | Sealing throughput of AES-256-GCM and ChaCha20-Poly1305 by payload size on (a) the Raspberry Pi 4B, which has no AES instructions, and (b) the ground station. |
| `plot05_timeline` | 190 mm | Thirteen minutes of operation with live 720p video: (a) frame rate at the ground station, (b) round trip of a control message, (c) processor load and (d) temperature of the Raspberry Pi; periodic rekeying marked, a recording running from 420 s to 540 s. |
| `plot06_loss` | 190 mm | Behaviour under packet loss injected on the Raspberry Pi: (a) live video, (b) time to a new session, (c) transfer of a photo with retransmission. |
| `plot07_latency` | 190 mm | (a) Round-trip time over the Wi-Fi link: ICMP echo, a control message through the secure link sent on the UAV's timer, and the same message sent right after a command arrived. (b) Where a video frame spends its time between the sensor and the decoded picture. |
| `plot08_media_protection` | 190 mm | Cost of protecting pictures and video. (a) Sealing a photo on the Raspberry Pi and (b) opening it on the ground station, for the earlier file format (ML-KEM-1024 alone, unsigned) and the present one (ML-KEM-1024 + X25519, ML-DSA-87 signature). (c) Bytes the key wrap and the signature add to a stored file. (d) Bytes of one second of live video on the air. |
| `plot09_cipher_statistics` | 190 mm | A picture before and after sealing: (a, d) the pixels, (b, e) their histogram, (c, f) each pixel against its right neighbour, and the usual statistics. The picture is a public-domain aerial photograph, not one taken by the prototype. |
| `plot10_attacks` | 190 mm | Attack experiments against the implementation on both machines. (a) Attempts made per kind of attack; none was accepted. (b) Time for a genuine UAV to connect while forged ClientHellos arrive at a given rate. (c) Welch's *t* for the time of a refusal between two classes of wrong input, with a deliberately leaking comparison as control. |

### What the measurements say

**Plot 1, cryptographic operations.** On the Pi every primitive stays under one millisecond at the median:
ML-KEM-1024 key generation 0.12 ms, encapsulation 0.13 ms, decapsulation 0.13 ms; X25519 key agreement 0.26 ms;
ML-DSA-87 signing 0.77 ms (0.54 to 1.64 ms between the 5th and 95th percentile: signing repeats until a signature
is acceptable, so its time varies by design), verification 0.45 ms. The Pi is 3 to 8 times slower than the laptop.
(`tables/plot01_crypto_primitives.csv`; the protocol steps built from these primitives are in
`tables/table_protocol_steps.csv`; ML-KEM-512/768, ML-DSA-44/65 and Ed25519, used by the ablation of plot 15, in
`tables/table_algorithm_variants.csv`.)

**Plot 2, session establishment.** All 450 operations succeeded. Median and 95th percentile at the UAV:
full handshake 23.2 ms / 30.8 ms, 1-RTT Cached RapidRekey 9.0 ms / 17.3 ms, PQ ratchet 14.1 ms / 22.0 ms.
The video stream ran throughout: 4,071 frames arrived during the 450 operations and one was lost. Panel (b) uses
times taken **inside the operations themselves**: the UAV times the phases of each of its operations, the ground
station its work on each request. For a full handshake the UAV computes for 8.2 ms and the ground station for
1.9 ms; the remaining 13.2 ms are the radio link in both directions (13 datagrams), scheduling and waiting. The
same steps run alone in a loop take 2.3 ms on the Pi and 0.4 ms on the laptop (`tables/table_protocol_steps.csv`):
a Pi that is encoding and sending video at the same time computes them about three times slower, and that is the
number that matters in operation.

**Plot 3, bytes on the wire.** Full handshake 13.1 kB in 13 datagrams, of which the two ML-DSA-87 signatures are
9.3 kB and the ML-KEM-1024 key and ciphertext 3.1 kB; PQ ratchet 4.8 kB in 5 datagrams; cached rekey 324 B in 3.

**Plot 4, record encryption.** The Pi 4's processor has no AES instructions: AES-256-GCM seals 1.1 kB records at
360 Mbit/s there, ChaCha20-Poly1305 at 1,012 Mbit/s (2.8 times faster; 5 times at 64 kB). On the laptop, with AES
in hardware, the order is reversed (3.8 against 3.1 Gbit/s at 1.1 kB). The whole record layer (header, lock, replay
window, AEAD) seals a video record in 32 µs on the Pi with AES-256-GCM, 16 µs with ChaCha20-Poly1305
(`tables/plot04_record_layer.csv`).

**Plot 5, thirteen minutes of operation.** 23,485 frames, 10 lost (0.04 %), frame rate steady at 30. In that time
the link changed its keys 27 times: 7 cached rekeys (every 120 s), 1 PQ ratchet (in the same second as a cached
rekey) and 19 epoch-key rotations (every 30 s between rekeys). The ten lost frames are single frames at ten
different times; none coincides with a key change (the nearest: one frame about a second before the rekey at
766 s). The
Pi's processor load was 8.6 % (median, all four cores = 100 %), its temperature 52 to 57.5 °C, never throttled;
the Wi-Fi signal at the Pi −61 dBm (median). 8 of 915 pings took more than 40 ms (the slowest 124 ms). From 420 s
to 540 s the Pi also wrote the stream to its SD card as an encrypted, signed recording (3,609 frames, 45.2 MB).

**Plot 6, packet loss.** Datagrams were dropped at random on the Pi, in both directions, at six rates; the rule's
own counters give the rate actually applied on the uplink: 0.55, 1.01, 2.07, 4.76, 10.4 and 19.9 % of about 15,000
datagrams per level.

* *(a) Live video* is sent without retransmission, and a frame is usable only if every one of its datagrams
  arrives (11.9 on average). The share of frames received complete follows that: 93.6 % at 0.55 % loss, 88.6 % at
  1 %, 59.5 % at 4.8 %, 13.3 % at 20 %; the grey curve is that model, computed from the recorded frame sizes. What
  the operator sees falls much faster, because after a lost frame the receiver shows nothing until the next
  keyframe, and a keyframe comes once a second: 35 % of the frames are shown at 0.55 % loss, 20 % at 1 %, 3 % at
  2 %, practically none from 5 % on. **This is the weakest point of the present system: under loss the link stays
  up and secure, the live picture does not stay usable.** Remedies that are not implemented: asking the UAV for a
  keyframe as soon as a frame is lost, forward error correction, a shorter keyframe interval (the first two are
  simulated in plot 16).
* *(b) Session operations* kept working. Of 196 operations that ran on the UAV, 193 completed; the three that timed
  out (one full handshake, two cached rekeys) were all at 20 % loss. Up to 5 % loss the medians do not move (full
  handshake 20 to 24 ms). A full handshake needs all 13 of its datagrams, so at 10 % loss its median includes one
  repetition of the ClientHello (1.2 s) and at 20 % two (2.4 s). The cached rekey, 3 datagrams, keeps a median of
  8 to 9 ms up to 10 % loss. The link never went down and no record failed authentication. (Ten operations of each
  kind were requested per level, 210 in all. A request from the ground station is a single message that is not
  repeated: 27 of the 210 were not acknowledged, 1 at 1 %, 2 at 2 %, 4 at 5 %, 6 at 10 % and 14 at 20 % loss.)
* *(c) A photo* of 0.2 MB, sent with selective retransmission, arrived intact every time (21 transfers, SHA-256
  verified): in 0.1 s without loss, 0.35 to 0.45 s at 1 to 5 %, 1.0 s at 10 % and 1.3 s at 20 % (medians).
* Telemetry, one small message per second, arrived 39 to 42 times in each 41 s window up to 5 % loss, 32 times at
  10 % and 21 times at 20 % (`tables/plot06_loss_video.csv`).

The Linux kernel reports a datagram dropped by the rule to the sending program as an error; the UAV counts it and
carries on exactly as for a datagram lost in the air (it never sends a record twice).

**Plot 7, latency.** An ICMP echo over the link has a median round trip of 7.7 ms. A control message through the
secure link, sent by the UAV on its own timer, comes back after 8.2 ms (95 % within 15.5 ms, 600 probes, none
lost). The same message sent right after a command from the ground station arrived comes back after 6.6 ms: the
Pi's radio is awake and the ground station's thread is running. Session operations are started by a command, so
the third curve is the one that describes them (and the one the simulation is calibrated with). A video frame
takes 91 ms from the sensor to the decoded picture at the median: 69 ms camera and hardware encoder, 2 ms sealing
and sending its 12 records, 4 ms radio, 16 ms decoder at the ground station. The ground station's own estimate
from both clocks is 95 ms.

*What the latency budget is made of.* Panel (b) comes from a run of its own (`data/latency.json`: two minutes of
live video, 240 samples, 3,592 frames, none lost; 4 October, 23:05; GENERAL detector and finder running), made
after the ground station's decoder was changed. Until then the decoder held every frame until the next one arrived
(33 ms at 30 frames a second), and in the 13-minute run of plot 5 the ground station paired each picture with the
capture time of the frame after it: that run reported 17 ms for the decoder, while the picture appeared one frame
period later than that (round 5 had measured 50 ms). An earlier version of this plot showed the 17 ms. The decoder
no longer holds frames (`../docs/TEST_REPORT.md` §15.5 no. 9); 16 ms is what it takes now, beside a detector and a
finder that use most of the laptop's cores (8 ms with both paused). The radio's share is half the ICMP round trip
of panel (a).

**Plot 8, protecting pictures and video.** The present file format wraps the file key with ML-KEM-1024 **and**
X25519 and signs the file with ML-DSA-87. On the Pi that costs about 2 ms per file plus about 6 ms per megabyte
(the hash the signature is made over): a 200 kB photo is sealed in 8.1 ms instead of 5.3 ms, a 3 MB one in 92 ms
instead of 71 ms. The laptop opens them, signature check first, in 0.5 ms and 4.9 ms. A file grows by 6,761 bytes
(signature 4,637, ML-KEM ciphertext 1,568), which is 3.4 % of a 200 kB photo. Live video: 356 records a second,
each sealed and sent by the Pi in 155 µs, 5.5 % of one of its four cores; the record layer adds 4.6 % to the
video's bytes and the UDP/IP headers another 2.7 %. **The post-quantum algorithms establish, wrap and sign;
AES-256-GCM encrypts the pixels** (`../paper_figures`, figure 11).

**Plot 9, statistics of the ciphertext.** The uncompressed pixels of a 768 × 768 picture were sealed as a stored
photo. Entropy rises from 6.77 to 7.9997 bits per byte, the correlation between neighbouring pixels falls from
0.91 to 0.95 to 0.000, the histogram is flat (χ² 261, where 293 is exceeded by chance in 5 % of cases). Two
sealings of the same picture differ in 99.61 % of their bytes (NPCR) with a mean difference of 33.45 % (UACI),
which is what two unrelated random byte strings give (99.61 %, 33.46 %). 200 of 200 files with one bit changed were
refused, and a key wrong in one bit is refused by the tag. **These statistics say that the ciphertext looks random.
Every sound cipher achieves that; they are a sanity check and not evidence of security**, which rests on
AES-256-GCM and on never repeating a nonce (`../docs/CRYPTANALYSIS_REPORT.txt` §5).

**Plot 10, attacks.** 339,084 forged, modified, replayed, spliced, downgraded or misplaced inputs were offered to
the implementation on the two machines in 24 kinds of attack; none was accepted. In a stress test of the sender,
192,000 records were sealed by eight racing threads without a nonce used twice. Under a flood of forged
ClientHellos a genuine UAV still connects: with the ground station on the laptop in 5 to 7 ms up to 3,000 forged
hellos per second and in 2.4 s at 10,324 per second; with a Raspberry Pi 4B in the role of the ground station in
10 to 29 ms up to 300 per second, and in 1 to 10 s (median) between 1,000 and 4,860 per second. Every connection
was made at every rate. The time of a refusal does not depend on where the tag or the MAC is wrong (largest |*t*|
2.7 in five rounds on each machine; the threshold is 4.5), while the same test finds a comparison that stops at
the first wrong byte in every round (|*t*| 116 to 1,706). What each attack is, why it fails and what an attacker
can still do: `../docs/CRYPTANALYSIS_REPORT.txt`.

## The plots about sealed audio (measured)

The scheme, the attacks and the limits are in `../docs/AUDIO_CRYPTANALYSIS_REPORT.txt`; the diagrams are figures 15 to
17 of `../paper_figures`.

| File | Width | Suggested caption |
|---|---|---|
| `plot17_audio_statistics` | 190 mm | A sound before and after sealing: (a, d) the samples, (b, e) their spectrogram, (c, f) their histogram, and the usual statistics. 37.5 s of 16-bit samples, sealed uncompressed for this figure; the system seals the encoder's frames. |
| `plot18_audio_shape` | 190 mm | What sizes give away. (a) The frames of a variable-bit-rate encoding, as encryption frame by frame would show them. (b) The sealed blocks of the same audio. (c) The number of blocks a clip is stored with against the number it needs. (d) Bytes added by sealing against the length of the clip. |
| `plot19_audio_cost` | 190 mm | Cost of sealed audio on the Raspberry Pi 4B and on the ground station: (a) sealing a clip, (b) verifying and opening it, against its length; (c) size of an excerpt of a 10-minute clip against the length of the excerpt, with the number of keys released. |
| `plot20_audio_attacks` | 190 mm | (a) Attack attempts on sealed clips, live blocks and excerpts on both machines; none was accepted. (b) A clip sent while it is sealed, with datagrams dropped on the Raspberry Pi: share of its blocks that arrived on the air, for blocks of seven datagrams and of one; grey: the share expected if datagrams are lost independently. (c) Share of the audio a listener heard as it came in; every clip was completed from the UAV's card and verified. |

### What the measurements say

**Plot 17, statistics.** Entropy rises from 6.83 to 7.9999 bits per byte; the correlation between neighbouring
samples falls from 0.985 to -0.0015; the byte histogram is flat (χ² 284, where 293 is exceeded by chance in 5 % of
cases); the spectrum is that of white noise (flatness 0.561, white noise 0.56; the sound 0.003). Two sealings of the
same sound differ in 99.61 % of their bytes with a mean difference of 33.48 %, as two unrelated random byte strings
do (99.61 %, 33.46 %). Opening gives back every byte. A key wrong in one bit is refused; with the checks removed it
gives noise. **As for plot 9: these numbers say that the ciphertext looks random, which every sound cipher achieves;
they are a sanity check and not evidence of security.** They are shown because the published audio-encryption
schemes report little else (`../docs/AUDIO_CRYPTANALYSIS_REPORT.txt` §1 and §6).

**Plot 18, shape.** The sample encoded at a variable bit rate has 1,436 frames of 7 different sizes (104 to 522
bytes), and the size changes 756 times: encryption that keeps frame boundaries keeps all of that. Sealed, it is 192
blocks of one size (4,252 bytes), one every 209 ms. The number of blocks is rounded up: of the 2,584 different
lengths a clip of 1 to 10 minutes can have, 53 remain, for 2.3 % of padding on average. The price: a clip at a
constant 128 kbit/s grows by 93 % if it lasts 1 s (the head and the signature weigh 6.7 kB), by 9.0 % for a minute
and by 3.4 % for 15 minutes; the sample as it is (256 kbit/s, constant) by 8.8 %; the same sample at a variable bit
rate by 195 %, because every frame is padded to the largest. **Uniform shape is cheap at a constant bit rate and
expensive at a variable one.** (`tables/plot18_*.csv`; three recordings of the same length, silence, speech and
music, sealed to the same size, block size and block count: `tables/plot18_three_recordings.csv`.)

**Plot 19, cost.** The Pi seals one minute of 128 kbit/s audio in 89 ms and 15 minutes in 1.25 s, about 700 times
faster than it is spoken (10.8 MB/s); the key wrap (0.65 ms) and the signature (0.76 ms) are paid once per clip. The
laptop verifies and opens a minute in 12.6 ms. An excerpt of one second of a 10-minute clip is a bundle of 31.7 kB
(0.3 % of the clip) that carries at most 5 of the clip's 2,944 block keys; five minutes are 49 % of the clip and at
most 16 keys. Besides its blocks an excerpt carries about 7.8 kB whatever its length (head, signature, proof, keys),
and is verified with the UAV's public key in 0.6 ms (one second) to 46 ms (five minutes) on the laptop
(`tables/plot19_*.csv`, also for 1 to 32 frames a block and for 64 to 320 kbit/s).

**Plot 20, attacks and loss.** 12,646 changed, re-ordered, borrowed, forged, re-signed or mislabelled clips, live
blocks and excerpts in 46 kinds of experiment (21 rows in the figure) on the two machines: none accepted, and no
exception other than the refusal the code promises. Among them 5,124 attempts to open other blocks of a clip with
the keys released for an excerpt. On the real link a clip of 37.5 s was sent while it was sealed, twelve times, with
nominally 0 to 20 % of the datagrams dropped (the x-axis shows what the rule's counters report). With 8 frames a
block (7 datagrams at this bit rate) 90 % of the blocks arrived on the air at 1 % loss, 74 % at 5 %, 50 % at 10 % and
22 % at 20 %; with 1 frame a block (1 datagram) 99 %, 95 %, 89 % and 81 %: the measured points lie on the curve for
independent losses. All twelve clips were completed from the
UAV's card (892 blocks fetched again) and verified against the signed root, byte for byte the source; in two of them
the request for the missing blocks had to be made twice. (In an earlier run of this experiment, before that request
was repeated, 2 of 12 clips stayed incomplete: `../docs/TEST_REPORT.md` §16.5.)

### Tables that are not plots

| File | Content |
|---|---|
| `table_pi_resources.csv` | Processor load, memory and temperature of the Pi: idle, live video, live video and recording |
| `table_transfers.csv` | Reliable transfer over the link: a 7.4 MB recording fetched five times (16.4 to 16.6 Mbit/s, SHA-256 and signature verified, decrypted) and ten photos |
| `table_at_rest.csv` | Encryption at rest on both machines: recording segments, SHA-256, photos of four sizes in both file formats |
| `table_protocol_steps.csv` | Each step of the three session operations run alone in one process, on both machines |
| `table_algorithm_variants.csv` | ML-KEM-512/768/1024, ML-DSA-44/65/87, X25519 and Ed25519 on both machines (input of the ablation in plot 15) |
| `table_environment.csv` | Hardware and software of the two machines, and the measured clock rate |
| `plot10_flood.csv` | Every level of the flood experiment on both machines |
| `plot09_npcr_uaci.csv` | NPCR and UACI of every pair compared |
| `table_rekey_schedule.csv`, `table_operation_costs.csv` | What the implemented key-refresh schedule costs per hour, against full handshakes or ratchets at the same instants (measured values only) |

## The motion watch, and what is proved (plots 21 and 22)

| File | Width | Suggested caption |
|---|---|---|
| `plot21_motion_watch` | 190 mm | The motion watch of the UAV node. Share of the looks in which a moving target is found, against (a) its contrast, (b) its size, (c) its speed, and (d) while the camera itself moves. Grey: generated scenes, with the noise of a bright and of a dim picture. Colour: the UAV's own camera, the target drawn into its pictures on the UAV. (e) Regions reported when nothing was meant to move. (f) What the watch costs the UAV, switched off and on in turns. |
| `plot22_proof_matrix` | 190 mm | (a) What ProVerif proves about each protocol, attacker by attacker. A dot: the claim holds for any number of sessions. A cross: the same claim with the decisive scheme broken or the decisive key leaked, where an attack must exist, and is found. (b) The libraries in use against NIST's known-answer vectors (FIPS 203, FIPS 204) and the RFCs' vectors, on both machines. |

### What plot 21 says

Generated scenes: 10 scenes a case, 320 looks, picture 320 × 180, 8 looks a second (`data/motion_synthetic.json`).
The camera: three captures of 44 looks in each mode, all used, in a lit room (472 lux) with people in it
(`data/motion_camera_{normal,night}.json`). Tables: `tables/plot21_motion_watch.csv`, `plot21_motion_cost.csv`.

**Not in the plot, and to be said with it:** the camera points are from a lit room. The same evening, with a lamp
only (89 lux) and a part of the scene changing its brightness ten times a second, the watch reported nothing: the
drawn target was found in 0 of 26 looks (`docs/TEST_REPORT.md` §17.4). That case was met by the pipeline test, not
by the campaign behind this plot, and is not repaired.

* **How faint, how small, how slow.** In the noise of a bright picture a moving target of 8 pixels is found in 88 %
  of the looks at a contrast of 6 grey levels (of 255) and in every look from 8 on; in the noise of a dim picture at
  high gain, in 31 % at 12 and in every look from 16 on. At a contrast of 25 it is found from 3 pixels of width on
  in day noise and from 6 in night noise (4 pixels: 95 %), and at any speed from 0.2 to 6 pixels a look (0.1: 62 %;
  10: 68 %). The camera's points lie on or above the day curve: 91 and 94 of 102 looks at a contrast of 4, all 102
  from 6 on.
* **While the camera moves** (generated scenes): the target is found in every look up to a pan of 2 pixels a look,
  in 95 % at 4, 67 % at 8 and 42 % at 12; a turn of 0.3° a look as well costs a few points. On the camera, imitated
  pans of 1, 2 and 3 pixels a look are measured as 0.99, 1.97 and 2.98.
* **When nothing moves** (generated scenes): 1 region in 3,200 looks at medium sensitivity, 10 at high, the worst
  case being a pan with a zoom. In front of the real camera "nothing moves" could not be arranged: with nothing
  drawn in, 13 and 18 regions in 102 looks, in a room with people in it. That number is not a false-alarm rate.
* **Cost:** 2.7 points of the Pi's four cores (9.1 % to 11.8 %), 31 ms a look, no video frame lost (0 of 7,303),
  and session operations that get quicker, because the governor raises the processor's clock from 0.8 to 1.8 GHz.

Two faults of the watch were found by the first version of this plot and are gone in this one (a curve that went
down as the contrast went up; a pan in the dark that was not measured): `../docs/TEST_REPORT.md` §17.5. What the
watch still cannot do is in §17.8 there.

**Plot 22** has no measurement in it. Panel (a) is `../formal/results.json`, written by `../formal/run.py`: 46 runs
of five models under four attackers, 177 queries, each compared with the outcome expected of it (100 claims proved;
77 that must be false are false: 45 "can this state be reached at all" checks and 32 with the decisive scheme broken
or key leaked). The matrix groups them into 16 claims. Three things in it are worth a sentence in the paper:

* The session and a stored file stay secret with **either** X25519 **or** ML-KEM broken, and fall only with both:
  the hybrid is a hybrid. A stolen ML-KEM recording key is harmless unless X25519 is broken too, and the other way
  round.
* The 1-RTT Cached RapidRekey does **not** heal: if the secret it starts from had leaked, the new keys are known
  (a cross in every column). The PQ ratchet does, against an attacker who only listens; against one who is active
  during the ratchet it does not (the cross in the last PQ ratchet row). Both are properties of the design, stated
  in `../docs/SECURITY_ARCHITECTURE.md`, and now shown.
* The UAV's assurance that it talks to the ground station holds in every column: it rests on the ground station's
  ML-DSA-87 signature over the whole transcript, and none of the four attackers breaks ML-DSA-87. The ground
  station's assurance about the UAV is stronger than "a signature was seen": it is agreement on the session **and
  its key**, and so it falls, like secrecy, when both key exchanges are broken (the attacker then knows the key and
  can finish a handshake that the UAV began). A break of ML-DSA-87 itself is not modelled; see
  `../docs/SECURITY_PROOFS.md` §12 for what it would mean.

Panel (b) is `data/pq_conformance_{pi,laptop}.json` (`kyber6g.tools.pq_conformance`): 162 of 162 vectors on each
machine. The model is symbolic (ideal primitives, no timing, no sizes); the computational arguments for the
components are in `../docs/SECURITY_PROOFS.md`.

## The simulated plots

Made by `../simulation/analyze.py` from `../simulation/results/` (1,830 runs of the ns-3 simulator; model,
calibration, studies and limits: [`../simulation/README.md`](../simulation/README.md)). **Everything in plots 12 to
16 is simulated; plot 11 shows measured and simulated values side by side.** The 5G NR cell is a model: the
prototype has only ever run over Wi-Fi.

| File | Width | Suggested caption |
|---|---|---|
| `plot11_sim_validation` | 190 mm | Check of the simulation against the measurements. (a) Time to a new session without loss: measured (colour) and simulated (thin black line). (b) Live video under packet loss: share of frames received complete and given to the decoder. (c) to (e) Every session operation measured under loss (markers) on the simulated median and 5th to 95th percentile band. |
| `plot12_sim_swarm` | 190 mm | Simulated 5G NR cell (3.5 GHz, 100 MHz) with 1 to 64 UAVs, each streaming 3 Mbit/s video. Time to a new session in (a) an uplink-heavy and (b) a downlink-heavy cell (marker: median, bar: 5th to 95th percentile), and (c) the share of the frames sent that reach the decoder. Shaded: the UAVs offer more video than the uplink carries. |
| `plot13_sim_storm` | 190 mm | Simulated: all UAVs of the cell start their first handshake at the same instant. (a) Time until every UAV has its session, with one answering thread at the ground station (as implemented) and with four (design study). (b) When each of 64 UAVs gets its session. |
| `plot14_sim_mobility_range` | 190 mm | Simulated: 8 UAVs in the NR cell. (a) Full handshakes per UAV and minute caused by changes of the position cell, against speed; (b) their duration; (c) the three session operations against the distance from the mast, with the modulation and coding index the uplink falls back to. |
| `plot15_ablation_crypto` | 190 mm | Ablation of the cryptographic configuration. (a) Bytes of a full handshake. (b) Computing per handshake from the measured primitives. (c) Simulated: full handshake over the Wi-Fi test-bed link without loss and at 2 % and 5 % loss (marker: median, bar: 5th to 95th percentile). (d) Simulated: in the NR cell, and the time until 64 UAVs that start together all have a session. |
| `plot16_ablation_design` | 190 mm | Ablation of the protocol's design choices, simulated on the test-bed link under loss. (a) Combining the fragments of repeated handshake messages. (b) Fragment size. (c) Fixed repeat timers (as implemented) against a timer of three round trips. (d) Live video with a keyframe on request and one parity datagram per frame: both simulated, neither implemented. |

### What the simulations say (details and tables: `../simulation/README.md` §3 and §5)

**Plot 11, the check.** The simulated replica of the test bed gives 23.1 ms for the full handshake (measured
23.2), 9.1 ms for the cached rekey (measured 9.0) and 16.3 ms for the PQ ratchet (measured 14.1: **16 % too slow**,
cause not found; the figure shows it). Live video under loss is reproduced within 0.8 points for frames received
complete and 2.6 points for frames given to the decoder, at all six loss rates. Neither the duration of an
operation nor anything measured under loss went into the calibration. Panels (c) to (e) show that the replica has
the repeats in the right places (1.2 s, 2.4 s … for the handshake); they do not confirm it to the millisecond: 89 of
the 163 operations measured under loss lie inside the simulated 5th-to-95th-percentile band, where nine in ten
would if the replica were exact (ten operations per loss rate, measured two hours before the calibration).

**Plot 12, swarm size.** In the uplink-heavy cell the full handshake stays at 23 to 30 ms (median) up to 64
UAVs and at least 99.7 % of the frames reach the decoder. The downlink-heavy cell carries 32 UAVs; with 48 the
video exceeds the uplink (77 % of the datagrams delivered, 5 % of the frames usable, operations 0.5 to 1 s). The
session protocol is not what limits the swarm.

**Plot 13, storm.** 64 UAVs that start their handshake together all have a session after 156 ms; the ground
station's single answering thread is the queue. Four threads would halve it.

**Plot 14, movement and range.** A UAV at 30 m/s makes 15 full handshakes a minute (one per position cell), each
in 26 ms, made in place: no frame is lost and the handshakes are 0.4 % of the uplink traffic. From 250 m to 4 km
the operations take the same time; the radio falls back from index 28 to 19 and repeats 5 % of its blocks at 4 km.

**Plot 15, what the post-quantum suite costs.** Against a classical X25519/Ed25519 handshake the implemented suite
costs 10 ms per handshake over Wi-Fi (23.1 against 12.9 ms) and 27 times the bytes (13.1 kB against 0.5 kB). The
X25519 half of the hybrid costs 1.2 ms; ML-KEM-512/ML-DSA-44 would save 4 ms. Under loss the number of datagrams
decides: the classical handshake (3 datagrams) rarely needs a repeat, the post-quantum ones (7 to 13) do in more
than one case in twenty at 2 % loss.

**Plot 16, design choices.** Combining the fragments of repeats keeps 83 % of the handshakes completing at 20 %
loss (29 % without). The implemented 1,180-byte fragment needs 12 datagrams; 400-byte fragments would need 32 and
get only half the handshakes through without a repeat at 2 % loss. (c) With the implementation's fixed repeat
timers a lost datagram costs 1.2 s (handshake), 0.7 s (cached rekey) or 0.35 s and more (ratchet): 95 % of the full
handshakes are done within 1.2 s at 1 % loss. A timer of three round trips, never longer than the fixed one
(simulated, not implemented), would make that 61 ms, and 208 ms at 20 % loss, without sending more datagrams and
without completing more operations. For the live video (simulated,
not implemented) a keyframe on request and one parity datagram per frame would raise the usable frames at 2 % loss
from 6 % to 80 %.

## How it was measured

| | |
|---|---|
| UAV node | Raspberry Pi 4 Model B Rev 1.5 (4 × Cortex-A72, 1.8 GHz, governor `ondemand`), Debian 13, kernel 6.18.34, Python 3.13.5, Waveshare RPi Camera (F) (OV5647), application running as the confined service `kyber6g-uav` |
| Ground station | Laptop with AMD Ryzen 5 5625U, WSL2 Ubuntu 22.04, Python 3.10.12, detector and finder running (GENERAL profile; paused only while the laptop's own crypto benchmark ran) |
| Libraries | liboqs 0.16.0, cryptography 50.0.1 (OpenSSL 4.0.2) on both |
| Link | UDP over Wi-Fi (IEEE 802.11, 5 GHz band) through one access point, indoors; signal at the Pi about −61 dBm; suite ML-KEM-1024 + X25519 + ML-DSA-87, HKDF-SHA256, AES-256-GCM |
| Video | 1280 × 720, 30 frames/s, H.264 at 3 Mbit/s from the Pi's hardware encoder; the room was dark (2 to 4 lux), the scene static |
| When | 4 October 2026: 14:33 to 15:13 (plots 1, 3 to 6, 8), 16:26 to 16:33 (plots 9, 10), 17:02 to 17:14 (plots 2 and 7a, repeated after the last change to the link code), 23:05 to 23:07 (plot 7b, measured again after the ground station's decoder was changed); 5 October 2026, 04:34 to 04:45 (plots 17 to 20, on the final code) |
| Tools | `kyber6g/tools/bench_crypto.py` (plots 1, 3, 4, 8), `bench_link.py` (plots 2, 5, 6, 7, 8), `attack_bench.py` (plot 10), `media_stats.py` (plot 9), `audio_bench.py` (plots 17 to 20), run by `run/measure.sh` |
| Audio | The sample the operator supplied (`audio encryption/audio_sample1_test.mp3`: 37.5 s, MPEG-1 layer III, 256 kbit/s, 44.1 kHz stereo). For plot 17 it was decoded to mono PCM, for plot 18 encoded again at a variable bit rate (libmp3lame `-q:a 5`), both with ffmpeg on the laptop; for plot 20 it was copied into the Pi's inbox and sealed there. Plots 19 and 20a use synthetic MPEG frames of pseudo-random content. Live video was off during the loss runs |

**Which clock.** The clock of the laptop's WSL virtual machine does not run at a steady rate (measured during these
runs: 0.999 to 1.019 of the Pi's; on other days 8 % slow). Therefore:

* every handshake, rekey, ratchet and round-trip time is timed **on the Pi** (clock disciplined by NTP) and only
  fetched from it;
* the laptop's own timings (its side of plots 1, 4 and 8, the ground station's share in plot 2, the decoder time in
  plot 7, transfer times) are divided by the clock rate that the same file records, measured against the Pi's clock
  during the run; the raw values stay in the files with the suffix `_raw`;
* frame rates come from the camera's time stamps.

**Packet loss** is injected with nftables on the Pi for UDP port 14600 in both directions. The loss on the x-axis
of plot 6 is the one the rule's own counters report (datagrams dropped / datagrams seen), not the nominal setting.

**The attack experiments** run both ends of the link on one machine (once on the Pi, once on the laptop) and call
the implementation with the attacker's input; the flood generator is a process of its own on the same machine.

## What these plots do not show

* **No 5G or 6G radio and no flight in anything measured.** The prototype ran over Wi-Fi on a desk. Plots 12 to 16
  contain a simulated NR cell; they are a model.
* **One UAV in everything measured.** More than one exists in the simulation only.
* **No microphone.** The audio of plots 17 to 20 is a file; capture from a sound card and a live encoder were not
  tested. Where the sample comes from and under what licence it may be reproduced has to be settled before its
  waveform or spectrogram (plot 17) is printed.
* **No energy figures.** No power meter was available; the earlier energy numbers came from a model and were removed.
* **No end-to-end "glass to glass" latency.** Plot 7b sums parts measured on each side and compares the sum with an
  estimate that needs both clocks; a measurement with one clock (a camera filming a running clock) was not done.
* **No detector plot.** The object detector's accuracy is reported in `docs/TEST_REPORT.md` (section 13.6); it is
  not part of the link evaluation.
* ML-KEM-1024 and ML-DSA-87 establish and authenticate the session and wrap and sign stored files; the data is
  encrypted with AES-256-GCM (or ChaCha20-Poly1305). The plots measure exactly that split.

## Rebuilding

```bash
bash run/kyber6g.sh measure          # the whole campaign on the hardware, about 70 minutes (phases can be chosen: see run/measure.sh)
bash run/kyber6g.sh measure attacks  # only the attack experiments on the Pi and on the laptop, and the picture statistics
bash run/kyber6g.sh measure audio    # only the experiments on sealed audio (about 15 min): plots 17 to 20
bash run/kyber6g.sh measure motion   # only the motion watch (about 40 min, half of it without the hardware): plot 21
bash run/kyber6g.sh measure pq       # known-answer tests on both machines, the ProVerif models, the bill of materials: plot 22
bash run/kyber6g.sh formal           # only the ProVerif models (about 30 s; needs ProVerif 2.05)
bash run/kyber6g.sh report           # docs/CRYPTANALYSIS_REPORT.txt and docs/AUDIO_CRYPTANALYSIS_REPORT.txt from the experiments
bash run/kyber6g.sh simulate         # calibrate, build and run the simulation studies (hours), then draw plots 11 to 16
bash run/kyber6g.sh plots            # draw all plots from the data that is there and check them (checks/build_report.md)
```

`build.py` stops with an error if a plot is not 90.0 or 190.0 mm wide, if a font is not embedded or not Arial, if
text is smaller than 6.5 pt, if a title, label, legend or note reaches beyond the edge of the figure or lies on top
of another text, or if two series of the palette cannot be told apart (with any of the three kinds of
colour-blindness, or with full colour vision) or do not stand out of the page.

## Style

The look is the house style of [figures4papers](https://github.com/ChenLiu-1996/figures4papers) (the plotting
scripts of several published papers and the design notes drawn from them), set in one place, `scripts/plotlib.py`:

* **Type:** Arial, that repository's portable stand-in for Helvetica. Its figures are drawn large and scaled down
  by the journal (axis labels of 28 pt on a 24 inch canvas); here the same proportions are set at the final size:
  8 pt axis labels and panel titles (titles bold), 7 pt ticks, legends and notes, nothing under 6.5 pt.
* **Axes:** black, 1 pt, without the top and right spines; no grid; legends without a frame.
* **Colour:** its palette (`plotlib.PALETTE`): blue `#0F4D92` for the thing the paper is about, red `#B64342` for
  what it is compared with, teal `#42949E` and violet `#9A4D8E` for a third and a fourth series, greens for gains,
  greys (`#CFCECE`, `#767676`, `#272727`) for context. A thing keeps its colour across plots: full handshake blue,
  cached rekey red, PQ ratchet teal; the Pi blue, the laptop red.
* **Bars:** square ends and a black outline, as in that repository's bar charts.
* Because a journal page may be printed in grey, every series also has its own marker and line style and every bar
  fill its own hatch (`checks/gray/` shows the grey versions). This is also what makes the palette's closest pair
  (teal and violet under deuteranopia) safe: `checks/palette.txt` has the validator's verdicts.
* No transparency (EPS has none), no second y-axis, text in black and never in a series colour.
* Where measured and simulated values share a panel (plots 11 and 21), the measurement is in colour and the
  simulation in grey.

Installed for this: nothing beyond what the diagrams already needed. Arial is taken from the Windows side of the
machine by `../paper_figures/scripts/setup_tools.sh` (Liberation Sans, which has the same widths, where there is
none); matplotlib is the ground station's. The repository itself was read, not installed: its scripts were the
model for `plotlib.py`, and none of its code is used here.

## The earlier plots

The plots of the earlier study (`simulation_results/plots/`, `hitl/plots/`, `ablation_study/plots/`, and
`final_publication_plots_2026/` in the parent folder) were removed on 2026-10-04: they showed the earlier prototype
and an analytical model, their "hardware versus simulation" comparison was true by construction (the simulated
values were the hardware values plus random numbers), and several assumed a 5G/6G radio that was never used. The
tracked ones remain in the git history; the untracked ones were moved to `_outdated_plots_2026-10-04/` beside the
repository. The plots of the first measurement campaign of the same day (seven plots, before the changes of the
second security pass) were replaced by the present ones.
