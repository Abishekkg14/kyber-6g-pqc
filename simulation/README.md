# Simulation of the Kyber-6G secure link

What the test bed cannot show - more than one UAV, a cellular radio, a moving UAV, a restarted ground station with a
whole swarm waiting - is simulated here. Everything in this folder is **simulation**; the measured results are in
`paper_plots/` (plots 1 to 10) and `docs/TEST_REPORT.md`.

```
simulation/
├── calibrate.py            measurements + implementation  ->  calibration/k6g_calibration.{txt,json}
├── ns3/k6g-swarm-sim.cc    the simulator (one ns-3 program; copied into ns-3-dev/scratch and built there)
├── ns3/patches/            two changes to the NR library (5G-LENA v3.3), applied by run_sweep.py
├── run_sweep.py            the studies: builds, runs every (study, parameters, seed) on all cores but two
├── analyze.py              results/raw  ->  paper_plots/exported_*/plot11..16, paper_plots/tables, results/summary.json
├── calibration/            the calibration the results were made with
└── results/                raw/ (one file per run), manifest.json, summary.json, rebuild_check.json
```

```bash
bash run/kyber6g.sh simulate            # calibrate, build, run every study, draw (about three hours on ten cores)
bash run/kyber6g.sh simulate list       # what would run
bash run/kyber6g.sh simulate swarm      # one study (validation swarm storm mobility range crypto design)
bash run/kyber6g.sh simulate analyze    # tables and figures again from the results that are there
```

## 1. What is simulated

The three session operations of the implemented protocol (`kyber6g/transport/link.py`) as the datagrams they are:

| | as implemented, and as simulated |
|---|---|
| Full handshake (1.5 round trips) | ClientHello 6,287 B in 6 fragments, ServerHello 6,311 B in 6, ClientFinished 40 B; repeated every 1.2 s, at most 5 times; the fragments of repeated transmissions combine (the message id is derived from the content); the ground station answers a repeated hello from its cache |
| 1-RTT Cached RapidRekey | request 96 B, answer 80 B, Finished 40 B; repeated every 0.7 s, at most 3 times |
| PQ ratchet | request 2,178 B and answer 2,204 B as control messages inside the session, 2 records each; repeated by the link manager (0.35 s × number sent, looked at every 0.1 s), at most 5 times, given up after 3 s |
| Change of position cell | a full handshake made in place when the UAV is 0.3 of a cell beyond its cell's edge (cell: 0.001°, 111 m) |
| Live video | 30 frames a second, keyframe every 30, frame sizes as recorded, 1,100 B per record; a frame is usable if all its records arrive within the 150 ms window, and after an unusable frame nothing is decoded until the next keyframe |
| Ground station | one thread receives: every datagram costs it the measured time, and a handshake answer is computed on that thread, so everything behind it waits |

None of these numbers is typed into the simulator. `calibrate.py` reads sizes, fragment size, timers and attempt
limits from the implementation itself (constants, and the source text of the functions that hold the timers) and
stops if it cannot find one; it also stops if the message sizes it computes differ from those measured.

**How long each side computes** is drawn from what was measured in the running system, not from a benchmark loop:
the UAV times the phases of each of its operations (building the request, working on the answer, installing the
new session) and the ground station its work on each request (corrected for its clock); the simulator draws from
the 150 samples of each phase recorded while the UAV streamed video. The difference matters: next to the video
encoder the Pi needs 2.8 times as long for the two cryptographic steps of a handshake as it does alone.

## 2. Two links

**Replica of the test bed** (`--link=testbed`). One UAV. A message of *k* datagrams takes, one way, half of what a
round trip of *k* datagrams each way was measured to take over the Wi-Fi link (*k* = 1 … 6, 150 probes each, with
the ground station's own time on the probe taken out); request and answer of one exchange use the same quantile,
so together they reproduce the measured distribution. The probes are started the way the measured operations were:
right after a command from the ground station has arrived. That is about 2 ms faster per round trip than a probe
sent on the UAV's own timer (6.5 against 8.3 to 9.0 ms for one datagram each way; the Pi's radio is awake, the
ground station's thread is running; plot 7), and a replica built on timer probes predicted the cached rekey and
the ratchet too slow. Each datagram is lost independently
with the set probability, in both directions, as in the measured loss experiment. This link exists to **check the
model**.

**5G NR cell** (`--link=nr`, ns-3.42 with 5G-LENA v3.3). One gNB (25 m mast, 4 × 8 antenna elements), N UAVs as UEs
(1 × 2 elements, 23 dBm) placed uniformly within 400 m at 60 to 120 m above ground, 3.5 GHz, 100 MHz, 30 kHz
subcarrier spacing, TDD. Two slot patterns: uplink-heavy `DL|S|UL|UL|UL` (6 of 10 slots uplink: a cell set up for
video from UAVs) and downlink-heavy `DL|DL|DL|S|UL|DL|DL|S|UL|UL` (3 of 10: the pattern of public networks). 3GPP
TR 38.901 urban-macro path loss, line of sight; HARQ; RLC in unacknowledged mode; proportional-fair scheduling, one
UAV at a time over the whole band (TDMA: the gNB forms one beam at a time). The ground station is a host behind the
core network, 1 ms away. The UAV's and the ground station's host processing of a message (0.60 ms: half the
difference between a round trip through the secure link and an ICMP round trip on the same path) is added, since
here the radio path is simulated and not measured.

**Video in the NR cell** is counted against what was sent: a frame the UAV sent and the ground station never
accounted for (it is still in the UAV's queue when the run ends, or was dropped from it) counts as not delivered,
except the last 200 ms of each run. In a cell that carries its load this is the receiver's own count; in an
overloaded one the receiver's count alone would call the little that arrives "nearly all".

## 3. The check (plot 11)

Calibration uses the computing phases and the round trips of plain messages. It does **not** use the duration of a
session operation as a whole, nor anything measured under packet loss. Those are what the replica is compared with
(260 runs: 3,000 simulated operations of each kind without loss, 400 at each loss rate; 40 runs of video at each
loss rate).

**Session operations without loss** (measured: 150 each, timed on the UAV):

| | Measured: median (95th pct.) | Simulated: median (95th pct.) | Median | Largest distance between the two distributions |
|---|---|---|---|---|
| Full handshake | 23.2 ms (30.8) | 23.1 ms (28.8) | −0.6 % | 0.13 |
| 1-RTT Cached RapidRekey | 9.0 ms (17.3) | 9.1 ms (13.8) | +0.2 % | 0.15 |
| PQ ratchet | 14.1 ms (22.0) | 16.3 ms (23.0) | **+15.9 %** | 0.48 |

The handshake and the cached rekey are reproduced at the median; the simulated distributions are narrower at the
top (the slowest measured operations contain stalls of the machines that independent draws do not reproduce). **The
PQ ratchet is predicted 2.2 ms too slow.** The model gives a message of two or three datagrams the delay of the
padded probes of that size (10.6 and 11.5 ms per round trip, so 11.0 ms for two datagrams up and three down), and
the ratchet's own exchange spends 9.1 ms on the link. Why a padded probe of two datagrams takes 4 ms longer than
one of one datagram, and the ratchet's messages do not, was not found. The model is therefore conservative for the
ratchet on the test-bed link. (In the NR cell the radio is simulated and
these probe delays are not used.)

**Live video under loss** (measured: about 1,230 frames per loss rate; simulated: mean of 40 runs):

| Datagrams lost | Frames complete: measured / simulated | Frames given to the decoder: measured / simulated |
|---|---|---|
| 0.55 % | 93.6 % / 93.8 % | 35.2 % / 36.8 % |
| 1.01 % | 88.6 % / 88.9 % | 19.6 % / 18.3 % |
| 2.07 % | 78.9 % / 79.0 % | 3.0 % / 5.6 % |
| 4.76 % | 59.5 % / 59.2 % | 0.6 % / 0.7 % |
| 10.4 % | 33.3 % / 33.3 % | 0 % / 0 % |
| 19.9 % | 13.3 % / 12.5 % | 0 % / 0 % |

Nothing of this was used to build the model: frame sizes, the 150 ms window and the rule "after an incomplete
frame nothing is decoded until the next keyframe" are the implementation's, and the loss is independent per
datagram.

**Session operations under loss** (plot 11c to e; measured: 10 operations of each kind per loss rate, 163 completed
in all). The simulation reproduces *when* an operation needs a repeat and what that costs (the steps at 1.2 s,
2.4 s … for the handshake, 0.7 s for the cached rekey, 0.35 s and more for the ratchet), and how often an operation
fails at 20 % loss. It does not confirm the replica to the millisecond: of the 163 measured operations, 89 lie
between the simulated 5th and 95th percentile for their loss rate (full handshake 34 of 55, cached rekey 37 of 53,
PQ ratchet 18 of 55), where nine in ten would if the replica were exact. Most of the others are operations that
needed no repeat and were faster than the replica's fastest twentieth: at 0.5 to 5 % loss the measured median is 20
to 23 ms for the full handshake (replica: 23 to 27 ms) and 12 to 13 ms for the ratchet (replica: 16 to 17 ms; it is
2.2 ms slow without loss already). The measurement has ten operations per loss rate and was made two hours before
the round trips the replica is calibrated with.

## 4. The studies

| Study | What varies | Runs | Figure |
|---|---|---|---|
| validation | loss 0 and the six measured loss rates, test-bed link | 260 | 11 |
| swarm | 1 to 64 UAVs, each streaming video; both TDD patterns | 200 | 12 |
| storm | 4 to 64 UAVs start their first handshake at the same instant; 1 or 4 answering threads | 100 | 13 |
| mobility | 8 UAVs at 0 to 30 m/s: handshakes after a change of position cell | 50 | 14 |
| range | 8 UAVs at 0.25 to 4 km from the mast | 30 | 14 |
| crypto (ablation) | classical only, ML-KEM-512/768 hybrids, ML-KEM-1024 alone, the implemented suite; both links, loss, storm | 250 | 15 |
| design (ablation) | combining fragments of repeats, fragment size, repeat timers; video with keyframe request and parity | 940 | 16 |

Every run is one process on one core with its own random streams (`RngRun`); runs are independent, so the sweep is
parallel by running as many at a time as there are cores to spare (and as fit into memory: a 64-UAV cell takes
0.4 GB). The 1,830 runs of 4 October 2026 took 3 h 5 min on ten of the laptop's twelve logical cores (30 hours of
processor time, 19 of them in the swarm study: a 64-UAV cell with video takes 35 to 55 minutes for 14 simulated
seconds). No run failed; the library was built with its assertions enabled and none fired. In the 480 NR runs, with
9,160 simulated UAVs, every UAV got its session and none fell silent.

**How far a run can be repeated.** A test-bed run is fixed by its arguments and its seed: made again with a rebuilt
simulator, 11 of 11 sampled runs were byte for byte the sweep's. An NR run is fixed by its arguments, its seed **and
the program**: one program gives the same result every time (two configurations run twice each, with and without
address-space randomisation; one with fresh memory filled with five different bytes: all identical), but another
build of the same source gives a result that differs in its last digits (the sweep's own source, built in the
cleaned ns-3 tree, did not give the sweep's bytes either; other settings of the memory allocator change the result
too). So something inside ns-3 or the NR library depends on the layout of the program's memory; the simulator's own
code keeps nothing ordered by address, and the place was not found. What it does to the reported numbers was
measured: two whole studies (range and storm, 130 runs) were made again with the rebuilt program. 57 runs were byte
for byte the sweep's; a single run differed by up to 5.5 % in its result; **the medians the paper reports moved by
0.9 % at most** (time until 64 UAVs have their session: 155.7 ms in the sweep, 156.4 ms rebuilt; full handshake at
3 km: 23.4 and 23.2 ms): `results/rebuild_check.json`. The NR results are therefore reproducible as statistics, to
about one per cent, and bit for bit only with the program that made them. All NR results in this folder are the
sweep's.

**The ablation of the cryptographic configuration** changes message sizes (from the algorithms' key, ciphertext and
signature sizes) and computing times: the measured time of the real step, with the measured times of this
configuration's primitives put in place of those of the implemented one (`bench_crypto`, group "variants", on both
machines). The alternatives were not implemented in the link.

**Two additions to the video path are simulated but not implemented**: a keyframe on request, and one parity
datagram per frame. They are in plot 16 as what would help, not as what the system does.

## 5. Results

Every number below is simulated (except 5.6, which is computed from measurements). The tables behind each figure
are in `paper_plots/tables/plotNN_*.csv`, the headline numbers in `results/summary.json`.

### 5.1 Swarm size (plot 12)

In the **uplink-heavy cell** the three operations take what they take for a single UAV up to 32 UAVs (medians: full
handshake 23 to 24 ms, cached rekey 13 ms, PQ ratchet 18 ms) and grow slowly beyond: 25 / 14 / 19 ms at 48 UAVs
and 30 / 19 / 22 ms at 64, where the cell carries 208 Mbit/s of video. The 95th percentile rises to about 150 ms
at 64 UAVs: the datagrams of an operation wait behind video in the UAV's queue. Every planned operation completed
and 99.7 % or more of the frames sent reached the decoder.

In the **downlink-heavy cell** the same holds up to 32 UAVs (104 Mbit/s of video; full handshake 30 ms, 95 % within
171 ms). At 48 UAVs they offer 156 Mbit/s, more than three uplink slots in ten carry: 77 % of the datagrams are
delivered, 5 % of the frames reach the decoder, the operations take 0.5 to 1 s at the median (2 to 2.6 s at the 95th
percentile), and only half of the planned operations get their turn before the run ends. At 64 UAVs 58 % of the
datagrams are delivered and 3 % of the frames are usable.

**What limits the swarm is the uplink capacity for video, not the session protocol**: a full handshake is 13 kB,
the video of one UAV about 400 kB every second. The ground station's receive thread is busy 29 % of the time at 64 UAVs.

A single UAV in the cell needs 22.9 ms for a full handshake, 13.1 ms for a cached rekey and 17.7 ms for a ratchet
(uplink-heavy pattern). That the full handshake comes out like the one measured over Wi-Fi (23.2 ms) is a
coincidence of two different links: the NR cell's slot structure costs about as much as the Wi-Fi link's round
trips, while the cached rekey, three small messages, is slower in the cell (13 ms against 9 ms) because each of
them waits for an uplink or a downlink slot.

### 5.2 Movement and range (plot 14)

**Movement** (8 UAVs, 50 runs). At 5, 10, 20 and 30 m/s a UAV makes 2.2, 4.6, 9.5 and 14.6 full handshakes a
minute: a little under one per 111 m flown, because a cell is left only when the UAV is 0.3 of a cell beyond its
edge. Each takes 26 to 27 ms at the median (95 % within 30 ms); all 1,751 completed with their first transmission,
and no video frame was lost, because the handshake is made in place while the running session carries the traffic.
At 30 m/s these handshakes are 1.5 kB/s of uplink per UAV, 0.4 % of its traffic.

**Range** (8 UAVs on a ring, 30 runs). From 250 m to 4 km the operations take the same time (full handshake 23.2
to 23.7 ms at the median). The radio hides the distance: the modulation and coding index falls from 28 to 19, and
at 4 km 4.7 % of the transport blocks fail a decoding attempt and are repeated. The video notices first: 99.8 % of
the frames reach the decoder at 3 km, 98.8 % at 4 km. (Line of sight throughout; the path-loss model is given for
up to 4 km.)

### 5.3 A storm of first handshakes (plot 13)

All UAVs of the cell start their first handshake at the same instant, as after a restart of the ground station.
The ground station answers on one thread (as implemented), so the answers queue: every UAV has its session after
32 ms with 4 UAVs, 41 ms with 8, 54 ms with 16, 91 ms with 32 and **156 ms with 64** (median of ten runs; 141 to
172 ms). No ClientHello had to be repeated, and nothing was answered from the cache. With four answering threads
(a design study, not implemented) 64 UAVs are up after 77 ms; what remains is the radio, which admits the 64
ClientHellos over about 70 ms.

### 5.4 Ablation: the cryptographic configuration (plot 15)

What the implemented suite costs against other choices. Message sizes follow from the algorithms; computing times
are the measured steps with each configuration's measured primitives put in. Only the implemented suite exists in
the link; the others are simulated.

| Configuration | On the wire | Wi-Fi replica, no loss | 2 % loss | In the NR cell (8 UAVs) | 64 UAVs at once |
|---|---|---|---|---|---|
| X25519, Ed25519 (no post-quantum part) | 0.5 kB, 3 datagrams | 12.9 ms (95 %: 17.6) | 13.0 ms (95 %: 21) | 16.4 ms | 110 ms |
| ML-KEM-512 + X25519, ML-DSA-44 | 6.9 kB, 7 | 19.0 ms (24.9) | 19.2 ms (1,217) | 20.9 ms | 113 ms |
| ML-KEM-768 + X25519, ML-DSA-65 | 9.5 kB, 9 | 20.6 ms (26.5) | 21.3 ms (1,221) | 21.5 ms | 135 ms |
| ML-KEM-1024 alone, ML-DSA-87 | 13.0 kB, 13 | 21.9 ms (27.9) | 22.4 ms (1,223) | 22.2 ms | 137 ms |
| **ML-KEM-1024 + X25519, ML-DSA-87 (implemented)** | 13.1 kB, 13 | 23.1 ms (28.2) | 24.1 ms (1,225) | 23.2 ms | 156 ms |

(Medians of the full handshake; "64 UAVs at once": until all have their session.)

- **Post-quantum security at the highest level costs 10 ms per handshake** on the Wi-Fi link against a classical
  handshake (23.1 against 12.9 ms), 7 ms in the NR cell, and 27 times the bytes. A handshake happens once per
  session and at a change of position cell; the refreshes in between are cached rekeys.
- **The classical half of the hybrid costs 1.2 ms and 64 bytes** (implemented suite against ML-KEM-1024 alone):
  the price of not resting on one assumption.
- **The parameter set matters less than the signatures' size:** ML-KEM-512/ML-DSA-44 instead of
  ML-KEM-1024/ML-DSA-87 saves 4 ms and half the bytes.
- **Under loss the number of datagrams decides.** The classical handshake is three datagrams; at 2 % loss 95 % of
  them still finish within 21 ms. Every post-quantum variant is 7 to 13 datagrams, and at 2 % loss more than one in
  twenty needs a repeat, which the fixed timer makes 1.2 s. This, not the computing, is the practical cost of the
  large signatures; plot 16c shows what a shorter repeat timer would recover.

### 5.5 Ablation: the protocol's own design choices (plot 16)

On the test-bed link, with loss.

**Combining the fragments of repeated messages** (16a). A repeated ClientHello has the same message id (it is
derived from the content), so a fragment that arrived in the first transmission need not arrive again. With this,
98.8 % of the handshakes complete within the five attempts at 10 % loss and 83 % at 20 %; if every repeat stood
on its own it would be 81 % and 29 %. At up to 2 % loss it makes no difference.

**Fragment size** (16b). The larger the fragment, the fewer datagrams a handshake needs and the more handshakes get
through without a repeat: at 2 % loss 52 % with 400-byte fragments (32 datagrams), 63 % with 600 bytes, 80 % with
the implemented 1,180 bytes (12 datagrams) and 83 % with 1,400 bytes. The gain from 1,180 to 1,400 is small, and
a 1,400-byte fragment is a 1,436-byte datagram, which does not fit every tunnelled or cellular path; with 1,180
bytes a datagram is 1,216 bytes on the wire, under the 1,280 bytes every IPv6 path must carry.

**When to repeat an unanswered message** (16c). The implementation waits a fixed time: 1.2 s for a handshake
message, 0.7 s for a cached rekey, 0.35 s and more for a ratchet. A lost datagram is therefore expensive: 95 % of
the full handshakes are done within 1.2 s at 1 % loss and within 2.4 s at 5 %, where one that needs no repeat takes
23 ms. A timer of three times the last round trip that needed no repeat, and never longer than the fixed one
(simulated, **not implemented**), brings that 95th percentile to 61 ms at 1 % loss, 112 ms at 5 % and 208 ms at
20 %; for the cached rekey to 55 ms instead of 709 ms at 5 % loss, for the ratchet to 134 ms instead of 723 ms. It
sends no more datagrams (1.65 transmissions of a request at 5 % loss against 1.62) and completes the same share of
operations (82 % of the full handshakes at 20 % loss either way): how many attempts are allowed decides that, not
how long each waits. Of the alternatives studied here this is the cheapest to build.

**Live video** (16d; the two additions are simulated, **not implemented**). As implemented, 45 % of the frames
reach the decoder at 0.45 % loss and 6 % at 2 %. A keyframe on request (the ground station asks for one as soon as
a frame is lost) gives 74 % and 20 %; one parity datagram per frame (any one lost datagram of a frame is rebuilt)
95 % and 53 %; both together 99 % and 80 %. Two parity datagrams with keyframe requests keep 97 % at 2 % loss and
62 % at 5 % (`paper_plots/tables/plot16_ablation_design.csv` has parity 2 and 3 as well). Above 5 % loss none of
them keeps the picture usable.

### 5.6 What the key-refresh schedule costs (measured, no simulation)

`paper_plots/tables/table_rekey_schedule.csv` and `table_operation_costs.csv`, from the measured operations
(`link_ops.json`) and message sizes. With the default intervals a session makes 24 cached rekeys and 6 PQ ratchets
an hour:

| Per hour of flight | Bytes on the wire | UAV computing (in the running system) | Time in operations |
|---|---|---|---|
| as implemented | 36 kB | 80 ms | 0.30 s |
| a PQ ratchet at each of the 30 instants | 143 kB | 126 ms | 0.42 s |
| a full handshake at each of the 30 instants | 393 kB | 247 ms | 0.70 s |

The implemented schedule costs 91 % fewer bytes and 68 % less computing on the UAV than refreshing with full
handshakes, and keeps what the cached rekey cannot give (fresh post-quantum secrets, recovery after a compromise)
at one ratchet every ten minutes.

## 6. What was wrong before, and what was found on the way

**The earlier simulation was not a simulation of this protocol.** The scripts that produced the earlier figures
(`scripts/run_hitl_calibrated_pipeline.py`, `swarm_pqc_simulation.py`, `kyber6g_simulation_engine.py`) drew random
numbers around constants and never ran ns-3; the ns-3 module beside them (`contrib/pqc-security`) computed a
"handshake latency" as a sum of modelled delays without sending a handshake packet, and its ablation switches
(CSIDH, CV-QKD, masked SHA-3 and others) changed log lines only. Its results and plots were removed.

**Found while building this one** (each would have produced wrong numbers that look plausible):

1. *UAVs that fall silent.* In the first full sweep 3 of 80 UAVs at 8 per cell and 26 of 160 at 16 per cell stopped
   sending for the rest of the run. Cause: the NR library's UE asks for an uplink grant once and then waits; if the
   transport block that carried its last buffer status report is lost, the gNB believes its buffer is empty and it
   waits forever. Real UEs have a timer for this (retxBSR-Timer, TS 38.321 §5.4.5). It was added to the library
   (`ns3/patches/0002`), and `analyze.py` checks every run for silent UAVs.
2. *Transport blocks lost by the scheduler's choice.* With the library's frequency-division scheduler and beams
   computed from the direct path, all UAVs counted as one beam and were put side by side in the same symbols, while
   the gNB can point its beam at one of them only: 7 % of the uplink blocks were not decoded. The time-division
   scheduler (one UAV at a time, as one beam requires) has none of this: 0 of 62,714 blocks not decoded at 8 UAVs.
3. *An assertion in the library* that fails when one UE's scheduling request is delivered twice (`ns3/patches/0001`),
   and the gNB's limit of sounding-signal slots (40 by default), which refused UEs from 32 per cell on.
4. *ns-3 cuts a command-line value at the first space*: the runs are started from this folder with relative paths.
5. *Link delays from the wrong kind of probe.* The first replica took its delays from round-trip probes the UAV
   sends on its own timer. The measured operations are started by a command from the ground station, and an
   exchange started that way is about 2 ms faster per round trip (§2). With timer probes the replica predicted the
   cached rekey and the ratchet too slow; the probes are now started the way the operations are.
6. *Computing times from a benchmark loop.* A full handshake costs the Pi 2.3 ms in a loop that does nothing else and
   8.2 ms inside the running system (the video encoder is running, the new session has to be installed). The
   simulator draws from the times measured inside the operations (§1).
7. *An overloaded cell that looked nearly fine.* The first analysis judged the video by the frames that arrived: in
   the downlink-heavy cell with 64 UAVs "96 % of the frames complete". Most frames never left the UAVs' queues.
   Counted against the frames sent, 56 % are complete and 3 % reach the decoder (§2, last paragraph).
8. *A design alternative set up to lose.* The repeat timer "three round trips" of the design study first took its
   round-trip time from every exchange, also from one that had been repeated, where the time measured is the
   timer's own. The estimate ran away, and the alternative looked far worse than the fixed timers (95 % of the
   handshakes within 34 s at 20 % loss). It now uses exchanges that needed no repeat only (Karn's rule) and never
   waits longer than the fixed timer would. The 100 runs that use it were made again; all others are the sweep's
   (`results/manifest.json`, `_made_with`).
9. *NR runs that cannot be repeated bit for bit by another build.* After the sweep the ns-3 tree was cleaned (the
   earlier study's module removed) and the simulator built again. Test-bed runs came out byte for byte as in the
   sweep; NR runs did not all (§4, "How far a run can be repeated").

## 7. Limits

- The NR results are a model: one cell without neighbours (no interference from other cells), line of sight
  throughout, no rain, ideal beam tracking. They show how the protocol behaves under contention and scheduling,
  not what a given network will deliver.
- The test-bed replica reproduces the delay of the link it was calibrated on: one Wi-Fi access point, one room, one
  afternoon.
- The ground station is modelled as its receive thread and its answering computations. The object detector, which
  shares the laptop's processor with it, is in the measured computing times but not modelled.
- The frame is given up exactly when its 150 ms window ends; the implementation looks every 50 ms at the latest.
- A cached rekey that is refused, and a link that times out (5 s without traffic), are not followed up: the
  operation counts as failed and the next planned one starts.
- Design alternatives (other algorithms, keyframe request, parity, other repeat timers, more answering threads) are
  simulated, not implemented.
- The PQ ratchet is predicted 16 % too slow on the test-bed link (§3); the cause was not found.
- The check under loss rests on few measured operations (10 of each kind per loss rate), and the loss experiment was
  run two hours before the round trips the model was calibrated on.
- The video is one recording: 1280×720 at 30 frames a second and 3 Mbit/s, of a dark room. Other scenes give other
  frame sizes; the share of frames lost at a given datagram loss depends on them.
- Loss on the test-bed link is independent from datagram to datagram, as it was injected in the measurement. Loss
  in bursts was neither measured nor simulated there.
