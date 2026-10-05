# Paper figures (architecture diagrams)

Nineteen diagrams for the Kyber-6G paper, as editable draw.io sources and as publication files for an Elsevier journal:
vector PDF and EPS at the exact column width, plus 600 dpi PNG previews.

They are drawn in the manner of the architecture figures of
[figures4papers](https://github.com/ChenLiu-1996/figures4papers) (its ImmunoStruct, RNAGenScape, VIGIL and Dispersion
schematics, looked at one by one): a white page; every component a rounded box with a pastel fill and a thin dark
outline; the pastel says which family the component belongs to (UAV, ground station, public-key step, symmetric
step, adversary), and the bold title or pictogram beside it wears the strong colour of that family; short block
arrows from one stage to the next, thin black arrows for data, dashed blue for key material; parts of a figure marked
with a bold letter; Arial. Pictures and pictograms still carry the meaning, and words stay short (see "Style").

Earlier versions: 1, cards and boxes of text, rejected, kept as `docs/legacy/paper_figures_v1_boxed.tar.gz`. 2, Times
New Roman with green and navy accents. 3 (5 October 2026), version 2 with that repository's font and palette only:
thin pale-blue boxes, blue connectors, dark filled pills; it did not look like that repository's figures. 4 (6 October
2026) is this one. Versions 2 and 3 are not kept: these folders had not been committed. Version 4 changed the style
library (`scripts/figlib.py`), not the layouts: the same 19 figures, the same words, two labels shortened.

```
paper_figures/
├── raw_drawio/         editable .drawio sources (open in draw.io / diagrams.net)
├── exported_pdf/       vector PDF, exact width 90 mm or 190 mm                    <- submit these
├── exported_eps/       EPS made from the same PDFs                                <- if the system asks for EPS
├── exported_png/       600 dpi previews
├── assets/
│   ├── pictograms/     57 solid pictograms (Material Design Icons, Apache-2.0) and 2 drawn for this paper (microphone, loudspeaker)
│   ├── photos/         one public-domain aerial photograph (USDA)
│   ├── illustrations/  drawn for this paper: frame crop, ciphertext noise, lattice, elliptic curve, a sound and its ciphertext
│   └── ARTWORK_ATTRIBUTION.md
├── checks/             build_report.md (measured values), gray/ (greyscale proofs)
└── scripts/            setup_tools.sh, fetch_artwork.py, make_illustrations.py, figlib.py, figures.py, build.py
```

## The figures

| No. | File stem | What it shows | Column | Size (mm) |
|---|---|---|---|---|
| 1 | `fig01_system_overview` | What travels between UAV and ground station, and how it is protected | double | 190.00 × 67.26 |
| 2 | `fig02_threat_model` | Network adversary, and the countermeasure for each of nine threats | single | 90.00 × 93.98 |
| 3 | `fig03_handshake` | Hybrid post-quantum handshake, message by message | double | 190.00 × 77.98 |
| 4 | `fig04_key_schedule` | From the two shared secrets to per-stream epoch keys | single | 90.00 × 92.18 |
| 5 | `fig05_session_lifecycle` | (a) link states, (b) key-refresh schedule | double | 190.00 × 52.51 |
| 6 | `fig06_record_layer` | Sealing one chunk into an AEAD record | single | 90.00 × 65.66 |
| 7 | `fig07_video_pipeline` | Live video from the camera to the decoded frame | double | 190.00 × 39.42 |
| 8 | `fig08_perception_hitl` | Finder, detector, overlay and the operator loop | double | 190.00 × 43.76 |
| 9 | `fig09_recording_at_rest` | A stored photo or recording: hybrid key wrap and signature on the UAV, verification and decryption on the GCS | single | 90.00 × 97.68 |
| 10 | `fig10_evaluation_workflow` | Measurements calibrate the simulation; the replica of the test bed is checked against them | double | 190.00 × 43.14 |
| 11 | `fig11_media_protection` | Live video and stored media side by side: where the post-quantum algorithms act and where AES-256-GCM does | double | 190.00 × 69.10 |
| 12 | `fig12_simulation_setup` | The two simulated links: (a) replica of the test bed, (b) 5G NR cell | double | 190.00 × 48.82 |
| 13 | `fig13_rekey_flows` | New keys for a running session, message by message: (a) 1-RTT Cached RapidRekey, (b) PQ ratchet | double | 190.00 × 73.67 |
| 14 | `fig14_hello_admission` | What a ClientHello has to pass at the ground station: cheap checks first, the costly signature check rationed | single | 90.00 × 78.62 |
| 15 | `fig15_audio_sealing` | Sealed audio: frames into blocks of one size, a key per block from the key tree, one signature; the same sealed blocks to the card and onto the link; what the ground station does with them | double | 190.00 × 85.22 |
| 16 | `fig16_audio_clip` | One sealed clip: head, blocks, root, signature; the key tree above the blocks, the hash tree below them; one block enlarged | double | 190.00 × 69.61 |
| 17 | `fig17_audio_excerpt` | An excerpt for a third party: what the ground station hands over, and the four checks anyone can make with the UAV's public key | double | 190.00 × 48.97 |
| 18 | `fig18_architecture` | Architecture of the whole system: every stream of the UAV node, the secure link on both sides, what the ground station does with each (after the project's block diagram, with sealed audio added) | double | 190.00 × 99.25 |
| 19 | `fig19_motion_watch` | The motion watch on the UAV node, step by step: two looks, their difference before and after the camera's own movement is taken out, what is reported (the pictures are computed by the detector itself) | double | 190.00 × 48.50 |

Every stem exists as `raw_drawio/<stem>.drawio`, `exported_pdf/<stem>.pdf`, `exported_eps/<stem>.eps` and
`exported_png/<stem>.png`. The files are already at their final size; include them unscaled:

```latex
\begin{figure}[t]   \centering \includegraphics{paper_figures/exported_pdf/fig06_record_layer}     \caption{...} \end{figure}
\begin{figure*}[t]  \centering \includegraphics{paper_figures/exported_pdf/fig01_system_overview}  \caption{...} \end{figure*}
```

## Suggested captions

1. System overview. Video, telemetry and operator commands cross an untrusted Wi-Fi/IP network as AEAD records;
   the session keys come from a hybrid post-quantum handshake with mutual authentication.
2. Threat model. A network adversary controls the channel and may store traffic for later cryptanalysis; a seized
   UAV, a planted file and a flood of forged handshake messages are considered as well. Each threat is paired with
   the mechanism that counters it.
3. Full handshake (1.5 round trips). Plain boxes are values, blue boxes public-key material, violet boxes MACs.
   Both long-term ML-DSA-87 keys are pinned.
4. Key schedule. The two shared secrets are concatenated and extracted with the transcript hash as salt; every
   stream and direction has its own one-way chain of epoch keys.
5. Session lifecycle. (a) Link states on the UAV; a rekey, a PQ ratchet and a change of cell replace the session
   in place while the link stays up. (b) Key refresh in one session with the default intervals: epoch rotation,
   1-RTT Cached RapidRekey and PQ ratchet.
6. Record layer. One chunk of an encoded frame is encrypted with AES-256-GCM under the epoch key; the nonce is
   derived from the sequence number, and the header is authenticated as associated data.
7. Live-video path. Encoded frames are split into chunks, each chunk is sealed as one record and sent as one UDP
   datagram; the ground station verifies, reorders and decodes.
8. Perception and operator loop on the ground station. The boxes of the real-time detector and of the slower
   open-vocabulary finder are placed by the capture time of the frame; operator input returns as teaching
   examples and as commands.
9. Stored photos and recordings. Each file is encrypted with AES-256-GCM under a random content key; that key is
   wrapped under a key derived from an ML-KEM-1024 encapsulation and an X25519 exchange with the ground station's
   public keys, and the whole file is signed with the UAV's ML-DSA-87 key. The UAV keeps no key that can decrypt a
   finished file; the ground station verifies the signature before it unwraps anything.
10. Evaluation workflow. Computing steps, round trips and frame sizes measured on the prototype calibrate the
    simulation. The simulated replica of the test bed is checked against measurements the calibration did not use
    (the duration of every session operation, and the runs under packet loss); the same protocol model then runs
    in a simulated 5G NR cell. The NR radio exists only in the simulation; the prototype runs over Wi-Fi.
11. Protection of pictures and video. Live video: the hybrid handshake and the PQ ratchet (ML-KEM-1024, X25519,
    ML-DSA-87) give both ends the epoch keys; AES-256-GCM seals one record per datagram. Stored media: the file key
    is wrapped with ML-KEM-1024 and X25519 and the file is signed with ML-DSA-87; the ground station verifies,
    unwraps and decrypts. The post-quantum algorithms establish, wrap and sign; AES-256-GCM encrypts the pixels.
12. The two simulated links. (a) Replica of the test bed: one UAV, messages delayed and lost as measured over
    Wi-Fi, computing times drawn from the measurements. (b) 5G NR cell (5G-LENA): 1 to 64 UAVs around one gNB,
    with a core network and the ground station behind it. Radio and core are simulated, not measured.
13. New keys for a running session. (a) 1-RTT Cached RapidRekey: three small datagrams authenticated with MACs under
    keys derived from the cached resumption secret; no public-key operation, allowed only in the same position cell
    and within 300 s. (b) PQ ratchet: a fresh ML-KEM-1024 and X25519 exchange carried in the session's own encrypted
    control stream and mixed with the current master secret. In both, *TH* is the hash of the exchange. (Suggested
    place: after figure 3; figures 3 and 13 together show every message that establishes or refreshes keys.)
14. Admission of a ClientHello at the ground station. Anybody can send one, and the sender's address proves
    nothing. Everything that costs no public-key operation comes first: reassembly with a bounded table, the answer
    to a repeated hello from a cache, the identity, the nonce and the time stamp. The one costly step an outsider
    can trigger, a signature check that fails, draws on a ration of a quarter of one core; a genuine hello never
    uses it. (Belongs with plot 10b, which shows the measured effect.)

15. Sealed audio. On the UAV the encoder's frames are grouped eight to a block; every block has the same size and
    is encrypted with AES-256-GCM under a key of its own, which comes from a key tree grown from the clip key. The clip
    key is wrapped with ML-KEM-1024 and X25519 for the ground station; one ML-DSA-87 signature over the Merkle root
    covers every block. The same sealed blocks are written to the card and sent over the link. The ground station
    plays each block as it opens, fetches from the card the blocks that were lost on the air, and stores the clip when
    every block is under the signed root. (The prototype has no microphone; a file stood in for it.)
16. One sealed clip. Above the blocks, the key tree: a node gives every key below it and no other, and the UAV keeps
    only the nodes that lead to blocks it has not sealed yet. Below, the hash tree: one signature covers every block
    and its place. Each block carries a commitment to its key, so that a key handed out later can be checked.
17. An excerpt for a third party. The ground station hands over the sealed blocks of seconds *a* to *b*, the key-tree
    nodes that cover exactly those blocks, the hashes that prove their place, and the UAV's signature. Anyone who has
    the UAV's public key verifies the excerpt and hears it, with the time and place of recording; the keys of all
    other blocks cannot be derived from those released.
18. Architecture. Left: acquisition and processing on the UAV node. Right: decryption, storage and analytics on the
    ground control station. Between them every stream crosses the untrusted network as AEAD records under its own
    keys; session keys come from the hybrid post-quantum handshake, the cached rekey and the PQ ratchet. Dotted:
    the operator's commands, in the other direction.

19. The motion watch on the UAV node. Two looks of the small picture, a second of flight apart in the example; their
    difference as it is (every edge of the scene lights up, because the camera moved); the same after the camera's
    own movement has been measured and taken out; and what is reported: a box around what moved by itself. The
    report travels as text in the status stream. The five pictures are computed by the detector itself
    (`kyber6g/camera/motion.py`) from the aerial photograph, with a simulated camera movement and a drawn target.

Wording the figures and captions keep to: the rekey is **1-RTT** Cached RapidRekey (not 0-RTT); ML-KEM and ML-DSA
establish and authenticate the session and wrap and sign stored files and audio clips, **AES-256-GCM** encrypts the
data; the prototype radio is **Wi-Fi**, the NR cell is **simulated**; the prototype has **no microphone**.

Add to the caption of any figure that shows the aerial picture (1, 6, 7, 8, 11, 19): *the frame shown is a public-domain
aerial photograph (USDA) used as an illustration, not an image taken by the prototype; the outlines on it are
schematic.* The waveform in figure 15 is a synthetic signal drawn for the figure, not a recording.

## Artwork and licences

Nothing was taken from a web image search: a picture found that way usually may not be reprinted without the
owner's permission. Everything used is free to publish (details in `assets/ARTWORK_ATTRIBUTION.md`):

| What | Source | Licence |
|---|---|---|
| Pictograms (drone, camera, key, lock, …) | Material Design Icons 7.4.47, Pictogrammers | Apache-2.0 |
| Aerial photograph (the "camera frame") | USDA National Agriculture Imagery Program, via Wikimedia Commons | public domain |
| Ciphertext noise | that frame encrypted with AES-256-GCM, the bytes shown as pixels | own work |
| Lattice and elliptic-curve drawings | `scripts/make_illustrations.py` | own work |
| A sound and its ciphertext (figure 15) | a synthetic, speech-like signal made by `scripts/make_illustrations.py`, and its samples encrypted with AES-256-GCM | own work |
| Microphone, loudspeaker and motion pictograms | built from sectors, circles and rectangles by `scripts/make_illustrations.py` | own work |
| The five pictures of figure 19 | computed by `kyber6g/camera/motion.py` from the aerial photograph above (a simulated camera movement, a drawn target) in `scripts/make_illustrations.py` | own work, on a public-domain photograph |

The camera captures stored on the ground station were **not** used: most of them show a person's face.
To use a real frame from the prototype instead, replace `assets/illustrations/frame.jpg` (16:9) and rebuild.

## Where each figure's content comes from

| Figure | Source in the repository |
|---|---|
| 1 | `kyber6g/uav/main.py`, `kyber6g/ground/main.py`, `kyber6g/config.py` |
| 2 | `docs/SECURITY_ARCHITECTURE.md` §1, `docs/CRYPTANALYSIS_REPORT.txt` §4, and the mechanisms in `kyber6g/crypto/`, `kyber6g/recording/` |
| 3 | `kyber6g/crypto/handshake.py` |
| 4 | `kyber6g/crypto/keyschedule.py` |
| 5 | `kyber6g/transport/link.py` (`UavLink._manage`), defaults in `kyber6g/config.py` |
| 6 | `kyber6g/crypto/record.py`; the inside of AES-GCM is the standard construction |
| 7 | `kyber6g/uav/main.py`, `kyber6g/ground/video_sink.py`, `kyber6g/config.py` |
| 8 | `kyber6g/ground/detector.py`, `kyber6g/ground/finder.py`, `kyber6g/ground/store.py` |
| 9 | `kyber6g/recording/sealing.py`, `photos.py`, `recorder.py`; `kyber6g/tools/decrypt_recording.py` |
| 10 | `simulation/README.md`, `simulation/calibrate.py`, `simulation/run_sweep.py` |
| 11 | `kyber6g/uav/main.py`, `kyber6g/crypto/record.py`, `kyber6g/recording/`, `kyber6g/ground/main.py` |
| 12 | `simulation/ns3/k6g-swarm-sim.cc` (defaults of its parameters), `simulation/README.md` |
| 13 | `kyber6g/crypto/handshake.py` (`build_rekey_request`, `server_process_rekey`, `client_process_rekey_resp`, `PQRatchetInitiator`, `pq_ratchet_respond`); byte counts from `paper_plots/tables/plot03_wire_bytes.csv` |
| 14 | `kyber6g/transport/link.py` (`GcsLink._on_handshake`, `_verify_ration`), `kyber6g/transport/framing.py`, `kyber6g/crypto/handshake.py` (`ServerHandshake.process_client_hello`); the two times from `paper_plots/tables/plot01_crypto_primitives.csv` |
| 15 | `kyber6g/audio/quaver.py` (`AudioSealer`, `SealerTree`), `kyber6g/audio/store.py`, `kyber6g/uav/main.py` (`_audio_live_run`), `kyber6g/ground/audio_desk.py` |
| 16 | `kyber6g/audio/quaver.py` (the layout in its first lines, `KeyTree`, `block_keys`, `Frontier`, `trailer_for`) |
| 17 | `kyber6g/audio/quaver.py` (`make_excerpt`, `verify_excerpt`), `kyber6g/ground/audio_desk.py` (`excerpt`) |
| 18 | `kyber6g/uav/main.py`, `kyber6g/ground/main.py`, `kyber6g/transport/link.py`, `kyber6g/config.py`; the block diagram of the project it was drawn after |
| 19 | `kyber6g/camera/motion.py` (the steps in its first lines), `kyber6g/camera/motion_eval.py`, `kyber6g/uav/main.py` (`on_motion`), `scripts/make_illustrations.py` (`motion`) |

The figures contain no results, with two exceptions that quote measured values from `paper_plots/`: the byte counts
in figure 13 (324 and 4,757 bytes on the wire, plot 3) and the two verification times in figure 14 (0.08 ms on the
laptop, 0.45 ms on the Pi, plot 1). If those measurements are repeated and change, change the two labels in
`scripts/figures.py`. Everything else is in `paper_plots/` (measured: plots 1 to 10 and 17 to 20, simulated: plots 11
to 16, the motion watch: plot 21, what is proved: plot 22). Figures 15, 18 and 19 state settings of the
implementation (8 frames a block, 720p at 30 frames a second, 3 Mbit/s, datagrams of at most 1472 bytes, a picture
of 320 × 180 pixels looked at 8 times a second), not results.

## Rebuild

```bash
sudo bash paper_figures/scripts/setup_tools.sh        # once: draw.io Desktop, Ghostscript, pdfcrop, fonts, pypdf
python3 paper_figures/scripts/fetch_artwork.py        # once: pictograms and the photograph (licences verified)
python3 paper_figures/scripts/make_illustrations.py   # once: frame crop, ciphertext noise, lattice, curve, sound, two pictograms
python3 paper_figures/scripts/build.py                # all figures;  build.py fig03 fig07  for a subset
```

`figures.py` holds one function per figure. Change a label or a coordinate there and run `build.py`: it writes the
`.drawio` file, exports it with the draw.io command line, crops it with `pdfcrop`, scales the page to exactly 90 mm
or 190 mm and derives EPS and PNG from that PDF. A figure edited by hand in draw.io can be exported from there, but
`build.py` regenerates `raw_drawio/` from `figures.py` and would overwrite the manual edit.

The build stops with exit status 1 if a figure has a layout problem: a connector over a label or through a shape,
two labels on top of each other, a label wider than its shape, a text that runs across the outline of a box,
anything outside the design width, text under 6.5 pt.

## Style

The look is that of the schematics of [figures4papers](https://github.com/ChenLiu-1996/figures4papers): its
architecture figures were looked at, its plotting scripts and design notes read; none of its code or artwork is
used. The typeface and the strong colours are shared with the plots. Everything is set in one place,
`scripts/figlib.py`.

- **Components:** a rounded box, pastel fill, dark outline `#272727` of 1 pt, words in near-black `#1A1A1A`. An
  algorithm is such a box with a bold name. A frame around several things is the same box, white or in the pastel of
  its side; a loose group stands in a dashed frame.
- **Families** (pastel fill / strong colour of titles, pictograms and lines):

  | Family | Fill | Strong colour |
  |---|---|---|
  | UAV node | green `#DDF3DE` | `#2E7D4F` |
  | Ground station | cream `#FCEFC8` | `#8A6A12` |
  | Public-key / post-quantum step, key material | blue `#D6E4F5` | `#0F4D92` |
  | Symmetric step (AES-256-GCM, HKDF, SHA-256, a MAC), what is encrypted | violet `#E9DDEF` | `#9A4D8E` |
  | Adversary, threats | red `#F6CFCB` | `#B64342` |
  | Neutral step, plain data; block arrows | grey `#EFEFEF`; `#DDDDDD` | `#767676` |

  The blue, the violet and the red are that repository's `blue_main`, `violet` and `red_strong`; the green and red
  fills are its `green_1` and `red_1`.
- **Arrows:** thin black (1 pt, right angles with rounded corners, heads 4 pt × 3 pt) = data; dashed blue = key
  material; dotted = operator commands. A short straight data arrow from one stage to the next is a **block arrow**
  (grey, dark outline): 86 of them. The library draws one where nothing stands in its way (a label on the line,
  another connector, a small operator circle keep the thin arrow); state diagrams, message sequences and trees keep
  thin lines throughout. Circles: plus = XOR, `||` = concatenation, bar = split into chunks.
- **Type:** Arial (that repository's portable stand-in for Helvetica), embedded. Labels 9 pt and 8 pt, notes 7 pt,
  indices 6.5 pt; nothing smaller. Variables italic (*ss*, *TH*, *CEK*, *N*), algorithm names upright and bold.
  The parts of a figure are marked **a**, **b**.
- **Width:** exactly 90 mm or 190 mm. The drawings have no frame, so two near-white specks (0.4 pt, 99 % white,
  0.5 mm inside each edge) mark the design width; they do not print.

## What was measured on the output (see `checks/build_report.md`)

| Check | Result |
|---|---|
| Page width | 90.00 mm and 190.00 mm on all nineteen PDFs |
| Text sizes in the PDFs | 6.5, 7.0, 8.0 and 9.0 pt; nothing below 6.5 pt |
| Fonts | Arial regular, bold, italic only; embedded |
| Pictograms and drawings | vector in every PDF |
| Raster pictures inside the PDFs (the frame, ciphertext shown as pixels, the five pictures of the motion watch) | 626 ppi or more at printed size (50 placements in 10 figures) |
| Connectors drawn by draw.io as designed | 220 of 220 (the other 86 arrows are block arrows, which are shapes) |
| Connector over text, text over text, label wider than its shape, text across an outline | none |
| Line width, arrowhead | 1.00 pt; 4 pt long, 3 pt wide (set values; the head was measured for the second version, not again) |
| Contrast (computed from the colours) | text on white 17.4 : 1, on the pastel fills 12.2 to 15.2 : 1; outlines against the fills 10.5 : 1 or more; coloured titles and pictograms on white 5.0 to 8.4 : 1 |
| Greyscale (`checks/gray/`) | the pastel fills are nearly the same light grey (215 to 239 of 255): in grey the families are told apart by their words and pictograms, not by the fill; outlines, text and the three line styles are unaffected |
| EPS | all nineteen written by pdftops (the second version's eighteen were also rendered in Ghostscript; not repeated) |
| PNG | 2126 px (90 mm) and 4489 px (190 mm) wide = 600 dpi |
| Colours | only the palette above; no pure black |
| Looked at | all nineteen PNGs of the final build, one by one (6 October 2026) |

Not checked: a specific journal's artwork checker, and printing on paper.
