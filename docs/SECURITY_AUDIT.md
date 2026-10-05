# Security and robustness review of the secure link (October 2026)

**Scope.** The present system in `kyber6g/` (crypto, transport, UAV application, ground station, web dashboard,
tools), its deployment (`deploy/`, `run/`), its dependencies on both machines, and the integrity of the repository.
The earlier prototype in `hitl/` and the simulation code were looked at only far enough to mark them as legacy.

**Date and versions.** 4 October 2026. Raspberry Pi 4 Model B (Debian 13, kernel 6.18.34, Python 3.13.5),
ground station in WSL2 Ubuntu 22.04 (Python 3.10.12); liboqs 0.16.0, cryptography 50.0.1 (OpenSSL 4.0.2) on both.

**Method.** Every source file of the present system was read with the question "what can a sender of datagrams, a
web page in the operator's browser, another local user, or a faulty peer make this code do?". Automatic tools ran
beside that (section 4). Every finding was fixed, and all but two were given a regression test (the confinement
of the service is checked on the Pi itself, the changes to the test tools have none); the tests were run on both
machines, the hardened system was deployed to the real hardware, and the end-to-end pipeline test and the browser
test of the dashboard were repeated on it (section 5). One finding (18) came out of the measurement campaign that
followed.

**What this is not.** It is not a formal proof of the protocol, not a side-channel or fault-injection analysis, and
not an independent penetration test (section 7).

---

## 1. Summary

| # | Area | Finding | Severity | Status |
|---|---|---|---|---|
| 1 | Record layer | Two threads sealing on one stream could use one sequence number, i.e. one AEAD nonce under one key | High (low likelihood) | fixed |
| 2 | Dashboard web API | No check of where a request comes from: commands from any web page (cross-site request), full access by DNS rebinding | High | fixed |
| 3 | Handshake reassembly | A full table refused every new message: 32 forged fragments per 5 s blocked all handshakes | High (availability) | fixed |
| 4 | Ground station, hello handling | Limit of 8 ClientHellos per source address in 10 s: one forged datagram per second with the UAV's address locked the UAV out | High (availability) | fixed |
| 5 | UAV, handshake answers | The first answer that did not verify, or an unauthenticated ERROR, ended the attempt; a duplicate ServerHello could reach a freed key object | High (availability) | fixed |
| 6 | Command path | Arguments of a dashboard command could replace the message type and reach the UAV as any message | Medium | fixed |
| 7 | Keys on disk | Key directory, pinned public keys and media directories writable or listable by group/others (0775 / 0664 on the Pi) | Medium | fixed |
| 8 | Messages from the peer | Fields of authenticated control messages, telemetry and transfer metadata used without checking their type; NaN accepted | Medium | fixed |
| 9 | Dashboard page | Values from the UAV inserted into the page unescaped in four places; no Content-Security-Policy | Medium | fixed |
| 10 | Stored files | The recording parser raised raw exceptions on damaged files, padded a short key ciphertext silently, ignored trailing bytes | Medium | fixed |
| 11 | UAV, concurrency | A rekey asked for from the dashboard ran beside the link manager's own handshake; each could cancel the other | Medium | fixed |
| 12 | GNSS reader | One malformed sentence with a valid checksum ended the reader thread for the rest of the run | Medium (robustness) | fixed |
| 13 | UAV service | Ran unconfined under a login that may use sudo without a password | Medium | fixed |
| 14 | Camera settings | Values from a command were applied unchecked and not rolled back when the encoder refused them | Low | fixed |
| 15 | Video receiver | A frame shorter than its time stamp raised; half-received frames were unbounded | Low | fixed |
| 16 | Web API details | Negative row limits read whole tables; the database export was built in memory; an empty CSV export was an empty file | Low | fixed |
| 17 | Tools | Camera test wrote plaintext pictures to fixed names in `/tmp`; model cache loaded with full pickle; test tools left the operator's settings changed | Low | fixed |
| 18 | Photo store | Two photos taken within one second got the same file name; the second replaced the first on the UAV and at the ground station | Medium (data loss) | fixed |
| 19 | UAV, change of position cell | The handshake a new cell requires took the link out of the UP state: nothing was sent for its duration, and one or two video frames (and the picture up to the next keyframe) were lost at every cell change | Medium (availability) | fixed |
| 20 | Ground station, flood handling | The ration of failing signature checks was a fixed 50 per second: a flood of a few megabit per second emptied it and the genuine UAV's hello was then dropped with the forgeries | High (availability) | fixed |
| 21 | Stored photos and recordings | Not signed and wrapped with ML-KEM-1024 alone: anyone who knew the ground station's public recording key could write a file that passed as the UAV's; one assumption carried the confidentiality | Medium | fixed (file format 2) |
| 22 | Stored photos | The ground station's long-term keys were used on a file before its signature was checked | Low | fixed |
| 23 | Management channel | Deploy, service control and measurements ran over SSH with a classical key exchange (X25519 alone), although both ends support a post-quantum hybrid one | Low | fixed |

Findings 19 to 23 are from the second pass of the same day (section 8), in which the implementation was attacked
with experiments instead of read.

Nothing was found that gives an outsider the session keys, lets a forged or replayed record through, or lets the
UAV or the ground station be impersonated: the handshake (pinned ML-DSA-87 keys, transcript-bound hybrid key
agreement, key confirmation), the record layer (per-stream, per-direction, per-epoch keys, authenticated header,
replay window) and the storage formats held up to reading and to the fuzz tests of section 5. The serious findings
were about **availability** (cheap ways to keep the link down), about the **web dashboard** (which had no defence
against other web pages) and one **concurrency fault** in the record layer.

---

## 2. Findings in detail

### 1. Sequence number taken without a lock (`crypto/record.py`)

`TxStream.seal` read `self.seq`, incremented it and encrypted, with no lock. The control stream is used by several
threads at once on both sides (commands and their answers, pings, transfer control, the link manager). Two threads
entering together could read the same number; the nonce is that number, so two different plaintexts would be
encrypted under one (key, nonce) pair. For AES-GCM and for ChaCha20-Poly1305 that reveals the XOR of the two
plaintexts and breaks the authentication key of that epoch.

*Reproduced:* with the lock replaced by a dummy and the interpreter told to switch threads as often as possible,
**1738 of 32,000 records** carried a number already used (Python 3.10, the ground station). With the interpreter's
normal switching interval the same workload produced none in 32,000, and on the Pi (Python 3.13) none in 64,000
even under forced switching - so it was rare, not impossible, and it depended on the interpreter version.

*Fix:* one lock per stream around "rotate the epoch if due, take the next number, encrypt". The receiving side
checks and commits the replay window under a lock as well. Tests: `TestSealIsThreadSafe` (unique numbers under
forced switching, also across epoch rotations; one record offered by eight threads is accepted once).

### 2. The dashboard trusted every request (`ground/main.py`)

The dashboard listens on 127.0.0.1 and has no login. Its HTTP server looked at nothing but the path:

* any web page open in the operator's browser could send `POST /api/cmd` with a `text/plain` body (a request a
  browser sends to another origin without asking) and so start or stop recording, change the camera, fetch files or
  force rekeys;
* a page using DNS rebinding (its own name made to resolve to 127.0.0.1) became "same origin" and could also read
  everything: the video, the telemetry, the database export.

*Fix:* every request is checked before anything is done (`request_refused`): the `Host` header must be `localhost`,
an IP address or a name the operator listed (`http_allowed_hosts`), with the right port; requests the browser marks
as coming from another site (`Sec-Fetch-Site`) are refused, except a plain navigation to the page itself; a `POST`
whose `Origin` is not this server is refused; commands must be `application/json`. Every response carries
`X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`; the page
carries a Content-Security-Policy (scripts only from this server, the one inline import map allowed by its hash,
no `eval`, no framing, connections only to this server). Refused requests are counted and shown on the SECURITY tab.
Tests: `TestDashboardRequestChecks`. Checked on the running station: foreign `Host` 403, foreign `Origin` 403,
`text/plain` command 415; the browser test of the dashboard passes with the policy enforced (section 5).

### 3. Reassembly table could be filled (`transport/framing.py`)

Handshake messages travel as fragments that cannot be authenticated before the message is complete. The table of
partial messages held 32 entries for 5 s and refused a new message when full. Thirty-two forged first fragments
every five seconds, from anywhere, kept every genuine handshake out.

*Fix:* a full table drops its oldest entry instead; one source address may hold four entries; a fragment larger
than a fragment can be is dropped; the table holds 128 entries (2.4 MB at most). Test: `TestHandshakeReassembly`.

### 4. Rate limit keyed on a forgeable address (`transport/link.py`, `crypto/handshake.py`)

The ground station accepted 8 new ClientHellos per source address in 10 s. The source address of a UDP datagram is
whatever its sender writes, so a forger using the UAV's address could spend the UAV's quota with one small datagram
per second. The running system had also hit the limit by itself (28 hello and 15 rekey drops in one night after the
laptop had slept).

*Fix:* the order of checks was changed so that the only expensive step an outsider can trigger is one signature
verification: unknown UAV, replayed nonce and out-of-window time stamp are refused first, at no cost. Failed
signature checks draw on one global ration (50 per second, burst 100); when it is empty, hellos are dropped
unverified until it refills. A genuine hello is not limited. Rekey requests are cheap (one HMAC) and need no limit;
the refusals sent for bad ones are rationed (20 per second) so the port cannot be used as a reflector. A repeated
rekey request now gets the same answer again (before, a lost answer forced a full handshake). A junk record for a
half-open session no longer costs a key derivation each time. Tests: `TestGroundStationFloodHandling`.

### 5. One bad datagram ended a handshake (`transport/link.py`)

On the UAV, a ServerHello that failed to verify set the attempt's result to "error", and so did the unauthenticated
ERROR message. Anyone able to send one datagram to the UAV during each attempt kept the link down for good. A
duplicate of the genuine ServerHello, arriving in the instant before the attempt was closed, would have reached the
ephemeral ML-KEM key after liboqs had freed it.

*Fix:* answers that do not verify are counted and dropped, and the attempt keeps waiting for the genuine one. An
ERROR is remembered for the log and never acted on. A rekey REJECT is honoured only if it names exactly the pending
request (it is a hint to fall back to the full handshake; a forged one costs time, never security). A completed
handshake object refuses further input. Handshake datagrams are accepted from the configured ground-station address
only. Tests: `TestUavIgnoresUnverifiedAnswers`, including a run over real sockets in which three forged answers
arrive for every datagram the UAV sends and the link still comes up at the first attempt.

### 6. Command arguments could replace the envelope

`{"t": cmd, "id": n, **args}`: an argument named `t` replaced the command type after it had passed the allow-list.
*Fix:* the envelope is written last and the names are refused. Test: `test_command_arguments_cannot_replace_the_envelope`.

### 7. Permissions of keys and media

On the Pi (umask 002) `~/.kyber6g` and `peers/` were 0775, the pinned public keys 0664, the recordings directory
0775; on the laptop 0755. Whoever may write a pinned key decides whom the node trusts and to whom recordings are
encrypted. (The group on both machines is the user's private group, so nobody else could in fact write them.)

*Fix:* `identity.private_dir` creates the directories 0700, tightens an own directory that is wider and says so in
the log together with the key's fingerprint, and refuses a directory or key owned by another user, a secret key
readable by others, and shared directories such as `/tmp`. Recordings and photos are created 0600 from the first
byte (`O_EXCL`). The deployment script sets the modes; the stored-data audit now checks them on both machines.
Tests: `TestKeyDirectoryPermissions`.

### 8. Values from the peer used as they came

The peer is authenticated, so this is about a faulty or taken-over UAV (or ground station), not an outsider.
Control messages (`pong`, ratchet request and answer, transfer NACKs, acknowledgements), telemetry and transfer
metadata were used without type checks: a missing field raised in the receive thread (logged with a traceback each
time), `NaN` passed through and made the state unreadable for the browser, a transfer could announce any name and
size, and each NACK started a sending thread.

*Fix:* every JSON message from the peer goes through `jsonmsg.loads` (rejects `NaN`/`Infinity`, bounds depth, sizes
and string lengths); the fields that enter arithmetic are typed (`jsonmsg.num`, `clean_telemetry`); transfer
metadata is checked field by field (`blob.valid_info`), the first metadata of a transfer stands, memory for all
transfers together is bounded, one sending thread per transfer; file names from the UAV must be plain
(`safe_name`) and an "image" must be a JPEG, a recording a `.k6grec`. Tracebacks from the receive thread are logged
at most once per 10 s. Tests: `TestControlMessagesFromThePeer`, `TestBlobTransferHardening`, `TestTelemetryCleaning`,
and the fuzz tests.

### 9. Dashboard page

`f()`, the number formatter of `app.js`, inserted anything that was not a number unescaped, and three templates
inserted values directly. With finding 8 a taken-over UAV could have run script in the operator's page, and from
there sent commands. *Fix:* escaping in those places, typed telemetry at the source, and the Content-Security-Policy
of finding 2 as the second line. Tests: `TestDashboardScriptEscapes`, `test_security_headers`.

### 10. Recording and photo files

`decrypt_recording` raised `struct.error`, `KeyError` or a JSON error on a damaged file, while its callers handle
`RecordingError` only; a truncated ML-KEM ciphertext was padded with zeros by the library binding; a frame could
claim to be longer than its segment; bytes after the FINAL segment went unnoticed. *Fix:* strict parsing, one
exception type, trailing bytes reported, the frame rate passed to ffmpeg restricted to a plain number.
Tests: `TestStoredFileParsers` (every truncation of the first 1700 bytes and 120 random ones; 400 random bit
changes, all detected; 200 for photos).

### 11 to 18, briefly

* **11** `UavLink` now serialises handshake and rekey (`_hs_lock`); a rekey from the dashboard waits for the
  manager's instead of cancelling it.
* **12** `GpsdReader` handles each line on its own; a bad one is counted (`gnss_parse_errors`) and the reader goes on.
  Test: `TestGnssReaderSurvivesBadLines` (a fake gpsd).
* **13** `deploy/kyber6g-uav.service` confines the service: no new privileges (sudo does nothing inside it), the
  file system read-only except the two media directories, private `/tmp`, umask 0077, no kernel tuning, only the
  socket families the link needs. `systemd-analyze security` rates the unit 3.8 ("OK"). Camera, I2C and the
  VideoCore interface need device access, so device isolation and a system-call filter are deliberately not used.
  `run/kyber6g.sh deploy` installs this unit and sets the directory modes it relies on, so a Pi deployed from the
  repository gets the confined service (before, both were steps done by hand).
* **14** `set_video` checks ranges and types and restores the previous settings if the encoder does not start.
  Test: `TestCameraSettingsFromTheGroundStation`.
* **15** `VideoSink` counts a frame that is too short instead of raising and keeps at most 256 unfinished frames.
* **16** Row limits are clamped, the database export is streamed from a snapshot, CSV exports always carry their
  header line.
* **17** `hwtest_camera` writes into a private directory; the text-embedding cache is loaded with
  `weights_only=True`; the browser test and the pipeline test put the operator's settings back when they end.
* **18** Found by the measurement campaign, not by reading: photo files were named by the second
  (`img_YYYYMMDD_HHMMSS`), and the loss test took photos faster than that. Four pairs shared a name; in each pair
  the second picture replaced the first, on the UAV's card and in the ground station's image folder, while the
  database kept both rows (the stored-data audit reports the four rows whose file no longer matches). *Fix:* names
  carry milliseconds (`photo_name`) and the photo store never overwrites an existing file (it appends `-2`, `-3`).
  Test: `test_two_photos_never_share_a_file`. The four replaced pictures are not recoverable.

---

## 3. What was read and found sound

* **Handshake** (`crypto/handshake.py`): both ML-DSA-87 keys are pinned from disk and never taken from a message;
  the signatures cover the suite id, both identities, both nonces, the mobility cell, the time stamp and both
  ephemeral public keys through the transcript hash, so a downgrade or a mix of two handshakes fails the signature;
  ML-KEM-1024 and X25519 secrets are both fed to HKDF with the transcript as salt; both sides prove possession of
  the keys with a Finished MAC before any data is accepted; a ClientHello is accepted once (nonce cache kept for
  twice the time window).
* **1-RTT Cached RapidRekey:** the request is authenticated before any state changes; the resumption secret is
  deleted when used; the mobility cell must match; the new session id and nonce are bound into the new keys.
* **PQ ratchet:** travels inside the authenticated session and mixes fresh ML-KEM-1024 and X25519 secrets with the
  current master secret; a repeated request gets the same answer.
* **Record layer:** the whole header (version, stream, session, epoch, sequence, extension) is authenticated; keys
  differ per stream, direction and epoch; the receiver never advances its key chain further than 8 epochs beyond
  the last authenticated one; replay window of 2048.
* **At rest:** recordings and photos are encrypted with a random key wrapped to the ground station's ML-KEM-1024
  key; the UAV holds nothing that opens them; segments cannot be reordered, dropped or moved between files.
* **Web server:** static files cannot leave their directory; media files are served by base name; SQL is
  parameterised; request bodies are size-limited.
* **Secrets:** none in the repository (section 4); secret keys are 0600 and refused otherwise; core dumps are
  disabled in both applications.

---

## 4. Automatic checks

| Check | Result |
|---|---|
| `git fsck --full` | no errors. 3,960 tracked files; against the last commit 5 are modified (`README.md`, two legacy READMEs, `.gitignore`, the website's lock file) and 34 deleted (the outdated plots and their viewer page, recoverable with `git checkout`); the present system is not committed yet |
| All own Python files compile | 127 files (present system, tests, plot and figure scripts, legacy scripts), no syntax error |
| ruff (undefined names, unused imports and variables, syntax) on the present system, the tests and the plot and figure scripts | no undefined name, no syntax error. 11 notes, all of them an unused local name or import in a test, a test tool or the figure script (`tools/pipeline_test.py` 2, `tools/ui_test.py` 3, `tests/` 3, `paper_figures/scripts/figures.py` 3); none in the code that runs on the UAV or in the ground station. Left as they are |
| bandit, present system (8,835 lines) | no finding of high severity; 16 medium and 38 low, each one read, none a defect: the UDP listener binds all interfaces on purpose (the UAV must reach it; the dashboard binds 127.0.0.1) (2); SQL text built from fixed table names, values always bound as parameters (3); `urlopen` with fixed http(s) addresses in test and benchmark tools (7); model download without a pinned revision in the benchmark tool (4, see residual risk 10); `subprocess` (27: always an argument list, never a shell; the variable parts are file names the program made itself, the checked frame rate of finding 10 and the SSH alias the operator gives a tool); `try … except: pass` around clean-up steps (11) |
| pip-audit, ground-station environment | no known vulnerability in the 66 installed packages |
| pip-audit, Pi environment | 100 advisories in 13 of 272 packages. All 13 are Debian system packages visible to the venv (pillow 11.1.0, pyjwt, urllib3, pip, soupsieve, requests, pygments, lxml, idna, brotli, wheel, oauthlib, fonttools). The UAV application imports one of them, Pillow, and only to ENCODE its own camera picture as JPEG; it never parses an image from outside |
| detect-secrets and a search for key files | no secret. Three hexadecimal strings were flagged and read: the SHA-1 check value of a public photograph (`paper_figures/scripts/fetch_artwork.py`) and the published HKDF test vector of RFC 5869 (`tests/test_crypto.py`). No key, `.pem`, `.env` or SSH key file in the repository; no password or private key in the measurement data. `.gitignore` excludes key files, recordings and received media |
| npm audit, project website | 13 advisories in the locked dependencies (8 high, 3 moderate, 2 low; among them vite, postcss, picomatch, js-yaml), none after `npm audit fix` with compatible updates only; the production build still succeeds. Only `package-lock.json` changed |
| systemd-analyze security, UAV service | exposure 9.0 ("UNSAFE") for the previous unit, 3.8 ("OK") for the present one; the service is active with 0 restarts since deployment |

---

## 5. Tests after the changes

| Test | Result |
|---|---|
| Unit tests, ground station (laptop, Python 3.10.12) | 185 run, all pass (67 s) |
| Unit tests, Raspberry Pi (Python 3.13.5) | 177 run, all pass; 8 skipped there: 4 need the detection models or OpenCV, 3 need node.js (the dashboard's scripts), 1 needs root (it makes a key file owned by another user; it runs on the laptop). The code on the Pi is byte for byte the repository's (hash over all Python files compared) |
| New in this review (`tests/test_hardening.py`) | 58 tests in 16 groups: regression tests for findings 1 to 10, 12, 14 to 16 and 18, the fuzz tests of the next three rows, and a test of the rekey-on-request path of finding 11. Findings 7 and 13 are checked on the two real machines by the stored-data audit (file modes, service confinement); finding 17 has no automatic test |
| Fuzz: 4000 random and mutated datagrams to each end of a running link | no unexpected exception at either end (counter `internal` absent), nothing forged delivered, session undisturbed, link usable afterwards |
| Fuzz: 1500 random authenticated control messages in both directions, plus non-JSON and incomplete ones | same |
| Fuzz: 3000 mutations of a genuine record; truncations and bit changes of ClientHello, Finished, rekey request | every one refused with a reason |
| End-to-end pipeline on the real hardware | 40 PASS, 1 FAIL, in each of two runs (the second after the last deployment). The one FAIL is the clock of the laptop's WSL virtual machine (11 % slow), a fault of that machine known since the fourth test round (`docs/TEST_REPORT.md` §13.2); every check of the link, the encryption, the stored media and the detector passes. Video frames lost during the test's 6 rekeys: 0 of 391 in the first run, 3 of 479 in the second, in a stall of the radio link that also delayed the ratchet itself (`docs/TEST_REPORT.md` §14.1) |
| Stored-data audit on both machines | 31 PASS, 1 WARN, 0 FAIL. The warning is the four photos of finding 18 |
| Dashboard in a real (headless) browser, policy enforced | 93 PASS, 0 FAIL; the browser reported no policy violation and no script error; every control of the page was used |
| Measurement campaign on the hardened system | 450 of 450 session operations succeeded, no video frame lost during them; 3 of 23,401 frames lost in 13 minutes of streaming (see `paper_plots/`) |

---

## 6. Residual risks (known, accepted or left to the operator)

1. **No login on the dashboard.** It binds to 127.0.0.1; every program and user on the ground-station machine can
   use it. The request checks stop other web pages, not local programs.
2. **The ground station runs as root inside its WSL virtual machine.** A flaw in it would give that virtual
   machine away. Running it as an ordinary user is possible and recommended.
3. **Flooding.** Forged ClientHellos can delay a handshake; they cannot break one. Measured in the second pass
   (`CRYPTANALYSIS_REPORT.txt` §4.12): with the ground station on the laptop, up to 3,000 forged hellos per second
   (156 Mbit/s) do not hold up a genuine handshake, and at 10,300 per second it takes 2.4 s. With a Raspberry Pi 4B
   in the role of the ground station the limit is about 300 per second (16 Mbit/s); at 1,000 to 4,900 per second a
   connection takes 1 to 10 s in the median and up to 33 s. Every connection was made at every rate. A stateless
   cookie exchange would move the limit further out; it is not implemented. Jamming and an attacker on the path who
   drops packets are outside what a protocol can prevent.
4. **Clocks.** A ClientHello is accepted within 120 s of the ground station's clock. A UAV whose clock is further
   off (no network time, no GNSS time) cannot connect; the refusal now says so and by how much.
5. **Cached rekey** adds no fresh key agreement (by design: one round trip, symmetric only). Forward secrecy and
   recovery after a compromise come from the PQ ratchet every 600 s and from full handshakes.
6. **Unauthenticated REJECT** can make the UAV fall back from a cached rekey to a full handshake (cost: about
   14 ms more, see `paper_plots/`).
7. **A captured UAV can sign as itself.** Stored files are signed by the UAV since the second pass (finding 21),
   so a file planted by someone else is refused. Whoever holds the UAV's SD card holds its identity key, though, and
   can speak and sign as that UAV until its pinned key is removed at the ground station. What is already stored on
   the card stays unreadable.
8. **Python and memory.** Secrets held in `bytearray` are wiped after use; keys inside the AEAD objects and
   transient `bytes` copies cannot be. Constant-time behaviour is that of liboqs and OpenSSL; MAC comparisons use a
   constant-time compare.
9. **Raspberry Pi OS updates.** Of the 108 packages with updates pending on 4 October 2026, 88 were installed in
   the second pass (all 14 from the security archive), and camera, GNSS, display and link were checked afterwards.
   19 are held back: kernel, firmware, bootloader, Wi-Fi firmware and the camera applications. They change the boot
   chain or the camera stack; installing them is the operator's decision and wants someone next to the Pi.
10. **Model files.** The detector's weights are downloaded once from their publishers and are pickle files; they
    are trusted as the libraries that load them are. The download is not pinned to a revision or checked against
    a known hash; after the first download the local copy is used.
11. **Legacy code.** `hitl/` and `src/hitl/` (the earlier prototype) trusted the peer's key on first use and
    listened on all interfaces. They were removed from the working tree in the second pass (they remain in the git
    history) and must not be run on a real network.

---

## 7. Not tested

* Formal verification of the handshake and the rekeying (no model in ProVerif, Tamarin or similar).
* Side channels and fault injection on the Raspberry Pi (power, electromagnetic, glitching, cache). Timing was
  tested coarsely in software (section 8).
* Coverage-guided fuzzing; the fuzz tests here are random and mutation-based with fixed seeds.
* An independent penetration test.
* More than one UAV; a UAV in flight; any radio other than Wi-Fi (no 5G or 6G radio was ever used). More than one
  UAV, movement and a cellular radio exist in the simulation only (`simulation/README.md`).

---

## 8. Second pass: the implementation attacked by experiment (4 October 2026, afternoon)

The first pass read the code. The second ran what an attacker can do against it, many times over, on both
machines (`kyber6g/tools/attack_bench.py`; `bash run/kyber6g.sh measure attacks`), and wrote the outcome as
`docs/CRYPTANALYSIS_REPORT.txt`. In 27 kinds of experiment, 169,542 attack attempts were made on each machine
(339,084 in all): forged, modified, replayed and spliced records; modified, replayed, mixed and downgraded
handshake messages and impersonated ends; forged rekey requests; replaced key shares; modified, cut, re-signed and
forged photos and recordings. None was accepted. A stress test of the sender (eight threads sealing on one stream
while its key rotates, 96,000 records on each machine) used no nonce twice. It also brought the five findings below, updated the
operating system of the Pi, and removed the legacy prototype from the working tree. The simulation was rebuilt in
the same pass (`simulation/README.md`); it is not part of the system under review.

### 19. A change of position cell interrupted the stream (`transport/link.py`)

A session belongs to the position cell it was made in, so a new cell needs a full handshake. The link manager made
it by leaving the UP state: for the 23 ms of a handshake (and for 6 s if it got no answer) the UAV sent nothing,
and the frame in flight was lost, with it the picture up to the next keyframe. A UAV at 30 m/s changes cell every
few seconds. *Fix:* the handshake after a change of cell is made in place, in a thread of its own, exactly like a
rekey the operator asks for: the running session carries the traffic until the new one is installed; if the
handshake fails, the running session goes on and it is tried again 0.5 s, 1 s, … 8 s later. Tests:
`test_a_change_of_cell_does_not_interrupt_the_stream`,
`test_a_change_of_cell_with_no_handshake_possible_keeps_the_running_session`.

### 20. The flood ration was a fixed number (`transport/link.py`)

Failing signature checks were rationed at 50 per second (finding 4). The flood experiment showed what that means:
50 forged ClientHellos per second are 2.6 Mbit/s; above that the ration was empty for most of every second and the
genuine UAV's hello was dropped unverified together with the forgeries, attempt after attempt. *Fix:* the ration is
computed when the ground station starts, from the cost of a check measured on that machine, as a quarter of one
core (`GcsLink._verify_ration`; measured: 3,274 failed checks per second on the laptop, 561 on a Raspberry Pi 4B).
Test: `test_the_ration_follows_from_the_cost_of_a_check_on_this_machine`.

Measured after the fix (the flood generator as a process of its own on the same machine, a genuine UAV connecting
six times or more at each rate, 60 s allowed per connection):

| Forged hellos per second | Mbit/s | Ground station on the laptop: median (slowest) | On a Raspberry Pi 4B: median (slowest) |
|---|---|---|---|
| 0 | 0 | 5 ms (6 ms) | 10 ms (12 ms) |
| 100 | 5.2 | 5 ms (6 ms) | 18 ms (29 ms) |
| 300 | 15.6 | 5 ms (6 ms) | 12 ms (14 ms) |
| 1,000 | 52 | 5 ms (5 ms) | 1.2 s (4.8 s) |
| 3,000 | 156 | 7 ms (7 ms) | 8.6 s (32.7 s) |
| as fast as one process can send | 537 (laptop), 253 (Pi) | 2.4 s (2.4 s) at 10,324 per second | 10.0 s (31.8 s) at 4,860 per second |

Every genuine connection was made at every rate, on both machines. Above the ration a hello needs repeats and the
connection takes seconds; nothing is disclosed or accepted (residual risk 3).

### 21. Stored photos and recordings: one assumption, and no origin (`recording/`)

The file key was wrapped with ML-KEM-1024 alone, while the link never relies on ML-KEM alone, and the file was
not signed: whoever knew the ground station's *public* recording key could write a file that decrypted and
authenticated, so a file planted on the UAV's card or in the ground station's folders could not be told from the
UAV's (residual risk 7 of the first pass). *Fix:* file format 2 (`recording/sealing.py`): the file key is wrapped
under a key derived from ML-KEM-1024 **and** X25519, and the UAV signs SHA-256 of the whole file with its ML-DSA-87
identity key; the ground station refuses a photo or recording without the pinned UAV's signature. Format 1 is
still read. Tests: `tests/test_sealing.py` (18); attack experiments on stored files (section 4.13 of the report).

### 22. Signature checked after the keys were used (`recording/photos.py`)

Opening a photo decapsulated with the ground station's long-term keys first and verified the UAV's signature
second. ML-KEM-1024 is designed to withstand chosen ciphertexts, so this was not a hole, but a forged file should
not reach long-term keys at all. *Fix:* the signature is verified first. A recording is still read without its
trailer, on purpose: one cut short by a power loss has none, and it is then reported as cut short and unsigned.

### 23. The management channel used a classical key exchange (`run/`, `deploy/`, `tools/sshopts.py`)

Deploying, controlling the service and measuring run over SSH. The laptop's OpenSSH 8.9 and the Pi's 10.0 agreed
on `curve25519-sha256`: a recording of such a session could be opened by a later quantum computer (it carries
code and public keys, no secret of the link, but also whatever a later tool might send). Both ends support a
hybrid exchange. *Fix:* every SSH call of the scripts and tools asks for a post-quantum hybrid key exchange first
(`sntrup761x25519-sha512`, or `mlkem768x25519-sha256` where the client has it); measured after the change:
`sntrup761x25519-sha512@openssh.com`. The stored-data audit checks it. SSH's host and user authentication stay
Ed25519: OpenSSH has no post-quantum signature.

### Other changes of the second pass

* **Expected refusals are not errors.** A command the UAV refuses (recording while the card is full, a photo that
  no longer exists) was logged as an ERROR with a traceback; it is a WARNING with the reason now.
* **Operating system of the Pi.** 88 packages were updated (all 14 from the security archive among them); the
  camera, the GNSS receiver, the display and the link were checked afterwards. 19 packages are held back on
  purpose: kernel, firmware, bootloader, Wi-Fi firmware and the camera applications, which change the boot chain or
  the camera stack and need someone next to the Pi (`sudo apt-mark showhold` lists them; `sudo apt-mark unhold …`
  releases them).
* **Legacy prototype removed.** `hitl/`, `src/hitl/` and `rpi_hitl_deployment/` (residual risk 11) are no longer
  in the working tree.
* **Residual risks 3, 7, 9 and 11 above** are changed by this: 3 now has measured limits (the report, §4.12), 7 is
  reduced to the captured UAV, 9 to the 19 held packages, 11 is closed.

### Tests after the second pass

| Test | Result |
|---|---|
| Unit tests, ground station (laptop) | 211 run, all pass. 26 more than after the first pass: 18 for file format 2 (`tests/test_sealing.py`), 2 for the change of position cell, 1 for the flood ration, 5 for the ground station's video path (`docs/TEST_REPORT.md` §15.5 no. 8 and 9; not security changes) |
| Unit tests, Raspberry Pi, on the code as finally deployed | 203 run, all pass; 8 skipped there (4 need the detection models or OpenCV, 3 need node.js, 1 needs root). The deployed files are byte for byte the repository's (85 of 85) |
| Attack experiments on both machines | 27 kinds, all PASS: 339,084 attack attempts, none accepted; 192,000 records sealed by racing threads, no nonce used twice; every genuine connection made under every flood rate; no timing difference found (largest \|*t*\| 2.7 in five rounds per machine; the leaking control was found in every round) |
| Stored-data audit on both machines | 35 PASS, 2 WARN, 0 FAIL. It now also checks the signatures of stored files against the pinned UAV key, the presence of both recording keys, the SSH key exchange, and that no classical-only public-key algorithm appears in the code. The warnings are the four photos of finding 18 and one telemetry row from the second in which the GNSS receiver acquired its fix |
| End-to-end pipeline on the real hardware | 42 PASS, 1 FAIL: the failing check is the steadiness of the laptop's own clock (the WSL virtual machine's clock ran 5.9 % fast), not the link. No record rejected, no frame lost during six rekeys, stored photo and recording fetched, signature and hash verified, decrypted |
| Dashboard in a real (headless) browser, policy enforced | 93 PASS, 0 FAIL: every control used with the content-security policy in force, no script error, no failed request, no HTTP error |
| Measurement campaign on the final code | 450 of 450 session operations succeeded; 1 of 4,071 video frames lost during them; 10 of 23,485 frames lost in 13 minutes of streaming, none at a key change (`docs/TEST_REPORT.md` §15) |
| Raspberry Pi after the operating-system update | service active with 0 restarts, confinement rating 3.8, no error or warning in its journal over the last six hours of the session; camera (OV5647) detected and streaming; no security update pending (19 packages held, one more kept back by apt: `rpi-swap`) |
| Repository | `git fsck` clean; 3,960 tracked files, **nothing committed**: in the working tree 228 tracked files are deleted (the earlier prototype, its simulation scripts, results and plots, the earlier ns-3 module and its helper scripts; all still in the history, and the documents and the ns-3 module also in `docs/legacy/`), 3 are modified (`.gitignore`, `README.md`, `kyber6g-website/package-lock.json`), and the present system is in 14 untracked entries. No password, private key or token is in any of them (the audit's own check, and `run/kyber6g.sh audit`) |

---

## 9. Third pass: sealed audio (5 October 2026)

The audio path added on 5 October (`kyber6g/audio/`, `docs/SECURITY_ARCHITECTURE.md` §9c) was reviewed and attacked
the same way: read, then attacked with experiments on both machines (`docs/AUDIO_CRYPTANALYSIS_REPORT.txt`), then
run under loss on the real link. Three of the defects that turned up bear on security or availability and are
numbered here; the others are in `docs/TEST_REPORT.md` §16.5.

| # | Area | Finding | Severity | Status |
|---|---|---|---|---|
| 24 | Sealed audio, shape | The size of a clip's blocks followed the largest frame of the stream: with a variable bit rate, quiet and loud recordings had blocks of different sizes | Low (one number per clip) | fixed by a setting (`audio_frame_cap`); without it a documented limit |
| 25 | Sealed audio, UAV memory | The sealer held the root of the clip's key tree until the clip was closed: a UAV taken while recording would have given up the blocks already sealed | Medium | fixed (`SealerTree`) |
| 26 | Sealed audio, live path | The ground station asked once for the blocks a live clip was missing; with the request or its answer lost, the clip stayed incomplete (2 of 12 clips in one run under loss), and a worker thread waited 25 s for the acknowledgement | Medium (availability) | fixed (the request is not waited for and is repeated) |

Nothing was found that lets a changed, forged, borrowed or mislabelled clip, live block or excerpt through, or that
gives the receiver of an excerpt any key but those released: 12,646 attempts in 46 kinds of experiment on the two
machines, none accepted, and no exception other than the one refusal the code promises.

### Tests after the third pass

| Test | Result |
|---|---|
| Unit tests, ground station (laptop) | 255 run, all pass; 44 more than after the second pass, all in `tests/test_audio.py` |
| Unit tests, Raspberry Pi, on the code as finally deployed | 247 run, all pass; 8 skipped there (the same as before). The deployed files are byte for byte the repository's (93 of 93) |
| Attack experiments on sealed audio, both machines | 46 kinds, all PASS: 12,646 attempts, none accepted; 6 controls as they must be; no key, commitment or tag twice among 5,280 blocks; no difference in the time of a refusal by the place of the change |
| A clip sent while it is sealed, 0 to 20 % of the datagrams dropped | 12 of 12 completed from the UAV's card and verified against the signed root |
| Stored-data audit on both machines | 41 PASS, 2 WARN, 0 FAIL; it now also verifies every sealed clip at the ground station and on the UAV's card, the chain, and that no plain audio is left on the UAV |
| End-to-end pipeline on the real hardware | 52 PASS, 1 FAIL (the laptop's clock, as before) |
| Dashboard in a real (headless) browser, policy enforced | 104 PASS, 0 FAIL |
| Raspberry Pi | service active with 0 restarts, confinement rating 3.8 (the audio directory added to the three it may write), no error in its journal |

Residual risks added by the audio path: the ground station's two recording keys open every clip sealed to them (no
forward secrecy for stored data, as for photos and recordings); a file that stands in for the microphone lies on the
card in the clear until it has been sealed; overwriting keys in memory is best effort in this language runtime; what
a clip shows without any key is listed in the report (§10).

## 10. Fourth pass: the post-quantum part made rigorous, and the motion watch (5 October 2026)

The question of this pass was not "can it be broken by trying" (sections 8 and 9) but "what exactly is claimed, and
what stands behind each claim". The protocols were written as ProVerif models and checked under four attackers
(`formal/`); the libraries were held against NIST's known-answer vectors on both machines
(`kyber6g/tools/pq_conformance.py`); the claims and their assumptions were written down
(`docs/SECURITY_PROOFS.md`); a bill of materials is generated from the code (`docs/CBOM.json`). Two defects turned up
on the way and are numbered here.

| # | Area | Finding | Severity | Status |
|---|---|---|---|---|
| 27 | Keys read from files and from the peer (`crypto/identity.py`, `recording/sealing.py`) | The length of a public key, a secret key or a signature was not checked before it was given to liboqs. Its Python binding copies a key into a buffer of the right size and fills a short one with zeros without a word: a recording key file cut short would have encapsulated to a key nobody holds, and every photo, recording and clip sealed with it would have been lost with no error | Medium (silent loss of stored data after a damaged or wrong key file; no way in for an attacker was found) | fixed: `identity.sized()` on every key from a file or from the peer; `verify()` refuses a key or a signature of the wrong length and takes no error of the library for "valid" |
| 28 | Start of both programs (`crypto/selftest.py`, `uav/main.py`, `ground/main.py`) | Nothing checked, when a program started, that the cryptographic libraries on that machine compute what they should. A wrong or half-installed library would have shown at the first handshake at the earliest, or (a broken generator, a mismatched pair of keys) not at all | Low | fixed: a self-test at every start, in the manner of FIPS 140-3 power-up tests: a known answer for every primitive in use (among them a NIST vector for ML-KEM-1024 key generation), and sign/verify and encapsulate/decapsulate with the machine's own keys. A failure stops the program. The result is in the status and on the SECURITY tab |

What the models say about the design is in `formal/RESULTS.md` and `docs/SECURITY_PROOFS.md`. No protocol flaw was
found. Three limits that were known and stated in words are now shown by a tool, with the attack trace:

* the 1-RTT Cached RapidRekey does not heal a session whose secret had leaked;
* the PQ ratchet heals only if the attacker does no more than listen while it runs;
* with both key exchanges broken nothing is left, and with ML-DSA-87 broken (not modelled) an active attacker could
  impersonate either side from then on: authentication is post-quantum only, not hybrid.

**The motion watch** (`camera/motion.py`, new in this pass) adds one command and one kind of report. What bears on
security was read and tested: the reports are text in the authenticated status stream and are validated at the
ground station before they are shown or stored (`clean_motion`; anything else is counted as malformed and
dropped); the self-test command takes numbers within fixed limits (at most 48 cases, 16 to 64 looks) and returns
counts only: the pictures it takes are never stored and never sent; a photo taken on motion is sealed and signed
like any other and rationed (one in 15 s); the watch runs at lower priority than the video. Its defects were of
another kind (what it reports, not what it lets in) and are in `docs/TEST_REPORT.md` §17.

### Tests after the fourth pass

| Test | Result |
|---|---|
| Protocol models in ProVerif 2.05, four attackers (`formal/run.py`) | 46 runs, 177 queries, every one as expected: 100 claims proved, 77 that must be false are false |
| Known answers for every primitive, both machines (`pq_conformance.py`) | 162 of 162 (NIST ACVP vectors for ML-KEM-1024 and ML-DSA-87, RFC vectors for the rest) |
| Self-test at the start of both programs | ground station 18 checks in 35 ms, UAV 16 checks in 18 ms; passed (checked again by the pipeline test) |
| Unit tests, ground station (laptop) | 310 run, all pass; 55 more than after the third pass (`tests/test_pq.py`, `tests/test_motion.py`, and one for a GNSS report without a position) |
| Unit tests, Raspberry Pi, on the code as finally deployed | 302 run, all pass; 9 skipped there. The deployed files are byte for byte the repository's (102 of 102) |
| End-to-end pipeline on the real hardware, three runs | 58 PASS, 3 FAIL each time; none of the failures is a check of the link's security (no authentication failure, replay or malformed record on the real link in any run). They are the laptop's clock; once a frame-rate reading of 0.0 and twice the motion watch's self-test in a lamp-lit room; and the stored-data audit below (`docs/TEST_REPORT.md` §17.7) |
| Dashboard in a real (headless) browser, policy enforced | 111 PASS, 0 FAIL |
| Stored-data audit on both machines | 40 PASS, 2 WARN, 1 FAIL. The failure is one telemetry row of 176,071 that says "3D fix" and has no position (gpsd's first report after the receiver had stood still for 58 s; nothing was invented, and the reader now takes such a report as no fix). The audit itself had stopped with an exception at that row, so that its checks of the stored photos, recordings, clips, files and of the UAV were not made until it was repaired the same evening. The two warnings are the old ones (finding 18's four photos; one row from the second of a first fix) |
| Raspberry Pi | service active, not restarted by systemd, not throttled; confinement rating 3.8; no error in its journal (four refusals of commands that the tests send on purpose) |

Residual risks added in this pass: none to the link. The proofs are symbolic (the primitives are taken as perfect)
and say nothing about side channels or about the implementation; the motion watch can be blinded by a scene (it then
reports nothing, `docs/TEST_REPORT.md` §17.4) and is not a safety function.
