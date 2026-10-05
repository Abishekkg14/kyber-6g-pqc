# Machine-checked models of the Kyber-6G protocols

ProVerif models of what the two ends say to each other and of what is written to storage, each run under four
attackers. What the results mean, and what they do not, is in [`docs/SECURITY_PROOFS.md`](../docs/SECURITY_PROOFS.md);
the result of every query of the last run is in [`RESULTS.md`](RESULTS.md) (and `results.json`).

```bash
bash run/kyber6g.sh formal          # = python3 formal/run.py : 46 runs, 177 queries, about 30 s
```

The script fails if a result differs from what `run.py` says it must be, or if ProVerif cannot decide a query.

## Files

| file | what it models (code it follows) |
|---|---|
| `primitives.pvl` | ML-DSA-87, ML-KEM-1024, X25519, SHA-256 / HMAC / HKDF, AES-256-GCM as ProVerif sees them; the labels |
| `attacker_classical.pvl` | an attacker who breaks nothing |
| `attacker_shor.pvl` | X25519 broken: the scalar follows from the public point (a quantum computer) |
| `attacker_mlkem.pvl` | ML-KEM-1024 broken: the secret key follows from the public key |
| `attacker_both.pvl` | both broken. Secrecy must then FAIL: the run that shows a model is able to fail |
| `handshake.pv` | the full handshake, any number of sessions, a second pinned UAV whose key the attacker has, both signing keys leaked afterwards (`crypto/handshake.py`: `ClientHandshake`, `ServerHandshake`) |
| `cached_rekey.pv` | 1-RTT Cached RapidRekey (`build_rekey_request`, `server_process_rekey`, `client_process_rekey_resp`) |
| `pq_ratchet.pv` | the PQ ratchet inside a session (`PQRatchetInitiator`, `pq_ratchet_respond`, `_pq_mix`) |
| `pq_ratchet_passive.pv` | ... after the old master secret leaked, the attacker listening: the session heals |
| `pq_ratchet_active.pv` | ... the attacker active at that moment: it does not (expected to fail) |
| `sealed_file.pv` | stored photos, recordings and audio clips: hybrid key wrap and the UAV's signature (`recording/sealing.py`) |
| `leak_*.pvl`, `file_leak_*.pvl` | what leaks and when, one file per case; a model is run once with each |
| `run.py` | runs everything, compares with the claims, writes `RESULTS.md` and `results.json` |

## ProVerif

Version 2.05 (B. Blanchet, V. Cheval, M. Sylvestre; GPL), built from the source archive of
<https://bblanche.gitlabpages.inria.fr/proverif/> with OCaml from the distribution:

```bash
sudo apt-get install ocaml-nox ocaml-findlib
curl -fsSLO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05 && ./build -nointeract
```

`run.py` looks for `proverif` on the PATH, in `/root/tools/proverif/` and in `~/tools/proverif/`, or takes `--proverif PATH`.

## Reading a result

A query that is a **claim** must come out `true`. Next to the claims stand queries that must come out `false`:

* the same secrecy or agreement question with the decisive scheme broken or the decisive key leaked (for example
  both key-establishment schemes broken, or both recording keys stolen): ProVerif must find the attack;
* one reachability question per model, written as "the protocol never finishes": it must be false, i.e. the model
  can run to the end.

They are there because a model that proves everything, whatever is broken, proves nothing.
