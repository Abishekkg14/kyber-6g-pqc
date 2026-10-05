# Documents in this folder

## The secure link in `kyber6g/` (what the paper describes)

| Document | Content |
|---|---|
| [`SECURITY_ARCHITECTURE.md`](SECURITY_ARCHITECTURE.md) | The protocol as implemented: handshake, key schedule, record layer, rekeying, stored photos and recordings, where public-key cryptography is used, what is and is not claimed |
| [`CRYPTANALYSIS_REPORT.txt`](CRYPTANALYSIS_REPORT.txt) | The attacks an adversary can try, why each fails, and what happened when each was tried against the implementation on both machines (plain text, written from the experiment data by `bash run/kyber6g.sh report`) |
| [`AUDIO_CRYPTANALYSIS_REPORT.txt`](AUDIO_CRYPTANALYSIS_REPORT.txt) | Sealed audio: where six published audio-encryption schemes fall short, the scheme built here, every attack tried on it with its outcome on both machines, ciphertext statistics, cost, a clip sent live under loss, limits, and what in it is new and what is not (plain text, written from the experiment data by `bash run/kyber6g.sh report`) |
| [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) | Security and robustness review of October 2026: findings, fixes, tests, residual risks, what was not tested |
| [`SECURITY_PROOFS.md`](SECURITY_PROOFS.md) | What is proved, under which assumptions and by what: the hybrid combiner, the handshake, the cached rekey, the PQ ratchet, the record layer, stored files and sealed audio; the evidence for each claim (ProVerif model, test, known answer, attack experiment); what is not proved and must not be claimed |
| [`../formal/README.md`](../formal/README.md) | The ProVerif models, the four attackers, how to run them, and the result of every query (`../formal/RESULTS.md`) |
| [`CBOM.json`](CBOM.json) | Cryptographic bill of materials (CycloneDX 1.6): every algorithm, where it is used, its parameters and its level; written from the code by `bash run/kyber6g.sh cbom` |
| [`AUDIO_ON_A_UAV.md`](AUDIO_ON_A_UAV.md) | Whether a UAV can record sound at all: what two web pages on drone microphones say, what research does about rotor noise, the cases in which sealed audio from a UAV makes sense, the exceptions, the wording for the paper |
| [`TEST_REPORT.md`](TEST_REPORT.md) | Tests on the real hardware and what they measured |
| [`RESEARCH_REFERENCES.md`](RESEARCH_REFERENCES.md) | Which ideas from the literature were adopted and where they live in the code |
| [`../paper_figures/README.md`](../paper_figures/README.md) | Diagrams for the paper (19 figures) |
| [`../paper_plots/README.md`](../paper_plots/README.md) | Plots for the paper: measured (1 to 10, and 17 to 20 for sealed audio), simulated (11 to 16), the motion watch (21: generated scenes and the camera), what is proved and checked (22); the data behind them, how to rebuild them |
| [`../simulation/README.md`](../simulation/README.md) | The simulation: what is modelled, how it is calibrated and checked, the studies and the ablations, its limits |

## `legacy/`: the earlier study (kept for the record, not used in the paper)

The notes and documents of the first phase of the project: the project brief (`MASTER PROMPT PROJECT.txt`,
`final response.txt`, `implementation_plan.md`), the description of the earlier ns-3 model and prototype
(`kyber6g_master_spec.md`, `project_architecture.md`, `simulation-methodology.md`, `experiment-reproducibility.md`,
`technical_changes_report.md` / `.tex`, `KYBER_6G_COMPLETE_PROJECT_DETAILS.txt`, `Kyber_1024_Transition_Documentation.docx`,
`BENCHMARK_VERSION.md`, `known_limitations.txt`, `plot_regeneration_changelog.md`, `previous-vs-improved.md`,
`advantages-and-limitations.md`), and background (`literature_analysis.md`, `mathematical_proofs.md`, `security-model.md`),
and two archives: `ns3_pqc_security_module.tar.gz`, the earlier ns-3 module and its scratch programs, and
`paper_figures_v1_boxed.tar.gz`, the first (rejected) version of the paper's diagrams.

Before quoting anything from them, note:

1. **The earlier simulation results were withdrawn.** The earlier study's agreement between "hardware" and
   "simulation" values was true by construction: the simulated values were generated from the hardware values plus
   small random numbers, and no ns-3 run took part. Its code, results and plots were removed from the working tree in
   October 2026 (they remain in the git history); `simulation/` replaces it.
2. The prototype has never used a 5G or 6G radio. It runs over Wi-Fi; a 5G NR cell exists only in the simulation.
3. Some of these documents say "0-RTT" for the cached rekey. The rekey costs one round trip; the project's term is
   **1-RTT Cached RapidRekey**.
4. ML-KEM-1024 and ML-DSA-87 establish and authenticate the session and wrap and sign the stored files; the data
   itself (video, telemetry, files, audio) is encrypted with AES-256-GCM (or ChaCha20-Poly1305). No document should be
   read as claiming that the video or the audio is "post-quantum encrypted" as a whole.
