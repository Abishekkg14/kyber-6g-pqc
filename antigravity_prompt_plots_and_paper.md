# PROMPT FOR ANTIGRAVITY: Regenerate All Figures + Rewrite the Paper (Same IEEE Template, Updated Content — Kyber-768 → Dual-Tier Kyber-1024)

## 0. ROLE AND GROUND RULES (read first — these override anything below that conflicts)

You are correcting and extending a paper that already exists in this project's workspace:
**"MAC-Layer Hybrid Post-Quantum Key Exchange with Mobility Caching for 5G/6G Drone Swarms"**
(base file: `access_revised__1__.pdf`, IEEE Access, DOI 10.1109/ACCESS.2026.0000000).

This is a **journal-grade revision job**, not a rewrite-from-scratch job. You must:

- **Keep the exact same template/skeleton** the base paper uses: same section order, same
  heading levels, same subsection names, same number of major sections, same algorithm/table/
  equation numbering conventions (Algorithm 1, Eq. 1–9, Table 1–6, Fig. 1–9).
- **Only change what needs to change**: (a) figures that are wrong or inconsistent with their
  own captions/underlying data, (b) numeric/textual inconsistencies inside the base paper itself,
  (c) new content required to document the Kyber-1024 dual-tier addition.
- **Never invent numbers.** Every number in the revised paper and every data point in every
  regenerated plot must trace to an actual file in the IDE workspace (simulation output, config,
  log, notebook, CSV/JSON). If a number cannot be traced to a workspace artifact, mark it
  `[VALUE NOT FOUND IN WORKSPACE — DO NOT PUBLISH UNTIL SOURCED]` rather than guessing or
  silently reusing the base PDF's version of it.
- The base PDF's own numbers are **not automatically trustworthy** — see Section 1 below for the
  specific internal contradictions already found in it. Do not launder any of them into the
  revised paper by paraphrasing around them.
- Before writing or plotting anything, **enumerate every relevant file in the IDE workspace**
  (simulation scripts, NS-3 output logs, CSV/JSON result files, existing plot-generation code,
  notebooks, configs, any Kyber-1024 research-compilation docs) and build an index of what data
  actually exists. Do not start Task A or Task B until this index exists.

---

## 1. KNOWN ERRORS IN THE CURRENT PAPER — MUST BE FIXED, NOT REPRODUCED

These are real internal inconsistencies found by reading the current draft. Every one of these
must be resolved (using workspace-verified numbers) in the rewritten paper and in the regenerated
figures — not silently carried forward.

1. **Ciphertext vs. public-key size swapped in prose.** Table 2 lists Kyber-768 as
   `PK = 1184 B, CT = 1088 B`. But the Abstract, Section III-A, Section III-B, and Section V-B
   all repeatedly call **1184 bytes "the Kyber-768 ciphertext"** ("a 1184-byte Kyber-768
   ciphertext that fits inside a single 5G NR MAC PDU," "A Kyber-768 ciphertext is
   1184 bytes—approximately 14 times larger than an ECC public key"). Pick the correct value from
   the actual KEM implementation used in the workspace and use it consistently everywhere (prose,
   Table 2, Table 4 footnote, Fig. 3, Fig. 8).
2. **ECDH curve name is inconsistent.** Figures 2–5, 8, 9 and Table 2 all label the classical leg
   "X25519," but Table 3 ("ECDH Curve: NIST P-256") and Algorithm 1's key sizes imply a different
   curve. X25519 and P-256 are different curves with different key/shared-secret encodings — this
   is not a cosmetic difference. Confirm which curve the workspace's actual ECDH implementation
   uses and use that name everywhere.
3. **Security-bit figures disagree across the paper.** The Introduction/Contributions and
   Proposition 1 state the hybrid gives **128-bit classical / 168-bit quantum** security. Table 1
   and Table 2 both list Hybrid-768 as **"203-bit quantum"** — a different number, and identical
   to the number given for ML-KEM-768 *alone* in the same table, which is also suspicious (the
   hybrid should not report the same quantum-security figure as the standalone KEM in a table meant
   to show comparative security). Also Section III-A's own MLWE paragraph says k=3 yields
   "192 bits of classical security and 168 bits of quantum security" — a third figure (192, not
   128 or 203) for classical security. Reconcile these to one internally consistent number set,
   sourced from the actual security analysis in the workspace.
4. **Table 4's own footnote formula does not reproduce Table 4's own totals.** Footnote: `Total =
   max(ECDH_KG, Kyber_KG) + Encaps + Decaps + HKDF + 2×T_RTT`, with `T_RTT = 0.4 ms`. Plugging in
   the Drone-column numbers (`max(2.10,1.85)=2.10`, `+1.78+1.91+0.12+0.8`) gives **6.71 ms**, not
   the **5.76 ms** printed as the "Total Handshake (parallel)" row. The Edge column has the same
   problem. Recompute this table directly from the workspace's timing data and make sure the
   printed total actually equals the stated formula, or correct the formula/column semantics
   (e.g., if Encaps runs at the edge and Decaps at the drone, they should not both be summed into
   a single "drone total" — clarify which operations belong in which column before re-totaling).
5. **Figure 4's caption does not match what the figure plots.** Caption claims a comparison of
   "5G mmWave (28 GHz) vs. 6G THz (0.3 THz)" and says it shows "packet delivery ratios (PDR)." The
   actual chart is titled "5G vs Projected 6G: KE Handshake Latency," its legend says "5G NR
   (3.5 GHz)" and "6G THz (140 GHz) [PROJECTED]," and it plots latency only, no PDR series. Rewrite
   the caption to match the real chart, and confirm the frequency values in the caption, title, and
   legend all agree with each other and with Table 3.
6. **Figure 5's caption does not match its own axis.** Caption says "varying mobility speeds
   (10 m/s to 50 m/s)"; the plotted x-axis runs 0–120 m/s. Table 3 also states "Maximum Drone
   Velocity: 25 m/s" as the simulated configuration, which is inconsistent with a 120 m/s plotted
   range. Decide the actually-simulated velocity range from the workspace's mobility-model config
   and make caption, axis range, and Table 3 agree.
7. **Table 6 is incomplete/inconsistent.** ECC and Kyber-768 rows each report three sample sizes
   (n = 10, 28, 56), but the "Hybrid (Cached)" rows only report n = 10 and n = 28 — the n = 56 row
   is missing. Also the three ECC/Kyber-768 rows are not labeled with what differs between them
   (different swarm sizes? different mobility speeds?) — add a labeling column so each row's
   condition is unambiguous, sourced from the actual sweep the workspace ran.
8. **Fig. 9's caption references "Cached ML-KEM-768"** but the plotted legend only shows
   "X25519 / ML-KEM-768 / Hybrid" with no explicit "cached" distinction — clarify whether the
   "Hybrid" series in Fig. 9 is the cached or uncached hybrid, and say so explicitly in both the
   caption and the legend.

Do not fix these by picking whichever number is more convenient — fix them by finding the actual
computed value in the workspace and making every mention of that quantity agree with it.

---

## 2. TASK A — REGENERATE EVERY FIGURE, CORRECTLY

### A.1 Full figure inventory (base paper — confirm each against workspace data before touching it)

| # | Current title/subject | Data it must reflect | Status |
|---|---|---|---|
| Fig. 1 | System architecture (drone swarm, gNB, MEC, Hybrid Crypto Engine) | Topology diagram — verify component labels match actual code architecture (drone/gNB/MEC/AMF roles) | Check diagram accuracy, not numeric |
| Fig. 2 | Six-step hybrid handshake sequence diagram | Must match Algorithm 1 exactly, step-for-step | Cross-check against Algorithm 1 pseudocode in workspace |
| Fig. 3 | IP fragmentation by KEM mode and MTU (X25519 / ML-KEM-512/768/1024 / Hybrid-768) | Fragment counts per PK/CT size vs. MTU 1500B / GTP-U 1400B / IPv6 1280B | Recompute from actual byte sizes (fixed per item 1 above) and real MTU thresholds |
| Fig. 4 | Handshake latency, 5G vs. 6G-projected | X25519 / ML-KEM-768 / Hybrid latency bars, two frequency conditions | **Flagged — caption/chart mismatch, see §1.5** |
| Fig. 5 | Handshake latency vs. mobility speed | ML-KEM-768 uncached / cached(PSK) / X25519, across simulated speed sweep | **Flagged — caption/axis mismatch, see §1.6** |
| Fig. 6 | End-to-end application latency vs. swarm size | X25519 / ML-KEM-768 / ML-KEM-768(PSK), vs. 10 ms URLLC line | Verify swarm-size range matches actual Monte Carlo sweep (Table 3 says 1–80 UEs) |
| Fig. 7 | Handshake success rate vs. channel packet loss (0–10%) | X25519(no frag) / ML-KEM-768 / Hybrid | Confirm modeled vs. simulated — caption says "(MODELED)"; verify this is disclosed consistently in text |
| Fig. 8 | Key exchange message sizes by KEM mode (PK vs. CT, bytes) | X25519 / ML-KEM-512/768/1024 / Hybrid-768 | **Flagged — must use corrected PK/CT values, see §1.1** |
| Fig. 9 | Radar/normalized comparison (Security, Latency, Size, Energy, Frag) | X25519 / ML-KEM-768 / Hybrid | **Flagged — cached/uncached ambiguity, see §1.8** |

### A.2 New figures required for the Kyber-1024 dual-tier addition (only if workspace data exists)

Add these **only if the corresponding simulation/recomputation actually exists in the workspace**.
Do not create a new figure number for a metric that was never actually recomputed for the
Kyber-1024 tier — state in the changelog that it was skipped and why.

- **Fig. 10 — Dual-tier handshake latency comparison**: X25519 / Hybrid-768 / Hybrid-1024 across
  swarm size, with the 10 ms URLLC line, showing where each tier stays inside/outside budget.
- **Fig. 11 — Fragmentation overhead, Kyber-1024 vs. Kyber-768**: fragment count and resulting
  retransmission-driven latency penalty for the 3-fragment Kyber-1024 ciphertext vs. the
  2-fragment Kyber-768 ciphertext, under the same MTU assumptions as Fig. 3.
- **Fig. 12 — MEC/edge acceleration utilization**: drone-side vs. edge-side crypto time for
  Kyber-1024, mirroring Table 4 but for the new tier — only if the workspace actually benchmarked
  Kyber-1024 keygen/encaps/decaps on both platforms.
- **Fig. 13 — Per-leg security category / two-tier policy map**: which drones/links use the
  Kyber-768 tier vs. the Kyber-1024 tier and under what trigger condition (e.g., static
  infrastructure keys vs. high-mobility session keys) — only if this policy was actually
  implemented/simulated, not just proposed in prose.

If the workspace contains additional recomputed metrics not listed here (e.g., a side-channel
budget or energy-tier comparison), add them as Fig. 14+ following the same rule: real data only.

### A.3 Method for every figure (Fig. 1–13+)

1. Locate the exact workspace data file behind the figure before touching the plot.
2. Re-derive the figure's caption and axis/legend labels from that data — do not keep an old
   caption that doesn't match the chart, even if only the caption changed.
3. Do not extend any series beyond the range actually simulated (e.g., do not plot mobility speed
   past what Table 3 / the actual sweep config covers, once that's corrected).
4. Keep one consistent color per series across the *entire* figure set: X25519, ML-KEM-512,
   ML-KEM-768, Hybrid-768, ML-KEM-1024, Hybrid-1024 each get one fixed color used everywhere they
   appear.
5. Every latency-vs-X plot keeps the 10 ms URLLC reference line where the original had one.
6. Show 95% CI (shaded band or error bars, matching the original style) wherever the underlying
   data has multiple Monte Carlo runs (Table 3 says 30–50 runs per configuration — CIs should be
   visibly tight, not decorative).
7. Export at **minimum 300 DPI**, vector-preferred (SVG/EPS/PDF) with a high-res PNG fallback for
   Word embedding. Sans-serif axis fonts, no default-software gridline clutter, legend inside or
   clearly anchored, no overlapping data labels.
8. Do not reuse or crop any image from the original PDF. Every figure is rendered fresh from data.

### A.4 Output for Task A

- One image file per figure: `fig01_system_architecture.png` ... `fig13_...png` (and beyond, as
  applicable), 300+ DPI.
- A **plot regeneration changelog** (markdown) with one entry per figure: workspace source file(s),
  what was wrong before, what was corrected, and — for new figures 10–13+ — whether the underlying
  Kyber-1024 data actually exists in the workspace or the figure was skipped and why.

---

## 3. TASK B — REWRITE THE PAPER IN THE SAME TEMPLATE, WITH CORRECTED + NEW CONTENT

### B.1 Keep the exact same skeleton as the base paper

Do not change the template. The revised paper must keep the same top-level structure, in this
order, with the same heading style (IEEE Access two-column, Abstract/Index Terms block, Roman-
numeral sections):

1. **Title / Author block / Abstract / Index Terms** — update the Abstract to reflect the added
   Kyber-1024 tier and the corrected numbers (do not just re-copy the old abstract's claims);
   Index Terms gains "Kyber-1024," "dual-tier security," etc. if the workspace's actual
   implementation adds them.
2. **I. Introduction** — same subsection flow (motivation → SWaP constraint → contributions list
   → paper organization). Update the numbered contributions list to include the dual-tier
   decision as a new contribution, stated only as it was actually implemented.
3. **II. Related Work and Gap Analysis** — same subsection groupings (drone/cellular, standard
   security, quantum threats/lattice crypto, PQC over wireless, simulation frameworks, Table 1
   comparison). Table 1 gets corrected/extended per §1.3 and, if applicable, a new row for
   Kyber-1024-capable prior work if such work exists in the actual references used.
4. **III. Methodology** — same subsection flow (A. Cryptographic and Latency Models,
   B. Threat Model and Radio Channel, C. Queuing/Energy/Security Argument). Table 2 and the MLWE/
   HKDF/handshake-latency equations get corrected per §1.1, §1.3, §1.4. Add the Kyber-1024
   parameter row to Table 2 (it is already implied — `k=4`, 1568/1568 bytes — verify against the
   workspace, not against memory) and explain, in the same prose style as the existing "Choice of
   Kyber-768" subsection, the actual criterion used to decide *when* Kyber-1024 is invoked in the
   dual-tier design.
5. **IV. Proposed System Architecture** — same subsection flow (A. Network Topology,
   B. Hybrid Handshake Protocol, C. Mobility-Aware Public Key Caching). Update Fig. 1/Fig. 2 and
   Algorithm 1 only if the dual-tier logic actually changes the handshake steps (e.g., a tier-
   selection step); if the six-step handshake is unchanged and only the KEM parameter set toggles,
   say that explicitly rather than inventing new steps.
6. **V. Performance Evaluation** — same subsection flow (A. Experimental Setup and Cryptographic
   Benchmarks, B. Results and Scalability Analysis). Table 3/Table 4/Table 5/Table 6 corrected per
   §1.4, §1.7; new results for the Kyber-1024 tier and the dual-tier comparison go here, tied to
   the new Fig. 10–13 from Task A.
7. **VI. Conclusion and Future Work** — update to reflect what the dual-tier transition actually
   achieved (per workspace results, not aspirational claims), keep the same
   Application Domains / Limitations / Future Research Directions subsection pattern. The
   Limitations subsection must explicitly retain or update the base paper's 7 numbered limitations,
   adding any new ones introduced by the Kyber-1024 tier (e.g., higher energy draw, 3-fragment
   packet loss sensitivity) and removing any that the transition actually resolved.
8. **References** — keep the existing numbered list, renumbering only if the corrected security
   analysis or the Kyber-1024 addition required citing sources not already listed. Do not add
   citations that were not actually consulted in the workspace's own research compilation.

### B.2 Content rules

- **No new plots or numbers without a workspace source.** If a Kyber-1024 metric is discussed in
  prose but was never actually measured in the workspace, write it as a stated design decision or
  future-work item — not as a measured result with a fabricated figure.
- **Every number that appears more than once in the paper must be identical everywhere** (Abstract,
  Introduction contributions list, Table 2/3/4, Section V prose, Conclusion). Do a final numeric
  consistency pass before finalizing — this is exactly the failure mode listed in §1.
- **Do not silently fix an error by rewording around it.** If a number changes, say so is
  traceable: the corrected figure should read as a clean, correct statement, not a hedge.
- Maintain the paper's existing formal, IEEE-technical tone; no marketing language, no
  unsupported superlatives ("groundbreaking," "unprecedented," etc.), no claims not backed by a
  cited source or a workspace-computed result.

### B.3 Output format for Task B

- Deliver as a proper IEEE Access-style two-column manuscript (Word .docx or LaTeX, matching
  whatever the workspace's existing paper source format is — do not switch formats).
- Consistent Heading 1/2/3 mapping to Section numbering above, auto-numbered figures/tables/
  equations, and a References list that matches in-text citation numbers exactly.
- Embed only the Task A regenerated figures — never the original PDF's images.

---

## 4. VERIFICATION CHECKLIST (confirm before declaring done)

- [ ] Every regenerated figure's data was traced to a specific workspace file before rendering.
- [ ] All 8 flagged inconsistencies in §1 are resolved consistently across every place they appear
      (prose, tables, figure captions, abstract).
- [ ] No fabricated Kyber-1024 series/figure appears where the workspace has no corresponding data;
      any skipped new figure (10–13+) is logged with a reason in the changelog.
- [ ] The plot regeneration changelog exists and cites a workspace source file per figure.
- [ ] The rewritten paper keeps the base paper's exact section skeleton (Abstract → Index Terms →
      I–VI → References), with only content, tables, figures, and numbers updated.
- [ ] Every repeated numeric claim is identical everywhere it appears in the final paper.
- [ ] Only the newly regenerated figures are embedded — none from the original PDF.
- [ ] Every claim/number in the revised paper is traceable to a workspace artifact or an actual
      cited source, never to memory or to an uncorrected base-PDF number.
