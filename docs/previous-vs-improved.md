# Previous vs Improved

## Summary

| Dimension | Previous | Improved | Evidence |
|-----------|----------|----------|----------|
| Kyber levels | CLI not propagated | 512/768/1024 wired | `KyberLevelPropagationTest` |
| Hybrid HKDF | Random XOR (mismatched UE/gNB) | Deterministic + encaps cache | `HybridDerivationConsistencyTest` |
| Caching | MEC delay flag only | TTL, revocation, stale, hit rate | `PqcKeyCache` + tests |
| Energy | Fixed 12096 µJ | Multi-component model + battery | `07_energy_battery.*` |
| Scenarios | LOS, fixed backhaul | NLOS, core/backhaul CLI | `PqcScenarioConfig` |
| Statistics | 12 single runs | 30+ Monte Carlo + 95% CI | `aggregate_results.py` |
| CLI | 6 args | Full matrix (nDrones, numRuns, hardwareProfile, …) | `drone-swarm-pqc-sim --help` |
| Tests | 6 | 16 | `pqc-security` suite PASS |
| Plots | 11 PNG, ±σ | PNG/SVG/PDF + CI + dashboard | `updated_access_plots_2026/` |
| Docs | 1 advantages doc | 4 research methodology docs | `docs/` |

## Guide comment mapping

1. **Innovation (MAC/RRC, caching, hybrid, scalability)** — RRC→PDCP flow documented; cache metrics; swarm sizes to 200
2. **Evidence-backed claims** — CI on plots; modeled fields labeled
3. **Quantitative outputs** — 20+ CSV metrics including energy, cache, security bits
4. **Methodology gaps** — Kyber level plot, parallel handshake, hardware profiles, NLOS, energy model, security cache
5. **Architecture gaps** — PDCP KDF chain, edge backhaul CLI, 5G-AKA extension point in security-model.md
6. **Evaluation gaps** — 30 runs, comparisons, scalability, attack-cost plot
7. **Previous vs improved** — this document + plot `10_previous_vs_improved`

## Remaining limitations

- Simulated crypto (not liboqs)
- NR handover algorithm not wired in this NR module build
- Energy from assumed power tables
- 200-drone runs may require significant wall-clock time
