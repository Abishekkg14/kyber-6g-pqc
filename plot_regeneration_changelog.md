# Plot Regeneration Changelog (Task A.4)

## Figure 4: Post-Quantum Security Strength Score (`04_security_strength.png`)
* **Data Source:** `simulation_results.json` (metric: `security_strength_score`).
* **Corrections Made:** Fixed previous axis label ambiguity by explicitly denoting equivalent symmetric security bits and plotting against NIST Level 1 and Level 5 reference lines.
* **Tiered-Model Addition:** Added the Kyber-1024 series per the workspace data, confirming Level 5 security (256-bit equivalent).

## Figure 5: Packet Delivery Ratio vs Swarm Size (`05_packet_delivery_ratio.png`)
* **Data Source:** `simulation_results.json` (metric: `packet_delivery_ratio`).
* **Corrections Made:** Corrected caption to accurately reflect that data is scaled as a percentage (%), not an absolute fraction, and bound the Y-axis to 100%.
* **Tiered-Model Addition:** Added Hybrid-Kyber1024-ECDH and pure ML-KEM-1024 series, proving that PDR remains >95% under DORA.

## Figure 7: Total Energy per Handshake & Projected Battery Life (`07_energy_battery.png`)
* **Data Source:** `simulation_results.json` (metrics: `total_energy_mj` and `estimated_battery_life_minutes`).
* **Corrections Made:** Modified chart to dual-axis/subplot to show both energy per handshake (mJ) and projected battery life (minutes) as computed by the model. 
* **Tiered-Model Addition:** Included Kyber-1024 data, noting the ~18.4 mJ modeled energy.

## Figure 8: Queueing Delay (`08_queueing_delay.png`)
* **Data Source:** `simulation_results.json` (metric: `mac_queue_delay_us`).
* **Corrections Made:** Clarified caption to explicitly refer to M/G/1 Pollaczek-Khinchine delays, correcting previous M/M/1 assumptions that incorrectly underestimated the delay for large PQC payloads.
* **Tiered-Model Addition:** Hybrid-Kyber1024-ECDH micro-bursts included, establishing accurate bounds for the 10ms URLLC deadline.

## Figure 12: Kyber Level Selection Rationale (`12_kyber_level_selection.png`)
* **Data Source:** Recomputed documented modeled parameters inside `build_results_and_plots.py` derived from hardware profile scaling constraints.
* **Corrections Made:** Consolidated size, latency, and security into a single 3-bar comparison for clear trade-off analysis.
* **Tiered-Model Addition:** Included Kyber-512, ML-KEM-768, and ML-KEM-1024, explicitly validating why Kyber-1024 was chosen.

## Figure 13: Handoff Latency CDF (`13_handoff_latency_cdf.png`)
* **Data Source:** `simulation_results.json` (metric: `handoff_latency_cdf`).
* **Corrections Made:** Fixed axis limits and unified line styling for clarity.
* **Tiered-Model Addition:** Showcases exactly how Edge/MEC mobility caching prevents full re-authentication for Kyber-1024 drones switching access points.
