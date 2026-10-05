# Build report of the paper's plots

Built 2026-10-05 22:28. Palette: series stay apart and stand out of the page (4 of the validator's rules of taste not met: see palette.txt) (`palette.txt`).

| plot | page (mm) | fonts in the PDF | smallest text (pt) | PNG at 600 dpi (px) | EPS width (mm) | PDF (kB) | checks |
|---|---|---|---|---|---|---|---|
| plot01_crypto_primitives | 190.00 × 78.00 | Arial | 7.0 | 4488 × 1842 | 190.1 | 37 | ok |
| plot02_handshake_latency | 190.00 × 70.00 | Arial Bold, Arial | 6.5 | 4488 × 1653 | 190.1 | 54 | ok |
| plot03_wire_bytes | 90.00 × 52.00 | Arial | 6.5 | 2125 × 1228 | 90.3 | 33 | ok |
| plot04_aead_throughput | 190.00 × 62.00 | Arial Bold, Arial | 6.5 | 4488 × 1464 | 190.1 | 46 | ok |
| plot05_timeline | 190.00 × 104.00 | Arial Bold, Arial | 6.5 | 4488 × 2456 | 190.1 | 72 | ok |
| plot06_loss | 190.00 × 66.00 | Arial Bold, Arial | 6.5 | 4488 × 1559 | 190.1 | 55 | ok |
| plot07_latency | 190.00 × 68.00 | Arial Bold, Arial | 6.5 | 4488 × 1606 | 190.1 | 59 | ok |
| plot08_media_protection | 190.00 × 122.00 | Arial Bold, Arial | 6.5 | 4488 × 2881 | 190.1 | 63 | ok |
| plot09_cipher_statistics | 190.00 × 104.00 | Arial Bold, Arial | 6.5 | 4488 × 2456 | 190.1 | 1223 | ok |
| plot10_attacks | 190.00 × 112.00 | Arial Bold, Arial | 6.5 | 4488 × 2645 | 190.1 | 61 | ok |
| plot11_sim_validation | 190.00 × 126.00 | Arial Bold, Arial | 7.0 | 4488 × 2976 | 190.1 | 75 | ok |
| plot12_sim_swarm | 190.00 × 70.00 | Arial Bold, Arial | 7.0 | 4488 × 1653 | 190.1 | 54 | ok |
| plot13_sim_storm | 190.00 × 64.00 | Arial Bold, Arial | 7.0 | 4488 × 1511 | 190.1 | 55 | ok |
| plot14_sim_mobility_range | 190.00 × 66.00 | Arial Bold, Arial | 6.5 | 4488 × 1559 | 190.1 | 50 | ok |
| plot15_ablation_crypto | 190.00 × 132.00 | Arial Bold, Arial | 6.5 | 4488 × 3118 | 190.1 | 57 | ok |
| plot16_ablation_design | 190.00 × 128.00 | Arial Bold, Arial | 7.0 | 4488 × 3023 | 190.1 | 55 | ok |
| plot17_audio_statistics | 190.00 × 104.00 | Arial Bold, Arial | 6.5 | 4488 × 2456 | 190.1 | 129 | ok |
| plot18_audio_shape | 190.00 × 98.00 | Arial Bold, Arial | 7.0 | 4488 × 2314 | 190.1 | 56 | ok |
| plot19_audio_cost | 190.00 × 66.00 | Arial Bold, Arial | 7.0 | 4488 × 1559 | 190.1 | 50 | ok |
| plot20_audio_attacks | 190.00 × 112.00 | Arial Bold, Arial | 6.5 | 4488 × 2645 | 190.1 | 60 | ok |
| plot21_motion_watch | 190.00 × 124.00 | Arial Bold, Arial | 6.5 | 4488 × 2929 | 190.1 | 63 | ok |
| plot22_proof_matrix | 190.00 × 117.00 | Arial Bold, Arial | 6.5 | 4488 × 2763 | 190.1 | 62 | ok |

Limits: width 90.0 or 190.0 mm (± 0.2), all fonts embedded and Arial only, no text under 6.5 pt (sizes as set when
drawing, cross-checked against the size of every word found in the PDF), PNG width 2126 or 4488 px. Grey-scale previews: `gray/`.

## What each plot was drawn from

* `crypto_primitives`: `{"n": 300, "laptop_clock_rate": 1.002497}`
* `handshake_latency`: `{"ops": 450, "ok": 450, "frames": 4071, "frames_lost": 1, "gaps": 0, "clock_rate": 1.018512}`
* `wire_bytes`: `{"Full handshake": 13106, "PQ ratchet": 4757, "Cached rekey": 324}`
* `aead_throughput`: `{"pi_has_aes": false, "laptop_has_aes": true}`
* `timeline`: `{"seconds": 783.0172319637512, "frames": 23485, "lost": 10, "events": {"1-RTT Cached RapidRekey": 7, "PQ ratchet": 1}, "rotations": 19, "clock_rate": 1.000014}`
* `loss`: `{"levels": [0.0, 0.55, 1.01, 2.07, 4.76, 10.37, 19.9], "complete": [100.0, 93.6, 88.6, 78.9, 59.5, 33.3, 13.3], "decoded": [99.9, 35.2, 19.6, 3.0, 0.6, 0.0, 0.0], "k": 11.87, "photos": "21/21", "clock_rate": 1.000135}`
* `latency`: `{"control_n": 600, "control_lost": 0, "icmp_n": 150, "chunks_per_frame": 11.91, "budget_ms": 90.9, "estimate_ms": 94.8}`
* `media_protection`: `{"format2_added_bytes": 6761, "format1_added_bytes": 1947, "records_per_s": 356.0, "seal_us": 154.9, "core_pct": 5.52}`
* `cipher_statistics`: `{"image": "aerial_usda_naip.jpg", "source": "public-domain aerial photograph (USDA NAIP, 2006, via Wikimedia Commons); not taken by the prototype", "pixels": "768x768", "entropy_cipher": [7.99967, 7.99965, 7.99972], "chi_square_cipher": [266.7, 285.3, 232.4], "npcr": 99.6149, "uaci": 33.4473, "seal_ms": 3.37, "open_ms": 2.86}`
* `attacks`: `{"attack_attempts": 339084, "accepted": 0, "kinds_of_attack": 24, "records_sealed_in_the_nonce_race": 192000, "nonce_pairs_used_twice": 0, "machines": ["Raspberry Pi 4B (UAV)", "Laptop (ground station)"]}`
* `tables`: `{"resources": [["idle (link up, camera off)", 180, 1.0, 1.7, 11.9, 52.1, 55.5, "0x0"], ["live video", 1319, 8.7, 9.9, 14.5, 53.1, 57.5, "0x0"], ["live video + encrypted recording", 241, 6.0, 10.3, 14.6, 55.0, 56.5, "0x0"]], "transfers": [["recording fetch", 7365056, 4.061, 14.51, "PASS", "PASS", 63.6], ["recording fetch", 7365056, 3.605, 16.35, "PASS", "PASS", 42.0], ["recording fetch", 7365056, 3.575, 16.48, "PASS", "PASS", 17.0], ["recording fetch", 7365056, 3.56, 16.55, "PASS", "PASS", 33.3], ["recording fetch", 7365056, 3.584, 16.44, "PASS", "PASS", 30.3], ["photo", 199632, 0.03, 53.17, "P`
* `audio_statistics`: `{"source": "audio_sample1_test.mp3", "seconds": 37.51, "entropy_cipher": 7.999938, "chi_square_cipher": 283.7, "correlation_plain": 0.985149, "correlation_cipher": -0.001516, "nscr": 99.6138, "uaci": 33.4771, "identical": true}`
* `audio_shape`: `{"frame_sizes": 7, "block_sizes": 1, "vbr_added_pct": 194.9, "cbr_sample_added_pct": 8.75, "added_pct_by_length": {"1": 92.8, "5": 19.76, "15": 16.83, "60": 8.99, "300": 5.02, "900": 3.41}}`
* `audio_cost`: `{"machines": ["Raspberry Pi 4B (UAV)", "Laptop (ground station)"], "seal_ms_60s": {"Raspberry Pi 4B (UAV)": 88.9908, "Laptop (ground station)": 19.644}, "open_ms_60s": {"Raspberry Pi 4B (UAV)": 72.2372, "Laptop (ground station)": 12.5849}, "pieces_ms": {"Raspberry Pi 4B (UAV)": {"hybrid key wrap (ML-KEM-1024 encapsulation + X25519 + AES-GCM), once per clip": 0.6528, "hybrid key unwrap, once per clip": 0.6198, "ML-DSA-87 signature, once per clip": 0.7594, "ML-DSA-87 verification, once per clip or excerpt": 0.4491}, "Laptop (ground station)": {"hybrid key wrap (ML-KEM-1024 encapsulation + X25519`
* `audio_attacks`: `{"attack_attempts": 12646, "accepted": 0, "crashes": 0, "rows": 21, "machines": ["Raspberry Pi 4B (UAV)", "Laptop (ground station)"], "live_clips": 12, "stored_and_verified": 12, "blocks_fetched_again": 892, "timing": {"Raspberry Pi 4B (UAV)": "PASS", "Laptop (ground station)": "PASS"}}`
* `motion_watch`: `{"cases": 119, "camera_modes": ["normal", "night"], "false_regions_camera_pans": 1}`
* `proof_matrix`: `{"proved": 42, "attacks_found": 16, "runs": 46, "queries": 177}`

## Simulation figures (plot11 and up): SIMULATED, from simulation/results (see simulation/README.md)

* `validation`: `{"operations_without_loss": {"full": {"measured_median_ms": 23.23, "simulated_median_ms": 23.09, "measured_p95_ms": 30.76, "simulated_p95_ms": 28.8, "ks_distance": 0.127}, "cached": {"measured_median_ms": 9.04, "simulated_median_ms": 9.06, "measured_p95_ms": 17.28, "simulated_p95_ms": 13.75, "ks_distance": 0.151}, "ratchet": {"measured_median_ms": 14.09, "simulated_median_ms": 16.33, "measured_p95_ms": 21.97, "simulated_p95_ms": 23.04, "ks_distance": 0.478}}, "video_under_loss": [{"loss_pct": 0.55, "complete_measured": 93.6, "complete_simulated": 93.8, "decoder_measured": 35.2, "decoder_simula`
* `swarm`: `{"dl_1": {"full_median_ms": 24.64, "full_p95_ms": 28.42, "cached_median_ms": 13.28, "ratchet_median_ms": 19.86, "planned_operations_run_pct": 100.0, "frames_complete_pct_of_sent": 100.0, "frames_to_decoder_pct_of_sent": 100.0, "datagrams_delivered_pct": 99.972, "offered_mbit_s": 3.2}, "dl_2": {"full_median_ms": 24.27, "full_p95_ms": 29.87, "cached_median_ms": 12.89, "ratchet_median_ms": 19.4, "planned_operations_run_pct": 100.0, "frames_complete_pct_of_sent": 100.0, "frames_to_decoder_pct_of_sent": 100.0, "datagrams_delivered_pct": 99.937, "offered_mbit_s": 6.5}, "dl_4": {"full_median_ms": 24.`
* `storm`: `{"workers1_n4": {"all_up_median_ms": 31.6, "all_up_max_ms": 34.3}, "workers1_n8": {"all_up_median_ms": 41.0, "all_up_max_ms": 44.0}, "workers1_n16": {"all_up_median_ms": 54.0, "all_up_max_ms": 57.3}, "workers1_n32": {"all_up_median_ms": 90.9, "all_up_max_ms": 104.0}, "workers1_n64": {"all_up_median_ms": 155.7, "all_up_max_ms": 171.9}, "workers4_n4": {"all_up_median_ms": 28.8, "all_up_max_ms": 32.1}, "workers4_n8": {"all_up_median_ms": 30.7, "all_up_max_ms": 32.1}, "workers4_n16": {"all_up_median_ms": 34.4, "all_up_max_ms": 35.9}, "workers4_n32": {"all_up_median_ms": 49.8, "all_up_max_ms": 51.1`
* `mobility`: `{"speed_0": {"handshakes_per_uav_minute": 0.0, "median_ms": "", "p95_ms": "", "completed": "0/0", "frames_complete_pct_of_sent": 100.0, "frames_to_decoder_pct_of_sent": 100.0, "handshake_share_of_uplink_bytes_pct": 0.0}, "speed_5": {"handshakes_per_uav_minute": 2.15, "median_ms": 26.5, "p95_ms": 30.22, "completed": "122/122", "frames_complete_pct_of_sent": 100.0, "frames_to_decoder_pct_of_sent": 100.0, "handshake_share_of_uplink_bytes_pct": 0.056}, "speed_10": {"handshakes_per_uav_minute": 4.64, "median_ms": 26.72, "p95_ms": 29.86, "completed": "263/263", "frames_complete_pct_of_sent": 100.0, `
* `ablation_crypto`: `{"classical": {"wire_bytes": 484, "datagrams": 3, "uav_compute_ms": 1.19, "gcs_compute_ms": 0.3, "testbed_loss0_median_ms": 12.88, "testbed_loss2_median_ms": 13.01, "testbed_loss5_median_ms": 13.12, "nr_median_ms": 16.41, "storm64_all_up_median_ms": 110.2}, "hybrid1": {"wire_bytes": 6908, "datagrams": 7, "uav_compute_ms": 1.49, "gcs_compute_ms": 0.29, "testbed_loss0_median_ms": 19.03, "testbed_loss2_median_ms": 19.19, "testbed_loss5_median_ms": 19.94, "nr_median_ms": 20.87, "storm64_all_up_median_ms": 112.9}, "hybrid3": {"wire_bytes": 9462, "datagrams": 9, "uav_compute_ms": 1.86, "gcs_compute_`
* `ablation_design`: `{"combine1_loss1": {"completed_pct": 100.0, "within_1s_pct": 89.67, "median_ms": 23.61, "p95_ms": 1220.45, "mean_transmissions": 1.11}, "combine1_loss2": {"completed_pct": 100.0, "within_1s_pct": 79.58, "median_ms": 24.05, "p95_ms": 1224.39, "mean_transmissions": 1.24}, "combine1_loss5": {"completed_pct": 99.92, "within_1s_pct": 54.08, "median_ms": 28.43, "p95_ms": 2420.97, "mean_transmissions": 1.63}, "combine1_loss10": {"completed_pct": 98.83, "within_1s_pct": 29.5, "median_ms": 1222.19, "p95_ms": 3620.37, "mean_transmissions": 2.29}, "combine1_loss20": {"completed_pct": 83.42, "within_1s_pc`
* `rekey_schedule`: `{"per_hour": {"as implemented: cached rekey every 120 s, PQ ratchet every 600 s": {"kB": 36.3, "uav_ms_in_the_running_system": 79.6, "time_in_operations_ms": 301.4}, "a full handshake at every one of those instants": {"kB": 393.2, "uav_ms_in_the_running_system": 246.8, "time_in_operations_ms": 696.9}, "a PQ ratchet at every one of those instants": {"kB": 142.7, "uav_ms_in_the_running_system": 125.6, "time_in_operations_ms": 422.7}}, "saved_against_full_handshakes_pct": {"bytes": 90.8, "uav_computing": 67.7, "time_in_operations": 56.8}}`
