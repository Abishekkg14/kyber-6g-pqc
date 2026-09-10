import yaml
import subprocess
import sys
import os
import argparse
import json

def parse_args():
    parser = argparse.ArgumentParser(description='Run NS-3 experiments based on config')
    parser.add_argument('--config', type=str, default='../experiments/config.yaml', help='Path to config.yaml')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads (ignored for now)')
    return parser.parse_args()

def run_experiment(config, scenario, mode, nodes, num_runs):
    defaults = config.get('defaults', {})
    seed = defaults.get('seed', 42)
    sim_time = defaults.get('simTime', 10.0)
    speed = defaults.get('speed', 120.0)
    band = defaults.get('band', '6g-140ghz')
    edge_backhaul_ms = defaults.get('edgeBackhaulMs', 2.0)
    parallel = defaults.get('parallelHandshake', False)
    cache_ttl = defaults.get('cacheTtl', 300.0)
    battery = defaults.get('batteryWh', 74.0)
    hw = defaults.get('hardwareProfile', 'jetson-nano')
    
    cmd = [
        './ns3', 'run',
        f'drone-swarm-pqc-sim '
        f'--cryptoMode={mode} '
        f'--scenario={scenario} '
        f'--nodes={nodes} '
        f'--numRuns={num_runs} '
        f'--seed={seed} '
        f'--simTime={sim_time} '
        f'--speed={speed} '
        f'--band={band} '
        f'--edgeBackhaulMs={edge_backhaul_ms} '
        f'--parallelHandshake={"true" if parallel else "false"} '
        f'--cacheTtl={cache_ttl} '
        f'--batteryWh={battery} '
        f'--hardwareProfile={hw}'
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode == 0

def main():
    args = parse_args()
    if not os.path.exists(args.config):
        print(f"Config file not found: {args.config}")
        sys.exit(1)
        
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
        
    jobs = []
    
    # Group 1: Serialization & Baseline (Fig 1)
    for mode in ['ecc', 'kyber', 'hybrid']:
        jobs.append(('6g-140ghz-baseline', mode, 10, 10))
        
    # Group 2: Routing Density Sweep (Fig 4)
    routing_scenarios = ['6g-dora-routing', 'ablation-a4-zrp-routing', 'ablation-a5-dsrp-routing']
    for scenario in routing_scenarios:
        for size in [10, 28, 56, 100, 140, 200]:
            jobs.append((scenario, 'hybrid', size, 30))
            
    # Group 3: Core Ablation Matrix (Table 8.1)
    ablation_scenarios = ['6g-xwing-hybrid', 'ablation-a1-no-csidh-bypass', 'ablation-a3-mm1-queue', 'ablation-a6-unmasked-sha3', 'ablation-a7-no-cvqkd', 'ablation-a8-no-emulsion']
    for scenario in ablation_scenarios:
        jobs.append((scenario, 'hybrid', 56, 10))
        
    # Group 4: Crypto Ablation A2 (Table 8.1)
    jobs.append(('ablation-a2-pure-mlkem', 'kyber', 56, 10))
    
    total = len(jobs)
    passed = 0
    failed = 0
    
    checkpoint_file = 'run_checkpoint.json'
    completed_jobs = []
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            try:
                completed_jobs = json.load(f)
            except:
                pass
                
    for count, (scenario, mode, size, num_runs) in enumerate(jobs, 1):
        job_id = f"{scenario}_{mode}_{size}_{num_runs}"
        if job_id in completed_jobs:
            print(f"\n[{count}/{total}] SKIPPING (Already completed): {job_id}")
            passed += 1
            continue
            
        print(f"\n[{count}/{total}] Scenario: {scenario}, Mode: {mode}, Nodes: {size}, Runs: {num_runs}")
        success = run_experiment(config, scenario, mode, size, num_runs)
        if success:
            passed += 1
            completed_jobs.append(job_id)
            with open(checkpoint_file, 'w') as f:
                json.dump(completed_jobs, f)
        else:
            failed += 1
            print(f"\n[FATAL] Experiment failed at Scenario: {scenario}, Mode: {mode}, Nodes: {size}")
            print("Aborting matrix execution as requested.")
            sys.exit(1)
            
    print("\n" + "="*40)
    print(f"SUMMARY: {passed} passed, {failed} failed / {total} total")
    print("="*40)

if __name__ == '__main__':
    main()
