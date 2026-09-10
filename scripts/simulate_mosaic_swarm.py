#!/usr/bin/env python3
"""
Algorithm 5: Autonomous Mosaic Swarm Reconnaissance & Attack Allocation
Using K-means Clustering and Distributed Model Predictive Control (DMPC)
"""

import numpy as np
import time

class Target:
    def __init__(self, id, x, y):
        self.id = id
        self.x = x
        self.y = y

class UAV:
    def __init__(self, id, type, x, y):
        self.id = id
        self.type = type
        self.x = x
        self.y = y

def kmeans_clustering_fusion(targets_list, max_iters=10, distance_threshold=50):
    # Simplified fusion: group targets that are very close to each other
    if not targets_list:
        return []
        
    unique_targets = []
    for t in targets_list:
        merged = False
        for ut in unique_targets:
            dist = np.sqrt((t.x - ut.x)**2 + (t.y - ut.y)**2)
            if dist < distance_threshold:
                # Merge targets (update center)
                ut.x = (ut.x + t.x) / 2
                ut.y = (ut.y + t.y) / 2
                merged = True
                break
        if not merged:
            unique_targets.append(t)
            
    return unique_targets

def dmpc_select_closest_recon(target, rec_nodes):
    # Simulates Distributed Model Predictive Control (DMPC) for Recon nodes
    # For now, it selects the closest node that minimizes latency and energy.
    best_node = None
    min_cost = float('inf')
    
    for r in rec_nodes:
        dist = np.sqrt((r.x - target.x)**2 + (r.y - target.y)**2)
        cost = dist # In full DMPC, this includes predictive pathing and battery life
        if cost < min_cost:
            min_cost = cost
            best_node = r
            
    return best_node

def differential_evolution_match(target, att_nodes, min_units=2):
    # Simulates Differential Evolution matching for optimal Attack node pairings
    # We sort by proximity and select top min_units
    nodes_with_cost = []
    for a in att_nodes:
        dist = np.sqrt((a.x - target.x)**2 + (a.y - target.y)**2)
        nodes_with_cost.append((dist, a))
        
    nodes_with_cost.sort(key=lambda item: item[0])
    selected_nodes = [n[1] for n in nodes_with_cost[:min_units]]
    
    # Pad if not enough nodes
    while len(selected_nodes) < min_units:
        selected_nodes.append(None)
        
    return selected_nodes

def mosaic_swarm_allocation(targets_list, swarm_uavs):
    # Step 1: K-means Clustering to Eliminate Duplicate Detections
    unique_targets = kmeans_clustering_fusion(targets_list)
    
    # Step 2: Dynamic Role Classification (Mosaic Components)
    rec_nodes = [u for u in swarm_uavs if u.type == 'RECON']
    att_nodes = [u for u in swarm_uavs if u.type == 'ATTACK']
    
    allocation_matrix = {}
    
    # Step 3: Distributed Model Predictive Control (DMPC) + Differential Evolution
    for target in unique_targets:
        assigned_rec = dmpc_select_closest_recon(target, rec_nodes)
        assigned_att = differential_evolution_match(target, att_nodes, min_units=2)
        
        # Enforce Visual Guidance Pairings
        allocation_matrix[target.id] = {
            'guidance_recon': assigned_rec.id if assigned_rec else None,
            'primary_attack': assigned_att[0].id if assigned_att[0] else None,
            'secondary_attack': assigned_att[1].id if assigned_att[1] else None
        }
        
    return allocation_matrix

def run_simulation():
    print("Running Mosaic Swarm Allocation Simulation...")
    
    # Generate random targets and UAVs
    np.random.seed(42)
    targets_list = [Target(i, np.random.uniform(0, 1000), np.random.uniform(0, 1000)) for i in range(20)]
    
    swarm_uavs = []
    for i in range(50):
        t_type = 'RECON' if i < 15 else 'ATTACK'
        swarm_uavs.append(UAV(i, t_type, np.random.uniform(0, 1000), np.random.uniform(0, 1000)))
        
    start_time = time.time()
    allocation = mosaic_swarm_allocation(targets_list, swarm_uavs)
    end_time = time.time()
    
    print(f"Simulation completed in {end_time - start_time:.4f} seconds.")
    print(f"Unique targets identified: {len(allocation)}")
    for t_id, assignment in allocation.items():
        print(f"Target {t_id}: Recon {assignment['guidance_recon']}, Primary Att {assignment['primary_attack']}, Secondary Att {assignment['secondary_attack']}")

if __name__ == "__main__":
    run_simulation()
