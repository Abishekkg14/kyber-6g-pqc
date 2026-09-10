export default function Conclusions() {
    const findings = [
        {
            indicator: 'positive',
            text: 'CRYSTALS-Kyber maintains exponential quantum resistance while ECC security degrades to polynomial complexity under Shor\'s algorithm, validating the hybrid KEM approach.'
        },
        {
            indicator: 'caution',
            text: 'Kyber-768 handshake latency is approximately 4× higher than ECC-only (1.25ms vs 0.31ms at 10 nodes), creating measurable control-plane overhead in dense deployments.'
        },
        {
            indicator: 'positive',
            text: 'AES-256-GCM data-plane encryption performance is identical regardless of key exchange mechanism, with encrypt/decrypt latency consistently at ~2μs per packet.'
        },
        {
            indicator: 'caution',
            text: 'RRC Connection Request size increases 10.25× (128B → 1312B) with Kyber, increasing RLC segmentation requirements and MAC queueing pressure under high load.'
        },
        {
            indicator: 'positive',
            text: 'PSK caching optimization reduces Kyber handshake latency by 73.8% (from 1.45ms to 0.38ms) at 56 nodes, bringing it near ECC baseline performance levels.'
        },
        {
            indicator: 'neutral',
            text: 'Gateway queueing delay scales superlinearly with swarm size for both schemes, following M/M/1 predictions. Kyber amplifies this by 35% due to larger control messages.'
        },
        {
            indicator: 'positive',
            text: 'The adaptive key manager successfully extends rekeying intervals during high-speed mobility, preventing cryptographic congestion-induced denial of service.'
        },
        {
            indicator: 'neutral',
            text: 'Multi-gNB deployment (7 base stations) distributes UE load to ~8 drones per cell, enabling 56-drone swarms within NR scheduling capacity constraints.'
        },
    ]

    return (
        <section id="conclusions" className="section" aria-label="Conclusions">
            <div className="section-inner">
                <span className="section-label">Conclusions</span>
                <h2>Key Findings</h2>
                <p className="section-desc">
                    The evaluation demonstrates that post-quantum security is achievable for military drone
                    swarm communication with acceptable performance trade-offs, provided adaptive optimization
                    mechanisms are employed for high-mobility scenarios.
                </p>

                <ul className="finding-list">
                    {findings.map((f, i) => (
                        <li key={i}>
                            <div className={`indicator ${f.indicator}`} />
                            <p style={{ fontSize: '0.9rem', color: 'var(--c-text-secondary)', maxWidth: 'none' }}>{f.text}</p>
                        </li>
                    ))}
                </ul>

                <div style={{ marginTop: '48px', padding: '24px', background: 'var(--c-surface-alt)', borderRadius: '12px' }}>
                    <h3>Future Work</h3>
                    <p style={{ fontSize: '0.9rem', marginTop: '8px' }}>
                        Extensions include evaluating Kyber-512 and Kyber-1024 variants, introducing ML-DSA mutual
                        authentication overhead analysis, testing with realistic urban channel models including fading
                        and NLOS propagation, and scaling to 200+ drone swarms with hierarchical multi-cell deployments.
                    </p>
                </div>
            </div>
        </section>
    )
}
