import { DroneIcon, AntennaIcon, KeyIcon, ShieldIcon, ChartIcon, LayersIcon, ArrowRightIcon } from '../components/Icons'
import ScrollReveal from '../components/ScrollReveal'

export default function Architecture() {
    const nodes = [
        { Icon: DroneIcon, color: '#7c3aed', name: 'Drone Swarm', desc: 'UE Nodes' },
        { Icon: AntennaIcon, color: '#0891b2', name: 'gNB Relay', desc: '5G Base Station' },
        { Icon: KeyIcon, color: '#2563eb', name: 'PQC Engine', desc: 'Kyber + ECDH' },
        { Icon: ShieldIcon, color: '#059669', name: 'AES-GCM', desc: 'Data Plane' },
        { Icon: ChartIcon, color: '#d97706', name: 'Metrics', desc: 'Collector' },
        { Icon: LayersIcon, color: '#dc2626', name: 'Analytics', desc: 'Visualization' },
    ]

    const layers = [
        {
            name: 'Application Layer',
            color: '#7c3aed',
            items: ['PqcDroneApp — Commander/Follower telemetry', 'AesGcmCipher — Authenticated encryption', 'PqcSessionKeys — Key material management']
        },
        {
            name: 'Security Control Layer',
            color: '#2563eb',
            items: ['PqcRrcExtension — Hybrid KEM handshake', 'PqcAdaptiveKeyManager — Mobility-aware rekeying', 'MlDsaSigner — Digital signature authentication']
        },
        {
            name: 'Cryptographic Primitives',
            color: '#0891b2',
            items: ['CrystalsKyberKem — ML-KEM (512/768/1024)', 'X25519Ecdh — Classical key agreement', 'HybridKemCombiner — KDF key fusion']
        },
        {
            name: 'Network Infrastructure',
            color: '#059669',
            items: ['5G-LENA NR Stack — gNB + UE radio', 'PqcScenarioHelper — Topology generator', 'PqcPdcpLayer — Encrypted PDCP tunnel']
        }
    ]

    return (
        <section id="architecture" className="section" aria-label="System Architecture">
            <div className="section-inner">
                <ScrollReveal>
                    <span className="section-label">Architecture</span>
                    <h2>System Architecture</h2>
                    <p className="section-desc">
                        The framework layers post-quantum security on top of the NS-3 5G-LENA NR stack.
                        Drones communicate through untrusted gNB relays with end-to-end AES-GCM encryption,
                        keyed by CRYSTALS-Kyber hybrid handshakes.
                    </p>
                </ScrollReveal>

                <div className="arch-diagram" role="img" aria-label="Data flow: Drone to Analytics">
                    {nodes.map((n, i) => (
                        <ScrollReveal key={i} delay={(i % 4) + 1} style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                            <div className="arch-node">
                                <div className="icon" style={{ color: n.color }}><n.Icon size={32} /></div>
                                <div className="name">{n.name}</div>
                                <div className="desc">{n.desc}</div>
                            </div>
                            {i < nodes.length - 1 && (
                                <span className="arch-arrow" style={{ color: '#d1d5db' }}>
                                    <ArrowRightIcon size={20} />
                                </span>
                            )}
                        </ScrollReveal>
                    ))}
                </div>

                <ScrollReveal delay={2}>
                    <h3 style={{ marginTop: '48px' }}>Module Hierarchy</h3>
                    <div style={{ display: 'grid', gap: '12px', marginTop: '20px' }}>
                        {layers.map((layer, i) => (
                            <div key={i} style={{
                                background: '#fff',
                                border: '1px solid var(--c-border)',
                                borderLeft: `3px solid ${layer.color}`,
                                borderRadius: '8px',
                                padding: '20px 24px',
                            }}>
                                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: layer.color, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '10px' }}>
                                    {layer.name}
                                </div>
                                <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
                                    {layer.items.map((item, j) => (
                                        <span key={j} style={{ fontSize: '0.825rem', color: 'var(--c-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                                            {item}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </ScrollReveal>
            </div>
        </section>
    )
}
