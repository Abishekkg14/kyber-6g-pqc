import { ShieldIcon, DroneIcon, ChartIcon, ZapIcon, LockIcon, AntennaIcon } from '../components/Icons'
import ScrollReveal from '../components/ScrollReveal'

export default function Overview() {
    const cards = [
        {
            Icon: ShieldIcon,
            color: '#7c3aed',
            bg: '#f5f3ff',
            title: 'Quantum-Resilient Security',
            desc: 'Hybrid KEM combining X25519-ECDH with CRYSTALS-Kyber protects against both classical and quantum adversaries using the LWE lattice hardness assumption.'
        },
        {
            Icon: DroneIcon,
            color: '#0891b2',
            bg: '#ecfeff',
            title: 'Drone Swarm Simulation',
            desc: 'NS-3 simulation of military drone swarms with 3D waypoint mobility, commander-follower topology, and 5G NR base station relays in dense urban scenarios.'
        },
        {
            Icon: ChartIcon,
            color: '#2563eb',
            bg: '#eff6ff',
            title: 'Rigorous Evaluation',
            desc: 'Comparative analysis across 7 experiment configurations measuring handshake latency, RRC overhead, queueing delay, throughput, and security strength.'
        },
        {
            Icon: ZapIcon,
            color: '#d97706',
            bg: '#fef3c7',
            title: 'Adaptive Optimization',
            desc: 'PSK caching mechanism reduces Kyber handshake latency by 73% during high-mobility scenarios, restoring queueing stability below saturation threshold.'
        },
        {
            Icon: LockIcon,
            color: '#db2777',
            bg: '#fce7f3',
            title: 'Forward Secrecy',
            desc: 'Periodic forced rekeying ensures compromised session keys expose only a brief window of traffic, securing past and future mission intelligence.'
        },
        {
            Icon: AntennaIcon,
            color: '#059669',
            bg: '#f0fdf4',
            title: '5G/6G NR Stack',
            desc: 'Full 5G-LENA NR stack with ideal beamforming, point-to-point EPC backhaul, configurable bandwidth parts, and multi-gNB dense urban deployment.'
        }
    ]

    return (
        <section id="overview" className="section" aria-label="Project Overview">
            <div className="section-inner">
                <span className="section-label">Overview</span>
                <h2>Why Post-Quantum Security for Drones?</h2>
                <p className="section-desc">
                    Quantum computers running Shor's algorithm will break elliptic curve cryptography.
                    Military drone swarms transmitting sensitive telemetry over untrusted 5G base stations
                    face a "store now, decrypt later" threat. This project evaluates hybridizing classical
                    ECDH with CRYSTALS-Kyber to maintain confidentiality against future quantum adversaries,
                    while quantifying the performance impact on latency-sensitive swarm coordination.
                </p>
                <div className="card-grid">
                    {cards.map((c, i) => (
                        <article className="card" key={i}>
                            <div className="card-icon" style={{ background: c.bg, color: c.color }}>
                                <c.Icon size={22} />
                            </div>
                            <h3>{c.title}</h3>
                            <p>{c.desc}</p>
                        </article>
                    ))}
                </div>
            </div>
        </section>
    )
}
