import { FlaskIcon, TargetIcon, RulerIcon } from '../components/Icons'
import ScrollReveal from '../components/ScrollReveal'

export default function Simulation() {
    const scenarios = [
        { crypto: 'ECC', nodes: 10, speed: 25, gnbs: 1, caching: 'No', label: 'ecc' },
        { crypto: 'ECC', nodes: 28, speed: 25, gnbs: 7, caching: 'No', label: 'ecc' },
        { crypto: 'ECC', nodes: 56, speed: 25, gnbs: 7, caching: 'No', label: 'ecc' },
        { crypto: 'Kyber-768', nodes: 10, speed: 25, gnbs: 1, caching: 'No', label: 'kyber' },
        { crypto: 'Kyber-768', nodes: 28, speed: 25, gnbs: 7, caching: 'No', label: 'kyber' },
        { crypto: 'Kyber-768', nodes: 56, speed: 25, gnbs: 7, caching: 'No', label: 'kyber' },
        { crypto: 'Kyber-768', nodes: 56, speed: 25, gnbs: 7, caching: 'Yes', label: 'kyber' },
    ]

    return (
        <section id="simulation" className="section" style={{ background: '#fff' }} aria-label="Simulation Methodology">
            <div className="section-inner">
                <ScrollReveal>
                    <span className="section-label">Simulation</span>
                    <h2>Experiment Methodology</h2>
                    <p className="section-desc">
                        All experiments use the NS-3 network simulator (v3.42) with the 5G-LENA NR module.
                        Drones operate as UE nodes attached to 5G NR gNB base stations in dense urban topology.
                        Each scenario runs for 10 simulated seconds with 1024-byte telemetry payloads at 200 kbps per drone.
                    </p>
                </ScrollReveal>

                <div className="card-grid" style={{ marginTop: '48px' }}>
                    <ScrollReveal delay={1}>
                        <article className="card">
                            <div className="card-icon" style={{ background: '#eff6ff', color: '#2563eb' }}><FlaskIcon size={26} /></div>
                            <h3>Controlled Variables</h3>
                            <p>Packet size (1024B), data rate (200 kbps), sim time (10s), altitude (100m), 28GHz mmWave, UMi-StreetCanyon propagation.</p>
                        </article>
                    </ScrollReveal>
                    <ScrollReveal delay={2}>
                        <article className="card">
                            <div className="card-icon" style={{ background: '#f5f3ff', color: '#7c3aed' }}><TargetIcon size={26} /></div>
                            <h3>Independent Variables</h3>
                            <p>Cryptographic scheme (ECC vs Kyber-768), swarm size (10/28/56 drones), PSK caching (on/off), mobility speed (25 m/s).</p>
                        </article>
                    </ScrollReveal>
                    <ScrollReveal delay={3}>
                        <article className="card">
                            <div className="card-icon" style={{ background: '#ecfeff', color: '#0891b2' }}><RulerIcon size={26} /></div>
                            <h3>Measured Metrics</h3>
                            <p>Handshake latency, RRC message sizes, E2E application latency, queueing delay, computation time, throughput, packet loss.</p>
                        </article>
                    </ScrollReveal>
                </div>

                <ScrollReveal delay={4}>
                    <h3 style={{ marginTop: '64px' }}>Experiment Matrix</h3>
                    <div style={{ overflowX: 'auto', borderRadius: '8px', overflow: 'hidden' }}>
                        <table className="scenario-table">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Cryptography</th>
                                    <th>Drones</th>
                                    <th>gNBs</th>
                                    <th>Speed</th>
                                    <th>PSK Cache</th>
                                </tr>
                            </thead>
                            <tbody>
                                {scenarios.map((s, i) => (
                                    <tr key={i}>
                                        <td>{i + 1}</td>
                                        <td><span className={`badge ${s.label}`}>{s.crypto}</span></td>
                                        <td>{s.nodes}</td>
                                        <td>{s.gnbs}</td>
                                        <td>{s.speed} m/s</td>
                                        <td>{s.caching}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </ScrollReveal>
            </div>
        </section>
    )
}
