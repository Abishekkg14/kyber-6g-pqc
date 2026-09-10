import { EyeIcon, RefreshIcon, WaveIcon, AlertIcon } from '../components/Icons'
import ScrollReveal from '../components/ScrollReveal'

export default function ThreatModel() {
    const threats = [
        {
            title: 'Eavesdropping & Store-Now-Decrypt-Later',
            Icon: EyeIcon,
            threat: 'Adversaries capture X25519-ECDH handshakes over untrusted gNB relays. Years later, a stable quantum computer runs Shor\'s algorithm to solve ECDLP, recovering the AES key and decrypting all stored mission telemetry.',
            mitigation: 'Hybrid KEM combines ECC with CRYSTALS-Kyber. Kyber bases security on the LWE lattice problem, maintaining exponential resistance O(2^{0.265n}) against quantum sieving. Even if ECC is broken, the fused key remains secure.',
        },
        {
            title: 'Replay & Active Traffic Manipulation',
            Icon: RefreshIcon,
            threat: 'Adversaries capture legitimate navigation or command packets broadcast by the Commander Drone, then rebroadcast them to manipulate the swarm formation.',
            mitigation: 'AES-256-GCM provides authenticated encryption. The 16-byte MAC tag invalidates any bit-flip alterations. Replay attacks are prevented by a monotonically increasing 12-byte nonce in the IV.',
        },
        {
            title: 'DoS via Cryptographic Congestion',
            Icon: WaveIcon,
            threat: 'Kyber KEM public keys (~1,184B) trigger RLC segmentation, saturating MAC queueing at the gNB. M/M/1 arrival rate exceeds service rate, causing unbounded delays.',
            mitigation: 'PqcAdaptiveKeyManager detects high-speed mobility and extends rekeying intervals using cached session keys. This reduces arrival rate back below the saturation threshold, restoring stable queueing behavior.',
        },
        {
            title: 'Node Compromise & Key Extraction',
            Icon: AlertIcon,
            threat: 'A follower drone crashes behind enemy lines. The adversary extracts the current AES symmetric key from memory, enabling decryption of intercepted traffic.',
            mitigation: 'Forward secrecy through periodic forced Kyber rekeying ensures a compromised key only exposes traffic within that specific brief time envelope. Past and future sessions remain protected.',
        }
    ]

    return (
        <section id="threats" className="section" style={{ background: '#fff' }} aria-label="Threat Model">
            <div className="section-inner">
                <ScrollReveal>
                    <span className="section-label">Security Analysis</span>
                    <h2>Threat Model Assessment</h2>
                    <p className="section-desc">
                        The system operates drone swarms over untrusted 5G base stations against adversaries
                        with passive interception, active manipulation, and potential future quantum capabilities.
                    </p>
                </ScrollReveal>

                <div className="card-grid" style={{ marginTop: '48px' }}>
                    {threats.map((t, i) => (
                        <ScrollReveal key={i} delay={(i % 4) + 1}>
                            <div className="threat-card">
                                <div style={{ marginBottom: '20px', color: '#dc2626', display: 'flex', width: '52px', height: '52px', alignItems: 'center', justifyContent: 'center', background: '#fef2f2', border: '1px solid #fee2e2', borderRadius: '12px', boxShadow: '0 4px 12px rgba(220,38,38,0.06)' }}>
                                    <t.Icon size={28} />
                                </div>
                                <div className="threat-label">Threat</div>
                                <h3 style={{ marginBottom: '12px' }}>{t.title}</h3>
                                <p style={{ fontSize: '0.875rem', lineHeight: '1.6' }}>{t.threat}</p>
                                <div className="mitigation">
                                    <div className="mit-label">Mitigation</div>
                                    <p style={{ fontSize: '0.875rem', lineHeight: '1.6' }}>{t.mitigation}</p>
                                </div>
                            </div>
                        </ScrollReveal>
                    ))}
                </div>
            </div>
        </section>
    )
}
