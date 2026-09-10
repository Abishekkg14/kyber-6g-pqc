import 'katex/dist/katex.min.css'
import { BlockMath } from 'react-katex'

const equations = [
    {
        label: 'End-to-End Handshake Latency',
        tex: 'T_{\\text{handshake}} = T_{\\text{keygen}} + T_{\\text{encaps}} + T_{\\text{decaps}} + T_{\\text{HKDF}} + 2 \\cdot T_{\\text{RTT}}',
        desc: 'Total time from RRC Connection Request to session establishment. Kyber-768 adds ~900μs compared to ECC-only due to lattice operations.'
    },
    {
        label: 'M/M/1 Queue Wait Time',
        tex: 'E[W] = \\frac{\\rho}{\\mu(1 - \\rho)}, \\quad \\rho = \\frac{\\lambda}{\\mu}',
        desc: 'Expected queueing delay at the gNB MAC layer. As drone count (λ) approaches channel capacity (μ), wait times grow asymptotically. Kyber\'s larger payloads increase effective λ.'
    },
    {
        label: 'Throughput Under Encryption',
        tex: 'C_{\\text{effective}} = \\frac{L_{\\text{payload}}}{L_{\\text{payload}} + L_{\\text{header}} + L_{\\text{MAC}}} \\cdot C_{\\text{channel}}',
        desc: 'AES-GCM adds a 16-byte authentication tag and 12-byte nonce per packet. The overhead ratio remains constant regardless of crypto scheme since data-plane encryption is identical.'
    },
    {
        label: 'Packet Delivery Ratio (AWGN)',
        tex: 'P_{\\text{deliver}} = (1 - P_b)^{L \\cdot 8}, \\quad P_b = \\frac{1}{2} \\operatorname{erfc}\\!\\left(\\sqrt{\\frac{E_b}{N_0}}\\right)',
        desc: 'BER-based reliability model. Kyber KEM payloads (1,184B) have significantly lower PDR than navigation packets (64B) at the same SNR, motivating RLC segmentation.'
    },
    {
        label: 'RLC Segmentation Count',
        tex: 'N_{\\text{segments}} = \\left\\lceil \\frac{L_{\\text{SDU}}}{L_{\\text{MTU}} - H_{\\text{RLC}}} \\right\\rceil',
        desc: 'Kyber public keys exceed typical NR MAC PDU limits, requiring fragmentation. More segments increase retransmission probability under fading channels.'
    },
    {
        label: 'LWE Security Strength',
        tex: 'T_{\\text{classical}} = 2^{0.292 \\cdot n}, \\quad T_{\\text{quantum}} = 2^{0.265 \\cdot n}',
        desc: 'Core-Sieve cost for solving the Learning With Errors problem on dimension n. Even quantum sieve attacks maintain exponential cost, unlike ECC which falls to polynomial O(n³) under Shor.'
    },
    {
        label: 'Adaptive Rekey Interval',
        tex: 'T_{\\text{rekey}} = T_{\\text{base}} \\cdot \\max\\!\\left(1,\\; \\frac{v_{\\text{threshold}}}{v_{\\text{current}}}\\right)',
        desc: 'The PqcAdaptiveKeyManager extends rekeying intervals proportionally when drone velocity exceeds a threshold, reducing handshake frequency during high-speed maneuvers.'
    },
    {
        label: 'Handover Interruption Time',
        tex: 'T_{\\text{HO}} = T_{\\text{detection}} + T_{\\text{preparation}} + T_{\\text{rekey\\_target}} + T_{\\text{path\\_switch}}',
        desc: 'Post-quantum handover adds rekey latency at the target gNB. The PqcHandoverManager pre-computes keys to minimize this component during inter-cell transitions.'
    }
]

export default function MathModels() {
    return (
        <section id="math" className="section" aria-label="Mathematical Models">
            <div className="section-inner">
                <span className="section-label">Mathematical Models</span>
                <h2>Theoretical Foundation</h2>
                <p className="section-desc">
                    The evaluation framework uses analytical models from queueing theory, information
                    theory, and computational complexity to validate simulation measurements and
                    characterize system behavior under varying conditions.
                </p>

                <div className="equations-grid">
                    {equations.map((eq, i) => (
                        <div className="equation-block" key={i}>
                            <div className="eq-label">{eq.label}</div>
                            <BlockMath math={eq.tex} />
                            <div className="eq-desc">{eq.desc}</div>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    )
}
