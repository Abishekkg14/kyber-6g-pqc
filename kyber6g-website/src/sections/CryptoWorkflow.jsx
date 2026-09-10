export default function CryptoWorkflow() {
    const steps = [
        {
            title: 'Key Generation',
            desc: 'The UE generates an ephemeral X25519 key pair and a CRYSTALS-Kyber-768 key pair. The public keys are bundled into an RRC Connection Request.',
            detail: 'pk_ecdh = X25519.Generate() | (pk_kyber, sk_kyber) = Kyber768.KeyGen()'
        },
        {
            title: 'RRC Connection Request',
            desc: 'The UE sends the combined public keys through the untrusted gNB relay to the network core. The request payload is ~1,312 bytes for Kyber-768 vs ~128 bytes for ECC-only.',
            detail: 'RRC_Request = { pk_ecdh (32B) + pk_kyber (1184B) + auth_metadata (96B) }'
        },
        {
            title: 'Encapsulation',
            desc: 'The gNB performs X25519 DH key agreement and Kyber encapsulation against the UE public keys, producing an ECDH shared secret and a Kyber ciphertext with encapsulated secret.',
            detail: 'ss_ecdh = X25519.DH(sk_gnb, pk_ecdh) | (ct, ss_kyber) = Kyber.Encaps(pk_kyber)'
        },
        {
            title: 'Hybrid Key Derivation',
            desc: 'Both shared secrets are combined using HKDF-SHA256 to produce the final session key material. This ensures security even if one primitive is broken.',
            detail: 'master_key = HKDF(ss_ecdh || ss_kyber, salt="kyber6g-kem", info="session")'
        },
        {
            title: 'RRC Connection Setup',
            desc: 'The gNB sends the Kyber ciphertext and ECDH public key back to the UE. Optionally includes an ML-DSA-65 signature for mutual authentication.',
            detail: 'RRC_Setup = { pk_gnb_ecdh (32B) + ct_kyber (1088B) + sig_mldsa (3309B) }'
        },
        {
            title: 'Session Establishment',
            desc: 'The UE decapsulates the Kyber ciphertext, computes the ECDH shared secret, and derives the identical master key. AES-256-GCM encryption begins immediately.',
            detail: 'ss_kyber = Kyber.Decaps(sk_kyber, ct) → AES-GCM-256(master_key) active'
        }
    ]

    return (
        <section id="crypto" className="section" style={{ background: '#fff' }} aria-label="Cryptographic Workflow">
            <div className="section-inner">
                <span className="section-label">Cryptography</span>
                <h2>Hybrid KEM Handshake Protocol</h2>
                <p className="section-desc">
                    The handshake combines classical X25519-ECDH with CRYSTALS-Kyber ML-KEM.
                    Both shared secrets are fused through HKDF to produce AES-256-GCM session keys.
                    If either primitive is secure, the combined key remains secure.
                </p>

                <div className="workflow-steps">
                    {steps.map((step, i) => (
                        <div className="workflow-step" key={i}>
                            <div className="step-number">{i + 1}</div>
                            <div className="step-content">
                                <h3>{step.title}</h3>
                                <p>{step.desc}</p>
                                <div className="step-detail">{step.detail}</div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    )
}
