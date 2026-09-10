import { lazy, Suspense } from 'react'

const DroneSwarmScene = lazy(() => import('../components/DroneSwarmScene'))

export default function Hero() {
    return (
        <section className="hero" aria-label="Project Introduction">
            <span className="section-label">Research Project</span>
            <h1>
                Post-Quantum Secure<br />
                <span className="accent">Military Drone Swarm</span><br />
                Communication
            </h1>
            <p className="hero-sub">
                An NS-3 simulation framework evaluating CRYSTALS-Kyber hybrid key exchange
                for 6G drone swarm networks — comparing post-quantum and classical
                cryptographic performance under realistic mobility conditions.
            </p>
            <div className="hero-tags">
                <span className="tag kyber">CRYSTALS-Kyber</span>
                <span className="tag">AES-256-GCM</span>
                <span className="tag ecc">X25519-ECDH</span>
                <span className="tag">ML-DSA</span>
                <span className="tag">NS-3 · 5G-LENA NR</span>
                <span className="tag">M/M/1 Queueing</span>
            </div>

            <Suspense fallback={
                <div className="scene-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ color: '#64748b', fontSize: '0.8rem' }}>Loading 3D visualization...</span>
                </div>
            }>
                <DroneSwarmScene />
            </Suspense>
        </section>
    )
}
