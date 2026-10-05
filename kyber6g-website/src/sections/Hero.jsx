import Figure from '../components/Figure'

export default function Hero({ data }) {
  return (
    <section className="hero" aria-label="Project introduction">
      <span className="section-label">Research prototype · measured on real hardware</span>
      <h1>
        A post-quantum secure link<br />
        for a UAV's <span className="accent">video, images, audio</span><br />
        and telemetry
      </h1>
      <p className="hero-sub">
        A Raspberry Pi 4B as the UAV's companion computer and a ground control station exchange live video, photos,
        sealed audio, telemetry and commands. Sessions are established with ML-KEM-1024 and X25519 together and
        authenticated with ML-DSA-87; the data itself is encrypted with AES-256-GCM. The prototype runs over Wi-Fi.
      </p>
      <div className="hero-tags">
        <span className="tag kyber">ML-KEM-1024 + X25519</span>
        <span className="tag kyber">ML-DSA-87</span>
        <span className="tag">AES-256-GCM</span>
        <span className="tag">1-RTT Cached RapidRekey</span>
        <span className="tag ecc">ProVerif models</span>
        <span className="tag ecc">NIST ACVP vectors</span>
        <span className="tag">Raspberry Pi 4B</span>
      </div>
      <div className="hero-figure">
        <Figure
          name="fig18_architecture"
          caption="The streams of the UAV node, the secure link on both sides, and what the ground station does with each."
        />
      </div>
      {data && <p className="hero-note">Results on this page were generated from the repository on {data.generated}.</p>}
    </section>
  )
}
