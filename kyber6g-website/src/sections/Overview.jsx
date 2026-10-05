import { ShieldIcon, ChartIcon, TargetIcon, FlaskIcon, LayersIcon, RulerIcon } from '../components/Icons'
import ScrollReveal from '../components/ScrollReveal'
import { fmt } from '../data'

export default function Overview({ data }) {
  const a = data ? data.attacks : null
  const f = data ? data.formal : null
  const ka = data ? Object.values(data.known_answers) : []
  const kinds = [
    {
      Icon: ChartIcon, color: '#2563eb', bg: '#eff6ff', title: 'Measured',
      desc: 'The prototype on real hardware, over Wi-Fi: every handshake, rekey, frame and file was timed on the machines themselves. Every sample is in the repository.',
    },
    {
      Icon: TargetIcon, color: '#dc2626', bg: '#fef2f2', title: 'Attacked',
      desc: a
        ? `${fmt(a.link_and_files.attempts + a.audio.attempts)} forged, replayed, re-ordered, spliced and re-signed inputs were offered to the running implementation on both machines. Accepted: ${fmt(a.link_and_files.accepted + a.audio.accepted)}.`
        : 'Forged, replayed, re-ordered, spliced and re-signed inputs offered to the running implementation on both machines.',
    },
    {
      Icon: RulerIcon, color: '#059669', bg: '#f0fdf4', title: 'Proved and checked',
      desc: f
        ? `ProVerif proves ${f.claims_proved} of the ${f.claims} claims made across its ${f.runs} runs (nothing broken, X25519 broken, ML-KEM broken) and finds the attack in every case built to have one. ${ka.length ? `${ka[0].passed} of ${ka[0].vectors}` : 'NIST\'s'} known-answer vectors pass on each machine.`
        : 'Symbolic proofs of the protocols under four attackers, and NIST\'s known-answer vectors on both machines.',
    },
    {
      Icon: FlaskIcon, color: '#7c3aed', bg: '#f5f3ff', title: 'Simulated',
      desc: 'What one UAV on a desk cannot show: many UAVs, a 5G NR cell, movement, range and other algorithms, in ns-3 with 5G-LENA, calibrated with the measurements. A model, and labelled as one.',
    },
    {
      Icon: LayersIcon, color: '#0891b2', bg: '#ecfeff', title: 'Five kinds of data',
      desc: 'Live video, stored recordings, photos, sealed audio and text (telemetry, status, motion reports, commands): each protected in transit, and each stored file sealed so that only the ground station opens it.',
    },
    {
      Icon: ShieldIcon, color: '#d97706', bg: '#fef3c7', title: 'Hybrid, on purpose',
      desc: 'Keys come from ML-KEM-1024 and X25519 together: an attacker has to break both. A recording made today stays closed if either one holds.',
    },
  ]
  const not = [
    'No 5G or 6G radio was used at any point. The prototype runs over Wi-Fi/IP; the NR cell exists in the simulation only.',
    'ML-KEM and ML-DSA establish, wrap and sign. They do not encrypt the video or the audio: AES-256-GCM does.',
    'The rekey is a 1-RTT Cached RapidRekey, not 0-RTT.',
    'The Raspberry Pi has no microphone: a file stands in for one. Nothing here was recorded by the UAV in flight.',
    'One UAV, on a desk. No flight, no energy measurements, no glass-to-glass latency.',
    'The proofs are symbolic (ideal primitives) plus reductions for the components; there is no computational proof of the whole protocol.',
  ]

  return (
    <section id="overview" className="section" aria-label="Overview">
      <div className="section-inner">
        <span className="section-label">Overview</span>
        <h2>What it is, and how each claim is backed</h2>
        <p className="section-desc">
          Traffic recorded today can be decrypted later by whoever builds a quantum computer that breaks elliptic
          curves. A UAV's video, pictures, sound and position are exactly the kind of data worth keeping for that
          day. This project builds a link whose keys do not depend on elliptic curves alone, runs it on a
          Raspberry Pi and a laptop, and keeps four kinds of evidence strictly apart.
        </p>
        <div className="card-grid">
          {kinds.map((c, i) => (
            <ScrollReveal key={i} delay={(i % 3) + 1}>
              <article className="card">
                <div className="card-icon" style={{ background: c.bg, color: c.color }}>
                  <c.Icon size={22} />
                </div>
                <h3>{c.title}</h3>
                <p>{c.desc}</p>
              </article>
            </ScrollReveal>
          ))}
        </div>
        <ScrollReveal>
          <h3 className="sub">What this is not</h3>
          <ul className="finding-list">
            {not.map((t, i) => (
              <li key={i}>
                <span className="indicator caution" aria-hidden="true" />
                <span>{t}</span>
              </li>
            ))}
          </ul>
        </ScrollReveal>
      </div>
    </section>
  )
}
