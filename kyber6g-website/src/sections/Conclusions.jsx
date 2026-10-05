import ScrollReveal from '../components/ScrollReveal'
import { rows, fmt } from '../data'

export default function Conclusions({ data }) {
  const lat = rows(data, 'plot02_handshake_latency')
  const op = name => lat.find(r => r.operation.toLowerCase().includes(name)) || {}
  const full = op('full'), cached = op('cached')
  const a = data ? data.attacks : null
  const f = data ? data.formal : null

  const holds = [
    data && full.median_ms
      ? `A hybrid post-quantum handshake at the highest parameter sets (ML-KEM-1024, ML-DSA-87) completes in ${fmt(full.median_ms)} ms on a Raspberry Pi 4B over Wi-Fi, and the 1-RTT Cached RapidRekey in ${fmt(cached.median_ms)} ms (medians, with live video running).`
      : 'A hybrid post-quantum handshake at the highest parameter sets runs on a Raspberry Pi 4B with live video running.',
    'Every kind of data the node produces is covered: live video, recordings, photos, audio, and text (telemetry, status, motion reports, commands). Stored files are sealed to the ground station and signed by the UAV.',
    a
      ? `${fmt(a.link_and_files.attempts + a.audio.attempts)} false inputs were offered to the running implementation on both machines; ${fmt(a.link_and_files.accepted + a.audio.accepted)} were accepted.`
      : 'False inputs offered to the running implementation on both machines were refused.',
    f
      ? `ProVerif proves all ${fmt(f.claims)} secrecy and authentication claims made across its ${fmt(f.runs)} runs (nothing broken, X25519 broken, ML-KEM broken) and finds the attack in each of the ${fmt(f.attacks_expected)} cases built to have one.`
      : 'The protocols are modelled and checked with ProVerif under four attackers.',
    'The node notices movement on board, with the camera still or moving, and reports it inside the secure link.',
  ]
  const limits = [
    'Wi-Fi, one UAV, on a desk. No 5G or 6G radio was used; more UAVs, a cellular cell, movement and range exist in the simulation only.',
    'The UAV has not flown. Nothing was measured in the air: no vibration, no real camera movement, no energy.',
    'No microphone: a file stands in for one. In flight a plain microphone would record the rotors.',
    'Live video does not survive packet loss well: a damaged frame blanks the picture until the next keyframe.',
    'The motion watch was tested with drawn targets and imitated camera movement, not in a field trial.',
    'The proofs are symbolic, with reductions for the components. There is no computational proof of the whole protocol, no side-channel or fault analysis and no independent penetration test.',
    'A captured UAV can be impersonated until its pinned key is removed at the ground station; what is stored on its card stays unreadable.',
    'A flood of forged handshakes delays a connection; jamming and dropped packets cannot be stopped by a protocol.',
  ]
  const wording = [
    ['"1-RTT Cached RapidRekey"', 'not "0-RTT"'],
    ['"session established with ML-KEM-1024 and X25519, data encrypted with AES-256-GCM"', 'not "post-quantum encrypted video" or "post-quantum encrypted audio"'],
    ['"prototype over Wi-Fi; an NR cell was simulated"', 'not "5G" or "6G link"'],
    ['"encoded audio from a file that stands in for a microphone"', 'not "audio recorded by the UAV"'],
    ['"proved in the symbolic model"', 'not "proven secure" or "unbreakable"'],
  ]

  return (
    <section id="limits" className="section alt" aria-label="What holds and the limits">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Limits</span>
          <h2>What holds, and what does not follow from it</h2>
        </ScrollReveal>
        <ScrollReveal>
          <h3 className="sub">What the evidence supports</h3>
          <ul className="finding-list">
            {holds.map((t, i) => <li key={i}><span className="indicator positive" aria-hidden="true" /><span>{t}</span></li>)}
          </ul>
        </ScrollReveal>
        <ScrollReveal>
          <h3 className="sub">Limits, stated plainly</h3>
          <ul className="finding-list">
            {limits.map((t, i) => <li key={i}><span className="indicator caution" aria-hidden="true" /><span>{t}</span></li>)}
          </ul>
        </ScrollReveal>
        <ScrollReveal>
          <h3 className="sub">Wording</h3>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Say</th><th>Do not say</th></tr></thead>
              <tbody>{wording.map((w, i) => <tr key={i}><td>{w[0]}</td><td>{w[1]}</td></tr>)}</tbody>
            </table>
          </div>
        </ScrollReveal>
      </div>
    </section>
  )
}
