import ScrollReveal from '../components/ScrollReveal'
import Figure from '../components/Figure'

/* What protects each kind of data: a statement about the design (kyber6g/crypto, recording, audio), not a measurement. */
const KINDS = [
  ['Live video', 'AES-256-GCM records under session keys', 'not stored unless recording', 'authentic to the ground station (session)'],
  ['Recorded video (.k6grec)', 'the sealed file itself is sent', 'file key wrapped with ML-KEM-1024 + X25519', 'ML-DSA-87 signature of the UAV'],
  ['Photo (.k6gimg)', 'AES-256-GCM records; SHA-256 checked on arrival', 'file key wrapped with ML-KEM-1024 + X25519', 'ML-DSA-87 signature of the UAV'],
  ['Audio (.k6gaud)', 'the same sealed blocks that go to the card', 'clip key wrapped with ML-KEM-1024 + X25519; a key per block', 'one ML-DSA-87 signature over all blocks; excerpts verifiable by anyone'],
  ['Telemetry, status, motion reports', 'AES-256-GCM records under session keys', 'never written to the card (memory only, two hours)', 'authentic to the ground station (session)'],
  ['Commands (ground to UAV)', 'AES-256-GCM records under session keys', 'not stored', 'authentic to the UAV (session)'],
]

export default function Architecture() {
  return (
    <section id="architecture" className="section alt" aria-label="Architecture">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Architecture</span>
          <h2>Two machines, one secure link, five kinds of data</h2>
          <p className="section-desc">
            The UAV node captures and seals; the ground station verifies, opens, stores and shows. Session keys come
            from a handshake in which ML-KEM-1024 and X25519 both contribute and both ends sign with ML-DSA-87 keys
            that were pinned beforehand. Files written on the UAV are sealed to the ground station: the UAV cannot
            read back what it stored.
          </p>
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="fig01_system_overview" caption="The prototype: Raspberry Pi 4B with camera, GNSS receiver and display; ground control station with the dashboard." />
        </ScrollReveal>
        <ScrollReveal>
          <h3 className="sub">What protects each kind of data</h3>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Data</th><th>In transit</th><th>At rest on the UAV</th><th>Origin</th></tr>
              </thead>
              <tbody>
                {KINDS.map((r, i) => (
                  <tr key={i}>{r.map((c, j) => <td key={j}>{j === 0 ? <strong>{c}</strong> : c}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="fig11_media_protection" caption="Where the post-quantum algorithms act on video and on stored files, and where AES-256-GCM does the encrypting." />
        </ScrollReveal>
      </div>
    </section>
  )
}
