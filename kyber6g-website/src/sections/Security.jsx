import ScrollReveal from '../components/ScrollReveal'
import Figure from '../components/Figure'
import ChartCard, { DataTable } from '../components/ChartCard'
import { rows, fmt } from '../data'

const ATTACKERS = [
  ['classical', 'breaks nothing'],
  ['shor', 'X25519 broken'],
  ['mlkem', 'ML-KEM broken'],
  ['both', 'both broken'],
]

function Metric({ label, value, unit, note }) {
  return (
    <div className="metric-card">
      <div className="label">{label}</div>
      <div className="value">{value}<span className="unit">{unit}</span></div>
      {note && <div className="delta">{note}</div>}
    </div>
  )
}

/* The rows of plot22_proof_matrix.csv (one per claim and attacker) as one row per claim. */
function Matrix({ data }) {
  const flat = rows(data, 'plot22_proof_matrix')
  if (!flat.length) return <p className="chart-note">The proof matrix has not been built yet (<code>bash run/kyber6g.sh plots</code>).</p>
  const claims = []
  const index = {}
  flat.forEach(r => {
    const k = `${r.protocol}|${r.claim}`
    if (!index[k]) {
      index[k] = { protocol: r.protocol, claim: r.claim, cells: {} }
      claims.push(index[k])
    }
    index[k].cells[r.attacker] = r.result
  })
  let last = null
  const body = []
  claims.forEach((c, i) => {
    if (c.protocol !== last) {
      body.push(<tr key={`g${i}`} className="group"><th colSpan={ATTACKERS.length + 1}>{c.protocol}</th></tr>)
      last = c.protocol
    }
    body.push(
      <tr key={i}>
        <td>{c.claim}</td>
        {ATTACKERS.map(([a]) => {
          const v = c.cells[a]
          if (v === 'proved') return <td key={a} className="mark ok"><span aria-hidden="true">●</span> proved</td>
          if (v === 'attack found') return <td key={a} className="mark no"><span aria-hidden="true">✕</span> attack found</td>
          if (v === 'not decided') return <td key={a} className="mark">not decided</td>
          return <td key={a} className="mark none">—</td>
        })}
      </tr>
    )
  })
  return (
    <div className="table-wrap">
      <table className="data-table matrix">
        <thead>
          <tr>
            <th>Claim</th>
            {ATTACKERS.map(([a, label]) => <th key={a}>Attacker: {label}</th>)}
          </tr>
        </thead>
        <tbody>{body}</tbody>
      </table>
    </div>
  )
}

export default function Security({ data }) {
  if (!data) return <section id="security" className="section" aria-label="Attacked and proved"><div className="section-inner"><p>Loading results…</p></div></section>
  const a = data.attacks
  const f = data.formal
  const ka = data.known_answers || {}
  const kaRows = rows(data, 'plot22_known_answers')
  const cb = data.cbom
  const groups = [
    ...a.link_and_files.groups.map(g => ({ ...g, where: 'link and stored files' })),
    ...a.audio.groups.map(g => ({ ...g, where: 'sealed audio' })),
  ]
  const notProved = [
    'There is no computational proof of the whole protocol. Handshake, rekey and ratchet are proved in the symbolic model (ideal primitives, no timing, no sizes); the computational arguments are for the components.',
    'Authentication is post-quantum only, not hybrid: if ML-DSA-87 were broken, an active attacker could impersonate either side from then on. Traffic recorded before stays closed.',
    'SHA-256 is used, not SHA-384, which is a deviation from CNSA 2.0 and is stated as one.',
    'No side-channel or fault analysis was made; keys are files on an SD card, not in a secure element.',
    'Jamming, flooding above the ration and dropping packets remain possible; sizes and timing of the records are visible.',
    'The Python code itself is tested (unit tests, known answers, attack experiments), not verified.',
  ]

  return (
    <section id="security" className="section" aria-label="Attacked and proved">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Attacked &amp; proved</span>
          <h2>Three kinds of evidence, and what none of them shows</h2>
          <p className="section-desc">
            The running implementation was attacked on both machines; the protocols were modelled and checked with
            ProVerif under four attackers; the libraries were held against NIST's known-answer vectors, and both
            programs repeat a self-test of their cryptography at every start and refuse to run if it fails.
          </p>
        </ScrollReveal>

        <div className="metric-grid">
          <ScrollReveal delay={1}>
            <Metric label="False inputs offered" value={fmt(a.link_and_files.attempts + a.audio.attempts)}
              note={`accepted: ${fmt(a.link_and_files.accepted + a.audio.accepted)}`} />
          </ScrollReveal>
          {f && (
            <ScrollReveal delay={2}>
              <Metric label="Claims proved (ProVerif)" value={`${fmt(f.claims_proved)} of ${fmt(f.claims)}`}
                note={`${fmt(f.runs)} runs, ${fmt(f.queries)} queries, ${fmt(f.seconds, 0)} s`} />
            </ScrollReveal>
          )}
          {f && (
            <ScrollReveal delay={3}>
              <Metric label="Attacks found where one must exist" value={`${fmt(f.attacks_found_where_expected)} of ${fmt(f.attacks_expected)}`}
                note="the model is not blind" />
            </ScrollReveal>
          )}
          {Object.entries(ka).map(([name, k], i) => (
            <ScrollReveal key={name} delay={4 + i}>
              <Metric label={`Known answers, ${name === 'pi' ? 'Raspberry Pi' : 'laptop'}`} value={`${fmt(k.passed)} of ${fmt(k.vectors)}`}
                note={`liboqs ${k.liboqs}, ${k.arch}`} />
            </ScrollReveal>
          ))}
        </div>

        <ScrollReveal>
          <Figure name="fig02_threat_model" caption="Who the attacker is, what they may do, and what is out of scope." />
        </ScrollReveal>

        <ScrollReveal>
          <ChartCard title="Attacked: what was offered, and what got through" kind="attacked"
            note={`Both machines together. Controls: ${fmt(a.audio.controls.accepted)} of ${fmt(a.audio.controls.offered)} genuine clips, excerpts and live blocks were accepted, as they must be. Separately, ${fmt(a.link_and_files.sender_stress.records_sealed)} records were sealed by racing threads; nonces used twice: ${fmt(a.link_and_files.sender_stress.nonces_used_twice)}.`}>
            <DataTable data={groups}
              cols={[['where', 'Part'], ['group', 'Target'], ['experiments', 'Kinds of attack', 0], ['attempts', 'Attempts', 0], ['accepted', 'Accepted', 0]]} />
          </ChartCard>
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="plot10_attacks" kind="attacked" caption="Every attack experiment on the link and on stored photos and recordings, on the Raspberry Pi and on the laptop." />
        </ScrollReveal>

        <ScrollReveal>
          <ChartCard title="Proved: claim by claim, attacker by attacker" kind="proved"
            note="ProVerif, for any number of sessions. A cross is not a failure of the protocol: it is the same claim with the decisive scheme broken or the decisive key leaked, where an attack must exist, and the tool finds it. A model that proved those cases too would be worthless. A dash: not run, because an attack found with nothing broken exists all the more with something broken.">
            <Matrix data={data} />
          </ChartCard>
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="plot22_proof_matrix" kind="proved" caption="The same matrix as printed in the paper, with the known-answer tests of both machines." />
        </ScrollReveal>

        {kaRows.length > 0 && (
          <ScrollReveal>
            <ChartCard title="Checked: the libraries against published answers" kind="checked"
              note="ML-KEM-1024 and ML-DSA-87 against NIST's ACVP vectors (FIPS 203 and FIPS 204), with the vectors' own random values fed into the library; the classical parts against the vectors of their RFCs and of NIST.">
              <DataTable data={kaRows}
                cols={[['test', 'Test'], ['what', 'What is compared'], ['vectors', 'Vectors', 0], ['passed_pi', 'Passed, Pi', 0], ['passed_laptop', 'Passed, laptop', 0]]} />
            </ChartCard>
          </ScrollReveal>
        )}

        <ScrollReveal>
          <h3 className="sub">Post-quantum, kind of data by kind of data</h3>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Data</th><th>Stays secret if X25519 is broken</th><th>Stays secret if ML-KEM is broken</th><th>Origin checked with</th></tr>
              </thead>
              <tbody>
                <tr><td>Live video, telemetry, status, motion reports, commands</td><td>yes (session keys need both)</td><td>yes</td><td>ML-DSA-87 at the handshake, then the session's keys</td></tr>
                <tr><td>Stored photo, recording, audio clip</td><td>yes (file key wrapped under both)</td><td>yes</td><td>ML-DSA-87 signature over every byte</td></tr>
                <tr><td>Excerpt of an audio clip for a third party</td><td colSpan={2}>only the released blocks open; the rest stays sealed</td><td>ML-DSA-87 signature, checkable with the public key alone</td></tr>
              </tbody>
            </table>
          </div>
          <p className="chart-note">
            Both columns are claims of the proof matrix above (rows "new keys secret" and "content secret"), not measurements.
            The data itself is encrypted with AES-256-GCM in every case.
            {cb ? ` A cryptographic bill of materials (${cb.spec}) lists the ${fmt(cb.cryptographic_assets)} cryptographic assets and ${fmt(cb.libraries)} libraries in use; it is generated from the code.` : ''}
          </p>
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">What is not proved, and is not claimed</h3>
          <ul className="finding-list">
            {notProved.map((t, i) => (
              <li key={i}><span className="indicator caution" aria-hidden="true" /><span>{t}</span></li>
            ))}
          </ul>
        </ScrollReveal>
      </div>
    </section>
  )
}
