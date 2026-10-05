import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import ScrollReveal from '../components/ScrollReveal'
import Figure from '../components/Figure'
import ChartCard, { DataTable } from '../components/ChartCard'
import legend from '../components/legend'
import { rows, pivot, SERIES, SIMULATED, AXIS, GRID, TIP } from '../data'

const DASHES = ['0', '6 4']

/* Panel (a) of the paper's plot 21: generated scenes in black and grey, the UAV's own camera in colour. */
function FoundByContrast({ data }) {
  // (the table also has a target darker than its background, contrast -25: it has no place on a logarithmic axis)
  const [points, names] = pivot(rows(data, 'plot21_motion_watch').filter(r => r.panel === 'a' && r.x > 0), 'x', 'series', 'found_pct')
  if (!points.length) return <p className="chart-note">Not measured yet (<code>bash run/kyber6g.sh measure motion</code>, then <code>plots</code>).</p>
  const generated = names.filter(n => n.startsWith('generated'))
  const camera = names.filter(n => !n.startsWith('generated'))
  const xs = points.map(p => p.x)
  return (
    <ResponsiveContainer width="100%" height={340}>
      <LineChart data={points} margin={{ top: 8, right: 24, left: 4, bottom: 24 }}>
        <CartesianGrid stroke={GRID} />
        {/* a logarithmic axis needs its two ends as numbers */}
        <XAxis type="number" dataKey="x" scale="log" domain={[Math.min(...xs), Math.max(...xs)]} ticks={[3, 6, 12, 25, 40]}
          tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
          label={{ value: 'contrast of the target (grey levels of 255, logarithmic)', position: 'bottom', offset: 4, ...AXIS }} />
        <YAxis domain={[0, 100]} tick={AXIS} tickLine={false} axisLine={false} unit=" %" width={52} />
        <Tooltip contentStyle={TIP} labelFormatter={v => `contrast ${v}`} formatter={v => `${v} % of the looks`} />
        <Legend verticalAlign="top" height={72} {...legend} />
        {generated.map((n, i) => (
          <Line key={n} type="linear" dataKey={n} name={`${n.replace('generated scene: ', '')}, generated`} stroke={SIMULATED[i % 2]} strokeWidth={2}
            strokeDasharray={DASHES[i % 2]} connectNulls isAnimationActive={false}
            dot={{ r: 4, fill: SIMULATED[i % 2], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 6 }} />
        ))}
        {camera.map((n, i) => (
          <Line key={n} type="linear" dataKey={n} name={n.replace('UAV camera', 'the camera')} stroke={SERIES[i]} strokeWidth={0} legendType="circle"
            isAnimationActive={false} dot={{ r: 5, fill: SERIES[i], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 7 }} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

function HeardLive({ data }) {
  const [points, names] = pivot(rows(data, 'plot20_audio_live_loss'), 'uplink_loss_pct',
    r => (r.frames_per_block === 1 ? 'one datagram per block' : `${r.datagrams_per_block} datagrams per block`), 'heard_live_pct')
  if (!points.length) return null
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={points} margin={{ top: 8, right: 24, left: 4, bottom: 24 }}>
        <CartesianGrid stroke={GRID} />
        <XAxis type="number" dataKey="x" domain={[0, 21]} ticks={[0, 5, 10, 15, 20]} tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
          label={{ value: 'datagrams lost on the way to the ground station (%)', position: 'bottom', offset: 4, ...AXIS }} />
        <YAxis domain={[0, 100]} tick={AXIS} tickLine={false} axisLine={false} unit=" %" width={52} />
        <Tooltip contentStyle={TIP} labelFormatter={v => `${v} % lost`} formatter={v => `${v} % heard live`} />
        <Legend verticalAlign="top" height={32} iconType="plainline" {...legend} />
        {names.map((n, i) => (
          <Line key={n} type="linear" dataKey={n} name={n} stroke={SERIES[i]} strokeWidth={2} connectNulls isAnimationActive={false}
            dot={{ r: 4, fill: SERIES[i], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 6 }} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

const CASES = [
  ['Landed or perched listening post', 'The UAV flies somewhere, lands, stops its rotors and listens: no rotor noise.'],
  ['Microphone array with its own processing', 'The payload delivers enhanced audio; the UAV seals what it is given.'],
  ['Microphone on a tether or a boom', 'Distance from the rotors; still needs wind protection.'],
  ['Fixed wing, gliding with the motor off', 'No propulsion noise for as long as the glide lasts.'],
  ['Relay and data mule', 'A ground sensor or a team hands audio to the UAV, which stores and carries or forwards it.'],
  ['Short clips around a loud event', 'A loud event survives noise that speech does not.'],
  ['Voice notes of the crew', 'Recorded on the ground and attached to the mission\'s data.'],
]

const EXCEPTIONS = [
  'This prototype has no microphone. A file put into the Pi\'s inbox stands in for one; nothing here was recorded by the UAV. The clip used for the statistics is a free sample supplied by the project owner.',
  'In flight, next to the rotors, a plain microphone records the rotors. The feature would seal that faithfully. No noise reduction is implemented, and none was tested.',
  'Noise reduction belongs before sealing or after opening, never in between: a cipher that tolerates processing of the ciphertext can also be changed by an attacker. An enhanced copy made on the ground is a derived copy that the UAV did not sign.',
  'The uniform block shape that hides silence costs bytes when the bit rate varies.',
  'Recording people\'s conversations without consent is restricted in many places. That is the operator\'s responsibility; the software does not decide it.',
]

const MOTION_LIMITS = [
  'The targets are drawn: into generated scenes, and on the UAV into its own camera\'s pictures. No person, vehicle or animal was tracked in a field trial, and the UAV has not flown.',
  'Camera movement was imitated by shifting pictures. One bright thing in an otherwise empty picture that the camera passes slowly (under about a pixel per look) cannot be told from a thing that moves by itself: the camera is then taken to stand still and the thing is reported, unless the GNSS says the UAV is under way, in which case the watch stays silent.',
  'A near, still thing passed by a moving camera (parallax) looks like a thing that moves. Something that fills most of the picture is taken for movement of the camera.',
  'Where it failed: in a room lit by a lamp only (89 lux), a part of the scene changed its brightness by up to a tenth ten times a second. The watch then says "the picture as a whole changed" and reports nothing: the drawn target was found in 0 of 26 looks, with no false region. Not repaired.',
  'It answers "something moves here", not "what is it": naming things is the detector\'s job, at the ground station, with a person deciding.',
]

export default function Sensing({ data }) {
  const cost = rows(data, 'plot21_motion_cost')
  const audio = rows(data, 'plot19_audio_cost').filter(r => String(r.machine).includes('Pi'))
  return (
    <section id="sensing" className="section alt" aria-label="Motion watch and sealed audio">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Motion &amp; audio</span>
          <h2>What the companion computer notices, and what it seals</h2>
          <p className="section-desc">
            The node is built as a companion computer: a camera with a near-infrared night mode, a motion watch that
            runs on board, object detection at the ground station with a person in the loop, and audio that is sealed
            block by block. Everything it reports travels inside the secure link.
          </p>
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">Motion watch, on board</h3>
          <p>
            Several times a second the node looks at a small copy of the camera picture, measures how the whole
            picture moved since the last look, undoes that movement, and reports what still differs: boxes in the
            status stream, drawn over the live video at the ground station. In a dim scene, where single pixels are
            mostly noise, the camera's movement is measured on pictures an eighth of the size, and a test with a
            known error rate decides whether the rest of the picture moved too (a camera passing a lamp) or not (a
            lamp that moves). A photo can be taken when something moves; it is sealed and signed like any other.
          </p>
          <Figure name="fig19_motion_watch" caption="The motion watch, step by step, computed by the detector itself from an aerial photograph." />
        </ScrollReveal>

        <div className="charts-grid">
          <ScrollReveal delay={1}>
            <ChartCard title="How faint a moving thing may be" kind="measured + simulated"
              note="Share of the looks in which a moving target of 8 pixels is found. Black and grey: generated scenes (simulated). Colour: the UAV's own camera in a lit room, the target drawn into its pictures on the UAV (measured; all looks of three captures together).">
              <FoundByContrast data={data} />
            </ChartCard>
          </ScrollReveal>
          <ScrollReveal delay={2}>
            <ChartCard title="What the watch costs the UAV" kind="measured"
              note="Watch switched off and on in turns while live video ran; medians of the stretches. ** With the watch on, the Pi's governor raises the processor clock: that is why the other work gets quicker, not slower.">
              {cost.length
                ? <DataTable data={cost} cols={[['quantity', 'Quantity'], ['watch_off', 'Watch off'], ['watch_on', 'Watch on']]} />
                : <p className="chart-note">Not measured yet.</p>}
            </ChartCard>
          </ScrollReveal>
        </div>
        <ScrollReveal>
          <Figure name="plot21_motion_watch" kind="measured + simulated" caption="The motion watch by contrast, size and speed of the target, while the camera moves, with nothing moving, and its cost." />
        </ScrollReveal>
        <ScrollReveal>
          <h3 className="sub">Limits of the motion watch</h3>
          <ul className="finding-list">
            {MOTION_LIMITS.map((t, i) => <li key={i}><span className="indicator caution" aria-hidden="true" /><span>{t}</span></li>)}
          </ul>
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">Detection, with a person in the loop</h3>
          <p>
            Naming what is in the picture is done at the ground station, on the decrypted video: a real-time detector
            with several profiles, a slower and more accurate finder, and an operator who confirms or rejects what
            they propose. The night mode changes exposure, gain and colour only; the camera sees in the dark as far
            as its two 850 nm lamps reach.
          </p>
          <Figure name="fig08_perception_hitl" caption="From the decrypted video to a confirmed, geotagged detection." />
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">Sealed audio</h3>
          <p>
            Encoded audio is cut into blocks of one size, each sealed under its own key, all of them bound by one
            ML-DSA-87 signature. Only the ground station can open a clip; the UAV cannot read back what it stored;
            a stretch of a clip can be handed to a third party who checks it with the UAV's public key alone.
          </p>
          <Figure name="fig15_audio_sealing" caption="How a clip is sealed: a key per block from one clip key, a tree of hashes over the blocks, one signature." />
        </ScrollReveal>

        <div className="charts-grid">
          <ScrollReveal delay={1}>
            <ChartCard title="Heard live when datagrams are lost" kind="measured"
              note="Blocks that did not arrive are fetched from the UAV's card afterwards: every clip was completed and verified, byte for byte the source.">
              <HeardLive data={data} />
            </ChartCard>
          </ScrollReveal>
          <ScrollReveal delay={2}>
            <ChartCard title="Sealing audio on the Raspberry Pi" kind="measured">
              <DataTable data={audio}
                cols={[['clip_s', 'Clip, s', 0], ['added_pct', 'Bytes added, %', 1], ['seal_ms', 'Seal, ms', 1], ['open_ms', 'Open, ms', 1],
                  ['verify_without_keys_ms', 'Verify without keys, ms', 1], ['seal_times_real_time', 'Times real time', 0]]} />
            </ChartCard>
          </ScrollReveal>
        </div>
        <ScrollReveal>
          <Figure name="fig17_audio_excerpt" caption="An excerpt for a third party: the blocks, the few keys that open them, and the proof that they belong to the signed clip." />
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">Can a UAV record sound at all?</h3>
          <p>
            Camera drones normally carry no microphone, because the rotors drown out what one would want to hear.
            The sealing does not depend on where the audio comes from, so the question is when there is audio worth
            sealing:
          </p>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Case</th><th>Why the rotor problem does not apply, or is dealt with</th></tr></thead>
              <tbody>{CASES.map((c, i) => <tr key={i}><td><strong>{c[0]}</strong></td><td>{c[1]}</td></tr>)}</tbody>
            </table>
          </div>
          <ul className="finding-list">
            {EXCEPTIONS.map((t, i) => <li key={i}><span className="indicator caution" aria-hidden="true" /><span>{t}</span></li>)}
          </ul>
        </ScrollReveal>
      </div>
    </section>
  )
}
