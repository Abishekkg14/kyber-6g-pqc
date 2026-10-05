import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ErrorBar, LabelList } from 'recharts'
import ScrollReveal from '../components/ScrollReveal'
import ChartCard, { DataTable } from '../components/ChartCard'
import legend from '../components/legend'
import { rows, fmt, SERIES, AXIS, GRID, TIP } from '../data'

function Metric({ label, value, unit, note }) {
  return (
    <div className="metric-card">
      <div className="label">{label}</div>
      <div className="value">{value}<span className="unit">{unit}</span></div>
      {note && <div className="delta">{note}</div>}
    </div>
  )
}

function LatencyTip({ active, payload }) {
  if (!active || !payload || !payload.length) return null
  const r = payload[0].payload
  return (
    <div className="tip">
      <strong>{r.operation}</strong>
      <div>median {fmt(r.median_ms)} ms</div>
      <div>5th to 95th percentile: {fmt(r.p5_ms)} to {fmt(r.p95_ms)} ms</div>
      <div>slowest {fmt(r.max_ms)} ms · {r.succeeded} of {r.attempted} completed</div>
    </div>
  )
}

function LossTip({ active, payload }) {
  if (!active || !payload || !payload.length) return null
  const r = payload[0].payload
  return (
    <div className="tip">
      <strong>{fmt(r.uplink_loss_pct, 2)} % of the datagrams lost</strong>
      <div>frames that arrived whole: {fmt(r.complete_pct)} % ({fmt(r.frames_complete)} of {fmt(r.frames_complete + r.frames_lost)})</div>
      <div>frames shown: {fmt(r.decoded_pct)} %</div>
    </div>
  )
}

const PARTS = [
  ['signature_bytes', 'ML-DSA-87 signatures'],
  ['kem_bytes', 'ML-KEM-1024 key and ciphertext'],
  ['other_bytes', 'everything else in the messages'],
  ['header_bytes', 'record headers and tags'],
]

export default function ResultsDashboard({ data }) {
  if (!data) {
    return (
      <section id="results" className="section alt" aria-label="Measured results">
        <div className="section-inner"><p>Loading results…</p></div>
      </section>
    )
  }
  const lat = rows(data, 'plot02_handshake_latency').map(r => ({ ...r, spread: [r.median_ms - r.p5_ms, r.p95_ms - r.median_ms] }))
  const wire = rows(data, 'plot03_wire_bytes')
  const loss = rows(data, 'plot06_loss_video')
  const prim = rows(data, 'plot01_crypto_primitives')
  const sched = rows(data, 'table_rekey_schedule')
  const env = rows(data, 'table_environment').map(r => ({ ...r, cpu_has_aes: r.cpu_has_aes === 'True' ? 'yes' : 'no' }))
  const budget = rows(data, 'plot07_latency_budget')
  const parts = rows(data, 'handshake_breakdown')
  const op = (list, name) => list.find(r => r.operation.toLowerCase().includes(name)) || {}
  const full = op(lat, 'full'), cached = op(lat, 'cached'), ratchet = op(lat, 'ratchet')
  const wFull = op(wire, 'full'), wCached = op(wire, 'cached')
  const asBuilt = sched[0] || {}
  const pi = env.find(r => r.machine.includes('Pi')) || {}
  const noAes = pi.cpu_has_aes === 'no'

  return (
    <section id="results" className="section alt" aria-label="Measured results">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Measured</span>
          <h2>What the prototype does on real hardware</h2>
          <p className="section-desc">
            Timed on the Raspberry Pi 4B and the laptop themselves, over Wi-Fi, in the running system.
            {noAes ? ' The Pi\'s processor has no AES instructions, so AES-256-GCM runs in software there.' : ''}
            {' '}Every sample behind these numbers is in the repository.
          </p>
        </ScrollReveal>

        <div className="metric-grid">
          <ScrollReveal delay={1}>
            <Metric label="Full handshake" value={fmt(full.median_ms)} unit="ms"
              note={`median of ${fmt(full.attempted)}; 95 % within ${fmt(full.p95_ms)} ms`} />
          </ScrollReveal>
          <ScrollReveal delay={2}>
            <Metric label="1-RTT Cached RapidRekey" value={fmt(cached.median_ms)} unit="ms"
              note={`${fmt(full.median_ms / cached.median_ms)} times quicker than a full handshake`} />
          </ScrollReveal>
          <ScrollReveal delay={3}>
            <Metric label="PQ ratchet" value={fmt(ratchet.median_ms)} unit="ms"
              note={`95 % within ${fmt(ratchet.p95_ms)} ms`} />
          </ScrollReveal>
          <ScrollReveal delay={4}>
            <Metric label="Full handshake on the wire" value={fmt(wFull.total_bytes_on_wire)} unit="bytes"
              note={`${fmt(wFull.datagrams)} datagrams; a cached rekey takes ${fmt(wCached.total_bytes_on_wire)} bytes`} />
          </ScrollReveal>
          <ScrollReveal delay={5}>
            <Metric label="Rekeying, per hour" value={fmt(asBuilt.kilobytes_per_hour_on_the_wire)} unit="kB"
              note={`${fmt(asBuilt.bytes_saved_against_full_handshakes_pct)} % less than a full handshake each time`} />
          </ScrollReveal>
        </div>

        <div className="charts-grid">
          <ScrollReveal delay={1}>
            <ChartCard title="Time to new keys" kind="measured"
              note="Bars: median over the link. Whiskers: 5th to 95th percentile. Request sent to keys in use, on the UAV.">
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={lat} layout="vertical" margin={{ top: 8, right: 28, left: 8, bottom: 20 }}>
                  <CartesianGrid horizontal={false} stroke={GRID} />
                  <XAxis type="number" tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
                    label={{ value: 'milliseconds', position: 'bottom', offset: 0, ...AXIS }} />
                  <YAxis type="category" dataKey="operation" width={170} tick={{ ...AXIS, fill: '#1a1a2e' }} tickLine={false} axisLine={false} />
                  <Tooltip content={<LatencyTip />} cursor={{ fill: 'rgba(0,0,0,.04)' }} />
                  <Bar dataKey="median_ms" name="median" fill={SERIES[0]} barSize={18} radius={[0, 4, 4, 0]} isAnimationActive={false}>
                    <ErrorBar dataKey="spread" direction="x" width={6} strokeWidth={1.5} stroke="#1a1a2e" />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </ScrollReveal>

          <ScrollReveal delay={2}>
            <ChartCard title="Bytes on the wire" kind="measured"
              note="Counted from the datagrams themselves. The numbers are in the table below.">
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={wire} layout="vertical" margin={{ top: 8, right: 64, left: 8, bottom: 20 }}>
                  <CartesianGrid horizontal={false} stroke={GRID} />
                  <XAxis type="number" tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
                    tickFormatter={v => v.toLocaleString('en-US')}
                    label={{ value: 'bytes', position: 'bottom', offset: 0, ...AXIS }} />
                  <YAxis type="category" dataKey="operation" width={110} tick={{ ...AXIS, fill: '#1a1a2e' }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={TIP} cursor={{ fill: 'rgba(0,0,0,.04)' }} formatter={v => `${v.toLocaleString('en-US')} bytes`} />
                  <Legend verticalAlign="top" height={44} iconType="square" {...legend} />
                  {PARTS.map(([key, name], i) => (
                    <Bar key={key} dataKey={key} name={name} stackId="bytes" fill={SERIES[i]} stroke="#ffffff" strokeWidth={2}
                      barSize={18} isAnimationActive={false}>
                      {i === PARTS.length - 1 && (
                        <LabelList dataKey="total_bytes_on_wire" position="right" formatter={v => v.toLocaleString('en-US')}
                          style={{ fontSize: 12, fill: '#1a1a2e' }} />
                      )}
                    </Bar>
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </ScrollReveal>
        </div>

        {parts.length > 0 && (
          <ScrollReveal>
            <DataTable data={parts} caption="Where the time of an operation goes (medians, timed inside the running programs, in milliseconds)"
              cols={[['operation', 'Operation'], ['uav_ms', 'Computing on the UAV', 1], ['gcs_ms', 'Computing at the ground station', 1],
                ['link_and_wait_ms', 'Link and waiting', 1], ['median_ms', 'Whole operation', 1]]} />
          </ScrollReveal>
        )}

        <ScrollReveal>
          <DataTable data={wire} caption="Bytes on the wire, by what they carry"
            cols={[['operation', 'Operation'], ['signature_bytes', 'Signatures', 0], ['kem_bytes', 'ML-KEM', 0], ['other_bytes', 'Other', 0],
              ['header_bytes', 'Headers and tags', 0], ['total_bytes_on_wire', 'Total', 0], ['datagrams', 'Datagrams', 0]]} />
        </ScrollReveal>

        <div className="charts-grid">
          <ScrollReveal delay={1}>
            <ChartCard title="Live video when datagrams are lost" kind="measured"
              note="After a damaged frame the receiver waits for the next keyframe, so far fewer frames are shown than arrive. A keyframe on request and forward error correction are not implemented. The loss axis is drawn on a square-root scale.">
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={loss} margin={{ top: 8, right: 24, left: 4, bottom: 24 }}>
                  <CartesianGrid stroke={GRID} />
                  <XAxis type="number" dataKey="uplink_loss_pct" scale="sqrt" domain={[0, 20]} ticks={[0, 0.5, 1, 2, 5, 10, 20]}
                    tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
                    label={{ value: 'datagrams lost on the way to the ground station (%)', position: 'bottom', offset: 4, ...AXIS }} />
                  <YAxis domain={[0, 100]} tick={AXIS} tickLine={false} axisLine={false} unit=" %" width={52} />
                  <Tooltip content={<LossTip />} />
                  <Legend verticalAlign="top" height={32} iconType="plainline" {...legend} />
                  <Line type="linear" dataKey="complete_pct" name="frames that arrived whole" stroke={SERIES[0]} strokeWidth={2}
                    dot={{ r: 4, fill: SERIES[0], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 6 }} isAnimationActive={false} />
                  <Line type="linear" dataKey="decoded_pct" name="frames shown" stroke={SERIES[1]} strokeWidth={2}
                    dot={{ r: 4, fill: SERIES[1], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 6 }} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </ChartCard>
          </ScrollReveal>

          <ScrollReveal delay={2}>
            <ChartCard title="Where the video's delay comes from" kind="measured"
              note="Sensor to decoded picture; the display itself (glass to glass) was not measured.">
              <DataTable data={budget} cols={[['component', 'Part'], ['ms', 'ms', 1]]} />
            </ChartCard>
          </ScrollReveal>
        </div>

        <ScrollReveal>
          <h3 className="sub">The building blocks, on both machines</h3>
          <DataTable data={prim} caption="Median time of one operation, in microseconds"
            cols={[['operation', 'Operation'], ['pi_median_us', 'Raspberry Pi 4B', 1], ['laptop_median_us', 'Laptop', 1], ['pi_over_laptop', 'Pi / laptop', 2]]} />
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">What rekeying costs in an hour</h3>
          <DataTable data={sched}
            cols={[['schedule', 'Schedule'], ['operations_per_hour', 'Operations', 0], ['kilobytes_per_hour_on_the_wire', 'kB on the wire', 1],
              ['uav_computing_ms_per_hour_in_the_running_system', 'UAV computing, ms', 1], ['time_in_operations_ms_per_hour', 'Time in operations, ms', 1],
              ['bytes_saved_against_full_handshakes_pct', 'Bytes saved, %', 1]]} />
        </ScrollReveal>

        <ScrollReveal>
          <h3 className="sub">The two machines</h3>
          <DataTable data={env}
            cols={[['machine', 'Machine'], ['cpu', 'Processor'], ['arch', 'Architecture'], ['python', 'Python'], ['liboqs', 'liboqs'],
              ['openssl', 'OpenSSL'], ['cpu_has_aes', 'AES instructions in the processor']]} />
        </ScrollReveal>
      </div>
    </section>
  )
}
