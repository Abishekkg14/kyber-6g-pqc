import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import ScrollReveal from '../components/ScrollReveal'
import Figure from '../components/Figure'
import ChartCard, { DataTable } from '../components/ChartCard'
import legend from '../components/legend'
import { rows, pivot, fmt, SIMULATED, AXIS, GRID, TIP } from '../data'

const DASHES = ['0', '6 4']
const UAVS = [1, 2, 4, 8, 16, 32, 64]

/* One quantity of the swarm table against the number of UAVs, one line per cell. Black and grey: simulated. */
function Swarm({ list, y, unit, log, label }) {
  const [points, names] = pivot(list, 'uavs', 'cell', y)
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={points} margin={{ top: 8, right: 24, left: 4, bottom: 24 }}>
        <CartesianGrid stroke={GRID} />
        <XAxis type="number" dataKey="x" scale="log" domain={[1, 64]} ticks={UAVS} tick={AXIS} tickLine={false} axisLine={{ stroke: GRID }}
          label={{ value: 'UAVs in the cell, all streaming video (logarithmic)', position: 'bottom', offset: 4, ...AXIS }} />
        {log
          ? <YAxis scale="log" domain={[10, 1000]} ticks={[10, 20, 50, 100, 200, 500, 1000]} tick={AXIS} tickLine={false} axisLine={false} width={56}
              label={{ value: label, angle: -90, position: 'insideLeft', offset: 8, ...AXIS }} />
          : <YAxis domain={[0, 100]} tick={AXIS} tickLine={false} axisLine={false} unit=" %" width={56} />}
        <Tooltip contentStyle={TIP} labelFormatter={v => `${v} UAVs`} formatter={v => `${fmt(v)} ${unit}`} />
        <Legend verticalAlign="top" height={48} iconType="plainline" {...legend} />
        {names.map((n, i) => (
          <Line key={n} type="linear" dataKey={n} name={n} stroke={SIMULATED[i % 2]} strokeWidth={2} strokeDasharray={DASHES[i % 2]}
            isAnimationActive={false} dot={{ r: 4, fill: SIMULATED[i % 2], stroke: '#ffffff', strokeWidth: 2 }} activeDot={{ r: 6 }} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

export default function Simulation({ data }) {
  const swarm = rows(data, 'plot12_sim_swarm')
  const ablation = rows(data, 'plot15_ablation_crypto')
  const cells = [...new Set(swarm.map(r => r.cell))]
  /* per cell: the largest swarm that still gets 99 % of its video frames through */
  const holds = cells.map(c => {
    const ok = swarm.filter(r => r.cell === c && r.frames_complete_pct_of_sent >= 99)
    const last = ok[ok.length - 1]
    return last ? `${c}: up to ${last.uavs} UAVs, full handshake ${fmt(last.full_median_ms)} ms` : `${c}: none`
  })

  return (
    <section id="simulation" className="section" aria-label="Simulated">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Simulated</span>
          <h2>What one UAV on a desk cannot show</h2>
          <p className="section-desc">
            Many UAVs, a 5G NR cell, movement and range were simulated: the implemented protocol in ns-3 with 5G-LENA,
            its timings and message sizes taken from the measurements. This is a model, not a measurement, and no
            cellular radio was used. Simulated results are drawn in black and grey throughout.
          </p>
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="fig12_simulation_setup" kind="simulated" caption="The simulation: what is taken from the test bed, what is modelled, and what is varied." />
        </ScrollReveal>

        {swarm.length > 0 && (
          <>
            <div className="charts-grid">
              <ScrollReveal delay={1}>
                <ChartCard title="Full handshake in a shared cell" kind="simulated"
                  note="Median time of a full handshake while every UAV streams video. Both axes are logarithmic.">
                  <Swarm list={swarm} y="full_median_ms" unit="ms" log label="milliseconds" />
                </ChartCard>
              </ScrollReveal>
              <ScrollReveal delay={2}>
                <ChartCard title="Video that gets through" kind="simulated"
                  note="Share of the video frames sent that arrive whole. Where it falls, the cell's uplink is full: the limit is the capacity for video, not the session protocol.">
                  <Swarm list={swarm} y="frames_complete_pct_of_sent" unit="%" />
                </ChartCard>
              </ScrollReveal>
            </div>
            <ScrollReveal>
              <p className="chart-note">With at least 99 % of the video frames arriving: {holds.join('; ')}.</p>
            </ScrollReveal>
          </>
        )}
        <ScrollReveal>
          <Figure name="plot12_sim_swarm" kind="simulated" caption="The same runs as printed in the paper: all three session operations, the video, and the load on the ground station." />
        </ScrollReveal>

        {ablation.length > 0 && (
          <ScrollReveal>
            <ChartCard title="What the post-quantum part costs, algorithm by algorithm" kind="simulated"
              note="The handshake with other algorithms in its place. Bytes and datagrams follow from the algorithms' sizes; the computing time was measured on the Raspberry Pi for each algorithm; the two medians are simulated.">
              <DataTable data={ablation}
                cols={[['algorithms', 'Algorithms'], ['wire_bytes', 'Bytes on the wire', 0], ['datagrams', 'Datagrams', 0], ['uav_compute_ms', 'UAV computing, ms', 2],
                  ['testbed_loss0_median_ms', 'Median, replica of the test bed, ms', 1], ['nr_median_ms', 'Median, NR cell, ms', 1]]} />
            </ChartCard>
          </ScrollReveal>
        )}
      </div>
    </section>
  )
}
