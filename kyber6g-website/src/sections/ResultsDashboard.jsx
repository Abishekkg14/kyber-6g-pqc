import { useState, useMemo } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, AreaChart, Area } from 'recharts'
import ScrollReveal from '../components/ScrollReveal'

function MetricCard({ label, value, unit, delta, direction }) {
    return (
        <div className="metric-card">
            <div className="label">{label}</div>
            <div className="value">
                {value}<span className="unit">{unit}</span>
            </div>
            {delta && (
                <div className={`delta ${direction === 'up' ? 'up' : 'down'}`}>
                    {direction === 'up' ? '+' : '-'} {delta}
                </div>
            )}
        </div>
    )
}

const COLORS = {
    ECC: '#0891b2',
    Kyber768: '#7c3aed',
    'Kyber768-Cached': '#059669',
}

export default function ResultsDashboard({ data }) {
    const [viewType, setViewType] = useState('all') // Added for the new UI

    const latencyData = useMemo(() => {
        if (!data) return []
        const byNodes = {}
        data.forEach(d => {
            const n = d.nodes
            if (!byNodes[n]) byNodes[n] = { nodes: n }
            const hs = d.metrics.handshake_latency_us
            // Updated to match new data keys in the provided diff
            if (d.crypto === 'ECC') byNodes[n].ecc = hs ? hs.mean : 0
            if (d.crypto === 'Kyber768') byNodes[n].kyber = hs ? hs.mean : 0
            if (d.crypto === 'Kyber768-Cached') byNodes[n].kyberOptimized = hs ? hs.mean : 0
        })
        return Object.values(byNodes).sort((a, b) => a.nodes - b.nodes)
    }, [data])

    const e2eData = useMemo(() => {
        if (!data) return []
        const byNodes = {}
        data.forEach(d => {
            const n = d.nodes
            if (!byNodes[n]) byNodes[n] = { nodes: n }
            const e2e = d.metrics.e2e_app_latency_ms
            // Updated to match new data keys in the provided diff
            if (d.crypto === 'ECC') byNodes[n].ecc = e2e ? e2e.mean : 0
            if (d.crypto === 'Kyber768') byNodes[n].kyber = e2e ? e2e.mean : 0
        })
        return Object.values(byNodes).sort((a, b) => a.nodes - b.nodes)
    }, [data])

    const overheadData = useMemo(() => {
        if (!data) return []
        return data
            .filter(d => d.nodes === 10)
            .map(d => ({
                crypto: d.crypto,
                request: d.metrics.rrc_request_size_bytes?.mean || 0,
                setup: d.metrics.rrc_setup_size_bytes?.mean || 0,
            }))
    }, [data])

    const queueData = useMemo(() => {
        if (!data) return []
        const byNodes = {}
        data.forEach(d => {
            const n = d.nodes
            if (!byNodes[n]) byNodes[n] = { nodes: n }
            const q = d.metrics.queueing_delay_us
            // Updated to match new data keys in the provided diff
            if (d.crypto === 'ECC') byNodes[n].ecc = q ? q.mean : 0
            if (d.crypto === 'Kyber768') byNodes[n].kyber = q ? q.mean : 0
            if (d.crypto === 'Kyber768-Cached') byNodes[n].optimized = q ? q.mean : 0
        })
        return Object.values(byNodes).sort((a, b) => a.nodes - b.nodes)
    }, [data])

    const securityData = useMemo(() => {
        const bits = []
        for (let b = 100; b <= 1000; b += 50) {
            bits.push({
                bits: b,
                classical: b / 2, // ECC Classical
                quantumEcc: Math.log2(Math.pow(b, 3)), // ECC Quantum (Shor)
                quantumKyber: 0.265 * b, // LWE Quantum (Sieving on Kyber) - simplified from original LWE Quantum
            })
        }
        return bits
    }, [])

    if (!data) return <div className="section"><div className="section-inner"><p>Loading results…</p></div></div>

    return (
        <section id="results" className="section" style={{ background: '#f8fafc' }} aria-label="Simulation Results">
            <div className="section-inner">
                <ScrollReveal>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '16px' }}>
                        <div>
                            <span className="section-label">Results</span>
                            <h2>Performance Dashboard</h2>
                            <p className="section-desc">Interactive NS-3 telemetry across multiple swarm configurations.</p>
                        </div>
                        <div className="chart-toggle">
                            {['ecc', 'kyber'].map(t => (
                                <button
                                    key={t}
                                    className={viewType === t ? 'active' : ''}
                                    onClick={() => setViewType(t)}
                                >{t.toUpperCase()} Nodes Only</button>
                            ))}
                            <button
                                className={viewType === 'all' ? 'active' : ''}
                                onClick={() => setViewType('all')}
                            >Compare All</button>
                        </div>
                    </div>
                </ScrollReveal>

                <div className="metric-grid">
                    <ScrollReveal delay={1}>
                        <div className="metric-card">
                            <div className="label">RRC Request Overhead</div>
                            <div className="value">1,312<span className="unit">Bytes</span></div>
                            <div className="delta up">+ 10.25x vs ECC</div>
                        </div>
                    </ScrollReveal>
                    <ScrollReveal delay={2}>
                        <div className="metric-card">
                            <div className="label">Handshake Latency (56 Nodes)</div>
                            <div className="value">1.45<span className="unit">ms</span></div>
                            <div className="delta up">+ 1.12ms vs ECC</div>
                        </div>
                    </ScrollReveal>
                    <ScrollReveal delay={3}>
                        <div className="metric-card">
                            <div className="label">Cached Handshake Latency</div>
                            <div className="value">0.38<span className="unit">ms</span></div>
                            <div className="delta down">- 73.8% via PSK Caching</div>
                        </div>
                    </ScrollReveal>
                    <ScrollReveal delay={4}>
                        <div className="metric-card">
                            <div className="label">Quantum Resistance</div>
                            <div className="value">2<sup style={{ fontSize: '0.6em' }}>164</sup><span className="unit">Ops</span></div>
                            <div className="delta">NIST Level 3</div>
                        </div>
                    </ScrollReveal>
                </div>

                <div className="charts-grid">
                    <ScrollReveal delay={1}>
                        <div className="chart-container">
                            <div className="chart-header">
                                <h3>Handshake Latency vs Swarm Size</h3>
                            </div>
                            <ResponsiveContainer width="100%" height={320}>
                                <LineChart data={latencyData} margin={{ top: 20, right: 30, left: 10, bottom: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                    <XAxis dataKey="nodes" label={{ value: 'Drones', position: 'bottom', offset: 0 }} tick={{ fontSize: 12 }} />
                                    <YAxis label={{ value: 'μs', angle: -90, position: 'insideLeft' }} tick={{ fontSize: 12 }} />
                                    <Tooltip contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }} />
                                    <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
                                    {(viewType === 'all' || viewType === 'ecc') && <Line type="monotone" dataKey="ecc" name="ECC (Baseline)" stroke="var(--c-ecc)" strokeWidth={2} dot={{ r: 4 }} activeDot={{ r: 6 }} />}
                                    {(viewType === 'all' || viewType === 'kyber') && <Line type="monotone" dataKey="kyber" name="Kyber-768" stroke="var(--c-kyber)" strokeWidth={2} dot={{ r: 4 }} activeDot={{ r: 6 }} />}
                                    {viewType === 'all' && <Line type="dashed" dataKey="kyberOptimized" name="Kyber (Cached)" stroke="#f59e0b" strokeWidth={2} strokeDasharray="5 5" dot={{ r: 4 }} />}
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    </ScrollReveal>

                    <ScrollReveal delay={2}>
                        <div className="chart-container">
                            <div className="chart-header">
                                <h3>E2E Application Latency</h3>
                            </div>
                            <ResponsiveContainer width="100%" height={320}>
                                <AreaChart data={e2eData} margin={{ top: 20, right: 30, left: 10, bottom: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                    <XAxis dataKey="nodes" label={{ value: 'Drones', position: 'bottom', offset: 0 }} tick={{ fontSize: 12 }} />
                                    <YAxis label={{ value: 'ms', angle: -90, position: 'insideLeft' }} tick={{ fontSize: 12 }} />
                                    <Tooltip contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }} />
                                    <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
                                    {(viewType === 'all' || viewType === 'kyber') && <Area type="monotone" dataKey="kyber" name="Kyber-768" fill="var(--c-kyber-light)" stroke="var(--c-kyber)" strokeWidth={2} />}
                                    {(viewType === 'all' || viewType === 'ecc') && <Area type="monotone" dataKey="ecc" name="ECC (Baseline)" fill="rgba(8, 145, 178, 0.1)" stroke="var(--c-ecc)" strokeWidth={2} />}
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </ScrollReveal>

                    <ScrollReveal delay={3}>
                        <div className="chart-container">
                            <div className="chart-header">
                                <h3>RRC Message Size Overhead</h3>
                            </div>
                            <ResponsiveContainer width="100%" height={320}>
                                <BarChart data={overheadData} layout="vertical" margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                    <XAxis type="number" label={{ value: 'Bytes', position: 'bottom', offset: 0 }} tick={{ fontSize: 12 }} />
                                    <YAxis type="category" dataKey="crypto" tick={{ fontSize: 12 }} width={120} />
                                    <Tooltip contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }} />
                                    <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
                                    <Bar dataKey="request" name="RRC Request" fill="#7c3aed" radius={[0, 4, 4, 0]} />
                                    <Bar dataKey="setup" name="RRC Setup" fill="#0891b2" radius={[0, 4, 4, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </ScrollReveal>

                    <ScrollReveal delay={4}>
                        <div className="chart-container">
                            <div className="chart-header">
                                <h3>Gateway Queueing Delay</h3>
                            </div>
                            <ResponsiveContainer width="100%" height={320}>
                                <LineChart data={queueData} margin={{ top: 20, right: 30, left: 10, bottom: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                    <XAxis dataKey="nodes" label={{ value: 'Drones', position: 'bottom', offset: 0 }} tick={{ fontSize: 12 }} />
                                    <YAxis label={{ value: 'μs', angle: -90, position: 'insideLeft' }} tick={{ fontSize: 12 }} />
                                    <Tooltip contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }} />
                                    <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
                                    {(viewType === 'all' || viewType === 'ecc') && <Line type="monotone" dataKey="ecc" name="ECC" stroke="var(--c-ecc)" strokeWidth={2} dot={{ r: 4 }} />}
                                    {(viewType === 'all' || viewType === 'kyber') && <Line type="monotone" dataKey="kyber" name="Kyber-768" stroke="var(--c-danger)" strokeWidth={2} dot={{ r: 4 }} />}
                                    {viewType === 'all' && <Line type="monotone" dataKey="optimized" name="Kyber (Optimized)" stroke="var(--c-success)" strokeWidth={2} dot={{ r: 7, stroke: 'var(--c-success)', strokeWidth: 2, fill: '#fff' }} activeDot={{ r: 9 }} connectNulls={false} />}
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    </ScrollReveal>

                    <ScrollReveal delay={5} style={{ gridColumn: '1 / -1' }}>
                        <div className="chart-container" style={{ maxWidth: '800px', margin: '0 auto' }}>
                            <div className="chart-header">
                                <h3>Computational Cost: Classical vs Lattice Cryptography</h3>
                            </div>
                            <ResponsiveContainer width="100%" height={360}>
                                <LineChart data={securityData} margin={{ top: 20, right: 30, left: 10, bottom: 20 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                    <XAxis dataKey="bits" label={{ value: 'Key Size', position: 'bottom', offset: 0 }} tick={{ fontSize: 12 }} />
                                    <YAxis label={{ value: 'log₂(Operations)', angle: -90, position: 'insideLeft' }} tick={{ fontSize: 12 }} domain={[0, 300]} />
                                    <Tooltip contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }} />
                                    <Legend verticalAlign="top" height={36} wrapperStyle={{ fontSize: 12 }} />
                                    <Line type="monotone" dataKey="classical" name="Classical Adversary (ECC)" stroke="var(--c-ecc)" strokeWidth={2} dot={{ r: 4 }} />
                                    <Line type="monotone" dataKey="quantumEcc" name="Quantum Adversary (Shor on ECC)" stroke="var(--c-danger)" strokeWidth={3} strokeDasharray="5 5" dot={{ r: 4 }} />
                                    <Line type="monotone" dataKey="quantumKyber" name="Quantum Adversary (Sieving on Kyber)" stroke="var(--c-kyber)" strokeWidth={2} dot={{ r: 4 }} />
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                    </ScrollReveal>
                </div>
            </div>
        </section>
    )
}
