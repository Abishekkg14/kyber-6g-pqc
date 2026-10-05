import { useState, useEffect } from 'react'
import Navigation from './components/Navigation'
import Hero from './sections/Hero'
import Overview from './sections/Overview'
import Architecture from './sections/Architecture'
import CryptoWorkflow from './sections/CryptoWorkflow'
import ResultsDashboard from './sections/ResultsDashboard'
import Security from './sections/Security'
import Sensing from './sections/Sensing'
import Simulation from './sections/Simulation'
import Conclusions from './sections/Conclusions'

/* Every number and picture on this page comes from public/data/results.json and public/img, which
   scripts/build_data.py writes from the repository's own results. Nothing measured is typed in here. */
export default function App() {
  const [data, setData] = useState(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}data/results.json`)
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(r.status))))
      .then(setData)
      .catch(() => setFailed(true))
  }, [])

  return (
    <>
      <Navigation />
      <main>
        <Hero data={data} />
        {failed && (
          <p className="notice">The results file could not be loaded (run <code>python3 scripts/build_data.py</code>).</p>
        )}
        <Overview data={data} />
        <Architecture />
        <CryptoWorkflow />
        <ResultsDashboard data={data} />
        <Security data={data} />
        <Sensing data={data} />
        <Simulation data={data} />
        <Conclusions data={data} />
      </main>
      <footer className="footer">
        <p>
          Kyber-6G · a post-quantum secure link for UAV video, images, audio and telemetry ·
          {data ? ` results as of ${data.generated}` : ' 2026'}
        </p>
      </footer>
    </>
  )
}
