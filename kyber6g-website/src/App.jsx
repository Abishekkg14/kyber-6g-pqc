import { useState, useEffect } from 'react'
import Navigation from './components/Navigation'
import Hero from './sections/Hero'
import Overview from './sections/Overview'
import Architecture from './sections/Architecture'
import CryptoWorkflow from './sections/CryptoWorkflow'
import MathModels from './sections/MathModels'
import Simulation from './sections/Simulation'
import ResultsDashboard from './sections/ResultsDashboard'
import ThreatModel from './sections/ThreatModel'
import Conclusions from './sections/Conclusions'

export default function App() {
  const [data, setData] = useState(null)

  useEffect(() => {
    fetch('/data/simulation_results.json')
      .then(r => r.json())
      .then(setData)
      .catch(() => setData([]))
  }, [])

  return (
    <>
      <Navigation />
      <main>
        <Hero />
        <Overview />
        <Architecture />
        <CryptoWorkflow />
        <MathModels />
        <Simulation />
        <ResultsDashboard data={data} />
        <ThreatModel />
        <Conclusions />
      </main>
      <footer className="footer">
        <p>Kyber-6G Project · Post-Quantum Secure Drone Swarm Communication · 2026</p>
      </footer>
    </>
  )
}
