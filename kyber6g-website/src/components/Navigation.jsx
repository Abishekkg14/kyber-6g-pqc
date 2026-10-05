import { useState, useEffect } from 'react'

const sections = [
  { id: 'overview', label: 'Overview' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'crypto', label: 'Protocol' },
  { id: 'results', label: 'Measured' },
  { id: 'security', label: 'Attacked & proved' },
  { id: 'sensing', label: 'Motion & audio' },
  { id: 'simulation', label: 'Simulated' },
  { id: 'limits', label: 'Limits' },
]

export default function Navigation() {
  const [active, setActive] = useState('')

  useEffect(() => {
    const observer = new IntersectionObserver(
      entries => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(e.target.id)
        }
      },
      { rootMargin: '-30% 0px -60% 0px' }
    )
    sections.forEach(s => {
      const el = document.getElementById(s.id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [])

  return (
    <nav className="nav" role="navigation" aria-label="Main navigation">
      <div className="nav-inner">
        <div className="nav-logo">
          <span className="dot" aria-hidden="true" />
          Kyber-6G
        </div>
        <ul className="nav-links">
          {sections.map(s => (
            <li key={s.id}>
              <a href={`#${s.id}`} className={active === s.id ? 'active' : ''}>
                {s.label}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  )
}
