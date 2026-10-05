/* Helpers for reading public/data/results.json (written by scripts/build_data.py). */

/* The rows of one table of the paper's plots, or [] while the results are loading. */
export function rows(data, name) {
  return (data && data.tables && data.tables[name]) || []
}

export function fmt(v, digits = 1) {
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v !== 'number') return String(v)
  return Number.isInteger(v) ? v.toLocaleString('en-US') : v.toLocaleString('en-US', { maximumFractionDigits: digits })
}

/* The value of the README's headline row whose description contains `text`, or '—'. */
export function headline(data, text) {
  const row = ((data && data.headline) || []).find(r => r[0].toLowerCase().includes(text.toLowerCase()))
  return row ? row[1] : '—'
}

/* Long rows (one per series and x) as one row per x with a column per series, for a chart with several lines.
   Returns [rows sorted by x, the series names in order of appearance]. */
export function pivot(list, x, series, y) {
  const byX = new Map()
  const names = []
  list.forEach(r => {
    const name = typeof series === 'function' ? series(r) : r[series]
    if (typeof r[y] !== 'number' || typeof r[x] !== 'number') return
    if (!names.includes(name)) names.push(name)
    const row = byX.get(r[x]) || { x: r[x] }
    row[name] = r[y]
    byX.set(r[x], row)
  })
  return [[...byX.values()].sort((p, q) => p.x - q.x), names]
}

/* Chart colours for measured results, in a fixed order and never by rank. Checked against the white chart card
   with the palette validator (lightness, chroma, colour-blind and normal-vision separation all pass; the third
   and fourth are below 3:1 against white, which is why a chart that uses them has its table underneath). */
export const SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']

/* Simulated results are drawn in black and grey, never in a colour, as in the paper's plots: nobody should be
   able to take a simulated curve for a measured one. The two are told apart by a dash pattern and a label too. */
export const SIMULATED = ['#1f2937', '#8b929c']

export const AXIS = { fontSize: 12, fill: '#6b7280' }
export const GRID = '#eceef1'
export const TIP = { borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13, boxShadow: '0 2px 8px rgba(0,0,0,.06)' }
