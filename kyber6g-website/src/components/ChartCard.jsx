/* A chart or a table with its title, what kind of evidence it is (measured, attacked, proved, simulated) and a note. */
export default function ChartCard({ title, kind, note, children }) {
  return (
    <div className="chart-container">
      <div className="chart-header">
        <h3>{title}</h3>
        {kind && <span className={`kind kind-${kind.split(' ')[0]}`}>{kind}</span>}
      </div>
      {children}
      {note && <p className="chart-note">{note}</p>}
    </div>
  )
}

/* A plain table of results: `cols` is a list of [key, heading, digits]. */
export function DataTable({ data, cols, caption }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        {caption && <caption>{caption}</caption>}
        <thead>
          <tr>{cols.map(c => <th key={c[0]} className={data.length && typeof data[0][c[0]] === 'number' ? 'num' : ''}>{c[1]}</th>)}</tr>
        </thead>
        <tbody>
          {data.map((r, i) => (
            <tr key={i}>
              {cols.map(c => {
                const v = r[c[0]]
                const num = typeof v === 'number'
                return (
                  <td key={c[0]} className={num ? 'num' : ''}>
                    {num ? v.toLocaleString('en-US', { maximumFractionDigits: c[2] === undefined ? 2 : c[2] }) : (v === '' || v === undefined || v === null ? '—' : String(v))}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
