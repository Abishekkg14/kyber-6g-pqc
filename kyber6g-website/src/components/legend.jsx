/* For a chart's <Legend>: the words in the text colour (the mark beside them carries the colour), and the series
   in the order they are given, not in alphabetical order. */
const legend = {
  formatter: value => <span style={{ color: '#1a1a2e' }}>{value}</span>,
  itemSorter: () => 0,
  wrapperStyle: { fontSize: 12 },
}

export default legend
