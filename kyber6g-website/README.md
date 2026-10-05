# Kyber-6G: the project's web page

One page (React, built with Vite) that presents the project as it is in this repository: what the system is, the
protocol, what was measured, what was attacked, what is proved and checked, the motion watch and sealed audio, the
simulation, and the limits.

**No number and no picture is typed into the page's source.** Everything it shows comes from two generated places:

| Generated | By | From |
|---|---|---|
| `public/data/results.json` | `scripts/build_data.py` | the "Results at a glance" table of `../README.md`, the tables behind the paper's plots (`../paper_plots/tables/*.csv`), the ProVerif results (`../formal/results.json`), the known-answer tests (`../paper_plots/data/pq_conformance_*.json`), the bill of materials (`../docs/CBOM.json`) |
| `public/img/*.png` | the same script | the paper's figures and plots (`../paper_figures/exported_png`, `../paper_plots/exported_png`), made smaller for a web page |

The sections say in a tag what kind of evidence each chart, table or figure is: **measured**, **attacked**,
**proved**, **checked** or **simulated**. Simulated results are drawn in grey in the page's own charts, never in a
colour, so that a simulated curve cannot be taken for a measured one.

## Build

```bash
cd kyber6g-website
python3 scripts/build_data.py     # after a measurement campaign, `plots`, `formal`, or a change of the README's results (needs Pillow)
npm install                       # once
npm run build                     # the page, in dist/
npm run preview                   # serves dist/ on http://localhost:4173
```

Node 20.19 or newer is what Vite 7 asks for; the build was also run with Node 18.20.8, where it works and prints a
warning.

## What is where

| Path | Content |
|---|---|
| `src/App.jsx` | loads `data/results.json` and hands it to the sections |
| `src/sections/` | `Hero`, `Overview`, `Architecture`, `CryptoWorkflow` (the protocol), `ResultsDashboard` (measured), `Security` (attacked, proved, checked), `Sensing` (motion watch, detection, sealed audio), `Simulation`, `Conclusions` (what holds, limits, wording) |
| `src/components/` | `Figure` (a figure or plot of the paper with its caption and tag), `ChartCard` and `DataTable`, `legend` (legend settings shared by the charts), `Navigation`, `ScrollReveal`, `Icons` |
| `src/data.js` | helpers for reading the results, and the chart colours |
| `scripts/build_data.py` | writes the two generated places above |

## Charts

The page's own charts (Recharts) follow a few rules: one y-axis per chart, a table beside or below every chart,
legend text in the text colour (the mark beside it carries the colour), hover details on every chart, and a note
wherever an axis is not linear. The four colours for measured series were run through a colour-vision validator
against the white chart card (separation under the three kinds of colour-blindness and for full colour vision:
pass; two of them are below 3 : 1 against white, which is why those charts have their table underneath).

## What was removed

The page of the earlier study (a 3-D swarm scene, formulas, a threat list and a dashboard of an analytical model's
numbers) and its data file `public/data/simulation_results.json` were removed on 5 October 2026: they described a
different system and data that this repository no longer contains. They are in the git history.
