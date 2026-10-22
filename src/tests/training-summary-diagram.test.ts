import test from 'node:test'
import assert from 'node:assert/strict'
import { parseSummaryDiagram } from '../training-summary-diagram'
import { loadTrainingSummary, renderTrainingSummary } from '../training-summary'
const player = { type: 'player', id: 'p', x: 100, y: 80, label: 'J1', side: 'away' }

test('keeps only frame zero and supports legacy data', () => {
  const result = parseSummaryDiagram(JSON.stringify({ orientation: 'portrait', rotationQuarterTurns: 3, frames: [{ name: 'Départ', items: [player] }, { items: [] }, { name: 'Arrivée', items: [player] }] }))
  assert.equal(result.width, 380)
  assert.equal(result.height, 600)
  assert.deepEqual(result.frames.map(frame => frame.step), [1])
  assert.equal(result.frames[0].items[0].color, 'red')
  assert.equal(result.frames[0].items[0].x, 100) // Coordinates are already rotated.
  assert.equal(parseSummaryDiagram({ items: [player] }).frames[0].step, null)
  assert.deepEqual(parseSummaryDiagram({ frames: [{ items: [] }, { items: [player] }] }).frames, [])
  assert.deepEqual(parseSummaryDiagram({ frames: [null, { items: [player] }] }).frames, [])
  assert.equal(parseSummaryDiagram({ frames: [{ items: [player] }, null] }).invalid, false)
  assert.equal(parseSummaryDiagram('{broken').invalid, true)
  assert.equal(parseSummaryDiagram({ frames: [{ items: [] }] }).invalid, false)
  assert.equal(parseSummaryDiagram({ items: [{ type: 'ball', x: 'NaN', y: 1 }] }).invalid, true)
})

test('loads scoped diagrams once, prefers latest session diagram and falls back only when absent', async () => {
  const diagram = { items: [player] }
  const result = await loadTrainingSummary({}, { clubId: 'club', teamId: 'wrong-team' }, { id: 'training', teamId: 'team', clubId: 'club' }, {
    attendance: async () => [],
    drills: async () => [{ id: 'td1', drillId: 'd1' }, { id: 'td2', drillId: 'd2' }, { id: 'td3', drillId: 'd3' }, { id: 'td4', drillId: 'd4' }],
    catalog: async () => ['d1', 'd2', 'd3', 'd4'].map(id => ({ id, title: id, description: id })),
    diagrams: async (_db: any, scope: any, args: any) => {
      assert.equal(scope.teamId, 'team')
      assert.equal(scope.clubId, 'club')
      assert.deepEqual(args.orderBy, [{ updatedAt: 'desc' }, { id: 'asc' }])
      assert.deepEqual(args.where.OR[0], { trainingDrillId: { in: ['td1', 'td2', 'td3', 'td4'] } })
      assert.equal(args.where.OR[1].trainingDrillId, null)
      return [
        { trainingDrillId: 'td1', data: JSON.stringify(diagram) },
        { trainingDrillId: 'td1', data: '{broken older' },
        { drillId: 'd1', data: '{broken catalogue' },
        { drillId: 'd2', data: JSON.stringify(diagram) },
        { trainingDrillId: 'td3', data: '{broken latest' },
        { drillId: 'd3', data: JSON.stringify(diagram) },
      ]
    },
  })
  assert.equal(result.drills[0].diagramSource, 'session')
  assert.equal(result.drills[0].diagram.invalid, false)
  assert.equal(result.drills[1].diagramSource, 'catalog')
  assert.equal(result.drills[2].diagram.invalid, true)
  assert.equal(result.drills[3].diagram, null)
})

test('renders only the first diagram frame without corrupt diagram failure', async () => {
  const data = parseSummaryDiagram({ frames: Array.from({ length: 10 }, (_, index) => ({ name: `Position ${index + 1}`, items: [player, { type: 'arrow', from: { x: 20, y: 20 }, to: { x: 200, y: 100 } }] })) })
  const pdf = await renderTrainingSummary({ date: '2026-10-21T16:00:00Z', players: [], drills: [{ title: 'Passes', description: 'À deux.', diagram: data }, { title: 'Invalide', description: '', diagram: parseSummaryDiagram('no json') }] }, 'Europe/Paris')
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-')
  const pages = pdf.toString('latin1').match(/\/Type \/Page\b/g) || []
  assert.equal(data.frames.length, 1)
  assert.equal(data.frames[0].name, 'Position 1')
  assert.equal(pages.length, 1)
})

test('paginates a long exercise description beside a portrait diagram', async () => {
  const diagram = parseSummaryDiagram({ orientation: 'portrait', frames: [{ name: 'Hidden caption', items: [player] }] })
  const pdf = await renderTrainingSummary({ date: '2026-10-22T16:00:00Z', players: [], drills: [{ title: 'Long exercice', description: 'Contrôler puis passer et se déplacer. '.repeat(160), diagram }, { title: 'Suivant', description: 'Fin.' }] }, 'Europe/Paris')
  const pages = pdf.toString('latin1').match(/\/Type \/Page\b/g) || []
  assert.ok(pages.length > 1)
  assert.ok(pages.length < 10)
})
