import test from 'node:test'
import assert from 'node:assert/strict'
import { descriptionText, loadTrainingSummary, renderTrainingSummary, summaryTimeZone } from '../training-summary'

test('validates timezone without accepting arrays or invalid zones', () => {
  assert.equal(summaryTimeZone(undefined), 'Europe/Paris')
  assert.equal(summaryTimeZone('Europe/Paris'), 'Europe/Paris')
  for (const value of ['', 'Invalid/Zone', ['Europe/Paris']]) assert.throws(() => summaryTimeZone(value))
})
test('preserves paragraphs, lists and entities without script text', () => {
  assert.equal(descriptionText('<p>Passes &amp; contrôle</p><ul><li>À deux</li><li>Tirer</li></ul><script>alert(1)</script>'), 'Passes & contrôle\n\n- À deux\n- Tirer')
})
test('uses actual attendance, deduplicates players, preserves drill ordering and missing items', async () => {
  const training = { id: 't1', teamId: 'team1', clubId: 'club1', observations: 'À revoir <texte libre>\nDeuxième ligne' }
  const result = await loadTrainingSummary({}, { id: 'u1' }, training, {
    attendance: async (_db: any, scope: any, args: any) => {
      assert.equal(scope.teamId, 'team1')
      assert.equal(args.where.session_type, 'TRAINING')
      assert.equal(args.where.session_id, 't1')
      return [{ playerId: 'a', player: { name: 'Zoé', teamId: 'team1' } }, { playerId: 'b', player: { name: 'Ana', teamId: 'team1' } }, { playerId: 'a', player: { name: 'Zoé', teamId: 'team1' } }, { playerId: 'c', player: { name: 'Autre', teamId: 'team2' } }]
    },
    drills: async () => [{ drillId: 'd2' }, { drillId: 'missing' }, { drillId: 'd1' }],
    catalog: async () => [{ id: 'd1', title: 'Premier catalogue', description: 'Un' }, { id: 'd2', title: 'Premier séance', description: '<p>Deux</p>' }],
  })
  assert.equal(result.observations, training.observations)
  assert.deepEqual(result.players, ['Ana', 'Zoé'])
  assert.deepEqual(result.drills.map((drill: any) => drill.title), ['Premier séance', 'Exercice indisponible', 'Premier catalogue'])
})
test('renders multipage PDFs and empty sections', async () => {
  const base = { date: '2026-10-20T16:00:00.000Z', endTime: null, status: 'CANCELLED', players: [], drills: [] }
  const empty = await renderTrainingSummary(base, 'Europe/Paris')
  assert.equal(empty.subarray(0, 5).toString(), '%PDF-')
  const long = await renderTrainingSummary({ ...base, observations: 'À revoir : contrôle.\n'.repeat(200), players: ['Éloïse Łukasz'], drills: [{ title: 'Contrôle', description: 'Une consigne détaillée. '.repeat(2000) }] }, 'Europe/Paris')
  assert.ok(long.length > empty.length)
})
