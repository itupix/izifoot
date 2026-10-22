import test from 'node:test'
import assert from 'node:assert/strict'
import { loadTrainingSummary, trainingSummaryVersion, summaryTimeZone } from '../training-summary'

const training = { id: 'training', teamId: 'team', clubId: 'club', date: '2026-10-22T16:00:00.000Z', updatedAt: '2026-10-22T12:00:00.000Z', status: 'PLANNED', observations: '', endTime: '19:30' }
const player = { playerId: 'player', player: { name: 'Éloïse', teamId: 'team' } }
const row = { id: 'row', drillId: 'drill', order: 0, notes: 'Notes' }
const drill = { id: 'drill', title: 'Passes', description: '<p>À deux.</p>' }
const diagram = { id: 'diagram', trainingDrillId: 'row', updatedAt: '2026-10-22T12:00:00.000Z', data: JSON.stringify({ items: [{ type: 'ball', x: 100, y: 100 }] }) }
async function version(patch: any = {}) {
  const summary = await loadTrainingSummary({}, { clubId: 'club' }, patch.training ?? training, {
    attendance: async () => patch.attendance ?? [player],
    drills: async () => patch.rows ?? [row],
    catalog: async () => patch.catalog ?? [drill],
    diagrams: async () => patch.diagrams ?? [diagram],
  })
  return trainingSummaryVersion(summary, 'Europe/Paris')
}

test('fingerprint changes for every PDF dependency without relying on Training.updatedAt', async () => {
  const original = await version()
  const changes = [
    { training: { ...training, date: '2026-10-23T16:00:00Z' } },
    { training: { ...training, endTime: '20:00' } },
    { training: { ...training, status: 'CANCELLED' } },
    { training: { ...training, observations: 'Progression' } },
    { training: { ...training, updatedAt: '2026-10-23T12:00:00Z' } },
    { attendance: [] },
    { attendance: [{ ...player, player: { ...player.player, name: 'Autre prénom' } }] },
    { rows: [] },
    { rows: [{ ...row, notes: 'Notes modifiées' }] },
    { rows: [{ ...row, order: 1 }] },
    { catalog: [{ ...drill, title: 'Tirs' }] },
    { catalog: [{ ...drill, description: 'Nouvelles consignes' }] },
    { diagrams: [] },
    { diagrams: [{ ...diagram, data: JSON.stringify({ items: [{ type: 'ball', x: 200, y: 100 }] }) }] },
    { diagrams: [{ ...diagram, trainingDrillId: null, drillId: 'drill' }] },
  ]
  for (const change of changes) assert.notEqual(await version(change), original, JSON.stringify(change))
  assert.equal(await version(), original)
})

test('unrelated catalogue entries and unselected diagrams do not invalidate cached PDFs', async () => {
  assert.equal(await version({ catalog: [drill, { id: 'unrelated', title: 'Autre', description: 'Autre' }] }), await version())
  assert.equal(await version({ diagrams: [diagram, { ...diagram, id: 'older', data: '{}' }] }), await version())
  assert.equal(await version({ training: { ...training, arbitraryUnrenderedField: Date.now() } }), await version())
})

test('fingerprint is canonical, uses timezone and has no generation-time dependency', () => {
  const base = { ...training, players: ['Éloïse'], drills: [], versionDependencies: [{ notes: 'Notes', order: 0 }] }
  const hash = trainingSummaryVersion(base, 'Europe/Paris')
  assert.match(hash, /^[a-f0-9]{64}$/)
  assert.equal(trainingSummaryVersion({ ...base, versionDependencies: [{ order: 0, notes: 'Notes' }] }, 'Europe/Paris'), hash)
  assert.notEqual(trainingSummaryVersion(base, 'UTC'), hash)
  assert.equal(summaryTimeZone('US/Eastern'), summaryTimeZone('America/New_York'))
  assert.equal(trainingSummaryVersion(base, 'US/Eastern'), trainingSummaryVersion(base, 'America/New_York'))
})
