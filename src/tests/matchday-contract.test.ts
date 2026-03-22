import test from 'node:test'
import assert from 'node:assert/strict'
import {
  deriveMatchdayMode,
  ensureRotationGameKeysForContract,
  normalizeRotationForContract,
} from '../matchday-contract'

test('deriveMatchdayMode returns ROTATION when planning indicates rotation', () => {
  assert.equal(deriveMatchdayMode({ hasPersistedRotationKey: false, hasPlanningRotation: true }), 'ROTATION')
})

test('ensureRotationGameKeysForContract preserves legacy/schedule and fills missing', () => {
  const rows = ensureRotationGameKeysForContract([
    { id: 'm1', rotationGameKey: 'legacy:0' },
    { id: 'm2', rotationGameKey: null },
    { id: 'm3', rotationGameKey: 'schedule:2' },
    { id: 'm4' },
  ], true)

  assert.equal(rows[0].rotationGameKey, 'legacy:0')
  assert.equal(rows[2].rotationGameKey, 'schedule:2')
  assert.ok(rows[1].rotationGameKey && rows[1].rotationGameKey.length > 0)
  assert.ok(rows[3].rotationGameKey && rows[3].rotationGameKey.length > 0)
})

test('normalizeRotationForContract enforces teams color/absent and keeps slots', () => {
  const rotation = normalizeRotationForContract({
    updatedAt: '2026-03-22T10:00:00.000Z',
    teams: [{ label: 'Club A' }, { label: 'Club B', color: '#111111', absent: 1 }],
    slots: [{ time: '10:00', games: [{ pitch: 1, A: 'Club A', B: 'Club B' }] }],
  }, '2026-03-22T09:00:00.000Z')

  assert.ok(rotation)
  assert.equal(rotation!.teams.length, 2)
  assert.equal(rotation!.teams[0].label, 'Club A')
  assert.ok(rotation!.teams[0].color.length > 0)
  assert.equal(rotation!.teams[0].absent, false)
  assert.equal(rotation!.teams[1].color, '#111111')
  assert.equal(rotation!.teams[1].absent, true)
  assert.equal(rotation!.slots[0].games[0].A, 'Club A')
})

