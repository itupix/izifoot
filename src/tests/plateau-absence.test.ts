import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildAbsenceMatchPatches,
  diffTeamAbsence,
  ensureRotationGameKeys,
  findRotationGameKeysForTeam,
} from '../plateau-absence'

test('propagation absent=true impacts N matches by rotation keys', () => {
  const rotation = ensureRotationGameKeys({
    teams: [{ label: 'Team A' }, { label: 'Team B' }, { label: 'Team C' }],
    slots: [
      { games: [{ A: 'Team A', B: 'Team B' }, { A: 'Team C', B: 'Team B' }] },
      { games: [{ A: 'Team A', B: 'Team C' }] },
    ],
  })

  const keys = findRotationGameKeysForTeam(rotation, 'Team B')
  assert.equal(keys.length, 2)

  const patches = buildAbsenceMatchPatches({
    absent: true,
    matches: [
      { id: 'm1', status: 'PLANNED', played: false },
      { id: 'm2', status: 'PLAYED', played: true },
    ],
  })

  assert.equal(patches.length, 2)
  assert.deepEqual(patches.map((p) => p.status), ['CANCELLED', 'CANCELLED'])
  assert.deepEqual(patches.map((p) => p.played), [false, false])
})

test('idempotence: absent=true repeated creates no additional patch on already cancelled matches', () => {
  const patches = buildAbsenceMatchPatches({
    absent: true,
    matches: [{ id: 'm1', status: 'CANCELLED', played: false }],
  })

  assert.equal(patches.length, 0)
})

test('absent=false restores PLANNED but keeps PLAYED as PLAYED', () => {
  const patches = buildAbsenceMatchPatches({
    absent: false,
    matches: [
      { id: 'm1', status: 'CANCELLED', played: false },
      { id: 'm2', status: 'PLAYED', played: true },
    ],
  })

  assert.equal(patches.length, 1)
  assert.equal(patches[0].id, 'm1')
  assert.equal(patches[0].status, 'PLANNED')
  assert.equal(patches[0].played, false)
})

test('absence diff reports only changed teams', () => {
  const changes = diffTeamAbsence(
    [
      { label: 'A', absent: false },
      { label: 'B', absent: false },
    ],
    [
      { label: 'A', absent: true },
      { label: 'B', absent: false },
    ],
  )

  assert.equal(changes.length, 1)
  assert.equal(changes[0].teamLabel, 'A')
  assert.equal(changes[0].absent, true)
})
