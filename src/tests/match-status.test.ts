import test from 'node:test'
import assert from 'node:assert/strict'
import {
  countPlayedMatchesExcludingCancelled,
  normalizeMatchWriteState,
  resolveMatchStatus,
  resolvePatchedMatchStatus,
} from '../match-status'

test('compat: played=true resolves to PLAYED when status is absent', () => {
  const status = resolveMatchStatus({ played: true })
  assert.equal(status, 'PLAYED')
})

test('status CANCELLED always normalizes to played=false with empty scorers', () => {
  const normalized = normalizeMatchWriteState({
    status: 'CANCELLED',
    score: { home: 3, away: 2 },
    buteurs: [{ playerId: 'p1', side: 'home' }],
  })

  assert.equal(normalized.played, false)
  assert.deepEqual(normalized.score, { home: 0, away: 0 })
  assert.deepEqual(normalized.buteurs, [])
})

test('played-only patch keeps CANCELLED status on legacy payload played=false', () => {
  const status = resolvePatchedMatchStatus({
    existingStatus: 'CANCELLED',
    payloadPlayed: false,
  })

  assert.equal(status, 'CANCELLED')
})

test('stats exclude CANCELLED matches from played count', () => {
  const playedCount = countPlayedMatchesExcludingCancelled([
    { status: 'PLAYED', played: true },
    { status: 'CANCELLED', played: false },
    { played: true },
    { status: 'PLANNED', played: false },
  ])

  assert.equal(playedCount, 2)
})
