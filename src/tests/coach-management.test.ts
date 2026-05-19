import test from 'node:test'
import assert from 'node:assert/strict'
import {
  mapCoachManagedTeams,
  normalizeCoachManagedTeamIds,
  resolveCoachActiveTeamId,
} from '../coach-management'

test('normalizeCoachManagedTeamIds keeps primary team first and deduplicates values', () => {
  assert.deepEqual(
    normalizeCoachManagedTeamIds('team-2', ['team-1', 'team-2', 'team-1', '', 'team-3']),
    ['team-2', 'team-1', 'team-3'],
  )
})

test('normalizeCoachManagedTeamIds falls back to managed teams when no primary team is set', () => {
  assert.deepEqual(
    normalizeCoachManagedTeamIds(null, ['team-1', 'team-1', 'team-4']),
    ['team-1', 'team-4'],
  )
})

test('resolveCoachActiveTeamId keeps the current team when still managed', () => {
  assert.equal(resolveCoachActiveTeamId('team-3', ['team-1', 'team-3']), 'team-3')
})

test('resolveCoachActiveTeamId falls back to the first managed team when current becomes invalid', () => {
  assert.equal(resolveCoachActiveTeamId('team-9', ['team-1', 'team-3']), 'team-1')
  assert.equal(resolveCoachActiveTeamId(null, []), null)
})

test('mapCoachManagedTeams resolves labels from the provided lookup', () => {
  const teamNameById = new Map([
    ['team-1', 'U11 A'],
    ['team-2', 'U13'],
  ])

  assert.deepEqual(
    mapCoachManagedTeams(['team-2', 'team-1', 'team-99'], teamNameById),
    [
      { id: 'team-2', name: 'U13' },
      { id: 'team-1', name: 'U11 A' },
      { id: 'team-99', name: 'team-99' },
    ],
  )
})
