import test from 'node:test'
import assert from 'node:assert/strict'
import { matchEventCreateSchema } from '../match-events'

test('matchEventCreateSchema accepts valid GOAL_FOR payload', () => {
  const parsed = matchEventCreateSchema.safeParse({
    minute: 12,
    type: 'GOAL_FOR',
    scorerId: 'player_123',
    assistId: 'player_456',
  })
  assert.equal(parsed.success, true)
})

test('matchEventCreateSchema rejects GOAL_FOR without scorerId', () => {
  const parsed = matchEventCreateSchema.safeParse({
    minute: 12,
    type: 'GOAL_FOR',
  })
  assert.equal(parsed.success, false)
})

test('matchEventCreateSchema accepts GOAL_AGAINST payload without player ids', () => {
  const parsed = matchEventCreateSchema.safeParse({
    minute: 18,
    type: 'GOAL_AGAINST',
  })
  assert.equal(parsed.success, true)
})

test('matchEventCreateSchema accepts SUBSTITUTION with one player id', () => {
  const parsed = matchEventCreateSchema.safeParse({
    minute: 21,
    type: 'SUBSTITUTION',
    outPlayerId: 'player_789',
  })
  assert.equal(parsed.success, true)
})

test('matchEventCreateSchema rejects SUBSTITUTION without in/out player', () => {
  const parsed = matchEventCreateSchema.safeParse({
    minute: 21,
    type: 'SUBSTITUTION',
    slotId: 'p2',
  })
  assert.equal(parsed.success, false)
})
