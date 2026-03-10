import test from 'node:test'
import assert from 'node:assert/strict'
import {
  normalizeTrainingRoleItems,
  trainingRolesPutBodySchema,
  validateNoDuplicatePlayers,
} from '../training-role-assignments'

test('PUT body schema accepts valid role assignments', () => {
  const parsed = trainingRolesPutBodySchema.safeParse({
    items: [
      { role: 'Capitaine', playerId: 'p1' },
      { role: 'Arbitre', playerId: 'p2' },
    ],
  })

  assert.equal(parsed.success, true)
})

test('PUT body schema rejects empty role and empty playerId', () => {
  const parsed = trainingRolesPutBodySchema.safeParse({
    items: [{ role: '   ', playerId: '' }],
  })

  assert.equal(parsed.success, false)
})

test('normalizeTrainingRoleItems trims role and playerId', () => {
  const items = normalizeTrainingRoleItems([
    { role: '  Gardien de but  ', playerId: '  p9  ' },
  ])

  assert.deepEqual(items, [{ role: 'Gardien de but', playerId: 'p9' }])
})

test('validateNoDuplicatePlayers accepts duplicated roles', () => {
  assert.doesNotThrow(() => {
    validateNoDuplicatePlayers([
      { role: 'Capitaine', playerId: 'p1' },
      { role: 'Capitaine', playerId: 'p2' },
    ])
  })
})

test('validateNoDuplicatePlayers rejects duplicated playerId', () => {
  assert.throws(() => {
    validateNoDuplicatePlayers([
      { role: 'Capitaine', playerId: 'p1' },
      { role: 'Arbitre', playerId: 'p1' },
    ])
  }, /Duplicate playerId in items/)
})

test('validateNoDuplicatePlayers accepts unique roles and players', () => {
  assert.doesNotThrow(() => {
    validateNoDuplicatePlayers([
      { role: 'Capitaine', playerId: 'p1' },
      { role: 'Arbitre', playerId: 'p2' },
      { role: 'Rangement matériel', playerId: 'p3' },
    ])
  })
})
