import test from 'node:test'
import assert from 'node:assert/strict'
import { matchTacticSchema, validateMatchTacticForPlayersOnField } from '../match-tactic'

test('matchTacticSchema accepts valid tactic payload', () => {
  const parsed = matchTacticSchema.safeParse({
    preset: 'formation:2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 33, y: 72 },
      p2: { x: 67, y: 72 },
      p3: { x: 50, y: 53 },
      p4: { x: 50, y: 32 },
    },
  })

  assert.equal(parsed.success, true)
})

test('matchTacticSchema rejects empty preset', () => {
  const parsed = matchTacticSchema.safeParse({
    preset: '   ',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 33, y: 72 },
      p2: { x: 67, y: 72 },
      p3: { x: 50, y: 53 },
      p4: { x: 50, y: 32 },
    },
  })

  assert.equal(parsed.success, false)
})

test('matchTacticSchema rejects invalid point tokens', () => {
  const parsed = matchTacticSchema.safeParse({
    preset: 'formation:2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 33, y: 72 },
      p2: { x: 67, y: 72 },
      p3: { x: 50, y: 53 },
      p4: { x: 50, y: 32 },
      foo: { x: 10, y: 10 },
    },
  })

  assert.equal(parsed.success, false)
})

test('matchTacticSchema rejects out-of-bounds coordinates', () => {
  const parsed = matchTacticSchema.safeParse({
    preset: 'formation:2-1-1',
    points: {
      gk: { x: 120, y: 90 },
      p1: { x: 33, y: 72 },
      p2: { x: 67, y: 72 },
      p3: { x: 50, y: 53 },
      p4: { x: 50, y: 32 },
    },
  })

  assert.equal(parsed.success, false)
})

test('validateMatchTacticForPlayersOnField rejects points beyond format size', () => {
  const parsed = matchTacticSchema.safeParse({
    preset: 'formation:2-1-1',
    points: {
      gk: { x: 50, y: 90 },
      p1: { x: 33, y: 72 },
      p2: { x: 67, y: 72 },
      p3: { x: 50, y: 53 },
      p4: { x: 50, y: 32 },
      p5: { x: 42, y: 20 },
    },
  })

  assert.equal(parsed.success, true)
  if (!parsed.success) return

  const validation = validateMatchTacticForPlayersOnField(parsed.data, 5)
  assert.equal(validation.ok, false)
})
