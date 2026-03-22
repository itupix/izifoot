import test from 'node:test'
import assert from 'node:assert/strict'
import { matchCreatePayloadSchema } from '../match-payload'

test('POST /matches payload accepts tactic when valid', () => {
  const parsed = matchCreatePayloadSchema.safeParse({
    type: 'ENTRAINEMENT',
    sides: {
      home: { starters: ['h1'], subs: [] },
      away: { starters: ['a1'], subs: [] },
    },
    tactic: {
      preset: 'formation:1-1',
      points: {
        gk: { x: 50, y: 90 },
        p1: { x: 50, y: 60 },
      },
    },
  })

  assert.equal(parsed.success, true)
})

test('POST /matches payload accepts missing tactic', () => {
  const parsed = matchCreatePayloadSchema.safeParse({
    type: 'PLATEAU',
    matchdayId: 'pl_1',
    sides: {
      home: { starters: ['h1'], subs: [] },
      away: { starters: ['a1'], subs: [] },
    },
  })

  assert.equal(parsed.success, true)
})

test('POST /matches payload rejects invalid tactic', () => {
  const parsed = matchCreatePayloadSchema.safeParse({
    type: 'ENTRAINEMENT',
    sides: {
      home: { starters: ['h1'], subs: [] },
      away: { starters: ['a1'], subs: [] },
    },
    tactic: {
      preset: '',
      points: {
        bad: { x: '50', y: 90 },
      },
    },
  })

  assert.equal(parsed.success, false)
})

test('POST /matches payload rejects played=true when status=CANCELLED', () => {
  const parsed = matchCreatePayloadSchema.safeParse({
    type: 'PLATEAU',
    status: 'CANCELLED',
    played: true,
    sides: {
      home: { starters: ['h1'], subs: [] },
      away: { starters: ['a1'], subs: [] },
    },
  })

  assert.equal(parsed.success, false)
})
