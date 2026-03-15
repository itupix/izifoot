import test from 'node:test'
import assert from 'node:assert/strict'
import { validateMatchUpdatePayloadForTeamFormat } from '../match-update-validation'

function buildPoint(x: number, y: number) {
  return { x, y }
}

test('3v3 accepts max 3 starters and points gk,p1,p2', () => {
  const result = validateMatchUpdatePayloadForTeamFormat({
    teamFormat: '3v3',
    sides: {
      home: { starters: ['h1', 'h2', 'h3'], subs: ['h4'] },
      away: { starters: ['a1', 'a2', 'a3'], subs: ['a4'] },
    },
    tactic: {
      preset: 'formation:1-1',
      points: {
        gk: buildPoint(50, 90),
        p1: buildPoint(35, 60),
        p2: buildPoint(65, 60),
      },
    },
  })

  assert.equal(result.ok, true)
})

test('8v8 accepts max 8 starters and points gk..p7', () => {
  const result = validateMatchUpdatePayloadForTeamFormat({
    teamFormat: '8v8',
    sides: {
      home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8'], subs: ['h9'] },
      away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8'], subs: ['a9'] },
    },
    tactic: {
      preset: 'formation:3-3-1',
      points: {
        gk: buildPoint(50, 90),
        p1: buildPoint(15, 70),
        p2: buildPoint(30, 70),
        p3: buildPoint(45, 70),
        p4: buildPoint(60, 70),
        p5: buildPoint(75, 70),
        p6: buildPoint(40, 45),
        p7: buildPoint(60, 45),
      },
    },
  })

  assert.equal(result.ok, true)
})

test('11v11 accepts max 11 starters and points gk..p10', () => {
  const result = validateMatchUpdatePayloadForTeamFormat({
    teamFormat: '11v11',
    sides: {
      home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9', 'h10', 'h11'], subs: ['h12'] },
      away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11'], subs: ['a12'] },
    },
    tactic: {
      preset: 'formation:4-4-2',
      points: {
        gk: buildPoint(50, 90),
        p1: buildPoint(10, 70),
        p2: buildPoint(20, 70),
        p3: buildPoint(35, 70),
        p4: buildPoint(50, 70),
        p5: buildPoint(65, 70),
        p6: buildPoint(80, 70),
        p7: buildPoint(20, 45),
        p8: buildPoint(40, 45),
        p9: buildPoint(60, 45),
        p10: buildPoint(80, 45),
      },
    },
  })

  assert.equal(result.ok, true)
})

test('invalid 5v5 payload rejects 6 starters with a clear message', () => {
  const result = validateMatchUpdatePayloadForTeamFormat({
    teamFormat: '5v5',
    sides: {
      home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], subs: [] },
      away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5'], subs: [] },
    },
    tactic: {
      preset: 'formation:2-2',
      points: {
        gk: buildPoint(50, 90),
        p1: buildPoint(30, 65),
        p2: buildPoint(70, 65),
        p3: buildPoint(40, 40),
        p4: buildPoint(60, 40),
      },
    },
  })

  assert.equal(result.ok, false)
  if (result.ok) return
  assert.match(result.error, /Too many starters for home/)
})

test('retro-compatibility: missing format falls back to 5v5 and accepts legacy payload', () => {
  const result = validateMatchUpdatePayloadForTeamFormat({
    teamFormat: null,
    sides: {
      home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5'], subs: ['h6'] },
      away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5'], subs: ['a6'] },
    },
    tactic: {
      preset: 'formation:2-2',
      points: {
        gk: buildPoint(50, 90),
        p1: buildPoint(30, 65),
        p2: buildPoint(70, 65),
        p3: buildPoint(40, 40),
        p4: buildPoint(60, 40),
      },
    },
  })

  assert.equal(result.ok, true)
  if (!result.ok) return
  assert.equal(result.format, '5v5')
  assert.equal(result.usedFallback, true)
})
