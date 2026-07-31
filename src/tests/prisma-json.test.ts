import test from 'node:test'
import assert from 'node:assert/strict'
import { Prisma } from '@prisma/client'
import { toPrismaNullableJsonValue } from '../prisma-json'

test('toPrismaNullableJsonValue converts null to Prisma.DbNull', () => {
  assert.equal(toPrismaNullableJsonValue(null), Prisma.DbNull)
})

test('toPrismaNullableJsonValue keeps JSON payloads unchanged', () => {
  const tactic = {
    formation: '2-3-1',
    points: {
      gk: { x: 10, y: 10 },
      p1: { x: 20, y: 20 },
    },
  }

  assert.equal(toPrismaNullableJsonValue(tactic), tactic)
})
