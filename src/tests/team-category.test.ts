import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeTeamCategory } from '../team-category'

test('normalizeTeamCategory accepts single U category', () => {
  const parsed = normalizeTeamCategory('u8')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.category, 'U8')
})

test('normalizeTeamCategory accepts contiguous U range', () => {
  const parsed = normalizeTeamCategory('U8 - U10')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.category, 'U8-U10')
})

test('normalizeTeamCategory accepts Vétérans without diacritics', () => {
  const parsed = normalizeTeamCategory('veterans')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.category, 'Vétérans')
})

test('normalizeTeamCategory rejects non-U range', () => {
  const parsed = normalizeTeamCategory('U8-Vétérans')
  assert.equal(parsed.ok, false)
})

test('normalizeTeamCategory rejects reversed U range', () => {
  const parsed = normalizeTeamCategory('U10-U8')
  assert.equal(parsed.ok, false)
})
