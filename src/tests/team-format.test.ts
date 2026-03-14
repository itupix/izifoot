import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeTeamFormat } from '../team-format'

test('normalizeTeamFormat accepts allowed values', () => {
  const parsed = normalizeTeamFormat('5v5')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.format, '5v5')
})

test('normalizeTeamFormat normalizes case and spaces', () => {
  const parsed = normalizeTeamFormat(' 11V11 ')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.format, '11v11')
})

test('normalizeTeamFormat rejects invalid value', () => {
  const parsed = normalizeTeamFormat('7v7')
  assert.equal(parsed.ok, false)
})

test('normalizeTeamFormat rejects missing value', () => {
  const parsed = normalizeTeamFormat('')
  assert.equal(parsed.ok, false)
})
