import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeTeamFormat, resolveTeamFormat } from '../team-format'

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

test('resolveTeamFormat maps format to playersOnField', () => {
  const resolved = resolveTeamFormat('8v8')
  assert.equal(resolved.format, '8v8')
  assert.equal(resolved.playersOnField, 8)
  assert.equal(resolved.usedFallback, false)
})

test('resolveTeamFormat falls back to 5v5 when format is missing/invalid', () => {
  const resolved = resolveTeamFormat('not-a-format')
  assert.equal(resolved.format, '5v5')
  assert.equal(resolved.playersOnField, 5)
  assert.equal(resolved.usedFallback, true)
})
