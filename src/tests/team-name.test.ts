import test from 'node:test'
import assert from 'node:assert/strict'
import { computeAutoTeamName, foldTeamNameForCompare } from '../team-name'

test('foldTeamNameForCompare removes accents and normalizes case', () => {
  assert.equal(foldTeamNameForCompare('  Vétérans  '), 'veterans')
  assert.equal(foldTeamNameForCompare('VETERANS'), 'veterans')
})

test('computeAutoTeamName keeps base name when available', () => {
  assert.equal(computeAutoTeamName('U8-U9', ['U10-U11', 'Seniors']), 'U8-U9')
})

test('computeAutoTeamName increments suffix when base name already exists', () => {
  assert.equal(computeAutoTeamName('Vétérans', ['Vétérans']), 'Vétérans 2')
})

test('computeAutoTeamName increments with accent/case-insensitive comparison', () => {
  assert.equal(
    computeAutoTeamName('Vétérans', ['veterans', 'Vétérans 2', 'VETERANS 3']),
    'Vétérans 4'
  )
})
