import assert from 'node:assert/strict'
import test from 'node:test'

import { resolvePlayerAccountInviteLookupRoles, resolvePlayerAccountInviteRole } from '../player-account-role'

test('child player invite role is PARENT', () => {
  assert.equal(resolvePlayerAccountInviteRole(true), 'PARENT')
})

test('non-child player invite role is PLAYER', () => {
  assert.equal(resolvePlayerAccountInviteRole(false), 'PLAYER')
})

test('child lookup roles keep PLAYER fallback for legacy invites', () => {
  assert.deepEqual(resolvePlayerAccountInviteLookupRoles(true), ['PARENT', 'PLAYER'])
})

test('non-child lookup roles only include PLAYER', () => {
  assert.deepEqual(resolvePlayerAccountInviteLookupRoles(false), ['PLAYER'])
})
