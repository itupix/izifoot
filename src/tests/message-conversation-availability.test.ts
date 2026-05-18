import assert from 'node:assert/strict'
import test from 'node:test'

import {
  PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
  resolveCoachConversationInvitationAvailability,
} from '../message-conversation-availability'

test('coach conversation is unavailable when player invitation status is NONE', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'NONE' })

  assert.deepEqual(result, {
    isAvailable: false,
    error: PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
  })
})

test('coach conversation is available when player invitation status is PENDING', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'PENDING' })

  assert.deepEqual(result, {
    isAvailable: true,
    invitationStatus: 'PENDING',
  })
})

test('coach conversation is available when player invitation status is ACCEPTED', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'ACCEPTED' })

  assert.deepEqual(result, {
    isAvailable: true,
    invitationStatus: 'ACCEPTED',
  })
})
