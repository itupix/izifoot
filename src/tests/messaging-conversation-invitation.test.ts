import test from 'node:test'
import assert from 'node:assert/strict'
import {
  PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
  resolveCoachConversationInvitationAvailability,
} from '../message-conversation-availability'

test('coach conversation is unavailable when player invitation status is NONE', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'NONE' })

  assert.deepEqual(result, {
    isAvailable: false,
    invitationStatus: 'NONE',
    error: PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
  })
})

test('coach conversation exposes PENDING invitation status when invite is pending', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'PENDING' })

  assert.deepEqual(result, {
    isAvailable: true,
    invitationStatus: 'PENDING',
  })
})

test('coach conversation exposes ACCEPTED invitation status when invite is accepted', () => {
  const result = resolveCoachConversationInvitationAvailability({ status: 'ACCEPTED' })

  assert.deepEqual(result, {
    isAvailable: true,
    invitationStatus: 'ACCEPTED',
  })
})
