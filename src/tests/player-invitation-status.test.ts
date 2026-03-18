import test from 'node:test'
import assert from 'node:assert/strict'
import { resolvePlayerInvitationStatus } from '../player-invitation-status'

test('returns NONE when no account and no invite', () => {
  const result = resolvePlayerInvitationStatus({
    hasActiveAccount: false,
    latestPendingInvite: null,
    latestAcceptedInvite: null,
  })

  assert.equal(result.status, 'NONE')
  assert.equal(result.invitationId, null)
  assert.equal(result.lastInvitationAt, null)
})

test('returns PENDING when latest pending invite exists', () => {
  const sentAt = new Date('2026-03-18T09:30:00.000Z')
  const result = resolvePlayerInvitationStatus({
    hasActiveAccount: false,
    latestPendingInvite: {
      id: 'inv_pending',
      createdAt: new Date('2026-03-17T09:30:00.000Z'),
      updatedAt: sentAt,
    },
    latestAcceptedInvite: null,
  })

  assert.equal(result.status, 'PENDING')
  assert.equal(result.invitationId, 'inv_pending')
  assert.equal(result.lastInvitationAt?.toISOString(), sentAt.toISOString())
})

test('returns ACCEPTED when account is already active', () => {
  const result = resolvePlayerInvitationStatus({
    hasActiveAccount: true,
    latestPendingInvite: {
      id: 'inv_pending',
      createdAt: new Date('2026-03-17T09:30:00.000Z'),
      updatedAt: new Date('2026-03-18T09:30:00.000Z'),
    },
    latestAcceptedInvite: null,
  })

  assert.equal(result.status, 'ACCEPTED')
  assert.equal(result.invitationId, null)
})

test('ACCEPTED has priority over PENDING when both exist', () => {
  const acceptedAt = new Date('2026-03-18T11:00:00.000Z')
  const result = resolvePlayerInvitationStatus({
    hasActiveAccount: false,
    latestPendingInvite: {
      id: 'inv_pending',
      createdAt: new Date('2026-03-17T09:30:00.000Z'),
      updatedAt: new Date('2026-03-18T09:30:00.000Z'),
    },
    latestAcceptedInvite: {
      id: 'inv_accepted',
      createdAt: new Date('2026-03-16T09:30:00.000Z'),
      updatedAt: new Date('2026-03-18T10:30:00.000Z'),
      acceptedAt,
    },
  })

  assert.equal(result.status, 'ACCEPTED')
  assert.equal(result.invitationId, 'inv_accepted')
  assert.equal(result.lastInvitationAt?.toISOString(), acceptedAt.toISOString())
})
