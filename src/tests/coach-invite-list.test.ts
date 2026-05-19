import test from 'node:test'
import assert from 'node:assert/strict'
import { filterLatestCoachInvites } from '../coach-invite-list'

test('filterLatestCoachInvites keeps the most recently updated invite for the same email', () => {
  const invites = filterLatestCoachInvites([
    {
      id: 'older-created-later-stale',
      email: 'coach@example.com',
      updatedAt: new Date('2026-05-18T08:00:00.000Z'),
      createdAt: new Date('2026-05-19T08:00:00.000Z'),
    },
    {
      id: 'resent-active',
      email: 'coach@example.com',
      updatedAt: new Date('2026-05-19T10:00:00.000Z'),
      createdAt: new Date('2026-05-17T08:00:00.000Z'),
    },
  ], new Set())

  assert.equal(invites.length, 1)
  assert.equal(invites[0]?.id, 'resent-active')
})

test('filterLatestCoachInvites excludes invites when the coach account is already active', () => {
  const invites = filterLatestCoachInvites([
    {
      id: 'pending-invite',
      email: 'coach@example.com',
      updatedAt: new Date('2026-05-19T10:00:00.000Z'),
      createdAt: new Date('2026-05-19T09:00:00.000Z'),
    },
  ], new Set(['coach@example.com']))

  assert.equal(invites.length, 0)
})
