import test from 'node:test'
import assert from 'node:assert/strict'
import {
  isSyntheticParentInviteEmail,
  normalizeParentInviteEmail,
  summarizeParentContacts,
} from '../player-parent-contacts'

test('synthetic parent invite emails are hidden from API payloads', () => {
  assert.equal(isSyntheticParentInviteEmail('parent+abc123@invite.izifoot.local'), true)
  assert.equal(normalizeParentInviteEmail('parent+abc123@invite.izifoot.local'), null)
  assert.equal(normalizeParentInviteEmail('parent@example.com'), 'parent@example.com')
})

test('summarizeParentContacts keeps accepted parent state ahead of stale duplicates', () => {
  const contacts = summarizeParentContacts([
    {
      id: 'expired-parent',
      email: 'parent@example.com',
      phone: '0600000000',
      status: 'EXPIRED',
      updatedAt: new Date('2026-05-18T09:00:00.000Z'),
      createdAt: new Date('2026-05-17T09:00:00.000Z'),
    },
    {
      id: 'accepted-parent',
      email: 'parent@example.com',
      phone: '0600000000',
      status: 'ACCEPTED',
      acceptedAt: new Date('2026-05-16T09:00:00.000Z'),
      updatedAt: new Date('2026-05-16T09:00:00.000Z'),
      createdAt: new Date('2026-05-15T09:00:00.000Z'),
      user: {
        id: 'user-parent',
        firstName: 'Marie',
        lastName: 'Martin',
        email: 'parent@example.com',
        phone: '0600000000',
      },
    },
  ])

  assert.equal(contacts.length, 1)
  assert.deepEqual(contacts[0], {
    parentId: 'accepted-parent',
    parentUserId: 'user-parent',
    firstName: 'Marie',
    lastName: 'Martin',
    email: 'parent@example.com',
    phone: '0600000000',
    status: 'ACCEPTED',
  })
})

test('summarizeParentContacts reuses the latest non-activated parent invite and hides placeholder email', () => {
  const contacts = summarizeParentContacts([
    {
      id: 'cancelled-parent',
      email: 'parent+seed@invite.izifoot.local',
      phone: '0611223344',
      status: 'CANCELLED',
      updatedAt: new Date('2026-05-17T09:00:00.000Z'),
      createdAt: new Date('2026-05-16T09:00:00.000Z'),
    },
    {
      id: 'pending-parent',
      email: 'parent+seed@invite.izifoot.local',
      phone: '0611223344',
      status: 'PENDING',
      updatedAt: new Date('2026-05-18T09:00:00.000Z'),
      createdAt: new Date('2026-05-18T08:00:00.000Z'),
    },
  ])

  assert.equal(contacts.length, 1)
  assert.deepEqual(contacts[0], {
    parentId: 'pending-parent',
    parentUserId: null,
    firstName: null,
    lastName: null,
    email: null,
    phone: '0611223344',
    status: 'PENDING',
  })
})
