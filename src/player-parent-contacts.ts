const SYNTHETIC_PARENT_INVITE_EMAIL_DOMAIN = '@invite.izifoot.local'

type ParentInviteUserLike = {
  id?: string | null
  firstName?: string | null
  lastName?: string | null
  email?: string | null
  phone?: string | null
}

export type ParentInviteLike = {
  id: string
  firstName?: string | null
  lastName?: string | null
  email?: string | null
  phone?: string | null
  status?: string | null
  acceptedAt?: Date | null
  updatedAt?: Date | null
  createdAt?: Date | null
  user?: ParentInviteUserLike | null
}

export type ParentContactSummary = {
  parentId: string | null
  parentUserId: string | null
  firstName: string | null
  lastName: string | null
  email: string | null
  phone: string | null
  status: string | null
}

function normalizeOptionalValue(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

export function isSyntheticParentInviteEmail(value: string | null | undefined): boolean {
  const normalized = normalizeOptionalValue(value)
  return Boolean(normalized && normalized.toLowerCase().endsWith(SYNTHETIC_PARENT_INVITE_EMAIL_DOMAIN))
}

export function normalizeParentInviteEmail(value: string | null | undefined): string | null {
  const normalized = normalizeOptionalValue(value)
  if (!normalized || isSyntheticParentInviteEmail(normalized)) return null
  return normalized
}

function resolveParentStatus(invite: ParentInviteLike): string | null {
  if (normalizeOptionalValue(invite.user?.id)) return 'ACCEPTED'
  const normalized = normalizeOptionalValue(invite.status)
  return normalized ? normalized.toUpperCase() : null
}

function resolveParentIdentityKey(invite: ParentInviteLike): string | null {
  const email = (normalizeParentInviteEmail(invite.user?.email) || normalizeParentInviteEmail(invite.email) || '').toLowerCase()
  const phone = normalizeOptionalValue(invite.user?.phone) || normalizeOptionalValue(invite.phone) || ''
  const firstName = (normalizeOptionalValue(invite.user?.firstName) || normalizeOptionalValue(invite.firstName) || '').toLowerCase()
  const lastName = (normalizeOptionalValue(invite.user?.lastName) || normalizeOptionalValue(invite.lastName) || '').toLowerCase()

  if (phone) return `phone:${phone}`
  if (email) return `email:${email}`
  if (firstName || lastName) return `name:${firstName}|${lastName}`
  return null
}

function resolveParentPriority(invite: ParentInviteLike): number {
  switch (resolveParentStatus(invite)) {
    case 'ACCEPTED':
      return 3
    case 'PENDING':
      return 2
    case 'EXPIRED':
      return 1
    case 'CANCELLED':
      return 0
    default:
      return -1
  }
}

function resolveParentTimestamp(invite: ParentInviteLike): number {
  return (invite.acceptedAt ?? invite.updatedAt ?? invite.createdAt ?? new Date(0)).getTime()
}

function compareParentInvites(a: ParentInviteLike, b: ParentInviteLike): number {
  const priorityDiff = resolveParentPriority(b) - resolveParentPriority(a)
  if (priorityDiff !== 0) return priorityDiff

  const timestampDiff = resolveParentTimestamp(b) - resolveParentTimestamp(a)
  if (timestampDiff !== 0) return timestampDiff

  return b.id.localeCompare(a.id)
}

function toParentContactSummary(invite: ParentInviteLike): ParentContactSummary {
  return {
    parentId: invite.id || null,
    parentUserId: normalizeOptionalValue(invite.user?.id),
    firstName: normalizeOptionalValue(invite.user?.firstName) || normalizeOptionalValue(invite.firstName),
    lastName: normalizeOptionalValue(invite.user?.lastName) || normalizeOptionalValue(invite.lastName),
    email: normalizeParentInviteEmail(invite.user?.email) || normalizeParentInviteEmail(invite.email),
    phone: normalizeOptionalValue(invite.user?.phone) || normalizeOptionalValue(invite.phone),
    status: resolveParentStatus(invite),
  }
}

export function summarizeParentContacts(invites: ParentInviteLike[]): ParentContactSummary[] {
  const groups = new Map<string, ParentInviteLike[]>()

  for (const invite of invites) {
    const key = resolveParentIdentityKey(invite)
    if (!key) continue
    const existing = groups.get(key)
    if (existing) existing.push(invite)
    else groups.set(key, [invite])
  }

  return [...groups.values()]
    .map((group) => group.slice().sort(compareParentInvites)[0])
    .sort(compareParentInvites)
    .map((invite) => toParentContactSummary(invite))
}
