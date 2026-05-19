export type CoachInviteListItem = {
  id: string
  email: string
  updatedAt?: Date | null
  createdAt?: Date | null
}

function normalizeInviteEmail(email: string): string {
  return email.trim().toLowerCase()
}

function inviteTimestamp(invite: CoachInviteListItem): number {
  return (invite.updatedAt ?? invite.createdAt ?? new Date(0)).getTime()
}

export function filterLatestCoachInvites<T extends CoachInviteListItem>(invites: T[], acceptedEmails: ReadonlySet<string>): T[] {
  const seenInviteEmails = new Set<string>()

  return invites
    .slice()
    .sort((lhs, rhs) => {
      const timestampDiff = inviteTimestamp(rhs) - inviteTimestamp(lhs)
      if (timestampDiff !== 0) return timestampDiff
      return rhs.id.localeCompare(lhs.id)
    })
    .filter((invite) => {
      const email = normalizeInviteEmail(invite.email)
      if (!email || acceptedEmails.has(email)) return false
      if (seenInviteEmails.has(email)) return false
      seenInviteEmails.add(email)
      return true
    })
}
