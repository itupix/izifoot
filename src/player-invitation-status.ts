export type PlayerInvitationStatus = 'NONE' | 'PENDING' | 'ACCEPTED'

type InviteSnapshot = {
  id: string
  createdAt: Date
  updatedAt: Date
  acceptedAt?: Date | null
}

export type ResolvePlayerInvitationStatusInput = {
  hasActiveAccount: boolean
  latestPendingInvite: InviteSnapshot | null
  latestAcceptedInvite: InviteSnapshot | null
}

export type PlayerInvitationStatusSnapshot = {
  status: PlayerInvitationStatus
  lastInvitationAt: Date | null
  invitationId: string | null
}

export function resolvePlayerInvitationStatus(input: ResolvePlayerInvitationStatusInput): PlayerInvitationStatusSnapshot {
  if (input.hasActiveAccount || input.latestAcceptedInvite) {
    return {
      status: 'ACCEPTED',
      invitationId: input.latestAcceptedInvite?.id ?? null,
      lastInvitationAt:
        input.latestAcceptedInvite?.acceptedAt ??
        input.latestAcceptedInvite?.updatedAt ??
        input.latestAcceptedInvite?.createdAt ??
        null,
    }
  }

  if (input.latestPendingInvite) {
    return {
      status: 'PENDING',
      invitationId: input.latestPendingInvite.id,
      lastInvitationAt: input.latestPendingInvite.updatedAt ?? input.latestPendingInvite.createdAt,
    }
  }

  return {
    status: 'NONE',
    invitationId: null,
    lastInvitationAt: null,
  }
}
