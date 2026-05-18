export type CoachConversationInvitationStatus = 'NONE' | 'PENDING' | 'ACCEPTED'

export const PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR = {
  error: 'Conversation unavailable until the player has been invited to join izifoot',
  code: 'PLAYER_INVITATION_REQUIRED' as const,
  invitationStatus: 'NONE' as const,
}

export function resolveCoachConversationInvitationAvailability(
  snapshot: { status?: string | null } | null | undefined,
): (
    | { isAvailable: true, invitationStatus: Exclude<CoachConversationInvitationStatus, 'NONE'> }
    | { isAvailable: false, invitationStatus: 'NONE', error: typeof PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR }
  ) {
  if (snapshot?.status === 'PENDING' || snapshot?.status === 'ACCEPTED') {
    return {
      isAvailable: true,
      invitationStatus: snapshot.status,
    }
  }

  return {
    isAvailable: false,
    invitationStatus: 'NONE',
    error: PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
  }
}
