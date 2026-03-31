export type PlayerAccountInviteRole = 'PLAYER' | 'PARENT'

export function resolvePlayerAccountInviteRole(isChild: boolean): PlayerAccountInviteRole {
  return isChild ? 'PARENT' : 'PLAYER'
}

export function resolvePlayerAccountInviteLookupRoles(isChild: boolean): PlayerAccountInviteRole[] {
  return isChild ? ['PARENT', 'PLAYER'] : ['PLAYER']
}
