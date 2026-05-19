export type CoachManagedTeam = {
  id: string
  name: string
}

export function normalizeCoachManagedTeamIds(
  teamId: string | null | undefined,
  managedTeamIds: string[] | null | undefined,
): string[] {
  const normalized: string[] = []
  const seen = new Set<string>()

  const push = (value: string | null | undefined) => {
    const trimmed = typeof value === 'string' ? value.trim() : ''
    if (!trimmed || seen.has(trimmed)) return
    seen.add(trimmed)
    normalized.push(trimmed)
  }

  push(teamId)
  for (const value of managedTeamIds || []) push(value)
  return normalized
}

export function resolveCoachActiveTeamId(
  currentTeamId: string | null | undefined,
  managedTeamIds: string[],
): string | null {
  const normalizedCurrent = typeof currentTeamId === 'string' ? currentTeamId.trim() : ''
  if (normalizedCurrent && managedTeamIds.includes(normalizedCurrent)) return normalizedCurrent
  return managedTeamIds[0] ?? null
}

export function mapCoachManagedTeams(
  managedTeamIds: string[],
  teamNameById: ReadonlyMap<string, string>,
): CoachManagedTeam[] {
  return managedTeamIds.map((id) => ({
    id,
    name: teamNameById.get(id) ?? id,
  }))
}
