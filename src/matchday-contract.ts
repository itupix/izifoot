export type MatchdayMode = 'ROTATION' | 'MANUAL'

const ROTATION_COLOR_PALETTE = [
  '#1d4ed8',
  '#e11d48',
  '#16a34a',
  '#f59e0b',
  '#7c3aed',
  '#0f766e',
]

function toNonEmptyString(value: any): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function fallbackColor(index: number): string {
  return ROTATION_COLOR_PALETTE[index % ROTATION_COLOR_PALETTE.length]
}

export function deriveMatchdayMode(input: {
  hasPersistedRotationKey: boolean
  hasPlanningRotation: boolean
}): MatchdayMode {
  return (input.hasPersistedRotationKey || input.hasPlanningRotation) ? 'ROTATION' : 'MANUAL'
}

export function normalizeRotationForContract(candidate: any, defaultUpdatedAtIso: string) {
  if (!candidate || !Array.isArray(candidate.slots)) return null
  const teamsRaw = Array.isArray(candidate.teams) ? candidate.teams : []
  const teams = teamsRaw.map((team: any, index: number) => ({
    label: toNonEmptyString(team?.label) || `Team ${index + 1}`,
    color: toNonEmptyString(team?.color) || fallbackColor(index),
    absent: Boolean(team?.absent),
  }))
  const slots = candidate.slots.map((slot: any) => ({
    time: String(slot?.time ?? ''),
    games: Array.isArray(slot?.games)
      ? slot.games.map((game: any) => ({
          pitch: game?.pitch ?? '',
          A: String(game?.A ?? ''),
          B: String(game?.B ?? ''),
        }))
      : [],
  }))
  const start = toNonEmptyString(candidate?.start)
  return {
    updatedAt: typeof candidate.updatedAt === 'string' ? candidate.updatedAt : defaultUpdatedAtIso,
    ...(start ? { start } : {}),
    teams,
    slots,
  }
}

export function ensureRotationGameKeysForContract<T extends { rotationGameKey?: string | null }>(
  matches: T[],
  enabled: boolean
): Array<T & { rotationGameKey: string | null }> {
  if (!enabled) {
    return matches.map((match) => ({ ...match, rotationGameKey: match.rotationGameKey ?? null }))
  }

  const used = new Set<string>(
    matches
      .map((match) => toNonEmptyString(match.rotationGameKey))
      .filter((value): value is string => Boolean(value))
  )

  return matches.map((match, index) => {
    const current = toNonEmptyString(match.rotationGameKey)
    if (current) return { ...match, rotationGameKey: current }

    let candidate = `schedule:${index}`
    if (used.has(candidate)) {
      let suffix = 1
      while (used.has(`schedule:${index}:${suffix}`)) suffix += 1
      candidate = `schedule:${index}:${suffix}`
    }
    used.add(candidate)
    return { ...match, rotationGameKey: candidate }
  })
}

