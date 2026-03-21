import { MatchStatus, resolveMatchStatus } from './match-status'

export type RotationTeam = {
  label: string
  color?: string
  absent?: boolean
}

export type RotationGame = {
  A: string
  B: string
  pitch?: string | number
  rotationGameKey?: string
}

export type RotationSlot = {
  time?: string
  games: RotationGame[]
}

export type Rotation = {
  teams?: RotationTeam[]
  slots: RotationSlot[]
}

export type MatchAbsenceTarget = {
  id: string
  status?: MatchStatus | null
  played?: boolean
}

function normalizeLabel(label: string): string {
  return label.trim().toLowerCase()
}

export function buildRotationGameKey(slotIndex: number, gameIndex: number, game: RotationGame): string {
  if (typeof game.rotationGameKey === 'string' && game.rotationGameKey.trim().length > 0) {
    return game.rotationGameKey.trim()
  }
  return `slot:${slotIndex}:game:${gameIndex}`
}

export function ensureRotationGameKeys(rotation: Rotation): Rotation {
  return {
    ...rotation,
    slots: (rotation.slots || []).map((slot, slotIndex) => ({
      ...slot,
      games: (slot.games || []).map((game, gameIndex) => ({
        ...game,
        rotationGameKey: buildRotationGameKey(slotIndex, gameIndex, game),
      })),
    })),
  }
}

export function extractRotationTeams(rotation: Rotation | null | undefined): RotationTeam[] {
  if (!rotation?.teams || !Array.isArray(rotation.teams)) return []
  return rotation.teams.map((team) => ({
    ...team,
    absent: Boolean(team.absent),
  }))
}

export function diffTeamAbsence(beforeTeams: RotationTeam[], afterTeams: RotationTeam[]) {
  const beforeMap = new Map(beforeTeams.map((team) => [normalizeLabel(team.label), Boolean(team.absent)]))
  const afterMap = new Map(afterTeams.map((team) => [normalizeLabel(team.label), Boolean(team.absent)]))
  const labels = new Set<string>([...beforeMap.keys(), ...afterMap.keys()])

  const changes: Array<{ teamLabel: string; absent: boolean }> = []
  for (const label of labels) {
    const before = beforeMap.get(label) ?? false
    const after = afterMap.get(label) ?? false
    if (before === after) continue
    const sourceLabel = afterTeams.find((team) => normalizeLabel(team.label) === label)?.label
      || beforeTeams.find((team) => normalizeLabel(team.label) === label)?.label
      || label
    changes.push({ teamLabel: sourceLabel, absent: after })
  }
  return changes
}

export function findRotationGameKeysForTeam(rotation: Rotation, teamLabel: string): string[] {
  const target = normalizeLabel(teamLabel)
  const keyed = ensureRotationGameKeys(rotation)
  const keys: string[] = []

  for (const [slotIndex, slot] of keyed.slots.entries()) {
    for (const [gameIndex, game] of slot.games.entries()) {
      const a = normalizeLabel(game.A || '')
      const b = normalizeLabel(game.B || '')
      if (a !== target && b !== target) continue
      keys.push(buildRotationGameKey(slotIndex, gameIndex, game))
    }
  }

  return keys
}

export function transitionMatchStatusForAbsence(currentStatus: MatchStatus, absent: boolean): MatchStatus {
  if (absent) return 'CANCELLED'
  if (currentStatus === 'PLAYED') return 'PLAYED'
  return 'PLANNED'
}

export function buildAbsenceMatchPatches(input: {
  matches: MatchAbsenceTarget[]
  absent: boolean
}) {
  const patches: Array<{ id: string; status: MatchStatus; played: boolean }> = []

  for (const match of input.matches) {
    const currentStatus = resolveMatchStatus({ status: match.status, played: match.played ?? false })
    const nextStatus = transitionMatchStatusForAbsence(currentStatus, input.absent)
    const nextPlayed = nextStatus === 'PLAYED'
    const currentPlayed = currentStatus === 'PLAYED'
    if (nextStatus === currentStatus && nextPlayed === currentPlayed) continue
    patches.push({ id: match.id, status: nextStatus, played: nextPlayed })
  }

  return patches
}
