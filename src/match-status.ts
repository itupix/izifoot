export const MATCH_STATUSES = ['PLANNED', 'PLAYED', 'CANCELLED'] as const

export type MatchStatus = typeof MATCH_STATUSES[number]

export type MatchScorerPayload = { playerId: string; side: 'home' | 'away'; assistId?: string | null }

export function isMatchStatus(value: unknown): value is MatchStatus {
  return typeof value === 'string' && (MATCH_STATUSES as readonly string[]).includes(value)
}

export function resolveMatchStatus(value: { status?: unknown; played?: boolean | null }): MatchStatus {
  if (isMatchStatus(value.status)) return value.status
  return value.played ? 'PLAYED' : 'PLANNED'
}

export function statusFromLegacyPlayed(played?: boolean): MatchStatus {
  return played ? 'PLAYED' : 'PLANNED'
}

export function derivePlayedFromStatus(status: MatchStatus): boolean {
  return status === 'PLAYED'
}

export function resolvePatchedMatchStatus(input: {
  payloadStatus?: unknown
  payloadPlayed?: boolean
  existingStatus: MatchStatus
}): MatchStatus {
  if (isMatchStatus(input.payloadStatus)) return input.payloadStatus
  if (input.payloadPlayed === undefined) return input.existingStatus
  if (input.payloadPlayed) return 'PLAYED'
  // Backward-compatible behavior for clients still sending only `played=false`.
  return input.existingStatus === 'CANCELLED' ? 'CANCELLED' : 'PLANNED'
}

export function normalizeMatchWriteState(input: {
  status: MatchStatus
  score?: { home: number; away: number }
  buteurs?: MatchScorerPayload[]
}) {
  if (input.status === 'PLAYED') {
    return {
      played: true,
      score: input.score ?? { home: 0, away: 0 },
      buteurs: input.buteurs ?? [],
    }
  }

  return {
    played: false,
    score: { home: 0, away: 0 },
    buteurs: [],
  }
}

export function countPlayedMatchesExcludingCancelled(rows: Array<{ status?: unknown; played?: boolean | null }>): number {
  return rows.reduce((count, row) => {
    const status = resolveMatchStatus(row)
    if (status !== 'PLAYED') return count
    return count + 1
  }, 0)
}
