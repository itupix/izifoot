import { MatchTactic, validateMatchTacticForPlayersOnField } from './match-tactic'
import { resolveTeamFormat } from './team-format'

type MatchSidePayload = {
  starters: string[]
  subs: string[]
}

type MatchSidesPayload = {
  home: MatchSidePayload
  away: MatchSidePayload
}

export function validateMatchUpdatePayloadForTeamFormat(input: {
  teamFormat: string | null | undefined
  sides: MatchSidesPayload
  tactic: MatchTactic | null | undefined
}): { ok: true; format: string; playersOnField: number; usedFallback: boolean } | { ok: false; error: string } {
  const resolved = resolveTeamFormat(input.teamFormat)

  for (const sideName of ['home', 'away'] as const) {
    const side = input.sides[sideName]

    if (side.starters.length > resolved.playersOnField) {
      return {
        ok: false,
        error: `Too many starters for ${sideName}: received ${side.starters.length}, max ${resolved.playersOnField} for format ${resolved.format}`,
      }
    }

    const starterSet = new Set(side.starters)
    if (starterSet.size !== side.starters.length) {
      return { ok: false, error: `Duplicate player IDs in ${sideName}.starters` }
    }

    const subSet = new Set(side.subs)
    if (subSet.size !== side.subs.length) {
      return { ok: false, error: `Duplicate player IDs in ${sideName}.subs` }
    }

    for (const playerId of starterSet) {
      if (subSet.has(playerId)) {
        return { ok: false, error: `Player "${playerId}" cannot be in both ${sideName}.starters and ${sideName}.subs` }
      }
    }
  }

  if (input.tactic) {
    const tacticValidation = validateMatchTacticForPlayersOnField(input.tactic, resolved.playersOnField)
    if (!tacticValidation.ok) {
      return { ok: false, error: tacticValidation.error }
    }
  }

  return {
    ok: true,
    format: resolved.format,
    playersOnField: resolved.playersOnField,
    usedFallback: resolved.usedFallback,
  }
}
