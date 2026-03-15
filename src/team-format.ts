const ALLOWED_TEAM_FORMAT_VALUES = ['3v3', '5v5', '8v8', '11v11'] as const

export const ALLOWED_TEAM_FORMATS = ALLOWED_TEAM_FORMAT_VALUES
export type TeamFormat = typeof ALLOWED_TEAM_FORMAT_VALUES[number]
export const DEFAULT_TEAM_FORMAT: TeamFormat = '5v5'

const allowedTeamFormatSet = new Set<string>(ALLOWED_TEAM_FORMAT_VALUES)
const playersOnFieldByFormat: Record<TeamFormat, number> = {
  '3v3': 3,
  '5v5': 5,
  '8v8': 8,
  '11v11': 11,
}

export function normalizeTeamFormat(rawFormat: string): { ok: true; format: string } | { ok: false; error: string } {
  const input = String(rawFormat || '').trim()
  if (!input) return { ok: false, error: 'Format is required' }

  const compact = input.replace(/\s+/g, '')
  const m = compact.match(/^(\d{1,2})v(\d{1,2})$/i)
  if (!m) {
    return { ok: false, error: `Invalid format. Allowed values: ${ALLOWED_TEAM_FORMAT_VALUES.join(', ')}` }
  }

  const normalized = `${Number(m[1])}v${Number(m[2])}`
  if (!allowedTeamFormatSet.has(normalized)) {
    return { ok: false, error: `Invalid format. Allowed values: ${ALLOWED_TEAM_FORMAT_VALUES.join(', ')}` }
  }

  return { ok: true, format: normalized }
}

export function resolveTeamFormat(rawFormat: string | null | undefined, fallback: TeamFormat = DEFAULT_TEAM_FORMAT): {
  format: TeamFormat
  playersOnField: number
  usedFallback: boolean
} {
  const parsed = typeof rawFormat === 'string' ? normalizeTeamFormat(rawFormat) : { ok: false as const, error: 'Format is required' }
  const resolvedFormat = parsed.ok ? (parsed.format as TeamFormat) : fallback
  return {
    format: resolvedFormat,
    playersOnField: playersOnFieldByFormat[resolvedFormat],
    usedFallback: !parsed.ok,
  }
}
