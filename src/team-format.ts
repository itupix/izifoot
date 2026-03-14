const ALLOWED_TEAM_FORMAT_VALUES = ['3v3', '5v5', '8v8', '11v11'] as const

export const ALLOWED_TEAM_FORMATS = ALLOWED_TEAM_FORMAT_VALUES

const allowedTeamFormatSet = new Set<string>(ALLOWED_TEAM_FORMAT_VALUES)

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
