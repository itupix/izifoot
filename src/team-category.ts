const MIN_U_CATEGORY = 6
const MAX_U_CATEGORY = 20

const NORMALIZED_NON_U_CATEGORIES = ['Seniors', 'Vétérans'] as const

export const ALLOWED_TEAM_CATEGORIES = [
  ...Array.from({ length: MAX_U_CATEGORY - MIN_U_CATEGORY + 1 }, (_, idx) => `U${MIN_U_CATEGORY + idx}`),
  ...NORMALIZED_NON_U_CATEGORIES,
] as const

function stripDiacritics(value: string) {
  return value.normalize('NFD').replace(/[\u0300-\u036f]/g, '')
}

function normalizeCategoryToken(token: string): string | null {
  const trimmed = token.trim()
  if (!trimmed) return null

  const uMatch = trimmed.match(/^u\s*(\d{1,2})$/i)
  if (uMatch) {
    const age = Number(uMatch[1])
    if (!Number.isInteger(age) || age < MIN_U_CATEGORY || age > MAX_U_CATEGORY) return null
    return `U${age}`
  }

  const folded = stripDiacritics(trimmed).toLowerCase()
  if (folded === 'senior' || folded === 'seniors') return 'Seniors'
  if (folded === 'veteran' || folded === 'veterans') return 'Vétérans'

  return null
}

function parseUAge(category: string): number | null {
  const match = category.match(/^U(\d{1,2})$/)
  if (!match) return null
  const age = Number(match[1])
  if (!Number.isInteger(age)) return null
  return age
}

export function normalizeTeamCategory(rawCategory: string): { ok: true; category: string } | { ok: false; error: string } {
  const input = String(rawCategory || '').trim()
  if (!input) return { ok: false, error: 'Category is required' }

  const rangeMatch = input.match(/^(.+?)\s*-\s*(.+)$/)
  if (!rangeMatch) {
    const normalizedSingle = normalizeCategoryToken(input)
    if (!normalizedSingle) {
      return { ok: false, error: 'Invalid category. Allowed values: U6-U20, Seniors, Vétérans, or contiguous U ranges like U8-U10' }
    }
    return { ok: true, category: normalizedSingle }
  }

  const left = normalizeCategoryToken(rangeMatch[1])
  const right = normalizeCategoryToken(rangeMatch[2])
  if (!left || !right) {
    return { ok: false, error: 'Invalid category range. Use contiguous U ranges only (for example U8-U10)' }
  }

  const leftAge = parseUAge(left)
  const rightAge = parseUAge(right)
  if (leftAge == null || rightAge == null) {
    return { ok: false, error: 'Invalid category range. Non-U ranges are not allowed (for example U8-Vétérans)' }
  }
  if (leftAge >= rightAge) {
    return { ok: false, error: 'Invalid category range. End of range must be greater than start (for example U8-U10)' }
  }

  return { ok: true, category: `${left}-${right}` }
}
