import { z } from 'zod'

function asOptionalTrimmedString(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function firstPresentString(...values: unknown[]): string | null {
  for (const value of values) {
    const normalized = asOptionalTrimmedString(value)
    if (normalized) return normalized
  }
  return null
}

function parseBooleanLike(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (value === 1) return true
    if (value === 0) return false
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    if (['true', '1', 'yes', 'y', 'oui'].includes(normalized)) return true
    if (['false', '0', 'no', 'n', 'non'].includes(normalized)) return false
  }
  return null
}

function splitLegacyName(fullName: string | null): { firstName: string | null, lastName: string | null } {
  if (!fullName) return { firstName: null, lastName: null }
  const parts = fullName.trim().split(/\s+/).filter(Boolean)
  if (!parts.length) return { firstName: null, lastName: null }
  if (parts.length === 1) return { firstName: parts[0], lastName: '' }
  return {
    firstName: parts[0],
    lastName: parts.slice(1).join(' '),
  }
}

function composeFullName(firstName: string | null, lastName: string | null, fallbackName?: string | null): string {
  const full = [firstName, lastName].filter((v) => !!(v && v.trim().length)).join(' ').trim()
  if (full.length) return full
  return (fallbackName || '').trim()
}

export const DEFAULT_PLAYER_PRIMARY_POSITION = 'NON DEFINI'

const basePlayerSchema = z.object({
  firstName: z.string(),
  lastName: z.string(),
  email: z.string(),
  phone: z.string(),
  primary_position: z.string(),
  secondary_position: z.string().nullable(),
  licence: z.string().nullable(),
  isChild: z.boolean(),
  parentFirstName: z.string().nullable(),
  parentLastName: z.string().nullable(),
  teamId: z.string().nullable(),
})

export type CanonicalPlayerPayload = z.infer<typeof basePlayerSchema>

function validatePlayerBusinessRules(payload: CanonicalPlayerPayload): CanonicalPlayerPayload {
  const parsed = basePlayerSchema.safeParse(payload)
  if (!parsed.success) {
    throw parsed.error
  }

  const normalized: CanonicalPlayerPayload = {
    ...parsed.data,
    firstName: parsed.data.firstName.trim(),
    lastName: parsed.data.lastName.trim(),
    email: parsed.data.email.trim(),
    phone: parsed.data.phone.trim(),
    primary_position: parsed.data.primary_position.trim(),
    secondary_position: parsed.data.secondary_position ? parsed.data.secondary_position.trim() : null,
    licence: parsed.data.licence ? parsed.data.licence.trim() : null,
    parentFirstName: parsed.data.parentFirstName ? parsed.data.parentFirstName.trim() : null,
    parentLastName: parsed.data.parentLastName ? parsed.data.parentLastName.trim() : null,
    teamId: parsed.data.teamId ? parsed.data.teamId.trim() : null,
  }

  if (!normalized.firstName) {
    throw new z.ZodError([{ code: 'custom', path: ['firstName'], message: 'Required' }])
  }

  if (!normalized.primary_position) {
    normalized.primary_position = DEFAULT_PLAYER_PRIMARY_POSITION
  }

  if (normalized.isChild) {
    // Child profiles should not carry parent identity or personal contact coordinates.
    normalized.parentFirstName = null
    normalized.parentLastName = null
    normalized.email = ''
    normalized.phone = ''
  } else {
    normalized.parentFirstName = null
    normalized.parentLastName = null

    if (normalized.email && !z.string().email().safeParse(normalized.email).success) {
      throw new z.ZodError([{ code: 'custom', path: ['email'], message: 'Invalid email' }])
    }
  }

  return normalized
}

function extractPlayerDraft(raw: any): Partial<CanonicalPlayerPayload> {
  const legacyName = firstPresentString(raw?.name)
  const splitLegacy = splitLegacyName(legacyName)

  const firstName = firstPresentString(raw?.firstName, raw?.first_name, raw?.prenom, splitLegacy.firstName)
  const lastName = firstPresentString(raw?.lastName, raw?.last_name, raw?.nom, splitLegacy.lastName)
  const email = firstPresentString(raw?.email)
  const phone = firstPresentString(raw?.phone, raw?.telephone)
  const primaryPosition = firstPresentString(raw?.primary_position, raw?.primaryPosition, raw?.poste)
  const secondaryPosition = firstPresentString(raw?.secondary_position, raw?.secondaryPosition)
  const parentFirstName = firstPresentString(raw?.parentFirstName, raw?.parent_first_name, raw?.parentPrenom)
  const parentLastName = firstPresentString(raw?.parentLastName, raw?.parent_last_name, raw?.parentNom)
  const teamId = firstPresentString(raw?.teamId, raw?.team_id)

  let isChild: boolean | undefined
  const parsedChild = parseBooleanLike(raw?.isChild ?? raw?.is_child ?? raw?.enfant)
  if (parsedChild !== null) isChild = parsedChild

  let licence: string | null | undefined
  if ('licence' in (raw || {}) || 'license' in (raw || {})) {
    licence = firstPresentString(raw?.licence, raw?.license)
  }

  let secondary_position: string | null | undefined
  if ('secondary_position' in (raw || {}) || 'secondaryPosition' in (raw || {})) {
    secondary_position = secondaryPosition
  }

  return {
    ...(firstName !== null ? { firstName } : {}),
    ...(lastName !== null ? { lastName } : {}),
    ...(email !== null ? { email } : {}),
    ...(phone !== null ? { phone } : {}),
    ...(primaryPosition !== null ? { primary_position: primaryPosition } : {}),
    ...(secondary_position !== undefined ? { secondary_position } : {}),
    ...(licence !== undefined ? { licence: licence ?? null } : {}),
    ...(isChild !== undefined ? { isChild } : {}),
    ...(parentFirstName !== null ? { parentFirstName } : {}),
    ...(parentLastName !== null ? { parentLastName } : {}),
    ...(teamId !== null ? { teamId } : {}),
  }
}

function canonicalFromExistingPlayer(existing: any): CanonicalPlayerPayload {
  const split = splitLegacyName(firstPresentString(existing?.name))
  const firstName = firstPresentString(existing?.firstName, existing?.first_name, split.firstName) || ''
  const lastName = firstPresentString(existing?.lastName, existing?.last_name, split.lastName) || ''
  const parentFirstName = firstPresentString(existing?.parentFirstName, existing?.parent_first_name)
  const parentLastName = firstPresentString(existing?.parentLastName, existing?.parent_last_name)
  const isChild = parseBooleanLike(existing?.isChild ?? existing?.is_child ?? existing?.enfant) || false

  return {
    firstName,
    lastName,
    email: firstPresentString(existing?.email) || '',
    phone: firstPresentString(existing?.phone) || '',
    primary_position: firstPresentString(existing?.primary_position) || DEFAULT_PLAYER_PRIMARY_POSITION,
    secondary_position: firstPresentString(existing?.secondary_position),
    licence: firstPresentString(existing?.licence, existing?.license),
    isChild,
    parentFirstName,
    parentLastName,
    teamId: firstPresentString(existing?.teamId, existing?.team_id),
  }
}

export function parsePlayerCreatePayload(raw: any): CanonicalPlayerPayload {
  const draft = extractPlayerDraft(raw)
  return validatePlayerBusinessRules({
    firstName: draft.firstName || '',
    lastName: draft.lastName || '',
    email: draft.email || '',
    phone: draft.phone || '',
    primary_position: draft.primary_position || DEFAULT_PLAYER_PRIMARY_POSITION,
    secondary_position: draft.secondary_position ?? null,
    licence: draft.licence ?? null,
    isChild: draft.isChild ?? false,
    parentFirstName: draft.parentFirstName ?? null,
    parentLastName: draft.parentLastName ?? null,
    teamId: draft.teamId ?? null,
  })
}

export function parsePlayerUpdatePayload(raw: any, existing: any): CanonicalPlayerPayload {
  const current = canonicalFromExistingPlayer(existing)
  const draft = extractPlayerDraft(raw)
  return validatePlayerBusinessRules({
    firstName: draft.firstName ?? current.firstName,
    lastName: draft.lastName ?? current.lastName,
    email: draft.email ?? current.email,
    phone: draft.phone ?? current.phone,
    primary_position: draft.primary_position ?? current.primary_position,
    secondary_position: draft.secondary_position !== undefined ? draft.secondary_position ?? null : current.secondary_position,
    licence: draft.licence !== undefined ? draft.licence ?? null : current.licence,
    isChild: draft.isChild ?? current.isChild,
    parentFirstName: draft.parentFirstName ?? current.parentFirstName,
    parentLastName: draft.parentLastName ?? current.parentLastName,
    teamId: draft.teamId ?? current.teamId,
  })
}

export function assertPlayerAccountInvitePrerequisites(
  player: any,
  overrides: { email?: string | null, phone?: string | null } = {}
) {
  const split = splitLegacyName(firstPresentString(player?.name))
  const isChild = parseBooleanLike(player?.isChild ?? player?.is_child ?? player?.enfant) || false
  if (isChild) return

  const lastName = firstPresentString(player?.lastName, player?.last_name, split.lastName)
  const email = firstPresentString(overrides.email, player?.email)
  const phone = firstPresentString(overrides.phone, player?.phone, player?.telephone)
  const issues: Array<{ code: 'custom', path: string[], message: string }> = []

  if (!lastName) {
    issues.push({ code: 'custom', path: ['lastName'], message: 'Required before sending account invitation' })
  }
  if (!email) {
    issues.push({ code: 'custom', path: ['email'], message: 'Required before sending account invitation' })
  } else if (!z.string().email().safeParse(email).success) {
    issues.push({ code: 'custom', path: ['email'], message: 'Invalid email' })
  }
  if (!phone) {
    issues.push({ code: 'custom', path: ['phone'], message: 'Required before sending account invitation' })
  }

  if (issues.length > 0) {
    throw new z.ZodError(issues)
  }
}

export function normalizePlayerForApi(player: any) {
  const split = splitLegacyName(firstPresentString(player?.name))
  const firstName = firstPresentString(player?.firstName, player?.first_name, split.firstName)
  const lastName = firstPresentString(player?.lastName, player?.last_name, split.lastName)
  const isChild = parseBooleanLike(player?.isChild ?? player?.is_child ?? player?.enfant) || false
  const licence = firstPresentString(player?.licence, player?.license)
  const email = isChild ? null : firstPresentString(player?.email)
  const phone = isChild ? null : firstPresentString(player?.phone, player?.telephone)

  return {
    ...player,
    firstName,
    lastName,
    name: composeFullName(firstName, lastName, player?.name),
    isChild,
    email: email ?? null,
    phone: phone ?? null,
    parentFirstName: null,
    parentLastName: null,
    parent_first_name: null,
    parent_last_name: null,
    licence: licence ?? null,
  }
}
