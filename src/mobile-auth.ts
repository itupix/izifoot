import { createHmac, randomBytes } from 'crypto'
import jwt from 'jsonwebtoken'
import { z } from 'zod'

export const MOBILE_AUTH_STATE_COOKIE_NAME = 'izifoot_mobile_auth'
export const MOBILE_AUTH_WEB_PATH = '/auth/mobile'
export const DEFAULT_MOBILE_AUTH_CODE_TTL_SECONDS = 300
export const DEFAULT_MOBILE_AUTH_STATE_TTL_SECONDS = 600

const MOBILE_AUTH_SECRET_MIN_LENGTH = 16
const MOBILE_AUTH_SECRET_MAX_LENGTH = 512
const MOBILE_AUTH_REDIRECT_URI_MAX_LENGTH = 1024
const DISALLOWED_REDIRECT_PROTOCOLS = new Set(['data:', 'file:', 'javascript:'])

export const mobileAuthPlatformSchema = z.enum(['ios'])
export type MobileAuthPlatform = z.infer<typeof mobileAuthPlatformSchema>

export const mobileAuthStartQuerySchema = z.object({
  platform: mobileAuthPlatformSchema,
  redirect_uri: z.string()
    .trim()
    .min(1)
    .max(MOBILE_AUTH_REDIRECT_URI_MAX_LENGTH)
    .refine((value) => isSafeRedirectUri(value), 'Invalid redirect_uri')
    .optional(),
  state: z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH).optional(),
})

export const mobileAuthCallbackQuerySchema = z.object({
  state: z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
})

export const mobileAuthExchangeBodySchema = z.object({
  platform: mobileAuthPlatformSchema.optional().default('ios'),
  code: z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
  state: z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
})

type MobileAuthStateCookiePayload = {
  aud: 'mobile_auth'
  platform: MobileAuthPlatform
  stateHash: string
  redirectUri: string
}

export type MobileAuthCodeRecordLike = {
  stateHash: string
  platform: string
  expiresAt: Date
  usedAt: Date | null
}

export type MobileAuthCodeValidationResult =
  | { ok: true }
  | { ok: false, error: 'state_invalid' | 'state_expired' | 'code_expired' | 'code_used' | 'platform_invalid' }

export type MobileAuthExchangeResult =
  | {
      ok: true
      record: MobileAuthCodeRecordLike & { id: string, userId: string }
      usedAt: Date
    }
  | {
      ok: false
      status: 400 | 404 | 409 | 410
      error: string
      code:
        | 'MOBILE_AUTH_CODE_NOT_FOUND'
        | 'MOBILE_AUTH_INVALID_STATE'
        | 'MOBILE_AUTH_CODE_ALREADY_USED'
        | 'MOBILE_AUTH_CODE_EXPIRED'
        | 'MOBILE_AUTH_PLATFORM_INVALID'
    }

export interface MobileAuthExchangeStore {
  findByCodeHash(codeHash: string): Promise<(MobileAuthCodeRecordLike & { id: string, userId: string }) | null>
  markCodeUsed(codeId: string, usedAt: Date): Promise<boolean>
}

export function hashMobileAuthValue(value: string, secret: string) {
  return createHmac('sha256', secret).update(value).digest('hex')
}

export function createMobileAuthState() {
  return randomBytes(24).toString('base64url')
}

export function createMobileAuthCode() {
  return randomBytes(32).toString('base64url')
}

export function signMobileAuthStateCookie(params: {
  platform: MobileAuthPlatform
  state: string
  redirectUri: string
  secret: string
  ttlSeconds?: number
}) {
  assertSafeRedirectUri(params.redirectUri)
  const ttlSeconds = params.ttlSeconds ?? DEFAULT_MOBILE_AUTH_STATE_TTL_SECONDS
  const payload: MobileAuthStateCookiePayload = {
    aud: 'mobile_auth',
    platform: params.platform,
    stateHash: hashMobileAuthValue(params.state, params.secret),
    redirectUri: params.redirectUri,
  }
  return jwt.sign(payload, params.secret, { expiresIn: ttlSeconds })
}

export function verifyMobileAuthStateCookie(params: {
  token: string | null | undefined
  platform: MobileAuthPlatform
  state: string
  secret: string
}): { ok: true, stateHash: string, redirectUri: string } | { ok: false, error: 'state_invalid' | 'state_expired' } {
  if (!params.token) return { ok: false, error: 'state_invalid' }

  try {
    const payload = jwt.verify(params.token, params.secret) as jwt.JwtPayload & Partial<MobileAuthStateCookiePayload>
    if (payload.aud !== 'mobile_auth') return { ok: false, error: 'state_invalid' }
    if (payload.platform !== params.platform) return { ok: false, error: 'state_invalid' }
    if (typeof payload.redirectUri !== 'string' || !isSafeRedirectUri(payload.redirectUri)) {
      return { ok: false, error: 'state_invalid' }
    }

    const stateHash = hashMobileAuthValue(params.state, params.secret)
    if (payload.stateHash !== stateHash) return { ok: false, error: 'state_invalid' }

    return { ok: true, stateHash, redirectUri: payload.redirectUri }
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return { ok: false, error: 'state_expired' }
    }
    return { ok: false, error: 'state_invalid' }
  }
}

export function validateMobileAuthCodeRecord(
  record: MobileAuthCodeRecordLike,
  params: {
    platform: MobileAuthPlatform
    state: string
    secret: string
    now?: Date
  }
): MobileAuthCodeValidationResult {
  const now = params.now ?? new Date()
  const hashedState = hashMobileAuthValue(params.state, params.secret)

  if (record.platform !== params.platform.toUpperCase()) {
    return { ok: false, error: 'platform_invalid' }
  }
  if (record.stateHash !== hashedState) {
    return { ok: false, error: 'state_invalid' }
  }
  if (record.usedAt) {
    return { ok: false, error: 'code_used' }
  }
  if (record.expiresAt.getTime() <= now.getTime()) {
    return { ok: false, error: 'code_expired' }
  }

  return { ok: true }
}

export async function consumeMobileAuthExchange(
  store: MobileAuthExchangeStore,
  params: {
    platform: MobileAuthPlatform
    code: string
    state: string
    secret: string
    now?: Date
  }
): Promise<MobileAuthExchangeResult> {
  const now = params.now ?? new Date()
  const codeHash = hashMobileAuthValue(params.code, params.secret)
  const record = await store.findByCodeHash(codeHash)

  if (!record) {
    return {
      ok: false,
      status: 404,
      error: 'Mobile auth code not found',
      code: 'MOBILE_AUTH_CODE_NOT_FOUND',
    }
  }

  const validation = validateMobileAuthCodeRecord(record, params)
  if (!validation.ok) {
    if (validation.error === 'platform_invalid') {
      return {
        ok: false,
        status: 400,
        error: 'Unsupported mobile auth platform',
        code: 'MOBILE_AUTH_PLATFORM_INVALID',
      }
    }
    if (validation.error === 'state_invalid') {
      return {
        ok: false,
        status: 400,
        error: 'Invalid mobile auth state',
        code: 'MOBILE_AUTH_INVALID_STATE',
      }
    }
    if (validation.error === 'code_used') {
      return {
        ok: false,
        status: 409,
        error: 'Mobile auth code already used',
        code: 'MOBILE_AUTH_CODE_ALREADY_USED',
      }
    }
    return {
      ok: false,
      status: 410,
      error: 'Mobile auth code expired',
      code: 'MOBILE_AUTH_CODE_EXPIRED',
    }
  }

  const usedAt = now
  const markedUsed = await store.markCodeUsed(record.id, usedAt)
  if (!markedUsed) {
    return {
      ok: false,
      status: 409,
      error: 'Mobile auth code already used',
      code: 'MOBILE_AUTH_CODE_ALREADY_USED',
    }
  }

  return { ok: true, record, usedAt }
}

export function buildMobileAuthWebUrl(params: {
  appBaseUrl: string
  platform: MobileAuthPlatform
  state: string
  error?: string | null
}) {
  const url = new URL(MOBILE_AUTH_WEB_PATH, ensureTrailingSlash(params.appBaseUrl))
  url.searchParams.set('platform', params.platform)
  url.searchParams.set('state', params.state)
  if (params.error) url.searchParams.set('error', params.error)
  return url.toString()
}

export function buildMobileAuthCallbackUrl(params: {
  apiBaseUrl: string
  state: string
}) {
  const url = new URL('/auth/mobile/callback', ensureTrailingSlash(params.apiBaseUrl))
  url.searchParams.set('state', params.state)
  return url.toString()
}

export function buildMobileAuthAppCallbackUrl(params: {
  callbackUrl: string
  code: string
  state: string
}) {
  assertSafeRedirectUri(params.callbackUrl)
  const url = new URL(params.callbackUrl)
  url.searchParams.set('code', params.code)
  url.searchParams.set('state', params.state)
  return url.toString()
}

function assertSafeRedirectUri(rawUrl: string) {
  if (!isSafeRedirectUri(rawUrl)) throw new Error('Invalid redirect_uri')
}

function isSafeRedirectUri(rawUrl: string) {
  try {
    const url = new URL(rawUrl)
    return !DISALLOWED_REDIRECT_PROTOCOLS.has(url.protocol)
  } catch {
    return false
  }
}

function ensureTrailingSlash(url: string) {
  return url.endsWith('/') ? url : `${url}/`
}
