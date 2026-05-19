import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildMobileAuthAppCallbackUrl,
  buildMobileAuthCallbackUrl,
  buildMobileAuthWebUrl,
  consumeMobileAuthExchange,
  hashMobileAuthValue,
  signMobileAuthStateCookie,
  validateMobileAuthCodeRecord,
  verifyMobileAuthStateCookie,
} from '../mobile-auth'

const secret = 'mobile-auth-test-secret'

test('verifyMobileAuthStateCookie accepts a matching state cookie', () => {
  const state = 'state-value-123456'
  const token = signMobileAuthStateCookie({
    platform: 'ios',
    state,
    redirectUri: 'izifoot://auth/callback',
    secret,
    ttlSeconds: 60,
  })

  const verified = verifyMobileAuthStateCookie({
    token,
    platform: 'ios',
    state,
    secret,
  })

  assert.equal(verified.ok, true)
  if (verified.ok) {
    assert.equal(verified.stateHash, hashMobileAuthValue(state, secret))
    assert.equal(verified.redirectUri, 'izifoot://auth/callback')
  }
})

test('validateMobileAuthCodeRecord rejects an invalid state', () => {
  const result = validateMobileAuthCodeRecord({
    stateHash: hashMobileAuthValue('expected-state', secret),
    platform: 'IOS',
    expiresAt: new Date('2026-05-19T10:05:00.000Z'),
    usedAt: null,
  }, {
    platform: 'ios',
    state: 'different-state',
    secret,
    now: new Date('2026-05-19T10:00:00.000Z'),
  })

  assert.deepEqual(result, { ok: false, error: 'state_invalid' })
})

test('validateMobileAuthCodeRecord rejects an expired code', () => {
  const state = 'state-expired'
  const result = validateMobileAuthCodeRecord({
    stateHash: hashMobileAuthValue(state, secret),
    platform: 'IOS',
    expiresAt: new Date('2026-05-19T09:59:59.000Z'),
    usedAt: null,
  }, {
    platform: 'ios',
    state,
    secret,
    now: new Date('2026-05-19T10:00:00.000Z'),
  })

  assert.deepEqual(result, { ok: false, error: 'code_expired' })
})

test('validateMobileAuthCodeRecord rejects an already used code', () => {
  const state = 'state-used'
  const result = validateMobileAuthCodeRecord({
    stateHash: hashMobileAuthValue(state, secret),
    platform: 'IOS',
    expiresAt: new Date('2026-05-19T10:05:00.000Z'),
    usedAt: new Date('2026-05-19T10:00:10.000Z'),
  }, {
    platform: 'ios',
    state,
    secret,
    now: new Date('2026-05-19T10:00:20.000Z'),
  })

  assert.deepEqual(result, { ok: false, error: 'code_used' })
})

test('validateMobileAuthCodeRecord accepts a fresh code/state pair', () => {
  const state = 'state-ok'
  const result = validateMobileAuthCodeRecord({
    stateHash: hashMobileAuthValue(state, secret),
    platform: 'IOS',
    expiresAt: new Date('2026-05-19T10:05:00.000Z'),
    usedAt: null,
  }, {
    platform: 'ios',
    state,
    secret,
    now: new Date('2026-05-19T10:00:00.000Z'),
  })

  assert.deepEqual(result, { ok: true })
})

test('consumeMobileAuthExchange succeeds once and marks the code used', async () => {
  const now = new Date('2026-05-19T10:00:00.000Z')
  const state = 'state-success-123456'
  const code = 'code-success-123456'
  let markedCodeId: string | null = null

  const result = await consumeMobileAuthExchange(
    {
      async findByCodeHash(candidateHash) {
        assert.equal(candidateHash, hashMobileAuthValue(code, secret))
        return {
          id: 'mobile-code-1',
          userId: 'user-1',
          stateHash: hashMobileAuthValue(state, secret),
          platform: 'IOS',
          expiresAt: new Date(now.getTime() + 60_000),
          usedAt: null,
        }
      },
      async markCodeUsed(codeId) {
        markedCodeId = codeId
        return true
      },
    },
    {
      platform: 'ios',
      code,
      state,
      secret,
      now,
    },
  )

  assert.equal(result.ok, true)
  if (result.ok) {
    assert.equal(result.record.id, 'mobile-code-1')
    assert.equal(result.record.userId, 'user-1')
  }
  assert.equal(markedCodeId, 'mobile-code-1')
})

test('mobile auth redirect builders preserve state and keep token exchange off URL', () => {
  assert.equal(
    buildMobileAuthWebUrl({
      appBaseUrl: 'https://app.izifoot.test',
      platform: 'ios',
      state: 'state-value-123456',
    }),
    'https://app.izifoot.test/auth/mobile?platform=ios&state=state-value-123456',
  )

  assert.equal(
    buildMobileAuthCallbackUrl({
      apiBaseUrl: 'https://api.izifoot.test',
      state: 'state-value-123456',
    }),
    'https://api.izifoot.test/auth/mobile/callback?state=state-value-123456',
  )

  assert.equal(
    buildMobileAuthAppCallbackUrl({
      callbackUrl: 'izifoot://auth/callback',
      code: 'code-value-123456',
      state: 'state-value-123456',
    }),
    'izifoot://auth/callback?code=code-value-123456&state=state-value-123456',
  )
})
