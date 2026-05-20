import test from 'node:test'
import assert from 'node:assert/strict'
import { parseMePasswordPutBody, validatePasswordChangeInput } from '../account-password'

test('parseMePasswordPutBody accepts canonical fields', () => {
  const parsed = parseMePasswordPutBody({
    currentPassword: 'ancien-secret',
    newPassword: 'nouveau-secret',
  })

  assert.equal(parsed.success, true)
  if (parsed.success) {
    assert.equal(parsed.data.currentPassword, 'ancien-secret')
    assert.equal(parsed.data.newPassword, 'nouveau-secret')
  }
})

test('parseMePasswordPutBody accepts alias fields', () => {
  const parsed = parseMePasswordPutBody({
    current_password: 'ancien-secret',
    motDePasseNouveau: 'nouveau-secret',
  })

  assert.equal(parsed.success, true)
  if (parsed.success) {
    assert.equal(parsed.data.currentPassword, 'ancien-secret')
    assert.equal(parsed.data.newPassword, 'nouveau-secret')
  }
})

test('parseMePasswordPutBody rejects too short new password', () => {
  const parsed = parseMePasswordPutBody({
    currentPassword: 'ancien-secret',
    newPassword: '123',
  })

  assert.equal(parsed.success, false)
})

test('validatePasswordChangeInput rejects unchanged password', () => {
  const validated = validatePasswordChangeInput({
    currentPassword: 'secret-identique',
    newPassword: 'secret-identique',
  })

  assert.equal(validated.ok, false)
  if (!validated.ok) assert.match(validated.error, /different/)
})
