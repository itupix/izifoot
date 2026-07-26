import test from 'node:test'
import assert from 'node:assert/strict'

import {
  compareMonthDay,
  normalizeClubSeasonConfig,
  resolveSeasonWindowForDate,
} from '../season'

test('normalizeClubSeasonConfig falls back to defaults', () => {
  const config = normalizeClubSeasonConfig({})
  assert.deepEqual(config, {
    startMonth: 8,
    startDay: 1,
    endMonth: 7,
    endDay: 31,
    timezone: 'Europe/Paris',
  })
})

test('resolveSeasonWindowForDate keeps July 26 2026 in season 2025-2026 with default config', () => {
  const season = resolveSeasonWindowForDate('2026-07-26T10:00:00.000Z', {})
  assert.equal(season.key, '2025-2026')
})

test('resolveSeasonWindowForDate maps August 1 2026 to season 2026-2027 with default config', () => {
  const season = resolveSeasonWindowForDate('2026-08-01T10:00:00.000Z', {})
  assert.equal(season.key, '2026-2027')
})

test('compareMonthDay compares month/day tuples', () => {
  assert.equal(compareMonthDay(7, 31, 8, 1) < 0, true)
  assert.equal(compareMonthDay(8, 1, 8, 1), 0)
  assert.equal(compareMonthDay(8, 2, 8, 1) > 0, true)
})
