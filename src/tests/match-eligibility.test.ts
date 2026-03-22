import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEligiblePlayerIdsFromMatchdayAttendance } from '../match-eligibility'

test('buildEligiblePlayerIdsFromMatchdayAttendance returns null when attendance is empty', () => {
  const eligible = buildEligiblePlayerIdsFromMatchdayAttendance([])
  assert.equal(eligible, null)
})

test('buildEligiblePlayerIdsFromMatchdayAttendance includes present and convoked players only', () => {
  const eligible = buildEligiblePlayerIdsFromMatchdayAttendance([
    { playerId: 'p1', session_type: 'PLATEAU', present: true },
    { playerId: 'p2', session_type: 'PLATEAU_ABSENT', present: false },
    { playerId: 'p3', session_type: 'PLATEAU_CONVOKE' },
    { playerId: 'p4', session_type: 'PLATEAU', present: false },
  ])

  assert.ok(eligible)
  assert.equal(eligible!.has('p1'), true)
  assert.equal(eligible!.has('p3'), true)
  assert.equal(eligible!.has('p2'), false)
  assert.equal(eligible!.has('p4'), false)
})

test('buildEligiblePlayerIdsFromMatchdayAttendance supports legacy PLATEAU marker without present field', () => {
  const eligible = buildEligiblePlayerIdsFromMatchdayAttendance([
    { playerId: 'p1', session_type: 'PLATEAU' },
  ])

  assert.ok(eligible)
  assert.equal(eligible!.has('p1'), true)
})
