import test from 'node:test'
import assert from 'node:assert/strict'
import { buildEligiblePlayerIdsFromPlateauAttendance } from '../match-eligibility'

test('buildEligiblePlayerIdsFromPlateauAttendance returns null when attendance is empty', () => {
  const eligible = buildEligiblePlayerIdsFromPlateauAttendance([])
  assert.equal(eligible, null)
})

test('buildEligiblePlayerIdsFromPlateauAttendance includes present and convoked players only', () => {
  const eligible = buildEligiblePlayerIdsFromPlateauAttendance([
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

test('buildEligiblePlayerIdsFromPlateauAttendance supports legacy PLATEAU marker without present field', () => {
  const eligible = buildEligiblePlayerIdsFromPlateauAttendance([
    { playerId: 'p1', session_type: 'PLATEAU' },
  ])

  assert.ok(eligible)
  assert.equal(eligible!.has('p1'), true)
})
