import test from 'node:test'
import assert from 'node:assert/strict'
import {
  attendanceSessionTypeVariants,
  attendanceStoredSessionType,
  normalizeAttendanceRow,
  persistAttendancePresence,
} from '../attendance'

test('attendanceStoredSessionType maps true/false explicitly', () => {
  assert.equal(attendanceStoredSessionType('PLATEAU', true), 'PLATEAU')
  assert.equal(attendanceStoredSessionType('PLATEAU', false), 'PLATEAU_ABSENT')
  assert.equal(attendanceStoredSessionType('TRAINING', true), 'TRAINING')
  assert.equal(attendanceStoredSessionType('TRAINING', false), 'TRAINING_ABSENT')
})

test('attendanceSessionTypeVariants includes both present and absent markers', () => {
  assert.deepEqual(attendanceSessionTypeVariants('PLATEAU'), ['PLATEAU', 'PLATEAU_ABSENT'])
  assert.deepEqual(attendanceSessionTypeVariants('TRAINING'), ['TRAINING', 'TRAINING_ABSENT'])
})

test('persistAttendancePresence writes false after true on same player/session', async () => {
  const writes: Array<{ session_type: string, session_id: string, playerId: string }> = []
  let rows: Array<{ session_type: string, session_id: string, playerId: string }> = []

  const io = {
    deleteMany: async (where: any) => {
      const allowed = new Set(where.session_type.in as string[])
      rows = rows.filter((r) => {
        if (r.session_id !== where.session_id) return true
        if (r.playerId !== where.playerId) return true
        return !allowed.has(r.session_type)
      })
      return { count: 1 }
    },
    create: async (data: any) => {
      rows.push(data)
      writes.push(data)
      return data
    }
  }

  await persistAttendancePresence({
    session_type: 'PLATEAU',
    session_id: 's1',
    playerId: 'p1',
    present: true,
  }, io)

  await persistAttendancePresence({
    session_type: 'PLATEAU',
    session_id: 's1',
    playerId: 'p1',
    present: false,
  }, io)

  assert.equal(writes[0].session_type, 'PLATEAU')
  assert.equal(writes[1].session_type, 'PLATEAU_ABSENT')
  assert.deepEqual(rows, [{ session_type: 'PLATEAU_ABSENT', session_id: 's1', playerId: 'p1' }])
})

test('normalizeAttendanceRow returns final boolean state for GET payload', () => {
  const absent = normalizeAttendanceRow({ session_type: 'PLATEAU_ABSENT', playerId: 'p1' })
  const present = normalizeAttendanceRow({ session_type: 'TRAINING', playerId: 'p2' })

  assert.equal(absent.session_type, 'PLATEAU')
  assert.equal(absent.present, false)
  assert.equal(present.session_type, 'TRAINING')
  assert.equal(present.present, true)
})
