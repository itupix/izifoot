export type AttendanceSessionType = 'TRAINING' | 'PLATEAU'

export type AttendancePresenceParams = {
  session_type: AttendanceSessionType
  session_id: string
  playerId: string
  present: boolean
}

export function attendanceStoredSessionType(sessionType: AttendanceSessionType, present: boolean) {
  return present ? sessionType : `${sessionType}_ABSENT`
}

export function attendanceSessionTypeVariants(sessionType: AttendanceSessionType) {
  return [sessionType, `${sessionType}_ABSENT`]
}

export function normalizeAttendanceRow(row: any) {
  if (row.session_type === 'TRAINING_ABSENT') {
    return { ...row, session_type: 'TRAINING', present: false }
  }
  if (row.session_type === 'PLATEAU_ABSENT') {
    return { ...row, session_type: 'PLATEAU', present: false }
  }
  if (row.session_type === 'TRAINING' || row.session_type === 'PLATEAU') {
    return { ...row, present: true }
  }
  return row
}

export async function persistAttendancePresence(
  params: AttendancePresenceParams,
  io: {
    deleteMany: (where: any) => Promise<any>
    create: (data: any) => Promise<any>
  }
) {
  const storedSessionType = attendanceStoredSessionType(params.session_type, params.present)
  await io.deleteMany({
    session_type: { in: attendanceSessionTypeVariants(params.session_type) } as any,
    session_id: params.session_id,
    playerId: params.playerId,
  })
  return io.create({
    session_type: storedSessionType,
    session_id: params.session_id,
    playerId: params.playerId,
  })
}
