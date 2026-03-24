import { z } from 'zod'

export type AttendanceSessionType = 'TRAINING' | 'PLATEAU'

export type AttendancePresenceParams = {
  session_type: AttendanceSessionType
  session_id: string
  playerId: string
  present: boolean
}

export const trainingAttendancePutBodySchema = z.object({
  playerIds: z.array(z.string().min(1)).default([]),
})

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

export function dedupeStringList(values: string[]) {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of values) {
    const value = raw.trim()
    if (!value || seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

export function buildTrainingAttendanceSnapshot(params: {
  trainingId: string
  trainingPlayerIds: string[]
  presentPlayerIds: string[]
}) {
  const trainingPlayerIds = dedupeStringList(params.trainingPlayerIds)
  const presentPlayerIds = dedupeStringList(params.presentPlayerIds)
  const allowed = new Set(trainingPlayerIds)
  const invalidPlayerIds = presentPlayerIds.filter((id) => !allowed.has(id))
  const presentSet = new Set(presentPlayerIds)

  const items = trainingPlayerIds.map((playerId) => ({
    session_type: attendanceStoredSessionType('TRAINING', presentSet.has(playerId)),
    session_id: params.trainingId,
    playerId,
  }))

  return { items, invalidPlayerIds }
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
