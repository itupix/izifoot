import { resolveOrCreateSeasonForClubDate } from './season'

export type ReportStatus = 'PRESENT' | 'ABSENT' | 'UNRECORDED' | 'UPCOMING' | 'CANCELLED' | 'NOT_APPLICABLE'
export type ReportStats = { presentCount: number; absentCount: number; unrecordedCount: number; recordedCount: number; attendanceRate: number | null }
const emptyStats = (): ReportStats => ({ presentCount: 0, absentCount: 0, unrecordedCount: 0, recordedCount: 0, attendanceRate: null })
function stats(statuses: ReportStatus[]): ReportStats {
  const out = emptyStats()
  for (const status of statuses) {
    if (status === 'PRESENT') out.presentCount++
    if (status === 'ABSENT') out.absentCount++
    if (status === 'UNRECORDED') out.unrecordedCount++
  }
  out.recordedCount = out.presentCount + out.absentCount
  out.attendanceRate = out.recordedCount ? Math.round(out.presentCount / out.recordedCount * 1000) / 10 : null
  return out
}
function monthOf(date: Date) {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit' }).formatToParts(date)
  return `${parts.find(p => p.type === 'year')!.value}-${parts.find(p => p.type === 'month')!.value}`
}
export function canReadTeamAttendance(auth: any, team: { id: string; clubId: string } | null) {
  if (!team || !auth?.clubId || team.clubId !== auth.clubId) return false
  return auth.role === 'DIRECTION' || (auth.role === 'COACH' && Array.isArray(auth.managedTeamIds) && auth.managedTeamIds.includes(team.id))
}
export function buildTeamAttendanceReport(input: { teamId: string; season: any; trainings: any[]; players: any[]; attendance: any[]; now?: Date }) {
  const now = input.now ?? new Date()
  const trainings = [...input.trainings].sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime() || a.id.localeCompare(b.id)).map(t => ({
    id: t.id, date: new Date(t.date).toISOString(), endTime: t.endTime ?? null, status: t.status,
    month: monthOf(new Date(t.date)), includedInRate: t.status !== 'CANCELLED' && new Date(t.date).getTime() <= now.getTime(),
  }))
  const months = [...new Set(trainings.map(t => t.month))]
  const records = new Map<string, ReportStatus>()
  for (const row of input.attendance) {
    if (row.session_type !== 'TRAINING' && row.session_type !== 'TRAINING_ABSENT') continue
    const key = `${row.session_id}:${row.playerId}`
    if (records.get(key) !== 'ABSENT') records.set(key, row.session_type === 'TRAINING' ? 'PRESENT' : 'ABSENT')
  }
  const players = input.players.filter(p => p.is_active === true).sort((a, b) => a.name.localeCompare(b.name, 'fr') || a.id.localeCompare(b.id)).map(p => {
    const attendances = trainings.map(t => {
      let status: ReportStatus
      const recorded = records.get(`${t.id}:${p.id}`)
      const date = new Date(t.date).getTime()
      if (t.status === 'CANCELLED') status = 'CANCELLED'
      else if (!t.includedInRate) status = 'UPCOMING'
      else if (recorded) status = recorded
      else if ((p.createdAt && date < new Date(p.createdAt).getTime()) || (p.deactivated_at && date > new Date(p.deactivated_at).getTime())) status = 'NOT_APPLICABLE'
      else status = 'UNRECORDED'
      return { trainingId: t.id, status }
    })
    return { id: p.id, name: p.name, first_name: p.first_name ?? null, last_name: p.last_name ?? null, is_active: p.is_active !== false,
      summary: stats(attendances.map(a => a.status)), months: months.map(month => ({ month, summary: stats(attendances.filter((_, i) => trainings[i].month === month).map(a => a.status)) })), attendances }
  })
  return { teamId: input.teamId, season: { id: input.season.id, key: input.season.key, label: input.season.label, startDate: new Date(input.season.startDate).toISOString(), endDate: new Date(input.season.endDate).toISOString() }, generatedAt: now.toISOString(),
    summary: stats(players.flatMap(p => p.attendances.map(a => a.status))), months: months.map(month => ({ month, summary: stats(players.flatMap(p => p.attendances.filter((_, i) => trainings[i].month === month).map(a => a.status))) })), trainings, players }
}

export async function resolveCurrentAttendanceSeason(db: any, clubId: string, now: Date, requestedSeasonId?: string) {
  const club = await db.club.findUnique({ where: { id: clubId } })
  if (!club) return { status: 404, error: 'Club not found' } as const
  const season = await resolveOrCreateSeasonForClubDate(db, club, now)
  if (!season) return { status: 404, error: 'Current season not found' } as const
  if (requestedSeasonId && requestedSeasonId !== season.id) return { status: 400, error: 'Only the current season is available' } as const
  return { season } as const
}

// Shared by JSON and PDF so authorization, roster and rates cannot diverge.
export async function loadTeamAttendanceReport(db: any, auth: any, teamId: string, requestedSeasonId?: string, now = new Date()) {
  if (!['DIRECTION', 'COACH'].includes(auth?.role)) return { status: 403, error: 'Attendance report requires coach or direction access' } as const
  const team = await db.team.findFirst({ where: { id: teamId, clubId: auth.clubId ?? '__no_club__' }, select: { id: true, clubId: true, name: true } })
  if (!canReadTeamAttendance(auth, team)) return { status: 404, error: 'Team not found' } as const
  const resolved = await resolveCurrentAttendanceSeason(db, team.clubId, now, requestedSeasonId)
  if (resolved.status !== undefined) return resolved
  const season = resolved.season
  const [trainings, players] = await Promise.all([
    db.training.findMany({ where: { teamId: team.id, clubId: team.clubId, seasonId: season.id }, select: { id: true, date: true, endTime: true, status: true } }),
    db.player.findMany({ where: { teamId: team.id, clubId: team.clubId, is_active: true }, select: { id: true, name: true, first_name: true, last_name: true, is_active: true, createdAt: true, deactivated_at: true } }),
  ])
  const attendance = trainings.length ? await db.attendance.findMany({ where: { session_id: { in: trainings.map((t: any) => t.id) }, session_type: { in: ['TRAINING', 'TRAINING_ABSENT'] }, playerId: { in: players.map((p: any) => p.id) } }, select: { session_id: true, session_type: true, playerId: true } }) : []
  return { team, report: buildTeamAttendanceReport({ teamId: team.id, season, trainings, players, attendance, now }) } as const
}
