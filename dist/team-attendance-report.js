"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.canReadTeamAttendance = canReadTeamAttendance;
exports.buildTeamAttendanceReport = buildTeamAttendanceReport;
exports.resolveCurrentAttendanceSeason = resolveCurrentAttendanceSeason;
const season_1 = require("./season");
const emptyStats = () => ({ presentCount: 0, absentCount: 0, unrecordedCount: 0, recordedCount: 0, attendanceRate: null });
function stats(statuses) {
    const out = emptyStats();
    for (const status of statuses) {
        if (status === 'PRESENT')
            out.presentCount++;
        if (status === 'ABSENT')
            out.absentCount++;
        if (status === 'UNRECORDED')
            out.unrecordedCount++;
    }
    out.recordedCount = out.presentCount + out.absentCount;
    out.attendanceRate = out.recordedCount ? Math.round(out.presentCount / out.recordedCount * 1000) / 10 : null;
    return out;
}
function monthOf(date) {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit' }).formatToParts(date);
    return `${parts.find(p => p.type === 'year').value}-${parts.find(p => p.type === 'month').value}`;
}
function canReadTeamAttendance(auth, team) {
    if (!team || !auth?.clubId || team.clubId !== auth.clubId)
        return false;
    return auth.role === 'DIRECTION' || (auth.role === 'COACH' && Array.isArray(auth.managedTeamIds) && auth.managedTeamIds.includes(team.id));
}
function buildTeamAttendanceReport(input) {
    const now = input.now ?? new Date();
    const trainings = [...input.trainings].sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime() || a.id.localeCompare(b.id)).map(t => ({
        id: t.id, date: new Date(t.date).toISOString(), endTime: t.endTime ?? null, status: t.status,
        month: monthOf(new Date(t.date)), includedInRate: t.status !== 'CANCELLED' && new Date(t.date).getTime() <= now.getTime(),
    }));
    const months = [...new Set(trainings.map(t => t.month))];
    const records = new Map();
    for (const row of input.attendance) {
        if (row.session_type !== 'TRAINING' && row.session_type !== 'TRAINING_ABSENT')
            continue;
        const key = `${row.session_id}:${row.playerId}`;
        if (records.get(key) !== 'ABSENT')
            records.set(key, row.session_type === 'TRAINING' ? 'PRESENT' : 'ABSENT');
    }
    const players = input.players.filter(p => p.is_active === true).sort((a, b) => a.name.localeCompare(b.name, 'fr') || a.id.localeCompare(b.id)).map(p => {
        const attendances = trainings.map(t => {
            let status;
            const recorded = records.get(`${t.id}:${p.id}`);
            const date = new Date(t.date).getTime();
            if (t.status === 'CANCELLED')
                status = 'CANCELLED';
            else if (!t.includedInRate)
                status = 'UPCOMING';
            else if (recorded)
                status = recorded;
            else if ((p.createdAt && date < new Date(p.createdAt).getTime()) || (p.deactivated_at && date > new Date(p.deactivated_at).getTime()))
                status = 'NOT_APPLICABLE';
            else
                status = 'UNRECORDED';
            return { trainingId: t.id, status };
        });
        return { id: p.id, name: p.name, first_name: p.first_name ?? null, last_name: p.last_name ?? null, is_active: p.is_active !== false,
            summary: stats(attendances.map(a => a.status)), months: months.map(month => ({ month, summary: stats(attendances.filter((_, i) => trainings[i].month === month).map(a => a.status)) })), attendances };
    });
    return { teamId: input.teamId, season: { id: input.season.id, key: input.season.key, label: input.season.label, startDate: new Date(input.season.startDate).toISOString(), endDate: new Date(input.season.endDate).toISOString() }, generatedAt: now.toISOString(),
        summary: stats(players.flatMap(p => p.attendances.map(a => a.status))), months: months.map(month => ({ month, summary: stats(players.flatMap(p => p.attendances.filter((_, i) => trainings[i].month === month).map(a => a.status))) })), trainings, players };
}
async function resolveCurrentAttendanceSeason(db, clubId, now, requestedSeasonId) {
    const club = await db.club.findUnique({ where: { id: clubId } });
    if (!club)
        return { status: 404, error: 'Club not found' };
    const season = await (0, season_1.resolveOrCreateSeasonForClubDate)(db, club, now);
    if (!season)
        return { status: 404, error: 'Current season not found' };
    if (requestedSeasonId && requestedSeasonId !== season.id)
        return { status: 400, error: 'Only the current season is available' };
    return { season };
}
