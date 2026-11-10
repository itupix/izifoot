"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const team_attendance_report_1 = require("../team-attendance-report");
const season = { id: 's', key: '2026-2027', label: '2026-2027', startDate: '2026-08-01', endDate: '2027-07-31' };
const player = (id, extra = {}) => ({ id, name: id, is_active: true, createdAt: '2026-01-01', ...extra });
const training = (id, date = '2026-09-02T12:00:00Z', status = 'PLANNED') => ({ id, date, status });
const row = (session_id, playerId, session_type = 'TRAINING') => ({ session_id, playerId, session_type });
const report = (extra = {}) => (0, team_attendance_report_1.buildTeamAttendanceReport)({ teamId: 't', season, now: new Date('2026-11-01T00:00:00Z'), trainings: [], players: [], attendance: [], ...extra });
(0, node_test_1.default)('weighted rates distinguish missing attendance from absence, and ignore intent', () => {
    const result = report({ trainings: [training('a'), training('b')], players: [player('p'), player('q')], attendance: [row('a', 'p'), row('b', 'p'), row('a', 'q', 'TRAINING_ABSENT'), row('b', 'q', 'TRAINING_INTENT')] });
    strict_1.default.deepEqual(result.summary, { presentCount: 2, absentCount: 1, unrecordedCount: 1, recordedCount: 3, attendanceRate: 66.7 });
    strict_1.default.equal(result.players[1].attendances[1].status, 'UNRECORDED');
    strict_1.default.equal(result.players[1].summary.attendanceRate, 0);
});
(0, node_test_1.default)('cancelled/future recordings excluded and never create a denominator', () => {
    const result = report({ trainings: [training('a', undefined, 'CANCELLED'), training('b', '2026-12-01')], players: [player('p')], attendance: [row('a', 'p'), row('b', 'p')] });
    strict_1.default.deepEqual(result.players[0].attendances.map(a => a.status), ['CANCELLED', 'UPCOMING']);
    strict_1.default.equal(result.summary.attendanceRate, null);
    strict_1.default.equal(result.summary.recordedCount, 0);
    strict_1.default.equal(result.summary.unrecordedCount, 0);
});
(0, node_test_1.default)('historical recordings override creation eligibility for active roster', () => {
    const result = report({ trainings: [training('a'), training('b', '2026-10-01')], players: [player('p', { createdAt: '2026-10-02' }), player('q', { deactivated_at: '2026-09-03' })], attendance: [row('a', 'p'), row('b', 'q', 'TRAINING_ABSENT')] });
    strict_1.default.deepEqual(result.players[0].attendances.map(a => a.status), ['PRESENT', 'NOT_APPLICABLE']);
    strict_1.default.deepEqual(result.players[1].attendances.map(a => a.status), ['UNRECORDED', 'ABSENT']);
    strict_1.default.equal(result.players[0].is_active, true);
});
(0, node_test_1.default)('months use Paris boundaries, trainings sort chronologically, empty reports have null rates', () => {
    const result = report({ trainings: [training('b', '2026-09-30T22:30:00Z'), training('a', '2026-09-01T00:00:00Z')], players: [player('p')], attendance: [row('b', 'p')] });
    strict_1.default.deepEqual(result.months.map(m => m.month), ['2026-09', '2026-10']);
    strict_1.default.deepEqual(result.trainings.map(t => t.id), ['a', 'b']);
    strict_1.default.equal(result.months[0].summary.attendanceRate, null);
    strict_1.default.equal(result.months[1].summary.attendanceRate, 100);
    strict_1.default.equal(report().summary.attendanceRate, null);
});
(0, node_test_1.default)('contradictory legacy records conservatively count absent independent of row order', () => {
    for (const attendance of [[row('a', 'p'), row('a', 'p', 'TRAINING_ABSENT')], [row('a', 'p', 'TRAINING_ABSENT'), row('a', 'p')]]) {
        strict_1.default.equal(report({ trainings: [training('a')], players: [player('p')], attendance }).summary.attendanceRate, 0);
    }
});
(0, node_test_1.default)('scope forbids roles, missing teams, other clubs and unmanaged teams', () => {
    const team = { id: 't', clubId: 'c' };
    strict_1.default.equal((0, team_attendance_report_1.canReadTeamAttendance)({ role: 'DIRECTION', clubId: 'c' }, team), true);
    strict_1.default.equal((0, team_attendance_report_1.canReadTeamAttendance)({ role: 'COACH', clubId: 'c', managedTeamIds: ['t'] }, team), true);
    for (const auth of [{ role: 'PLAYER', clubId: 'c' }, { role: 'PARENT', clubId: 'c' }, { role: 'COACH', clubId: 'c', managedTeamIds: ['other'] }, { role: 'DIRECTION', clubId: 'other' }, { role: 'DIRECTION' }])
        strict_1.default.equal((0, team_attendance_report_1.canReadTeamAttendance)(auth, team), false);
    strict_1.default.equal((0, team_attendance_report_1.canReadTeamAttendance)({ role: 'DIRECTION', clubId: 'c' }, null), false);
});
(0, node_test_1.default)('inactive and unknown-status players and their observations never affect current roster totals', () => {
    const result = report({ trainings: [training('a'), training('b')], players: [player('active'), player('inactive', { is_active: false }), player('legacy', { is_active: undefined })], attendance: [row('a', 'active'), row('a', 'inactive', 'TRAINING_ABSENT'), row('b', 'inactive', 'TRAINING_ABSENT'), row('a', 'legacy', 'TRAINING_ABSENT')] });
    strict_1.default.deepEqual(result.players.map(p => p.id), ['active']);
    strict_1.default.deepEqual(result.summary, { presentCount: 1, absentCount: 0, unrecordedCount: 1, recordedCount: 1, attendanceRate: 100 });
    strict_1.default.deepEqual(result.months[0].summary, result.summary);
    const empty = report({ trainings: [training('a')], players: [player('inactive', { is_active: false })], attendance: [row('a', 'inactive')] });
    strict_1.default.deepEqual(empty.players, []);
    strict_1.default.equal(empty.summary.recordedCount, 0);
    strict_1.default.equal(empty.summary.attendanceRate, null);
    strict_1.default.equal(empty.months[0].summary.attendanceRate, null);
});
(0, node_test_1.default)('server resolves current season from Paris club calendar without catalogue or past fallback', async () => {
    const now = new Date('2026-07-31T22:30:00Z'); // August 1 in Paris
    let requestedKey = '';
    const db = { club: { findUnique: async () => ({ id: 'c' }) }, season: { findUnique: async (args) => { requestedKey = args.where.clubId_key.key; return season; } } };
    strict_1.default.deepEqual(await (0, team_attendance_report_1.resolveCurrentAttendanceSeason)(db, 'c', now), { season });
    strict_1.default.equal(requestedKey, '2026-2027');
    strict_1.default.deepEqual(await (0, team_attendance_report_1.resolveCurrentAttendanceSeason)(db, 'c', now, 'past'), { status: 400, error: 'Only the current season is available' });
    strict_1.default.deepEqual(await (0, team_attendance_report_1.resolveCurrentAttendanceSeason)(db, 'c', now, 's'), { season });
});
(0, node_test_1.default)('current season resolver creates missing current season and reports missing club explicitly', async () => {
    let created;
    const db = { club: { findUnique: async () => ({ id: 'c' }) }, season: { findUnique: async () => null, create: async (args) => { created = args.data; return { id: 'new', ...args.data }; } } };
    const result = await (0, team_attendance_report_1.resolveCurrentAttendanceSeason)(db, 'c', new Date('2026-11-10T12:00:00Z'));
    strict_1.default.equal(result.season?.id, 'new');
    strict_1.default.equal(created.key, '2026-2027');
    strict_1.default.deepEqual(await (0, team_attendance_report_1.resolveCurrentAttendanceSeason)({ club: { findUnique: async () => null } }, 'missing', new Date()), { status: 404, error: 'Club not found' });
});
