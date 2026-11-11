"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const team_attendance_pdf_1 = require("../team-attendance-pdf");
const team_attendance_report_1 = require("../team-attendance-report");
const season = { id: 's', key: '2026-2027', label: '2026-2027', startDate: '2026-07-31T22:00:00Z', endDate: '2027-07-31T21:59:59Z' };
const report = (trainings = [], players = []) => (0, team_attendance_report_1.buildTeamAttendanceReport)({ teamId: 't', season, trainings, players, attendance: [], now: new Date('2026-11-11') });
(0, node_test_1.default)('PDF month requires explicit calendar month and checks Paris season boundaries', () => {
    for (const value of [undefined, '', '2026-00', '2026-13', '2026-1', ['2026-10'], '2026-10\n', '0000-10'])
        strict_1.default.equal((0, team_attendance_pdf_1.validAttendanceMonth)(value), false);
    strict_1.default.equal((0, team_attendance_pdf_1.validAttendanceMonth)('2026-10'), true);
    strict_1.default.equal((0, team_attendance_pdf_1.attendanceMonthInSeason)('2026-07', season), false);
    strict_1.default.equal((0, team_attendance_pdf_1.attendanceMonthInSeason)('2026-08', season), true);
    strict_1.default.equal((0, team_attendance_pdf_1.attendanceMonthInSeason)('2027-07', season), true);
    strict_1.default.equal((0, team_attendance_pdf_1.attendanceMonthInSeason)('2027-08', season), false);
});
(0, node_test_1.default)('shared loader forbids role and unmanaged team before loading attendance', async () => {
    strict_1.default.equal((await (0, team_attendance_report_1.loadTeamAttendanceReport)({}, { role: 'PLAYER' }, 't')).status, 403);
    const db = { team: { findFirst: async () => ({ id: 't', clubId: 'c', name: 'Test' }) } };
    strict_1.default.equal((await (0, team_attendance_report_1.loadTeamAttendanceReport)(db, { role: 'COACH', clubId: 'c', managedTeamIds: ['other'] }, 't')).status, 404);
    strict_1.default.equal((await (0, team_attendance_report_1.loadTeamAttendanceReport)(db, { role: 'DIRECTION', clubId: 'other' }, 't')).status, 404);
});
(0, node_test_1.default)('shared loader pins exact club team season active roster for both PDF and JSON', async () => {
    const db = { team: { findFirst: async () => ({ id: 't', clubId: 'c', name: 'Équipe' }) }, club: { findUnique: async () => ({ id: 'c' }) }, season: { findUnique: async () => season }, training: { findMany: async (args) => { strict_1.default.deepEqual(args.where, { teamId: 't', clubId: 'c', seasonId: 's' }); return [{ id: 'a', date: '2026-10-01', status: 'PLANNED' }]; } }, player: { findMany: async (args) => { strict_1.default.deepEqual(args.where, { teamId: 't', clubId: 'c', is_active: true }); return [{ id: 'p', name: 'Zoé', is_active: true }]; } }, attendance: { findMany: async (args) => { strict_1.default.deepEqual(args.where.playerId.in, ['p']); strict_1.default.deepEqual(args.where.session_id.in, ['a']); return [{ session_id: 'a', playerId: 'p', session_type: 'TRAINING' }]; } } };
    const result = await (0, team_attendance_report_1.loadTeamAttendanceReport)(db, { role: 'COACH', clubId: 'c', managedTeamIds: ['t'] }, 't', undefined, new Date('2026-11-11'));
    if (result.status !== undefined)
        strict_1.default.fail(result.error);
    strict_1.default.equal(result.report.summary.attendanceRate, 100);
    strict_1.default.equal(result.team.name, 'Équipe');
});
(0, node_test_1.default)('PDF renders empty state and multiple pages of players and training groups', async () => {
    const empty = await (0, team_attendance_pdf_1.renderMonthlyAttendancePdf)(report(), 'Équipe U13', '2026-10');
    strict_1.default.equal(empty.subarray(0, 5).toString(), '%PDF-');
    const trainings = Array.from({ length: 8 }, (_, i) => ({ id: `t${i}`, date: `2026-10-${String(i + 1).padStart(2, '0')}T15:00:00Z`, status: 'PLANNED' }));
    const players = Array.from({ length: 35 }, (_, i) => ({ id: `p${i}`, name: `Éloïse ${'Nom composé très long '.repeat(4)} ${i}`, is_active: true }));
    const large = await (0, team_attendance_pdf_1.renderMonthlyAttendancePdf)(report(trainings, players), 'Équipe U13', '2026-10');
    strict_1.default.ok(large.length > empty.length);
    strict_1.default.ok((large.toString('latin1').match(/\/Type \/Page\b/g) || []).length >= 8);
    await strict_1.default.rejects((0, team_attendance_pdf_1.renderMonthlyAttendancePdf)(report(), 'Équipe', '2025-01'), /outside/);
});
(0, node_test_1.default)('PDF names and alphabetical order match the UI instead of legacy name fields', () => {
    const result = (0, team_attendance_pdf_1.monthlyAttendancePlayers)(report([], [{ id: 'z', name: 'AAA legacy', first_name: 'Zoé', last_name: 'Martin', is_active: true }, { id: 'a', name: 'ZZZ legacy', first_name: 'André', last_name: 'Dupont', is_active: true }, { id: 'b', name: 'Baptiste', is_active: true }]));
    strict_1.default.deepEqual(result.map(p => p.displayName), ['André Dupont', 'Baptiste', 'Zoé Martin']);
    strict_1.default.deepEqual(result.map(p => p.id), ['a', 'b', 'z']);
});
