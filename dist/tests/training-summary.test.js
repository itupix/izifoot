"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const training_summary_1 = require("../training-summary");
(0, node_test_1.default)('validates timezone without accepting arrays or invalid zones', () => {
    strict_1.default.equal((0, training_summary_1.summaryTimeZone)(undefined), 'Europe/Paris');
    strict_1.default.equal((0, training_summary_1.summaryTimeZone)('Europe/Paris'), 'Europe/Paris');
    for (const value of ['', 'Invalid/Zone', ['Europe/Paris']])
        strict_1.default.throws(() => (0, training_summary_1.summaryTimeZone)(value));
});
(0, node_test_1.default)('preserves paragraphs, lists and entities without script text', () => {
    strict_1.default.equal((0, training_summary_1.descriptionText)('<p>Passes &amp; contrôle</p><ul><li>À deux</li><li>Tirer</li></ul><script>alert(1)</script>'), 'Passes & contrôle\n\n- À deux\n- Tirer');
});
(0, node_test_1.default)('uses actual attendance, deduplicates players, preserves drill ordering and missing items', async () => {
    const training = { id: 't1', teamId: 'team1', clubId: 'club1' };
    const result = await (0, training_summary_1.loadTrainingSummary)({}, { id: 'u1' }, training, {
        attendance: async (_db, scope, args) => {
            strict_1.default.equal(scope.teamId, 'team1');
            strict_1.default.equal(args.where.session_type, 'TRAINING');
            strict_1.default.equal(args.where.session_id, 't1');
            return [{ playerId: 'a', player: { name: 'Zoé', teamId: 'team1' } }, { playerId: 'b', player: { name: 'Ana', teamId: 'team1' } }, { playerId: 'a', player: { name: 'Zoé', teamId: 'team1' } }, { playerId: 'c', player: { name: 'Autre', teamId: 'team2' } }];
        },
        drills: async () => [{ drillId: 'd2' }, { drillId: 'missing' }, { drillId: 'd1' }],
        catalog: async () => [{ id: 'd1', title: 'Premier catalogue', description: 'Un' }, { id: 'd2', title: 'Premier séance', description: '<p>Deux</p>' }],
    });
    strict_1.default.deepEqual(result.players, ['Ana', 'Zoé']);
    strict_1.default.deepEqual(result.drills.map((drill) => drill.title), ['Premier séance', 'Exercice indisponible', 'Premier catalogue']);
});
(0, node_test_1.default)('renders multipage PDFs and empty sections', async () => {
    const base = { date: '2026-10-20T16:00:00.000Z', endTime: null, status: 'CANCELLED', players: [], drills: [] };
    const empty = await (0, training_summary_1.renderTrainingSummary)(base, 'Europe/Paris');
    strict_1.default.equal(empty.subarray(0, 5).toString(), '%PDF-');
    const long = await (0, training_summary_1.renderTrainingSummary)({ ...base, players: ['Éloïse Łukasz'], drills: [{ title: 'Contrôle', description: 'Une consigne détaillée. '.repeat(2000) }] }, 'Europe/Paris');
    strict_1.default.ok(long.length > empty.length);
});
