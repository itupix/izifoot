"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const training_summary_1 = require("../training-summary");
const training = { id: 'training', teamId: 'team', clubId: 'club', date: '2026-10-22T16:00:00.000Z', updatedAt: '2026-10-22T12:00:00.000Z', status: 'PLANNED', observations: '', endTime: '19:30' };
const player = { playerId: 'player', player: { name: 'Éloïse', teamId: 'team' } };
const row = { id: 'row', drillId: 'drill', order: 0, notes: 'Notes' };
const drill = { id: 'drill', title: 'Passes', description: '<p>À deux.</p>' };
const diagram = { id: 'diagram', trainingDrillId: 'row', updatedAt: '2026-10-22T12:00:00.000Z', data: JSON.stringify({ items: [{ type: 'ball', x: 100, y: 100 }] }) };
async function version(patch = {}) {
    const summary = await (0, training_summary_1.loadTrainingSummary)({}, { clubId: 'club' }, patch.training ?? training, {
        attendance: async () => patch.attendance ?? [player],
        drills: async () => patch.rows ?? [row],
        catalog: async () => patch.catalog ?? [drill],
        diagrams: async () => patch.diagrams ?? [diagram],
    });
    return (0, training_summary_1.trainingSummaryVersion)(summary, 'Europe/Paris');
}
(0, node_test_1.default)('fingerprint changes for every PDF dependency without relying on Training.updatedAt', async () => {
    const original = await version();
    const changes = [
        { training: { ...training, date: '2026-10-23T16:00:00Z' } },
        { training: { ...training, endTime: '20:00' } },
        { training: { ...training, status: 'CANCELLED' } },
        { training: { ...training, observations: 'Progression' } },
        { training: { ...training, updatedAt: '2026-10-23T12:00:00Z' } },
        { attendance: [] },
        { attendance: [{ ...player, player: { ...player.player, name: 'Autre prénom' } }] },
        { rows: [] },
        { rows: [{ ...row, notes: 'Notes modifiées' }] },
        { rows: [{ ...row, order: 1 }] },
        { catalog: [{ ...drill, title: 'Tirs' }] },
        { catalog: [{ ...drill, description: 'Nouvelles consignes' }] },
        { diagrams: [] },
        { diagrams: [{ ...diagram, data: JSON.stringify({ items: [{ type: 'ball', x: 200, y: 100 }] }) }] },
        { diagrams: [{ ...diagram, trainingDrillId: null, drillId: 'drill' }] },
    ];
    for (const change of changes)
        strict_1.default.notEqual(await version(change), original, JSON.stringify(change));
    strict_1.default.equal(await version(), original);
});
(0, node_test_1.default)('unrelated catalogue entries and unselected diagrams do not invalidate cached PDFs', async () => {
    strict_1.default.equal(await version({ catalog: [drill, { id: 'unrelated', title: 'Autre', description: 'Autre' }] }), await version());
    strict_1.default.equal(await version({ diagrams: [diagram, { ...diagram, id: 'older', data: '{}' }] }), await version());
    strict_1.default.equal(await version({ training: { ...training, arbitraryUnrenderedField: Date.now() } }), await version());
});
(0, node_test_1.default)('fingerprint is canonical, uses timezone and has no generation-time dependency', () => {
    const base = { ...training, players: ['Éloïse'], drills: [], versionDependencies: [{ notes: 'Notes', order: 0 }] };
    const hash = (0, training_summary_1.trainingSummaryVersion)(base, 'Europe/Paris');
    strict_1.default.match(hash, /^[a-f0-9]{64}$/);
    strict_1.default.equal((0, training_summary_1.trainingSummaryVersion)({ ...base, versionDependencies: [{ order: 0, notes: 'Notes' }] }, 'Europe/Paris'), hash);
    strict_1.default.notEqual((0, training_summary_1.trainingSummaryVersion)(base, 'UTC'), hash);
    strict_1.default.equal((0, training_summary_1.summaryTimeZone)('US/Eastern'), (0, training_summary_1.summaryTimeZone)('America/New_York'));
    strict_1.default.equal((0, training_summary_1.trainingSummaryVersion)(base, 'US/Eastern'), (0, training_summary_1.trainingSummaryVersion)(base, 'America/New_York'));
});
