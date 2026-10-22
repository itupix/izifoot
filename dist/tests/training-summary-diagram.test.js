"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const training_summary_diagram_1 = require("../training-summary-diagram");
const training_summary_1 = require("../training-summary");
const player = { type: 'player', id: 'p', x: 100, y: 80, label: 'J1', side: 'away' };
(0, node_test_1.default)('keeps only frame zero and supports legacy data', () => {
    const result = (0, training_summary_diagram_1.parseSummaryDiagram)(JSON.stringify({ orientation: 'portrait', rotationQuarterTurns: 3, frames: [{ name: 'Départ', items: [player] }, { items: [] }, { name: 'Arrivée', items: [player] }] }));
    strict_1.default.equal(result.width, 380);
    strict_1.default.equal(result.height, 600);
    strict_1.default.deepEqual(result.frames.map(frame => frame.step), [1]);
    strict_1.default.equal(result.frames[0].items[0].color, 'red');
    strict_1.default.equal(result.frames[0].items[0].x, 100); // Coordinates are already rotated.
    strict_1.default.equal((0, training_summary_diagram_1.parseSummaryDiagram)({ items: [player] }).frames[0].step, null);
    strict_1.default.deepEqual((0, training_summary_diagram_1.parseSummaryDiagram)({ frames: [{ items: [] }, { items: [player] }] }).frames, []);
    strict_1.default.deepEqual((0, training_summary_diagram_1.parseSummaryDiagram)({ frames: [null, { items: [player] }] }).frames, []);
    strict_1.default.equal((0, training_summary_diagram_1.parseSummaryDiagram)({ frames: [{ items: [player] }, null] }).invalid, false);
    strict_1.default.equal((0, training_summary_diagram_1.parseSummaryDiagram)('{broken').invalid, true);
    strict_1.default.equal((0, training_summary_diagram_1.parseSummaryDiagram)({ frames: [{ items: [] }] }).invalid, false);
    strict_1.default.equal((0, training_summary_diagram_1.parseSummaryDiagram)({ items: [{ type: 'ball', x: 'NaN', y: 1 }] }).invalid, true);
});
(0, node_test_1.default)('loads scoped diagrams once, prefers latest session diagram and falls back only when absent', async () => {
    const diagram = { items: [player] };
    const result = await (0, training_summary_1.loadTrainingSummary)({}, { clubId: 'club', teamId: 'wrong-team' }, { id: 'training', teamId: 'team', clubId: 'club' }, {
        attendance: async () => [],
        drills: async () => [{ id: 'td1', drillId: 'd1' }, { id: 'td2', drillId: 'd2' }, { id: 'td3', drillId: 'd3' }, { id: 'td4', drillId: 'd4' }],
        catalog: async () => ['d1', 'd2', 'd3', 'd4'].map(id => ({ id, title: id, description: id })),
        diagrams: async (_db, scope, args) => {
            strict_1.default.equal(scope.teamId, 'team');
            strict_1.default.equal(scope.clubId, 'club');
            strict_1.default.deepEqual(args.orderBy, [{ updatedAt: 'desc' }, { id: 'asc' }]);
            strict_1.default.deepEqual(args.where.OR[0], { trainingDrillId: { in: ['td1', 'td2', 'td3', 'td4'] } });
            strict_1.default.equal(args.where.OR[1].trainingDrillId, null);
            return [
                { trainingDrillId: 'td1', data: JSON.stringify(diagram) },
                { trainingDrillId: 'td1', data: '{broken older' },
                { drillId: 'd1', data: '{broken catalogue' },
                { drillId: 'd2', data: JSON.stringify(diagram) },
                { trainingDrillId: 'td3', data: '{broken latest' },
                { drillId: 'd3', data: JSON.stringify(diagram) },
            ];
        },
    });
    strict_1.default.equal(result.drills[0].diagramSource, 'session');
    strict_1.default.equal(result.drills[0].diagram.invalid, false);
    strict_1.default.equal(result.drills[1].diagramSource, 'catalog');
    strict_1.default.equal(result.drills[2].diagram.invalid, true);
    strict_1.default.equal(result.drills[3].diagram, null);
});
(0, node_test_1.default)('renders only the first diagram frame without corrupt diagram failure', async () => {
    const data = (0, training_summary_diagram_1.parseSummaryDiagram)({ frames: Array.from({ length: 10 }, (_, index) => ({ name: `Position ${index + 1}`, items: [player, { type: 'arrow', from: { x: 20, y: 20 }, to: { x: 200, y: 100 } }] })) });
    const pdf = await (0, training_summary_1.renderTrainingSummary)({ date: '2026-10-21T16:00:00Z', players: [], drills: [{ title: 'Passes', description: 'À deux.', diagram: data }, { title: 'Invalide', description: '', diagram: (0, training_summary_diagram_1.parseSummaryDiagram)('no json') }] }, 'Europe/Paris');
    strict_1.default.equal(pdf.subarray(0, 5).toString(), '%PDF-');
    const pages = pdf.toString('latin1').match(/\/Type \/Page\b/g) || [];
    strict_1.default.equal(data.frames.length, 1);
    strict_1.default.equal(data.frames[0].name, 'Position 1');
    strict_1.default.equal(pages.length, 1);
});
