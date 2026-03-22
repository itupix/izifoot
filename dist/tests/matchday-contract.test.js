"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const matchday_contract_1 = require("../matchday-contract");
(0, node_test_1.default)('deriveMatchdayMode returns ROTATION when planning indicates rotation', () => {
    strict_1.default.equal((0, matchday_contract_1.deriveMatchdayMode)({ hasPersistedRotationKey: false, hasPlanningRotation: true }), 'ROTATION');
});
(0, node_test_1.default)('ensureRotationGameKeysForContract preserves legacy/schedule and fills missing', () => {
    const rows = (0, matchday_contract_1.ensureRotationGameKeysForContract)([
        { id: 'm1', rotationGameKey: 'legacy:0' },
        { id: 'm2', rotationGameKey: null },
        { id: 'm3', rotationGameKey: 'schedule:2' },
        { id: 'm4' },
    ], true);
    strict_1.default.equal(rows[0].rotationGameKey, 'legacy:0');
    strict_1.default.equal(rows[2].rotationGameKey, 'schedule:2');
    strict_1.default.ok(rows[1].rotationGameKey && rows[1].rotationGameKey.length > 0);
    strict_1.default.ok(rows[3].rotationGameKey && rows[3].rotationGameKey.length > 0);
});
(0, node_test_1.default)('normalizeRotationForContract enforces teams color/absent and keeps slots', () => {
    const rotation = (0, matchday_contract_1.normalizeRotationForContract)({
        updatedAt: '2026-03-22T10:00:00.000Z',
        teams: [{ label: 'Club A' }, { label: 'Club B', color: '#111111', absent: 1 }],
        slots: [{ time: '10:00', games: [{ pitch: 1, A: 'Club A', B: 'Club B' }] }],
    }, '2026-03-22T09:00:00.000Z');
    strict_1.default.ok(rotation);
    strict_1.default.equal(rotation.teams.length, 2);
    strict_1.default.equal(rotation.teams[0].label, 'Club A');
    strict_1.default.ok(rotation.teams[0].color.length > 0);
    strict_1.default.equal(rotation.teams[0].absent, false);
    strict_1.default.equal(rotation.teams[1].color, '#111111');
    strict_1.default.equal(rotation.teams[1].absent, true);
    strict_1.default.equal(rotation.slots[0].games[0].A, 'Club A');
});
