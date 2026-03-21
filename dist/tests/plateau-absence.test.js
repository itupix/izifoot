"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const plateau_absence_1 = require("../plateau-absence");
(0, node_test_1.default)('propagation absent=true impacts N matches by rotation keys', () => {
    const rotation = (0, plateau_absence_1.ensureRotationGameKeys)({
        teams: [{ label: 'Team A' }, { label: 'Team B' }, { label: 'Team C' }],
        slots: [
            { games: [{ A: 'Team A', B: 'Team B' }, { A: 'Team C', B: 'Team B' }] },
            { games: [{ A: 'Team A', B: 'Team C' }] },
        ],
    });
    const keys = (0, plateau_absence_1.findRotationGameKeysForTeam)(rotation, 'Team B');
    strict_1.default.equal(keys.length, 2);
    const patches = (0, plateau_absence_1.buildAbsenceMatchPatches)({
        absent: true,
        matches: [
            { id: 'm1', status: 'PLANNED', played: false },
            { id: 'm2', status: 'PLAYED', played: true },
        ],
    });
    strict_1.default.equal(patches.length, 2);
    strict_1.default.deepEqual(patches.map((p) => p.status), ['CANCELLED', 'CANCELLED']);
    strict_1.default.deepEqual(patches.map((p) => p.played), [false, false]);
});
(0, node_test_1.default)('idempotence: absent=true repeated creates no additional patch on already cancelled matches', () => {
    const patches = (0, plateau_absence_1.buildAbsenceMatchPatches)({
        absent: true,
        matches: [{ id: 'm1', status: 'CANCELLED', played: false }],
    });
    strict_1.default.equal(patches.length, 0);
});
(0, node_test_1.default)('absent=false restores PLANNED but keeps PLAYED as PLAYED', () => {
    const patches = (0, plateau_absence_1.buildAbsenceMatchPatches)({
        absent: false,
        matches: [
            { id: 'm1', status: 'CANCELLED', played: false },
            { id: 'm2', status: 'PLAYED', played: true },
        ],
    });
    strict_1.default.equal(patches.length, 1);
    strict_1.default.equal(patches[0].id, 'm1');
    strict_1.default.equal(patches[0].status, 'PLANNED');
    strict_1.default.equal(patches[0].played, false);
});
(0, node_test_1.default)('absence diff reports only changed teams', () => {
    const changes = (0, plateau_absence_1.diffTeamAbsence)([
        { label: 'A', absent: false },
        { label: 'B', absent: false },
    ], [
        { label: 'A', absent: true },
        { label: 'B', absent: false },
    ]);
    strict_1.default.equal(changes.length, 1);
    strict_1.default.equal(changes[0].teamLabel, 'A');
    strict_1.default.equal(changes[0].absent, true);
});
