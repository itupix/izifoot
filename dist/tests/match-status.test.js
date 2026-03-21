"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_status_1 = require("../match-status");
(0, node_test_1.default)('compat: played=true resolves to PLAYED when status is absent', () => {
    const status = (0, match_status_1.resolveMatchStatus)({ played: true });
    strict_1.default.equal(status, 'PLAYED');
});
(0, node_test_1.default)('status CANCELLED always normalizes to played=false with empty scorers', () => {
    const normalized = (0, match_status_1.normalizeMatchWriteState)({
        status: 'CANCELLED',
        score: { home: 3, away: 2 },
        buteurs: [{ playerId: 'p1', side: 'home' }],
    });
    strict_1.default.equal(normalized.played, false);
    strict_1.default.deepEqual(normalized.score, { home: 0, away: 0 });
    strict_1.default.deepEqual(normalized.buteurs, []);
});
(0, node_test_1.default)('played-only patch keeps CANCELLED status on legacy payload played=false', () => {
    const status = (0, match_status_1.resolvePatchedMatchStatus)({
        existingStatus: 'CANCELLED',
        payloadPlayed: false,
    });
    strict_1.default.equal(status, 'CANCELLED');
});
(0, node_test_1.default)('stats exclude CANCELLED matches from played count', () => {
    const playedCount = (0, match_status_1.countPlayedMatchesExcludingCancelled)([
        { status: 'PLAYED', played: true },
        { status: 'CANCELLED', played: false },
        { played: true },
        { status: 'PLANNED', played: false },
    ]);
    strict_1.default.equal(playedCount, 2);
});
