"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_update_validation_1 = require("../match-update-validation");
function buildPoint(x, y) {
    return { x, y };
}
(0, node_test_1.default)('3v3 accepts max 3 starters and points gk,p1,p2', () => {
    const result = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat: '3v3',
        sides: {
            home: { starters: ['h1', 'h2', 'h3'], subs: ['h4'] },
            away: { starters: ['a1', 'a2', 'a3'], subs: ['a4'] },
        },
        tactic: {
            preset: 'formation:1-1',
            points: {
                gk: buildPoint(50, 90),
                p1: buildPoint(35, 60),
                p2: buildPoint(65, 60),
            },
        },
    });
    strict_1.default.equal(result.ok, true);
});
(0, node_test_1.default)('8v8 accepts max 8 starters and points gk..p7', () => {
    const result = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat: '8v8',
        sides: {
            home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8'], subs: ['h9'] },
            away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8'], subs: ['a9'] },
        },
        tactic: {
            preset: 'formation:3-3-1',
            points: {
                gk: buildPoint(50, 90),
                p1: buildPoint(15, 70),
                p2: buildPoint(30, 70),
                p3: buildPoint(45, 70),
                p4: buildPoint(60, 70),
                p5: buildPoint(75, 70),
                p6: buildPoint(40, 45),
                p7: buildPoint(60, 45),
            },
        },
    });
    strict_1.default.equal(result.ok, true);
});
(0, node_test_1.default)('11v11 accepts max 11 starters and points gk..p10', () => {
    const result = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat: '11v11',
        sides: {
            home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9', 'h10', 'h11'], subs: ['h12'] },
            away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a10', 'a11'], subs: ['a12'] },
        },
        tactic: {
            preset: 'formation:4-4-2',
            points: {
                gk: buildPoint(50, 90),
                p1: buildPoint(10, 70),
                p2: buildPoint(20, 70),
                p3: buildPoint(35, 70),
                p4: buildPoint(50, 70),
                p5: buildPoint(65, 70),
                p6: buildPoint(80, 70),
                p7: buildPoint(20, 45),
                p8: buildPoint(40, 45),
                p9: buildPoint(60, 45),
                p10: buildPoint(80, 45),
            },
        },
    });
    strict_1.default.equal(result.ok, true);
});
(0, node_test_1.default)('invalid 5v5 payload rejects 6 starters with a clear message', () => {
    const result = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat: '5v5',
        sides: {
            home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'], subs: [] },
            away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5'], subs: [] },
        },
        tactic: {
            preset: 'formation:2-2',
            points: {
                gk: buildPoint(50, 90),
                p1: buildPoint(30, 65),
                p2: buildPoint(70, 65),
                p3: buildPoint(40, 40),
                p4: buildPoint(60, 40),
            },
        },
    });
    strict_1.default.equal(result.ok, false);
    if (result.ok)
        return;
    strict_1.default.match(result.error, /Too many starters for home/);
});
(0, node_test_1.default)('retro-compatibility: missing format falls back to 5v5 and accepts legacy payload', () => {
    const result = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat: null,
        sides: {
            home: { starters: ['h1', 'h2', 'h3', 'h4', 'h5'], subs: ['h6'] },
            away: { starters: ['a1', 'a2', 'a3', 'a4', 'a5'], subs: ['a6'] },
        },
        tactic: {
            preset: 'formation:2-2',
            points: {
                gk: buildPoint(50, 90),
                p1: buildPoint(30, 65),
                p2: buildPoint(70, 65),
                p3: buildPoint(40, 40),
                p4: buildPoint(60, 40),
            },
        },
    });
    strict_1.default.equal(result.ok, true);
    if (!result.ok)
        return;
    strict_1.default.equal(result.format, '5v5');
    strict_1.default.equal(result.usedFallback, true);
});
