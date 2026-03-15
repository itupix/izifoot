"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_tactic_1 = require("../match-tactic");
(0, node_test_1.default)('matchTacticSchema accepts valid tactic payload', () => {
    const parsed = match_tactic_1.matchTacticSchema.safeParse({
        preset: 'formation:2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 33, y: 72 },
            p2: { x: 67, y: 72 },
            p3: { x: 50, y: 53 },
            p4: { x: 50, y: 32 },
        },
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('matchTacticSchema rejects empty preset', () => {
    const parsed = match_tactic_1.matchTacticSchema.safeParse({
        preset: '   ',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 33, y: 72 },
            p2: { x: 67, y: 72 },
            p3: { x: 50, y: 53 },
            p4: { x: 50, y: 32 },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('matchTacticSchema rejects invalid point tokens', () => {
    const parsed = match_tactic_1.matchTacticSchema.safeParse({
        preset: 'formation:2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 33, y: 72 },
            p2: { x: 67, y: 72 },
            p3: { x: 50, y: 53 },
            p4: { x: 50, y: 32 },
            foo: { x: 10, y: 10 },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('matchTacticSchema rejects out-of-bounds coordinates', () => {
    const parsed = match_tactic_1.matchTacticSchema.safeParse({
        preset: 'formation:2-1-1',
        points: {
            gk: { x: 120, y: 90 },
            p1: { x: 33, y: 72 },
            p2: { x: 67, y: 72 },
            p3: { x: 50, y: 53 },
            p4: { x: 50, y: 32 },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('validateMatchTacticForPlayersOnField rejects points beyond format size', () => {
    const parsed = match_tactic_1.matchTacticSchema.safeParse({
        preset: 'formation:2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 33, y: 72 },
            p2: { x: 67, y: 72 },
            p3: { x: 50, y: 53 },
            p4: { x: 50, y: 32 },
            p5: { x: 42, y: 20 },
        },
    });
    strict_1.default.equal(parsed.success, true);
    if (!parsed.success)
        return;
    const validation = (0, match_tactic_1.validateMatchTacticForPlayersOnField)(parsed.data, 5);
    strict_1.default.equal(validation.ok, false);
});
