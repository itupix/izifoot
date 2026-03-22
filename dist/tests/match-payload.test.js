"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_payload_1 = require("../match-payload");
(0, node_test_1.default)('POST /matches payload accepts tactic when valid', () => {
    const parsed = match_payload_1.matchCreatePayloadSchema.safeParse({
        type: 'ENTRAINEMENT',
        sides: {
            home: { starters: ['h1'], subs: [] },
            away: { starters: ['a1'], subs: [] },
        },
        tactic: {
            preset: 'formation:1-1',
            points: {
                gk: { x: 50, y: 90 },
                p1: { x: 50, y: 60 },
            },
        },
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('POST /matches payload accepts missing tactic', () => {
    const parsed = match_payload_1.matchCreatePayloadSchema.safeParse({
        type: 'PLATEAU',
        matchdayId: 'pl_1',
        sides: {
            home: { starters: ['h1'], subs: [] },
            away: { starters: ['a1'], subs: [] },
        },
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('POST /matches payload rejects invalid tactic', () => {
    const parsed = match_payload_1.matchCreatePayloadSchema.safeParse({
        type: 'ENTRAINEMENT',
        sides: {
            home: { starters: ['h1'], subs: [] },
            away: { starters: ['a1'], subs: [] },
        },
        tactic: {
            preset: '',
            points: {
                bad: { x: '50', y: 90 },
            },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('POST /matches payload rejects played=true when status=CANCELLED', () => {
    const parsed = match_payload_1.matchCreatePayloadSchema.safeParse({
        type: 'PLATEAU',
        status: 'CANCELLED',
        played: true,
        sides: {
            home: { starters: ['h1'], subs: [] },
            away: { starters: ['a1'], subs: [] },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
