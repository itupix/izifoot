"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_events_1 = require("../match-events");
(0, node_test_1.default)('matchEventCreateSchema accepts valid GOAL_FOR payload', () => {
    const parsed = match_events_1.matchEventCreateSchema.safeParse({
        minute: 12,
        type: 'GOAL_FOR',
        scorerId: 'player_123',
        assistId: 'player_456',
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('matchEventCreateSchema rejects GOAL_FOR without scorerId', () => {
    const parsed = match_events_1.matchEventCreateSchema.safeParse({
        minute: 12,
        type: 'GOAL_FOR',
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('matchEventCreateSchema accepts GOAL_AGAINST payload without player ids', () => {
    const parsed = match_events_1.matchEventCreateSchema.safeParse({
        minute: 18,
        type: 'GOAL_AGAINST',
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('matchEventCreateSchema accepts SUBSTITUTION with one player id', () => {
    const parsed = match_events_1.matchEventCreateSchema.safeParse({
        minute: 21,
        type: 'SUBSTITUTION',
        outPlayerId: 'player_789',
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('matchEventCreateSchema rejects SUBSTITUTION without in/out player', () => {
    const parsed = match_events_1.matchEventCreateSchema.safeParse({
        minute: 21,
        type: 'SUBSTITUTION',
        slotId: 'p2',
    });
    strict_1.default.equal(parsed.success, false);
});
