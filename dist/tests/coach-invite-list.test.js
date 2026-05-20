"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const coach_invite_list_1 = require("../coach-invite-list");
(0, node_test_1.default)('filterLatestCoachInvites keeps the most recently updated invite for the same email', () => {
    const invites = (0, coach_invite_list_1.filterLatestCoachInvites)([
        {
            id: 'older-created-later-stale',
            email: 'coach@example.com',
            updatedAt: new Date('2026-05-18T08:00:00.000Z'),
            createdAt: new Date('2026-05-19T08:00:00.000Z'),
        },
        {
            id: 'resent-active',
            email: 'coach@example.com',
            updatedAt: new Date('2026-05-19T10:00:00.000Z'),
            createdAt: new Date('2026-05-17T08:00:00.000Z'),
        },
    ], new Set());
    strict_1.default.equal(invites.length, 1);
    strict_1.default.equal(invites[0]?.id, 'resent-active');
});
(0, node_test_1.default)('filterLatestCoachInvites excludes invites when the coach account is already active', () => {
    const invites = (0, coach_invite_list_1.filterLatestCoachInvites)([
        {
            id: 'pending-invite',
            email: 'coach@example.com',
            updatedAt: new Date('2026-05-19T10:00:00.000Z'),
            createdAt: new Date('2026-05-19T09:00:00.000Z'),
        },
    ], new Set(['coach@example.com']));
    strict_1.default.equal(invites.length, 0);
});
