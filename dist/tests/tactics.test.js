"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const tactics_1 = require("../tactics");
(0, node_test_1.default)('tacticPayloadSchema accepts valid tactic payload', () => {
    const parsed = tactics_1.tacticPayloadSchema.safeParse({
        teamId: 'team-1',
        name: 'Pressing haut',
        formation: '2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 32, y: 64 },
            p2: { x: 68, y: 64 },
            p3: { x: 50, y: 44 },
            p4: { x: 50, y: 24 },
        },
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('tacticPayloadSchema rejects incomplete points payload', () => {
    const parsed = tactics_1.tacticPayloadSchema.safeParse({
        teamId: 'team-1',
        name: 'Pressing haut',
        formation: '2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 32, y: 64 },
            p2: { x: 68, y: 64 },
            p3: { x: 50, y: 44 },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('tacticPayloadSchema rejects out-of-bounds coordinates', () => {
    const parsed = tactics_1.tacticPayloadSchema.safeParse({
        teamId: 'team-1',
        name: 'Pressing haut',
        formation: '2-1-1',
        points: {
            gk: { x: 5, y: 90 },
            p1: { x: 32, y: 64 },
            p2: { x: 68, y: 64 },
            p3: { x: 50, y: 44 },
            p4: { x: 50, y: 24 },
        },
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('canWriteTacticForTeam only allows DIRECTION/COACH on active team', () => {
    strict_1.default.equal((0, tactics_1.canWriteTacticForTeam)({ role: 'DIRECTION', teamId: 'team-1' }, 'team-1'), true);
    strict_1.default.equal((0, tactics_1.canWriteTacticForTeam)({ role: 'DIRECTION', teamId: 'team-1' }, 'team-2'), false);
    strict_1.default.equal((0, tactics_1.canWriteTacticForTeam)({ role: 'COACH', teamId: 'team-1', managedTeamIds: ['team-1', 'team-3'] }, 'team-1'), true);
    strict_1.default.equal((0, tactics_1.canWriteTacticForTeam)({ role: 'COACH', teamId: 'team-2', managedTeamIds: ['team-1', 'team-3'] }, 'team-1'), false);
    strict_1.default.equal((0, tactics_1.canWriteTacticForTeam)({ role: 'PLAYER', teamId: 'team-1' }, 'team-1'), false);
});
(0, node_test_1.default)('upsertTacticByTeamAndName creates then updates existing tactic (case-insensitive name)', async () => {
    const rows = [];
    const delegate = {
        findFirst: async ({ where }) => {
            const needle = String(where?.name?.equals || '').toLowerCase();
            return rows.find((row) => row.teamId === where.teamId && row.name.toLowerCase() === needle) || null;
        },
        create: async ({ data }) => {
            const now = new Date();
            const row = {
                id: `t_${rows.length + 1}`,
                createdAt: now,
                updatedAt: now,
                ...data,
            };
            rows.push(row);
            return row;
        },
        update: async ({ where, data }) => {
            const idx = rows.findIndex((row) => row.id === where.id);
            if (idx < 0)
                throw new Error('row not found');
            rows[idx] = { ...rows[idx], ...data, updatedAt: new Date() };
            return rows[idx];
        },
    };
    const created = await (0, tactics_1.upsertTacticByTeamAndName)(delegate, {
        teamId: 'team-1',
        name: 'Pressing Haut',
        formation: '2-1-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 32, y: 64 },
            p2: { x: 68, y: 64 },
            p3: { x: 50, y: 44 },
            p4: { x: 50, y: 24 },
        },
    });
    const updated = await (0, tactics_1.upsertTacticByTeamAndName)(delegate, {
        teamId: 'team-1',
        name: 'pressing haut',
        formation: '1-2-1',
        points: {
            gk: { x: 50, y: 90 },
            p1: { x: 28, y: 64 },
            p2: { x: 72, y: 64 },
            p3: { x: 50, y: 44 },
            p4: { x: 50, y: 24 },
        },
    });
    strict_1.default.equal(rows.length, 1);
    strict_1.default.equal(updated.id, created.id);
    strict_1.default.equal(updated.formation, '1-2-1');
    strict_1.default.equal(updated.name, 'pressing haut');
});
(0, node_test_1.default)('sortTacticsByUpdatedAtDesc orders most recent first', () => {
    const rows = (0, tactics_1.sortTacticsByUpdatedAtDesc)([
        { id: 'a', updatedAt: '2026-03-10T10:00:00.000Z' },
        { id: 'b', updatedAt: '2026-03-12T10:00:00.000Z' },
        { id: 'c', updatedAt: '2026-03-11T10:00:00.000Z' },
    ]);
    strict_1.default.deepEqual(rows.map((r) => r.id), ['b', 'c', 'a']);
});
