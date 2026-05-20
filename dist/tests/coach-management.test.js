"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const coach_management_1 = require("../coach-management");
(0, node_test_1.default)('normalizeCoachManagedTeamIds keeps primary team first and deduplicates values', () => {
    strict_1.default.deepEqual((0, coach_management_1.normalizeCoachManagedTeamIds)('team-2', ['team-1', 'team-2', 'team-1', '', 'team-3']), ['team-2', 'team-1', 'team-3']);
});
(0, node_test_1.default)('normalizeCoachManagedTeamIds falls back to managed teams when no primary team is set', () => {
    strict_1.default.deepEqual((0, coach_management_1.normalizeCoachManagedTeamIds)(null, ['team-1', 'team-1', 'team-4']), ['team-1', 'team-4']);
});
(0, node_test_1.default)('resolveCoachActiveTeamId keeps the current team when still managed', () => {
    strict_1.default.equal((0, coach_management_1.resolveCoachActiveTeamId)('team-3', ['team-1', 'team-3']), 'team-3');
});
(0, node_test_1.default)('resolveCoachActiveTeamId falls back to the first managed team when current becomes invalid', () => {
    strict_1.default.equal((0, coach_management_1.resolveCoachActiveTeamId)('team-9', ['team-1', 'team-3']), 'team-1');
    strict_1.default.equal((0, coach_management_1.resolveCoachActiveTeamId)(null, []), null);
});
(0, node_test_1.default)('mapCoachManagedTeams resolves labels from the provided lookup', () => {
    const teamNameById = new Map([
        ['team-1', 'U11 A'],
        ['team-2', 'U13'],
    ]);
    strict_1.default.deepEqual((0, coach_management_1.mapCoachManagedTeams)(['team-2', 'team-1', 'team-99'], teamNameById), [
        { id: 'team-2', name: 'U13' },
        { id: 'team-1', name: 'U11 A' },
        { id: 'team-99', name: 'team-99' },
    ]);
});
