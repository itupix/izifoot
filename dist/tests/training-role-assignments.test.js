"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const training_role_assignments_1 = require("../training-role-assignments");
(0, node_test_1.default)('PUT body schema accepts valid role assignments', () => {
    const parsed = training_role_assignments_1.trainingRolesPutBodySchema.safeParse({
        items: [
            { role: 'Capitaine', playerId: 'p1' },
            { role: 'Arbitre', playerId: 'p2' },
        ],
    });
    strict_1.default.equal(parsed.success, true);
});
(0, node_test_1.default)('PUT body schema rejects empty role and empty playerId', () => {
    const parsed = training_role_assignments_1.trainingRolesPutBodySchema.safeParse({
        items: [{ role: '   ', playerId: '' }],
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('normalizeTrainingRoleItems trims role and playerId', () => {
    const items = (0, training_role_assignments_1.normalizeTrainingRoleItems)([
        { role: '  Gardien de but  ', playerId: '  p9  ' },
    ]);
    strict_1.default.deepEqual(items, [{ role: 'Gardien de but', playerId: 'p9' }]);
});
(0, node_test_1.default)('validateNoDuplicatePlayers accepts duplicated roles', () => {
    strict_1.default.doesNotThrow(() => {
        (0, training_role_assignments_1.validateNoDuplicatePlayers)([
            { role: 'Capitaine', playerId: 'p1' },
            { role: 'Capitaine', playerId: 'p2' },
        ]);
    });
});
(0, node_test_1.default)('validateNoDuplicatePlayers rejects duplicated playerId', () => {
    strict_1.default.throws(() => {
        (0, training_role_assignments_1.validateNoDuplicatePlayers)([
            { role: 'Capitaine', playerId: 'p1' },
            { role: 'Arbitre', playerId: 'p1' },
        ]);
    }, /Duplicate playerId in items/);
});
(0, node_test_1.default)('validateNoDuplicatePlayers accepts unique roles and players', () => {
    strict_1.default.doesNotThrow(() => {
        (0, training_role_assignments_1.validateNoDuplicatePlayers)([
            { role: 'Capitaine', playerId: 'p1' },
            { role: 'Arbitre', playerId: 'p2' },
            { role: 'Rangement matériel', playerId: 'p3' },
        ]);
    });
});
