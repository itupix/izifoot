"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.trainingRolesPutBodySchema = exports.trainingRoleItemInputSchema = void 0;
exports.normalizeTrainingRoleItems = normalizeTrainingRoleItems;
exports.findDuplicateValues = findDuplicateValues;
exports.validateNoDuplicatePlayers = validateNoDuplicatePlayers;
const zod_1 = require("zod");
exports.trainingRoleItemInputSchema = zod_1.z.object({
    role: zod_1.z.string().trim().min(1).max(80),
    playerId: zod_1.z.string().trim().min(1),
});
exports.trainingRolesPutBodySchema = zod_1.z.object({
    items: zod_1.z.array(exports.trainingRoleItemInputSchema),
});
function normalizeTrainingRoleItems(items) {
    return items.map((item) => ({
        role: item.role.trim(),
        playerId: item.playerId.trim(),
    }));
}
function findDuplicateValues(values) {
    const counts = new Map();
    for (const value of values) {
        counts.set(value, (counts.get(value) ?? 0) + 1);
    }
    return Array.from(counts.entries())
        .filter(([, count]) => count > 1)
        .map(([value]) => value);
}
function validateNoDuplicatePlayers(items) {
    const duplicatePlayers = findDuplicateValues(items.map((item) => item.playerId));
    if (duplicatePlayers.length > 0) {
        const err = new Error('Duplicate playerId in items');
        err.code = 'DUPLICATE_PLAYER';
        throw err;
    }
}
