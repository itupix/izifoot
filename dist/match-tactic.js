"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchTacticSchema = exports.matchTacticPointsSchema = void 0;
exports.validateMatchTacticForPlayersOnField = validateMatchTacticForPlayersOnField;
const zod_1 = require("zod");
const matchTacticPointSchema = zod_1.z.object({
    x: zod_1.z.number().min(0).max(100),
    y: zod_1.z.number().min(0).max(100),
}).strict();
exports.matchTacticPointsSchema = zod_1.z.record(matchTacticPointSchema).superRefine((points, ctx) => {
    if (!Object.prototype.hasOwnProperty.call(points, 'gk')) {
        ctx.addIssue({
            code: zod_1.z.ZodIssueCode.custom,
            path: ['gk'],
            message: 'tactic.points.gk is required',
        });
    }
    for (const key of Object.keys(points)) {
        if (key === 'gk')
            continue;
        if (!/^p[1-9]\d*$/.test(key)) {
            ctx.addIssue({
                code: zod_1.z.ZodIssueCode.custom,
                path: [key],
                message: 'Invalid tactic point key. Allowed keys: gk, p1..pN',
            });
        }
    }
});
exports.matchTacticSchema = zod_1.z.object({
    preset: zod_1.z.string().trim().min(1),
    points: exports.matchTacticPointsSchema,
}).strict();
function validateMatchTacticForPlayersOnField(tactic, playersOnField) {
    const maxOutfieldSlots = Math.max(0, playersOnField - 1);
    for (const key of Object.keys(tactic.points)) {
        if (key === 'gk')
            continue;
        const parsedIndex = Number(key.slice(1));
        if (!Number.isFinite(parsedIndex) || parsedIndex < 1 || parsedIndex > maxOutfieldSlots) {
            return {
                ok: false,
                error: `Invalid tactic point key "${key}" for format size ${playersOnField}. Allowed keys: gk and p1..p${maxOutfieldSlots}`,
            };
        }
    }
    return { ok: true };
}
