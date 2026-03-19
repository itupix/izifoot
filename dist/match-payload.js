"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchCreatePayloadSchema = exports.matchSidesPayloadSchema = exports.matchScorerPayloadSchema = void 0;
const zod_1 = require("zod");
const match_tactic_1 = require("./match-tactic");
exports.matchScorerPayloadSchema = zod_1.z.object({
    playerId: zod_1.z.string(),
    side: zod_1.z.enum(['home', 'away']),
    assistId: zod_1.z.string().nullable().optional(),
}).superRefine((value, ctx) => {
    if (value.assistId && value.assistId === value.playerId) {
        ctx.addIssue({
            code: zod_1.z.ZodIssueCode.custom,
            path: ['assistId'],
            message: 'assistId must be different from playerId',
        });
    }
});
exports.matchSidesPayloadSchema = zod_1.z.object({
    home: zod_1.z.object({
        starters: zod_1.z.array(zod_1.z.string()).default([]),
        subs: zod_1.z.array(zod_1.z.string()).default([])
    }).default({ starters: [], subs: [] }),
    away: zod_1.z.object({
        starters: zod_1.z.array(zod_1.z.string()).default([]),
        subs: zod_1.z.array(zod_1.z.string()).default([])
    }).default({ starters: [], subs: [] })
});
exports.matchCreatePayloadSchema = zod_1.z.object({
    type: zod_1.z.enum(['ENTRAINEMENT', 'PLATEAU']),
    played: zod_1.z.boolean().optional(),
    plateauId: zod_1.z.string().optional(),
    sides: exports.matchSidesPayloadSchema,
    score: zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) }).optional(),
    buteurs: zod_1.z.array(exports.matchScorerPayloadSchema).optional(),
    opponentName: zod_1.z.string().min(1).max(100).optional(),
    tactic: match_tactic_1.matchTacticSchema.nullable().optional(),
});
