"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchEventCreateSchema = exports.matchEventSlotSchema = exports.matchEventTypeSchema = void 0;
const zod_1 = require("zod");
exports.matchEventTypeSchema = zod_1.z.enum(['GOAL_FOR', 'GOAL_AGAINST', 'SUBSTITUTION']);
exports.matchEventSlotSchema = zod_1.z.enum(['gk', 'p1', 'p2', 'p3', 'p4']);
exports.matchEventCreateSchema = zod_1.z.object({
    minute: zod_1.z.number().int().min(0),
    type: exports.matchEventTypeSchema,
    scorerId: zod_1.z.string().min(1).optional(),
    assistId: zod_1.z.string().min(1).optional(),
    slotId: exports.matchEventSlotSchema.optional(),
    inPlayerId: zod_1.z.string().min(1).optional(),
    outPlayerId: zod_1.z.string().min(1).optional(),
}).superRefine((value, ctx) => {
    if (value.type === 'GOAL_FOR') {
        if (!value.scorerId) {
            ctx.addIssue({
                code: zod_1.z.ZodIssueCode.custom,
                path: ['scorerId'],
                message: 'scorerId is required for GOAL_FOR',
            });
        }
        return;
    }
    if (value.type === 'SUBSTITUTION') {
        if (!value.inPlayerId && !value.outPlayerId) {
            ctx.addIssue({
                code: zod_1.z.ZodIssueCode.custom,
                path: ['inPlayerId'],
                message: 'SUBSTITUTION requires at least inPlayerId or outPlayerId',
            });
        }
    }
});
