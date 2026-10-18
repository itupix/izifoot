"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.trainingDrillUpdateSchema = exports.trainingDrillCreateSchema = exports.drillUpdateSchema = exports.drillCreateSchema = exports.drillCategorySchema = exports.DRILL_CATEGORIES = void 0;
const zod_1 = require("zod");
exports.DRILL_CATEGORIES = ['collectif', 'technique', 'jeu', 'autres'];
exports.drillCategorySchema = zod_1.z.enum(exports.DRILL_CATEGORIES);
// Zod strips retired duration/players fields sent by older clients.
exports.drillCreateSchema = zod_1.z.object({
    title: zod_1.z.string().min(1).max(100),
    category: exports.drillCategorySchema,
    description: zod_1.z.string().min(1).max(2000),
    tags: zod_1.z.array(zod_1.z.string().min(1).max(32)).max(20).optional(),
});
exports.drillUpdateSchema = exports.drillCreateSchema.partial();
exports.trainingDrillCreateSchema = zod_1.z.object({
    drillId: zod_1.z.string().min(1),
    notes: zod_1.z.string().max(1000).optional(),
    trainingDrillId: zod_1.z.string().min(1).optional(),
    replaceTrainingDrillId: zod_1.z.string().min(1).optional(),
    id: zod_1.z.string().min(1).optional(),
});
exports.trainingDrillUpdateSchema = zod_1.z.object({
    drillId: zod_1.z.string().min(1).optional(),
    notes: zod_1.z.string().max(1000).nullable().optional(),
    order: zod_1.z.number().int().min(0).optional(),
}).refine(data => Object.values(data).some(value => value !== undefined), {
    message: 'At least one field must be provided',
});
