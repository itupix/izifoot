"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchTacticSchema = exports.matchTacticPointsSchema = void 0;
const zod_1 = require("zod");
const matchTacticPointSchema = zod_1.z.object({
    x: zod_1.z.number().min(0).max(100),
    y: zod_1.z.number().min(0).max(100),
}).strict();
exports.matchTacticPointsSchema = zod_1.z.object({
    gk: matchTacticPointSchema,
    p1: matchTacticPointSchema,
    p2: matchTacticPointSchema,
    p3: matchTacticPointSchema,
    p4: matchTacticPointSchema,
}).strict();
exports.matchTacticSchema = zod_1.z.object({
    preset: zod_1.z.string().trim().min(1),
    points: exports.matchTacticPointsSchema,
}).strict();
