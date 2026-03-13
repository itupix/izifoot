"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tacticPayloadSchema = exports.tacticPointsSchema = exports.tacticFormationSchema = void 0;
exports.canWriteTacticForTeam = canWriteTacticForTeam;
exports.sortTacticsByUpdatedAtDesc = sortTacticsByUpdatedAtDesc;
exports.upsertTacticByTeamAndName = upsertTacticByTeamAndName;
const zod_1 = require("zod");
const TOKEN_IDS = ['gk', 'p1', 'p2', 'p3', 'p4'];
const FORMATIONS = ['2-1-1', '1-2-1', '1-1-2'];
const tacticPointSchema = zod_1.z.object({
    x: zod_1.z.number().min(6).max(94),
    y: zod_1.z.number().min(8).max(92),
}).strict();
exports.tacticFormationSchema = zod_1.z.enum(FORMATIONS);
exports.tacticPointsSchema = zod_1.z.object({
    gk: tacticPointSchema,
    p1: tacticPointSchema,
    p2: tacticPointSchema,
    p3: tacticPointSchema,
    p4: tacticPointSchema,
}).strict();
exports.tacticPayloadSchema = zod_1.z.object({
    teamId: zod_1.z.string().min(1),
    name: zod_1.z.string().trim().min(1).max(50),
    formation: exports.tacticFormationSchema,
    points: exports.tacticPointsSchema,
}).strict();
function getActiveTeamIdForAuth(auth) {
    if (!auth)
        return null;
    if (auth.role === 'COACH') {
        const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : [];
        if (auth.teamId && managedIds.includes(auth.teamId))
            return auth.teamId;
        if (managedIds.length === 1)
            return managedIds[0];
        return null;
    }
    return auth.teamId || null;
}
function canWriteTacticForTeam(auth, teamId) {
    if (!auth)
        return false;
    if (auth.role !== 'COACH' && auth.role !== 'DIRECTION')
        return false;
    const activeTeamId = getActiveTeamIdForAuth(auth);
    return !!activeTeamId && activeTeamId === teamId;
}
function sortTacticsByUpdatedAtDesc(rows) {
    return [...rows].sort((a, b) => {
        const ta = new Date(a.updatedAt).getTime();
        const tb = new Date(b.updatedAt).getTime();
        return tb - ta;
    });
}
async function upsertTacticByTeamAndName(tacticDelegate, payload) {
    const existing = await tacticDelegate.findFirst({
        where: {
            teamId: payload.teamId,
            name: {
                equals: payload.name,
                mode: 'insensitive',
            },
        },
    });
    if (existing) {
        return tacticDelegate.update({
            where: { id: existing.id },
            data: {
                name: payload.name,
                formation: payload.formation,
                points: payload.points,
            },
        });
    }
    return tacticDelegate.create({
        data: {
            teamId: payload.teamId,
            name: payload.name,
            formation: payload.formation,
            points: payload.points,
        },
    });
}
