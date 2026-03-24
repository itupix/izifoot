"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.trainingAttendancePutBodySchema = void 0;
exports.attendanceStoredSessionType = attendanceStoredSessionType;
exports.attendanceSessionTypeVariants = attendanceSessionTypeVariants;
exports.normalizeAttendanceRow = normalizeAttendanceRow;
exports.dedupeStringList = dedupeStringList;
exports.buildTrainingAttendanceSnapshot = buildTrainingAttendanceSnapshot;
exports.persistAttendancePresence = persistAttendancePresence;
const zod_1 = require("zod");
exports.trainingAttendancePutBodySchema = zod_1.z.object({
    playerIds: zod_1.z.array(zod_1.z.string().min(1)).default([]),
});
function attendanceStoredSessionType(sessionType, present) {
    return present ? sessionType : `${sessionType}_ABSENT`;
}
function attendanceSessionTypeVariants(sessionType) {
    return [sessionType, `${sessionType}_ABSENT`];
}
function normalizeAttendanceRow(row) {
    if (row.session_type === 'TRAINING_ABSENT') {
        return { ...row, session_type: 'TRAINING', present: false };
    }
    if (row.session_type === 'PLATEAU_ABSENT') {
        return { ...row, session_type: 'PLATEAU', present: false };
    }
    if (row.session_type === 'TRAINING' || row.session_type === 'PLATEAU') {
        return { ...row, present: true };
    }
    return row;
}
function dedupeStringList(values) {
    const seen = new Set();
    const out = [];
    for (const raw of values) {
        const value = raw.trim();
        if (!value || seen.has(value))
            continue;
        seen.add(value);
        out.push(value);
    }
    return out;
}
function buildTrainingAttendanceSnapshot(params) {
    const trainingPlayerIds = dedupeStringList(params.trainingPlayerIds);
    const presentPlayerIds = dedupeStringList(params.presentPlayerIds);
    const allowed = new Set(trainingPlayerIds);
    const invalidPlayerIds = presentPlayerIds.filter((id) => !allowed.has(id));
    const presentSet = new Set(presentPlayerIds);
    const items = trainingPlayerIds.map((playerId) => ({
        session_type: attendanceStoredSessionType('TRAINING', presentSet.has(playerId)),
        session_id: params.trainingId,
        playerId,
    }));
    return { items, invalidPlayerIds };
}
async function persistAttendancePresence(params, io) {
    const storedSessionType = attendanceStoredSessionType(params.session_type, params.present);
    await io.deleteMany({
        session_type: { in: attendanceSessionTypeVariants(params.session_type) },
        session_id: params.session_id,
        playerId: params.playerId,
    });
    return io.create({
        session_type: storedSessionType,
        session_id: params.session_id,
        playerId: params.playerId,
    });
}
