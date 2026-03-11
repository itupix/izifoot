"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.attendanceStoredSessionType = attendanceStoredSessionType;
exports.attendanceSessionTypeVariants = attendanceSessionTypeVariants;
exports.normalizeAttendanceRow = normalizeAttendanceRow;
exports.persistAttendancePresence = persistAttendancePresence;
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
