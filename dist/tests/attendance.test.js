"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const attendance_1 = require("../attendance");
(0, node_test_1.default)('attendanceStoredSessionType maps true/false explicitly', () => {
    strict_1.default.equal((0, attendance_1.attendanceStoredSessionType)('PLATEAU', true), 'PLATEAU');
    strict_1.default.equal((0, attendance_1.attendanceStoredSessionType)('PLATEAU', false), 'PLATEAU_ABSENT');
    strict_1.default.equal((0, attendance_1.attendanceStoredSessionType)('TRAINING', true), 'TRAINING');
    strict_1.default.equal((0, attendance_1.attendanceStoredSessionType)('TRAINING', false), 'TRAINING_ABSENT');
});
(0, node_test_1.default)('attendanceSessionTypeVariants includes both present and absent markers', () => {
    strict_1.default.deepEqual((0, attendance_1.attendanceSessionTypeVariants)('PLATEAU'), ['PLATEAU', 'PLATEAU_ABSENT']);
    strict_1.default.deepEqual((0, attendance_1.attendanceSessionTypeVariants)('TRAINING'), ['TRAINING', 'TRAINING_ABSENT']);
});
(0, node_test_1.default)('persistAttendancePresence writes false after true on same player/session', async () => {
    const writes = [];
    let rows = [];
    const io = {
        deleteMany: async (where) => {
            const allowed = new Set(where.session_type.in);
            rows = rows.filter((r) => {
                if (r.session_id !== where.session_id)
                    return true;
                if (r.playerId !== where.playerId)
                    return true;
                return !allowed.has(r.session_type);
            });
            return { count: 1 };
        },
        create: async (data) => {
            rows.push(data);
            writes.push(data);
            return data;
        }
    };
    await (0, attendance_1.persistAttendancePresence)({
        session_type: 'PLATEAU',
        session_id: 's1',
        playerId: 'p1',
        present: true,
    }, io);
    await (0, attendance_1.persistAttendancePresence)({
        session_type: 'PLATEAU',
        session_id: 's1',
        playerId: 'p1',
        present: false,
    }, io);
    strict_1.default.equal(writes[0].session_type, 'PLATEAU');
    strict_1.default.equal(writes[1].session_type, 'PLATEAU_ABSENT');
    strict_1.default.deepEqual(rows, [{ session_type: 'PLATEAU_ABSENT', session_id: 's1', playerId: 'p1' }]);
});
(0, node_test_1.default)('normalizeAttendanceRow returns final boolean state for GET payload', () => {
    const absent = (0, attendance_1.normalizeAttendanceRow)({ session_type: 'PLATEAU_ABSENT', playerId: 'p1' });
    const present = (0, attendance_1.normalizeAttendanceRow)({ session_type: 'TRAINING', playerId: 'p2' });
    strict_1.default.equal(absent.session_type, 'PLATEAU');
    strict_1.default.equal(absent.present, false);
    strict_1.default.equal(present.session_type, 'TRAINING');
    strict_1.default.equal(present.present, true);
});
