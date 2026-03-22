"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const match_eligibility_1 = require("../match-eligibility");
(0, node_test_1.default)('buildEligiblePlayerIdsFromMatchdayAttendance returns null when attendance is empty', () => {
    const eligible = (0, match_eligibility_1.buildEligiblePlayerIdsFromMatchdayAttendance)([]);
    strict_1.default.equal(eligible, null);
});
(0, node_test_1.default)('buildEligiblePlayerIdsFromMatchdayAttendance includes present and convoked players only', () => {
    const eligible = (0, match_eligibility_1.buildEligiblePlayerIdsFromMatchdayAttendance)([
        { playerId: 'p1', session_type: 'PLATEAU', present: true },
        { playerId: 'p2', session_type: 'PLATEAU_ABSENT', present: false },
        { playerId: 'p3', session_type: 'PLATEAU_CONVOKE' },
        { playerId: 'p4', session_type: 'PLATEAU', present: false },
    ]);
    strict_1.default.ok(eligible);
    strict_1.default.equal(eligible.has('p1'), true);
    strict_1.default.equal(eligible.has('p3'), true);
    strict_1.default.equal(eligible.has('p2'), false);
    strict_1.default.equal(eligible.has('p4'), false);
});
(0, node_test_1.default)('buildEligiblePlayerIdsFromMatchdayAttendance supports legacy PLATEAU marker without present field', () => {
    const eligible = (0, match_eligibility_1.buildEligiblePlayerIdsFromMatchdayAttendance)([
        { playerId: 'p1', session_type: 'PLATEAU' },
    ]);
    strict_1.default.ok(eligible);
    strict_1.default.equal(eligible.has('p1'), true);
});
