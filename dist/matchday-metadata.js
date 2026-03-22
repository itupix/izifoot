"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchdayMetadataSchema = exports.HHMM_TIME_REGEX = void 0;
exports.buildMatchdayMetadataPatch = buildMatchdayMetadataPatch;
exports.toPublicMatchday = toPublicMatchday;
const zod_1 = require("zod");
exports.HHMM_TIME_REGEX = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
const nullableHHMMSchema = zod_1.z.union([
    zod_1.z.string().regex(exports.HHMM_TIME_REGEX, 'Invalid time format, expected HH:MM'),
    zod_1.z.null(),
]);
exports.matchdayMetadataSchema = zod_1.z.object({
    address: zod_1.z.union([zod_1.z.string(), zod_1.z.null()]).optional(),
    startTime: nullableHHMMSchema.optional(),
    meetingTime: nullableHHMMSchema.optional(),
});
function buildMatchdayMetadataPatch(data) {
    const patch = {};
    if (Object.prototype.hasOwnProperty.call(data, 'address'))
        patch.address = data.address ?? null;
    if (Object.prototype.hasOwnProperty.call(data, 'startTime'))
        patch.startTime = data.startTime ?? null;
    if (Object.prototype.hasOwnProperty.call(data, 'meetingTime'))
        patch.meetingTime = data.meetingTime ?? null;
    return patch;
}
function toPublicMatchday(matchday) {
    return {
        id: matchday.id,
        date: matchday.date,
        lieu: matchday.lieu,
        address: matchday.address ?? null,
        startTime: matchday.startTime ?? null,
        meetingTime: matchday.meetingTime ?? null,
    };
}
