"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MATCH_STATUSES = void 0;
exports.isMatchStatus = isMatchStatus;
exports.resolveMatchStatus = resolveMatchStatus;
exports.statusFromLegacyPlayed = statusFromLegacyPlayed;
exports.derivePlayedFromStatus = derivePlayedFromStatus;
exports.resolvePatchedMatchStatus = resolvePatchedMatchStatus;
exports.normalizeMatchWriteState = normalizeMatchWriteState;
exports.countPlayedMatchesExcludingCancelled = countPlayedMatchesExcludingCancelled;
exports.MATCH_STATUSES = ['PLANNED', 'PLAYED', 'CANCELLED'];
function isMatchStatus(value) {
    return typeof value === 'string' && exports.MATCH_STATUSES.includes(value);
}
function resolveMatchStatus(value) {
    if (isMatchStatus(value.status))
        return value.status;
    return value.played ? 'PLAYED' : 'PLANNED';
}
function statusFromLegacyPlayed(played) {
    return played ? 'PLAYED' : 'PLANNED';
}
function derivePlayedFromStatus(status) {
    return status === 'PLAYED';
}
function resolvePatchedMatchStatus(input) {
    if (isMatchStatus(input.payloadStatus))
        return input.payloadStatus;
    if (input.payloadPlayed === undefined)
        return input.existingStatus;
    if (input.payloadPlayed)
        return 'PLAYED';
    // Backward-compatible behavior for clients still sending only `played=false`.
    return input.existingStatus === 'CANCELLED' ? 'CANCELLED' : 'PLANNED';
}
function normalizeMatchWriteState(input) {
    if (input.status === 'PLAYED') {
        return {
            played: true,
            score: input.score ?? { home: 0, away: 0 },
            buteurs: input.buteurs ?? [],
        };
    }
    return {
        played: false,
        score: { home: 0, away: 0 },
        buteurs: [],
    };
}
function countPlayedMatchesExcludingCancelled(rows) {
    return rows.reduce((count, row) => {
        const status = resolveMatchStatus(row);
        if (status !== 'PLAYED')
            return count;
        return count + 1;
    }, 0);
}
