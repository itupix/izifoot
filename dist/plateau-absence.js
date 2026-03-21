"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildRotationGameKey = buildRotationGameKey;
exports.ensureRotationGameKeys = ensureRotationGameKeys;
exports.extractRotationTeams = extractRotationTeams;
exports.diffTeamAbsence = diffTeamAbsence;
exports.findRotationGameKeysForTeam = findRotationGameKeysForTeam;
exports.transitionMatchStatusForAbsence = transitionMatchStatusForAbsence;
exports.buildAbsenceMatchPatches = buildAbsenceMatchPatches;
const match_status_1 = require("./match-status");
function normalizeLabel(label) {
    return label.trim().toLowerCase();
}
function buildRotationGameKey(slotIndex, gameIndex, game) {
    if (typeof game.rotationGameKey === 'string' && game.rotationGameKey.trim().length > 0) {
        return game.rotationGameKey.trim();
    }
    return `slot:${slotIndex}:game:${gameIndex}`;
}
function ensureRotationGameKeys(rotation) {
    return {
        ...rotation,
        slots: (rotation.slots || []).map((slot, slotIndex) => ({
            ...slot,
            games: (slot.games || []).map((game, gameIndex) => ({
                ...game,
                rotationGameKey: buildRotationGameKey(slotIndex, gameIndex, game),
            })),
        })),
    };
}
function extractRotationTeams(rotation) {
    if (!rotation?.teams || !Array.isArray(rotation.teams))
        return [];
    return rotation.teams.map((team) => ({
        ...team,
        absent: Boolean(team.absent),
    }));
}
function diffTeamAbsence(beforeTeams, afterTeams) {
    const beforeMap = new Map(beforeTeams.map((team) => [normalizeLabel(team.label), Boolean(team.absent)]));
    const afterMap = new Map(afterTeams.map((team) => [normalizeLabel(team.label), Boolean(team.absent)]));
    const labels = new Set([...beforeMap.keys(), ...afterMap.keys()]);
    const changes = [];
    for (const label of labels) {
        const before = beforeMap.get(label) ?? false;
        const after = afterMap.get(label) ?? false;
        if (before === after)
            continue;
        const sourceLabel = afterTeams.find((team) => normalizeLabel(team.label) === label)?.label
            || beforeTeams.find((team) => normalizeLabel(team.label) === label)?.label
            || label;
        changes.push({ teamLabel: sourceLabel, absent: after });
    }
    return changes;
}
function findRotationGameKeysForTeam(rotation, teamLabel) {
    const target = normalizeLabel(teamLabel);
    const keyed = ensureRotationGameKeys(rotation);
    const keys = [];
    for (const [slotIndex, slot] of keyed.slots.entries()) {
        for (const [gameIndex, game] of slot.games.entries()) {
            const a = normalizeLabel(game.A || '');
            const b = normalizeLabel(game.B || '');
            if (a !== target && b !== target)
                continue;
            keys.push(buildRotationGameKey(slotIndex, gameIndex, game));
        }
    }
    return keys;
}
function transitionMatchStatusForAbsence(currentStatus, absent) {
    if (absent)
        return 'CANCELLED';
    if (currentStatus === 'PLAYED')
        return 'PLAYED';
    return 'PLANNED';
}
function buildAbsenceMatchPatches(input) {
    const patches = [];
    for (const match of input.matches) {
        const currentStatus = (0, match_status_1.resolveMatchStatus)({ status: match.status, played: match.played ?? false });
        const nextStatus = transitionMatchStatusForAbsence(currentStatus, input.absent);
        const nextPlayed = nextStatus === 'PLAYED';
        const currentPlayed = currentStatus === 'PLAYED';
        if (nextStatus === currentStatus && nextPlayed === currentPlayed)
            continue;
        patches.push({ id: match.id, status: nextStatus, played: nextPlayed });
    }
    return patches;
}
