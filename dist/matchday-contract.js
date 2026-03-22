"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveMatchdayMode = deriveMatchdayMode;
exports.normalizeRotationForContract = normalizeRotationForContract;
exports.ensureRotationGameKeysForContract = ensureRotationGameKeysForContract;
const ROTATION_COLOR_PALETTE = [
    '#1d4ed8',
    '#e11d48',
    '#16a34a',
    '#f59e0b',
    '#7c3aed',
    '#0f766e',
];
function toNonEmptyString(value) {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}
function fallbackColor(index) {
    return ROTATION_COLOR_PALETTE[index % ROTATION_COLOR_PALETTE.length];
}
function deriveMatchdayMode(input) {
    return (input.hasPersistedRotationKey || input.hasPlanningRotation) ? 'ROTATION' : 'MANUAL';
}
function normalizeRotationForContract(candidate, defaultUpdatedAtIso) {
    if (!candidate || !Array.isArray(candidate.slots))
        return null;
    const teamsRaw = Array.isArray(candidate.teams) ? candidate.teams : [];
    const teams = teamsRaw.map((team, index) => ({
        label: toNonEmptyString(team?.label) || `Team ${index + 1}`,
        color: toNonEmptyString(team?.color) || fallbackColor(index),
        absent: Boolean(team?.absent),
    }));
    const slots = candidate.slots.map((slot) => ({
        time: String(slot?.time ?? ''),
        games: Array.isArray(slot?.games)
            ? slot.games.map((game) => ({
                pitch: game?.pitch ?? '',
                A: String(game?.A ?? ''),
                B: String(game?.B ?? ''),
            }))
            : [],
    }));
    const start = toNonEmptyString(candidate?.start);
    return {
        updatedAt: typeof candidate.updatedAt === 'string' ? candidate.updatedAt : defaultUpdatedAtIso,
        ...(start ? { start } : {}),
        teams,
        slots,
    };
}
function ensureRotationGameKeysForContract(matches, enabled) {
    if (!enabled) {
        return matches.map((match) => ({ ...match, rotationGameKey: match.rotationGameKey ?? null }));
    }
    const used = new Set(matches
        .map((match) => toNonEmptyString(match.rotationGameKey))
        .filter((value) => Boolean(value)));
    return matches.map((match, index) => {
        const current = toNonEmptyString(match.rotationGameKey);
        if (current)
            return { ...match, rotationGameKey: current };
        let candidate = `schedule:${index}`;
        if (used.has(candidate)) {
            let suffix = 1;
            while (used.has(`schedule:${index}:${suffix}`))
                suffix += 1;
            candidate = `schedule:${index}:${suffix}`;
        }
        used.add(candidate);
        return { ...match, rotationGameKey: candidate };
    });
}
