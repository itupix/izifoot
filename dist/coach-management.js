"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeCoachManagedTeamIds = normalizeCoachManagedTeamIds;
exports.resolveCoachActiveTeamId = resolveCoachActiveTeamId;
exports.mapCoachManagedTeams = mapCoachManagedTeams;
function normalizeCoachManagedTeamIds(teamId, managedTeamIds) {
    const normalized = [];
    const seen = new Set();
    const push = (value) => {
        const trimmed = typeof value === 'string' ? value.trim() : '';
        if (!trimmed || seen.has(trimmed))
            return;
        seen.add(trimmed);
        normalized.push(trimmed);
    };
    push(teamId);
    for (const value of managedTeamIds || [])
        push(value);
    return normalized;
}
function resolveCoachActiveTeamId(currentTeamId, managedTeamIds) {
    const normalizedCurrent = typeof currentTeamId === 'string' ? currentTeamId.trim() : '';
    if (normalizedCurrent && managedTeamIds.includes(normalizedCurrent))
        return normalizedCurrent;
    return managedTeamIds[0] ?? null;
}
function mapCoachManagedTeams(managedTeamIds, teamNameById) {
    return managedTeamIds.map((id) => ({
        id,
        name: teamNameById.get(id) ?? id,
    }));
}
