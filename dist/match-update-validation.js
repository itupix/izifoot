"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateMatchUpdatePayloadForTeamFormat = validateMatchUpdatePayloadForTeamFormat;
const match_tactic_1 = require("./match-tactic");
const team_format_1 = require("./team-format");
function validateMatchUpdatePayloadForTeamFormat(input) {
    const resolved = (0, team_format_1.resolveTeamFormat)(input.teamFormat);
    for (const sideName of ['home', 'away']) {
        const side = input.sides[sideName];
        if (side.starters.length > resolved.playersOnField) {
            return {
                ok: false,
                error: `Too many starters for ${sideName}: received ${side.starters.length}, max ${resolved.playersOnField} for format ${resolved.format}`,
            };
        }
        const starterSet = new Set(side.starters);
        if (starterSet.size !== side.starters.length) {
            return { ok: false, error: `Duplicate player IDs in ${sideName}.starters` };
        }
        const subSet = new Set(side.subs);
        if (subSet.size !== side.subs.length) {
            return { ok: false, error: `Duplicate player IDs in ${sideName}.subs` };
        }
        for (const playerId of starterSet) {
            if (subSet.has(playerId)) {
                return { ok: false, error: `Player "${playerId}" cannot be in both ${sideName}.starters and ${sideName}.subs` };
            }
        }
    }
    if (input.tactic) {
        const tacticValidation = (0, match_tactic_1.validateMatchTacticForPlayersOnField)(input.tactic, resolved.playersOnField);
        if (!tacticValidation.ok) {
            return { ok: false, error: tacticValidation.error };
        }
    }
    return {
        ok: true,
        format: resolved.format,
        playersOnField: resolved.playersOnField,
        usedFallback: resolved.usedFallback,
    };
}
