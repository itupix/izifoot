"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_TEAM_FORMAT = exports.ALLOWED_TEAM_FORMATS = void 0;
exports.normalizeTeamFormat = normalizeTeamFormat;
exports.resolveTeamFormat = resolveTeamFormat;
const ALLOWED_TEAM_FORMAT_VALUES = ['3v3', '5v5', '8v8', '11v11'];
exports.ALLOWED_TEAM_FORMATS = ALLOWED_TEAM_FORMAT_VALUES;
exports.DEFAULT_TEAM_FORMAT = '5v5';
const allowedTeamFormatSet = new Set(ALLOWED_TEAM_FORMAT_VALUES);
const playersOnFieldByFormat = {
    '3v3': 3,
    '5v5': 5,
    '8v8': 8,
    '11v11': 11,
};
function normalizeTeamFormat(rawFormat) {
    const input = String(rawFormat || '').trim();
    if (!input)
        return { ok: false, error: 'Format is required' };
    const compact = input.replace(/\s+/g, '');
    const m = compact.match(/^(\d{1,2})v(\d{1,2})$/i);
    if (!m) {
        return { ok: false, error: `Invalid format. Allowed values: ${ALLOWED_TEAM_FORMAT_VALUES.join(', ')}` };
    }
    const normalized = `${Number(m[1])}v${Number(m[2])}`;
    if (!allowedTeamFormatSet.has(normalized)) {
        return { ok: false, error: `Invalid format. Allowed values: ${ALLOWED_TEAM_FORMAT_VALUES.join(', ')}` };
    }
    return { ok: true, format: normalized };
}
function resolveTeamFormat(rawFormat, fallback = exports.DEFAULT_TEAM_FORMAT) {
    const parsed = typeof rawFormat === 'string' ? normalizeTeamFormat(rawFormat) : { ok: false, error: 'Format is required' };
    const resolvedFormat = parsed.ok ? parsed.format : fallback;
    return {
        format: resolvedFormat,
        playersOnField: playersOnFieldByFormat[resolvedFormat],
        usedFallback: !parsed.ok,
    };
}
