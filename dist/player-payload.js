"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePlayerCreatePayload = parsePlayerCreatePayload;
exports.parsePlayerUpdatePayload = parsePlayerUpdatePayload;
exports.normalizePlayerForApi = normalizePlayerForApi;
const zod_1 = require("zod");
function asOptionalTrimmedString(value) {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}
function firstPresentString(...values) {
    for (const value of values) {
        const normalized = asOptionalTrimmedString(value);
        if (normalized)
            return normalized;
    }
    return null;
}
function parseBooleanLike(value) {
    if (typeof value === 'boolean')
        return value;
    if (typeof value === 'number') {
        if (value === 1)
            return true;
        if (value === 0)
            return false;
    }
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (['true', '1', 'yes', 'y', 'oui'].includes(normalized))
            return true;
        if (['false', '0', 'no', 'n', 'non'].includes(normalized))
            return false;
    }
    return null;
}
function splitLegacyName(fullName) {
    if (!fullName)
        return { firstName: null, lastName: null };
    const parts = fullName.trim().split(/\s+/).filter(Boolean);
    if (!parts.length)
        return { firstName: null, lastName: null };
    if (parts.length === 1)
        return { firstName: parts[0], lastName: '' };
    return {
        firstName: parts[0],
        lastName: parts.slice(1).join(' '),
    };
}
function composeFullName(firstName, lastName, fallbackName) {
    const full = [firstName, lastName].filter((v) => !!(v && v.trim().length)).join(' ').trim();
    if (full.length)
        return full;
    return (fallbackName || '').trim();
}
const basePlayerSchema = zod_1.z.object({
    firstName: zod_1.z.string().min(1),
    lastName: zod_1.z.string().min(1),
    email: zod_1.z.string(),
    phone: zod_1.z.string(),
    primary_position: zod_1.z.string().min(1),
    secondary_position: zod_1.z.string().nullable(),
    licence: zod_1.z.string().nullable(),
    isChild: zod_1.z.boolean(),
    parentFirstName: zod_1.z.string().nullable(),
    parentLastName: zod_1.z.string().nullable(),
    teamId: zod_1.z.string().nullable(),
});
function validatePlayerBusinessRules(payload) {
    const parsed = basePlayerSchema.safeParse(payload);
    if (!parsed.success) {
        throw parsed.error;
    }
    const normalized = {
        ...parsed.data,
        firstName: parsed.data.firstName.trim(),
        lastName: parsed.data.lastName.trim(),
        email: parsed.data.email.trim(),
        phone: parsed.data.phone.trim(),
        primary_position: parsed.data.primary_position.trim(),
        secondary_position: parsed.data.secondary_position ? parsed.data.secondary_position.trim() : null,
        licence: parsed.data.licence ? parsed.data.licence.trim() : null,
        parentFirstName: parsed.data.parentFirstName ? parsed.data.parentFirstName.trim() : null,
        parentLastName: parsed.data.parentLastName ? parsed.data.parentLastName.trim() : null,
        teamId: parsed.data.teamId ? parsed.data.teamId.trim() : null,
    };
    if (normalized.isChild) {
        // Child profiles should not carry parent identity or personal contact coordinates.
        normalized.parentFirstName = null;
        normalized.parentLastName = null;
        normalized.email = '';
        normalized.phone = '';
    }
    else {
        normalized.parentFirstName = null;
        normalized.parentLastName = null;
        if (!normalized.email) {
            throw new zod_1.z.ZodError([{ code: 'custom', path: ['email'], message: 'Required when isChild is false' }]);
        }
        if (!zod_1.z.string().email().safeParse(normalized.email).success) {
            throw new zod_1.z.ZodError([{ code: 'custom', path: ['email'], message: 'Invalid email' }]);
        }
        if (!normalized.phone) {
            throw new zod_1.z.ZodError([{ code: 'custom', path: ['phone'], message: 'Required when isChild is false' }]);
        }
    }
    return normalized;
}
function extractPlayerDraft(raw) {
    const legacyName = firstPresentString(raw?.name);
    const splitLegacy = splitLegacyName(legacyName);
    const firstName = firstPresentString(raw?.firstName, raw?.first_name, raw?.prenom, splitLegacy.firstName);
    const lastName = firstPresentString(raw?.lastName, raw?.last_name, raw?.nom, splitLegacy.lastName);
    const email = firstPresentString(raw?.email);
    const phone = firstPresentString(raw?.phone, raw?.telephone);
    const primaryPosition = firstPresentString(raw?.primary_position, raw?.primaryPosition, raw?.poste);
    const secondaryPosition = firstPresentString(raw?.secondary_position, raw?.secondaryPosition);
    const parentFirstName = firstPresentString(raw?.parentFirstName, raw?.parent_first_name, raw?.parentPrenom);
    const parentLastName = firstPresentString(raw?.parentLastName, raw?.parent_last_name, raw?.parentNom);
    const teamId = firstPresentString(raw?.teamId, raw?.team_id);
    let isChild;
    const parsedChild = parseBooleanLike(raw?.isChild ?? raw?.is_child ?? raw?.enfant);
    if (parsedChild !== null)
        isChild = parsedChild;
    let licence;
    if ('licence' in (raw || {}) || 'license' in (raw || {})) {
        licence = firstPresentString(raw?.licence, raw?.license);
    }
    let secondary_position;
    if ('secondary_position' in (raw || {}) || 'secondaryPosition' in (raw || {})) {
        secondary_position = secondaryPosition;
    }
    return {
        ...(firstName !== null ? { firstName } : {}),
        ...(lastName !== null ? { lastName } : {}),
        ...(email !== null ? { email } : {}),
        ...(phone !== null ? { phone } : {}),
        ...(primaryPosition !== null ? { primary_position: primaryPosition } : {}),
        ...(secondary_position !== undefined ? { secondary_position } : {}),
        ...(licence !== undefined ? { licence: licence ?? null } : {}),
        ...(isChild !== undefined ? { isChild } : {}),
        ...(parentFirstName !== null ? { parentFirstName } : {}),
        ...(parentLastName !== null ? { parentLastName } : {}),
        ...(teamId !== null ? { teamId } : {}),
    };
}
function canonicalFromExistingPlayer(existing) {
    const split = splitLegacyName(firstPresentString(existing?.name));
    const firstName = firstPresentString(existing?.firstName, existing?.first_name, split.firstName) || '';
    const lastName = firstPresentString(existing?.lastName, existing?.last_name, split.lastName) || '';
    const parentFirstName = firstPresentString(existing?.parentFirstName, existing?.parent_first_name);
    const parentLastName = firstPresentString(existing?.parentLastName, existing?.parent_last_name);
    const isChild = parseBooleanLike(existing?.isChild ?? existing?.is_child ?? existing?.enfant) || false;
    return {
        firstName,
        lastName,
        email: firstPresentString(existing?.email) || '',
        phone: firstPresentString(existing?.phone) || '',
        primary_position: firstPresentString(existing?.primary_position) || 'NON DEFINI',
        secondary_position: firstPresentString(existing?.secondary_position),
        licence: firstPresentString(existing?.licence, existing?.license),
        isChild,
        parentFirstName,
        parentLastName,
        teamId: firstPresentString(existing?.teamId, existing?.team_id),
    };
}
function parsePlayerCreatePayload(raw) {
    const draft = extractPlayerDraft(raw);
    return validatePlayerBusinessRules({
        firstName: draft.firstName || '',
        lastName: draft.lastName || '',
        email: draft.email || '',
        phone: draft.phone || '',
        primary_position: draft.primary_position || '',
        secondary_position: draft.secondary_position ?? null,
        licence: draft.licence ?? null,
        isChild: draft.isChild ?? false,
        parentFirstName: draft.parentFirstName ?? null,
        parentLastName: draft.parentLastName ?? null,
        teamId: draft.teamId ?? null,
    });
}
function parsePlayerUpdatePayload(raw, existing) {
    void existing;
    const draft = extractPlayerDraft(raw);
    return validatePlayerBusinessRules({
        firstName: draft.firstName || '',
        lastName: draft.lastName || '',
        email: draft.email || '',
        phone: draft.phone || '',
        primary_position: draft.primary_position || '',
        secondary_position: draft.secondary_position ?? null,
        licence: draft.licence ?? null,
        isChild: draft.isChild ?? false,
        parentFirstName: draft.parentFirstName ?? null,
        parentLastName: draft.parentLastName ?? null,
        teamId: draft.teamId ?? null,
    });
}
function normalizePlayerForApi(player) {
    const split = splitLegacyName(firstPresentString(player?.name));
    const firstName = firstPresentString(player?.firstName, player?.first_name, split.firstName);
    const lastName = firstPresentString(player?.lastName, player?.last_name, split.lastName);
    const isChild = parseBooleanLike(player?.isChild ?? player?.is_child ?? player?.enfant) || false;
    const parentFirstName = firstPresentString(player?.parentFirstName, player?.parent_first_name);
    const parentLastName = firstPresentString(player?.parentLastName, player?.parent_last_name);
    const licence = firstPresentString(player?.licence, player?.license);
    return {
        ...player,
        firstName,
        lastName,
        name: composeFullName(firstName, lastName, player?.name),
        isChild,
        parentFirstName: isChild ? parentFirstName : null,
        parentLastName: isChild ? parentLastName : null,
        licence: licence ?? null,
    };
}
