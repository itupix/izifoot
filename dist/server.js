"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const client_1 = require("@prisma/client");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const nanoid_1 = require("nanoid");
const qrcode_1 = __importDefault(require("qrcode"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const date_fns_1 = require("date-fns");
const crypto_1 = require("crypto");
const matchday_metadata_1 = require("./matchday-metadata");
const attendance_1 = require("./attendance");
const training_role_assignments_1 = require("./training-role-assignments");
const tactics_1 = require("./tactics");
const team_category_1 = require("./team-category");
const team_format_1 = require("./team-format");
const team_name_1 = require("./team-name");
const match_tactic_1 = require("./match-tactic");
const match_eligibility_1 = require("./match-eligibility");
const match_events_1 = require("./match-events");
const match_update_validation_1 = require("./match-update-validation");
const player_payload_1 = require("./player-payload");
const player_invitation_status_1 = require("./player-invitation-status");
const player_account_role_1 = require("./player-account-role");
const match_payload_1 = require("./match-payload");
const match_status_1 = require("./match-status");
const matchday_absence_1 = require("./matchday-absence");
const matchday_contract_1 = require("./matchday-contract");
const app = (0, express_1.default)();
const prisma = new client_1.PrismaClient();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const IS_PROD = process.env.NODE_ENV === 'production';
const SLOW_REQUEST_MS = Number(process.env.SLOW_REQUEST_MS || 700);
const PERF_SAMPLE_WINDOW = Number(process.env.PERF_SAMPLE_WINDOW || 200);
const PERF_LOG_EVERY = Number(process.env.PERF_LOG_EVERY || 100);
const DEFAULT_DEV_APP_BASE_URL = 'http://localhost:5173';
const APP_BASE_URL = process.env.APP_BASE_URL || DEFAULT_DEV_APP_BASE_URL;
const API_BASE_URL = process.env.API_BASE_URL || `http://localhost:${PORT}`;
const AUTH_COOKIE_NAME = 'token';
const ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID = Boolean(prisma?._runtimeDataModel?.models?.AccountInvite?.fields?.some((field) => field?.name === 'linkedPlayerId'));
// Railway/Reverse proxy support so secure cookies can be set correctly.
app.set('trust proxy', 1);
function wrapExpressHandler(handler) {
    return function wrappedHandler(req, res, next) {
        return Promise.resolve(handler(req, res, next)).catch(next);
    };
}
for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
    const original = app[method].bind(app);
    app[method] = (path, ...handlers) => {
        return original(path, ...handlers.map((handler) => wrapExpressHandler(handler)));
    };
}
function toOrigin(raw) {
    const s = raw.trim();
    if (!s)
        return null;
    try {
        return new URL(s).origin;
    }
    catch {
        return null;
    }
}
function toWildcardRule(raw) {
    const s = raw.trim();
    if (!s.includes('*'))
        return null;
    const m = s.match(/^(https?):\/\/\*\.(.+?)(?::(\d+))?$/i);
    if (!m)
        return null;
    return {
        protocol: m[1].toLowerCase(),
        hostnameSuffix: m[2].toLowerCase(),
        port: m[3] || '',
    };
}
const exactFrontOrigins = new Set();
const wildcardFrontOrigins = [];
const configuredFrontOrigins = [
    ...(IS_PROD ? [] : [APP_BASE_URL]),
    ...(!IS_PROD && !process.env.APP_BASE_URL ? [] : [process.env.APP_BASE_URL || '']),
    ...(process.env.APP_BASE_URLS || '').split(','),
];
for (const rawOrigin of configuredFrontOrigins) {
    const wildcardRule = toWildcardRule(rawOrigin);
    if (wildcardRule) {
        wildcardFrontOrigins.push(wildcardRule);
        continue;
    }
    const normalizedOrigin = toOrigin(rawOrigin);
    if (!normalizedOrigin)
        continue;
    exactFrontOrigins.add(normalizedOrigin);
    const u = new URL(normalizedOrigin);
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
        const port = u.port || '5173';
        exactFrontOrigins.add(`http://localhost:${port}`);
        exactFrontOrigins.add(`http://127.0.0.1:${port}`);
        exactFrontOrigins.add(`https://localhost:${port}`);
        exactFrontOrigins.add(`https://127.0.0.1:${port}`);
    }
}
function isAllowedOrigin(origin) {
    if (exactFrontOrigins.has(origin))
        return true;
    let parsed;
    try {
        parsed = new URL(origin);
    }
    catch {
        return false;
    }
    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.replace(/:$/, '').toLowerCase();
    const port = parsed.port || '';
    return wildcardFrontOrigins.some((rule) => {
        if (!rule)
            return false;
        if (rule.protocol !== protocol)
            return false;
        if (rule.port !== port)
            return false;
        if (hostname === rule.hostnameSuffix)
            return false;
        return hostname.endsWith(`.${rule.hostnameSuffix}`);
    });
}
if (IS_PROD && exactFrontOrigins.size === 0 && wildcardFrontOrigins.length === 0) {
    console.warn('[cors] No front-end origin configured. Set APP_BASE_URL or APP_BASE_URLS in production.');
}
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)({
    origin(origin, callback) {
        if (!origin)
            return callback(null, true);
        if (isAllowedOrigin(origin))
            return callback(null, true);
        console.warn(`[cors] Blocked origin: ${origin}`);
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
}));
app.use(express_1.default.json({ limit: '1mb' }));
app.use((0, cookie_parser_1.default)());
app.use((0, morgan_1.default)('dev'));
app.use((req, res, next) => {
    const startedAt = process.hrtime.bigint();
    res.on('finish', () => {
        const durationMs = Number(process.hrtime.bigint() - startedAt) / 1000000;
        const path = String(req.originalUrl || req.url || '').split('?')[0] || '/';
        const routeKey = `${req.method} ${path}`;
        recordRoutePerf(routeKey, durationMs);
        if (durationMs >= SLOW_REQUEST_MS || res.statusCode >= 500) {
            const level = res.statusCode >= 500 ? 'error' : 'warn';
            console[level]('[perf.request]', {
                method: req.method,
                path,
                status: res.statusCode,
                durationMs: Number(durationMs.toFixed(1)),
            });
        }
    });
    next();
});
// Anti-cache pour l'API (évite les 304 Not Modified sur GET protégés)
app.set('etag', false);
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    // Important si tu utilises Authorization ou cookies
    res.setHeader('Vary', 'Authorization, Origin');
    next();
});
// --- Cookie helper for robust cross-site cookie options ---
function authCookieOpts() {
    const isProd = process.env.NODE_ENV === 'production';
    const sameSite = isProd ? 'none' : 'lax';
    return {
        httpOnly: true,
        sameSite,
        secure: isProd,
        path: '/',
        maxAge: 7 * 24 * 3600 * 1000
    };
}
function authClearCookieOpts() {
    const { maxAge, ...opts } = authCookieOpts();
    return opts;
}
function playerCookieOpts() {
    const isProd = process.env.NODE_ENV === 'production';
    const sameSite = isProd ? 'none' : 'lax';
    return {
        httpOnly: true,
        sameSite,
        secure: isProd,
        path: '/',
        maxAge: 30 * 24 * 3600 * 1000
    };
}
function toNonNegativeInt(value) {
    if (value === undefined || value === null || value === '')
        return null;
    const n = Number(value);
    if (!Number.isFinite(n))
        return null;
    const i = Math.trunc(n);
    return i >= 0 ? i : null;
}
function readPagination(query, defaults = { limit: 50, maxLimit: 200 }) {
    const limitInput = toNonNegativeInt(query?.limit);
    const offsetInput = toNonNegativeInt(query?.offset);
    const limit = Math.min(limitInput ?? defaults.limit, defaults.maxLimit);
    const offset = offsetInput ?? 0;
    return { take: limit, skip: offset, limit, offset };
}
function percentile(values, p) {
    if (!values.length)
        return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
    return sorted[idx];
}
const routePerfStats = new Map();
function recordRoutePerf(routeKey, durationMs) {
    let stat = routePerfStats.get(routeKey);
    if (!stat) {
        stat = { count: 0, samples: [] };
        routePerfStats.set(routeKey, stat);
    }
    stat.count += 1;
    stat.samples.push(durationMs);
    if (stat.samples.length > PERF_SAMPLE_WINDOW)
        stat.samples.shift();
    if (stat.count % PERF_LOG_EVERY === 0) {
        const sampleCount = stat.samples.length;
        const sum = stat.samples.reduce((acc, ms) => acc + ms, 0);
        const avg = sampleCount ? sum / sampleCount : 0;
        const p95 = percentile(stat.samples, 0.95);
        const p99 = percentile(stat.samples, 0.99);
        console.log('[perf.route]', {
            route: routeKey,
            sampleCount,
            p95Ms: Number(p95.toFixed(1)),
            p99Ms: Number(p99.toFixed(1)),
            avgMs: Number(avg.toFixed(1)),
        });
    }
}
// --- Auth helpers ---
function signToken(userId) {
    return jsonwebtoken_1.default.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' });
}
async function resolveUserAuthContext(userId) {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
            team: true,
            club: true,
        }
    });
    if (!user)
        return null;
    let resolvedTeamId = user.teamId;
    if (user.role === 'DIRECTION' && !resolvedTeamId && user.clubId) {
        const clubTeams = await prisma.team.findMany({
            where: { clubId: user.clubId },
            orderBy: { name: 'asc' },
            select: { id: true },
            take: 2
        });
        if (clubTeams.length === 1)
            resolvedTeamId = clubTeams[0].id;
    }
    let managedTeamIds = [];
    if (user.role === 'COACH') {
        const candidateIds = Array.isArray(user.managedTeamIds) ? user.managedTeamIds : [];
        if (candidateIds.length) {
            const managedTeams = await prisma.team.findMany({
                where: {
                    id: { in: candidateIds },
                    ...(user.clubId ? { clubId: user.clubId } : {}),
                },
                select: { id: true }
            });
            managedTeamIds = managedTeams.map((t) => t.id);
        }
    }
    let parentLinkedPlayer = null;
    if (user.role === 'PARENT' && user.linkedPlayerUserId) {
        parentLinkedPlayer = await prisma.user.findUnique({
            where: { id: user.linkedPlayerUserId },
            select: { id: true, role: true, teamId: true, clubId: true }
        });
    }
    return {
        id: user.id,
        email: user.email,
        role: user.role,
        clubId: user.clubId,
        teamId: resolvedTeamId,
        managedTeamIds,
        linkedPlayerUserId: user.linkedPlayerUserId,
        parentLinkedPlayer,
    };
}
async function authMiddleware(req, res, next) {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token)
        return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        const auth = await resolveUserAuthContext(payload.sub);
        if (!auth)
            return res.status(401).json({ error: 'Unauthorized' });
        req.userId = auth.id;
        req.auth = auth;
        next();
    }
    catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
function ensureDirection(req, res) {
    if (req.auth?.role !== 'DIRECTION') {
        res.status(403).json({ error: 'Only direction accounts can perform this action' });
        return false;
    }
    return true;
}
function isReadOnlyRole(auth) {
    return auth?.role === 'PLAYER' || auth?.role === 'PARENT';
}
function ensureStaff(req, res) {
    if (req.auth?.role === 'DIRECTION' || req.auth?.role === 'COACH')
        return true;
    res.status(403).json({ error: 'Only direction and coach accounts can perform this action' });
    return false;
}
function isWriteMethod(method) {
    return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
}
async function generateAutoTeamName(clubId, baseName, opts = {}) {
    const existingTeams = await prisma.team.findMany({
        where: {
            clubId,
            ...(opts.excludeTeamId ? { id: { not: opts.excludeTeamId } } : {}),
        },
        select: { name: true },
    });
    return (0, team_name_1.computeAutoTeamName)(baseName, existingTeams.map((row) => row.name));
}
const teamUpsertPayloadSchema = zod_1.z.preprocess((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
        return raw;
    const payload = raw;
    return {
        name: payload.name ?? payload.teamName ?? null,
        category: payload.category,
        format: payload.format ?? payload.gameFormat ?? payload.game_format,
    };
}, zod_1.z.object({
    name: zod_1.z.string({ invalid_type_error: 'Name must be a string' }).max(80, 'Name must be at most 80 characters').optional().nullable(),
    category: zod_1.z.string({ required_error: 'Category is required', invalid_type_error: 'Category must be a string' }).min(1, 'Category is required'),
    format: zod_1.z.string({ required_error: 'Format is required', invalid_type_error: 'Format must be a string' }).min(1, 'Format is required'),
}));
function normalizeTeamResponse(team) {
    const resolvedFormat = (0, team_format_1.resolveTeamFormat)(team?.format);
    return withTeamFormatAliases({
        id: team.id,
        name: team.name,
        category: team.category,
        format: resolvedFormat.format,
        clubId: team.clubId,
        createdAt: team.createdAt,
    });
}
function withTeamFormatAliases(team) {
    const resolvedFormat = (0, team_format_1.resolveTeamFormat)(team?.format);
    return {
        ...team,
        format: resolvedFormat.format,
        gameFormat: resolvedFormat.format,
        game_format: resolvedFormat.format,
    };
}
function logTeamValidationFailure(endpoint, reason, details = {}) {
    console.warn(`[${endpoint}] team validation failed: ${reason}`, details);
}
function pathStartsWith(pathname, prefix) {
    return pathname === prefix || pathname.startsWith(`${prefix}/`);
}
function getActiveTeamIdForAuth(auth) {
    if (!auth)
        return null;
    if (auth.role === 'COACH') {
        const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : [];
        if (auth.teamId && managedIds.includes(auth.teamId))
            return auth.teamId;
        if (managedIds.length === 1)
            return managedIds[0];
        return null;
    }
    if (auth.role === 'DIRECTION')
        return auth.teamId || null;
    return auth.teamId || null;
}
function getReadableTeamIds(auth) {
    if (!auth)
        return [];
    if (auth.role === 'DIRECTION') {
        const activeTeamId = getActiveTeamIdForAuth(auth);
        return activeTeamId ? [activeTeamId] : [];
    }
    if (auth.role === 'COACH') {
        const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds.filter(Boolean) : [];
        if (auth.teamId && managedIds.includes(auth.teamId))
            return [auth.teamId];
        if (managedIds.length)
            return managedIds;
        return auth.teamId ? [auth.teamId] : [];
    }
    if (auth.role === 'PARENT') {
        const linkedTeamId = auth.parentLinkedPlayer?.teamId || auth.teamId;
        return linkedTeamId ? [linkedTeamId] : [];
    }
    return auth.teamId ? [auth.teamId] : [];
}
function applyScopeWhere(auth, where = {}, opts = {}) {
    const scopedWhere = { ...(where || {}) };
    if (auth?.clubId)
        scopedWhere.clubId = auth.clubId;
    const teamIds = getReadableTeamIds(auth);
    if (auth?.role === 'DIRECTION' && auth?.clubId && !auth?.teamId) {
        // Direction accounts without an active team can read all club data.
    }
    else if (teamIds.length === 1) {
        scopedWhere.teamId = teamIds[0];
    }
    else if (teamIds.length > 1) {
        scopedWhere.teamId = { in: teamIds };
    }
    else {
        scopedWhere.teamId = '__no_access_team__';
    }
    if (!opts.includeLegacyOwner)
        return scopedWhere;
    return {
        OR: [
            scopedWhere,
            { ...(where || {}), userId: auth?.id }
        ]
    };
}
async function resolveTeamForWrite(auth, requestedTeamId) {
    if (!auth?.clubId) {
        const err = new Error('No club attached to account');
        err.code = 'NO_CLUB';
        throw err;
    }
    if (auth.role === 'DIRECTION' || auth.role === 'COACH') {
        const activeTeamId = getActiveTeamIdForAuth(auth);
        const teamId = requestedTeamId || activeTeamId;
        if (!teamId) {
            const err = new Error('Active team selection is required');
            err.code = 'TEAM_REQUIRED';
            throw err;
        }
        if (auth.role === 'COACH') {
            const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : [];
            if (!managedIds.includes(teamId)) {
                const err = new Error('Coach cannot write outside managed teams');
                err.code = 'TEAM_FORBIDDEN';
                throw err;
            }
        }
        const team = await prisma.team.findFirst({
            where: { id: teamId, clubId: auth.clubId },
            select: { id: true, clubId: true }
        });
        if (!team) {
            const err = new Error('Selected team not found in club');
            err.code = 'TEAM_FORBIDDEN';
            throw err;
        }
        return team;
    }
    const err = new Error('Write access forbidden');
    err.code = 'WRITE_FORBIDDEN';
    throw err;
}
const teamMessageCreateBodySchema = zod_1.z.object({
    content: zod_1.z.string().trim().min(1).max(2000),
    teamId: zod_1.z.string().trim().min(1).optional(),
});
async function resolveReadableTeamForMessaging(auth, requestedTeamId) {
    if (!auth?.clubId) {
        const err = new Error('No club attached to account');
        err.code = 'NO_CLUB';
        throw err;
    }
    const readableTeamIds = getReadableTeamIds(auth);
    const requested = (requestedTeamId || '').trim() || null;
    if (requested) {
        const canRead = auth.role === 'DIRECTION' && !auth.teamId
            ? true
            : readableTeamIds.includes(requested);
        if (!canRead) {
            const err = new Error('Forbidden team scope');
            err.code = 'TEAM_FORBIDDEN';
            throw err;
        }
        const team = await prisma.team.findFirst({
            where: { id: requested, clubId: auth.clubId },
            select: { id: true, clubId: true },
        });
        if (!team) {
            const err = new Error('Team not found in club');
            err.code = 'TEAM_FORBIDDEN';
            throw err;
        }
        return team;
    }
    if (auth.role === 'DIRECTION' || auth.role === 'COACH') {
        const activeTeamId = getActiveTeamIdForAuth(auth);
        if (!activeTeamId) {
            const err = new Error('Active team selection is required');
            err.code = 'TEAM_REQUIRED';
            throw err;
        }
        const team = await prisma.team.findFirst({
            where: { id: activeTeamId, clubId: auth.clubId },
            select: { id: true, clubId: true },
        });
        if (!team) {
            const err = new Error('Team not found in club');
            err.code = 'TEAM_FORBIDDEN';
            throw err;
        }
        return team;
    }
    if (readableTeamIds.length !== 1) {
        const err = new Error('Readable team scope missing');
        err.code = 'TEAM_REQUIRED';
        throw err;
    }
    const team = await prisma.team.findFirst({
        where: { id: readableTeamIds[0], clubId: auth.clubId },
        select: { id: true, clubId: true },
    });
    if (!team) {
        const err = new Error('Team not found in club');
        err.code = 'TEAM_FORBIDDEN';
        throw err;
    }
    return team;
}
async function assertCanReadTeamOrThrow(auth, teamId, clubId) {
    if (!auth?.clubId || auth.clubId !== clubId) {
        const err = new Error('Forbidden team scope');
        err.code = 'TEAM_FORBIDDEN';
        throw err;
    }
    if (auth.role === 'DIRECTION' && !auth.teamId)
        return;
    const readableTeamIds = getReadableTeamIds(auth);
    if (!readableTeamIds.includes(teamId)) {
        const err = new Error('Forbidden team scope');
        err.code = 'TEAM_FORBIDDEN';
        throw err;
    }
}
async function computeUnreadTeamMessagesCount(auth) {
    if (!auth?.id || !auth?.clubId)
        return 0;
    const teamIds = auth.role === 'DIRECTION' && !auth.teamId
        ? (await prisma.team.findMany({
            where: { clubId: auth.clubId },
            select: { id: true },
        })).map((row) => row.id)
        : getReadableTeamIds(auth);
    if (!teamIds.length)
        return 0;
    const reads = await prisma.teamMessageRead.findMany({
        where: { userId: auth.id, teamId: { in: teamIds } },
        select: { teamId: true, lastReadAt: true },
    });
    const readByTeamId = new Map(reads.map((row) => [row.teamId, row.lastReadAt]));
    let count = 0;
    for (const teamId of teamIds) {
        const lastReadAt = readByTeamId.get(teamId);
        count += await prisma.teamMessage.count({
            where: {
                clubId: auth.clubId,
                teamId,
                authorUserId: { not: auth.id },
                ...(lastReadAt ? { createdAt: { gt: lastReadAt } } : {}),
            },
        });
    }
    return count;
}
function normalizeScopeInput(scopeOrUserId) {
    if (scopeOrUserId && typeof scopeOrUserId === 'object' && 'role' in scopeOrUserId)
        return scopeOrUserId;
    if (typeof scopeOrUserId === 'string')
        return { id: scopeOrUserId, role: 'DIRECTION' };
    return { id: null, role: 'DIRECTION' };
}
function scopedWhereOrLegacy(scopeOrUserId, where = {}) {
    if (typeof scopeOrUserId === 'string')
        return { ...(where || {}), userId: scopeOrUserId };
    return applyScopeWhere(normalizeScopeInput(scopeOrUserId), where, { includeLegacyOwner: true });
}
async function playerCreateForUser(db, scopeOrUserId, data) {
    return db.player.create({
        data: {
            ...data,
        }
    });
}
async function attendanceFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.attendance.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function attendanceFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.attendance.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function attendanceDeleteManyForUser(db, scopeOrUserId, where = {}) {
    return db.attendance.deleteMany({ where: scopedWhereOrLegacy(scopeOrUserId, where) });
}
async function attendanceUpsertMarkerForUser(db, scopeOrUserId, params) {
    const auth = normalizeScopeInput(scopeOrUserId);
    const { session_type, session_id, playerId } = params;
    await attendanceDeleteManyForUser(db, scopeOrUserId, { session_type, session_id, playerId });
    return db.attendance.create({
        data: {
            ...(auth?.id ? { userId: auth.id } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
            session_type,
            session_id,
            playerId
        }
    });
}
async function attendanceSetPresenceForUser(db, scopeOrUserId, params) {
    const auth = normalizeScopeInput(scopeOrUserId);
    return (0, attendance_1.persistAttendancePresence)(params, {
        deleteMany: (where) => attendanceDeleteManyForUser(db, scopeOrUserId, where),
        create: (data) => db.attendance.create({
            data: {
                ...(auth?.id ? { userId: auth.id } : {}),
                ...(auth?.clubId ? { clubId: auth.clubId } : {}),
                ...(auth?.teamId ? { teamId: auth.teamId } : {}),
                ...data
            },
        })
    });
}
async function attendanceSetMatchdayRsvpForUser(db, scopeOrUserId, matchdayId, playerId, present) {
    return attendanceSetPresenceForUser(db, scopeOrUserId, {
        session_type: 'PLATEAU',
        session_id: matchdayId,
        playerId,
        present,
    });
}
async function resolveAttendanceScopeFromSession(auth, session_type, session_id) {
    if (session_type === 'TRAINING') {
        const training = await trainingFindFirstForUser(prisma, auth, {
            where: { id: session_id },
            select: { id: true, clubId: true, teamId: true },
        });
        if (!training)
            return null;
        return {
            ...auth,
            clubId: training.clubId ?? auth?.clubId ?? null,
            teamId: training.teamId ?? auth?.teamId ?? null,
        };
    }
    const matchday = await matchdayFindFirstForUser(prisma, auth, {
        where: { id: session_id },
        select: { id: true, clubId: true, teamId: true },
    });
    if (!matchday)
        return null;
    return {
        ...auth,
        clubId: matchday.clubId ?? auth?.clubId ?? null,
        teamId: matchday.teamId ?? auth?.teamId ?? null,
    };
}
async function playerFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.player.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function playerFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.player.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function playerFindByIdCompat(db, id) {
    return db.player.findUnique({ where: { id } });
}
async function trainingFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.training.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function trainingFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.training.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function trainingCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    return db.training.create({
        data: {
            ...data,
            ...(auth?.id ? { userId: auth.id } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        }
    });
}
async function trainingUpdateCompat(db, id, data) {
    return db.training.update({ where: { id }, data });
}
async function matchdayFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.plateau.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function matchdayFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.plateau.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function matchdayCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    return db.plateau.create({
        data: {
            ...data,
            ...(auth?.id ? { userId: auth.id } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        }
    });
}
async function matchFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.match.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function matchFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.match.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function matchFindUniqueCompat(db, args) {
    return db.match.findUnique(args);
}
async function matchCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    const { plateauId, ...rest } = data;
    return db.match.create({
        data: {
            ...rest,
            ...(plateauId ? { plateau: { connect: { id: plateauId } } } : {}),
            ...(auth?.id ? { user: { connect: { id: auth.id } } } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        }
    });
}
async function trainingDrillFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.trainingDrill.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function trainingDrillFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.trainingDrill.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function trainingDrillCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    return db.trainingDrill.create({
        data: {
            ...data,
            ...(auth?.id ? { userId: auth.id } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        }
    });
}
async function trainingRoleAssignmentFindManyForUser(db, scopeOrUserId, args = {}) {
    try {
        return await db.trainingRoleAssignment.findMany({
            ...args,
            where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
        });
    }
    catch (e) {
        if (e?.code === 'P2021') {
            const err = new Error('Training role storage unavailable');
            err.code = 'TRAINING_ROLE_STORAGE_UNAVAILABLE';
            throw err;
        }
        throw e;
    }
}
function toTrainingRoleAssignmentResponseItem(row) {
    return {
        id: row.id,
        trainingId: row.trainingId,
        role: row.role,
        playerId: row.playerId,
        player: row.player ? { id: row.player.id, name: row.player.name } : null,
    };
}
function getDrillDelegate(db) {
    const delegate = db?.drill;
    if (!delegate || typeof delegate.findMany !== 'function' || typeof delegate.findFirst !== 'function') {
        return null;
    }
    return delegate;
}
async function drillFindManyForUser(db, scopeOrUserId, args = {}) {
    const delegate = getDrillDelegate(db);
    if (!delegate)
        return [];
    try {
        return await delegate.findMany({
            ...args,
            where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
        });
    }
    catch (e) {
        if (e?.code === 'P2021')
            return [];
        throw e;
    }
}
async function drillFindFirstForUser(db, scopeOrUserId, args = {}) {
    const delegate = getDrillDelegate(db);
    if (!delegate)
        return null;
    try {
        return await delegate.findFirst({
            ...args,
            where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
        });
    }
    catch (e) {
        if (e?.code === 'P2021')
            return null;
        throw e;
    }
}
async function drillCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    const delegate = getDrillDelegate(db);
    if (!delegate || typeof delegate.create !== 'function') {
        const err = new Error('Drill storage unavailable');
        err.code = 'DRILL_STORAGE_UNAVAILABLE';
        throw err;
    }
    try {
        return await delegate.create({
            data: {
                ...data,
                ...(auth?.id ? { userId: auth.id } : {}),
                ...(auth?.clubId ? { clubId: auth.clubId } : {}),
                ...(auth?.teamId ? { teamId: auth.teamId } : {}),
            }
        });
    }
    catch (e) {
        if (e?.code === 'P2021') {
            const err = new Error('Drill storage unavailable');
            err.code = 'DRILL_STORAGE_UNAVAILABLE';
            throw err;
        }
        throw e;
    }
}
async function resolveTrainingDrillForRouteRef(db, scopeOrUserId, trainingId, trainingDrillRef) {
    const byId = await trainingDrillFindFirstForUser(db, scopeOrUserId, {
        where: { id: trainingDrillRef, trainingId },
    });
    if (byId)
        return byId;
    const byDrillId = await trainingDrillFindManyForUser(db, scopeOrUserId, {
        where: { drillId: trainingDrillRef, trainingId },
        orderBy: { order: 'asc' },
        take: 2,
    });
    if (byDrillId.length !== 1)
        return null;
    return byDrillId[0];
}
async function listTrainingDrillsInOrder(db, scopeOrUserId, trainingId, args = {}) {
    return trainingDrillFindManyForUser(db, scopeOrUserId, {
        ...args,
        where: { ...(args.where || {}), trainingId },
        orderBy: args.orderBy || [{ order: 'asc' }, { id: 'asc' }],
    });
}
async function normalizeTrainingDrillOrders(db, scopeOrUserId, trainingId) {
    const rows = await listTrainingDrillsInOrder(db, scopeOrUserId, trainingId, {
        select: { id: true, order: true },
    });
    for (const [index, row] of rows.entries()) {
        if (row.order === index)
            continue;
        await db.trainingDrill.update({
            where: { id: row.id },
            data: { order: index },
        });
    }
}
async function moveTrainingDrillToOrder(db, scopeOrUserId, trainingId, trainingDrillId, targetOrder) {
    const rows = await listTrainingDrillsInOrder(db, scopeOrUserId, trainingId, {
        select: { id: true, order: true },
    });
    const currentIndex = rows.findIndex((row) => row.id === trainingDrillId);
    if (currentIndex < 0) {
        const err = new Error('Training drill not found');
        err.code = 'TRAINING_DRILL_NOT_FOUND';
        throw err;
    }
    if (targetOrder < 0 || targetOrder >= rows.length) {
        const err = new Error('Invalid order');
        err.code = 'INVALID_ORDER';
        throw err;
    }
    if (currentIndex === targetOrder)
        return;
    const [moved] = rows.splice(currentIndex, 1);
    rows.splice(targetOrder, 0, moved);
    for (const [index, row] of rows.entries()) {
        if (row.order === index)
            continue;
        await db.trainingDrill.update({
            where: { id: row.id },
            data: { order: index },
        });
    }
}
async function diagramFindManyForUser(db, scopeOrUserId, args = {}) {
    return db.diagram.findMany({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function diagramFindFirstForUser(db, scopeOrUserId, args = {}) {
    return db.diagram.findFirst({
        ...args,
        where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    });
}
async function diagramCreateForUser(db, scopeOrUserId, data) {
    const auth = normalizeScopeInput(scopeOrUserId);
    return db.diagram.create({
        data: {
            ...data,
            ...(auth?.id ? { userId: auth.id } : {}),
            ...(auth?.clubId ? { clubId: auth.clubId } : {}),
            ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        }
    });
}
// --- Nodemailer (optional) ---
let transporter = null;
const SMTP_URL = process.env.SMTP_URL;
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
try {
    if (SMTP_URL) {
        transporter = nodemailer_1.default.createTransport(SMTP_URL);
    }
    else if (SMTP_HOST && SMTP_HOST !== 'smtp.example.com') {
        transporter = nodemailer_1.default.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_SECURE,
            auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
            connectionTimeout: 10000,
        });
    }
    else if (SMTP_HOST === 'smtp.example.com') {
        console.warn('[smtp] Placeholder SMTP_HOST detected (smtp.example.com). Email notifications disabled. Set real creds or unset SMTP_HOST.');
    }
    if (transporter) {
        // Verify at startup; if it fails, disable transporter to avoid noisy errors at runtime.
        transporter.verify().then(() => {
            console.log('[smtp] Transport ready');
        }).catch((err) => {
            console.warn('[smtp] Verification failed. Disabling email notifications.', err?.message || err);
            transporter = null;
        });
    }
}
catch (e) {
    console.warn('[smtp] Failed to initialize transporter. Email notifications disabled.', e?.message || e);
    transporter = null;
}
// --- Waitlist helpers (in‑memory) ---
const waitlistSeen = new Map(); // email -> timestamp
const WAITLIST_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes
function normEmail(e) { return e.trim().toLowerCase(); }
function asOptionalTrimmedString(value) {
    if (typeof value !== 'string')
        return null;
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
}
function asStringArray(value) {
    if (!Array.isArray(value))
        return [];
    return value
        .map((item) => (typeof item === 'string' ? item.trim() : ''))
        .filter((item) => item.length > 0);
}
function firstPresentString(...values) {
    for (const value of values) {
        const normalized = asOptionalTrimmedString(value);
        if (normalized)
            return normalized;
    }
    return null;
}
function normalizeCoachPayload(raw) {
    const managedTeamIds = asStringArray(raw?.managedTeamIds ?? raw?.managed_team_ids);
    const teamIdFromLegacyManaged = managedTeamIds[0] ?? null;
    return {
        role: firstPresentString(raw?.role) ?? 'COACH',
        firstName: firstPresentString(raw?.firstName, raw?.first_name, raw?.prenom),
        lastName: firstPresentString(raw?.lastName, raw?.last_name, raw?.nom),
        email: firstPresentString(raw?.email),
        phone: firstPresentString(raw?.phone, raw?.telephone),
        teamId: firstPresentString(raw?.teamId, raw?.team_id, teamIdFromLegacyManaged),
        managedTeamIds,
        expiresInDays: raw?.expiresInDays ?? raw?.expires_in_days,
    };
}
function toCoachSummaryFromUser(user) {
    return {
        id: user.id,
        firstName: user.firstName ?? null,
        lastName: user.lastName ?? null,
        email: user.email,
        phone: user.phone ?? null,
        teamId: user.teamId ?? null,
        teamName: user.team?.name ?? null,
        invitationStatus: 'ACCEPTED',
    };
}
function toCoachSummaryFromInvite(invite) {
    return {
        id: invite.id,
        firstName: invite.firstName ?? null,
        lastName: invite.lastName ?? null,
        email: invite.email,
        phone: invite.phone ?? null,
        teamId: invite.teamId ?? null,
        teamName: invite.teamName ?? invite.team?.name ?? null,
        invitationStatus: invite.status,
    };
}
function getPlayerInviteLinkWhere(player, linkedPlayerAccountUserId) {
    if (ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID)
        return { linkedPlayerId: player.id };
    if (linkedPlayerAccountUserId)
        return { linkedPlayerUserId: linkedPlayerAccountUserId };
    return null;
}
function getPlayerInviteLinkSelect() {
    const base = {
        linkedPlayerUserId: true,
    };
    if (ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID)
        base.linkedPlayerId = true;
    return base;
}
async function resolveLinkedPlayerAccountUser(player, clubId) {
    if (!player?.userId)
        return null;
    const linkedUser = await prisma.user.findUnique({
        where: { id: player.userId },
        select: { id: true, role: true, clubId: true }
    });
    if (!linkedUser)
        return null;
    const allowedRoles = (0, player_account_role_1.resolvePlayerAccountInviteLookupRoles)(Boolean(player?.is_child));
    const linkedUserRole = linkedUser.role === 'PLAYER' || linkedUser.role === 'PARENT' ? linkedUser.role : null;
    if (!linkedUserRole || !allowedRoles.includes(linkedUserRole))
        return null;
    if (clubId && linkedUser.clubId && linkedUser.clubId !== clubId)
        return null;
    return linkedUser;
}
async function getPlayerInvitationStatusSnapshot(auth, player) {
    const now = new Date();
    const clubId = player.clubId || auth?.clubId || null;
    const linkedUser = await resolveLinkedPlayerAccountUser(player, clubId);
    const hasActiveAccount = Boolean(linkedUser);
    const linkWhere = getPlayerInviteLinkWhere(player, linkedUser?.id);
    if (!linkWhere) {
        return (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
            hasActiveAccount,
            latestPendingInvite: null,
            latestAcceptedInvite: null,
        });
    }
    const inviteRoles = (0, player_account_role_1.resolvePlayerAccountInviteLookupRoles)(Boolean(player?.is_child));
    if (clubId) {
        await prisma.accountInvite.updateMany({
            where: {
                clubId,
                role: { in: inviteRoles },
                ...linkWhere,
                status: 'PENDING',
                expiresAt: { lt: now }
            },
            data: { status: 'EXPIRED' }
        });
    }
    const [latestPendingInvite, latestAcceptedInvite] = await Promise.all([
        prisma.accountInvite.findFirst({
            where: {
                ...(clubId ? { clubId } : {}),
                role: { in: inviteRoles },
                ...linkWhere,
                status: 'PENDING',
                expiresAt: { gte: now }
            },
            select: {
                id: true,
                createdAt: true,
                updatedAt: true,
            },
            orderBy: [{ updatedAt: 'desc' }, { createdAt: 'desc' }]
        }),
        prisma.accountInvite.findFirst({
            where: {
                ...(clubId ? { clubId } : {}),
                role: { in: inviteRoles },
                ...linkWhere,
                status: 'ACCEPTED'
            },
            select: {
                id: true,
                createdAt: true,
                updatedAt: true,
                acceptedAt: true,
            },
            orderBy: [{ acceptedAt: 'desc' }, { updatedAt: 'desc' }]
        })
    ]);
    return (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
        hasActiveAccount,
        latestPendingInvite,
        latestAcceptedInvite,
    });
}
async function getPlayerInvitationStatusForRequest(req, playerId) {
    const player = await playerFindFirstForUser(prisma, req.auth, {
        where: { id: playerId },
    });
    if (!player)
        return null;
    const snapshot = await getPlayerInvitationStatusSnapshot(req.auth, player);
    return {
        player,
        snapshot,
    };
}
async function sendPlayerAccountInviteEmail(params) {
    if (!transporter)
        return;
    const inviteUrl = buildAccountInviteUrl(params.token);
    const displayName = (params.playerName || '').trim();
    const greeting = displayName ? `Bonjour ${displayName},` : 'Bonjour,';
    try {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || 'no-reply@example.com',
            to: params.inviteEmail,
            subject: 'Activation de votre compte joueur Izifoot',
            html: `<p>${greeting}</p>
<p>Votre compte joueur Izifoot est pret. Cliquez sur le lien ci-dessous pour activer votre compte et definir votre mot de passe.</p>
<p><a href="${inviteUrl}">${inviteUrl}</a></p>
<p>Ce lien expire le ${params.expiresAt.toISOString()}.</p>`
        });
    }
    catch (e) {
        console.warn('[players invite] email failed:', e);
    }
}
function buildAccountInviteUrl(token) {
    const acceptPath = process.env.INVITE_ACCEPT_PATH || '/invite/accept';
    return `${APP_BASE_URL.replace(/\/+$/, '')}${acceptPath}?token=${encodeURIComponent(token)}`;
}
// --- Routes ---
function safeParseJSON(s) {
    if (!s)
        return null;
    try {
        return JSON.parse(s);
    }
    catch {
        return null;
    }
}
function slugifyDrillTitle(title) {
    return title.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}
async function buildUniqueDrillId(db, scopeOrUserId, title) {
    const base = slugifyDrillTitle(title);
    let id = `d_${base || 'new'}`;
    let i = 1;
    while (await drillFindFirstForUser(db, scopeOrUserId, { where: { id } })) {
        id = `d_${base || 'new'}_${i++}`;
    }
    return id;
}
function inferAgeBandFromTeamName(teamName) {
    const raw = String(teamName || '');
    const m = raw.match(/\bU\s*([0-9]{1,2})\b/i);
    if (!m)
        return 'U9-U11';
    const age = Number(m[1]);
    if (!Number.isFinite(age))
        return 'U9-U11';
    return `U${age}`;
}
const aiGeneratedDrillSchema = zod_1.z.object({
    t: zod_1.z.string().min(1).max(100),
    c: zod_1.z.string().min(1).max(500),
    m: zod_1.z.number().int().min(6).max(40),
    p: zod_1.z.string().min(1).max(500),
    s: zod_1.z.string().min(1).max(2000),
    g: zod_1.z.array(zod_1.z.string().min(1).max(64)).max(8),
    a: zod_1.z.object({
        p: zod_1.z.array(zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()])).max(5).optional(),
        s: zod_1.z.array(zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()])).max(5).optional(),
        c: zod_1.z.array(zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()])).max(4).optional(),
    }).optional(),
    k: zod_1.z.object({
        f: zod_1.z.array(zod_1.z.object({
            a: zod_1.z.string().min(1).max(24),
            t: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]),
        })).max(6)
    }).optional(),
    v: zod_1.z.object({
        c: zod_1.z.array(zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()])).max(4).optional(),
        f: zod_1.z.array(zod_1.z.object({
            p1: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]),
            p2: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]),
            b: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]).optional(),
        })).min(3).max(12).optional(),
    }).optional(),
});
const aiGeneratedBundleSchema = zod_1.z.object({
    d: zod_1.z.array(aiGeneratedDrillSchema).length(5)
});
function readFirstString(...values) {
    for (const value of values) {
        if (typeof value === 'string' && value.trim())
            return value.trim();
    }
    return '';
}
function readFirstInt(...values) {
    for (const value of values) {
        if (typeof value === 'number' && Number.isFinite(value))
            return Math.trunc(value);
        if (typeof value === 'string' && value.trim()) {
            const n = Number(value);
            if (Number.isFinite(n))
                return Math.trunc(n);
        }
    }
    return 0;
}
function readTags(value) {
    if (!Array.isArray(value))
        return [];
    return value
        .map((tag) => typeof tag === 'string' ? tag.trim() : '')
        .filter(Boolean);
}
function readPointPairs(value) {
    if (!Array.isArray(value))
        return [];
    const points = [];
    for (const item of value) {
        if (!Array.isArray(item) || item.length < 2)
            continue;
        const x = Number(item[0]);
        const y = Number(item[1]);
        if (!Number.isFinite(x) || !Number.isFinite(y))
            continue;
        points.push([x, y]);
    }
    return points;
}
function readPhases(value) {
    if (!Array.isArray(value))
        return [];
    return value.map((phase) => ({
        a: readFirstString(phase?.a, phase?.action, phase?.type),
        t: readPointPairs([phase?.t ?? phase?.target])[0]
    })).filter((phase) => phase.a && Array.isArray(phase.t));
}
function readVisualFrames(value) {
    if (!Array.isArray(value))
        return [];
    return value.map((frame) => ({
        p1: readPointPairs([frame?.p1 ?? frame?.a ?? frame?.attacker])[0],
        p2: readPointPairs([frame?.p2 ?? frame?.s ?? frame?.support])[0],
        b: readPointPairs([frame?.b ?? frame?.ball])[0],
    })).filter((frame) => Array.isArray(frame.p1) && Array.isArray(frame.p2));
}
function normalizeFrameSeries(frames) {
    if (!frames.length)
        return [];
    if (frames.length === 10)
        return frames;
    const out = [];
    for (let i = 0; i < 10; i += 1) {
        const t = i / 9;
        const scaled = t * (frames.length - 1);
        const fromIndex = Math.floor(scaled);
        const toIndex = Math.min(frames.length - 1, fromIndex + 1);
        const localT = scaled - fromIndex;
        const from = frames[fromIndex];
        const to = frames[toIndex];
        const lerp = (a, b) => a + (b - a) * localT;
        const p1 = [lerp(from.p1[0], to.p1[0]), lerp(from.p1[1], to.p1[1])];
        const p2 = [lerp(from.p2[0], to.p2[0]), lerp(from.p2[1], to.p2[1])];
        const b0 = from.b || from.p1;
        const b1 = to.b || to.p1;
        const b = [lerp(b0[0], b1[0]), lerp(b0[1], b1[1])];
        out.push({ p1, p2, b });
    }
    return out;
}
function buildDetailedDescription(raw, title, ageBand, objective) {
    const compact = raw.trim().replace(/\s+/g, ' ').slice(0, 1400);
    const hasSections = /organisation\s*:|consignes?\s*:|variables?\s*:|vigilance\s*:/i.test(compact);
    if (compact.length >= 420 && hasSections)
        return compact;
    const fallback = [
        `Organisation: ${compact || `atelier "${title}"`} sur 20x20m, 2 couloirs de jeu, rotation toutes les 60-90 secondes, groupes équilibrés pour ${ageBand}.`,
        `Consignes: contrôler orienté, annoncer l'information avant réception, enchaîner en 2 touches max, se replacer immédiatement après action.`,
        `Déroulé: démarrage à faible intensité (2 min), montée en rythme (4-6 min), situation opposée finale avec score/objectif lié à "${objective}".`,
        `Variables: réduire l'espace, ajouter un défenseur, imposer un sens de circulation ou une zone de finition pour augmenter la complexité.`,
        `Vigilance: distances de sécurité, contacts maîtrisés, qualité des appuis et correction courte entre rotations.`,
    ].join(' ');
    return fallback.slice(0, 1400);
}
function sentenceize(value) {
    const compact = value.trim().replace(/\s+/g, ' ');
    if (!compact)
        return '';
    return /[.!?]$/.test(compact) ? compact : `${compact}.`;
}
function extractSection(content, section) {
    const lower = content.toLowerCase();
    const sectionLabel = `${section.toLowerCase()}:`;
    const start = lower.indexOf(sectionLabel);
    if (start < 0)
        return '';
    const after = start + sectionLabel.length;
    const nextCandidates = ['organisation:', 'consignes:', 'deroule:', 'déroulé:', 'variables:', 'vigilance:']
        .map((label) => lower.indexOf(label, after))
        .filter((index) => index >= 0);
    const end = nextCandidates.length ? Math.min(...nextCandidates) : content.length;
    return content.slice(after, end).trim();
}
function formatDrillDescription(raw) {
    const compact = raw.trim().replace(/\r\n/g, '\n').replace(/\s+/g, ' ');
    const normalized = compact
        .replace(/déroulé\s*:/gi, 'Deroule:')
        .replace(/organisation\s*:/gi, 'Organisation:')
        .replace(/consignes?\s*:/gi, 'Consignes:')
        .replace(/variables?\s*:/gi, 'Variables:')
        .replace(/vigilance\s*:/gi, 'Vigilance:');
    const organisation = extractSection(normalized, 'Organisation');
    const consignes = extractSection(normalized, 'Consignes');
    const deroule = extractSection(normalized, 'Deroule');
    const variables = extractSection(normalized, 'Variables');
    const vigilance = extractSection(normalized, 'Vigilance');
    if (organisation || consignes || deroule || variables || vigilance) {
        const lines = [
            organisation ? `**Organisation :** ${sentenceize(organisation)}` : '',
            consignes ? `**Consignes :** ${sentenceize(consignes)}` : '',
            deroule ? `**Déroulé :** ${sentenceize(deroule)}` : '',
            variables ? `**Variables :** ${sentenceize(variables)}` : '',
            vigilance ? `**Vigilance :** ${sentenceize(vigilance)}` : '',
        ].filter(Boolean);
        return lines.join('\n');
    }
    // Fallback: split dense text into digestible action lines.
    const parts = compact
        .split(/[.!?]\s+/)
        .map((part) => part.trim())
        .filter(Boolean)
        .slice(0, 5);
    const fallbackLines = [
        parts[0] ? `**Organisation :** ${sentenceize(parts[0])}` : '',
        parts[1] ? `**Consignes :** ${sentenceize(parts[1])}` : '',
        parts[2] ? `**Déroulé :** ${sentenceize(parts[2])}` : '',
        parts[3] ? `**Variables :** ${sentenceize(parts[3])}` : '',
        parts[4] ? `**Vigilance :** ${sentenceize(parts[4])}` : '',
    ].filter(Boolean);
    return fallbackLines.join('\n');
}
function escapeHtml(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
function toDrillDescriptionHtml(value) {
    const lines = value
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    if (!lines.length)
        return '';
    return lines.map((line) => {
        const md = line.match(/^\*\*(.+?)\*\*\s*(.*)$/);
        if (md) {
            return `<p><strong>${escapeHtml(md[1].trim())}</strong> ${escapeHtml(md[2])}</p>`;
        }
        const plain = line.match(/^([^:]+)\s*:\s*(.*)$/);
        if (plain) {
            return `<p><strong>${escapeHtml(plain[1].trim())} :</strong> ${escapeHtml(plain[2])}</p>`;
        }
        return `<p>${escapeHtml(line)}</p>`;
    }).join('');
}
function normalizeIncomingDescription(raw) {
    const noHtml = raw.replace(/<[^>]*>/g, ' ');
    const noMarkdown = noHtml
        .replace(/\*\*(.*?)\*\*/g, '$1')
        .replace(/__(.*?)__/g, '$1')
        .replace(/`([^`]+)`/g, '$1');
    return noMarkdown.replace(/\s+/g, ' ').trim();
}
function withDrillDescriptionHtml(drill) {
    const raw = typeof drill?.description === 'string' ? drill.description : '';
    const normalizedRaw = normalizeIncomingDescription(raw);
    const formatted = formatDrillDescription(normalizedRaw);
    return {
        ...drill,
        description: formatted,
        descriptionHtml: toDrillDescriptionHtml(formatted),
    };
}
function normalizeAiDrillValue(value, ctx) {
    const title = value.t.trim().slice(0, 100);
    const category = value.c.trim().slice(0, 50);
    const duration = Math.max(6, Math.min(40, Math.trunc(value.m)));
    const players = value.p.trim().slice(0, 50);
    const description = buildDetailedDescription(value.s, title, ctx.ageBand, ctx.objective).slice(0, 1200);
    const tags = Array.from(new Set(value.g
        .map((tag) => tag.trim().toLowerCase().slice(0, 24))
        .filter(Boolean))).slice(0, 3);
    const clampPoint = ([x, y]) => [
        Math.max(0, Math.min(100, Math.round(x))),
        Math.max(0, Math.min(100, Math.round(y))),
    ];
    const primaryPath = (value.a?.p || []).map(clampPoint).slice(0, 5);
    const supportPath = (value.a?.s || []).map(clampPoint).slice(0, 5);
    const cones = (value.a?.c || []).map(clampPoint).slice(0, 4);
    const animation = {
        p: primaryPath.length >= 2 ? primaryPath : undefined,
        s: supportPath.length >= 2 ? supportPath : undefined,
        c: cones.length >= 2 ? cones : undefined,
    };
    const phaseAction = (raw) => {
        const s = raw.toUpperCase();
        if (s.includes('PRESS'))
            return 'PRESS';
        if (s.includes('INTERCEPT'))
            return 'INTERCEPT';
        if (s.includes('DRIBBLE'))
            return 'DRIBBLE';
        if (s.includes('FINISH') || s.includes('SHOT') || s.includes('TIR'))
            return 'FINISH';
        if (s.includes('SUPPORT') || s.includes('APPU'))
            return 'SUPPORT';
        if (s.includes('PASS') || s.includes('PASSE'))
            return 'PASS';
        return 'MOVE';
    };
    const rawPhases = (value.k?.f || []);
    const phases = rawPhases.map((phase) => ({
        a: phaseAction(String(phase.a || '')),
        t: clampPoint(phase.t)
    })).slice(0, 6);
    const tacticalPlan = { phases: phases.length ? phases : undefined };
    const sequence = tacticalPlan.phases?.map((phase) => phase.a).join(' -> ');
    const descriptionWithPlan = sequence
        ? `${description} Séquence: ${sequence}.`
        : description;
    const formattedDescription = formatDrillDescription(descriptionWithPlan).slice(0, 1200);
    const descriptionHtml = toDrillDescriptionHtml(formattedDescription);
    const visualCones = (value.v?.c || []).map(clampPoint).slice(0, 4);
    const visualFramesRaw = normalizeFrameSeries((value.v?.f || []).map((frame) => ({
        p1: clampPoint(frame.p1),
        p2: clampPoint(frame.p2),
        b: frame.b ? clampPoint(frame.b) : clampPoint(frame.p1),
    })));
    const visualPlan = {
        c: visualCones.length >= 2 ? visualCones : undefined,
        f: visualFramesRaw.length === 10 ? visualFramesRaw : undefined,
    };
    return {
        title,
        category,
        duration,
        players,
        description: formattedDescription,
        descriptionHtml,
        tags,
        animation,
        tacticalPlan,
        visualPlan
    };
}
function coerceOpenAiBundle(raw) {
    const root = raw && typeof raw === 'object' ? raw : {};
    const list = (Array.isArray(root.d) && root.d) ||
        (Array.isArray(root.drills) && root.drills) ||
        (Array.isArray(root.exercises) && root.exercises) ||
        (Array.isArray(root.items) && root.items) ||
        (Array.isArray(raw) && raw) ||
        [];
    const mapped = list.slice(0, 5).map((item) => ({
        t: readFirstString(item?.t, item?.title, item?.name),
        c: readFirstString(item?.c, item?.category, item?.theme, item?.type),
        m: readFirstInt(item?.m, item?.minutes, item?.duration),
        p: readFirstString(item?.p, item?.players, item?.group, item?.format),
        s: readFirstString(item?.s, item?.description, item?.consigne, item?.instructions),
        g: readTags(item?.g ?? item?.tags ?? item?.keywords),
        a: {
            p: readPointPairs(item?.a?.p ?? item?.animation?.p ?? item?.path ?? item?.primaryPath),
            s: readPointPairs(item?.a?.s ?? item?.animation?.s ?? item?.supportPath),
            c: readPointPairs(item?.a?.c ?? item?.animation?.c ?? item?.cones),
        },
        k: {
            f: readPhases(item?.k?.f ?? item?.plan?.f ?? item?.phases ?? item?.sequence),
        },
        v: {
            c: readPointPairs(item?.v?.c ?? item?.visual?.c ?? item?.visualPlan?.c ?? item?.cones),
            f: readVisualFrames(item?.v?.f ?? item?.visual?.f ?? item?.visualPlan?.f ?? item?.frames),
        },
    }));
    return { d: mapped };
}
function shortNodeId() {
    return (0, crypto_1.randomUUID)().replace(/-/g, '').slice(0, 8);
}
function hashText(input) {
    let hash = 0;
    for (let i = 0; i < input.length; i += 1) {
        hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
    }
    return Math.abs(hash);
}
function pointAtPath(points, t) {
    if (!points.length)
        return { x: 100, y: 80 };
    if (points.length === 1)
        return points[0];
    const scaled = t * (points.length - 1);
    const i = Math.min(points.length - 2, Math.max(0, Math.floor(scaled)));
    const localT = scaled - i;
    const from = points[i];
    const to = points[i + 1];
    return {
        x: from.x + (to.x - from.x) * localT,
        y: from.y + (to.y - from.y) * localT,
    };
}
function normalizePathPoints(index, points) {
    if (!points || points.length < 2)
        return null;
    const offset = (index % 5) * 6;
    return points.map(([x, y]) => ({
        x: 36 + x * 1.6 + offset,
        y: 30 + y * 1.1,
    }));
}
function warpPoint(x, y, t, seed, variant) {
    const ampX = 4 + (seed % 6);
    const ampY = 3 + ((seed >> 3) % 6);
    const freq = 1 + (seed % 3);
    const phase = (seed % 360) * (Math.PI / 180);
    const wx = x + Math.sin((t * Math.PI * 2 * freq) + phase) * ampX * (variant === 1 ? 1.2 : 0.8);
    const wy = y + Math.cos((t * Math.PI * freq) + phase / 2) * ampY * (variant === 2 ? 1.25 : 0.75);
    return { x: wx, y: wy };
}
function maybeMirrorX(x, seed) {
    // Keep coordinates in the same board space while inverting shape orientation for half the drills.
    if (seed % 2 === 0)
        return x;
    return 300 - x;
}
function scaleDiagramToViewport(data) {
    const frames = Array.isArray(data?.frames) ? data.frames : [];
    if (!frames.length)
        return data;
    const points = [];
    for (const frame of frames) {
        const items = Array.isArray(frame?.items) ? frame.items : [];
        for (const item of items) {
            if (typeof item?.x === 'number' && typeof item?.y === 'number') {
                points.push({ x: item.x, y: item.y });
            }
            if (item?.from && typeof item.from.x === 'number' && typeof item.from.y === 'number') {
                points.push({ x: item.from.x, y: item.from.y });
            }
            if (item?.to && typeof item.to.x === 'number' && typeof item.to.y === 'number') {
                points.push({ x: item.to.x, y: item.to.y });
            }
        }
    }
    if (!points.length)
        return data;
    let minX = points[0].x;
    let maxX = points[0].x;
    let minY = points[0].y;
    let maxY = points[0].y;
    for (const point of points) {
        if (point.x < minX)
            minX = point.x;
        if (point.x > maxX)
            maxX = point.x;
        if (point.y < minY)
            minY = point.y;
        if (point.y > maxY)
            maxY = point.y;
    }
    const width = Math.max(1, maxX - minX);
    const height = Math.max(1, maxY - minY);
    const targetMinX = 16;
    const targetMaxX = 284;
    const targetMinY = 12;
    const targetMaxY = 168;
    const targetWidth = targetMaxX - targetMinX;
    const targetHeight = targetMaxY - targetMinY;
    const scale = Math.min(targetWidth / width, targetHeight / height);
    const scaledWidth = width * scale;
    const scaledHeight = height * scale;
    const translateX = targetMinX + (targetWidth - scaledWidth) / 2 - minX * scale;
    const translateY = targetMinY + (targetHeight - scaledHeight) / 2 - minY * scale;
    const transform = (x, y) => ({ x: x * scale + translateX, y: y * scale + translateY });
    const scaledFrames = frames.map((frame) => {
        const items = Array.isArray(frame?.items) ? frame.items : [];
        return {
            ...frame,
            items: items.map((item) => {
                const next = { ...item };
                if (typeof next.x === 'number' && typeof next.y === 'number') {
                    const p = transform(next.x, next.y);
                    next.x = p.x;
                    next.y = p.y;
                }
                if (next.from && typeof next.from.x === 'number' && typeof next.from.y === 'number') {
                    const p = transform(next.from.x, next.from.y);
                    next.from = { ...next.from, x: p.x, y: p.y };
                }
                if (next.to && typeof next.to.x === 'number' && typeof next.to.y === 'number') {
                    const p = transform(next.to.x, next.to.y);
                    next.to = { ...next.to, x: p.x, y: p.y };
                }
                return next;
            })
        };
    });
    return {
        ...data,
        items: scaledFrames[0]?.items || [],
        frames: scaledFrames
    };
}
function buildDefaultDiagramData(index, drill) {
    const offset = (index % 5) * 14;
    const startX = 88 + offset;
    const frameCount = 10;
    const seed = hashText(`${drill.title}|${drill.category}|${(drill.tags || []).join(',')}`);
    const variant = (seed + index) % 4;
    const playerId = shortNodeId();
    const supportId = shortNodeId();
    const coneAId = shortNodeId();
    const coneBId = shortNodeId();
    const coneCId = shortNodeId();
    const toBoardPoint = ([x, y]) => ({ x: 18 + (x * 2.64), y: 12 + (y * 1.56) });
    const hasVisualFrames = Array.isArray(drill.visualPlan?.f) && drill.visualPlan.f.length === 10;
    const visualCones = Array.isArray(drill.visualPlan?.c) ? drill.visualPlan.c.slice(0, 3).map(toBoardPoint) : [];
    if (hasVisualFrames) {
        const frames = drill.visualPlan.f.map((frame, frameIndex) => {
            const p1 = toBoardPoint(frame.p1);
            const p2 = toBoardPoint(frame.p2);
            const b = toBoardPoint(frame.b || frame.p1);
            const prev = frameIndex > 0 ? drill.visualPlan.f[frameIndex - 1] : null;
            const prevP1 = prev ? toBoardPoint(prev.p1) : p1;
            const prevP2 = prev ? toBoardPoint(prev.p2) : p2;
            return {
                items: [
                    { type: 'player', id: playerId, x: p1.x, y: p1.y, side: 'home', label: 'J1' },
                    { type: 'player', id: supportId, x: p2.x, y: p2.y, side: 'home', label: 'J2' },
                    { type: 'ball', id: shortNodeId(), x: b.x, y: b.y },
                    { type: 'cone', id: coneAId, x: visualCones[0]?.x ?? 72, y: visualCones[0]?.y ?? 86 },
                    { type: 'cone', id: coneBId, x: visualCones[1]?.x ?? 144, y: visualCones[1]?.y ?? 66 },
                    { type: 'cone', id: coneCId, x: visualCones[2]?.x ?? 204, y: visualCones[2]?.y ?? 96 },
                    { type: 'arrow', id: shortNodeId(), from: { x: prevP1.x, y: prevP1.y }, to: { x: p1.x, y: p1.y } },
                    { type: 'arrow', id: shortNodeId(), from: { x: prevP2.x, y: prevP2.y }, to: { x: p2.x, y: p2.y } },
                ]
            };
        });
        return scaleDiagramToViewport({ items: frames[0].items, frames });
    }
    const tacticalPath = normalizePathPoints(index, (drill.tacticalPlan?.phases || []).map((phase) => phase.t));
    const primaryPath = tacticalPath && tacticalPath.length >= 2 ? tacticalPath : normalizePathPoints(index, drill.animation?.p);
    const supportPath = normalizePathPoints(index, drill.animation?.s);
    const conePoints = normalizePathPoints(index, drill.animation?.c);
    const startY = 98;
    const frames = Array.from({ length: frameCount }, (_unused, frameIndex) => {
        const t = frameIndex / (frameCount - 1);
        let px = startX;
        let py = startY;
        let supportX = startX + 10;
        let supportY = startY + 18;
        if (primaryPath) {
            const p = pointAtPath(primaryPath, t);
            px = p.x;
            py = p.y;
            const s = supportPath ? pointAtPath(supportPath, t) : pointAtPath(primaryPath, Math.max(0, t - 0.22));
            supportX = s.x;
            supportY = s.y + 18;
        }
        else if (variant === 0) {
            px = startX + 58 * t;
            py = 98 - 38 * t;
            supportX = startX + 6 + 32 * t;
            supportY = 118 - 18 * t;
        }
        else if (variant === 1) {
            px = startX + 58 * t;
            py = 84 + Math.sin(t * Math.PI * 2) * 16;
            supportX = startX + 18 + 42 * t;
            supportY = 106 - Math.sin(t * Math.PI * 2) * 10;
        }
        else if (variant === 2) {
            px = startX + 44 * t;
            py = 90 - t * 24;
            supportX = startX + 60 - t * 42;
            supportY = 62 + t * 30;
        }
        else {
            px = startX + 10 + Math.sin(t * Math.PI) * 18;
            py = 98 - t * 26;
            supportX = startX + 56 - Math.sin(t * Math.PI) * 18;
            supportY = 80 + t * 18;
        }
        const wp = warpPoint(px, py, t, seed, variant);
        px = maybeMirrorX(wp.x, seed);
        py = wp.y;
        const ws = warpPoint(supportX, supportY, t, seed + 17, (variant + 1) % 4);
        supportX = maybeMirrorX(ws.x, seed);
        supportY = ws.y;
        const c0 = conePoints?.[0];
        const c1 = conePoints?.[1];
        const c2 = conePoints?.[2];
        return {
            items: [
                { type: 'player', id: playerId, x: px, y: py, side: 'home', label: 'J1' },
                { type: 'player', id: supportId, x: supportX, y: supportY, side: 'home', label: 'J2' },
                { type: 'cone', id: coneAId, x: c0?.x ?? startX + (variant === 3 ? 14 : 26), y: c0?.y ?? 84 },
                { type: 'cone', id: coneBId, x: c1?.x ?? startX + 56, y: c1?.y ?? (variant === 1 ? 72 : 64) },
                { type: 'cone', id: coneCId, x: c2?.x ?? startX + 36, y: c2?.y ?? (variant === 2 ? 52 : 102) },
                { type: 'arrow', id: shortNodeId(), from: { x: px, y: py }, to: { x: px + (variant === 2 ? 5 : 8), y: py - 6 } },
                { type: 'arrow', id: shortNodeId(), from: { x: supportX, y: supportY }, to: { x: px, y: py } },
            ]
        };
    });
    const raw = {
        items: frames[0].items,
        frames
    };
    return scaleDiagramToViewport(raw);
}
async function generateDrillsWithOpenAI(params, opts = {}) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
        const err = new Error('OPENAI_API_KEY is missing');
        err.code = 'OPENAI_API_KEY_MISSING';
        throw err;
    }
    const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
    const objective = params.objective.trim();
    const ageBand = params.ageBand.trim();
    const teamName = params.teamName.trim();
    const includeVisualPlan = !!opts.includeVisualPlan;
    const systemFormat = includeVisualPlan
        ? 'Tu es un coach football jeunes. Réponds uniquement en JSON compact valide sans markdown. Format strict: {"d":[{"t":"","c":"","m":0,"p":"","s":"","g":[""],"v":{"c":[[20,30],[80,50],[45,80]],"f":[{"p1":[10,70],"p2":[30,80],"b":[10,70]}]},"k":{"f":[{"a":"PASS","t":[30,60]},{"a":"DRIBBLE","t":[60,45]},{"a":"FINISH","t":[85,35]}]},"a":{"p":[[0,0],[100,100]],"s":[[0,0],[100,100]],"c":[[20,30],[80,60],[40,80]]}}]} avec exactement 5 exercices.'
        : 'Tu es un coach football jeunes. Réponds uniquement en JSON compact valide sans markdown. Format strict: {"d":[{"t":"","c":"","m":0,"p":"","s":"","g":[""]}]} avec exactement 5 exercices.';
    const userConstraints = includeVisualPlan
        ? `Objectif:${objective}\nAge:${ageBand}\nEquipe:${teamName}\nContraintes: français; adaptés à l'âge; progression simple->complexe; sécurité; pas de doublons; m en minutes entières; g max 3 tags courts; s très détaillée et opérationnelle (organisation, consignes, déroulé, variables, vigilance), entre 420 et 1000 caractères; k obligatoire: 3 à 5 phases ordonnées (a+t) cohérentes avec la description; v obligatoire: 10 frames (f) avec p1/p2/b en 0..100 + 2-3 cônes (c); les 5 exercices doivent avoir des schémas visuels nettement différents (zones, trajectoires et orientation).`
        : `Objectif:${objective}\nAge:${ageBand}\nEquipe:${teamName}\nContraintes: français; adaptés à l'âge; progression simple->complexe; sécurité; pas de doublons; m en minutes entières; g max 3 tags courts; s très détaillée et opérationnelle (organisation, consignes, déroulé, variables, vigilance), entre 420 et 1000 caractères.`;
    const input = [
        {
            role: 'system',
            content: [
                {
                    type: 'input_text',
                    text: systemFormat
                }
            ]
        },
        {
            role: 'user',
            content: [
                {
                    type: 'input_text',
                    text: userConstraints
                }
            ]
        }
    ];
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let response;
    try {
        try {
            response = await fetch('https://api.openai.com/v1/responses', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    model,
                    input,
                    temperature: 0.4,
                    max_output_tokens: includeVisualPlan ? 2800 : 1400,
                    text: { format: { type: 'json_object' } }
                }),
                signal: controller.signal,
            });
        }
        catch (e) {
            const err = new Error('OpenAI network request failed');
            err.code = e?.name === 'AbortError' ? 'OPENAI_TIMEOUT' : 'OPENAI_NETWORK_ERROR';
            err.detail = e?.message || String(e);
            throw err;
        }
    }
    finally {
        clearTimeout(timeout);
    }
    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        const parsedDetail = safeParseJSON(detail);
        const err = new Error(`OpenAI request failed (${response.status})`);
        err.code = 'OPENAI_REQUEST_FAILED';
        err.status = response.status;
        err.detail = detail.slice(0, 500);
        err.openai = parsedDetail?.error || null;
        throw err;
    }
    const payload = await response.json();
    const rawText = typeof payload?.output_text === 'string'
        ? payload.output_text
        : Array.isArray(payload?.output)
            ? payload.output
                .flatMap((item) => Array.isArray(item?.content) ? item.content : [])
                .map((chunk) => chunk?.text || '')
                .join('\n')
            : '';
    const parsedJson = safeParseJSON(rawText);
    if (!parsedJson) {
        const err = new Error('OpenAI response is not valid JSON');
        err.code = 'OPENAI_INVALID_JSON';
        err.raw = String(rawText || '').slice(0, 2000);
        throw err;
    }
    const strictParsed = aiGeneratedBundleSchema.safeParse(parsedJson);
    if (strictParsed.success) {
        return strictParsed.data.d.map((drill) => normalizeAiDrillValue(drill, { ageBand: params.ageBand, objective: params.objective }));
    }
    const coerced = coerceOpenAiBundle(parsedJson);
    const parsed = aiGeneratedBundleSchema.safeParse(coerced);
    if (!parsed.success) {
        const err = new Error('OpenAI response does not match expected schema');
        err.code = 'OPENAI_SCHEMA_MISMATCH';
        err.raw = JSON.stringify(parsedJson).slice(0, 2000);
        err.coerced = JSON.stringify(coerced).slice(0, 2000);
        err.issues = parsed.error.issues.slice(0, 6);
        throw err;
    }
    return parsed.data.d.map((drill) => normalizeAiDrillValue(drill, { ageBand: params.ageBand, objective: params.objective }));
}
const aiVisualPlanSchema = zod_1.z.object({
    c: zod_1.z.array(zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()])).min(2).max(12),
    f: zod_1.z.array(zod_1.z.object({
        p1: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]),
        p2: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]),
        b: zod_1.z.tuple([zod_1.z.number(), zod_1.z.number()]).optional(),
    })).min(3).max(12)
});
function coerceVisualPlan(raw) {
    const root = raw && typeof raw === 'object' ? raw : {};
    return {
        c: readPointPairs(root?.c ?? root?.cones ?? root?.visual?.c ?? root?.v?.c),
        f: readVisualFrames(root?.f ?? root?.frames ?? root?.visual?.f ?? root?.v?.f),
    };
}
async function generateVisualPlanWithOpenAI(params) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
        const err = new Error('OPENAI_API_KEY is missing');
        err.code = 'OPENAI_API_KEY_MISSING';
        throw err;
    }
    const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
    const input = [
        {
            role: 'system',
            content: [
                {
                    type: 'input_text',
                    text: 'Tu crées uniquement un plan visuel de diagramme football jeunes. Réponds en JSON compact valide sans markdown. Format strict: {"c":[[20,30],[80,50],[45,80]],"f":[{"p1":[10,70],"p2":[30,80],"b":[10,70]}]}.'
                }
            ]
        },
        {
            role: 'user',
            content: [
                {
                    type: 'input_text',
                    text: `Exercice:${params.title}\nCategorie:${params.category}\nAge:${params.ageBand}\nObjectif:${params.objective || params.title}\nTags:${params.tags.join(',')}\nDescription:${params.description}\nContraintes: produire 10 frames cohérentes avec le texte; p1=joueur principal, p2=soutien; b=ballon; coordonnées 0..100; trajectoires lisibles; schéma différent des exercices classiques (éviter ligne droite simple).`
                }
            ]
        }
    ];
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let response;
    try {
        try {
            response = await fetch('https://api.openai.com/v1/responses', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    model,
                    input,
                    temperature: 0.3,
                    max_output_tokens: 1100,
                    text: { format: { type: 'json_object' } }
                }),
                signal: controller.signal,
            });
        }
        catch (e) {
            const err = new Error('OpenAI network request failed');
            err.code = e?.name === 'AbortError' ? 'OPENAI_TIMEOUT' : 'OPENAI_NETWORK_ERROR';
            err.detail = e?.message || String(e);
            throw err;
        }
    }
    finally {
        clearTimeout(timeout);
    }
    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        const parsedDetail = safeParseJSON(detail);
        const err = new Error(`OpenAI request failed (${response.status})`);
        err.code = 'OPENAI_REQUEST_FAILED';
        err.status = response.status;
        err.detail = detail.slice(0, 500);
        err.openai = parsedDetail?.error || null;
        throw err;
    }
    const payload = await response.json();
    const rawText = typeof payload?.output_text === 'string'
        ? payload.output_text
        : Array.isArray(payload?.output)
            ? payload.output
                .flatMap((item) => Array.isArray(item?.content) ? item.content : [])
                .map((chunk) => chunk?.text || '')
                .join('\n')
            : '';
    const parsedJson = safeParseJSON(rawText);
    if (!parsedJson) {
        const err = new Error('OpenAI response is not valid JSON');
        err.code = 'OPENAI_INVALID_JSON';
        err.raw = String(rawText || '').slice(0, 2000);
        throw err;
    }
    const strict = aiVisualPlanSchema.safeParse(parsedJson);
    const value = strict.success ? strict.data : coerceVisualPlan(parsedJson);
    const parsed = aiVisualPlanSchema.safeParse(value);
    if (!parsed.success) {
        const err = new Error('OpenAI visual response schema mismatch');
        err.code = 'OPENAI_SCHEMA_MISMATCH';
        err.raw = JSON.stringify(parsedJson).slice(0, 2000);
        err.coerced = JSON.stringify(value).slice(0, 2000);
        err.issues = parsed.error.issues.slice(0, 6);
        throw err;
    }
    const clampPoint = ([x, y]) => [
        Math.max(0, Math.min(100, Math.round(x))),
        Math.max(0, Math.min(100, Math.round(y))),
    ];
    return {
        c: parsed.data.c.map(clampPoint).slice(0, 4),
        f: normalizeFrameSeries(parsed.data.f.map((frame) => ({
            p1: clampPoint(frame.p1),
            p2: clampPoint(frame.p2),
            b: frame.b ? clampPoint(frame.b) : clampPoint(frame.p1),
        }))).slice(0, 10),
    };
}
function summarizeErrorForLog(error) {
    return {
        code: error?.code || null,
        status: error?.status || null,
        message: error?.message || String(error),
        detail: error?.detail || null,
        openai: error?.openai || null,
        issues: error?.issues || null,
        raw: error?.raw || null,
        stack: typeof error?.stack === 'string' ? error.stack.split('\n').slice(0, 4).join('\n') : null,
    };
}
function normalizePublicTeamLabel(raw, fallback) {
    const normalized = String(raw || '').trim().toUpperCase();
    if (!normalized)
        return fallback;
    if (normalized === 'HOME')
        return 'A';
    if (normalized === 'AWAY')
        return 'B';
    return normalized;
}
function buildPublicMatchdayRotation(matches) {
    if (!matches.length)
        return null;
    const slots = matches.map((match, index) => {
        const orderedTeams = match.teams.slice().sort((a, b) => a.side.localeCompare(b.side));
        const teamA = normalizePublicTeamLabel(orderedTeams[0]?.side, 'A');
        const teamB = (match.opponentName && match.opponentName.trim().length > 0)
            ? match.opponentName.trim()
            : normalizePublicTeamLabel(orderedTeams[1]?.side, 'B');
        return {
            time: match.createdAt.toISOString(),
            games: [{ pitch: `Terrain ${index + 1}`, A: teamA, B: teamB }]
        };
    });
    const teamsByLabel = new Map();
    for (const slot of slots) {
        for (const game of slot.games) {
            if (game.A && !teamsByLabel.has(game.A))
                teamsByLabel.set(game.A, { label: game.A });
            if (game.B && !teamsByLabel.has(game.B))
                teamsByLabel.set(game.B, { label: game.B });
        }
    }
    const updatedAt = matches.reduce((latest, current) => current.updatedAt > latest ? current.updatedAt : latest, matches[0].updatedAt);
    return (0, matchday_contract_1.normalizeRotationForContract)({
        updatedAt: updatedAt.toISOString(),
        teams: Array.from(teamsByLabel.values()),
        slots,
    }, updatedAt.toISOString());
}
function normalizePublicRotation(candidate, defaultUpdatedAtIso) {
    return (0, matchday_contract_1.normalizeRotationForContract)(candidate, defaultUpdatedAtIso);
}
function findRotationCandidate(data) {
    if (!data || typeof data !== 'object')
        return null;
    const directCandidates = [
        data.rotation,
        data?.data?.rotation,
        data?.planning?.rotation,
        data?.schedule?.rotation,
        data?.rotationData,
        data,
    ];
    for (const c of directCandidates) {
        if (c && typeof c === 'object' && Array.isArray(c.slots))
            return c;
    }
    return null;
}
function buildPlanningScopeForMatchday(matchday) {
    if (matchday.userId)
        return { userId: matchday.userId };
    if (matchday.teamId)
        return { teamId: matchday.teamId };
    if (matchday.clubId)
        return { clubId: matchday.clubId };
    return {};
}
async function findLatestPlanningForMatchday(db, matchday) {
    const dayStart = new Date(matchday.date);
    dayStart.setHours(0, 0, 0, 0);
    const dayEnd = new Date(dayStart);
    dayEnd.setDate(dayEnd.getDate() + 1);
    const scope = buildPlanningScopeForMatchday(matchday);
    return db.planning.findFirst({
        where: {
            date: { gte: dayStart, lt: dayEnd },
            ...scope,
        },
        orderBy: { updatedAt: 'desc' },
    });
}
function findPlanningMatchdayIdCandidate(data) {
    if (!data || typeof data !== 'object')
        return null;
    const directCandidates = [
        data.matchdayId,
        data?.data?.matchdayId,
        data?.planning?.matchdayId,
        data?.rotation?.matchdayId,
        data?.meta?.matchdayId,
        data.plateauId,
        data?.data?.plateauId,
        data?.planning?.plateauId,
        data?.rotation?.plateauId,
        data?.meta?.plateauId,
    ];
    for (const candidate of directCandidates) {
        if (typeof candidate === 'string' && candidate.trim().length > 0)
            return candidate.trim();
    }
    return null;
}
async function findMatchdayLinkedToPlanning(db, planning, scopeOrUserId, planningData) {
    const explicitMatchdayId = findPlanningMatchdayIdCandidate(planningData);
    if (explicitMatchdayId) {
        return matchdayFindFirstForUser(db, scopeOrUserId, { where: { id: explicitMatchdayId }, select: { id: true } });
    }
    const dayStart = new Date(planning.date);
    dayStart.setHours(0, 0, 0, 0);
    const dayEnd = new Date(dayStart);
    dayEnd.setDate(dayEnd.getDate() + 1);
    return matchdayFindFirstForUser(db, scopeOrUserId, {
        where: {
            date: { gte: dayStart, lt: dayEnd },
            ...(planning.userId ? { userId: planning.userId } : {}),
        },
        orderBy: { updatedAt: 'desc' },
        select: { id: true },
    });
}
async function applyTeamAbsenceOnMatchdayTx(input) {
    const keyedRotation = (0, matchday_absence_1.ensureRotationGameKeys)(input.rotation);
    const targetRotationGameKeys = (0, matchday_absence_1.findRotationGameKeysForTeam)(keyedRotation, input.teamLabel);
    if (!targetRotationGameKeys.length) {
        return { impactedCount: 0, updatedCount: 0 };
    }
    const matchdayMatches = await matchFindManyForUser(input.tx, input.auth, {
        where: {
            plateauId: input.matchdayId,
            OR: [
                { rotationGameKey: { in: targetRotationGameKeys } },
                { opponentName: { equals: input.teamLabel, mode: 'insensitive' } },
            ],
        },
        select: { id: true, status: true, played: true },
    });
    const patches = (0, matchday_absence_1.buildAbsenceMatchPatches)({ matches: matchdayMatches, absent: input.absent });
    if (!patches.length) {
        return { impactedCount: matchdayMatches.length, updatedCount: 0 };
    }
    const groups = new Map();
    for (const patch of patches) {
        const key = `${patch.status}:${patch.played ? '1' : '0'}`;
        if (!groups.has(key))
            groups.set(key, []);
        groups.get(key).push(patch.id);
    }
    for (const [key, ids] of groups.entries()) {
        const [status, playedToken] = key.split(':');
        await input.tx.match.updateMany({
            where: { id: { in: ids } },
            data: { status, played: playedToken === '1' },
        });
    }
    return { impactedCount: matchdayMatches.length, updatedCount: patches.length };
}
async function getPublicMatchdayPayloadByToken(token) {
    let share;
    try {
        share = await prisma.plateauShareToken.findFirst({
            where: {
                OR: [
                    { token },
                    { id: token }, // compat if frontend accidentally stores share row id instead of token
                ]
            },
            include: { plateau: true }
        });
    }
    catch (e) {
        if (e?.code === 'P2021') {
            return { status: 503, body: { error: 'Public sharing is not ready on this environment' } };
        }
        throw e;
    }
    if (!share)
        return { status: 404, body: { error: 'Invalid link' } };
    if (share.expiresAt && share.expiresAt < new Date())
        return { status: 410, body: { error: 'Link expired' } };
    const matchesRaw = await prisma.match.findMany({
        where: { plateauId: share.plateauId },
        select: {
            id: true,
            createdAt: true,
            updatedAt: true,
            status: true,
            played: true,
            rotationGameKey: true,
            opponentName: true,
            teams: { select: { side: true, score: true } }
        },
        orderBy: { createdAt: 'asc' }
    });
    const hasPersistedRotationKey = matchesRaw.some((m) => typeof m.rotationGameKey === 'string' && m.rotationGameKey.trim().length > 0);
    // Prefer rotation saved by the planning editor (same day + best available scope).
    let hasPlanningRotation = false;
    let rotation = null;
    const planning = await findLatestPlanningForMatchday(prisma, {
        date: share.plateau.date,
        userId: share.plateau.userId ?? null,
        teamId: share.plateau.teamId ?? null,
        clubId: share.plateau.clubId ?? null,
    });
    if (planning) {
        const planningData = safeParseJSON(planning.data);
        const candidate = findRotationCandidate(planningData);
        hasPlanningRotation = Boolean(candidate);
        rotation = normalizePublicRotation(candidate, planning.updatedAt.toISOString());
    }
    const mode = (0, matchday_contract_1.deriveMatchdayMode)({ hasPersistedRotationKey, hasPlanningRotation });
    if (mode === 'ROTATION' && !rotation) {
        const fallbackRotationMatches = matchesRaw.map((m) => ({
            createdAt: m.createdAt,
            updatedAt: m.updatedAt,
            opponentName: m.opponentName ?? null,
            teams: (m.teams || []).map((team) => ({ side: team.side })),
        }));
        rotation = buildPublicMatchdayRotation(fallbackRotationMatches);
    }
    const publicMatches = (0, matchday_contract_1.ensureRotationGameKeysForContract)(matchesRaw.map((match) => {
        const status = (0, match_status_1.resolveMatchStatus)({ status: match.status, played: Boolean(match.played) });
        return {
            id: match.id,
            matchdayId: share.plateauId,
            status,
            played: (0, match_status_1.derivePlayedFromStatus)(status),
            rotationGameKey: match.rotationGameKey ?? null,
            teams: (match.teams || []).map((team) => ({
                side: team.side,
                score: team.score ?? 0,
            })),
        };
    }), mode === 'ROTATION');
    return {
        status: 200,
        body: {
            mode,
            matchday: (0, matchday_metadata_1.toPublicMatchday)(share.plateau),
            rotation: mode === 'ROTATION' ? (rotation || { updatedAt: new Date().toISOString(), teams: [], slots: [] }) : null,
            matches: publicMatches,
            rotationGameKeyFormat: {
                canonical: 'schedule:{index}',
                accepts: ['schedule:*', 'legacy:*'],
            },
        }
    };
}
app.post('/auth/register', async (req, res) => {
    const schema = zod_1.z.object({
        email: zod_1.z.string().email(),
        password: zod_1.z.string().min(6),
        clubName: zod_1.z.string().trim().min(2).optional(),
        // Backward compatibility for old front payloads.
        club: zod_1.z.string().trim().min(2).optional(),
        role: zod_1.z.enum(['DIRECTION']).optional()
    }).refine((data) => Boolean(data.clubName || data.club), {
        path: ['clubName'],
        message: 'Required'
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
        const firstIssue = parsed.error.issues[0];
        return res.status(400).json({ error: firstIssue?.message || parsed.error.flatten() });
    }
    const { email, password } = parsed.data;
    const clubName = parsed.data.clubName || parsed.data.club;
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
        return res.status(409).json({ error: 'Email already in use' });
    const passwordHash = await bcryptjs_1.default.hash(password, 10);
    const club = await prisma.club.create({ data: { name: clubName } });
    const user = await prisma.user.create({
        data: { email, passwordHash, role: 'DIRECTION', clubId: club.id }
    });
    const token = signToken(user.id);
    res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts());
    res.json({
        id: user.id,
        email: user.email,
        isPremium: user.isPremium,
        role: user.role,
        clubId: user.clubId,
        teamId: user.teamId,
        managedTeamIds: user.managedTeamIds
    });
});
app.post('/auth/login', async (req, res) => {
    const schema = zod_1.z.object({ email: zod_1.z.string().email(), password: zod_1.z.string() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { email, password } = parsed.data;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
        return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcryptjs_1.default.compare(password, user.passwordHash);
    if (!ok)
        return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken(user.id);
    res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts());
    res.json({
        id: user.id,
        email: user.email,
        isPremium: user.isPremium,
        role: user.role,
        clubId: user.clubId,
        teamId: user.teamId,
        managedTeamIds: user.managedTeamIds
    });
});
app.get('/auth/invitations/:token', async (req, res) => {
    const invite = await prisma.accountInvite.findUnique({
        where: { token: req.params.token },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            status: true,
            expiresAt: true,
            teamId: true,
            managedTeamIds: true,
            ...getPlayerInviteLinkSelect()
        }
    });
    if (!invite)
        return res.status(404).json({ error: 'Invitation not found' });
    if (invite.status !== 'PENDING')
        return res.status(409).json({ error: `Invitation is ${invite.status.toLowerCase()}` });
    if (invite.expiresAt < new Date()) {
        await prisma.accountInvite.update({
            where: { id: invite.id },
            data: { status: 'EXPIRED' }
        });
        return res.status(410).json({ error: 'Invitation expired' });
    }
    res.json(invite);
});
app.post('/auth/invitations/accept', async (req, res) => {
    const schema = zod_1.z.object({
        token: zod_1.z.string().min(8),
        password: zod_1.z.string().min(6)
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const invite = await prisma.accountInvite.findUnique({ where: { token: parsed.data.token } });
    if (!invite)
        return res.status(404).json({ error: 'Invitation not found' });
    if (invite.status !== 'PENDING')
        return res.status(409).json({ error: `Invitation is ${invite.status.toLowerCase()}` });
    if (invite.expiresAt < new Date()) {
        await prisma.accountInvite.update({
            where: { id: invite.id },
            data: { status: 'EXPIRED' }
        });
        return res.status(410).json({ error: 'Invitation expired' });
    }
    const inviteLinkedPlayerId = ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID ? invite?.linkedPlayerId ?? null : null;
    const existing = await prisma.user.findUnique({ where: { email: invite.email } });
    if (existing)
        return res.status(409).json({ error: 'Email already in use' });
    const passwordHash = await bcryptjs_1.default.hash(parsed.data.password, 10);
    const { user } = await prisma.$transaction(async (tx) => {
        const createdUser = await tx.user.create({
            data: {
                email: invite.email,
                passwordHash,
                firstName: invite.firstName,
                lastName: invite.lastName,
                phone: invite.phone,
                role: invite.role,
                clubId: invite.clubId,
                teamId: invite.teamId,
                managedTeamIds: invite.managedTeamIds,
                linkedPlayerUserId: invite.linkedPlayerUserId
            }
        });
        if (inviteLinkedPlayerId && invite.role === 'PLAYER') {
            await tx.player.updateMany({
                where: {
                    id: inviteLinkedPlayerId,
                    ...(invite.clubId ? { clubId: invite.clubId } : {}),
                },
                data: { userId: createdUser.id }
            });
        }
        await tx.accountInvite.update({
            where: { id: invite.id },
            data: {
                status: 'ACCEPTED',
                acceptedAt: new Date(),
                userId: createdUser.id
            }
        });
        await tx.accountInvite.updateMany({
            where: {
                clubId: invite.clubId,
                email: invite.email,
                status: 'PENDING',
                id: { not: invite.id }
            },
            data: { status: 'CANCELLED' }
        });
        return { user: createdUser };
    });
    const token = signToken(user.id);
    res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts());
    res.json({
        id: user.id,
        email: user.email,
        isPremium: user.isPremium,
        role: user.role,
        clubId: user.clubId,
        teamId: user.teamId,
        managedTeamIds: user.managedTeamIds
    });
});
app.post('/auth/logout', (req, res) => {
    res.clearCookie(AUTH_COOKIE_NAME, authClearCookieOpts());
    res.json({ ok: true });
});
app.get('/me', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token) {
        return res.json({
            id: null,
            email: null,
            firstName: null,
            lastName: null,
            phone: null,
            isPremium: false,
            planningCount: 0,
            anonymous: true,
            role: null,
            clubId: null,
            teamId: null,
            managedTeamIds: []
        });
    }
    return next();
}, authMiddleware, async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } });
    if (!user)
        return res.status(404).json({ error: 'User not found' });
    const planningCount = user.plannings.length;
    res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName ?? null,
        lastName: user.lastName ?? null,
        phone: user.phone ?? null,
        isPremium: user.isPremium,
        planningCount,
        role: user.role,
        clubId: user.clubId,
        teamId: user.teamId,
        managedTeamIds: user.managedTeamIds
    });
});
app.get('/me/child', authMiddleware, async (req, res) => {
    if (req.auth?.role !== 'PARENT')
        return res.json(null);
    let linkedPlayerId = null;
    if (ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID) {
        const acceptedInvite = await prisma.accountInvite.findFirst({
            where: {
                userId: req.auth.id,
                role: 'PARENT',
                status: 'ACCEPTED',
                ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
                linkedPlayerId: { not: null },
            },
            select: { linkedPlayerId: true },
            orderBy: [{ acceptedAt: 'desc' }, { updatedAt: 'desc' }],
        });
        linkedPlayerId = acceptedInvite?.linkedPlayerId ?? null;
    }
    let linkedPlayer = null;
    if (linkedPlayerId) {
        linkedPlayer = await prisma.player.findFirst({
            where: {
                id: linkedPlayerId,
                ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
            },
            select: {
                id: true,
                name: true,
                first_name: true,
                last_name: true,
                email: true,
                phone: true,
                teamId: true,
                is_child: true,
                parent_first_name: true,
                parent_last_name: true,
            }
        });
    }
    if (!linkedPlayer) {
        const parentUser = await prisma.user.findUnique({
            where: { id: req.auth.id },
            select: { linkedPlayerUserId: true },
        });
        const candidateUserIds = [
            parentUser?.linkedPlayerUserId ?? null,
            req.auth.id,
        ].filter((value, index, arr) => Boolean(value) && arr.indexOf(value) === index);
        if (!candidateUserIds.length)
            return res.json(null);
        linkedPlayer = await prisma.player.findFirst({
            where: {
                userId: { in: candidateUserIds },
                ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
            },
            select: {
                id: true,
                name: true,
                first_name: true,
                last_name: true,
                email: true,
                phone: true,
                teamId: true,
                is_child: true,
                parent_first_name: true,
                parent_last_name: true,
            }
        });
    }
    if (!linkedPlayer)
        return res.json(null);
    const linkedTeam = await prisma.team.findFirst({
        where: {
            id: linkedPlayer.teamId,
            ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
        },
        select: { name: true },
    });
    const normalizedPlayer = (0, player_payload_1.normalizePlayerForApi)(linkedPlayer);
    return res.json({
        ...normalizedPlayer,
        teamName: linkedTeam?.name ?? null,
    });
});
app.put('/me/profile', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        firstName: zod_1.z.string().trim().min(1).max(80).optional(),
        lastName: zod_1.z.string().trim().min(1).max(80).optional(),
        phone: zod_1.z.string().trim().min(3).max(32).nullable().optional(),
        email: zod_1.z.string().trim().email().optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const patch = {};
    if (parsed.data.firstName !== undefined)
        patch.firstName = parsed.data.firstName;
    if (parsed.data.lastName !== undefined)
        patch.lastName = parsed.data.lastName;
    if (parsed.data.phone !== undefined)
        patch.phone = parsed.data.phone;
    if (parsed.data.email !== undefined)
        patch.email = normEmail(parsed.data.email);
    if (Object.keys(patch).length === 0)
        return res.status(400).json({ error: 'No profile fields provided' });
    if (patch.email) {
        const existing = await prisma.user.findUnique({
            where: { email: patch.email },
            select: { id: true }
        });
        if (existing && existing.id !== req.auth.id) {
            return res.status(409).json({ error: 'Email already in use' });
        }
    }
    const updated = await prisma.user.update({
        where: { id: req.auth.id },
        data: patch,
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            isPremium: true,
            role: true,
            clubId: true,
            teamId: true,
            managedTeamIds: true,
        }
    });
    res.json(updated);
});
app.put('/me/team', authMiddleware, async (req, res) => {
    if (!req.auth?.clubId)
        return res.status(400).json({ error: 'No club attached to account' });
    if (req.auth?.role !== 'DIRECTION' && req.auth?.role !== 'COACH') {
        return res.status(403).json({ error: 'Only direction and coach accounts can change active team' });
    }
    const schema = zod_1.z.object({ teamId: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const requestedTeamId = parsed.data.teamId;
    if (req.auth.role === 'COACH') {
        const managedIds = Array.isArray(req.auth.managedTeamIds) ? req.auth.managedTeamIds : [];
        if (!managedIds.includes(requestedTeamId)) {
            return res.status(403).json({ error: 'Coach cannot select an unmanaged team' });
        }
    }
    const team = await prisma.team.findFirst({
        where: {
            id: requestedTeamId,
            clubId: req.auth.clubId
        },
        select: { id: true }
    });
    if (!team)
        return res.status(404).json({ error: 'Team not found in club' });
    const updated = await prisma.user.update({
        where: { id: req.auth.id },
        data: { teamId: team.id },
        select: {
            id: true,
            email: true,
            role: true,
            clubId: true,
            teamId: true,
            managedTeamIds: true
        }
    });
    res.json(updated);
});
app.get('/clubs/me', authMiddleware, async (req, res) => {
    if (!req.auth?.clubId)
        return res.status(404).json({ error: 'Club not found' });
    const club = await prisma.club.findUnique({
        where: { id: req.auth.clubId },
        include: {
            teams: { orderBy: { name: 'asc' } },
            users: {
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                    phone: true,
                    role: true,
                    teamId: true,
                    managedTeamIds: true,
                    linkedPlayerUserId: true,
                    createdAt: true
                },
                orderBy: { createdAt: 'asc' }
            }
        }
    });
    if (!club)
        return res.status(404).json({ error: 'Club not found' });
    res.json({
        ...club,
        teams: (club.teams || []).map(withTeamFormatAliases),
    });
});
app.get('/clubs/me/coaches', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(404).json({ error: 'Club not found' });
    await prisma.accountInvite.updateMany({
        where: {
            clubId: req.auth.clubId,
            role: 'COACH',
            status: 'PENDING',
            expiresAt: { lt: new Date() }
        },
        data: { status: 'EXPIRED' }
    });
    const [coaches, invites] = await Promise.all([
        prisma.user.findMany({
            where: { clubId: req.auth.clubId, role: 'COACH' },
            select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                phone: true,
                teamId: true,
                managedTeamIds: true,
                createdAt: true,
                team: { select: { name: true } },
            },
            orderBy: [{ createdAt: 'desc' }, { email: 'asc' }]
        }),
        prisma.accountInvite.findMany({
            where: { clubId: req.auth.clubId, role: 'COACH' },
            select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                phone: true,
                teamId: true,
                status: true,
                managedTeamIds: true,
                createdAt: true,
            },
            orderBy: [{ createdAt: 'desc' }]
        })
    ]);
    const teamIds = new Set();
    for (const coach of coaches)
        if (coach.teamId)
            teamIds.add(coach.teamId);
    for (const invite of invites)
        if (invite.teamId)
            teamIds.add(invite.teamId);
    const teams = teamIds.size
        ? await prisma.team.findMany({
            where: { id: { in: Array.from(teamIds) }, clubId: req.auth.clubId },
            select: { id: true, name: true }
        })
        : [];
    const teamNameById = new Map(teams.map((team) => [team.id, team.name]));
    const acceptedEmails = new Set(coaches.map((coach) => normEmail(coach.email)));
    const seenInviteEmails = new Set();
    const pendingItems = invites.filter((invite) => {
        const email = normEmail(invite.email);
        if (acceptedEmails.has(email))
            return false;
        if (seenInviteEmails.has(email))
            return false;
        seenInviteEmails.add(email);
        return true;
    });
    res.json([
        ...coaches.map(toCoachSummaryFromUser),
        ...pendingItems.map((invite) => toCoachSummaryFromInvite({
            ...invite,
            teamName: invite.teamId ? (teamNameById.get(invite.teamId) ?? null) : null
        })),
    ]);
});
app.get('/coaches/:id', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(404).json({ error: 'Club not found' });
    await prisma.accountInvite.updateMany({
        where: {
            clubId: req.auth.clubId,
            role: 'COACH',
            status: 'PENDING',
            expiresAt: { lt: new Date() }
        },
        data: { status: 'EXPIRED' }
    });
    const coach = await prisma.user.findFirst({
        where: {
            id: req.params.id,
            clubId: req.auth.clubId,
            role: 'COACH'
        },
        select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            phone: true,
            teamId: true,
            managedTeamIds: true,
            createdAt: true,
            team: { select: { name: true } },
        }
    });
    if (coach) {
        return res.json({
            ...toCoachSummaryFromUser(coach),
            role: 'COACH',
            managedTeamIds: coach.managedTeamIds,
            createdAt: coach.createdAt,
        });
    }
    const invite = await prisma.accountInvite.findFirst({
        where: {
            id: req.params.id,
            clubId: req.auth.clubId,
            role: 'COACH'
        },
        select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            phone: true,
            status: true,
            teamId: true,
            managedTeamIds: true,
            invitedByUserId: true,
            expiresAt: true,
            acceptedAt: true,
            createdAt: true,
            updatedAt: true,
        }
    });
    if (!invite)
        return res.status(404).json({ error: 'Coach not found' });
    const teamName = invite.teamId
        ? await prisma.team.findFirst({
            where: { id: invite.teamId, clubId: req.auth.clubId },
            select: { name: true }
        }).then((team) => team?.name ?? null)
        : null;
    return res.json({
        ...toCoachSummaryFromInvite({ ...invite, teamName }),
        role: 'COACH',
        managedTeamIds: invite.managedTeamIds,
        invitedByUserId: invite.invitedByUserId,
        expiresAt: invite.expiresAt,
        acceptedAt: invite.acceptedAt,
        createdAt: invite.createdAt,
        updatedAt: invite.updatedAt,
    });
});
app.put('/clubs/me', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(404).json({ error: 'Club not found' });
    const schema = zod_1.z.object({
        name: zod_1.z.string().min(2).max(120)
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const updated = await prisma.club.update({
        where: { id: req.auth.clubId },
        data: { name: parsed.data.name.trim() }
    });
    res.json(updated);
});
app.get('/teams', authMiddleware, async (req, res) => {
    if (!req.auth?.clubId)
        return res.json([]);
    const teams = await prisma.team.findMany({
        where: { clubId: req.auth.clubId },
        orderBy: { name: 'asc' },
        select: {
            id: true,
            name: true,
            category: true,
            format: true,
            clubId: true,
            createdAt: true,
        },
    });
    res.json(teams.map(normalizeTeamResponse));
});
app.post('/teams', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(400).json({ error: 'Direction account must be attached to a club' });
    const parsed = teamUpsertPayloadSchema.safeParse(req.body);
    if (!parsed.success) {
        const message = parsed.error.issues[0]?.message || 'Invalid team payload';
        logTeamValidationFailure('POST /teams', message, { clubId: req.auth.clubId });
        return res.status(400).json({ error: message });
    }
    const categoryResult = (0, team_category_1.normalizeTeamCategory)(parsed.data.category);
    if (!categoryResult.ok) {
        logTeamValidationFailure('POST /teams', categoryResult.error, {
            clubId: req.auth.clubId,
            category: parsed.data.category,
        });
        return res.status(400).json({ error: categoryResult.error });
    }
    const formatResult = (0, team_format_1.normalizeTeamFormat)(parsed.data.format);
    if (!formatResult.ok) {
        logTeamValidationFailure('POST /teams', formatResult.error, {
            clubId: req.auth.clubId,
            format: parsed.data.format,
        });
        return res.status(400).json({ error: formatResult.error });
    }
    const providedName = typeof parsed.data.name === 'string' ? parsed.data.name.trim() : '';
    const finalName = providedName || await generateAutoTeamName(req.auth.clubId, categoryResult.category);
    try {
        const team = await prisma.team.create({
            data: { name: finalName, category: categoryResult.category, format: formatResult.format, clubId: req.auth.clubId },
            select: {
                id: true,
                name: true,
                category: true,
                format: true,
                clubId: true,
                createdAt: true,
            },
        });
        return res.status(201).json(normalizeTeamResponse(team));
    }
    catch (e) {
        if (e?.code === 'P2002') {
            return res.status(409).json({ error: 'Team name already exists in this club' });
        }
        throw e;
    }
});
app.put('/teams/:id', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(400).json({ error: 'Direction account must be attached to a club' });
    const parsed = teamUpsertPayloadSchema.safeParse(req.body);
    if (!parsed.success) {
        const message = parsed.error.issues[0]?.message || 'Invalid team payload';
        logTeamValidationFailure('PUT /teams/:id', message, {
            clubId: req.auth.clubId,
            teamId: req.params.id,
        });
        return res.status(400).json({ error: message });
    }
    const categoryResult = (0, team_category_1.normalizeTeamCategory)(parsed.data.category);
    if (!categoryResult.ok) {
        logTeamValidationFailure('PUT /teams/:id', categoryResult.error, {
            clubId: req.auth.clubId,
            teamId: req.params.id,
            category: parsed.data.category,
        });
        return res.status(400).json({ error: categoryResult.error });
    }
    const formatResult = (0, team_format_1.normalizeTeamFormat)(parsed.data.format);
    if (!formatResult.ok) {
        logTeamValidationFailure('PUT /teams/:id', formatResult.error, {
            clubId: req.auth.clubId,
            teamId: req.params.id,
            format: parsed.data.format,
        });
        return res.status(400).json({ error: formatResult.error });
    }
    const existingTeam = await prisma.team.findFirst({
        where: { id: req.params.id, clubId: req.auth.clubId },
        select: { id: true },
    });
    if (!existingTeam)
        return res.status(404).json({ error: 'Team not found' });
    const providedName = typeof parsed.data.name === 'string' ? parsed.data.name.trim() : '';
    const finalName = providedName || await generateAutoTeamName(req.auth.clubId, categoryResult.category, { excludeTeamId: existingTeam.id });
    try {
        const updated = await prisma.team.update({
            where: { id: existingTeam.id },
            data: {
                name: finalName,
                category: categoryResult.category,
                format: formatResult.format,
            },
            select: {
                id: true,
                name: true,
                category: true,
                format: true,
                clubId: true,
                createdAt: true,
            },
        });
        return res.json(normalizeTeamResponse(updated));
    }
    catch (e) {
        if (e?.code === 'P2002') {
            return res.status(409).json({ error: 'Team name already exists in this club' });
        }
        throw e;
    }
});
app.delete('/teams/:id', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(400).json({ error: 'Direction account must be attached to a club' });
    const team = await prisma.team.findFirst({
        where: { id: req.params.id, clubId: req.auth.clubId },
        select: { id: true },
    });
    if (!team)
        return res.status(404).json({ error: 'Team not found' });
    try {
        await prisma.team.delete({ where: { id: team.id } });
        return res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2003' || e?.code === 'P2014') {
            return res.status(409).json({ error: 'Cannot delete team because it is still referenced by related data' });
        }
        throw e;
    }
});
app.post('/accounts', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.status(400).json({ error: 'Direction account must be attached to a club' });
    const normalized = normalizeCoachPayload(req.body);
    const schema = zod_1.z.object({
        role: zod_1.z.enum(['COACH']),
        firstName: zod_1.z.string().min(1, 'firstName is required').max(80),
        lastName: zod_1.z.string().min(1, 'lastName is required').max(80),
        email: zod_1.z.string().email('Invalid email format'),
        phone: zod_1.z.string().min(3).max(32).nullable().optional(),
        teamId: zod_1.z.string().min(1, 'teamId is required'),
        managedTeamIds: zod_1.z.array(zod_1.z.string().min(1)).optional(),
        expiresInDays: zod_1.z.coerce.number().int().min(1).max(30).optional()
    });
    const parsed = schema.safeParse(normalized);
    if (!parsed.success) {
        const firstIssue = parsed.error.issues[0];
        return res.status(400).json({ error: firstIssue?.message || parsed.error.flatten() });
    }
    const email = normEmail(parsed.data.email);
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
        return res.status(409).json({ error: 'Email already in use' });
    const selectedTeam = await prisma.team.findFirst({
        where: {
            id: parsed.data.teamId,
            clubId: req.auth.clubId
        },
        select: { id: true, name: true }
    });
    if (!selectedTeam)
        return res.status(404).json({ error: 'Team not found in club' });
    const requestedManagedTeamIds = parsed.data.managedTeamIds || [];
    const filteredManagedTeamIds = requestedManagedTeamIds.length
        ? await prisma.team.findMany({
            where: {
                id: { in: requestedManagedTeamIds },
                clubId: req.auth.clubId
            },
            select: { id: true }
        }).then((rows) => rows.map((row) => row.id))
        : [];
    const managedTeamIds = Array.from(new Set([selectedTeam.id, ...filteredManagedTeamIds]));
    await prisma.accountInvite.updateMany({
        where: {
            clubId: req.auth.clubId,
            email,
            status: 'PENDING'
        },
        data: { status: 'CANCELLED' }
    });
    const inviteToken = (0, nanoid_1.nanoid)(48);
    const expiresAt = (0, date_fns_1.addDays)(new Date(), parsed.data.expiresInDays ?? 7);
    const created = await prisma.accountInvite.create({
        data: {
            email,
            firstName: parsed.data.firstName,
            lastName: parsed.data.lastName,
            phone: parsed.data.phone ?? null,
            token: inviteToken,
            role: 'COACH',
            clubId: req.auth.clubId,
            invitedByUserId: req.auth.id,
            teamId: selectedTeam.id,
            managedTeamIds,
            expiresAt
        },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            token: true,
            role: true,
            clubId: true,
            teamId: true,
            managedTeamIds: true,
            linkedPlayerUserId: true,
            status: true,
            expiresAt: true,
            createdAt: true
        }
    });
    const acceptPath = process.env.INVITE_ACCEPT_PATH || '/invite/accept';
    const inviteUrl = `${APP_BASE_URL.replace(/\/+$/, '')}${acceptPath}?token=${encodeURIComponent(created.token)}`;
    if (transporter) {
        try {
            await transporter.sendMail({
                from: process.env.SMTP_FROM || 'no-reply@example.com',
                to: created.email,
                subject: 'Invitation Izifoot',
                html: `<p>Vous avez ete invite sur Izifoot.</p>
<p>Pour finaliser votre compte et definir votre mot de passe, cliquez ici :</p>
<p><a href="${inviteUrl}">${inviteUrl}</a></p>
<p>Ce lien expire le ${created.expiresAt.toISOString()}.</p>`
            });
        }
        catch (e) {
            console.warn('[accounts invite] email failed:', e);
        }
    }
    res.status(201).json({ ...created, inviteUrl });
});
app.get('/accounts', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.json([]);
    const users = await prisma.user.findMany({
        where: { clubId: req.auth.clubId },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            teamId: true,
            managedTeamIds: true,
            linkedPlayerUserId: true,
            createdAt: true,
        },
        orderBy: [{ createdAt: 'desc' }, { email: 'asc' }]
    });
    const userIds = users.map((user) => user.id);
    const linkedPlayers = userIds.length
        ? await prisma.player.findMany({
            where: {
                userId: { in: userIds },
                ...(req.auth.clubId ? { clubId: req.auth.clubId } : {}),
            },
            select: { id: true, userId: true }
        })
        : [];
    const playerIdByUserId = new Map();
    for (const linkedPlayer of linkedPlayers) {
        if (linkedPlayer.userId)
            playerIdByUserId.set(linkedPlayer.userId, linkedPlayer.id);
    }
    res.json(users.map((user) => ({
        ...user,
        linkedPlayerId: playerIdByUserId.get(user.id) ?? null,
        playerId: playerIdByUserId.get(user.id) ?? null,
    })));
});
app.get('/accounts/invitations', authMiddleware, async (req, res) => {
    if (!ensureDirection(req, res))
        return;
    if (!req.auth?.clubId)
        return res.json([]);
    await prisma.accountInvite.updateMany({
        where: {
            clubId: req.auth.clubId,
            status: 'PENDING',
            expiresAt: { lt: new Date() }
        },
        data: { status: 'EXPIRED' }
    });
    const invites = await prisma.accountInvite.findMany({
        where: { clubId: req.auth.clubId },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            status: true,
            teamId: true,
            managedTeamIds: true,
            ...getPlayerInviteLinkSelect(),
            expiresAt: true,
            acceptedAt: true,
            createdAt: true,
            user: {
                select: {
                    id: true,
                    email: true,
                    createdAt: true
                }
            }
        },
        orderBy: { createdAt: 'desc' }
    });
    res.json(invites.map((invite) => ({
        ...invite,
        playerId: ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID ? invite.linkedPlayerId ?? null : null,
    })));
});
// Collect waitlist emails
app.post('/waitlist', async (req, res) => {
    try {
        const schema = zod_1.z.object({ email: zod_1.z.string().email(), source: zod_1.z.string().optional() });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json({ error: parsed.error.flatten() });
        const email = normEmail(parsed.data.email);
        const now = Date.now();
        const last = waitlistSeen.get(email) || 0;
        if (now - last < WAITLIST_COOLDOWN_MS) {
            return res.status(202).json({ ok: true, message: 'Already registered recently' });
        }
        waitlistSeen.set(email, now);
        // If SMTP is configured, send a notification email; otherwise log to console.
        if (transporter) {
            try {
                await transporter.sendMail({
                    from: process.env.SMTP_FROM || 'no-reply@example.com',
                    to: process.env.NOTIFY_EMAIL || process.env.WAITLIST_NOTIFY_TO || process.env.SMTP_FROM || 'no-reply@example.com',
                    replyTo: email,
                    subject: 'Nouveau contact – inscription email',
                    text: `Adresse saisie: ${email}`,
                    html: `<p><strong>Adresse saisie:</strong> ${email}</p>`
                });
            }
            catch (err) {
                console.error('Failed to send waitlist email', err);
                // Non-fatal; continue
            }
        }
        else {
            console.log('[waitlist] new signup (no SMTP configured):', { email });
        }
        return res.json({ ok: true });
    }
    catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Internal error' });
    }
});
app.use(async (req, res, next) => {
    if (!isWriteMethod(req.method))
        return next();
    const guardedPrefixes = [
        '/plannings',
        '/players',
        '/trainings',
        '/matchday',
        '/attendance',
        '/matches',
        '/schedule',
        '/drills',
        '/training-drills',
        '/diagrams',
        '/tactics',
    ];
    const isGuarded = guardedPrefixes.some((prefix) => pathStartsWith(req.path, prefix));
    if (!isGuarded)
        return next();
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token)
        return next();
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        const auth = await resolveUserAuthContext(payload.sub);
        if (!auth)
            return res.status(401).json({ error: 'Unauthorized' });
        if (isReadOnlyRole(auth)) {
            return res.status(403).json({ error: 'Read-only account: write access is not allowed' });
        }
    }
    catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
    return next();
});
app.post('/plannings', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ date: zod_1.z.string(), data: zod_1.z.any() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { date, data } = parsed.data;
    const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } });
    if (!user)
        return res.status(404).json({ error: 'User not found' });
    const isoDate = new Date(date);
    const planning = await prisma.planning.upsert({
        where: { userId_date: { userId: user.id, date: isoDate } },
        update: { data: JSON.stringify(data) },
        create: { userId: user.id, date: isoDate, data: JSON.stringify(data) },
    });
    res.json({ ...planning, data });
});
app.get('/plannings', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token) {
        return res.json([]);
    }
    return next();
}, authMiddleware, async (req, res) => {
    const plans = await prisma.planning.findMany({ where: { userId: req.userId }, orderBy: { date: 'asc' } });
    const mapped = plans.map((p) => ({ ...p, data: safeParseJSON(p.data) }));
    res.json(mapped);
});
app.get('/plannings/:id', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token) {
        return res.status(404).json({ error: 'Not found' });
    }
    return next();
}, authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    res.json({ ...p, data: safeParseJSON(p.data) });
});
app.put('/plannings/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ data: zod_1.z.any() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    try {
        const result = await prisma.$transaction(async (tx) => {
            const p = await tx.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
            if (!p) {
                const err = new Error('Not found');
                err.code = 'PLANNING_NOT_FOUND';
                throw err;
            }
            const previousData = safeParseJSON(p.data);
            const nextData = parsed.data.data;
            const updated = await tx.planning.update({ where: { id: p.id }, data: { data: JSON.stringify(nextData) } });
            const nextRotationRaw = findRotationCandidate(nextData);
            const previousRotationRaw = findRotationCandidate(previousData);
            const nextRotation = nextRotationRaw ? (0, matchday_absence_1.ensureRotationGameKeys)(nextRotationRaw) : null;
            const previousTeams = (0, matchday_absence_1.extractRotationTeams)(previousRotationRaw);
            const nextTeams = (0, matchday_absence_1.extractRotationTeams)(nextRotation);
            const changes = (0, matchday_absence_1.diffTeamAbsence)(previousTeams, nextTeams);
            if (!changes.length || !nextRotation) {
                return { updated, data: nextData, propagation: [] };
            }
            const linkedMatchday = await findMatchdayLinkedToPlanning(tx, p, req.auth, nextData);
            if (!linkedMatchday) {
                return { updated, data: nextData, propagation: [] };
            }
            const propagation = [];
            for (const change of changes) {
                const stats = await applyTeamAbsenceOnMatchdayTx({
                    tx,
                    auth: req.auth,
                    matchdayId: linkedMatchday.id,
                    rotation: nextRotation,
                    teamLabel: change.teamLabel,
                    absent: change.absent,
                });
                propagation.push({ teamLabel: change.teamLabel, absent: change.absent, ...stats });
            }
            return { updated, data: nextData, propagation };
        });
        res.json(result);
    }
    catch (e) {
        if (e?.code === 'PLANNING_NOT_FOUND')
            return res.status(404).json({ error: 'Not found' });
        throw e;
    }
});
app.delete('/plannings/:id', authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    await prisma.shareToken.deleteMany({ where: { planningId: p.id } });
    await prisma.planning.delete({ where: { id: p.id } });
    res.json({ ok: true });
});
// Sharing: create a share token (optional email)
app.post('/plannings/:id/share', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ expiresInDays: zod_1.z.number().int().min(1).max(365).optional(), email: zod_1.z.string().email().optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    const token = (0, nanoid_1.nanoid)(24);
    const expiresAt = parsed.data.expiresInDays ? (0, date_fns_1.addDays)(new Date(), parsed.data.expiresInDays) : null;
    const share = await prisma.shareToken.create({ data: { planningId: p.id, token, expiresAt: expiresAt ?? undefined } });
    const url = `${API_BASE_URL}/s/${token}`;
    if (parsed.data.email && transporter) {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || 'no-reply@example.com',
            to: parsed.data.email,
            subject: 'Partage de planning U9',
            text: `Consultez le planning : ${url}`,
            html: `<p>Consultez le planning :</p><p><a href="${url}">${url}</a></p>`
        });
    }
    res.json({ token, url, expiresAt });
});
// Public share endpoint
app.get('/s/:token', async (req, res) => {
    const s = await prisma.shareToken.findUnique({ where: { token: req.params.token }, include: { planning: true } });
    if (!s)
        return res.status(404).json({ error: 'Invalid link' });
    if (s.expiresAt && s.expiresAt < new Date())
        return res.status(410).json({ error: 'Link expired' });
    res.json({ planning: { ...s.planning, data: safeParseJSON(s.planning.data) } });
});
// QR code PNG for sharing URL
app.get('/plannings/:id/qr', authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    const existing = await prisma.shareToken.findFirst({ where: { planningId: p.id }, orderBy: { createdAt: 'asc' } });
    let token = existing?.token;
    if (!token) {
        token = (0, nanoid_1.nanoid)(24);
        await prisma.shareToken.create({ data: { planningId: p.id, token } });
    }
    const url = `${API_BASE_URL}/s/${token}`;
    const png = await qrcode_1.default.toBuffer(url, { width: 512 });
    res.type('image/png').send(png);
});
// === FOOT DOMAIN API ===
// ---- Drills (exercises) ----
app.get('/drills', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const pagination = readPagination(req.query, { limit: 50, maxLimit: 200 });
    const q = req.query.q?.toLowerCase().trim();
    const cat = req.query.category?.toLowerCase().trim();
    const tag = req.query.tag?.toLowerCase().trim();
    const where = {};
    const and = [];
    if (q) {
        and.push({
            OR: [
                { title: { contains: q, mode: 'insensitive' } },
                { description: { contains: q, mode: 'insensitive' } },
            ],
        });
    }
    if (cat)
        and.push({ category: { equals: cat, mode: 'insensitive' } });
    if (tag)
        and.push({ tags: { has: tag } });
    if (and.length > 0)
        where.AND = and;
    const [catalog, items] = await Promise.all([
        drillFindManyForUser(prisma, req.auth, { orderBy: { createdAt: 'asc' } }),
        drillFindManyForUser(prisma, req.auth, {
            where,
            orderBy: { createdAt: 'asc' },
            take: pagination.take,
            skip: pagination.skip,
        }),
    ]);
    const renderedItems = items.map((d) => withDrillDescriptionHtml(d));
    const renderedCatalog = catalog.map((d) => withDrillDescriptionHtml(d));
    res.json({
        items: renderedItems,
        categories: Array.from(new Set(renderedCatalog.map(d => d.category))).sort(),
        tags: Array.from(new Set(renderedCatalog.flatMap(d => d.tags))).sort(),
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: renderedItems.length }
    });
});
app.get('/drills/:id', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const d = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!d)
        return res.status(404).json({ error: 'Not found' });
    res.json(withDrillDescriptionHtml(d));
});
app.put('/drills/:id', authMiddleware, async (req, res) => {
    const existing = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!existing)
        return res.status(404).json({ error: 'Not found' });
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100).optional(),
        category: zod_1.z.string().min(1).max(50).optional(),
        duration: zod_1.z.coerce.number().int().min(1).max(180).optional(),
        players: zod_1.z.string().min(1).max(50).optional(),
        description: zod_1.z.string().min(1).max(2000).optional(),
        tags: zod_1.z.array(zod_1.z.string().min(1).max(32)).max(20).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const patch = {};
    if (parsed.data.title !== undefined)
        patch.title = parsed.data.title;
    if (parsed.data.category !== undefined)
        patch.category = parsed.data.category;
    if (parsed.data.duration !== undefined)
        patch.duration = parsed.data.duration;
    if (parsed.data.players !== undefined)
        patch.players = parsed.data.players;
    if (parsed.data.description !== undefined)
        patch.description = parsed.data.description;
    if (parsed.data.tags !== undefined)
        patch.tags = parsed.data.tags;
    const updated = await prisma.drill.update({
        where: { id: existing.id },
        data: patch
    });
    res.json(withDrillDescriptionHtml(updated));
});
app.delete('/drills/:id', authMiddleware, async (req, res) => {
    const existing = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!existing)
        return res.status(404).json({ error: 'Not found' });
    const drillId = existing.id;
    const rows = await trainingDrillFindManyForUser(prisma, req.auth, {
        where: { drillId },
        select: { id: true }
    });
    const trainingDrillIds = rows.map((row) => row.id);
    await prisma.$transaction([
        prisma.diagram.deleteMany({ where: applyScopeWhere(req.auth, { drillId }, { includeLegacyOwner: true }) }),
        prisma.diagram.deleteMany({ where: applyScopeWhere(req.auth, { trainingDrillId: { in: trainingDrillIds } }, { includeLegacyOwner: true }) }),
        prisma.trainingDrill.deleteMany({ where: applyScopeWhere(req.auth, { drillId }, { includeLegacyOwner: true }) }),
        prisma.drill.deleteMany({ where: applyScopeWhere(req.auth, { id: drillId }, { includeLegacyOwner: true }) }),
    ]);
    res.json({ ok: true });
});
app.post('/drills', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        category: zod_1.z.string().min(1).max(50),
        duration: zod_1.z.coerce.number().int().min(1).max(180),
        players: zod_1.z.string().min(1).max(50),
        description: zod_1.z.string().min(1).max(2000),
        tags: zod_1.z.array(zod_1.z.string().min(1).max(32)).max(20).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const id = await buildUniqueDrillId(prisma, req.auth, parsed.data.title);
    try {
        const drill = await drillCreateForUser(prisma, req.auth, {
            id,
            clubId: team.clubId,
            teamId: team.id,
            title: parsed.data.title,
            category: parsed.data.category,
            duration: parsed.data.duration,
            players: parsed.data.players,
            description: parsed.data.description,
            tags: (parsed.data.tags && parsed.data.tags.length) ? parsed.data.tags : []
        });
        res.status(201).json(withDrillDescriptionHtml(drill));
    }
    catch (e) {
        if (e?.code === 'DRILL_STORAGE_UNAVAILABLE') {
            return res.status(503).json({ error: 'Drill storage unavailable' });
        }
        throw e;
    }
});
// Models used: Player, Training, Matchday, Attendance, Match, MatchTeam, MatchTeamPlayer, Scorer
// All endpoints are protected (same as plannings). Adjust if you want some public.
// ---- Players ----
app.get('/players', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const pagination = readPagination(req.query, { limit: 100, maxLimit: 300 });
    const players = await playerFindManyForUser(prisma, req.auth, {
        orderBy: [{ first_name: 'asc' }, { last_name: 'asc' }, { name: 'asc' }],
        take: pagination.take,
        skip: pagination.skip,
    });
    res.json({
        items: players.map((player) => (0, player_payload_1.normalizePlayerForApi)(player)),
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: players.length }
    });
});
const getPlayerByIdHandler = async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const scopedPlayer = await getPlayerInvitationStatusForRequest(req, id);
    if (!scopedPlayer)
        return res.status(404).json({ error: 'Player not found' });
    const normalizedPlayer = (0, player_payload_1.normalizePlayerForApi)(scopedPlayer.player);
    res.json({
        ...normalizedPlayer,
        invitationStatus: scopedPlayer.snapshot.status,
        invitation: {
            status: scopedPlayer.snapshot.status,
            invitationId: scopedPlayer.snapshot.invitationId,
            lastInvitationAt: scopedPlayer.snapshot.lastInvitationAt ? scopedPlayer.snapshot.lastInvitationAt.toISOString() : null,
        }
    });
};
app.get('/players/:id', authMiddleware, getPlayerByIdHandler);
app.get('/effectif/:id', authMiddleware, getPlayerByIdHandler);
app.get('/api/players/:id', authMiddleware, getPlayerByIdHandler);
app.get('/api/effectif/:id', authMiddleware, getPlayerByIdHandler);
app.get('/players/:id/invitation-status', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const scopedPlayer = await getPlayerInvitationStatusForRequest(req, id);
    if (!scopedPlayer)
        return res.status(404).json({ error: 'Player not found' });
    res.json({
        playerId: scopedPlayer.player.id,
        status: scopedPlayer.snapshot.status,
        lastInvitationAt: scopedPlayer.snapshot.lastInvitationAt ? scopedPlayer.snapshot.lastInvitationAt.toISOString() : null,
        invitationId: scopedPlayer.snapshot.invitationId,
    });
});
app.get('/api/players/:id/invitation-status', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const scopedPlayer = await getPlayerInvitationStatusForRequest(req, id);
    if (!scopedPlayer)
        return res.status(404).json({ error: 'Player not found' });
    res.json({
        playerId: scopedPlayer.player.id,
        status: scopedPlayer.snapshot.status,
        lastInvitationAt: scopedPlayer.snapshot.lastInvitationAt ? scopedPlayer.snapshot.lastInvitationAt.toISOString() : null,
        invitationId: scopedPlayer.snapshot.invitationId,
    });
});
app.post('/players', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    let payload;
    try {
        payload = (0, player_payload_1.parsePlayerCreatePayload)(req.body);
    }
    catch (e) {
        if (e instanceof zod_1.z.ZodError)
            return res.status(400).json({ error: e.flatten() });
        throw e;
    }
    let team;
    try {
        team = await resolveTeamForWrite(req.auth, payload.teamId || undefined);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const baseData = {
        clubId: team.clubId,
        teamId: team.id,
        name: `${payload.firstName} ${payload.lastName}`.trim(),
        first_name: payload.firstName,
        last_name: payload.lastName,
        primary_position: payload.primary_position,
        secondary_position: payload.secondary_position,
        email: payload.email,
        phone: payload.phone,
        is_child: payload.isChild,
        parent_first_name: payload.parentFirstName,
        parent_last_name: payload.parentLastName,
        licence: payload.licence,
    };
    const p = await playerCreateForUser(prisma, req.auth, baseData);
    res.json((0, player_payload_1.normalizePlayerForApi)(p));
});
const updatePlayerByIdHandler = async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const existing = await playerFindFirstForUser(prisma, req.auth, { where: { id } });
    if (!existing)
        return res.status(404).json({ error: 'Player not found' });
    let payload;
    try {
        payload = (0, player_payload_1.parsePlayerUpdatePayload)(req.body, existing);
    }
    catch (e) {
        if (e instanceof zod_1.z.ZodError)
            return res.status(400).json({ error: e.flatten() });
        throw e;
    }
    const patch = {};
    patch.first_name = payload.firstName;
    patch.last_name = payload.lastName;
    patch.name = `${payload.firstName} ${payload.lastName}`.trim();
    patch.primary_position = payload.primary_position;
    patch.secondary_position = payload.secondary_position;
    patch.email = payload.email;
    patch.phone = payload.phone;
    patch.is_child = payload.isChild;
    patch.parent_first_name = payload.parentFirstName;
    patch.parent_last_name = payload.parentLastName;
    patch.licence = payload.licence;
    const updated = await prisma.player.update({ where: { id: existing.id }, data: patch });
    res.json((0, player_payload_1.normalizePlayerForApi)(updated));
};
app.put('/players/:id', authMiddleware, updatePlayerByIdHandler);
app.put('/effectif/:id', authMiddleware, updatePlayerByIdHandler);
app.put('/api/players/:id', authMiddleware, updatePlayerByIdHandler);
app.put('/api/effectif/:id', authMiddleware, updatePlayerByIdHandler);
// --- Player invite JWT and playerAuth ---
function signPlayerInvite(playerId, matchdayId, email) {
    return jsonwebtoken_1.default.sign({ aud: 'player_invite', pid: playerId, mid: matchdayId || null, em: email || null }, JWT_SECRET, { expiresIn: '30d' });
}
function signRsvpToken(playerId, matchdayId, status) {
    return jsonwebtoken_1.default.sign({ aud: 'player_rsvp', pid: playerId, mid: matchdayId, st: status }, JWT_SECRET, { expiresIn: '60d' });
}
async function playerAuth(req, res, next) {
    const token = req.cookies?.player_token || req.headers['x-player-token'];
    if (!token)
        return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.status(401).json({ error: 'Invalid token' });
        const player = await playerFindByIdCompat(prisma, payload.pid);
        if (!player)
            return res.status(401).json({ error: 'Invalid token' });
        req.playerId = payload.pid;
        req.playerUserId = player.userId;
        req.scopeMatchdayId = payload.mid || null;
        next();
    }
    catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
// --- Player invite endpoint ---
app.post('/players/:id/invite', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const schema = zod_1.z.object({
        matchdayId: zod_1.z.string().optional(),
        email: zod_1.z.string().email().optional(),
        expiresInDays: zod_1.z.coerce.number().int().min(1).max(30).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const player = await playerFindFirstForUser(prisma, req.auth, {
        where: { id },
        select: {
            id: true,
            userId: true,
            clubId: true,
            teamId: true,
            email: true,
            first_name: true,
            last_name: true,
            name: true,
            is_child: true,
            parent_first_name: true,
            parent_last_name: true,
        }
    });
    if (!player)
        return res.status(404).json({ error: 'Player not found' });
    const inviteEmail = parsed.data.email || player.email || null;
    if (parsed.data.matchdayId) {
        const base = `${req.protocol}://${req.get('host')}`;
        const presentToken = signRsvpToken(id, parsed.data.matchdayId, 'present');
        const absentToken = signRsvpToken(id, parsed.data.matchdayId, 'absent');
        const presentUrl = `${base}/rsvp/p?token=${encodeURIComponent(presentToken)}`;
        const absentUrl = `${base}/rsvp/a?token=${encodeURIComponent(absentToken)}`;
        // Mark player as convoked for this matchday
        try {
            await attendanceUpsertMarkerForUser(prisma, req.auth, {
                session_type: 'PLATEAU_CONVOKE',
                session_id: parsed.data.matchdayId,
                playerId: id,
            });
        }
        catch (e) {
            console.warn('[invite] failed to upsert convocation marker', e);
        }
        if (inviteEmail && transporter) {
            try {
                await transporter.sendMail({
                    from: process.env.SMTP_FROM || 'no-reply@example.com',
                    to: inviteEmail,
                    subject: 'Confirmation de présence – Izifoot',
                    html: `<p>Bonjour${player.name ? ' ' + player.name : ''},</p>
<p>Merci d'indiquer votre présence pour le matchday.</p>
<p><a href="${presentUrl}">Je serai présent</a> &nbsp;|&nbsp; <a href="${absentUrl}">Je serai absent</a></p>
<p>(Ces liens sont valables 60 jours)</p>`
                });
            }
            catch (e) {
                console.warn('[invite] email failed:', e);
            }
        }
        return res.json({ ok: true, presentUrl, absentUrl });
    }
    const playerEmail = inviteEmail ? normEmail(inviteEmail) : null;
    if (!playerEmail) {
        return res.status(400).json({ error: 'Player email is required to send account invitation' });
    }
    if (!req.auth?.clubId) {
        return res.status(400).json({ error: 'Staff account must be attached to a club' });
    }
    const linkedPlayerAccountUser = await resolveLinkedPlayerAccountUser(player, req.auth.clubId);
    const snapshot = await getPlayerInvitationStatusSnapshot(req.auth, player);
    if (snapshot.status === 'ACCEPTED') {
        return res.status(409).json({ error: 'Compte déjà activé' });
    }
    const existingUser = await prisma.user.findUnique({
        where: { email: playerEmail },
        select: { id: true }
    });
    if (existingUser && existingUser.id !== linkedPlayerAccountUser?.id) {
        return res.status(409).json({ error: 'Email already in use by another account' });
    }
    const expiresAt = (0, date_fns_1.addDays)(new Date(), parsed.data.expiresInDays ?? 7);
    const inviteToken = (0, nanoid_1.nanoid)(48);
    const playerFullName = [player.first_name, player.last_name].filter(Boolean).join(' ').trim() || player.name || null;
    const inviteRole = (0, player_account_role_1.resolvePlayerAccountInviteRole)(Boolean(player?.is_child));
    const inviteFirstName = inviteRole === 'PARENT'
        ? ((player.parent_first_name || '').trim() || player.first_name || null)
        : (player.first_name || null);
    const inviteLastName = inviteRole === 'PARENT'
        ? ((player.parent_last_name || '').trim() || player.last_name || null)
        : (player.last_name || null);
    const invitation = snapshot.status === 'PENDING' && snapshot.invitationId
        ? await prisma.accountInvite.update({
            where: { id: snapshot.invitationId },
            data: {
                email: playerEmail,
                firstName: inviteFirstName,
                lastName: inviteLastName,
                token: inviteToken,
                role: inviteRole,
                teamId: player.teamId ?? null,
                ...(ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID ? { linkedPlayerId: player.id } : {}),
                invitedByUserId: req.auth.id,
                status: 'PENDING',
                expiresAt,
            },
            select: {
                id: true,
                token: true,
                updatedAt: true,
                expiresAt: true,
            }
        })
        : await prisma.accountInvite.create({
            data: {
                email: playerEmail,
                firstName: inviteFirstName,
                lastName: inviteLastName,
                token: inviteToken,
                role: inviteRole,
                clubId: req.auth.clubId,
                invitedByUserId: req.auth.id,
                teamId: player.teamId ?? null,
                managedTeamIds: [],
                ...(ACCOUNT_INVITE_HAS_LINKED_PLAYER_ID ? { linkedPlayerId: player.id } : {}),
                linkedPlayerUserId: linkedPlayerAccountUser?.id ?? null,
                expiresAt,
            },
            select: {
                id: true,
                token: true,
                updatedAt: true,
                expiresAt: true,
            }
        });
    await sendPlayerAccountInviteEmail({
        playerName: playerFullName,
        inviteEmail: playerEmail,
        token: invitation.token,
        expiresAt: invitation.expiresAt,
    });
    const inviteUrl = buildAccountInviteUrl(invitation.token);
    return res.json({
        status: 'PENDING',
        invitationId: invitation.id,
        sentAt: invitation.updatedAt.toISOString(),
        expiresAt: invitation.expiresAt ? invitation.expiresAt.toISOString() : null,
        inviteUrl,
    });
});
app.get('/players/:id/invite/qr', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    const player = await playerFindFirstForUser(prisma, req.auth, {
        where: { id },
        select: {
            id: true,
            userId: true,
            clubId: true,
            teamId: true,
        }
    });
    if (!player)
        return res.status(404).json({ error: 'Player not found' });
    const snapshot = await getPlayerInvitationStatusSnapshot(req.auth, player);
    if (snapshot.status !== 'PENDING' || !snapshot.invitationId) {
        return res.status(404).json({ error: 'No active invitation for this player' });
    }
    const invitation = await prisma.accountInvite.findUnique({
        where: { id: snapshot.invitationId },
        select: {
            id: true,
            token: true,
            status: true,
            expiresAt: true,
        }
    });
    if (!invitation || invitation.status !== 'PENDING' || invitation.expiresAt < new Date()) {
        return res.status(404).json({ error: 'No active invitation for this player' });
    }
    const inviteUrl = buildAccountInviteUrl(invitation.token);
    const png = await qrcode_1.default.toBuffer(inviteUrl, { width: 512 });
    res.setHeader('Cache-Control', 'no-store');
    res.type('image/png').send(png);
});
// --- Public endpoint to accept invite and set player_token cookie ---
app.get('/player/accept', async (req, res) => {
    const token = req.query.token;
    if (!token)
        return res.status(400).json({ error: 'Missing token' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.status(400).json({ error: 'Invalid token' });
        res.cookie('player_token', token, playerCookieOpts());
        const r = req.query.r;
        const redirectTo = (r && r.startsWith(APP_BASE_URL)) ? r : undefined;
        res.json({ ok: true, redirectTo });
    }
    catch {
        return res.status(400).json({ error: 'Invalid token' });
    }
});
app.get('/player/login', async (req, res) => {
    const token = req.query.token;
    const r = req.query.r || '';
    let redirectTo = process.env.PLAYER_PORTAL_REDIRECT || APP_BASE_URL;
    // If a custom redirect is provided and starts with APP_BASE_URL, use it
    if (r && r.startsWith(APP_BASE_URL))
        redirectTo = r;
    if (!token)
        return res.redirect(302, redirectTo);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.redirect(302, redirectTo);
        res.cookie('player_token', token, playerCookieOpts());
        // If token is scoped to a matchday, send the user straight to that MatchDay
        if (payload?.mid) {
            const dest = `${APP_BASE_URL}/match-day/${payload.mid}`;
            return res.redirect(302, dest);
        }
        return res.redirect(302, redirectTo);
    }
    catch {
        return res.redirect(302, redirectTo);
    }
});
// --- RSVP endpoints ---
app.get('/rsvp/p', async (req, res) => {
    const token = req.query.token;
    const redirectBase = APP_BASE_URL;
    if (!token)
        return res.redirect(302, redirectBase);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_rsvp' || payload?.st !== 'present' || !payload?.pid || !payload?.mid) {
            return res.redirect(302, redirectBase);
        }
        const player = await playerFindByIdCompat(prisma, payload.pid);
        if (!player?.userId)
            return res.redirect(302, redirectBase);
        try {
            await attendanceSetMatchdayRsvpForUser(prisma, player.userId, payload.mid, payload.pid, true);
        }
        catch (e) {
            // Ignore, always redirect anyway
        }
        return res.redirect(302, `${redirectBase}/match-day/${payload.mid}?rsvp=present`);
    }
    catch {
        return res.redirect(302, redirectBase);
    }
});
app.get('/rsvp/a', async (req, res) => {
    const token = req.query.token;
    const redirectBase = APP_BASE_URL;
    if (!token)
        return res.redirect(302, redirectBase);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_rsvp' || payload?.st !== 'absent' || !payload?.pid || !payload?.mid) {
            return res.redirect(302, redirectBase);
        }
        const player = await playerFindByIdCompat(prisma, payload.pid);
        if (!player?.userId)
            return res.redirect(302, redirectBase);
        try {
            await attendanceSetMatchdayRsvpForUser(prisma, player.userId, payload.mid, payload.pid, false);
        }
        catch (e) {
            console.warn('[RSVP absent] failed', e);
        }
        return res.redirect(302, `${redirectBase}/match-day/${payload.mid}?rsvp=absent`);
    }
    catch {
        return res.redirect(302, redirectBase);
    }
});
// --- Debug route for cookie visibility ---
app.get('/player/debug', (req, res) => {
    res.json({ hasCookie: Boolean(req.cookies?.player_token), cookies: Object.keys(req.cookies || {}) });
});
// --- Scoped player endpoints ---
app.get('/player/me', playerAuth, async (req, res) => {
    const p = await playerFindFirstForUser(prisma, req.playerUserId, { where: { id: req.playerId } });
    if (!p)
        return res.status(404).json({ error: 'Player not found' });
    res.json({ id: p.id, name: p.name || '', email: p.email || null, phone: p.phone || null });
});
app.get('/player/matchday', playerAuth, async (req, res) => {
    const playerId = req.playerId;
    // Matchdays via attendance
    const att = await attendanceFindManyForUser(prisma, req.playerUserId, {
        where: { session_type: 'PLATEAU', playerId },
        select: { session_id: true }
    });
    const matchdayIdsFromAttendance = Array.from(new Set(att.map(a => a.session_id)));
    // Matchdays via match participation
    const mtps = await prisma.matchTeamPlayer.findMany({ where: { playerId }, select: { matchTeamId: true } });
    const teamIds = mtps.map(m => m.matchTeamId);
    let matchdayIdsFromMatches = [];
    if (teamIds.length) {
        const teams = await prisma.matchTeam.findMany({ where: { id: { in: teamIds } }, select: { matchId: true } });
        const matchIds = teams.map(t => t.matchId);
        if (matchIds.length) {
            const matches = await matchFindManyForUser(prisma, req.playerUserId, { where: { id: { in: matchIds } }, select: { plateauId: true } });
            matchdayIdsFromMatches = matches.map(m => m.plateauId).filter(Boolean);
        }
    }
    const set = new Set([...matchdayIdsFromAttendance, ...matchdayIdsFromMatches]);
    const ids = Array.from(set);
    if (!ids.length)
        return res.json([]);
    const matchdays = await matchdayFindManyForUser(prisma, req.playerUserId, { where: { id: { in: ids } }, orderBy: { date: 'desc' } });
    res.json(matchdays);
});
app.get('/player/matchday/:id/summary', playerAuth, async (req, res) => {
    const matchdayId = req.params.id;
    // If token is scoped to a specific matchday, enforce it
    if (req.scopeMatchdayId && req.scopeMatchdayId !== matchdayId)
        return res.status(403).json({ error: 'Forbidden' });
    // Reuse the same build as /matchday/:id/summary
    const ctxRes = {};
    const fakeReq = { params: { id: matchdayId }, userId: req.playerUserId };
    const fakeRes = {
        statusCode: 200,
        _json: null,
        status(c) { this.statusCode = c; return this; },
        json(v) { this._json = v; return this; }
    };
    await app._router.handle({ ...fakeReq, method: 'GET', url: `/matchday/${matchdayId}/summary` }, fakeRes, () => { });
    const summary = fakeRes._json;
    if (!summary || fakeRes.statusCode !== 200)
        return res.status(fakeRes.statusCode || 500).json(summary || { error: 'Failed' });
    // Check convocation: present in attendance OR in any team players
    const isConvocated = Boolean((summary.convocations || []).some((c) => c.player?.id === req.playerId) ||
        (summary.matches || []).some((m) => (m.teams || []).some((t) => (t.players || []).some((p) => p.playerId === req.playerId))));
    if (!isConvocated)
        return res.status(403).json({ error: 'Not convocated for this matchday' });
    // Optionally, we could filter convocations to only the player
    const filtered = { ...summary, convocations: (summary.convocations || []).filter((c) => c.player?.id === req.playerId) };
    res.json(filtered);
});
const deletePlayerByIdHandler = async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id } = req.params;
    try {
        // Ensure the player exists first
        const exists = await playerFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!exists)
            return res.status(404).json({ error: 'Player not found' });
        await prisma.$transaction(async (tx) => {
            await tx.scorer.deleteMany({ where: { playerId: id } });
            await tx.matchTeamPlayer.deleteMany({ where: { playerId: id } });
            await attendanceDeleteManyForUser(tx, req.auth, { playerId: id });
            await tx.player.delete({ where: { id: exists.id } });
        });
        res.json({ ok: true });
    }
    catch (e) {
        console.error('[DELETE /players/:id] failed', e);
        // If it still fails due to referential integrity, surface 409
        return res.status(409).json({ error: 'Cannot delete player due to related data' });
    }
};
app.delete('/players/:id', authMiddleware, deletePlayerByIdHandler);
app.delete('/effectif/:id', authMiddleware, deletePlayerByIdHandler);
app.delete('/api/players/:id', authMiddleware, deletePlayerByIdHandler);
app.delete('/api/effectif/:id', authMiddleware, deletePlayerByIdHandler);
// ---- Trainings ----
app.get('/trainings', authMiddleware, async (req, res) => {
    const pagination = readPagination(req.query, { limit: 50, maxLimit: 200 });
    const trainings = await trainingFindManyForUser(prisma, req.auth, {
        orderBy: { date: 'desc' },
        take: pagination.take,
        skip: pagination.skip,
    });
    res.json({
        items: trainings,
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: trainings.length }
    });
});
// Get single training
app.get('/trainings/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!training)
            return res.status(404).json({ error: 'Training not found' });
        res.json(training);
    }
    catch (e) {
        console.error('[GET /trainings/:id] failed', e);
        return res.status(500).json({ error: 'Failed to fetch training' });
    }
});
app.post('/trainings', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const schema = zod_1.z.object({ date: zod_1.z.string().or(zod_1.z.date()) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const date = new Date(parsed.data.date);
    const t = await trainingCreateForUser(prisma, req.auth, {
        date,
        status: 'PLANNED',
        clubId: team.clubId,
        teamId: team.id
    });
    res.json(t);
});
// Update a training (date/status)
app.put('/trainings/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        date: zod_1.z.string().or(zod_1.z.date()).optional(),
        status: zod_1.z.enum(['PLANNED', 'CANCELLED']).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const data = {};
    if (parsed.data.date !== undefined)
        data.date = new Date(parsed.data.date);
    if (parsed.data.status !== undefined)
        data.status = parsed.data.status;
    try {
        const existing = await trainingFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
        if (!existing)
            return res.status(404).json({ error: 'Training not found' });
        const updated = await trainingUpdateCompat(prisma, existing.id, data);
        res.json(updated);
    }
    catch (e) {
        if (e?.code === 'P2025') {
            return res.status(404).json({ error: 'Training not found' });
        }
        console.error('[PUT /trainings/:id] update failed', e);
        return res.status(500).json({ error: 'Failed to update training' });
    }
});
// Replace full attendance snapshot for a training
app.put('/trainings/:trainingId/attendance', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const trainingId = req.params.trainingId;
    const parsed = attendance_1.trainingAttendancePutBodySchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    try {
        const training = await trainingFindFirstForUser(prisma, req.auth, {
            where: { id: trainingId },
            select: { id: true, clubId: true, teamId: true },
        });
        if (!training)
            return res.status(404).json({ error: 'Training not found' });
        const scopeAuth = {
            ...req.auth,
            clubId: training.clubId ?? req.auth?.clubId ?? null,
            teamId: training.teamId ?? req.auth?.teamId ?? null,
        };
        const players = await prisma.player.findMany({
            where: { teamId: training.teamId },
            select: { id: true },
        });
        const snapshot = (0, attendance_1.buildTrainingAttendanceSnapshot)({
            trainingId,
            trainingPlayerIds: players.map((p) => p.id),
            presentPlayerIds: parsed.data.playerIds,
        });
        if (snapshot.invalidPlayerIds.length > 0) {
            return res.status(400).json({ error: 'One or more players do not belong to the training team' });
        }
        const rows = await prisma.$transaction(async (tx) => {
            const attendanceWhere = {
                session_type: { in: (0, attendance_1.attendanceSessionTypeVariants)('TRAINING') },
                session_id: trainingId,
                teamId: training.teamId,
            };
            if (training.clubId)
                attendanceWhere.clubId = training.clubId;
            await tx.attendance.deleteMany({ where: attendanceWhere });
            if (snapshot.items.length > 0) {
                await tx.attendance.createMany({
                    data: snapshot.items.map((item) => ({
                        ...(scopeAuth?.id ? { userId: scopeAuth.id } : {}),
                        ...(scopeAuth?.clubId ? { clubId: scopeAuth.clubId } : {}),
                        ...(scopeAuth?.teamId ? { teamId: scopeAuth.teamId } : {}),
                        trainingId,
                        ...item,
                    })),
                });
            }
            return tx.attendance.findMany({
                where: attendanceWhere,
                orderBy: { playerId: 'asc' },
            });
        });
        return res.status(200).json({ items: rows.map(attendance_1.normalizeAttendanceRow) });
    }
    catch (e) {
        console.error('[PUT /trainings/:trainingId/attendance] failed', {
            trainingId,
            error: e,
        });
        return res.status(500).json({ error: 'Failed to update training attendance' });
    }
});
// Delete a training (and clean related attendance + drills)
app.delete('/trainings/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        const existing = await trainingFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!existing)
            return res.status(404).json({ error: 'Training not found' });
        await prisma.$transaction(async (tx) => {
            await attendanceDeleteManyForUser(tx, req.auth, { session_type: 'TRAINING', session_id: id });
            await tx.trainingDrill.deleteMany({ where: applyScopeWhere(req.auth, { trainingId: id }, { includeLegacyOwner: true }) });
            await tx.training.delete({ where: { id: existing.id } });
        });
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025') {
            return res.status(404).json({ error: 'Training not found' });
        }
        console.error('[DELETE /trainings/:id] delete failed', e);
        return res.status(500).json({ error: 'Failed to delete training' });
    }
});
app.get('/trainings/:id/roles', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const trainingId = req.params.id;
    try {
        const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } });
        if (!training)
            return res.status(404).json({ error: 'Training not found' });
        const rows = await trainingRoleAssignmentFindManyForUser(prisma, req.auth, {
            where: { trainingId },
            include: { player: { select: { id: true, name: true } } },
            orderBy: [{ role: 'asc' }, { id: 'asc' }],
        });
        return res.json({ items: rows.map(toTrainingRoleAssignmentResponseItem) });
    }
    catch (e) {
        if (e?.code === 'TRAINING_ROLE_STORAGE_UNAVAILABLE') {
            return res.status(503).json({ error: 'Training role storage unavailable' });
        }
        console.error('[GET /trainings/:id/roles] failed', {
            trainingId,
            error: e,
        });
        return res.status(500).json({ error: 'Failed to fetch training roles' });
    }
});
app.put('/trainings/:id/roles', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const trainingId = req.params.id;
    const parsed = training_role_assignments_1.trainingRolesPutBodySchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.flatten() });
    }
    const items = (0, training_role_assignments_1.normalizeTrainingRoleItems)(parsed.data.items);
    try {
        (0, training_role_assignments_1.validateNoDuplicatePlayers)(items);
    }
    catch (e) {
        return res.status(400).json({ error: e?.message || 'Invalid role assignments payload' });
    }
    try {
        const training = await trainingFindFirstForUser(prisma, req.auth, {
            where: { id: trainingId },
            select: { id: true, clubId: true, teamId: true },
        });
        if (!training)
            return res.status(404).json({ error: 'Training not found' });
        const playerIds = Array.from(new Set(items.map((item) => item.playerId)));
        if (playerIds.length > 0) {
            const players = await playerFindManyForUser(prisma, req.auth, {
                where: {
                    id: { in: playerIds },
                    teamId: training.teamId,
                },
                select: { id: true },
            });
            if (players.length !== playerIds.length) {
                return res.status(400).json({ error: 'One or more players do not belong to the training team' });
            }
        }
        const savedRows = await prisma.$transaction(async (tx) => {
            await tx.trainingRoleAssignment.deleteMany({
                where: applyScopeWhere(req.auth, { trainingId }, { includeLegacyOwner: true }),
            });
            if (items.length > 0) {
                await tx.trainingRoleAssignment.createMany({
                    data: items.map((item) => ({
                        userId: req.auth?.id ?? null,
                        clubId: training.clubId ?? null,
                        teamId: training.teamId ?? null,
                        trainingId,
                        role: item.role,
                        playerId: item.playerId,
                    })),
                });
            }
            return trainingRoleAssignmentFindManyForUser(tx, req.auth, {
                where: { trainingId },
                include: { player: { select: { id: true, name: true } } },
                orderBy: [{ role: 'asc' }, { id: 'asc' }],
            });
        });
        return res.json({ items: savedRows.map(toTrainingRoleAssignmentResponseItem) });
    }
    catch (e) {
        if (e?.code === 'P2021' || e?.code === 'TRAINING_ROLE_STORAGE_UNAVAILABLE') {
            return res.status(503).json({ error: 'Training role storage unavailable' });
        }
        if (e?.code === 'P2002') {
            return res.status(409).json({ error: 'Role assignments conflict with uniqueness constraints' });
        }
        if (e?.code === 'P2003') {
            return res.status(409).json({ error: 'Invalid player reference in role assignments' });
        }
        console.error('[PUT /trainings/:id/roles] failed', {
            trainingId,
            body: req.body,
            error: e,
        });
        return res.status(500).json({ error: 'Failed to save training roles' });
    }
});
// ---- Matchdays ----
app.get('/matchday', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token)
        return res.json({ items: [], pagination: { limit: 0, offset: 0, returned: 0 } });
    return next();
}, authMiddleware, async (req, res) => {
    const pagination = readPagination(req.query, { limit: 50, maxLimit: 200 });
    const matchdays = await matchdayFindManyForUser(prisma, req.auth, {
        orderBy: { date: 'desc' },
        take: pagination.take,
        skip: pagination.skip,
    });
    res.json({
        items: matchdays,
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: matchdays.length }
    });
});
app.post('/matchday', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const schema = zod_1.z.object({
        date: zod_1.z.string().or(zod_1.z.date()),
        lieu: zod_1.z.string().min(1),
        teamId: zod_1.z.string().min(1).optional(),
    }).merge(matchday_metadata_1.matchdayMetadataSchema);
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth, parsed.data.teamId || undefined);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const date = new Date(parsed.data.date);
    const pl = await matchdayCreateForUser(prisma, req.auth, {
        date,
        lieu: parsed.data.lieu,
        ...(0, matchday_metadata_1.buildMatchdayMetadataPatch)(parsed.data),
        clubId: team.clubId,
        teamId: team.id
    });
    res.json(pl);
});
app.put('/matchday/:id', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = matchday_metadata_1.matchdayMetadataSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const data = (0, matchday_metadata_1.buildMatchdayMetadataPatch)(parsed.data);
    if (Object.keys(data).length === 0) {
        return res.status(400).json({ error: 'No updatable fields provided' });
    }
    try {
        const existing = await matchdayFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
        if (!existing)
            return res.status(404).json({ error: 'Matchday not found' });
        const updated = await prisma.plateau.update({ where: { id: existing.id }, data });
        res.json(updated);
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Matchday not found' });
        console.error('[PUT /matchday/:id] update failed', e);
        return res.status(500).json({ error: 'Failed to update matchday' });
    }
});
app.post('/matchday/:id/teams/absence', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const schema = zod_1.z.object({
        teamLabel: zod_1.z.string().min(1),
        absent: zod_1.z.boolean(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const matchday = await matchdayFindFirstForUser(prisma, req.auth, {
        where: { id: req.params.id },
        select: { id: true, date: true, userId: true },
    });
    if (!matchday)
        return res.status(404).json({ error: 'Matchday not found' });
    try {
        const payload = await prisma.$transaction(async (tx) => {
            const dayStart = new Date(matchday.date);
            dayStart.setHours(0, 0, 0, 0);
            const dayEnd = new Date(dayStart);
            dayEnd.setDate(dayEnd.getDate() + 1);
            const planning = await tx.planning.findFirst({
                where: {
                    date: { gte: dayStart, lt: dayEnd },
                    ...(matchday.userId ? { userId: matchday.userId } : {}),
                },
                orderBy: { updatedAt: 'desc' },
            });
            if (!planning) {
                const err = new Error('Planning not found for this matchday day');
                err.code = 'PLANNING_NOT_FOUND';
                throw err;
            }
            const planningData = safeParseJSON(planning.data);
            const rotationCandidate = findRotationCandidate(planningData);
            if (!rotationCandidate) {
                const err = new Error('Rotation not found in planning');
                err.code = 'ROTATION_NOT_FOUND';
                throw err;
            }
            const keyedRotation = (0, matchday_absence_1.ensureRotationGameKeys)(rotationCandidate);
            const teams = (0, matchday_absence_1.extractRotationTeams)(keyedRotation);
            let foundTeam = false;
            let touched = false;
            const nextTeams = teams.map((team) => {
                if (team.label.trim().toLowerCase() !== parsed.data.teamLabel.trim().toLowerCase())
                    return team;
                foundTeam = true;
                const currentAbsent = Boolean(team.absent);
                if (currentAbsent === parsed.data.absent)
                    return team;
                touched = true;
                return { ...team, absent: parsed.data.absent };
            });
            if (!foundTeam) {
                const err = new Error('No team found in rotation');
                err.code = 'TEAM_NOT_FOUND';
                throw err;
            }
            const nextRotation = { ...keyedRotation, teams: nextTeams };
            const nextPlanningData = {
                ...(planningData && typeof planningData === 'object' ? planningData : {}),
                rotation: nextRotation,
            };
            if (touched) {
                await tx.planning.update({
                    where: { id: planning.id },
                    data: { data: JSON.stringify(nextPlanningData) },
                });
            }
            const stats = await applyTeamAbsenceOnMatchdayTx({
                tx,
                auth: req.auth,
                matchdayId: matchday.id,
                rotation: nextRotation,
                teamLabel: parsed.data.teamLabel,
                absent: parsed.data.absent,
            });
            return {
                ok: true,
                planningId: planning.id,
                teamLabel: parsed.data.teamLabel,
                absent: parsed.data.absent,
                planningUpdated: touched,
                ...stats,
            };
        });
        return res.json(payload);
    }
    catch (e) {
        if (e?.code === 'PLANNING_NOT_FOUND')
            return res.status(404).json({ error: e.message });
        if (e?.code === 'ROTATION_NOT_FOUND')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'TEAM_NOT_FOUND')
            return res.status(404).json({ error: e.message });
        console.error('[POST /matchday/:id/teams/absence] failed', e);
        return res.status(500).json({ error: 'Failed to update team absence' });
    }
});
app.post('/matchday/:id/share', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ expiresInDays: zod_1.z.number().int().min(1).max(365).optional() });
    const parsed = schema.safeParse(req.body ?? {});
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const matchday = await matchdayFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!matchday)
        return res.status(404).json({ error: 'Matchday not found' });
    const existing = await prisma.plateauShareToken.findFirst({
        where: { plateauId: matchday.id },
        orderBy: { createdAt: 'desc' }
    });
    let token = existing?.token || (0, crypto_1.randomUUID)();
    let expiresAt = existing?.expiresAt ?? null;
    if (parsed.data.expiresInDays) {
        expiresAt = (0, date_fns_1.addDays)(new Date(), parsed.data.expiresInDays);
    }
    else if (existing?.expiresAt && existing.expiresAt < new Date()) {
        // Re-enable an expired link while keeping the same URL.
        expiresAt = null;
    }
    if (existing) {
        await prisma.plateauShareToken.update({
            where: { id: existing.id },
            data: { expiresAt: expiresAt ?? null }
        });
    }
    else {
        await prisma.plateauShareToken.create({
            data: {
                plateauId: matchday.id,
                token,
                expiresAt: expiresAt ?? undefined
            }
        });
    }
    const url = `${APP_BASE_URL.replace(/\/+$/, '')}/public/matchday/${token}`;
    res.json({ token, url, expiresAt });
});
app.post('/matchday/:id/repair-rotation-keys', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const dryRun = req.query.dryRun === '1' || req.query.dryRun === 'true';
    const matchday = await matchdayFindFirstForUser(prisma, req.auth, {
        where: { id: req.params.id },
        select: { id: true },
    });
    if (!matchday)
        return res.status(404).json({ error: 'Matchday not found' });
    const matches = await matchFindManyForUser(prisma, req.auth, {
        where: { plateauId: matchday.id },
        select: { id: true, rotationGameKey: true, createdAt: true },
        orderBy: { createdAt: 'asc' },
    });
    if (!matches.length) {
        return res.json({ ok: true, dryRun, matchdayId: matchday.id, total: 0, repaired: 0, repairedMatchIds: [] });
    }
    const used = new Set(matches
        .map((m) => (typeof m.rotationGameKey === 'string' ? m.rotationGameKey.trim() : ''))
        .filter((key) => key.length > 0));
    const repairs = [];
    for (const [index, match] of matches.entries()) {
        const current = typeof match.rotationGameKey === 'string' ? match.rotationGameKey.trim() : '';
        if (current.length > 0)
            continue;
        let candidate = `schedule:${index}`;
        if (used.has(candidate)) {
            let suffix = 1;
            while (used.has(`schedule:${index}:${suffix}`))
                suffix += 1;
            candidate = `schedule:${index}:${suffix}`;
        }
        used.add(candidate);
        repairs.push({ id: match.id, rotationGameKey: candidate });
    }
    if (!dryRun && repairs.length > 0) {
        await prisma.$transaction(repairs.map((repair) => prisma.match.update({
            where: { id: repair.id },
            data: { rotationGameKey: repair.rotationGameKey },
        })));
    }
    return res.json({
        ok: true,
        dryRun,
        matchdayId: matchday.id,
        total: matches.length,
        repaired: repairs.length,
        repairedMatchIds: repairs.map((r) => r.id),
    });
});
app.delete('/matchday/:id/share', authMiddleware, async (req, res) => {
    const matchday = await matchdayFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!matchday)
        return res.status(404).json({ error: 'Matchday not found' });
    await prisma.plateauShareToken.deleteMany({ where: { plateauId: matchday.id } });
    res.json({ ok: true });
});
app.get('/public/matchday/:token', async (req, res) => {
    const result = await getPublicMatchdayPayloadByToken(req.params.token);
    return res.status(result.status).json(result.body);
});
app.delete('/matchday/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        // Ensure matchday exists
        const exists = await matchdayFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!exists)
            return res.status(404).json({ error: 'Matchday not found' });
        // Collect related matches and teams
        const matches = await matchFindManyForUser(prisma, req.auth, { where: { plateauId: id }, include: { teams: true } });
        const matchIds = matches.map((m) => m.id);
        const teamIds = matches.flatMap((m) => m.teams.map((t) => t.id));
        await prisma.$transaction(async (tx) => {
            await tx.scorer.deleteMany({ where: { matchId: { in: matchIds } } });
            await tx.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } });
            await tx.matchTeam.deleteMany({ where: { matchId: { in: matchIds } } });
            await tx.match.deleteMany({ where: { id: { in: matchIds } } });
            await attendanceDeleteManyForUser(tx, req.auth, {
                session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] },
                session_id: id
            });
            await tx.plateau.delete({ where: { id: exists.id } });
        });
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Matchday not found' });
        console.error('[DELETE /matchday/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete matchday' });
    }
});
// Get a single matchday by id
app.get('/matchday/:id', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (token)
        return next();
    const result = await getPublicMatchdayPayloadByToken(req.params.id);
    if (result.status !== 200)
        return res.status(result.status).json(result.body);
    return res.json(result.body.matchday);
});
app.get('/matchday/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const matchday = await matchdayFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!matchday)
            return res.status(404).json({ error: 'Matchday not found' });
        res.json(matchday);
    }
    catch (e) {
        console.error('[GET /matchday/:id] failed', e);
        return res.status(500).json({ error: 'Failed to fetch matchday' });
    }
});
// Aggregated view for a matchday
app.get('/matchday/:id/summary', async (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (token)
        return next();
    const result = await getPublicMatchdayPayloadByToken(req.params.id);
    return res.status(result.status).json(result.body);
});
app.get('/matchday/:id/summary', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const includeAllPlayers = req.query.includeAllPlayers === '1' || req.query.includeAllPlayers === 'true';
    try {
        const matchday = await matchdayFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!matchday)
            return res.status(404).json({ error: 'Matchday not found' });
        // Attendance (present/absent records) for this matchday, include player info
        const attendance = await attendanceFindManyForUser(prisma, req.auth, {
            where: {
                session_id: id,
                session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] },
            },
            select: {
                playerId: true,
                session_type: true,
                player: {
                    select: {
                        id: true,
                        name: true,
                        primary_position: true,
                        secondary_position: true,
                        email: true,
                        phone: true,
                    },
                },
            },
        });
        // Build attendancePlayers and playersById from attendance
        const attendancePlayers = attendance.map(a => a.player).filter(Boolean);
        const playersById = {};
        for (const pl of attendancePlayers) {
            playersById[pl.id] = {
                id: pl.id,
                name: pl.name,
                primary_position: pl.primary_position ?? null,
                secondary_position: pl.secondary_position ?? null,
                email: pl.email ?? null,
                phone: pl.phone ?? null
            };
        }
        // Matches for this matchday (with teams and scorers first)
        const matchesRaw = await matchFindManyForUser(prisma, req.auth, {
            where: { plateauId: id },
            include: {
                teams: { select: { id: true, side: true, score: true } },
                scorers: { select: { id: true, playerId: true, assistId: true, side: true } }
            },
            orderBy: { createdAt: 'asc' }
        });
        const hasPersistedRotationKey = matchesRaw.some((m) => {
            return typeof m.rotationGameKey === 'string' && m.rotationGameKey.trim().length > 0;
        });
        let hasPlanningRotation = false;
        let rotation = null;
        const planning = await findLatestPlanningForMatchday(prisma, {
            date: matchday.date,
            userId: matchday.userId ?? null,
            teamId: matchday.teamId ?? null,
            clubId: matchday.clubId ?? null,
        });
        if (planning) {
            const planningData = safeParseJSON(planning.data);
            const candidate = findRotationCandidate(planningData);
            hasPlanningRotation = Boolean(candidate);
            rotation = normalizePublicRotation(candidate, planning.updatedAt.toISOString());
        }
        const mode = (0, matchday_contract_1.deriveMatchdayMode)({ hasPersistedRotationKey, hasPlanningRotation });
        if (mode === 'ROTATION' && !rotation) {
            const fallbackRotationMatches = matchesRaw.map((m) => ({
                createdAt: m.createdAt,
                updatedAt: m.updatedAt,
                opponentName: m.opponentName ?? null,
                teams: (m.teams || []).map((team) => ({ side: team.side })),
            }));
            rotation = buildPublicMatchdayRotation(fallbackRotationMatches);
        }
        // Fetch all team players in one query and attach player objects
        const allTeamIds = matchesRaw.flatMap((m) => m.teams.map((t) => t.id));
        const mtPlayers = allTeamIds.length ? await prisma.matchTeamPlayer.findMany({
            where: { matchTeamId: { in: allTeamIds } },
            select: {
                matchTeamId: true,
                playerId: true,
                role: true,
                player: {
                    select: {
                        id: true,
                        name: true,
                        primary_position: true,
                        secondary_position: true,
                        email: true,
                        phone: true,
                    },
                },
            },
        }) : [];
        const byTeam = {};
        for (const row of mtPlayers) {
            if (!byTeam[row.matchTeamId])
                byTeam[row.matchTeamId] = [];
            byTeam[row.matchTeamId].push(row);
        }
        const matchesRawWithContractKeys = (0, matchday_contract_1.ensureRotationGameKeysForContract)(matchesRaw, mode === 'ROTATION');
        // Build enriched matches with teams[].players including player info
        const matches = matchesRawWithContractKeys.map((m) => {
            const status = (0, match_status_1.resolveMatchStatus)({ status: m.status, played: Boolean(m.played) });
            const { plateauId, ...rest } = m;
            return {
                ...rest,
                matchdayId: plateauId ?? null,
                status,
                played: (0, match_status_1.derivePlayedFromStatus)(status),
                rotationGameKey: m.rotationGameKey ?? null,
                teams: m.teams.map((t) => ({
                    ...t,
                    players: (byTeam[t.id] || []).map(p => ({
                        playerId: p.playerId,
                        role: p.role,
                        player: p.player
                    }))
                }))
            };
        });
        // Hydrate playersById from match teams and build convocations
        const convocatedMap = {};
        for (const m of matches) {
            for (const t of m.teams) {
                for (const p of t.players) {
                    const pl = p.player;
                    if (pl) {
                        playersById[pl.id] = playersById[pl.id] || {
                            id: pl.id,
                            name: pl.name,
                            primary_position: pl.primary_position ?? null,
                            secondary_position: pl.secondary_position ?? null,
                            email: pl.email ?? null,
                            phone: pl.phone ?? null
                        };
                        if (!convocatedMap[pl.id])
                            convocatedMap[pl.id] = playersById[pl.id];
                    }
                }
            }
        }
        for (const pl of attendancePlayers) {
            if (!convocatedMap[pl.id])
                convocatedMap[pl.id] = playersById[pl.id];
        }
        // Ensure we know all players (for listing). We do not auto-mark as convoked.
        if (includeAllPlayers) {
            try {
                const allPlayers = await playerFindManyForUser(prisma, req.auth, {
                    orderBy: { name: 'asc' },
                    select: {
                        id: true,
                        name: true,
                        primary_position: true,
                        secondary_position: true,
                        email: true,
                        phone: true,
                    },
                });
                for (const pl of allPlayers) {
                    if (!playersById[pl.id]) {
                        playersById[pl.id] = {
                            id: pl.id,
                            name: pl.name,
                            primary_position: pl.primary_position ?? null,
                            secondary_position: pl.secondary_position ?? null,
                            email: pl.email ?? null,
                            phone: pl.phone ?? null,
                        };
                    }
                }
            }
            catch (e) {
                // If fetching all players fails for any reason, proceed with partial list
                console.warn('[summary] failed to include full players list', e?.message || e);
            }
        }
        // Mark presence/absence and convocation using attendance
        const attendanceMap = new Map();
        const convokeSet = new Set();
        for (const a of attendance) {
            if (a.session_type === 'PLATEAU_CONVOKE') {
                convokeSet.add(a.playerId);
                continue;
            }
            if (a.present === true) {
                attendanceMap.set(a.playerId, true);
                continue;
            }
            if (a.present === false) {
                attendanceMap.set(a.playerId, false);
                continue;
            }
            // No `present` field: use session_type marker if available
            if (a.session_type === 'PLATEAU_ABSENT') {
                attendanceMap.set(a.playerId, false);
                continue;
            }
            // Old schema "present" implied by existence of PLATEAU row
            if (a.session_type === 'PLATEAU') {
                attendanceMap.set(a.playerId, true);
                continue;
            }
        }
        // Build convocations list for ALL players known in playersById
        const convocations = Object.values(playersById).map(pl => {
            const att = attendanceMap.get(pl.id);
            let status;
            if (att === true)
                status = 'present';
            else if (att === false)
                status = 'absent';
            else if (convokeSet.has(pl.id))
                status = 'convoque';
            else
                status = 'non_convoque';
            return { player: pl, status, present: status === 'present' };
        });
        // Add scorersDetailed to each match, resolving playerName from playersById
        const matchesEnriched = matches.map(m => ({
            ...m,
            scorersDetailed: m.scorers.map((s) => ({
                ...s,
                playerName: playersById[s.playerId]?.name || null,
                assistName: s.assistId ? (playersById[s.assistId]?.name || null) : null
            }))
        }));
        const stats = {
            matchesTotal: matchesEnriched.length,
            matchesPlayed: (0, match_status_1.countPlayedMatchesExcludingCancelled)(matchesEnriched),
            matchesCancelled: matchesEnriched.filter((m) => (0, match_status_1.resolveMatchStatus)({ status: m.status, played: m.played }) === 'CANCELLED').length,
        };
        res.json({
            matchday,
            mode,
            rotation: mode === 'ROTATION' ? (rotation || { updatedAt: new Date().toISOString(), teams: [], slots: [] }) : null,
            matches: matchesEnriched,
            convocations,
            playersById,
            stats,
            rotationGameKeyFormat: {
                canonical: 'schedule:{index}',
                accepts: ['schedule:*', 'legacy:*'],
            },
        });
    }
    catch (e) {
        console.error('[GET /matchday/:id/summary] failed', e);
        return res.status(500).json({ error: 'Failed to fetch matchday summary' });
    }
});
// ---- Attendance (TRAINING / PLATEAU) ----
app.get('/attendance', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        session_type: zod_1.z.enum(['TRAINING', 'PLATEAU']).optional(),
        session_id: zod_1.z.string().optional()
    });
    const parsed = schema.safeParse(req.query);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { session_type, session_id } = parsed.data;
    let scopeAuth = req.auth;
    if (session_type && session_id) {
        const resolved = await resolveAttendanceScopeFromSession(req.auth, session_type, session_id);
        if (!resolved)
            return res.status(404).json({ error: `${session_type === 'TRAINING' ? 'Training' : 'Matchday'} not found` });
        scopeAuth = resolved;
    }
    const where = {};
    if (session_type)
        where.session_type = { in: (0, attendance_1.attendanceSessionTypeVariants)(session_type) };
    else
        where.session_type = { in: ['TRAINING', 'TRAINING_ABSENT', 'PLATEAU', 'PLATEAU_ABSENT'] };
    if (session_id)
        where.session_id = session_id;
    const pagination = readPagination(req.query, { limit: 200, maxLimit: 500 });
    const rows = await attendanceFindManyForUser(prisma, scopeAuth, {
        where,
        take: pagination.take,
        skip: pagination.skip,
    });
    res.json({
        items: rows.map(attendance_1.normalizeAttendanceRow),
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: rows.length }
    });
});
app.post('/attendance', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        session_type: zod_1.z.enum(['TRAINING', 'PLATEAU']),
        session_id: zod_1.z.string(),
        playerId: zod_1.z.string(),
        // Some clients omit `present` when unchecking; treat missing as absent.
        present: zod_1.z.boolean().optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { session_type, session_id, playerId } = parsed.data;
    const present = parsed.data.present ?? false;
    const scopeAuth = await resolveAttendanceScopeFromSession(req.auth, session_type, session_id);
    if (!scopeAuth)
        return res.status(404).json({ error: `${session_type === 'TRAINING' ? 'Training' : 'Matchday'} not found` });
    await attendanceSetPresenceForUser(prisma, scopeAuth, { session_type, session_id, playerId, present });
    res.json({ ok: true });
});
// ---- Matches ----
function rowsForMatchTeam(matchTeamId, ids, role) {
    return ids.map((playerId) => ({ matchTeamId, playerId, role }));
}
function normalizeMatchState(input) {
    const status = (0, match_status_1.resolvePatchedMatchStatus)({
        payloadStatus: input.payload.status,
        payloadPlayed: input.payload.played,
        existingStatus: input.fallbackStatus ?? 'PLANNED',
    });
    const normalized = (0, match_status_1.normalizeMatchWriteState)({
        status,
        score: input.payload.score,
        buteurs: input.payload.buteurs,
    });
    return {
        status,
        played: normalized.played,
        score: normalized.score,
        buteurs: normalized.buteurs,
    };
}
function toMatchEventResponse(row) {
    return {
        id: row.id,
        matchId: row.matchId,
        minute: row.minute,
        type: row.type,
        scorerId: row.scorerId ?? null,
        assistId: row.assistId ?? null,
        slotId: row.slotId ?? null,
        inPlayerId: row.inPlayerId ?? null,
        outPlayerId: row.outPlayerId ?? null,
        createdAt: row.createdAt,
    };
}
async function listMatchEventsByMatchId(db, matchId) {
    try {
        const rows = await db.matchEvent.findMany({
            where: { matchId },
            orderBy: [{ minute: 'asc' }, { createdAt: 'asc' }],
        });
        return rows.map(toMatchEventResponse);
    }
    catch (e) {
        if (e?.code === 'P2021')
            return [];
        throw e;
    }
}
async function listMatchEventsForUser(db, scopeOrUserId, matchId) {
    const match = await matchFindFirstForUser(db, scopeOrUserId, {
        where: { id: matchId },
        select: { id: true },
    });
    if (!match)
        return null;
    return listMatchEventsByMatchId(db, matchId);
}
async function assertEventPlayerIdsInMatchScope(db, scopeOrUserId, matchId, playerIds) {
    const uniqueIds = Array.from(new Set(playerIds.filter(Boolean)));
    if (!uniqueIds.length)
        return;
    const matchTeams = await db.matchTeam.findMany({
        where: { matchId },
        select: { id: true },
    });
    const matchTeamIds = matchTeams.map((row) => row.id);
    const rows = matchTeamIds.length
        ? await db.matchTeamPlayer.findMany({
            where: {
                matchTeamId: { in: matchTeamIds },
                playerId: { in: uniqueIds },
            },
            select: { playerId: true },
        })
        : [];
    const foundIds = new Set(rows.map((row) => row.playerId));
    const missingInMatchTeams = uniqueIds.filter((id) => !foundIds.has(id));
    if (!missingInMatchTeams.length)
        return;
    const scopedPlayers = await playerFindManyForUser(db, scopeOrUserId, {
        where: { id: { in: missingInMatchTeams } },
        select: { id: true },
    });
    const scopedIds = new Set(scopedPlayers.map((row) => row.id));
    const forbiddenPlayerId = missingInMatchTeams.find((id) => !scopedIds.has(id));
    if (forbiddenPlayerId) {
        const err = new Error(`Player ${forbiddenPlayerId} is outside match scope`);
        err.code = 'PLAYER_SCOPE_FORBIDDEN';
        throw err;
    }
}
async function assertPlayerIdsInMatchTeams(db, matchId, playerIds) {
    const uniqueIds = Array.from(new Set(playerIds.filter(Boolean)));
    if (!uniqueIds.length)
        return;
    const matchTeams = await db.matchTeam.findMany({
        where: { matchId },
        select: { id: true },
    });
    const matchTeamIds = matchTeams.map((row) => row.id);
    const rows = matchTeamIds.length
        ? await db.matchTeamPlayer.findMany({
            where: {
                matchTeamId: { in: matchTeamIds },
                playerId: { in: uniqueIds },
            },
            select: { playerId: true },
        })
        : [];
    const foundIds = new Set(rows.map((row) => row.playerId));
    const missing = uniqueIds.filter((id) => !foundIds.has(id));
    if (!missing.length)
        return;
    const err = new Error(`Players not in match teams: ${missing.join(', ')}`);
    err.code = 'PLAYER_NOT_IN_MATCH_TEAMS';
    throw err;
}
async function getMatchDetailForUser(db, scopeOrUserId, id) {
    const match = await matchFindFirstForUser(db, scopeOrUserId, {
        where: { id },
        include: { teams: true, scorers: true }
    });
    if (!match)
        return null;
    let eligiblePlayerIds = null;
    if (match.plateauId) {
        const attendanceRows = await attendanceFindManyForUser(db, scopeOrUserId, {
            where: {
                session_id: match.plateauId,
                session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] },
            },
            select: {
                playerId: true,
                session_type: true,
            },
        });
        eligiblePlayerIds = (0, match_eligibility_1.buildEligiblePlayerIdsFromMatchdayAttendance)(attendanceRows);
    }
    const teamIds = (match.teams || []).map((t) => t.id);
    const teamPlayers = teamIds.length ? await db.matchTeamPlayer.findMany({
        where: { matchTeamId: { in: teamIds } },
        include: { player: true }
    }) : [];
    const byTeam = {};
    for (const row of teamPlayers) {
        if (!byTeam[row.matchTeamId])
            byTeam[row.matchTeamId] = [];
        byTeam[row.matchTeamId].push(row);
    }
    const allPlayersById = {};
    for (const row of teamPlayers) {
        const pl = row.player;
        if (!pl)
            continue;
        allPlayersById[pl.id] = allPlayersById[pl.id] || {
            id: pl.id,
            name: pl.name,
            primary_position: pl.primary_position ?? null,
            secondary_position: pl.secondary_position ?? null
        };
    }
    const playersById = {};
    const teams = (match.teams || []).map((team) => ({
        id: team.id,
        side: team.side,
        score: team.score,
        players: (byTeam[team.id] || []).filter((row) => {
            return !eligiblePlayerIds || eligiblePlayerIds.has(row.playerId);
        }).map((row) => {
            const pl = row.player;
            if (pl) {
                playersById[pl.id] = playersById[pl.id] || {
                    id: pl.id,
                    name: pl.name,
                    primary_position: pl.primary_position ?? null,
                    secondary_position: pl.secondary_position ?? null
                };
            }
            return {
                playerId: row.playerId,
                role: row.role,
                player: pl ? allPlayersById[pl.id] : null
            };
        })
    }));
    const scorers = (match.scorers || []).map((s) => ({
        id: s.id,
        playerId: s.playerId,
        side: s.side,
        assistId: s.assistId ?? null,
        playerName: allPlayersById[s.playerId]?.name || playersById[s.playerId]?.name || null,
        assistName: s.assistId ? (allPlayersById[s.assistId]?.name || playersById[s.assistId]?.name || null) : null
    }));
    const events = await listMatchEventsByMatchId(db, id);
    const status = (0, match_status_1.resolveMatchStatus)({ status: match.status, played: Boolean(match.played) });
    return {
        id: match.id,
        createdAt: match.createdAt,
        type: match.type,
        status,
        played: (0, match_status_1.derivePlayedFromStatus)(status),
        matchdayId: match.plateauId ?? null,
        rotationGameKey: match.rotationGameKey ?? null,
        opponentName: match.opponentName ?? null,
        tactic: match.tactic ?? null,
        teams,
        scorers,
        events,
        playersById
    };
}
app.get('/matches', authMiddleware, async (req, res) => {
    const pagination = readPagination(req.query, { limit: 50, maxLimit: 200 });
    const { matchdayId } = req.query;
    const where = matchdayId ? { plateauId: String(matchdayId) } : {};
    const matches = await matchFindManyForUser(prisma, req.auth, {
        where,
        include: { teams: true, scorers: true },
        orderBy: { createdAt: 'desc' },
        take: pagination.take,
        skip: pagination.skip,
    });
    let hasPlanningRotation = false;
    const hasPersistedRotationKey = matches.some((match) => typeof match.rotationGameKey === 'string' && match.rotationGameKey.trim().length > 0);
    if (matchdayId && !hasPersistedRotationKey) {
        const matchday = await matchdayFindFirstForUser(prisma, req.auth, {
            where: { id: String(matchdayId) },
            select: { date: true, userId: true, teamId: true, clubId: true },
        });
        if (matchday) {
            const planning = await findLatestPlanningForMatchday(prisma, matchday);
            if (planning) {
                const planningData = safeParseJSON(planning.data);
                hasPlanningRotation = Boolean(findRotationCandidate(planningData));
            }
        }
    }
    const mode = (0, matchday_contract_1.deriveMatchdayMode)({ hasPersistedRotationKey, hasPlanningRotation });
    const matchesWithContractKeys = (0, matchday_contract_1.ensureRotationGameKeysForContract)(matches, mode === 'ROTATION');
    res.json({
        items: matchesWithContractKeys.map((match) => {
            const status = (0, match_status_1.resolveMatchStatus)({ status: match.status, played: Boolean(match.played) });
            const { plateauId, ...rest } = match;
            return {
                ...rest,
                matchdayId: plateauId ?? null,
                status,
                played: (0, match_status_1.derivePlayedFromStatus)(status),
                tactic: match.tactic ?? null,
                rotationGameKey: match.rotationGameKey ?? null,
            };
        }),
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: matches.length }
    });
});
app.get('/matches/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const match = await getMatchDetailForUser(prisma, req.auth, id);
        if (!match)
            return res.status(404).json({ error: 'Match not found' });
        return res.json(match);
    }
    catch (e) {
        console.error('[GET /matches/:id] failed', e);
        return res.status(500).json({ error: 'Failed to fetch match' });
    }
});
app.get('/matches/:id/events', authMiddleware, async (req, res) => {
    const { id: matchId } = req.params;
    try {
        const events = await listMatchEventsForUser(prisma, req.auth, matchId);
        if (!events)
            return res.status(404).json({ error: 'Match not found' });
        return res.json(events);
    }
    catch (e) {
        console.error('[GET /matches/:id/events] failed', e);
        return res.status(500).json({ error: 'Failed to fetch match events' });
    }
});
app.post('/matches/:id/events', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id: matchId } = req.params;
    const parsed = match_events_1.matchEventCreateSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    try {
        const match = await matchFindFirstForUser(prisma, req.auth, {
            where: { id: matchId },
            select: { id: true, status: true, played: true },
        });
        if (!match)
            return res.status(404).json({ error: 'Match not found' });
        if ((0, match_status_1.resolveMatchStatus)({ status: match.status, played: Boolean(match.played) }) === 'CANCELLED') {
            return res.status(409).json({ error: 'Cannot start live actions on a cancelled match' });
        }
        const payload = parsed.data;
        const playerIds = [payload.scorerId, payload.assistId, payload.inPlayerId, payload.outPlayerId].filter(Boolean);
        await assertEventPlayerIdsInMatchScope(prisma, req.auth, matchId, playerIds);
        const created = await prisma.matchEvent.create({
            data: {
                matchId,
                minute: payload.minute,
                type: payload.type,
                scorerId: payload.scorerId ?? null,
                assistId: payload.assistId ?? null,
                slotId: payload.slotId ?? null,
                inPlayerId: payload.inPlayerId ?? null,
                outPlayerId: payload.outPlayerId ?? null,
            },
        });
        return res.status(201).json(toMatchEventResponse(created));
    }
    catch (e) {
        if (e?.code === 'PLAYER_SCOPE_FORBIDDEN')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'P2003')
            return res.status(400).json({ error: 'Invalid foreign key reference in event payload' });
        if (e?.code === 'P2021')
            return res.status(503).json({ error: 'Match event storage unavailable' });
        console.error('[POST /matches/:id/events] failed', e);
        return res.status(500).json({ error: 'Failed to create match event' });
    }
});
app.delete('/matches/:id/events/:eventId', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const { id: matchId, eventId } = req.params;
    try {
        const match = await matchFindFirstForUser(prisma, req.auth, {
            where: { id: matchId },
            select: { id: true },
        });
        if (!match)
            return res.status(404).json({ error: 'Match not found' });
        const deleted = await prisma.matchEvent.deleteMany({
            where: { id: eventId, matchId },
        });
        if (deleted.count === 0)
            return res.status(404).json({ error: 'Match event not found' });
        return res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2021')
            return res.status(503).json({ error: 'Match event storage unavailable' });
        console.error('[DELETE /matches/:id/events/:eventId] failed', e);
        return res.status(500).json({ error: 'Failed to delete match event' });
    }
});
app.post('/matches', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = match_payload_1.matchCreatePayloadSchema.safeParse(req.body);
    if (!parsed.success) {
        const firstIssue = parsed.error.issues[0];
        return res.status(400).json({ error: firstIssue?.message || parsed.error.flatten() });
    }
    const { type, matchdayId, sides, score, buteurs, opponentName, played, status, tactic, rotationGameKey } = parsed.data;
    const normalized = normalizeMatchState({
        payload: { played, status, score, buteurs },
        fallbackStatus: 'PLANNED',
    });
    if (status === 'CANCELLED' && played === true) {
        return res.status(400).json({ error: 'played must be false when status is CANCELLED' });
    }
    let team = null;
    let teamFormat = null;
    if (matchdayId) {
        const ownedMatchday = await matchdayFindFirstForUser(prisma, req.auth, {
            where: { id: matchdayId },
            select: { teamId: true, clubId: true },
        });
        if (!ownedMatchday)
            return res.status(404).json({ error: 'Matchday not found' });
        team = { id: ownedMatchday.teamId, clubId: ownedMatchday.clubId };
    }
    else {
        try {
            team = await resolveTeamForWrite(req.auth);
        }
        catch (e) {
            return res.status(400).json({ error: e.message });
        }
    }
    const owningTeam = team?.id
        ? await prisma.team.findFirst({
            where: { id: team.id, ...(team?.clubId ? { clubId: team.clubId } : {}) },
            select: { format: true },
        })
        : null;
    teamFormat = owningTeam?.format ?? null;
    const payloadValidation = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
        teamFormat,
        sides,
        tactic,
    });
    if (!payloadValidation.ok)
        return res.status(400).json({ error: payloadValidation.error });
    try {
        const match = await matchCreateForUser(prisma, req.auth, {
            type, plateauId: matchdayId, opponentName, played: normalized.played, status: normalized.status,
            rotationGameKey: rotationGameKey ?? null,
            tactic: tactic ?? null,
            clubId: team?.clubId ?? req.auth.clubId ?? null,
            teamId: team?.id ?? null
        });
        const home = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'home', score: normalized.score.home } });
        const away = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'away', score: normalized.score.away } });
        const toMTP = (matchTeamId, ids, role) => ids.map(playerId => ({ matchTeamId, playerId, role }));
        const mtps = [
            ...toMTP(home.id, sides.home.starters, 'starter'),
            ...toMTP(home.id, sides.home.subs, 'sub'),
            ...toMTP(away.id, sides.away.starters, 'starter'),
            ...toMTP(away.id, sides.away.subs, 'sub'),
        ];
        const uniqueMtps = Array.from(new Map(mtps.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values());
        if (uniqueMtps.length)
            await prisma.matchTeamPlayer.createMany({ data: uniqueMtps });
        if (normalized.buteurs.length) {
            const scorerPlayerIds = normalized.buteurs.flatMap((b) => [b.playerId, b.assistId ?? null].filter(Boolean));
            await assertPlayerIdsInMatchTeams(prisma, match.id, scorerPlayerIds);
            await prisma.scorer.createMany({
                data: normalized.buteurs.map((b) => ({
                    matchId: match.id,
                    playerId: b.playerId,
                    assistId: b.assistId ?? null,
                    side: b.side,
                }))
            });
        }
        const full = await matchFindUniqueCompat(prisma, {
            where: { id: match.id },
            include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
        });
        const { plateauId, ...rest } = full;
        res.status(201).json({ ...rest, matchdayId: plateauId ?? null });
    }
    catch (e) {
        if (e?.code === 'PLAYER_NOT_IN_MATCH_TEAMS')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'P2003')
            return res.status(400).json({ error: 'Invalid scorer reference in payload' });
        console.error('[POST /matches] failed', e);
        return res.status(500).json({ error: 'Failed to create match' });
    }
});
// Update a match: score, opponentName, and (optionally) scorers (replace all)
app.put('/matches/:id', authMiddleware, async (req, res) => {
    const matchId = req.params.id;
    const forceClearRotationKey = req.query.forceClearRotationKey === '1'
        || req.query.forceClearRotationKey === 'true'
        || req.body?.forceClearRotationKey === true;
    const schema = zod_1.z.object({
        type: zod_1.z.enum(['ENTRAINEMENT', 'PLATEAU']).optional(),
        status: zod_1.z.enum(['PLANNED', 'PLAYED', 'CANCELLED']).optional(),
        played: zod_1.z.boolean().optional(),
        matchdayId: zod_1.z.string().nullable().optional(),
        rotationGameKey: zod_1.z.string().min(1).max(120).nullable().optional(),
        sides: zod_1.z.object({
            home: zod_1.z.object({
                starters: zod_1.z.array(zod_1.z.string()).default([]),
                subs: zod_1.z.array(zod_1.z.string()).default([])
            }),
            away: zod_1.z.object({
                starters: zod_1.z.array(zod_1.z.string()).default([]),
                subs: zod_1.z.array(zod_1.z.string()).default([])
            })
        }),
        score: zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) }),
        buteurs: zod_1.z.array(match_payload_1.matchScorerPayloadSchema).default([]),
        opponentName: zod_1.z.string().max(100).optional(),
        tactic: match_tactic_1.matchTacticSchema.nullable().optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    if (parsed.data.status === 'CANCELLED' && parsed.data.played === true) {
        return res.status(400).json({ error: 'played must be false when status is CANCELLED' });
    }
    try {
        const payload = parsed.data;
        const updatedId = await prisma.$transaction(async (tx) => {
            const existing = await matchFindFirstForUser(tx, req.auth, {
                where: { id: matchId },
                include: { teams: { select: { id: true, side: true } } }
            });
            if (!existing) {
                const err = new Error('Match not found');
                err.code = 'MATCH_NOT_FOUND';
                throw err;
            }
            const owningTeam = existing.teamId
                ? await tx.team.findFirst({
                    where: { id: existing.teamId, clubId: req.auth.clubId },
                    select: { format: true },
                })
                : null;
            const payloadValidation = (0, match_update_validation_1.validateMatchUpdatePayloadForTeamFormat)({
                teamFormat: owningTeam?.format,
                sides: payload.sides,
                tactic: payload.tactic,
            });
            if (!payloadValidation.ok) {
                const err = new Error(payloadValidation.error);
                err.code = 'MATCH_PAYLOAD_INVALID';
                throw err;
            }
            if (payloadValidation.usedFallback) {
                console.warn('[PUT /matches/:id] invalid or missing team format, fallback applied', {
                    matchId,
                    fallbackFormat: payloadValidation.format,
                });
            }
            const existingStatus = (0, match_status_1.resolveMatchStatus)({ status: existing.status, played: Boolean(existing.played) });
            const normalized = normalizeMatchState({
                payload: {
                    played: payload.played,
                    status: payload.status,
                    score: payload.score,
                    buteurs: payload.buteurs,
                },
                fallbackStatus: existingStatus,
            });
            if (payload.matchdayId !== undefined && payload.matchdayId) {
                const matchday = await matchdayFindFirstForUser(tx, req.auth, { where: { id: payload.matchdayId }, select: { id: true } });
                if (!matchday) {
                    const err = new Error('Matchday not found');
                    err.code = 'MATCHDAY_NOT_FOUND';
                    throw err;
                }
            }
            const teamBySide = { home: null, away: null };
            for (const team of existing.teams || []) {
                if (team.side === 'home' || team.side === 'away') {
                    const side = team.side;
                    teamBySide[side] = team;
                }
            }
            if (!teamBySide.home) {
                teamBySide.home = await tx.matchTeam.create({ data: { matchId, side: 'home', score: normalized.score.home }, select: { id: true, side: true } });
            }
            if (!teamBySide.away) {
                teamBySide.away = await tx.matchTeam.create({ data: { matchId, side: 'away', score: normalized.score.away }, select: { id: true, side: true } });
            }
            const matchPatch = {};
            if (payload.type !== undefined)
                matchPatch.type = payload.type;
            if (payload.played !== undefined || payload.status !== undefined) {
                matchPatch.played = normalized.played;
                matchPatch.status = normalized.status;
            }
            if (payload.matchdayId !== undefined) {
                matchPatch.plateau = payload.matchdayId
                    ? { connect: { id: payload.matchdayId } }
                    : { disconnect: true };
            }
            if (payload.rotationGameKey !== undefined) {
                const currentRotationGameKey = typeof existing.rotationGameKey === 'string'
                    ? existing.rotationGameKey.trim()
                    : '';
                if (payload.rotationGameKey === null && currentRotationGameKey.length > 0 && !forceClearRotationKey) {
                    // Non-destructive default: keep existing rotation key unless clear is explicit.
                    console.warn('[PUT /matches/:id] rotationGameKey clear ignored (use forceClearRotationKey=true to clear)', {
                        matchId,
                        existingRotationGameKey: currentRotationGameKey,
                    });
                }
                else {
                    matchPatch.rotationGameKey = payload.rotationGameKey ?? null;
                }
            }
            if (payload.opponentName !== undefined)
                matchPatch.opponentName = payload.opponentName;
            if (payload.tactic !== undefined)
                matchPatch.tactic = payload.tactic;
            if (Object.keys(matchPatch).length > 0) {
                await tx.match.update({ where: { id: matchId }, data: matchPatch });
            }
            await Promise.all([
                tx.matchTeam.update({ where: { id: teamBySide.home.id }, data: { score: normalized.score.home } }),
                tx.matchTeam.update({ where: { id: teamBySide.away.id }, data: { score: normalized.score.away } })
            ]);
            await tx.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: [teamBySide.home.id, teamBySide.away.id] } } });
            const mtps = [
                ...rowsForMatchTeam(teamBySide.home.id, payload.sides.home.starters, 'starter'),
                ...rowsForMatchTeam(teamBySide.home.id, payload.sides.home.subs, 'sub'),
                ...rowsForMatchTeam(teamBySide.away.id, payload.sides.away.starters, 'starter'),
                ...rowsForMatchTeam(teamBySide.away.id, payload.sides.away.subs, 'sub'),
            ];
            const uniqueMtps = Array.from(new Map(mtps.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values());
            if (uniqueMtps.length) {
                await tx.matchTeamPlayer.createMany({ data: uniqueMtps });
            }
            await tx.scorer.deleteMany({ where: { matchId } });
            if (normalized.buteurs.length) {
                const scorerPlayerIds = normalized.buteurs.flatMap((b) => [b.playerId, b.assistId ?? null].filter(Boolean));
                await assertPlayerIdsInMatchTeams(tx, matchId, scorerPlayerIds);
                await tx.scorer.createMany({
                    data: normalized.buteurs.map((b) => ({
                        matchId,
                        playerId: b.playerId,
                        assistId: b.assistId ?? null,
                        side: b.side,
                    }))
                });
            }
            try {
                const [goalForCount, goalAgainstCount] = await Promise.all([
                    tx.matchEvent.count({ where: { matchId, type: 'GOAL_FOR' } }),
                    tx.matchEvent.count({ where: { matchId, type: 'GOAL_AGAINST' } }),
                ]);
                if (goalForCount !== normalized.score.home || goalAgainstCount !== normalized.score.away) {
                    console.warn('[PUT /matches/:id] score/events mismatch', {
                        matchId,
                        expected: normalized.score,
                        eventsCount: { GOAL_FOR: goalForCount, GOAL_AGAINST: goalAgainstCount },
                    });
                }
            }
            catch (e) {
                if (e?.code !== 'P2021')
                    throw e;
            }
            return existing.id;
        });
        const updated = await getMatchDetailForUser(prisma, req.auth, updatedId);
        if (!updated)
            return res.status(404).json({ error: 'Match not found' });
        return res.json(updated);
    }
    catch (e) {
        if (e?.code === 'MATCH_NOT_FOUND')
            return res.status(404).json({ error: 'Match not found' });
        if (e?.code === 'MATCHDAY_NOT_FOUND')
            return res.status(404).json({ error: 'Matchday not found' });
        if (e?.code === 'MATCH_PAYLOAD_INVALID')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'PLAYER_NOT_IN_MATCH_TEAMS')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'P2003')
            return res.status(400).json({ error: 'Invalid scorer reference in payload' });
        console.error('[PUT /matches/:id] failed', e);
        return res.status(500).json({ error: 'Failed to update match' });
    }
});
// Delete a match (cascade delete teams, players, scorers)
app.delete('/matches/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        const exists = await matchFindFirstForUser(prisma, req.auth, { where: { id } });
        if (!exists)
            return res.status(404).json({ error: 'Match not found' });
        const teams = await prisma.matchTeam.findMany({ where: { matchId: id } });
        const teamIds = teams.map(t => t.id);
        await prisma.$transaction([
            prisma.scorer.deleteMany({ where: { matchId: id } }),
            prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
            prisma.matchTeam.deleteMany({ where: { matchId: id } }),
            prisma.match.delete({ where: { id: exists.id } })
        ]);
        res.json({ ok: true });
    }
    catch (e) {
        console.error('[DELETE /matches/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete match' });
    }
});
// ---- Schedule generator (pairings only) ----
function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}
app.post('/schedule/generate', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        teams: zod_1.z.array(zod_1.z.array(zod_1.z.string().min(1))).min(2),
        options: zod_1.z.object({ m: zod_1.z.number().int().min(1), allowRematch: zod_1.z.boolean().optional() }).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { teams, options } = parsed.data;
    const n = teams.length;
    const m = options?.m ?? Math.max(1, n - 1);
    const allowRematch = options?.allowRematch ?? false;
    const idx = shuffle(Array.from({ length: n }, (_, i) => i));
    const pairs = [];
    const played = new Set();
    outer: for (let round = 0; round < m; round++) {
        for (let a = 0; a < n; a++) {
            for (let b = a + 1; b < n; b++) {
                const i = idx[a], j = idx[b];
                const key = i < j ? `${i}-${j}` : `${j}-${i}`;
                if (!allowRematch && played.has(key))
                    continue;
                pairs.push({ home: i, away: j });
                played.add(key);
                if (pairs.length >= Math.ceil((m * n) / 2))
                    break outer;
            }
        }
    }
    res.json({ matches: pairs, teamCount: n });
});
app.post('/schedule/commit', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const schema = zod_1.z.object({
        matchdayId: zod_1.z.string().optional(),
        teams: zod_1.z.array(zod_1.z.array(zod_1.z.string().min(1))).min(2),
        schedule: zod_1.z.object({ matches: zod_1.z.array(zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) })) }),
        defaults: zod_1.z.object({ startersPerTeam: zod_1.z.number().int().min(1).max(11).default(5) }).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { matchdayId, teams, schedule, defaults } = parsed.data;
    const startersPerTeam = defaults?.startersPerTeam ?? 5;
    let targetTeam = null;
    if (matchdayId) {
        const ownedMatchday = await matchdayFindFirstForUser(prisma, req.auth, { where: { id: matchdayId } });
        if (!ownedMatchday)
            return res.status(404).json({ error: 'Matchday not found' });
        targetTeam = { id: ownedMatchday.teamId, clubId: ownedMatchday.clubId };
    }
    else {
        try {
            targetTeam = await resolveTeamForWrite(req.auth);
        }
        catch (e) {
            return res.status(400).json({ error: e.message });
        }
    }
    const createdIds = await prisma.$transaction(async (db) => {
        const ids = [];
        for (const [index, m] of schedule.matches.entries()) {
            const match = await matchCreateForUser(db, req.auth, {
                type: matchdayId ? 'PLATEAU' : 'ENTRAINEMENT',
                plateauId: matchdayId,
                status: 'PLANNED',
                played: false,
                rotationGameKey: matchdayId ? `schedule:${index}` : null,
                clubId: targetTeam?.clubId ?? req.auth.clubId ?? null,
                teamId: targetTeam?.id ?? null
            });
            const home = await db.matchTeam.create({ data: { matchId: match.id, side: 'home', score: 0 } });
            const away = await db.matchTeam.create({ data: { matchId: match.id, side: 'away', score: 0 } });
            const pick = (arr) => arr.slice(0, startersPerTeam);
            const toMTP = (matchTeamId, ids, role) => ids.map(playerId => ({ matchTeamId, playerId, role }));
            const homeIds = teams[m.home] ?? [];
            const awayIds = teams[m.away] ?? [];
            const rows = [
                ...toMTP(home.id, pick(homeIds), 'starter'),
                ...toMTP(away.id, pick(awayIds), 'starter'),
            ];
            const uniqueRows = Array.from(new Map(rows.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values());
            if (uniqueRows.length)
                await db.matchTeamPlayer.createMany({ data: uniqueRows });
            ids.push(match.id);
        }
        return ids;
    });
    const matches = await matchFindManyForUser(prisma, req.auth, {
        where: { id: { in: createdIds } },
        include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
    });
    const normalizedMatches = matches.map((match) => {
        const { plateauId, ...rest } = match;
        return { ...rest, matchdayId: plateauId ?? null };
    });
    res.json({ ok: true, createdCount: createdIds.length, matches: normalizedMatches });
});
// ---- Training drills (exercices attachés à une séance) ----
app.post('/trainings/:id/drills/generate-ai', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const trainingId = req.params.id;
    const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } });
    if (!training)
        return res.status(404).json({ error: 'Training not found' });
    const schema = zod_1.z.object({
        objective: zod_1.z.string().min(10).max(400),
        includeDiagrams: zod_1.z.boolean().optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const team = await prisma.team.findFirst({
        where: {
            id: training.teamId,
            ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
        },
        select: { id: true, name: true }
    });
    if (!team)
        return res.status(404).json({ error: 'Team not found' });
    const ageBand = inferAgeBandFromTeamName(team.name);
    const includeDiagrams = parsed.data.includeDiagrams === true;
    const aiRequestId = (0, crypto_1.randomUUID)().slice(0, 8);
    const aiStartAt = Date.now();
    let generated;
    try {
        generated = await generateDrillsWithOpenAI({
            objective: parsed.data.objective,
            ageBand,
            teamName: team.name || 'Equipe',
        }, { includeVisualPlan: false });
        console.log('[POST /trainings/:id/drills/generate-ai] OpenAI success', {
            requestId: aiRequestId,
            durationMs: Date.now() - aiStartAt,
            count: generated.length,
        });
    }
    catch (e) {
        const logError = summarizeErrorForLog(e);
        console.error('[POST /trainings/:id/drills/generate-ai] OpenAI failed', {
            requestId: aiRequestId,
            durationMs: Date.now() - aiStartAt,
            ...logError,
        });
        if (e?.code === 'OPENAI_API_KEY_MISSING') {
            return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' });
        }
        if (e?.code === 'OPENAI_TIMEOUT') {
            return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' });
        }
        if (e?.code === 'OPENAI_NETWORK_ERROR') {
            return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' });
        }
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota') {
            return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' });
        }
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401) {
            return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' });
        }
        if (e?.code === 'OPENAI_INVALID_JSON') {
            return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' });
        }
        if (e?.code === 'OPENAI_SCHEMA_MISMATCH') {
            return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' });
        }
        return res.status(502).json({ error: 'Failed to generate drills with AI' });
    }
    const created = await prisma.$transaction(async (tx) => {
        const existingRows = await trainingDrillFindManyForUser(tx, req.auth, {
            where: { trainingId },
            select: { order: true }
        });
        let nextOrder = existingRows.reduce((max, row) => Math.max(max, row.order ?? -1), -1) + 1;
        const items = [];
        for (const [index, item] of generated.entries()) {
            const id = await buildUniqueDrillId(tx, req.auth, item.title);
            const drill = await drillCreateForUser(tx, req.auth, {
                id,
                clubId: training.clubId,
                teamId: training.teamId,
                title: item.title,
                category: item.category,
                duration: item.duration,
                players: item.players,
                description: item.description,
                tags: item.tags,
            });
            const trainingDrill = await trainingDrillCreateForUser(tx, req.auth, {
                trainingId,
                drillId: drill.id,
                duration: item.duration,
                notes: null,
                order: nextOrder++,
            });
            items.push({
                drill: { ...drill, descriptionHtml: item.descriptionHtml },
                trainingDrill,
                diagram: null
            });
            if (includeDiagrams) {
                const diagramData = buildDefaultDiagramData(index, item);
                const diagram = await diagramCreateForUser(tx, req.auth, {
                    drillId: drill.id,
                    title: `${drill.title} - Diagramme`,
                    data: JSON.stringify(diagramData),
                });
                items[items.length - 1].diagram = { ...diagram, data: diagramData };
            }
        }
        return items;
    });
    res.status(201).json({
        objective: parsed.data.objective,
        ageBand,
        includeDiagrams,
        count: created.length,
        items: created
    });
});
// Lister les exercices d'une séance (avec enrichissement à partir du catalogue Drill)
app.get('/trainings/:id/drills', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } });
    if (!training)
        return res.status(404).json({ error: 'Training not found' });
    const rows = await listTrainingDrillsInOrder(prisma, req.auth, trainingId);
    const catalog = await drillFindManyForUser(prisma, req.auth, { orderBy: { createdAt: 'asc' } });
    const catalogById = new Map(catalog.map((drill) => [drill.id, withDrillDescriptionHtml(drill)]));
    const items = rows.map(r => {
        const meta = catalogById.get(r.drillId) || null;
        return { ...r, meta };
    });
    res.json(items);
});
// Ajouter un exercice à une séance
app.post('/trainings/:id/drills', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } });
    if (!training)
        return res.status(404).json({ error: 'Training not found' });
    const schema = zod_1.z.object({
        drillId: zod_1.z.string().min(1),
        duration: zod_1.z.number().int().min(1).max(120).optional(),
        notes: zod_1.z.string().max(1000).optional(),
        trainingDrillId: zod_1.z.string().min(1).optional(),
        replaceTrainingDrillId: zod_1.z.string().min(1).optional(),
        id: zod_1.z.string().min(1).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: parsed.data.drillId } });
    if (!drill)
        return res.status(404).json({ error: 'Drill not found' });
    const requestedTrainingDrillRef = parsed.data.trainingDrillId ||
        parsed.data.replaceTrainingDrillId ||
        (parsed.data.id && parsed.data.id !== parsed.data.drillId ? parsed.data.id : undefined);
    if (requestedTrainingDrillRef) {
        const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, requestedTrainingDrillRef);
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        const updated = await prisma.trainingDrill.update({
            where: { id: existing.id },
            data: {
                drillId: parsed.data.drillId,
                ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration } : {}),
                ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes } : {}),
            }
        });
        const meta = drill;
        return res.json({ ...updated, meta });
    }
    const row = await prisma.$transaction(async (tx) => {
        const existingRows = await trainingDrillFindManyForUser(tx, req.auth, {
            where: { trainingId },
            select: { order: true }
        });
        const nextOrder = existingRows.reduce((max, currentRow) => Math.max(max, currentRow.order ?? -1), -1) + 1;
        return trainingDrillCreateForUser(tx, req.auth, {
            trainingId, drillId: parsed.data.drillId, duration: parsed.data.duration, notes: parsed.data.notes, order: nextOrder
        });
    });
    const meta = drill;
    res.json({ ...row, meta });
});
// Modifier (notes/duration/order)
app.put('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const trainingDrillId = req.params.trainingDrillId;
    const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, trainingDrillId);
    if (!existing)
        return res.status(404).json({ error: 'Not found' });
    const schema = zod_1.z.object({
        drillId: zod_1.z.string().min(1).optional(),
        duration: zod_1.z.number().int().min(1).max(120).nullable().optional(),
        notes: zod_1.z.string().max(1000).nullable().optional(),
        order: zod_1.z.number().int().min(0).optional()
    }).refine((data) => (data.drillId !== undefined ||
        data.duration !== undefined ||
        data.notes !== undefined ||
        data.order !== undefined), {
        message: 'At least one field must be provided',
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    if (parsed.data.drillId !== undefined) {
        const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: parsed.data.drillId } });
        if (!drill)
            return res.status(404).json({ error: 'Drill not found' });
    }
    try {
        const updateData = {
            ...(parsed.data.drillId !== undefined ? { drillId: parsed.data.drillId } : {}),
            ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration ?? null } : {}),
            ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes ?? null } : {}),
        };
        const updated = await prisma.$transaction(async (tx) => {
            if (parsed.data.order !== undefined) {
                await moveTrainingDrillToOrder(tx, req.auth, trainingId, existing.id, parsed.data.order);
            }
            if (Object.keys(updateData).length > 0) {
                return tx.trainingDrill.update({
                    where: { id: existing.id },
                    data: updateData
                });
            }
            return tx.trainingDrill.findUnique({
                where: { id: existing.id }
            });
        });
        if (!updated)
            return res.status(404).json({ error: 'Not found' });
        const meta = await drillFindFirstForUser(prisma, req.auth, { where: { id: updated.drillId } });
        res.json({ ...updated, meta });
    }
    catch (e) {
        if (e?.code === 'INVALID_ORDER') {
            return res.status(400).json({ error: 'Invalid order' });
        }
        res.status(404).json({ error: 'Not found' });
    }
});
// Supprimer un exercice d'une séance
app.delete('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const trainingDrillId = req.params.trainingDrillId;
    try {
        const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, trainingDrillId);
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        const deleted = await prisma.$transaction(async (tx) => {
            await tx.diagram.deleteMany({ where: applyScopeWhere(req.auth, { trainingDrillId: existing.id }, { includeLegacyOwner: true }) });
            const removed = await tx.trainingDrill.deleteMany({ where: { id: existing.id } });
            if (removed.count) {
                await normalizeTrainingDrillOrders(tx, req.auth, trainingId);
            }
            return removed;
        });
        if (!deleted.count)
            return res.status(404).json({ error: 'Not found' });
        res.json({ ok: true });
    }
    catch (e) {
        console.error('[DELETE /trainings/:id/drills/:trainingDrillId] failed', e);
        res.status(500).json({ error: 'Failed to delete training drill' });
    }
});
// ---- Diagrams (exercices) ----
app.post('/drills/:id/diagrams/generate-ai', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const drillId = req.params.id;
    const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: drillId } });
    if (!drill)
        return res.status(404).json({ error: 'Drill not found' });
    const schema = zod_1.z.object({
        objective: zod_1.z.string().min(3).max(400).optional(),
    });
    const parsed = schema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let ageBand = 'U9-U11';
    if (drill.teamId) {
        const team = await prisma.team.findFirst({
            where: { id: drill.teamId, ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}) },
            select: { name: true }
        });
        if (team?.name)
            ageBand = inferAgeBandFromTeamName(team.name);
    }
    const requestId = (0, crypto_1.randomUUID)().slice(0, 8);
    const startAt = Date.now();
    try {
        const visualPlan = await generateVisualPlanWithOpenAI({
            title: drill.title,
            category: drill.category,
            description: drill.description,
            tags: Array.isArray(drill.tags) ? drill.tags : [],
            ageBand,
            objective: parsed.data.objective,
        });
        const diagramData = buildDefaultDiagramData(0, {
            title: drill.title,
            category: drill.category,
            tags: Array.isArray(drill.tags) ? drill.tags : [],
            visualPlan
        });
        const created = await diagramCreateForUser(prisma, req.auth, {
            drillId: drill.id,
            title: `${drill.title} - Diagramme IA`,
            data: JSON.stringify(diagramData),
        });
        console.log('[POST /drills/:id/diagrams/generate-ai] OpenAI success', {
            requestId,
            durationMs: Date.now() - startAt,
            drillId: drill.id,
        });
        return res.status(201).json({ ...created, data: diagramData });
    }
    catch (e) {
        console.error('[POST /drills/:id/diagrams/generate-ai] OpenAI failed', {
            requestId,
            durationMs: Date.now() - startAt,
            ...summarizeErrorForLog(e),
        });
        if (e?.code === 'OPENAI_API_KEY_MISSING')
            return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' });
        if (e?.code === 'OPENAI_TIMEOUT')
            return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' });
        if (e?.code === 'OPENAI_NETWORK_ERROR')
            return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' });
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota')
            return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' });
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401)
            return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' });
        if (e?.code === 'OPENAI_INVALID_JSON')
            return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' });
        if (e?.code === 'OPENAI_SCHEMA_MISMATCH')
            return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' });
        return res.status(502).json({ error: 'Failed to generate diagram with AI' });
    }
});
app.post('/training-drills/:id/diagrams/generate-ai', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const trainingDrillId = req.params.id;
    const trainingDrill = await trainingDrillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrillId } });
    if (!trainingDrill)
        return res.status(404).json({ error: 'Training drill not found' });
    const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrill.drillId } });
    if (!drill)
        return res.status(404).json({ error: 'Drill not found' });
    const schema = zod_1.z.object({
        objective: zod_1.z.string().min(3).max(400).optional(),
    });
    const parsed = schema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let ageBand = 'U9-U11';
    if (trainingDrill.teamId || drill.teamId) {
        const team = await prisma.team.findFirst({
            where: { id: trainingDrill.teamId || drill.teamId, ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}) },
            select: { name: true }
        });
        if (team?.name)
            ageBand = inferAgeBandFromTeamName(team.name);
    }
    const requestId = (0, crypto_1.randomUUID)().slice(0, 8);
    const startAt = Date.now();
    try {
        const visualPlan = await generateVisualPlanWithOpenAI({
            title: drill.title,
            category: drill.category,
            description: drill.description,
            tags: Array.isArray(drill.tags) ? drill.tags : [],
            ageBand,
            objective: parsed.data.objective,
        });
        const diagramData = buildDefaultDiagramData(0, {
            title: drill.title,
            category: drill.category,
            tags: Array.isArray(drill.tags) ? drill.tags : [],
            visualPlan
        });
        const created = await diagramCreateForUser(prisma, req.auth, {
            trainingDrillId: trainingDrill.id,
            title: `${drill.title} - Diagramme IA`,
            data: JSON.stringify(diagramData),
        });
        console.log('[POST /training-drills/:id/diagrams/generate-ai] OpenAI success', {
            requestId,
            durationMs: Date.now() - startAt,
            trainingDrillId: trainingDrill.id,
        });
        return res.status(201).json({ ...created, data: diagramData });
    }
    catch (e) {
        console.error('[POST /training-drills/:id/diagrams/generate-ai] OpenAI failed', {
            requestId,
            durationMs: Date.now() - startAt,
            ...summarizeErrorForLog(e),
        });
        if (e?.code === 'OPENAI_API_KEY_MISSING')
            return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' });
        if (e?.code === 'OPENAI_TIMEOUT')
            return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' });
        if (e?.code === 'OPENAI_NETWORK_ERROR')
            return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' });
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota')
            return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' });
        if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401)
            return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' });
        if (e?.code === 'OPENAI_INVALID_JSON')
            return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' });
        if (e?.code === 'OPENAI_SCHEMA_MISMATCH')
            return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' });
        return res.status(502).json({ error: 'Failed to generate diagram with AI' });
    }
});
app.get('/drills/:id/diagrams', authMiddleware, async (req, res) => {
    const drillId = req.params.id;
    const rows = await diagramFindManyForUser(prisma, req.auth, { where: { drillId }, orderBy: { updatedAt: 'desc' } });
    res.json(rows);
});
app.get('/training-drills/:id/diagrams', authMiddleware, async (req, res) => {
    const trainingDrillId = req.params.id;
    const rows = await diagramFindManyForUser(prisma, req.auth, { where: { trainingDrillId }, orderBy: { updatedAt: 'desc' } });
    res.json(rows);
});
app.get('/diagrams/:id', authMiddleware, async (req, res) => {
    const d = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
    if (!d)
        return res.status(404).json({ error: 'Not found' });
    res.json(d);
});
app.post('/drills/:id/diagrams', authMiddleware, async (req, res) => {
    const drillId = req.params.id;
    const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: drillId } });
    if (!drill)
        return res.status(404).json({ error: 'Drill not found' });
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        data: zod_1.z.any() // JSON
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const created = await diagramCreateForUser(prisma, req.auth, {
        drillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data)
    });
    res.json({ ...created, data: parsed.data.data });
});
app.post('/training-drills/:id/diagrams', authMiddleware, async (req, res) => {
    const trainingDrillId = req.params.id;
    const trainingDrill = await trainingDrillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrillId } });
    if (!trainingDrill)
        return res.status(404).json({ error: 'Training drill not found' });
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        data: zod_1.z.any()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const created = await diagramCreateForUser(prisma, req.auth, {
        trainingDrillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data)
    });
    res.json({ ...created, data: parsed.data.data });
});
app.put('/diagrams/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100).optional(),
        data: zod_1.z.any().optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const patch = {};
    if (parsed.data.title !== undefined)
        patch.title = parsed.data.title;
    if (parsed.data.data !== undefined)
        patch.data = JSON.stringify(parsed.data.data);
    try {
        const existing = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        const updated = await prisma.diagram.update({ where: { id: existing.id }, data: patch });
        res.json({ ...updated, data: parsed.data.data ?? JSON.parse(updated.data) });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Not found' });
        console.error('[PUT /diagrams/:id] failed', e);
        return res.status(500).json({ error: 'Failed to update diagram' });
    }
});
app.delete('/diagrams/:id', authMiddleware, async (req, res) => {
    try {
        const existing = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } });
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        const deleted = await prisma.diagram.deleteMany({ where: { id: existing.id } });
        if (!deleted.count)
            return res.status(404).json({ error: 'Not found' });
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Not found' });
        console.error('[DELETE /diagrams/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete diagram' });
    }
});
app.get('/team-messages/unread-count', authMiddleware, async (req, res) => {
    const count = await computeUnreadTeamMessagesCount(req.auth);
    return res.json({ count });
});
app.get('/team-messages', authMiddleware, async (req, res) => {
    const queryParsed = zod_1.z.object({
        teamId: zod_1.z.string().trim().min(1).optional(),
        limit: zod_1.z.coerce.number().int().min(1).max(100).optional(),
        offset: zod_1.z.coerce.number().int().min(0).optional(),
    }).safeParse(req.query);
    if (!queryParsed.success) {
        return res.status(400).json({ error: queryParsed.error.issues[0]?.message || queryParsed.error.flatten() });
    }
    let team;
    try {
        team = await resolveReadableTeamForMessaging(req.auth, queryParsed.data.teamId);
    }
    catch (e) {
        if (e?.code === 'TEAM_REQUIRED')
            return res.status(400).json({ error: e.message });
        if (e?.code === 'TEAM_FORBIDDEN')
            return res.status(403).json({ error: e.message });
        return res.status(400).json({ error: e.message || 'Invalid team scope' });
    }
    const pagination = readPagination(queryParsed.data, { limit: 30, maxLimit: 100 });
    const items = await prisma.teamMessage.findMany({
        where: { clubId: team.clubId, teamId: team.id },
        include: {
            author: {
                select: { id: true, firstName: true, lastName: true, role: true },
            },
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: pagination.limit,
        skip: pagination.offset,
    });
    const messageIds = items.map((item) => item.id);
    const [likes, likedByMeRows] = await Promise.all([
        messageIds.length
            ? prisma.teamMessageLike.findMany({
                where: { messageId: { in: messageIds } },
                select: { messageId: true },
            })
            : Promise.resolve([]),
        messageIds.length
            ? prisma.teamMessageLike.findMany({
                where: { messageId: { in: messageIds }, userId: req.auth.id },
                select: { messageId: true },
            })
            : Promise.resolve([]),
    ]);
    const likesCountByMessageId = new Map();
    for (const like of likes)
        likesCountByMessageId.set(like.messageId, (likesCountByMessageId.get(like.messageId) || 0) + 1);
    const likedByMeSet = new Set(likedByMeRows.map((row) => row.messageId));
    if (req.auth?.id) {
        const now = new Date();
        await prisma.teamMessageRead.upsert({
            where: { teamId_userId: { teamId: team.id, userId: req.auth.id } },
            create: {
                teamId: team.id,
                userId: req.auth.id,
                lastReadAt: now,
            },
            update: { lastReadAt: now },
        });
    }
    return res.json({
        items: items.map((item) => ({
            id: item.id,
            teamId: item.teamId,
            clubId: item.clubId,
            content: item.content,
            createdAt: item.createdAt,
            updatedAt: item.updatedAt,
            author: item.author ? {
                id: item.author.id,
                firstName: item.author.firstName || null,
                lastName: item.author.lastName || null,
                role: item.author.role,
            } : null,
            likesCount: likesCountByMessageId.get(item.id) || 0,
            likedByMe: likedByMeSet.has(item.id),
        })),
        pagination: { limit: pagination.limit, offset: pagination.offset, returned: items.length },
    });
});
app.post('/team-messages', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = teamMessageCreateBodySchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.issues[0]?.message || parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth, parsed.data.teamId || undefined);
    }
    catch (e) {
        if (e?.code === 'TEAM_FORBIDDEN')
            return res.status(403).json({ error: e.message });
        return res.status(400).json({ error: e.message || 'Invalid team scope' });
    }
    const created = await prisma.teamMessage.create({
        data: {
            clubId: team.clubId,
            teamId: team.id,
            authorUserId: req.auth.id,
            content: parsed.data.content,
        },
        include: {
            author: {
                select: { id: true, firstName: true, lastName: true, role: true },
            },
        },
    });
    return res.status(201).json({
        id: created.id,
        teamId: created.teamId,
        clubId: created.clubId,
        content: created.content,
        createdAt: created.createdAt,
        updatedAt: created.updatedAt,
        author: created.author ? {
            id: created.author.id,
            firstName: created.author.firstName || null,
            lastName: created.author.lastName || null,
            role: created.author.role,
        } : null,
        likesCount: 0,
        likedByMe: false,
    });
});
app.post('/team-messages/:id/reactions/like', authMiddleware, async (req, res) => {
    const message = await prisma.teamMessage.findUnique({
        where: { id: req.params.id },
        select: { id: true, teamId: true, clubId: true },
    });
    if (!message)
        return res.status(404).json({ error: 'Message not found' });
    try {
        await assertCanReadTeamOrThrow(req.auth, message.teamId, message.clubId);
    }
    catch (e) {
        return res.status(403).json({ error: e.message || 'Forbidden team scope' });
    }
    await prisma.teamMessageLike.upsert({
        where: { messageId_userId: { messageId: message.id, userId: req.auth.id } },
        create: {
            messageId: message.id,
            userId: req.auth.id,
        },
        update: {},
    });
    const likesCount = await prisma.teamMessageLike.count({ where: { messageId: message.id } });
    return res.json({ ok: true, likesCount, likedByMe: true });
});
app.delete('/team-messages/:id/reactions/like', authMiddleware, async (req, res) => {
    const message = await prisma.teamMessage.findUnique({
        where: { id: req.params.id },
        select: { id: true, teamId: true, clubId: true },
    });
    if (!message)
        return res.status(404).json({ error: 'Message not found' });
    try {
        await assertCanReadTeamOrThrow(req.auth, message.teamId, message.clubId);
    }
    catch (e) {
        return res.status(403).json({ error: e.message || 'Forbidden team scope' });
    }
    await prisma.teamMessageLike.deleteMany({ where: { messageId: message.id, userId: req.auth.id } });
    const likesCount = await prisma.teamMessageLike.count({ where: { messageId: message.id } });
    return res.json({ ok: true, likesCount, likedByMe: false });
});
app.get('/tactics', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = zod_1.z.object({ teamId: zod_1.z.string().min(1) }).safeParse(req.query);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { teamId } = parsed.data;
    if (!(0, tactics_1.canWriteTacticForTeam)(req.auth, teamId)) {
        return res.status(403).json({ error: 'Forbidden team scope for tactics' });
    }
    const rows = await prisma.tactic.findMany({
        where: { teamId },
        orderBy: { updatedAt: 'desc' },
    });
    return res.json(rows);
});
app.get('/tactics/:id', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const activeTeamId = getActiveTeamIdForAuth(req.auth);
    if (!activeTeamId)
        return res.status(400).json({ error: 'Active team selection is required' });
    const row = await prisma.tactic.findFirst({
        where: { id: req.params.id, teamId: activeTeamId },
    });
    if (!row)
        return res.status(404).json({ error: 'Tactic not found' });
    return res.json(row);
});
app.post('/tactics', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = tactics_1.tacticPayloadSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    if (parsed.data.teamId !== team.id || !(0, tactics_1.canWriteTacticForTeam)(req.auth, parsed.data.teamId)) {
        return res.status(403).json({ error: 'Forbidden team scope for tactics' });
    }
    try {
        const saved = await (0, tactics_1.upsertTacticByTeamAndName)(prisma.tactic, parsed.data);
        return res.json(saved);
    }
    catch (e) {
        if (e?.code === 'P2002') {
            const existing = await prisma.tactic.findFirst({
                where: {
                    teamId: parsed.data.teamId,
                    name: {
                        equals: parsed.data.name,
                        mode: 'insensitive',
                    },
                },
            });
            if (existing) {
                const updated = await prisma.tactic.update({
                    where: { id: existing.id },
                    data: {
                        name: parsed.data.name,
                        formation: parsed.data.formation,
                        points: parsed.data.points,
                    },
                });
                return res.json(updated);
            }
            return res.status(409).json({ error: 'Tactic name conflict for this team' });
        }
        console.error('[POST /tactics] failed', e);
        return res.status(500).json({ error: 'Failed to save tactic' });
    }
});
app.put('/tactics/:id', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    const parsed = tactics_1.tacticPayloadSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    let team;
    try {
        team = await resolveTeamForWrite(req.auth);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    if (parsed.data.teamId !== team.id || !(0, tactics_1.canWriteTacticForTeam)(req.auth, parsed.data.teamId)) {
        return res.status(403).json({ error: 'Forbidden team scope for tactics' });
    }
    const existing = await prisma.tactic.findFirst({
        where: { id: req.params.id, teamId: parsed.data.teamId },
    });
    if (!existing)
        return res.status(404).json({ error: 'Tactic not found' });
    try {
        const updated = await prisma.tactic.update({
            where: { id: existing.id },
            data: {
                name: parsed.data.name,
                formation: parsed.data.formation,
                points: parsed.data.points,
            },
        });
        return res.json(updated);
    }
    catch (e) {
        if (e?.code === 'P2002')
            return res.status(409).json({ error: 'Tactic name conflict for this team' });
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Tactic not found' });
        console.error('[PUT /tactics/:id] failed', e);
        return res.status(500).json({ error: 'Failed to update tactic' });
    }
});
app.delete('/tactics/:id', authMiddleware, async (req, res) => {
    if (!ensureStaff(req, res))
        return;
    let team;
    try {
        team = await resolveTeamForWrite(req.auth);
    }
    catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const deleted = await prisma.tactic.deleteMany({
        where: { id: req.params.id, teamId: team.id },
    });
    if (!deleted.count)
        return res.status(404).json({ error: 'Tactic not found' });
    return res.json({ ok: true });
});
// === END FOOT DOMAIN API ===
app.get('/health', (_req, res) => res.json({ ok: true }));
app.use((err, _req, res, _next) => {
    console.error('[unhandled]', err);
    if (res.headersSent)
        return;
    const status = err?.statusCode || err?.status || 500;
    res.status(status).json({
        error: status >= 500 ? 'Internal error' : (err?.message || 'Request failed')
    });
});
app.listen(PORT, () => {
    console.log(`API listening on ${PORT}`);
});
