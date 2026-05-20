"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.mobileAuthExchangeBodySchema = exports.mobileAuthCallbackQuerySchema = exports.mobileAuthStartQuerySchema = exports.mobileAuthPlatformSchema = exports.DEFAULT_MOBILE_AUTH_STATE_TTL_SECONDS = exports.DEFAULT_MOBILE_AUTH_CODE_TTL_SECONDS = exports.MOBILE_AUTH_WEB_PATH = exports.MOBILE_AUTH_STATE_COOKIE_NAME = void 0;
exports.hashMobileAuthValue = hashMobileAuthValue;
exports.createMobileAuthState = createMobileAuthState;
exports.createMobileAuthCode = createMobileAuthCode;
exports.signMobileAuthStateCookie = signMobileAuthStateCookie;
exports.verifyMobileAuthStateCookie = verifyMobileAuthStateCookie;
exports.validateMobileAuthCodeRecord = validateMobileAuthCodeRecord;
exports.consumeMobileAuthExchange = consumeMobileAuthExchange;
exports.buildMobileAuthWebUrl = buildMobileAuthWebUrl;
exports.buildMobileAuthCallbackUrl = buildMobileAuthCallbackUrl;
exports.buildMobileAuthAppCallbackUrl = buildMobileAuthAppCallbackUrl;
const crypto_1 = require("crypto");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
exports.MOBILE_AUTH_STATE_COOKIE_NAME = 'izifoot_mobile_auth';
exports.MOBILE_AUTH_WEB_PATH = '/auth/mobile';
exports.DEFAULT_MOBILE_AUTH_CODE_TTL_SECONDS = 300;
exports.DEFAULT_MOBILE_AUTH_STATE_TTL_SECONDS = 600;
const MOBILE_AUTH_SECRET_MIN_LENGTH = 16;
const MOBILE_AUTH_SECRET_MAX_LENGTH = 512;
const MOBILE_AUTH_REDIRECT_URI_MAX_LENGTH = 1024;
const DISALLOWED_REDIRECT_PROTOCOLS = new Set(['data:', 'file:', 'javascript:']);
exports.mobileAuthPlatformSchema = zod_1.z.enum(['ios']);
exports.mobileAuthStartQuerySchema = zod_1.z.object({
    platform: exports.mobileAuthPlatformSchema,
    redirect_uri: zod_1.z.string()
        .trim()
        .min(1)
        .max(MOBILE_AUTH_REDIRECT_URI_MAX_LENGTH)
        .refine((value) => isSafeRedirectUri(value), 'Invalid redirect_uri')
        .optional(),
    state: zod_1.z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH).optional(),
});
exports.mobileAuthCallbackQuerySchema = zod_1.z.object({
    state: zod_1.z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
});
exports.mobileAuthExchangeBodySchema = zod_1.z.object({
    platform: exports.mobileAuthPlatformSchema.optional().default('ios'),
    code: zod_1.z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
    state: zod_1.z.string().trim().min(MOBILE_AUTH_SECRET_MIN_LENGTH).max(MOBILE_AUTH_SECRET_MAX_LENGTH),
});
function hashMobileAuthValue(value, secret) {
    return (0, crypto_1.createHmac)('sha256', secret).update(value).digest('hex');
}
function createMobileAuthState() {
    return (0, crypto_1.randomBytes)(24).toString('base64url');
}
function createMobileAuthCode() {
    return (0, crypto_1.randomBytes)(32).toString('base64url');
}
function signMobileAuthStateCookie(params) {
    assertSafeRedirectUri(params.redirectUri);
    const ttlSeconds = params.ttlSeconds ?? exports.DEFAULT_MOBILE_AUTH_STATE_TTL_SECONDS;
    const payload = {
        aud: 'mobile_auth',
        platform: params.platform,
        stateHash: hashMobileAuthValue(params.state, params.secret),
        redirectUri: params.redirectUri,
    };
    return jsonwebtoken_1.default.sign(payload, params.secret, { expiresIn: ttlSeconds });
}
function verifyMobileAuthStateCookie(params) {
    if (!params.token)
        return { ok: false, error: 'state_invalid' };
    try {
        const payload = jsonwebtoken_1.default.verify(params.token, params.secret);
        if (payload.aud !== 'mobile_auth')
            return { ok: false, error: 'state_invalid' };
        if (payload.platform !== params.platform)
            return { ok: false, error: 'state_invalid' };
        if (typeof payload.redirectUri !== 'string' || !isSafeRedirectUri(payload.redirectUri)) {
            return { ok: false, error: 'state_invalid' };
        }
        const stateHash = hashMobileAuthValue(params.state, params.secret);
        if (payload.stateHash !== stateHash)
            return { ok: false, error: 'state_invalid' };
        return { ok: true, stateHash, redirectUri: payload.redirectUri };
    }
    catch (error) {
        if (error instanceof jsonwebtoken_1.default.TokenExpiredError) {
            return { ok: false, error: 'state_expired' };
        }
        return { ok: false, error: 'state_invalid' };
    }
}
function validateMobileAuthCodeRecord(record, params) {
    const now = params.now ?? new Date();
    const hashedState = hashMobileAuthValue(params.state, params.secret);
    if (record.platform !== params.platform.toUpperCase()) {
        return { ok: false, error: 'platform_invalid' };
    }
    if (record.stateHash !== hashedState) {
        return { ok: false, error: 'state_invalid' };
    }
    if (record.usedAt) {
        return { ok: false, error: 'code_used' };
    }
    if (record.expiresAt.getTime() <= now.getTime()) {
        return { ok: false, error: 'code_expired' };
    }
    return { ok: true };
}
async function consumeMobileAuthExchange(store, params) {
    const now = params.now ?? new Date();
    const codeHash = hashMobileAuthValue(params.code, params.secret);
    const record = await store.findByCodeHash(codeHash);
    if (!record) {
        return {
            ok: false,
            status: 404,
            error: 'Mobile auth code not found',
            code: 'MOBILE_AUTH_CODE_NOT_FOUND',
        };
    }
    const validation = validateMobileAuthCodeRecord(record, params);
    if (!validation.ok) {
        if (validation.error === 'platform_invalid') {
            return {
                ok: false,
                status: 400,
                error: 'Unsupported mobile auth platform',
                code: 'MOBILE_AUTH_PLATFORM_INVALID',
            };
        }
        if (validation.error === 'state_invalid') {
            return {
                ok: false,
                status: 400,
                error: 'Invalid mobile auth state',
                code: 'MOBILE_AUTH_INVALID_STATE',
            };
        }
        if (validation.error === 'code_used') {
            return {
                ok: false,
                status: 409,
                error: 'Mobile auth code already used',
                code: 'MOBILE_AUTH_CODE_ALREADY_USED',
            };
        }
        return {
            ok: false,
            status: 410,
            error: 'Mobile auth code expired',
            code: 'MOBILE_AUTH_CODE_EXPIRED',
        };
    }
    const usedAt = now;
    const markedUsed = await store.markCodeUsed(record.id, usedAt);
    if (!markedUsed) {
        return {
            ok: false,
            status: 409,
            error: 'Mobile auth code already used',
            code: 'MOBILE_AUTH_CODE_ALREADY_USED',
        };
    }
    return { ok: true, record, usedAt };
}
function buildMobileAuthWebUrl(params) {
    const url = new URL(exports.MOBILE_AUTH_WEB_PATH, ensureTrailingSlash(params.appBaseUrl));
    url.searchParams.set('platform', params.platform);
    url.searchParams.set('state', params.state);
    if (params.error)
        url.searchParams.set('error', params.error);
    return url.toString();
}
function buildMobileAuthCallbackUrl(params) {
    const url = new URL('/auth/mobile/callback', ensureTrailingSlash(params.apiBaseUrl));
    url.searchParams.set('state', params.state);
    return url.toString();
}
function buildMobileAuthAppCallbackUrl(params) {
    assertSafeRedirectUri(params.callbackUrl);
    const url = new URL(params.callbackUrl);
    url.searchParams.set('code', params.code);
    url.searchParams.set('state', params.state);
    return url.toString();
}
function assertSafeRedirectUri(rawUrl) {
    if (!isSafeRedirectUri(rawUrl))
        throw new Error('Invalid redirect_uri');
}
function isSafeRedirectUri(rawUrl) {
    try {
        const url = new URL(rawUrl);
        return !DISALLOWED_REDIRECT_PROTOCOLS.has(url.protocol);
    }
    catch {
        return false;
    }
}
function ensureTrailingSlash(url) {
    return url.endsWith('/') ? url : `${url}/`;
}
