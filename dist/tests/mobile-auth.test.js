"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const mobile_auth_1 = require("../mobile-auth");
const secret = 'mobile-auth-test-secret';
(0, node_test_1.default)('verifyMobileAuthStateCookie accepts a matching state cookie', () => {
    const state = 'state-value-123456';
    const token = (0, mobile_auth_1.signMobileAuthStateCookie)({
        platform: 'ios',
        state,
        redirectUri: 'izifoot://auth/callback',
        secret,
        ttlSeconds: 60,
    });
    const verified = (0, mobile_auth_1.verifyMobileAuthStateCookie)({
        token,
        platform: 'ios',
        state,
        secret,
    });
    strict_1.default.equal(verified.ok, true);
    if (verified.ok) {
        strict_1.default.equal(verified.stateHash, (0, mobile_auth_1.hashMobileAuthValue)(state, secret));
        strict_1.default.equal(verified.redirectUri, 'izifoot://auth/callback');
    }
});
(0, node_test_1.default)('validateMobileAuthCodeRecord rejects an invalid state', () => {
    const result = (0, mobile_auth_1.validateMobileAuthCodeRecord)({
        stateHash: (0, mobile_auth_1.hashMobileAuthValue)('expected-state', secret),
        platform: 'IOS',
        expiresAt: new Date('2026-05-19T10:05:00.000Z'),
        usedAt: null,
    }, {
        platform: 'ios',
        state: 'different-state',
        secret,
        now: new Date('2026-05-19T10:00:00.000Z'),
    });
    strict_1.default.deepEqual(result, { ok: false, error: 'state_invalid' });
});
(0, node_test_1.default)('validateMobileAuthCodeRecord rejects an expired code', () => {
    const state = 'state-expired';
    const result = (0, mobile_auth_1.validateMobileAuthCodeRecord)({
        stateHash: (0, mobile_auth_1.hashMobileAuthValue)(state, secret),
        platform: 'IOS',
        expiresAt: new Date('2026-05-19T09:59:59.000Z'),
        usedAt: null,
    }, {
        platform: 'ios',
        state,
        secret,
        now: new Date('2026-05-19T10:00:00.000Z'),
    });
    strict_1.default.deepEqual(result, { ok: false, error: 'code_expired' });
});
(0, node_test_1.default)('validateMobileAuthCodeRecord rejects an already used code', () => {
    const state = 'state-used';
    const result = (0, mobile_auth_1.validateMobileAuthCodeRecord)({
        stateHash: (0, mobile_auth_1.hashMobileAuthValue)(state, secret),
        platform: 'IOS',
        expiresAt: new Date('2026-05-19T10:05:00.000Z'),
        usedAt: new Date('2026-05-19T10:00:10.000Z'),
    }, {
        platform: 'ios',
        state,
        secret,
        now: new Date('2026-05-19T10:00:20.000Z'),
    });
    strict_1.default.deepEqual(result, { ok: false, error: 'code_used' });
});
(0, node_test_1.default)('validateMobileAuthCodeRecord accepts a fresh code/state pair', () => {
    const state = 'state-ok';
    const result = (0, mobile_auth_1.validateMobileAuthCodeRecord)({
        stateHash: (0, mobile_auth_1.hashMobileAuthValue)(state, secret),
        platform: 'IOS',
        expiresAt: new Date('2026-05-19T10:05:00.000Z'),
        usedAt: null,
    }, {
        platform: 'ios',
        state,
        secret,
        now: new Date('2026-05-19T10:00:00.000Z'),
    });
    strict_1.default.deepEqual(result, { ok: true });
});
(0, node_test_1.default)('consumeMobileAuthExchange succeeds once and marks the code used', async () => {
    const now = new Date('2026-05-19T10:00:00.000Z');
    const state = 'state-success-123456';
    const code = 'code-success-123456';
    let markedCodeId = null;
    const result = await (0, mobile_auth_1.consumeMobileAuthExchange)({
        async findByCodeHash(candidateHash) {
            strict_1.default.equal(candidateHash, (0, mobile_auth_1.hashMobileAuthValue)(code, secret));
            return {
                id: 'mobile-code-1',
                userId: 'user-1',
                stateHash: (0, mobile_auth_1.hashMobileAuthValue)(state, secret),
                platform: 'IOS',
                expiresAt: new Date(now.getTime() + 60000),
                usedAt: null,
            };
        },
        async markCodeUsed(codeId) {
            markedCodeId = codeId;
            return true;
        },
    }, {
        platform: 'ios',
        code,
        state,
        secret,
        now,
    });
    strict_1.default.equal(result.ok, true);
    if (result.ok) {
        strict_1.default.equal(result.record.id, 'mobile-code-1');
        strict_1.default.equal(result.record.userId, 'user-1');
    }
    strict_1.default.equal(markedCodeId, 'mobile-code-1');
});
(0, node_test_1.default)('mobile auth redirect builders preserve state and keep token exchange off URL', () => {
    strict_1.default.equal((0, mobile_auth_1.buildMobileAuthWebUrl)({
        appBaseUrl: 'https://app.izifoot.test',
        platform: 'ios',
        state: 'state-value-123456',
    }), 'https://app.izifoot.test/auth/mobile?platform=ios&state=state-value-123456');
    strict_1.default.equal((0, mobile_auth_1.buildMobileAuthCallbackUrl)({
        apiBaseUrl: 'https://api.izifoot.test',
        state: 'state-value-123456',
    }), 'https://api.izifoot.test/auth/mobile/callback?state=state-value-123456');
    strict_1.default.equal((0, mobile_auth_1.buildMobileAuthAppCallbackUrl)({
        callbackUrl: 'izifoot://auth/callback',
        code: 'code-value-123456',
        state: 'state-value-123456',
    }), 'izifoot://auth/callback?code=code-value-123456&state=state-value-123456');
});
