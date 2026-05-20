"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const account_password_1 = require("../account-password");
(0, node_test_1.default)('parseMePasswordPutBody accepts canonical fields', () => {
    const parsed = (0, account_password_1.parseMePasswordPutBody)({
        currentPassword: 'ancien-secret',
        newPassword: 'nouveau-secret',
    });
    strict_1.default.equal(parsed.success, true);
    if (parsed.success) {
        strict_1.default.equal(parsed.data.currentPassword, 'ancien-secret');
        strict_1.default.equal(parsed.data.newPassword, 'nouveau-secret');
    }
});
(0, node_test_1.default)('parseMePasswordPutBody accepts alias fields', () => {
    const parsed = (0, account_password_1.parseMePasswordPutBody)({
        current_password: 'ancien-secret',
        motDePasseNouveau: 'nouveau-secret',
    });
    strict_1.default.equal(parsed.success, true);
    if (parsed.success) {
        strict_1.default.equal(parsed.data.currentPassword, 'ancien-secret');
        strict_1.default.equal(parsed.data.newPassword, 'nouveau-secret');
    }
});
(0, node_test_1.default)('parseMePasswordPutBody rejects too short new password', () => {
    const parsed = (0, account_password_1.parseMePasswordPutBody)({
        currentPassword: 'ancien-secret',
        newPassword: '123',
    });
    strict_1.default.equal(parsed.success, false);
});
(0, node_test_1.default)('validatePasswordChangeInput rejects unchanged password', () => {
    const validated = (0, account_password_1.validatePasswordChangeInput)({
        currentPassword: 'secret-identique',
        newPassword: 'secret-identique',
    });
    strict_1.default.equal(validated.ok, false);
    if (!validated.ok)
        strict_1.default.match(validated.error, /different/);
});
