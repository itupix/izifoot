"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = __importDefault(require("node:test"));
const player_account_role_1 = require("../player-account-role");
(0, node_test_1.default)('child player invite role is PARENT', () => {
    strict_1.default.equal((0, player_account_role_1.resolvePlayerAccountInviteRole)(true), 'PARENT');
});
(0, node_test_1.default)('non-child player invite role is PLAYER', () => {
    strict_1.default.equal((0, player_account_role_1.resolvePlayerAccountInviteRole)(false), 'PLAYER');
});
(0, node_test_1.default)('child lookup roles keep PLAYER fallback for legacy invites', () => {
    strict_1.default.deepEqual((0, player_account_role_1.resolvePlayerAccountInviteLookupRoles)(true), ['PARENT', 'PLAYER']);
});
(0, node_test_1.default)('non-child lookup roles only include PLAYER', () => {
    strict_1.default.deepEqual((0, player_account_role_1.resolvePlayerAccountInviteLookupRoles)(false), ['PLAYER']);
});
