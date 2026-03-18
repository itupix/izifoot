"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const player_invitation_status_1 = require("../player-invitation-status");
(0, node_test_1.default)('returns NONE when no account and no invite', () => {
    const result = (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
        hasActiveAccount: false,
        latestPendingInvite: null,
        latestAcceptedInvite: null,
    });
    strict_1.default.equal(result.status, 'NONE');
    strict_1.default.equal(result.invitationId, null);
    strict_1.default.equal(result.lastInvitationAt, null);
});
(0, node_test_1.default)('returns PENDING when latest pending invite exists', () => {
    const sentAt = new Date('2026-03-18T09:30:00.000Z');
    const result = (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
        hasActiveAccount: false,
        latestPendingInvite: {
            id: 'inv_pending',
            createdAt: new Date('2026-03-17T09:30:00.000Z'),
            updatedAt: sentAt,
        },
        latestAcceptedInvite: null,
    });
    strict_1.default.equal(result.status, 'PENDING');
    strict_1.default.equal(result.invitationId, 'inv_pending');
    strict_1.default.equal(result.lastInvitationAt?.toISOString(), sentAt.toISOString());
});
(0, node_test_1.default)('returns ACCEPTED when account is already active', () => {
    const result = (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
        hasActiveAccount: true,
        latestPendingInvite: {
            id: 'inv_pending',
            createdAt: new Date('2026-03-17T09:30:00.000Z'),
            updatedAt: new Date('2026-03-18T09:30:00.000Z'),
        },
        latestAcceptedInvite: null,
    });
    strict_1.default.equal(result.status, 'ACCEPTED');
    strict_1.default.equal(result.invitationId, null);
});
(0, node_test_1.default)('ACCEPTED has priority over PENDING when both exist', () => {
    const acceptedAt = new Date('2026-03-18T11:00:00.000Z');
    const result = (0, player_invitation_status_1.resolvePlayerInvitationStatus)({
        hasActiveAccount: false,
        latestPendingInvite: {
            id: 'inv_pending',
            createdAt: new Date('2026-03-17T09:30:00.000Z'),
            updatedAt: new Date('2026-03-18T09:30:00.000Z'),
        },
        latestAcceptedInvite: {
            id: 'inv_accepted',
            createdAt: new Date('2026-03-16T09:30:00.000Z'),
            updatedAt: new Date('2026-03-18T10:30:00.000Z'),
            acceptedAt,
        },
    });
    strict_1.default.equal(result.status, 'ACCEPTED');
    strict_1.default.equal(result.invitationId, 'inv_accepted');
    strict_1.default.equal(result.lastInvitationAt?.toISOString(), acceptedAt.toISOString());
});
