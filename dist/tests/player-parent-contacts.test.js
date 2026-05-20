"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const player_parent_contacts_1 = require("../player-parent-contacts");
(0, node_test_1.default)('synthetic parent invite emails are hidden from API payloads', () => {
    strict_1.default.equal((0, player_parent_contacts_1.isSyntheticParentInviteEmail)('parent+abc123@invite.izifoot.local'), true);
    strict_1.default.equal((0, player_parent_contacts_1.normalizeParentInviteEmail)('parent+abc123@invite.izifoot.local'), null);
    strict_1.default.equal((0, player_parent_contacts_1.normalizeParentInviteEmail)('parent@example.com'), 'parent@example.com');
});
(0, node_test_1.default)('summarizeParentContacts keeps accepted parent state ahead of stale duplicates', () => {
    const contacts = (0, player_parent_contacts_1.summarizeParentContacts)([
        {
            id: 'expired-parent',
            email: 'parent@example.com',
            phone: '0600000000',
            status: 'EXPIRED',
            updatedAt: new Date('2026-05-18T09:00:00.000Z'),
            createdAt: new Date('2026-05-17T09:00:00.000Z'),
        },
        {
            id: 'accepted-parent',
            email: 'parent@example.com',
            phone: '0600000000',
            status: 'ACCEPTED',
            acceptedAt: new Date('2026-05-16T09:00:00.000Z'),
            updatedAt: new Date('2026-05-16T09:00:00.000Z'),
            createdAt: new Date('2026-05-15T09:00:00.000Z'),
            user: {
                id: 'user-parent',
                firstName: 'Marie',
                lastName: 'Martin',
                email: 'parent@example.com',
                phone: '0600000000',
            },
        },
    ]);
    strict_1.default.equal(contacts.length, 1);
    strict_1.default.deepEqual(contacts[0], {
        parentId: 'accepted-parent',
        parentUserId: 'user-parent',
        firstName: 'Marie',
        lastName: 'Martin',
        email: 'parent@example.com',
        phone: '0600000000',
        status: 'ACCEPTED',
    });
});
(0, node_test_1.default)('summarizeParentContacts reuses the latest non-activated parent invite and hides placeholder email', () => {
    const contacts = (0, player_parent_contacts_1.summarizeParentContacts)([
        {
            id: 'cancelled-parent',
            email: 'parent+seed@invite.izifoot.local',
            phone: '0611223344',
            status: 'CANCELLED',
            updatedAt: new Date('2026-05-17T09:00:00.000Z'),
            createdAt: new Date('2026-05-16T09:00:00.000Z'),
        },
        {
            id: 'pending-parent',
            email: 'parent+seed@invite.izifoot.local',
            phone: '0611223344',
            status: 'PENDING',
            updatedAt: new Date('2026-05-18T09:00:00.000Z'),
            createdAt: new Date('2026-05-18T08:00:00.000Z'),
        },
    ]);
    strict_1.default.equal(contacts.length, 1);
    strict_1.default.deepEqual(contacts[0], {
        parentId: 'pending-parent',
        parentUserId: null,
        firstName: null,
        lastName: null,
        email: null,
        phone: '0611223344',
        status: 'PENDING',
    });
});
