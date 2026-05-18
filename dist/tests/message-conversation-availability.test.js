"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = __importDefault(require("node:test"));
const message_conversation_availability_1 = require("../message-conversation-availability");
(0, node_test_1.default)('coach conversation is unavailable when player invitation status is NONE', () => {
    const result = (0, message_conversation_availability_1.resolveCoachConversationInvitationAvailability)({ status: 'NONE' });
    strict_1.default.deepEqual(result, {
        isAvailable: false,
        error: message_conversation_availability_1.PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
    });
});
(0, node_test_1.default)('coach conversation is available when player invitation status is PENDING', () => {
    const result = (0, message_conversation_availability_1.resolveCoachConversationInvitationAvailability)({ status: 'PENDING' });
    strict_1.default.deepEqual(result, {
        isAvailable: true,
        invitationStatus: 'PENDING',
    });
});
(0, node_test_1.default)('coach conversation is available when player invitation status is ACCEPTED', () => {
    const result = (0, message_conversation_availability_1.resolveCoachConversationInvitationAvailability)({ status: 'ACCEPTED' });
    strict_1.default.deepEqual(result, {
        isAvailable: true,
        invitationStatus: 'ACCEPTED',
    });
});
