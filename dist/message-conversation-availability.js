"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR = void 0;
exports.resolveCoachConversationInvitationAvailability = resolveCoachConversationInvitationAvailability;
exports.PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR = {
    error: 'Conversation unavailable until the player has been invited to join izifoot',
    code: 'PLAYER_INVITATION_REQUIRED',
    invitationStatus: 'NONE',
};
function resolveCoachConversationInvitationAvailability(snapshot) {
    if (snapshot?.status === 'PENDING' || snapshot?.status === 'ACCEPTED') {
        return {
            isAvailable: true,
            invitationStatus: snapshot.status,
        };
    }
    return {
        isAvailable: false,
        invitationStatus: 'NONE',
        error: exports.PLAYER_INVITATION_REQUIRED_CONVERSATION_ERROR,
    };
}
