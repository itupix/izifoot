"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolvePlayerInvitationStatus = resolvePlayerInvitationStatus;
function resolvePlayerInvitationStatus(input) {
    if (input.hasActiveAccount || input.latestAcceptedInvite) {
        return {
            status: 'ACCEPTED',
            invitationId: input.latestAcceptedInvite?.id ?? null,
            lastInvitationAt: input.latestAcceptedInvite?.acceptedAt ??
                input.latestAcceptedInvite?.updatedAt ??
                input.latestAcceptedInvite?.createdAt ??
                null,
        };
    }
    if (input.latestPendingInvite) {
        return {
            status: 'PENDING',
            invitationId: input.latestPendingInvite.id,
            lastInvitationAt: input.latestPendingInvite.updatedAt ?? input.latestPendingInvite.createdAt,
        };
    }
    return {
        status: 'NONE',
        invitationId: null,
        lastInvitationAt: null,
    };
}
