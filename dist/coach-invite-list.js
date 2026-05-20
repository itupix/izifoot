"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.filterLatestCoachInvites = filterLatestCoachInvites;
function normalizeInviteEmail(email) {
    return email.trim().toLowerCase();
}
function inviteTimestamp(invite) {
    return (invite.updatedAt ?? invite.createdAt ?? new Date(0)).getTime();
}
function filterLatestCoachInvites(invites, acceptedEmails) {
    const seenInviteEmails = new Set();
    return invites
        .slice()
        .sort((lhs, rhs) => {
        const timestampDiff = inviteTimestamp(rhs) - inviteTimestamp(lhs);
        if (timestampDiff !== 0)
            return timestampDiff;
        return rhs.id.localeCompare(lhs.id);
    })
        .filter((invite) => {
        const email = normalizeInviteEmail(invite.email);
        if (!email || acceptedEmails.has(email))
            return false;
        if (seenInviteEmails.has(email))
            return false;
        seenInviteEmails.add(email);
        return true;
    });
}
