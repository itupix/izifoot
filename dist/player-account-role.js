"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolvePlayerAccountInviteRole = resolvePlayerAccountInviteRole;
exports.resolvePlayerAccountInviteLookupRoles = resolvePlayerAccountInviteLookupRoles;
function resolvePlayerAccountInviteRole(isChild) {
    return isChild ? 'PARENT' : 'PLAYER';
}
function resolvePlayerAccountInviteLookupRoles(isChild) {
    return isChild ? ['PARENT', 'PLAYER'] : ['PLAYER'];
}
