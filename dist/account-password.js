"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mePasswordPutBodySchema = void 0;
exports.parseMePasswordPutBody = parseMePasswordPutBody;
exports.validatePasswordChangeInput = validatePasswordChangeInput;
const zod_1 = require("zod");
exports.mePasswordPutBodySchema = zod_1.z.object({
    currentPassword: zod_1.z.string().min(1).max(200),
    newPassword: zod_1.z.string().min(6).max(200),
});
function parseMePasswordPutBody(raw) {
    return exports.mePasswordPutBodySchema.safeParse({
        currentPassword: raw?.currentPassword ?? raw?.current_password ?? raw?.motDePasseActuel,
        newPassword: raw?.newPassword ?? raw?.new_password ?? raw?.motDePasseNouveau ?? raw?.motDePasse,
    });
}
function validatePasswordChangeInput(input) {
    if (input.currentPassword === input.newPassword) {
        return {
            ok: false,
            error: 'Le nouveau mot de passe doit etre different du mot de passe actuel.',
        };
    }
    return { ok: true };
}
