import { z } from 'zod'

export const mePasswordPutBodySchema = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: z.string().min(6).max(200),
})

export function parseMePasswordPutBody(raw: any) {
  return mePasswordPutBodySchema.safeParse({
    currentPassword: raw?.currentPassword ?? raw?.current_password ?? raw?.motDePasseActuel,
    newPassword: raw?.newPassword ?? raw?.new_password ?? raw?.motDePasseNouveau ?? raw?.motDePasse,
  })
}

export function validatePasswordChangeInput(input: { currentPassword: string, newPassword: string }) {
  if (input.currentPassword === input.newPassword) {
    return {
      ok: false as const,
      error: 'Le nouveau mot de passe doit etre different du mot de passe actuel.',
    }
  }

  return { ok: true as const }
}
