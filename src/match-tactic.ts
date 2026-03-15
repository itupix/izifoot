import { z } from 'zod'

const matchTacticPointSchema = z.object({
  x: z.number().min(0).max(100),
  y: z.number().min(0).max(100),
}).strict()

export const matchTacticPointsSchema = z.record(matchTacticPointSchema).superRefine((points, ctx) => {
  if (!Object.prototype.hasOwnProperty.call(points, 'gk')) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['gk'],
      message: 'tactic.points.gk is required',
    })
  }

  for (const key of Object.keys(points)) {
    if (key === 'gk') continue
    if (!/^p[1-9]\d*$/.test(key)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [key],
        message: 'Invalid tactic point key. Allowed keys: gk, p1..pN',
      })
    }
  }
})

export const matchTacticSchema = z.object({
  preset: z.string().trim().min(1),
  points: matchTacticPointsSchema,
}).strict()

export type MatchTactic = z.infer<typeof matchTacticSchema>

export function validateMatchTacticForPlayersOnField(tactic: MatchTactic, playersOnField: number): { ok: true } | { ok: false; error: string } {
  const maxOutfieldSlots = Math.max(0, playersOnField - 1)
  for (const key of Object.keys(tactic.points)) {
    if (key === 'gk') continue
    const parsedIndex = Number(key.slice(1))
    if (!Number.isFinite(parsedIndex) || parsedIndex < 1 || parsedIndex > maxOutfieldSlots) {
      return {
        ok: false,
        error: `Invalid tactic point key "${key}" for format size ${playersOnField}. Allowed keys: gk and p1..p${maxOutfieldSlots}`,
      }
    }
  }
  return { ok: true }
}
