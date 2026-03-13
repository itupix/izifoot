import { z } from 'zod'

export const matchEventTypeSchema = z.enum(['GOAL_FOR', 'GOAL_AGAINST', 'SUBSTITUTION'])
export const matchEventSlotSchema = z.enum(['gk', 'p1', 'p2', 'p3', 'p4'])

export const matchEventCreateSchema = z.object({
  minute: z.number().int().min(0),
  type: matchEventTypeSchema,
  scorerId: z.string().min(1).optional(),
  assistId: z.string().min(1).optional(),
  slotId: matchEventSlotSchema.optional(),
  inPlayerId: z.string().min(1).optional(),
  outPlayerId: z.string().min(1).optional(),
}).superRefine((value, ctx) => {
  if (value.type === 'GOAL_FOR') {
    if (!value.scorerId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['scorerId'],
        message: 'scorerId is required for GOAL_FOR',
      })
    }
    return
  }

  if (value.type === 'SUBSTITUTION') {
    if (!value.inPlayerId && !value.outPlayerId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['inPlayerId'],
        message: 'SUBSTITUTION requires at least inPlayerId or outPlayerId',
      })
    }
  }
})

export type MatchEventCreatePayload = z.infer<typeof matchEventCreateSchema>
