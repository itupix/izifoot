import { z } from 'zod'
import { matchTacticSchema } from './match-tactic'

export const matchScorerPayloadSchema = z.object({
  playerId: z.string(),
  side: z.enum(['home', 'away']),
  assistId: z.string().nullable().optional(),
}).superRefine((value, ctx) => {
  if (value.assistId && value.assistId === value.playerId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['assistId'],
      message: 'assistId must be different from playerId',
    })
  }
})

export const matchSidesPayloadSchema = z.object({
  home: z.object({
    starters: z.array(z.string()).default([]),
    subs: z.array(z.string()).default([])
  }).default({ starters: [], subs: [] }),
  away: z.object({
    starters: z.array(z.string()).default([]),
    subs: z.array(z.string()).default([])
  }).default({ starters: [], subs: [] })
})

export const matchCreatePayloadSchema = z.object({
  type: z.enum(['ENTRAINEMENT', 'PLATEAU']),
  played: z.boolean().optional(),
  plateauId: z.string().optional(),
  sides: matchSidesPayloadSchema,
  score: z.object({ home: z.number().int().min(0), away: z.number().int().min(0) }).optional(),
  buteurs: z.array(matchScorerPayloadSchema).optional(),
  opponentName: z.string().min(1).max(100).optional(),
  tactic: matchTacticSchema.nullable().optional(),
})
