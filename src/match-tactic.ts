import { z } from 'zod'

const matchTacticPointSchema = z.object({
  x: z.number().min(0).max(100),
  y: z.number().min(0).max(100),
}).strict()

export const matchTacticPointsSchema = z.object({
  gk: matchTacticPointSchema,
  p1: matchTacticPointSchema,
  p2: matchTacticPointSchema,
  p3: matchTacticPointSchema,
  p4: matchTacticPointSchema,
}).strict()

export const matchTacticSchema = z.object({
  preset: z.string().trim().min(1),
  points: matchTacticPointsSchema,
}).strict()

export type MatchTactic = z.infer<typeof matchTacticSchema>
