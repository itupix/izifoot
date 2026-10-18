import { z } from 'zod'

export const DRILL_CATEGORIES = ['collectif', 'technique', 'jeu', 'autres'] as const
export const drillCategorySchema = z.enum(DRILL_CATEGORIES)

// Zod strips retired duration/players fields sent by older clients.
export const drillCreateSchema = z.object({
  title: z.string().min(1).max(100),
  category: drillCategorySchema,
  description: z.string().min(1).max(2000),
  tags: z.array(z.string().min(1).max(32)).max(20).optional(),
})
export const drillUpdateSchema = drillCreateSchema.partial()

export const trainingDrillCreateSchema = z.object({
  drillId: z.string().min(1),
  notes: z.string().max(1000).optional(),
  trainingDrillId: z.string().min(1).optional(),
  replaceTrainingDrillId: z.string().min(1).optional(),
  id: z.string().min(1).optional(),
})
export const trainingDrillUpdateSchema = z.object({
  drillId: z.string().min(1).optional(),
  notes: z.string().max(1000).nullable().optional(),
  order: z.number().int().min(0).optional(),
}).refine(data => Object.values(data).some(value => value !== undefined), {
  message: 'At least one field must be provided',
})
