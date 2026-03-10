import { z } from 'zod'

export const trainingRoleItemInputSchema = z.object({
  role: z.string().trim().min(1).max(80),
  playerId: z.string().trim().min(1),
})

export const trainingRolesPutBodySchema = z.object({
  items: z.array(trainingRoleItemInputSchema),
})

export type TrainingRoleItemInput = z.infer<typeof trainingRoleItemInputSchema>

export function normalizeTrainingRoleItems(items: TrainingRoleItemInput[]): TrainingRoleItemInput[] {
  return items.map((item) => ({
    role: item.role.trim(),
    playerId: item.playerId.trim(),
  }))
}

export function findDuplicateValues(values: string[]): string[] {
  const counts = new Map<string, number>()
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1)
  }
  return Array.from(counts.entries())
    .filter(([, count]) => count > 1)
    .map(([value]) => value)
}

export function validateNoDuplicatePlayers(items: TrainingRoleItemInput[]) {
  const duplicatePlayers = findDuplicateValues(items.map((item) => item.playerId))
  if (duplicatePlayers.length > 0) {
    const err: any = new Error('Duplicate playerId in items')
    err.code = 'DUPLICATE_PLAYER'
    throw err
  }
}
