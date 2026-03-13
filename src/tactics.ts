import { z } from 'zod'

const TOKEN_IDS = ['gk', 'p1', 'p2', 'p3', 'p4'] as const
const FORMATIONS = ['2-1-1', '1-2-1', '1-1-2'] as const

export type TacticTokenId = (typeof TOKEN_IDS)[number]
export type TacticFormation = (typeof FORMATIONS)[number]

const tacticPointSchema = z.object({
  x: z.number().min(6).max(94),
  y: z.number().min(8).max(92),
}).strict()

export const tacticFormationSchema = z.enum(FORMATIONS)

export const tacticPointsSchema = z.object({
  gk: tacticPointSchema,
  p1: tacticPointSchema,
  p2: tacticPointSchema,
  p3: tacticPointSchema,
  p4: tacticPointSchema,
}).strict()

export const tacticPayloadSchema = z.object({
  teamId: z.string().min(1),
  name: z.string().trim().min(1).max(50),
  formation: tacticFormationSchema,
  points: tacticPointsSchema,
}).strict()

export type TacticPayload = z.infer<typeof tacticPayloadSchema>

type AuthLike = {
  role?: string
  teamId?: string | null
  managedTeamIds?: string[] | null
}

function getActiveTeamIdForAuth(auth: AuthLike | null | undefined): string | null {
  if (!auth) return null
  if (auth.role === 'COACH') {
    const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : []
    if (auth.teamId && managedIds.includes(auth.teamId)) return auth.teamId
    if (managedIds.length === 1) return managedIds[0]
    return null
  }
  return auth.teamId || null
}

export function canWriteTacticForTeam(auth: AuthLike | null | undefined, teamId: string): boolean {
  if (!auth) return false
  if (auth.role !== 'COACH' && auth.role !== 'DIRECTION') return false
  const activeTeamId = getActiveTeamIdForAuth(auth)
  return !!activeTeamId && activeTeamId === teamId
}

export function sortTacticsByUpdatedAtDesc<T extends { updatedAt: Date | string }>(rows: T[]): T[] {
  return [...rows].sort((a, b) => {
    const ta = new Date(a.updatedAt).getTime()
    const tb = new Date(b.updatedAt).getTime()
    return tb - ta
  })
}

type TacticDelegate = {
  findFirst: (args: any) => Promise<any>
  create: (args: any) => Promise<any>
  update: (args: any) => Promise<any>
}

export async function upsertTacticByTeamAndName(
  tacticDelegate: TacticDelegate,
  payload: TacticPayload
): Promise<any> {
  const existing = await tacticDelegate.findFirst({
    where: {
      teamId: payload.teamId,
      name: {
        equals: payload.name,
        mode: 'insensitive',
      },
    },
  })

  if (existing) {
    return tacticDelegate.update({
      where: { id: existing.id },
      data: {
        name: payload.name,
        formation: payload.formation,
        points: payload.points,
      },
    })
  }

  return tacticDelegate.create({
    data: {
      teamId: payload.teamId,
      name: payload.name,
      formation: payload.formation,
      points: payload.points,
    },
  })
}
