import { z } from 'zod'

export const HHMM_TIME_REGEX = /^(?:[01]\d|2[0-3]):[0-5]\d$/

const nullableHHMMSchema = z.union([
  z.string().regex(HHMM_TIME_REGEX, 'Invalid time format, expected HH:MM'),
  z.null(),
])

export const matchdayMetadataSchema = z.object({
  address: z.union([z.string(), z.null()]).optional(),
  startTime: nullableHHMMSchema.optional(),
  meetingTime: nullableHHMMSchema.optional(),
  competitionType: z.enum(['PLATEAU', 'MATCH', 'TOURNOI']).optional(),
  tournamentHasGroupStage: z.boolean().nullable().optional(),
  tournamentKnockoutMode: z.enum(['NONE', 'SINGLE', 'HOME_AWAY']).nullable().optional(),
})

export function buildMatchdayMetadataPatch(data: z.infer<typeof matchdayMetadataSchema>) {
  const patch: {
    address?: string | null
    startTime?: string | null
    meetingTime?: string | null
    competitionType?: 'PLATEAU' | 'MATCH' | 'TOURNOI'
    tournamentHasGroupStage?: boolean | null
    tournamentKnockoutMode?: 'NONE' | 'SINGLE' | 'HOME_AWAY' | null
  } = {}

  if (Object.prototype.hasOwnProperty.call(data, 'address')) patch.address = data.address ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'startTime')) patch.startTime = data.startTime ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'meetingTime')) patch.meetingTime = data.meetingTime ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'competitionType') && data.competitionType) patch.competitionType = data.competitionType
  if (Object.prototype.hasOwnProperty.call(data, 'tournamentHasGroupStage')) patch.tournamentHasGroupStage = data.tournamentHasGroupStage ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'tournamentKnockoutMode')) patch.tournamentKnockoutMode = data.tournamentKnockoutMode ?? null

  return patch
}

export function toPublicMatchday(matchday: {
  id: string
  date: Date
  lieu: string
  address?: string | null
  startTime?: string | null
  meetingTime?: string | null
  competitionType?: 'PLATEAU' | 'MATCH' | 'TOURNOI' | null
  tournamentHasGroupStage?: boolean | null
  tournamentKnockoutMode?: 'NONE' | 'SINGLE' | 'HOME_AWAY' | null
}) {
  return {
    id: matchday.id,
    date: matchday.date,
    lieu: matchday.lieu,
    address: matchday.address ?? null,
    startTime: matchday.startTime ?? null,
    meetingTime: matchday.meetingTime ?? null,
    competitionType: matchday.competitionType ?? 'PLATEAU',
    tournamentHasGroupStage: matchday.tournamentHasGroupStage ?? null,
    tournamentKnockoutMode: matchday.tournamentKnockoutMode ?? null,
  }
}
