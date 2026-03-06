import { z } from 'zod'

export const HHMM_TIME_REGEX = /^(?:[01]\d|2[0-3]):[0-5]\d$/

const nullableHHMMSchema = z.union([
  z.string().regex(HHMM_TIME_REGEX, 'Invalid time format, expected HH:MM'),
  z.null(),
])

export const plateauMetadataSchema = z.object({
  address: z.union([z.string(), z.null()]).optional(),
  startTime: nullableHHMMSchema.optional(),
  meetingTime: nullableHHMMSchema.optional(),
})

export function buildPlateauMetadataPatch(data: z.infer<typeof plateauMetadataSchema>) {
  const patch: { address?: string | null; startTime?: string | null; meetingTime?: string | null } = {}

  if (Object.prototype.hasOwnProperty.call(data, 'address')) patch.address = data.address ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'startTime')) patch.startTime = data.startTime ?? null
  if (Object.prototype.hasOwnProperty.call(data, 'meetingTime')) patch.meetingTime = data.meetingTime ?? null

  return patch
}

export function toPublicPlateau(plateau: {
  id: string
  date: Date
  lieu: string
  address?: string | null
  startTime?: string | null
  meetingTime?: string | null
}) {
  return {
    id: plateau.id,
    date: plateau.date,
    lieu: plateau.lieu,
    address: plateau.address ?? null,
    startTime: plateau.startTime ?? null,
    meetingTime: plateau.meetingTime ?? null,
  }
}
