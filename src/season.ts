import { z } from 'zod'

export const DEFAULT_SEASON_TIMEZONE = 'Europe/Paris'

export const clubSeasonConfigSchema = z.object({
  startMonth: z.number().int().min(1).max(12),
  startDay: z.number().int().min(1).max(31),
  endMonth: z.number().int().min(1).max(12),
  endDay: z.number().int().min(1).max(31),
  timezone: z.literal(DEFAULT_SEASON_TIMEZONE).optional(),
}).superRefine((value, ctx) => {
  if (!isValidMonthDay(value.startMonth, value.startDay)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['startDay'],
      message: 'Invalid season start date',
    })
  }
  if (!isValidMonthDay(value.endMonth, value.endDay)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['endDay'],
      message: 'Invalid season end date',
    })
  }
  if (compareMonthDay(value.endMonth, value.endDay, value.startMonth, value.startDay) >= 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['endMonth'],
      message: 'Season end must fall before season start in the calendar year',
    })
  }
})

export type ClubSeasonConfig = z.infer<typeof clubSeasonConfigSchema>

export const DEFAULT_SEASON_CONFIG: ClubSeasonConfig = {
  startMonth: 8,
  startDay: 1,
  endMonth: 7,
  endDay: 31,
  timezone: DEFAULT_SEASON_TIMEZONE,
}

function isValidMonthDay(month: number, day: number) {
  const probe = new Date(Date.UTC(2001, month - 1, day))
  return probe.getUTCMonth() === month - 1 && probe.getUTCDate() === day
}

function parisParts(input: Date) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: DEFAULT_SEASON_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(input)
  const read = (type: Intl.DateTimeFormatPartTypes) => Number(parts.find((part) => part.type === type)?.value || 0)
  return {
    year: read('year'),
    month: read('month'),
    day: read('day'),
    hour: read('hour'),
    minute: read('minute'),
    second: read('second'),
  }
}

function parisOffsetMinutesAt(utcDate: Date) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: DEFAULT_SEASON_TIMEZONE,
    timeZoneName: 'shortOffset',
    hour: '2-digit',
    hour12: false,
  }).formatToParts(utcDate)
  const token = parts.find((part) => part.type === 'timeZoneName')?.value || 'GMT+0'
  const match = token.match(/(?:GMT|UTC)([+-]\d{1,2})(?::?(\d{2}))?/i)
  if (!match) return 0
  const rawHours = Number(match[1] || 0)
  const rawMinutes = Number(match[2] || 0)
  const sign = rawHours < 0 ? -1 : 1
  return rawHours * 60 + sign * rawMinutes
}

function parisLocalToUtc(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  millisecond: number,
) {
  const baseUtcMillis = Date.UTC(year, month - 1, day, hour, minute, second, millisecond)
  let candidateUtcMillis = baseUtcMillis
  for (let i = 0; i < 2; i += 1) {
    const offsetMinutes = parisOffsetMinutesAt(new Date(candidateUtcMillis))
    candidateUtcMillis = baseUtcMillis - offsetMinutes * 60_000
  }
  return new Date(candidateUtcMillis)
}

export function compareMonthDay(
  lhsMonth: number,
  lhsDay: number,
  rhsMonth: number,
  rhsDay: number,
) {
  if (lhsMonth !== rhsMonth) return lhsMonth < rhsMonth ? -1 : 1
  if (lhsDay !== rhsDay) return lhsDay < rhsDay ? -1 : 1
  return 0
}

export function normalizeClubSeasonConfig(raw: any): ClubSeasonConfig {
  const parsed = clubSeasonConfigSchema.safeParse({
    startMonth: raw?.seasonStartMonth ?? raw?.startMonth ?? DEFAULT_SEASON_CONFIG.startMonth,
    startDay: raw?.seasonStartDay ?? raw?.startDay ?? DEFAULT_SEASON_CONFIG.startDay,
    endMonth: raw?.seasonEndMonth ?? raw?.endMonth ?? DEFAULT_SEASON_CONFIG.endMonth,
    endDay: raw?.seasonEndDay ?? raw?.endDay ?? DEFAULT_SEASON_CONFIG.endDay,
    timezone: raw?.seasonTimezone ?? raw?.timezone ?? DEFAULT_SEASON_TIMEZONE,
  })
  if (!parsed.success) return DEFAULT_SEASON_CONFIG
  return {
    ...parsed.data,
    timezone: DEFAULT_SEASON_TIMEZONE,
  }
}

export function buildSeasonConfigPatch(config: ClubSeasonConfig) {
  return {
    seasonStartMonth: config.startMonth,
    seasonStartDay: config.startDay,
    seasonEndMonth: config.endMonth,
    seasonEndDay: config.endDay,
    seasonTimezone: DEFAULT_SEASON_TIMEZONE,
  }
}

export function resolveSeasonWindowForDate(dateInput: Date | string, configInput: any) {
  const date = dateInput instanceof Date ? dateInput : new Date(dateInput)
  if (Number.isNaN(date.getTime())) {
    throw new Error('Invalid season date input')
  }

  const config = normalizeClubSeasonConfig(configInput)
  const parts = parisParts(date)
  const startYear = compareMonthDay(parts.month, parts.day, config.startMonth, config.startDay) >= 0
    ? parts.year
    : parts.year - 1
  const endYear = startYear + 1
  const startDate = parisLocalToUtc(startYear, config.startMonth, config.startDay, 0, 0, 0, 0)
  const endDate = parisLocalToUtc(endYear, config.endMonth, config.endDay, 23, 59, 59, 999)
  const key = `${startYear}-${endYear}`

  return {
    key,
    label: key,
    startYear,
    endYear,
    startDate,
    endDate,
  }
}

export function isDateWithinSeason(dateInput: Date | string, season: { startDate: Date | string, endDate: Date | string }) {
  const date = dateInput instanceof Date ? dateInput : new Date(dateInput)
  const startDate = season.startDate instanceof Date ? season.startDate : new Date(season.startDate)
  const endDate = season.endDate instanceof Date ? season.endDate : new Date(season.endDate)
  return date.getTime() >= startDate.getTime() && date.getTime() <= endDate.getTime()
}

export function toSeasonResponse(season: any, referenceDate: Date = new Date()) {
  if (!season) return null
  return {
    id: season.id,
    clubId: season.clubId,
    key: season.key,
    label: season.label ?? season.key,
    startDate: season.startDate,
    endDate: season.endDate,
    isCurrent: isDateWithinSeason(referenceDate, season),
  }
}

export async function resolveOrCreateSeasonForClubDate(db: any, club: any, dateInput: Date | string) {
  if (!club?.id) return null

  const window = resolveSeasonWindowForDate(dateInput, club)
  const uniqueWhere = {
    clubId_key: {
      clubId: club.id,
      key: window.key,
    },
  }

  const existing = await db.season.findUnique({ where: uniqueWhere })
  if (existing) return existing

  try {
    return await db.season.create({
      data: {
        clubId: club.id,
        key: window.key,
        label: window.label,
        startDate: window.startDate,
        endDate: window.endDate,
      },
    })
  } catch (error: any) {
    if (error?.code !== 'P2002') throw error
    return db.season.findUnique({ where: uniqueWhere })
  }
}

