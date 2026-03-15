import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import cookieParser from 'cookie-parser'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import QRCode from 'qrcode'
import nodemailer from 'nodemailer'
import { addDays } from 'date-fns'
import { randomUUID } from 'crypto'
import { buildPlateauMetadataPatch, plateauMetadataSchema, toPublicPlateau } from './plateau-metadata'
import {
  attendanceSessionTypeVariants,
  normalizeAttendanceRow,
  persistAttendancePresence,
} from './attendance'
import {
  normalizeTrainingRoleItems,
  trainingRolesPutBodySchema,
  validateNoDuplicatePlayers,
} from './training-role-assignments'
import {
  canWriteTacticForTeam,
  tacticPayloadSchema,
  upsertTacticByTeamAndName,
} from './tactics'
import { normalizeTeamCategory } from './team-category'
import { normalizeTeamFormat, resolveTeamFormat } from './team-format'
import { computeAutoTeamName } from './team-name'
import { matchTacticSchema } from './match-tactic'
import { buildEligiblePlayerIdsFromPlateauAttendance } from './match-eligibility'
import { matchEventCreateSchema } from './match-events'
import { validateMatchUpdatePayloadForTeamFormat } from './match-update-validation'

const app = express()
const prisma = new PrismaClient()
const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret'
const IS_PROD = process.env.NODE_ENV === 'production'
const DEFAULT_DEV_APP_BASE_URL = 'http://localhost:5173'
const APP_BASE_URL = process.env.APP_BASE_URL || DEFAULT_DEV_APP_BASE_URL
const API_BASE_URL = process.env.API_BASE_URL || `http://localhost:${PORT}`
const AUTH_COOKIE_NAME = 'token'

// Railway/Reverse proxy support so secure cookies can be set correctly.
app.set('trust proxy', 1)

type ExpressHandler = (...args: any[]) => any

function wrapExpressHandler(handler: ExpressHandler): ExpressHandler {
  return function wrappedHandler(req: any, res: any, next: any) {
    return Promise.resolve(handler(req, res, next)).catch(next)
  }
}

for (const method of ['get', 'post', 'put', 'delete', 'patch'] as const) {
  const original = (app as any)[method].bind(app)
  ;(app as any)[method] = (path: string, ...handlers: ExpressHandler[]) => {
    return original(path, ...handlers.map((handler) => wrapExpressHandler(handler)))
  }
}

function toOrigin(raw: string) {
  const s = raw.trim()
  if (!s) return null
  try {
    return new URL(s).origin
  } catch {
    return null
  }
}

function toWildcardRule(raw: string) {
  const s = raw.trim()
  if (!s.includes('*')) return null
  const m = s.match(/^(https?):\/\/\*\.(.+?)(?::(\d+))?$/i)
  if (!m) return null
  return {
    protocol: m[1].toLowerCase(),
    hostnameSuffix: m[2].toLowerCase(),
    port: m[3] || '',
  }
}

const exactFrontOrigins = new Set<string>()
const wildcardFrontOrigins: Array<ReturnType<typeof toWildcardRule>> = []
const configuredFrontOrigins = [
  ...(IS_PROD ? [] : [APP_BASE_URL]),
  ...(!IS_PROD && !process.env.APP_BASE_URL ? [] : [process.env.APP_BASE_URL || '']),
  ...(process.env.APP_BASE_URLS || '').split(','),
]

for (const rawOrigin of configuredFrontOrigins) {
  const wildcardRule = toWildcardRule(rawOrigin)
  if (wildcardRule) {
    wildcardFrontOrigins.push(wildcardRule)
    continue
  }

  const normalizedOrigin = toOrigin(rawOrigin)
  if (!normalizedOrigin) continue
  exactFrontOrigins.add(normalizedOrigin)

  const u = new URL(normalizedOrigin)
  if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
    const port = u.port || '5173'
    exactFrontOrigins.add(`http://localhost:${port}`)
    exactFrontOrigins.add(`http://127.0.0.1:${port}`)
    exactFrontOrigins.add(`https://localhost:${port}`)
    exactFrontOrigins.add(`https://127.0.0.1:${port}`)
  }
}

function isAllowedOrigin(origin: string) {
  if (exactFrontOrigins.has(origin)) return true

  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }

  const hostname = parsed.hostname.toLowerCase()
  const protocol = parsed.protocol.replace(/:$/, '').toLowerCase()
  const port = parsed.port || ''

  return wildcardFrontOrigins.some((rule) => {
    if (!rule) return false
    if (rule.protocol !== protocol) return false
    if (rule.port !== port) return false
    if (hostname === rule.hostnameSuffix) return false
    return hostname.endsWith(`.${rule.hostnameSuffix}`)
  })
}

if (IS_PROD && exactFrontOrigins.size === 0 && wildcardFrontOrigins.length === 0) {
  console.warn('[cors] No front-end origin configured. Set APP_BASE_URL or APP_BASE_URLS in production.')
}

app.use(helmet())
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true)
    if (isAllowedOrigin(origin)) return callback(null, true)
    console.warn(`[cors] Blocked origin: ${origin}`)
    return callback(new Error('Not allowed by CORS'))
  },
  credentials: true,
}))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use(morgan('dev'))

// Anti-cache pour l'API (évite les 304 Not Modified sur GET protégés)
app.set('etag', false)
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  // Important si tu utilises Authorization ou cookies
  res.setHeader('Vary', 'Authorization, Origin')
  next()
})

// --- Cookie helper for robust cross-site cookie options ---
function authCookieOpts() {
  const isProd = process.env.NODE_ENV === 'production'
  const sameSite: 'lax' | 'none' = isProd ? 'none' : 'lax'
  return {
    httpOnly: true,
    sameSite,
    secure: isProd,
    path: '/',
    maxAge: 7 * 24 * 3600 * 1000
  }
}

function authClearCookieOpts() {
  const { maxAge, ...opts } = authCookieOpts()
  return opts
}

function playerCookieOpts() {
  const isProd = process.env.NODE_ENV === 'production'
  const sameSite: 'lax' | 'none' = isProd ? 'none' : 'lax'
  return {
    httpOnly: true,
    sameSite,
    secure: isProd,
    path: '/',
    maxAge: 30 * 24 * 3600 * 1000
  }
}

// --- Auth helpers ---
function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' })
}

async function resolveUserAuthContext(userId: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      team: true,
      club: true,
    }
  })
  if (!user) return null

  let resolvedTeamId: string | null = user.teamId
  if (user.role === 'DIRECTION' && !resolvedTeamId && user.clubId) {
    const clubTeams = await prisma.team.findMany({
      where: { clubId: user.clubId },
      orderBy: { name: 'asc' },
      select: { id: true },
      take: 2
    })
    if (clubTeams.length === 1) resolvedTeamId = clubTeams[0].id
  }

  let managedTeamIds: string[] = []
  if (user.role === 'COACH') {
    const candidateIds = Array.isArray((user as any).managedTeamIds) ? (user as any).managedTeamIds : []
    if (candidateIds.length) {
      const managedTeams = await prisma.team.findMany({
        where: {
          id: { in: candidateIds },
          ...(user.clubId ? { clubId: user.clubId } : {}),
        },
        select: { id: true }
      })
      managedTeamIds = managedTeams.map((t) => t.id)
    }
  }

  let parentLinkedPlayer: any = null
  if (user.role === 'PARENT' && user.linkedPlayerUserId) {
    parentLinkedPlayer = await prisma.user.findUnique({
      where: { id: user.linkedPlayerUserId },
      select: { id: true, role: true, teamId: true, clubId: true }
    })
  }

  return {
    id: user.id,
    email: user.email,
    role: user.role,
    clubId: user.clubId,
    teamId: resolvedTeamId,
    managedTeamIds,
    linkedPlayerUserId: user.linkedPlayerUserId,
    parentLinkedPlayer,
  }
}

async function authMiddleware(req: any, res: any, next: any) {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    const auth = await resolveUserAuthContext(payload.sub)
    if (!auth) return res.status(401).json({ error: 'Unauthorized' })
    req.userId = auth.id
    req.auth = auth
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

function ensureDirection(req: any, res: any): boolean {
  if (req.auth?.role !== 'DIRECTION') {
    res.status(403).json({ error: 'Only direction accounts can perform this action' })
    return false
  }
  return true
}

function isReadOnlyRole(auth: any): boolean {
  return auth?.role === 'PLAYER' || auth?.role === 'PARENT'
}

function ensureStaff(req: any, res: any): boolean {
  if (req.auth?.role === 'DIRECTION' || req.auth?.role === 'COACH') return true
  res.status(403).json({ error: 'Only direction and coach accounts can perform this action' })
  return false
}

function isWriteMethod(method: string) {
  return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE'
}

async function generateAutoTeamName(clubId: string, baseName: string, opts: { excludeTeamId?: string } = {}) {
  const existingTeams = await prisma.team.findMany({
    where: {
      clubId,
      ...(opts.excludeTeamId ? { id: { not: opts.excludeTeamId } } : {}),
    },
    select: { name: true },
  })
  return computeAutoTeamName(baseName, existingTeams.map((row) => row.name))
}

const teamUpsertPayloadSchema = z.preprocess(
  (raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return raw
    const payload = raw as Record<string, unknown>
    return {
      name: payload.name ?? payload.teamName ?? null,
      category: payload.category,
      format: payload.format ?? payload.gameFormat ?? payload.game_format,
    }
  },
  z.object({
    name: z.string({ invalid_type_error: 'Name must be a string' }).max(80, 'Name must be at most 80 characters').optional().nullable(),
    category: z.string({ required_error: 'Category is required', invalid_type_error: 'Category must be a string' }).min(1, 'Category is required'),
    format: z.string({ required_error: 'Format is required', invalid_type_error: 'Format must be a string' }).min(1, 'Format is required'),
  })
)

function normalizeTeamResponse(team: any) {
  const resolvedFormat = resolveTeamFormat(team?.format)
  return withTeamFormatAliases({
    id: team.id,
    name: team.name,
    category: team.category,
    format: resolvedFormat.format,
    clubId: team.clubId,
    createdAt: team.createdAt,
  })
}

function withTeamFormatAliases(team: any) {
  const resolvedFormat = resolveTeamFormat(team?.format)
  return {
    ...team,
    format: resolvedFormat.format,
    gameFormat: resolvedFormat.format,
    game_format: resolvedFormat.format,
  }
}

function logTeamValidationFailure(endpoint: string, reason: string, details: Record<string, unknown> = {}) {
  console.warn(`[${endpoint}] team validation failed: ${reason}`, details)
}

function pathStartsWith(pathname: string, prefix: string) {
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

function getActiveTeamIdForAuth(auth: any): string | null {
  if (!auth) return null
  if (auth.role === 'COACH') {
    const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : []
    if (auth.teamId && managedIds.includes(auth.teamId)) return auth.teamId
    if (managedIds.length === 1) return managedIds[0]
    return null
  }
  if (auth.role === 'DIRECTION') return auth.teamId || null
  return auth.teamId || null
}

function getReadableTeamIds(auth: any): string[] {
  if (!auth) return []
  if (auth.role === 'DIRECTION' || auth.role === 'COACH') {
    const activeTeamId = getActiveTeamIdForAuth(auth)
    return activeTeamId ? [activeTeamId] : []
  }
  if (auth.role === 'PARENT') {
    const linkedTeamId = auth.parentLinkedPlayer?.teamId || auth.teamId
    return linkedTeamId ? [linkedTeamId] : []
  }
  return auth.teamId ? [auth.teamId] : []
}

function applyScopeWhere(auth: any, where: any = {}, opts: { includeLegacyOwner?: boolean } = {}) {
  const scopedWhere: any = { ...(where || {}) }
  if (auth?.clubId) scopedWhere.clubId = auth.clubId
  const teamIds = getReadableTeamIds(auth)

  if (teamIds.length === 1) {
    scopedWhere.teamId = teamIds[0]
  } else if (teamIds.length > 1) {
    scopedWhere.teamId = { in: teamIds }
  } else {
    scopedWhere.teamId = '__no_access_team__'
  }

  if (!opts.includeLegacyOwner) return scopedWhere
  return {
    OR: [
      scopedWhere,
      { ...(where || {}), userId: auth?.id }
    ]
  }
}

async function resolveTeamForWrite(auth: any, requestedTeamId?: string | null) {
  if (!auth?.clubId) {
    const err: any = new Error('No club attached to account')
    err.code = 'NO_CLUB'
    throw err
  }

  if (auth.role === 'DIRECTION' || auth.role === 'COACH') {
    const activeTeamId = getActiveTeamIdForAuth(auth)
    const teamId = requestedTeamId || activeTeamId
    if (!teamId) {
      const err: any = new Error('Active team selection is required')
      err.code = 'TEAM_REQUIRED'
      throw err
    }
    if (auth.role === 'COACH') {
      const managedIds = Array.isArray(auth.managedTeamIds) ? auth.managedTeamIds : []
      if (!managedIds.includes(teamId)) {
        const err: any = new Error('Coach cannot write outside managed teams')
        err.code = 'TEAM_FORBIDDEN'
        throw err
      }
    }
    const team = await prisma.team.findFirst({
      where: { id: teamId, clubId: auth.clubId },
      select: { id: true, clubId: true }
    })
    if (!team) {
      const err: any = new Error('Selected team not found in club')
      err.code = 'TEAM_FORBIDDEN'
      throw err
    }
    return team
  }

  const err: any = new Error('Write access forbidden')
  err.code = 'WRITE_FORBIDDEN'
  throw err
}

function normalizeScopeInput(scopeOrUserId: any) {
  if (scopeOrUserId && typeof scopeOrUserId === 'object' && 'role' in scopeOrUserId) return scopeOrUserId
  if (typeof scopeOrUserId === 'string') return { id: scopeOrUserId, role: 'DIRECTION' }
  return { id: null, role: 'DIRECTION' }
}

function scopedWhereOrLegacy(scopeOrUserId: any, where: any = {}) {
  if (typeof scopeOrUserId === 'string') return { ...(where || {}), userId: scopeOrUserId }
  return applyScopeWhere(normalizeScopeInput(scopeOrUserId), where, { includeLegacyOwner: true })
}

async function playerCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return db.player.create({
    data: {
      ...data,
      ...(auth?.id ? { userId: auth.id } : {})
    }
  })
}

async function attendanceFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.attendance.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function attendanceFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.attendance.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function attendanceDeleteManyForUser(db: any, scopeOrUserId: any, where: any = {}) {
  return db.attendance.deleteMany({ where: scopedWhereOrLegacy(scopeOrUserId, where) })
}

async function attendanceUpsertMarkerForUser(db: any, scopeOrUserId: any, params: { session_type: string, session_id: string, playerId: string }) {
  const auth = normalizeScopeInput(scopeOrUserId)
  const { session_type, session_id, playerId } = params
  await attendanceDeleteManyForUser(db, scopeOrUserId, { session_type, session_id, playerId })
  return db.attendance.create({
    data: {
      ...(auth?.id ? { userId: auth.id } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
      session_type,
      session_id,
      playerId
    }
  })
}

async function attendanceSetPresenceForUser(db: any, scopeOrUserId: any, params: { session_type: string, session_id: string, playerId: string, present: boolean }) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return persistAttendancePresence(params as any, {
    deleteMany: (where) => attendanceDeleteManyForUser(db, scopeOrUserId, where),
    create: (data) => db.attendance.create({
      data: {
        ...(auth?.id ? { userId: auth.id } : {}),
        ...(auth?.clubId ? { clubId: auth.clubId } : {}),
        ...(auth?.teamId ? { teamId: auth.teamId } : {}),
        ...data
      },
    })
  })
}

async function attendanceSetPlateauRsvpForUser(db: any, scopeOrUserId: any, plateauId: string, playerId: string, present: boolean) {
  return attendanceSetPresenceForUser(db, scopeOrUserId, {
    session_type: 'PLATEAU',
    session_id: plateauId,
    playerId,
    present,
  })
}

async function resolveAttendanceScopeFromSession(auth: any, session_type: 'TRAINING' | 'PLATEAU', session_id: string) {
  if (session_type === 'TRAINING') {
    const training = await trainingFindFirstForUser(prisma, auth, {
      where: { id: session_id },
      select: { id: true, clubId: true, teamId: true },
    })
    if (!training) return null
    return {
      ...auth,
      clubId: training.clubId ?? auth?.clubId ?? null,
      teamId: training.teamId ?? auth?.teamId ?? null,
    }
  }

  const plateau = await plateauFindFirstForUser(prisma, auth, {
    where: { id: session_id },
    select: { id: true, clubId: true, teamId: true },
  })
  if (!plateau) return null
  return {
    ...auth,
    clubId: plateau.clubId ?? auth?.clubId ?? null,
    teamId: plateau.teamId ?? auth?.teamId ?? null,
  }
}

async function playerFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.player.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function playerFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.player.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function playerFindByIdCompat(db: any, id: string): Promise<any> {
  return db.player.findUnique({ where: { id } })
}

async function trainingFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.training.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function trainingFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.training.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function trainingCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return db.training.create({
    data: {
      ...data,
      ...(auth?.id ? { userId: auth.id } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
    }
  })
}

async function trainingUpdateCompat(db: any, id: string, data: any) {
  return db.training.update({ where: { id }, data })
}

async function plateauFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.plateau.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function plateauFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.plateau.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function plateauCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return db.plateau.create({
    data: {
      ...data,
      ...(auth?.id ? { userId: auth.id } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
    }
  })
}

async function matchFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.match.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function matchFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.match.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function matchFindUniqueCompat(db: any, args: any): Promise<any> {
  return db.match.findUnique(args)
}

async function matchCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  const { plateauId, ...rest } = data
  return db.match.create({
    data: {
      ...rest,
      ...(plateauId ? { plateau: { connect: { id: plateauId } } } : {}),
      ...(auth?.id ? { user: { connect: { id: auth.id } } } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
    }
  })
}

async function trainingDrillFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.trainingDrill.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function trainingDrillFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.trainingDrill.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function trainingDrillCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return db.trainingDrill.create({
    data: {
      ...data,
      ...(auth?.id ? { userId: auth.id } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
    }
  })
}

async function trainingRoleAssignmentFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  try {
    return await db.trainingRoleAssignment.findMany({
      ...args,
      where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    })
  } catch (e: any) {
    if (e?.code === 'P2021') {
      const err: any = new Error('Training role storage unavailable')
      err.code = 'TRAINING_ROLE_STORAGE_UNAVAILABLE'
      throw err
    }
    throw e
  }
}

function toTrainingRoleAssignmentResponseItem(row: any) {
  return {
    id: row.id,
    trainingId: row.trainingId,
    role: row.role,
    playerId: row.playerId,
    player: row.player ? { id: row.player.id, name: row.player.name } : null,
  }
}

function getDrillDelegate(db: any) {
  const delegate = db?.drill
  if (!delegate || typeof delegate.findMany !== 'function' || typeof delegate.findFirst !== 'function') {
    return null
  }
  return delegate
}

async function drillFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  const delegate = getDrillDelegate(db)
  if (!delegate) return []
  try {
    return await delegate.findMany({
      ...args,
      where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    })
  } catch (e: any) {
    if (e?.code === 'P2021') return []
    throw e
  }
}

async function drillFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  const delegate = getDrillDelegate(db)
  if (!delegate) return null
  try {
    return await delegate.findFirst({
      ...args,
      where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
    })
  } catch (e: any) {
    if (e?.code === 'P2021') return null
    throw e
  }
}

async function drillCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  const delegate = getDrillDelegate(db)
  if (!delegate || typeof delegate.create !== 'function') {
    const err: any = new Error('Drill storage unavailable')
    err.code = 'DRILL_STORAGE_UNAVAILABLE'
    throw err
  }
  try {
    return await delegate.create({
      data: {
        ...data,
        ...(auth?.id ? { userId: auth.id } : {}),
        ...(auth?.clubId ? { clubId: auth.clubId } : {}),
        ...(auth?.teamId ? { teamId: auth.teamId } : {}),
      }
    })
  } catch (e: any) {
    if (e?.code === 'P2021') {
      const err: any = new Error('Drill storage unavailable')
      err.code = 'DRILL_STORAGE_UNAVAILABLE'
      throw err
    }
    throw e
  }
}

async function resolveTrainingDrillForRouteRef(
  db: any,
  scopeOrUserId: any,
  trainingId: string,
  trainingDrillRef: string
): Promise<any> {
  const byId = await trainingDrillFindFirstForUser(db, scopeOrUserId, {
    where: { id: trainingDrillRef, trainingId },
  })
  if (byId) return byId
  const byDrillId = await trainingDrillFindManyForUser(db, scopeOrUserId, {
    where: { drillId: trainingDrillRef, trainingId },
    orderBy: { order: 'asc' },
    take: 2,
  })
  if (byDrillId.length !== 1) return null
  return byDrillId[0]
}

async function listTrainingDrillsInOrder(db: any, scopeOrUserId: any, trainingId: string, args: any = {}): Promise<any[]> {
  return trainingDrillFindManyForUser(db, scopeOrUserId, {
    ...args,
    where: { ...(args.where || {}), trainingId },
    orderBy: args.orderBy || [{ order: 'asc' }, { id: 'asc' }],
  })
}

async function normalizeTrainingDrillOrders(db: any, scopeOrUserId: any, trainingId: string) {
  const rows = await listTrainingDrillsInOrder(db, scopeOrUserId, trainingId, {
    select: { id: true, order: true },
  })

  for (const [index, row] of rows.entries()) {
    if (row.order === index) continue
    await db.trainingDrill.update({
      where: { id: row.id },
      data: { order: index },
    })
  }
}

async function moveTrainingDrillToOrder(
  db: any,
  scopeOrUserId: any,
  trainingId: string,
  trainingDrillId: string,
  targetOrder: number
) {
  const rows = await listTrainingDrillsInOrder(db, scopeOrUserId, trainingId, {
    select: { id: true, order: true },
  })
  const currentIndex = rows.findIndex((row: any) => row.id === trainingDrillId)
  if (currentIndex < 0) {
    const err: any = new Error('Training drill not found')
    err.code = 'TRAINING_DRILL_NOT_FOUND'
    throw err
  }
  if (targetOrder < 0 || targetOrder >= rows.length) {
    const err: any = new Error('Invalid order')
    err.code = 'INVALID_ORDER'
    throw err
  }
  if (currentIndex === targetOrder) return

  const [moved] = rows.splice(currentIndex, 1)
  rows.splice(targetOrder, 0, moved)

  for (const [index, row] of rows.entries()) {
    if (row.order === index) continue
    await db.trainingDrill.update({
      where: { id: row.id },
      data: { order: index },
    })
  }
}

async function diagramFindManyForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any[]> {
  return db.diagram.findMany({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function diagramFindFirstForUser(db: any, scopeOrUserId: any, args: any = {}): Promise<any> {
  return db.diagram.findFirst({
    ...args,
    where: scopedWhereOrLegacy(scopeOrUserId, args.where || {}),
  })
}

async function diagramCreateForUser(db: any, scopeOrUserId: any, data: any) {
  const auth = normalizeScopeInput(scopeOrUserId)
  return db.diagram.create({
    data: {
      ...data,
      ...(auth?.id ? { userId: auth.id } : {}),
      ...(auth?.clubId ? { clubId: auth.clubId } : {}),
      ...(auth?.teamId ? { teamId: auth.teamId } : {}),
    }
  })
}

// --- Nodemailer (optional) ---
let transporter: nodemailer.Transporter | null = null

const SMTP_URL = process.env.SMTP_URL
const SMTP_HOST = process.env.SMTP_HOST
const SMTP_PORT = Number(process.env.SMTP_PORT || 587)
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465
const SMTP_USER = process.env.SMTP_USER
const SMTP_PASS = process.env.SMTP_PASS

try {
  if (SMTP_URL) {
    transporter = nodemailer.createTransport(SMTP_URL)
  } else if (SMTP_HOST && SMTP_HOST !== 'smtp.example.com') {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
      connectionTimeout: 10_000,
    })
  } else if (SMTP_HOST === 'smtp.example.com') {
    console.warn('[smtp] Placeholder SMTP_HOST detected (smtp.example.com). Email notifications disabled. Set real creds or unset SMTP_HOST.')
  }

  if (transporter) {
    // Verify at startup; if it fails, disable transporter to avoid noisy errors at runtime.
    transporter.verify().then(() => {
      console.log('[smtp] Transport ready')
    }).catch((err) => {
      console.warn('[smtp] Verification failed. Disabling email notifications.', err?.message || err)
      transporter = null
    })
  }
} catch (e: any) {
  console.warn('[smtp] Failed to initialize transporter. Email notifications disabled.', e?.message || e)
  transporter = null
}

// --- Waitlist helpers (in‑memory) ---
const waitlistSeen = new Map<string, number>(); // email -> timestamp
const WAITLIST_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes
function normEmail(e: string) { return e.trim().toLowerCase(); }

function asOptionalTrimmedString(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length ? trimmed : null
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0)
}

function firstPresentString(...values: unknown[]): string | null {
  for (const value of values) {
    const normalized = asOptionalTrimmedString(value)
    if (normalized) return normalized
  }
  return null
}

function normalizeCoachPayload(raw: any) {
  const managedTeamIds = asStringArray(raw?.managedTeamIds ?? raw?.managed_team_ids)
  const teamIdFromLegacyManaged = managedTeamIds[0] ?? null

  return {
    role: firstPresentString(raw?.role) ?? 'COACH',
    firstName: firstPresentString(raw?.firstName, raw?.first_name, raw?.prenom),
    lastName: firstPresentString(raw?.lastName, raw?.last_name, raw?.nom),
    email: firstPresentString(raw?.email),
    phone: firstPresentString(raw?.phone, raw?.telephone),
    teamId: firstPresentString(raw?.teamId, raw?.team_id, teamIdFromLegacyManaged),
    managedTeamIds,
    expiresInDays: raw?.expiresInDays ?? raw?.expires_in_days,
  }
}

function toCoachSummaryFromUser(user: any) {
  return {
    id: user.id,
    firstName: user.firstName ?? null,
    lastName: user.lastName ?? null,
    email: user.email,
    phone: user.phone ?? null,
    teamId: user.teamId ?? null,
    teamName: user.team?.name ?? null,
    invitationStatus: 'ACCEPTED',
  }
}

function toCoachSummaryFromInvite(invite: any) {
  return {
    id: invite.id,
    firstName: invite.firstName ?? null,
    lastName: invite.lastName ?? null,
    email: invite.email,
    phone: invite.phone ?? null,
    teamId: invite.teamId ?? null,
    teamName: invite.teamName ?? invite.team?.name ?? null,
    invitationStatus: invite.status,
  }
}

// --- Routes ---
function safeParseJSON(s: string | null) {
  if (!s) return null
  try { return JSON.parse(s) } catch { return null }
}

function slugifyDrillTitle(title: string) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')
}

async function buildUniqueDrillId(db: any, scopeOrUserId: any, title: string) {
  const base = slugifyDrillTitle(title)
  let id = `d_${base || 'new'}`
  let i = 1
  while (await drillFindFirstForUser(db, scopeOrUserId, { where: { id } })) {
    id = `d_${base || 'new'}_${i++}`
  }
  return id
}

function inferAgeBandFromTeamName(teamName: string | null | undefined) {
  const raw = String(teamName || '')
  const m = raw.match(/\bU\s*([0-9]{1,2})\b/i)
  if (!m) return 'U9-U11'
  const age = Number(m[1])
  if (!Number.isFinite(age)) return 'U9-U11'
  return `U${age}`
}

const aiGeneratedDrillSchema = z.object({
  t: z.string().min(1).max(100),
  c: z.string().min(1).max(500),
  m: z.number().int().min(6).max(40),
  p: z.string().min(1).max(500),
  s: z.string().min(1).max(2000),
  g: z.array(z.string().min(1).max(64)).max(8),
  a: z.object({
    p: z.array(z.tuple([z.number(), z.number()])).max(5).optional(),
    s: z.array(z.tuple([z.number(), z.number()])).max(5).optional(),
    c: z.array(z.tuple([z.number(), z.number()])).max(4).optional(),
  }).optional(),
  k: z.object({
    f: z.array(z.object({
      a: z.string().min(1).max(24),
      t: z.tuple([z.number(), z.number()]),
    })).max(6)
  }).optional(),
  v: z.object({
    c: z.array(z.tuple([z.number(), z.number()])).max(4).optional(),
    f: z.array(z.object({
      p1: z.tuple([z.number(), z.number()]),
      p2: z.tuple([z.number(), z.number()]),
      b: z.tuple([z.number(), z.number()]).optional(),
    })).min(3).max(12).optional(),
  }).optional(),
})

const aiGeneratedBundleSchema = z.object({
  d: z.array(aiGeneratedDrillSchema).length(5)
})

function readFirstString(...values: any[]) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  return ''
}

function readFirstInt(...values: any[]) {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value)
    if (typeof value === 'string' && value.trim()) {
      const n = Number(value)
      if (Number.isFinite(n)) return Math.trunc(n)
    }
  }
  return 0
}

function readTags(value: any) {
  if (!Array.isArray(value)) return []
  return value
    .map((tag) => typeof tag === 'string' ? tag.trim() : '')
    .filter(Boolean)
}

function readPointPairs(value: any) {
  if (!Array.isArray(value)) return []
  const points: Array<[number, number]> = []
  for (const item of value) {
    if (!Array.isArray(item) || item.length < 2) continue
    const x = Number(item[0])
    const y = Number(item[1])
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue
    points.push([x, y])
  }
  return points
}

function readPhases(value: any) {
  if (!Array.isArray(value)) return []
  return value.map((phase: any) => ({
    a: readFirstString(phase?.a, phase?.action, phase?.type),
    t: readPointPairs([phase?.t ?? phase?.target])[0]
  })).filter((phase: any) => phase.a && Array.isArray(phase.t))
}

function readVisualFrames(value: any) {
  if (!Array.isArray(value)) return []
  return value.map((frame: any) => ({
    p1: readPointPairs([frame?.p1 ?? frame?.a ?? frame?.attacker])[0],
    p2: readPointPairs([frame?.p2 ?? frame?.s ?? frame?.support])[0],
    b: readPointPairs([frame?.b ?? frame?.ball])[0],
  })).filter((frame: any) => Array.isArray(frame.p1) && Array.isArray(frame.p2))
}

function normalizeFrameSeries(frames: Array<{ p1: [number, number], p2: [number, number], b?: [number, number] }>) {
  if (!frames.length) return []
  if (frames.length === 10) return frames
  const out: Array<{ p1: [number, number], p2: [number, number], b?: [number, number] }> = []
  for (let i = 0; i < 10; i += 1) {
    const t = i / 9
    const scaled = t * (frames.length - 1)
    const fromIndex = Math.floor(scaled)
    const toIndex = Math.min(frames.length - 1, fromIndex + 1)
    const localT = scaled - fromIndex
    const from = frames[fromIndex]
    const to = frames[toIndex]
    const lerp = (a: number, b: number) => a + (b - a) * localT
    const p1: [number, number] = [lerp(from.p1[0], to.p1[0]), lerp(from.p1[1], to.p1[1])]
    const p2: [number, number] = [lerp(from.p2[0], to.p2[0]), lerp(from.p2[1], to.p2[1])]
    const b0 = from.b || from.p1
    const b1 = to.b || to.p1
    const b: [number, number] = [lerp(b0[0], b1[0]), lerp(b0[1], b1[1])]
    out.push({ p1, p2, b })
  }
  return out
}

function buildDetailedDescription(raw: string, title: string, ageBand: string, objective: string) {
  const compact = raw.trim().replace(/\s+/g, ' ').slice(0, 1400)
  const hasSections =
    /organisation\s*:|consignes?\s*:|variables?\s*:|vigilance\s*:/i.test(compact)

  if (compact.length >= 420 && hasSections) return compact

  const fallback = [
    `Organisation: ${compact || `atelier "${title}"`} sur 20x20m, 2 couloirs de jeu, rotation toutes les 60-90 secondes, groupes équilibrés pour ${ageBand}.`,
    `Consignes: contrôler orienté, annoncer l'information avant réception, enchaîner en 2 touches max, se replacer immédiatement après action.`,
    `Déroulé: démarrage à faible intensité (2 min), montée en rythme (4-6 min), situation opposée finale avec score/objectif lié à "${objective}".`,
    `Variables: réduire l'espace, ajouter un défenseur, imposer un sens de circulation ou une zone de finition pour augmenter la complexité.`,
    `Vigilance: distances de sécurité, contacts maîtrisés, qualité des appuis et correction courte entre rotations.`,
  ].join(' ')
  return fallback.slice(0, 1400)
}

function sentenceize(value: string) {
  const compact = value.trim().replace(/\s+/g, ' ')
  if (!compact) return ''
  return /[.!?]$/.test(compact) ? compact : `${compact}.`
}

function extractSection(content: string, section: string) {
  const lower = content.toLowerCase()
  const sectionLabel = `${section.toLowerCase()}:`
  const start = lower.indexOf(sectionLabel)
  if (start < 0) return ''
  const after = start + sectionLabel.length
  const nextCandidates = ['organisation:', 'consignes:', 'deroule:', 'déroulé:', 'variables:', 'vigilance:']
    .map((label) => lower.indexOf(label, after))
    .filter((index) => index >= 0)
  const end = nextCandidates.length ? Math.min(...nextCandidates) : content.length
  return content.slice(after, end).trim()
}

function formatDrillDescription(raw: string) {
  const compact = raw.trim().replace(/\r\n/g, '\n').replace(/\s+/g, ' ')
  const normalized = compact
    .replace(/déroulé\s*:/gi, 'Deroule:')
    .replace(/organisation\s*:/gi, 'Organisation:')
    .replace(/consignes?\s*:/gi, 'Consignes:')
    .replace(/variables?\s*:/gi, 'Variables:')
    .replace(/vigilance\s*:/gi, 'Vigilance:')

  const organisation = extractSection(normalized, 'Organisation')
  const consignes = extractSection(normalized, 'Consignes')
  const deroule = extractSection(normalized, 'Deroule')
  const variables = extractSection(normalized, 'Variables')
  const vigilance = extractSection(normalized, 'Vigilance')

  if (organisation || consignes || deroule || variables || vigilance) {
    const lines = [
      organisation ? `**Organisation :** ${sentenceize(organisation)}` : '',
      consignes ? `**Consignes :** ${sentenceize(consignes)}` : '',
      deroule ? `**Déroulé :** ${sentenceize(deroule)}` : '',
      variables ? `**Variables :** ${sentenceize(variables)}` : '',
      vigilance ? `**Vigilance :** ${sentenceize(vigilance)}` : '',
    ].filter(Boolean)
    return lines.join('\n')
  }

  // Fallback: split dense text into digestible action lines.
  const parts = compact
    .split(/[.!?]\s+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .slice(0, 5)

  const fallbackLines = [
    parts[0] ? `**Organisation :** ${sentenceize(parts[0])}` : '',
    parts[1] ? `**Consignes :** ${sentenceize(parts[1])}` : '',
    parts[2] ? `**Déroulé :** ${sentenceize(parts[2])}` : '',
    parts[3] ? `**Variables :** ${sentenceize(parts[3])}` : '',
    parts[4] ? `**Vigilance :** ${sentenceize(parts[4])}` : '',
  ].filter(Boolean)

  return fallbackLines.join('\n')
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function toDrillDescriptionHtml(value: string) {
  const lines = value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  if (!lines.length) return ''

  return lines.map((line) => {
    const md = line.match(/^\*\*(.+?)\*\*\s*(.*)$/)
    if (md) {
      return `<p><strong>${escapeHtml(md[1].trim())}</strong> ${escapeHtml(md[2])}</p>`
    }
    const plain = line.match(/^([^:]+)\s*:\s*(.*)$/)
    if (plain) {
      return `<p><strong>${escapeHtml(plain[1].trim())} :</strong> ${escapeHtml(plain[2])}</p>`
    }
    return `<p>${escapeHtml(line)}</p>`
  }).join('')
}

function normalizeIncomingDescription(raw: string) {
  const noHtml = raw.replace(/<[^>]*>/g, ' ')
  const noMarkdown = noHtml
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/__(.*?)__/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
  return noMarkdown.replace(/\s+/g, ' ').trim()
}

function withDrillDescriptionHtml<T extends { description?: string | null }>(drill: T): T & { descriptionHtml: string } {
  const raw = typeof drill?.description === 'string' ? drill.description : ''
  const normalizedRaw = normalizeIncomingDescription(raw)
  const formatted = formatDrillDescription(normalizedRaw)
  return {
    ...drill,
    description: formatted,
    descriptionHtml: toDrillDescriptionHtml(formatted),
  }
}

function normalizeAiDrillValue(
  value: z.infer<typeof aiGeneratedDrillSchema>,
  ctx: { ageBand: string, objective: string }
) {
  const title = value.t.trim().slice(0, 100)
  const category = value.c.trim().slice(0, 50)
  const duration = Math.max(6, Math.min(40, Math.trunc(value.m)))
  const players = value.p.trim().slice(0, 50)
  const description = buildDetailedDescription(value.s, title, ctx.ageBand, ctx.objective).slice(0, 1200)
  const tags = Array.from(
    new Set(
      value.g
        .map((tag) => tag.trim().toLowerCase().slice(0, 24))
        .filter(Boolean)
    )
  ).slice(0, 3)
  const clampPoint = ([x, y]: [number, number]): [number, number] => [
    Math.max(0, Math.min(100, Math.round(x))),
    Math.max(0, Math.min(100, Math.round(y))),
  ]
  const primaryPath = (value.a?.p || []).map(clampPoint).slice(0, 5)
  const supportPath = (value.a?.s || []).map(clampPoint).slice(0, 5)
  const cones = (value.a?.c || []).map(clampPoint).slice(0, 4)
  const animation = {
    p: primaryPath.length >= 2 ? primaryPath : undefined,
    s: supportPath.length >= 2 ? supportPath : undefined,
    c: cones.length >= 2 ? cones : undefined,
  }
  const phaseAction = (raw: string) => {
    const s = raw.toUpperCase()
    if (s.includes('PRESS')) return 'PRESS'
    if (s.includes('INTERCEPT')) return 'INTERCEPT'
    if (s.includes('DRIBBLE')) return 'DRIBBLE'
    if (s.includes('FINISH') || s.includes('SHOT') || s.includes('TIR')) return 'FINISH'
    if (s.includes('SUPPORT') || s.includes('APPU')) return 'SUPPORT'
    if (s.includes('PASS') || s.includes('PASSE')) return 'PASS'
    return 'MOVE'
  }
  const rawPhases = (value.k?.f || [])
  const phases = rawPhases.map((phase) => ({
    a: phaseAction(String(phase.a || '')),
    t: clampPoint(phase.t)
  })).slice(0, 6)

  const tacticalPlan = { phases: phases.length ? phases : undefined }
  const sequence = tacticalPlan.phases?.map((phase) => phase.a).join(' -> ')
  const descriptionWithPlan = sequence
    ? `${description} Séquence: ${sequence}.`
    : description
  const formattedDescription = formatDrillDescription(descriptionWithPlan).slice(0, 1200)
  const descriptionHtml = toDrillDescriptionHtml(formattedDescription)
  const visualCones = (value.v?.c || []).map(clampPoint).slice(0, 4)
  const visualFramesRaw = normalizeFrameSeries(
    (value.v?.f || []).map((frame) => ({
      p1: clampPoint(frame.p1),
      p2: clampPoint(frame.p2),
      b: frame.b ? clampPoint(frame.b) : clampPoint(frame.p1),
    }))
  )
  const visualPlan = {
    c: visualCones.length >= 2 ? visualCones : undefined,
    f: visualFramesRaw.length === 10 ? visualFramesRaw : undefined,
  }

  return {
    title,
    category,
    duration,
    players,
    description: formattedDescription,
    descriptionHtml,
    tags,
    animation,
    tacticalPlan,
    visualPlan
  }
}

function coerceOpenAiBundle(raw: any) {
  const root = raw && typeof raw === 'object' ? raw : {}
  const list =
    (Array.isArray(root.d) && root.d) ||
    (Array.isArray(root.drills) && root.drills) ||
    (Array.isArray(root.exercises) && root.exercises) ||
    (Array.isArray(root.items) && root.items) ||
    (Array.isArray(raw) && raw) ||
    []

  const mapped = list.slice(0, 5).map((item: any) => ({
    t: readFirstString(item?.t, item?.title, item?.name),
    c: readFirstString(item?.c, item?.category, item?.theme, item?.type),
    m: readFirstInt(item?.m, item?.minutes, item?.duration),
    p: readFirstString(item?.p, item?.players, item?.group, item?.format),
    s: readFirstString(item?.s, item?.description, item?.consigne, item?.instructions),
    g: readTags(item?.g ?? item?.tags ?? item?.keywords),
    a: {
      p: readPointPairs(item?.a?.p ?? item?.animation?.p ?? item?.path ?? item?.primaryPath),
      s: readPointPairs(item?.a?.s ?? item?.animation?.s ?? item?.supportPath),
      c: readPointPairs(item?.a?.c ?? item?.animation?.c ?? item?.cones),
    },
    k: {
      f: readPhases(item?.k?.f ?? item?.plan?.f ?? item?.phases ?? item?.sequence),
    },
    v: {
      c: readPointPairs(item?.v?.c ?? item?.visual?.c ?? item?.visualPlan?.c ?? item?.cones),
      f: readVisualFrames(item?.v?.f ?? item?.visual?.f ?? item?.visualPlan?.f ?? item?.frames),
    },
  }))

  return { d: mapped }
}

function shortNodeId() {
  return randomUUID().replace(/-/g, '').slice(0, 8)
}

function hashText(input: string) {
  let hash = 0
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }
  return Math.abs(hash)
}

function pointAtPath(points: Array<{ x: number, y: number }>, t: number) {
  if (!points.length) return { x: 100, y: 80 }
  if (points.length === 1) return points[0]
  const scaled = t * (points.length - 1)
  const i = Math.min(points.length - 2, Math.max(0, Math.floor(scaled)))
  const localT = scaled - i
  const from = points[i]
  const to = points[i + 1]
  return {
    x: from.x + (to.x - from.x) * localT,
    y: from.y + (to.y - from.y) * localT,
  }
}

function normalizePathPoints(index: number, points?: Array<[number, number]>) {
  if (!points || points.length < 2) return null
  const offset = (index % 5) * 6
  return points.map(([x, y]) => ({
    x: 36 + x * 1.6 + offset,
    y: 30 + y * 1.1,
  }))
}

function warpPoint(x: number, y: number, t: number, seed: number, variant: number) {
  const ampX = 4 + (seed % 6)
  const ampY = 3 + ((seed >> 3) % 6)
  const freq = 1 + (seed % 3)
  const phase = (seed % 360) * (Math.PI / 180)
  const wx = x + Math.sin((t * Math.PI * 2 * freq) + phase) * ampX * (variant === 1 ? 1.2 : 0.8)
  const wy = y + Math.cos((t * Math.PI * freq) + phase / 2) * ampY * (variant === 2 ? 1.25 : 0.75)
  return { x: wx, y: wy }
}

function maybeMirrorX(x: number, seed: number) {
  // Keep coordinates in the same board space while inverting shape orientation for half the drills.
  if (seed % 2 === 0) return x
  return 300 - x
}

function scaleDiagramToViewport(data: any) {
  const frames = Array.isArray(data?.frames) ? data.frames : []
  if (!frames.length) return data

  const points: Array<{ x: number, y: number }> = []
  for (const frame of frames) {
    const items = Array.isArray(frame?.items) ? frame.items : []
    for (const item of items) {
      if (typeof item?.x === 'number' && typeof item?.y === 'number') {
        points.push({ x: item.x, y: item.y })
      }
      if (item?.from && typeof item.from.x === 'number' && typeof item.from.y === 'number') {
        points.push({ x: item.from.x, y: item.from.y })
      }
      if (item?.to && typeof item.to.x === 'number' && typeof item.to.y === 'number') {
        points.push({ x: item.to.x, y: item.to.y })
      }
    }
  }
  if (!points.length) return data

  let minX = points[0].x
  let maxX = points[0].x
  let minY = points[0].y
  let maxY = points[0].y
  for (const point of points) {
    if (point.x < minX) minX = point.x
    if (point.x > maxX) maxX = point.x
    if (point.y < minY) minY = point.y
    if (point.y > maxY) maxY = point.y
  }

  const width = Math.max(1, maxX - minX)
  const height = Math.max(1, maxY - minY)
  const targetMinX = 16
  const targetMaxX = 284
  const targetMinY = 12
  const targetMaxY = 168
  const targetWidth = targetMaxX - targetMinX
  const targetHeight = targetMaxY - targetMinY
  const scale = Math.min(targetWidth / width, targetHeight / height)
  const scaledWidth = width * scale
  const scaledHeight = height * scale
  const translateX = targetMinX + (targetWidth - scaledWidth) / 2 - minX * scale
  const translateY = targetMinY + (targetHeight - scaledHeight) / 2 - minY * scale

  const transform = (x: number, y: number) => ({ x: x * scale + translateX, y: y * scale + translateY })
  const scaledFrames = frames.map((frame: any) => {
    const items = Array.isArray(frame?.items) ? frame.items : []
    return {
      ...frame,
      items: items.map((item: any) => {
        const next: any = { ...item }
        if (typeof next.x === 'number' && typeof next.y === 'number') {
          const p = transform(next.x, next.y)
          next.x = p.x
          next.y = p.y
        }
        if (next.from && typeof next.from.x === 'number' && typeof next.from.y === 'number') {
          const p = transform(next.from.x, next.from.y)
          next.from = { ...next.from, x: p.x, y: p.y }
        }
        if (next.to && typeof next.to.x === 'number' && typeof next.to.y === 'number') {
          const p = transform(next.to.x, next.to.y)
          next.to = { ...next.to, x: p.x, y: p.y }
        }
        return next
      })
    }
  })

  return {
    ...data,
    items: scaledFrames[0]?.items || [],
    frames: scaledFrames
  }
}

function buildDefaultDiagramData(
  index: number,
  drill: {
    title: string,
    category: string,
    tags: string[],
    animation?: { p?: Array<[number, number]>, s?: Array<[number, number]>, c?: Array<[number, number]> },
    tacticalPlan?: { phases?: Array<{ a: string, t: [number, number] }> },
    visualPlan?: { c?: Array<[number, number]>, f?: Array<{ p1: [number, number], p2: [number, number], b?: [number, number] }> }
  }
) {
  const offset = (index % 5) * 14
  const startX = 88 + offset
  const frameCount = 10
  const seed = hashText(`${drill.title}|${drill.category}|${(drill.tags || []).join(',')}`)
  const variant = (seed + index) % 4

  const playerId = shortNodeId()
  const supportId = shortNodeId()
  const coneAId = shortNodeId()
  const coneBId = shortNodeId()
  const coneCId = shortNodeId()

  const toBoardPoint = ([x, y]: [number, number]) => ({ x: 18 + (x * 2.64), y: 12 + (y * 1.56) })
  const hasVisualFrames = Array.isArray(drill.visualPlan?.f) && drill.visualPlan!.f!.length === 10
  const visualCones = Array.isArray(drill.visualPlan?.c) ? drill.visualPlan!.c!.slice(0, 3).map(toBoardPoint) : []

  if (hasVisualFrames) {
    const frames = drill.visualPlan!.f!.map((frame, frameIndex) => {
      const p1 = toBoardPoint(frame.p1)
      const p2 = toBoardPoint(frame.p2)
      const b = toBoardPoint(frame.b || frame.p1)
      const prev = frameIndex > 0 ? drill.visualPlan!.f![frameIndex - 1] : null
      const prevP1 = prev ? toBoardPoint(prev.p1) : p1
      const prevP2 = prev ? toBoardPoint(prev.p2) : p2
      return {
        items: [
          { type: 'player', id: playerId, x: p1.x, y: p1.y, side: 'home', label: 'J1' },
          { type: 'player', id: supportId, x: p2.x, y: p2.y, side: 'home', label: 'J2' },
          { type: 'ball', id: shortNodeId(), x: b.x, y: b.y },
          { type: 'cone', id: coneAId, x: visualCones[0]?.x ?? 72, y: visualCones[0]?.y ?? 86 },
          { type: 'cone', id: coneBId, x: visualCones[1]?.x ?? 144, y: visualCones[1]?.y ?? 66 },
          { type: 'cone', id: coneCId, x: visualCones[2]?.x ?? 204, y: visualCones[2]?.y ?? 96 },
          { type: 'arrow', id: shortNodeId(), from: { x: prevP1.x, y: prevP1.y }, to: { x: p1.x, y: p1.y } },
          { type: 'arrow', id: shortNodeId(), from: { x: prevP2.x, y: prevP2.y }, to: { x: p2.x, y: p2.y } },
        ]
      }
    })
    return scaleDiagramToViewport({ items: frames[0].items, frames })
  }

  const tacticalPath = normalizePathPoints(index, (drill.tacticalPlan?.phases || []).map((phase) => phase.t))
  const primaryPath = tacticalPath && tacticalPath.length >= 2 ? tacticalPath : normalizePathPoints(index, drill.animation?.p)
  const supportPath = normalizePathPoints(index, drill.animation?.s)
  const conePoints = normalizePathPoints(index, drill.animation?.c)
  const startY = 98

  const frames = Array.from({ length: frameCount }, (_unused, frameIndex) => {
    const t = frameIndex / (frameCount - 1)
    let px = startX
    let py = startY
    let supportX = startX + 10
    let supportY = startY + 18

    if (primaryPath) {
      const p = pointAtPath(primaryPath, t)
      px = p.x
      py = p.y
      const s = supportPath ? pointAtPath(supportPath, t) : pointAtPath(primaryPath, Math.max(0, t - 0.22))
      supportX = s.x
      supportY = s.y + 18
    } else if (variant === 0) {
      px = startX + 58 * t
      py = 98 - 38 * t
      supportX = startX + 6 + 32 * t
      supportY = 118 - 18 * t
    } else if (variant === 1) {
      px = startX + 58 * t
      py = 84 + Math.sin(t * Math.PI * 2) * 16
      supportX = startX + 18 + 42 * t
      supportY = 106 - Math.sin(t * Math.PI * 2) * 10
    } else if (variant === 2) {
      px = startX + 44 * t
      py = 90 - t * 24
      supportX = startX + 60 - t * 42
      supportY = 62 + t * 30
    } else {
      px = startX + 10 + Math.sin(t * Math.PI) * 18
      py = 98 - t * 26
      supportX = startX + 56 - Math.sin(t * Math.PI) * 18
      supportY = 80 + t * 18
    }

    const wp = warpPoint(px, py, t, seed, variant)
    px = maybeMirrorX(wp.x, seed)
    py = wp.y
    const ws = warpPoint(supportX, supportY, t, seed + 17, (variant + 1) % 4)
    supportX = maybeMirrorX(ws.x, seed)
    supportY = ws.y

    const c0 = conePoints?.[0]
    const c1 = conePoints?.[1]
    const c2 = conePoints?.[2]

    return {
      items: [
        { type: 'player', id: playerId, x: px, y: py, side: 'home', label: 'J1' },
        { type: 'player', id: supportId, x: supportX, y: supportY, side: 'home', label: 'J2' },
        { type: 'cone', id: coneAId, x: c0?.x ?? startX + (variant === 3 ? 14 : 26), y: c0?.y ?? 84 },
        { type: 'cone', id: coneBId, x: c1?.x ?? startX + 56, y: c1?.y ?? (variant === 1 ? 72 : 64) },
        { type: 'cone', id: coneCId, x: c2?.x ?? startX + 36, y: c2?.y ?? (variant === 2 ? 52 : 102) },
        { type: 'arrow', id: shortNodeId(), from: { x: px, y: py }, to: { x: px + (variant === 2 ? 5 : 8), y: py - 6 } },
        { type: 'arrow', id: shortNodeId(), from: { x: supportX, y: supportY }, to: { x: px, y: py } },
      ]
    }
  })

  const raw = {
    items: frames[0].items,
    frames
  }
  return scaleDiagramToViewport(raw)
}

async function generateDrillsWithOpenAI(
  params: { objective: string, ageBand: string, teamName: string },
  opts: { includeVisualPlan?: boolean } = {}
) {
  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) {
    const err: any = new Error('OPENAI_API_KEY is missing')
    err.code = 'OPENAI_API_KEY_MISSING'
    throw err
  }

  const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini'
  const objective = params.objective.trim()
  const ageBand = params.ageBand.trim()
  const teamName = params.teamName.trim()
  const includeVisualPlan = !!opts.includeVisualPlan
  const systemFormat = includeVisualPlan
    ? 'Tu es un coach football jeunes. Réponds uniquement en JSON compact valide sans markdown. Format strict: {"d":[{"t":"","c":"","m":0,"p":"","s":"","g":[""],"v":{"c":[[20,30],[80,50],[45,80]],"f":[{"p1":[10,70],"p2":[30,80],"b":[10,70]}]},"k":{"f":[{"a":"PASS","t":[30,60]},{"a":"DRIBBLE","t":[60,45]},{"a":"FINISH","t":[85,35]}]},"a":{"p":[[0,0],[100,100]],"s":[[0,0],[100,100]],"c":[[20,30],[80,60],[40,80]]}}]} avec exactement 5 exercices.'
    : 'Tu es un coach football jeunes. Réponds uniquement en JSON compact valide sans markdown. Format strict: {"d":[{"t":"","c":"","m":0,"p":"","s":"","g":[""]}]} avec exactement 5 exercices.'
  const userConstraints = includeVisualPlan
    ? `Objectif:${objective}\nAge:${ageBand}\nEquipe:${teamName}\nContraintes: français; adaptés à l'âge; progression simple->complexe; sécurité; pas de doublons; m en minutes entières; g max 3 tags courts; s très détaillée et opérationnelle (organisation, consignes, déroulé, variables, vigilance), entre 420 et 1000 caractères; k obligatoire: 3 à 5 phases ordonnées (a+t) cohérentes avec la description; v obligatoire: 10 frames (f) avec p1/p2/b en 0..100 + 2-3 cônes (c); les 5 exercices doivent avoir des schémas visuels nettement différents (zones, trajectoires et orientation).`
    : `Objectif:${objective}\nAge:${ageBand}\nEquipe:${teamName}\nContraintes: français; adaptés à l'âge; progression simple->complexe; sécurité; pas de doublons; m en minutes entières; g max 3 tags courts; s très détaillée et opérationnelle (organisation, consignes, déroulé, variables, vigilance), entre 420 et 1000 caractères.`
  const input = [
    {
      role: 'system',
      content: [
        {
          type: 'input_text',
          text: systemFormat
        }
      ]
    },
    {
      role: 'user',
      content: [
        {
          type: 'input_text',
          text: userConstraints
        }
      ]
    }
  ]

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 15000)

  let response: Response
  try {
    try {
      response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          input,
          temperature: 0.4,
          max_output_tokens: includeVisualPlan ? 2800 : 1400,
          text: { format: { type: 'json_object' } }
        }),
        signal: controller.signal,
      })
    } catch (e: any) {
      const err: any = new Error('OpenAI network request failed')
      err.code = e?.name === 'AbortError' ? 'OPENAI_TIMEOUT' : 'OPENAI_NETWORK_ERROR'
      err.detail = e?.message || String(e)
      throw err
    }
  } finally {
    clearTimeout(timeout)
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    const parsedDetail = safeParseJSON(detail) as any
    const err: any = new Error(`OpenAI request failed (${response.status})`)
    err.code = 'OPENAI_REQUEST_FAILED'
    err.status = response.status
    err.detail = detail.slice(0, 500)
    err.openai = parsedDetail?.error || null
    throw err
  }

  const payload: any = await response.json()
  const rawText = typeof payload?.output_text === 'string'
    ? payload.output_text
    : Array.isArray(payload?.output)
      ? payload.output
        .flatMap((item: any) => Array.isArray(item?.content) ? item.content : [])
        .map((chunk: any) => chunk?.text || '')
        .join('\n')
      : ''

  const parsedJson = safeParseJSON(rawText)
  if (!parsedJson) {
    const err: any = new Error('OpenAI response is not valid JSON')
    err.code = 'OPENAI_INVALID_JSON'
    err.raw = String(rawText || '').slice(0, 2000)
    throw err
  }

  const strictParsed = aiGeneratedBundleSchema.safeParse(parsedJson)
  if (strictParsed.success) {
    return strictParsed.data.d.map((drill) => normalizeAiDrillValue(drill, { ageBand: params.ageBand, objective: params.objective }))
  }

  const coerced = coerceOpenAiBundle(parsedJson)
  const parsed = aiGeneratedBundleSchema.safeParse(coerced)
  if (!parsed.success) {
    const err: any = new Error('OpenAI response does not match expected schema')
    err.code = 'OPENAI_SCHEMA_MISMATCH'
    err.raw = JSON.stringify(parsedJson).slice(0, 2000)
    err.coerced = JSON.stringify(coerced).slice(0, 2000)
    err.issues = parsed.error.issues.slice(0, 6)
    throw err
  }

  return parsed.data.d.map((drill) => normalizeAiDrillValue(drill, { ageBand: params.ageBand, objective: params.objective }))
}

const aiVisualPlanSchema = z.object({
  c: z.array(z.tuple([z.number(), z.number()])).min(2).max(12),
  f: z.array(z.object({
    p1: z.tuple([z.number(), z.number()]),
    p2: z.tuple([z.number(), z.number()]),
    b: z.tuple([z.number(), z.number()]).optional(),
  })).min(3).max(12)
})

function coerceVisualPlan(raw: any) {
  const root = raw && typeof raw === 'object' ? raw : {}
  return {
    c: readPointPairs(root?.c ?? root?.cones ?? root?.visual?.c ?? root?.v?.c),
    f: readVisualFrames(root?.f ?? root?.frames ?? root?.visual?.f ?? root?.v?.f),
  }
}

async function generateVisualPlanWithOpenAI(params: {
  title: string,
  category: string,
  description: string,
  tags: string[],
  ageBand: string,
  objective?: string,
}) {
  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) {
    const err: any = new Error('OPENAI_API_KEY is missing')
    err.code = 'OPENAI_API_KEY_MISSING'
    throw err
  }

  const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini'
  const input = [
    {
      role: 'system',
      content: [
        {
          type: 'input_text',
          text: 'Tu crées uniquement un plan visuel de diagramme football jeunes. Réponds en JSON compact valide sans markdown. Format strict: {"c":[[20,30],[80,50],[45,80]],"f":[{"p1":[10,70],"p2":[30,80],"b":[10,70]}]}.'
        }
      ]
    },
    {
      role: 'user',
      content: [
        {
          type: 'input_text',
          text: `Exercice:${params.title}\nCategorie:${params.category}\nAge:${params.ageBand}\nObjectif:${params.objective || params.title}\nTags:${params.tags.join(',')}\nDescription:${params.description}\nContraintes: produire 10 frames cohérentes avec le texte; p1=joueur principal, p2=soutien; b=ballon; coordonnées 0..100; trajectoires lisibles; schéma différent des exercices classiques (éviter ligne droite simple).`
        }
      ]
    }
  ]

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 15000)
  let response: Response
  try {
    try {
      response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          input,
          temperature: 0.3,
          max_output_tokens: 1100,
          text: { format: { type: 'json_object' } }
        }),
        signal: controller.signal,
      })
    } catch (e: any) {
      const err: any = new Error('OpenAI network request failed')
      err.code = e?.name === 'AbortError' ? 'OPENAI_TIMEOUT' : 'OPENAI_NETWORK_ERROR'
      err.detail = e?.message || String(e)
      throw err
    }
  } finally {
    clearTimeout(timeout)
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    const parsedDetail = safeParseJSON(detail) as any
    const err: any = new Error(`OpenAI request failed (${response.status})`)
    err.code = 'OPENAI_REQUEST_FAILED'
    err.status = response.status
    err.detail = detail.slice(0, 500)
    err.openai = parsedDetail?.error || null
    throw err
  }

  const payload: any = await response.json()
  const rawText = typeof payload?.output_text === 'string'
    ? payload.output_text
    : Array.isArray(payload?.output)
      ? payload.output
        .flatMap((item: any) => Array.isArray(item?.content) ? item.content : [])
        .map((chunk: any) => chunk?.text || '')
        .join('\n')
      : ''

  const parsedJson = safeParseJSON(rawText)
  if (!parsedJson) {
    const err: any = new Error('OpenAI response is not valid JSON')
    err.code = 'OPENAI_INVALID_JSON'
    err.raw = String(rawText || '').slice(0, 2000)
    throw err
  }

  const strict = aiVisualPlanSchema.safeParse(parsedJson)
  const value = strict.success ? strict.data : coerceVisualPlan(parsedJson)
  const parsed = aiVisualPlanSchema.safeParse(value)
  if (!parsed.success) {
    const err: any = new Error('OpenAI visual response schema mismatch')
    err.code = 'OPENAI_SCHEMA_MISMATCH'
    err.raw = JSON.stringify(parsedJson).slice(0, 2000)
    err.coerced = JSON.stringify(value).slice(0, 2000)
    err.issues = parsed.error.issues.slice(0, 6)
    throw err
  }

  const clampPoint = ([x, y]: [number, number]): [number, number] => [
    Math.max(0, Math.min(100, Math.round(x))),
    Math.max(0, Math.min(100, Math.round(y))),
  ]
  return {
    c: parsed.data.c.map(clampPoint).slice(0, 4),
    f: normalizeFrameSeries(parsed.data.f.map((frame) => ({
      p1: clampPoint(frame.p1),
      p2: clampPoint(frame.p2),
      b: frame.b ? clampPoint(frame.b) : clampPoint(frame.p1),
    }))).slice(0, 10),
  }
}

function summarizeErrorForLog(error: any) {
  return {
    code: error?.code || null,
    status: error?.status || null,
    message: error?.message || String(error),
    detail: error?.detail || null,
    openai: error?.openai || null,
    issues: error?.issues || null,
    raw: error?.raw || null,
    stack: typeof error?.stack === 'string' ? error.stack.split('\n').slice(0, 4).join('\n') : null,
  }
}

function normalizePublicTeamLabel(raw: string | null | undefined, fallback: string) {
  const normalized = String(raw || '').trim().toUpperCase()
  if (!normalized) return fallback
  if (normalized === 'HOME') return 'A'
  if (normalized === 'AWAY') return 'B'
  return normalized
}

function buildPublicPlateauRotation(matches: Array<{ createdAt: Date; updatedAt: Date; opponentName: string | null; teams: Array<{ side: string }> }>) {
  if (!matches.length) return null

  const slots = matches.map((match, index) => {
    const orderedTeams = match.teams.slice().sort((a, b) => a.side.localeCompare(b.side))
    const teamA = normalizePublicTeamLabel(orderedTeams[0]?.side, 'A')
    const teamB = (match.opponentName && match.opponentName.trim().length > 0)
      ? match.opponentName.trim()
      : normalizePublicTeamLabel(orderedTeams[1]?.side, 'B')

    return {
      time: match.createdAt.toISOString(),
      games: [{ pitch: `Terrain ${index + 1}`, A: teamA, B: teamB }]
    }
  })

  const updatedAt = matches.reduce((latest, current) => current.updatedAt > latest ? current.updatedAt : latest, matches[0].updatedAt)
  return { updatedAt: updatedAt.toISOString(), slots }
}

function normalizePublicRotation(candidate: any, defaultUpdatedAtIso: string) {
  if (!candidate || !Array.isArray(candidate.slots)) return null
  const slots = candidate.slots.map((slot: any) => ({
    time: String(slot?.time ?? ''),
    games: Array.isArray(slot?.games)
      ? slot.games.map((game: any) => ({
          pitch: String(game?.pitch ?? ''),
          A: String(game?.A ?? ''),
          B: String(game?.B ?? ''),
        }))
      : [],
  }))
  return {
    updatedAt: typeof candidate.updatedAt === 'string' ? candidate.updatedAt : defaultUpdatedAtIso,
    slots
  }
}

function findRotationCandidate(data: any) {
  if (!data || typeof data !== 'object') return null
  const directCandidates = [
    data.rotation,
    data?.data?.rotation,
    data?.planning?.rotation,
    data?.schedule?.rotation,
    data?.rotationData,
    data,
  ]
  for (const c of directCandidates) {
    if (c && typeof c === 'object' && Array.isArray((c as any).slots)) return c
  }
  return null
}

async function getPublicPlateauPayloadByToken(token: string) {
  let share: any
  try {
    share = await prisma.plateauShareToken.findFirst({
      where: {
        OR: [
          { token },
          { id: token }, // compat if frontend accidentally stores share row id instead of token
        ]
      },
      include: { plateau: true }
    })
  } catch (e: any) {
    if (e?.code === 'P2021') {
      return { status: 503 as const, body: { error: 'Public sharing is not ready on this environment' } }
    }
    throw e
  }
  if (!share) return { status: 404 as const, body: { error: 'Invalid link' } }
  if (share.expiresAt && share.expiresAt < new Date()) return { status: 410 as const, body: { error: 'Link expired' } }

  let rotation: any = null

  // Prefer rotation saved by the planning editor (same coach + same day).
  if (share.plateau.userId) {
    const dayStart = new Date(share.plateau.date)
    dayStart.setHours(0, 0, 0, 0)
    const dayEnd = new Date(dayStart)
    dayEnd.setDate(dayEnd.getDate() + 1)

    const planning = await prisma.planning.findFirst({
      where: {
        userId: share.plateau.userId,
        date: { gte: dayStart, lt: dayEnd }
      },
      orderBy: { updatedAt: 'desc' }
    })

    if (planning) {
      const planningData = safeParseJSON(planning.data)
      const candidate = findRotationCandidate(planningData)
      rotation = normalizePublicRotation(candidate, planning.updatedAt.toISOString())
    }
  }

  // Fallback: synthesize a minimal rotation from matches.
  if (!rotation) {
    const matches = await prisma.match.findMany({
      where: { plateauId: share.plateauId },
      select: {
        createdAt: true,
        updatedAt: true,
        opponentName: true,
        teams: { select: { side: true } }
      },
      orderBy: { createdAt: 'asc' }
    })
    rotation = buildPublicPlateauRotation(matches)
  }

  return {
    status: 200 as const,
    body: {
      plateau: toPublicPlateau(share.plateau),
      rotation
    }
  }
}

app.post('/auth/register', async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    clubName: z.string().trim().min(2).optional(),
    // Backward compatibility for old front payloads.
    club: z.string().trim().min(2).optional(),
    role: z.enum(['DIRECTION']).optional()
  }).refine((data) => Boolean(data.clubName || data.club), {
    path: ['clubName'],
    message: 'Required'
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password } = parsed.data
  const clubName = parsed.data.clubName || parsed.data.club!
  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) return res.status(409).json({ error: 'Email already in use' })
  const passwordHash = await bcrypt.hash(password, 10)
  const club = await prisma.club.create({ data: { name: clubName } })
  const user = await prisma.user.create({
    data: { email, passwordHash, role: 'DIRECTION', clubId: club.id }
  })
  const token = signToken(user.id)
  res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts())
  res.json({
    id: user.id,
    email: user.email,
    isPremium: user.isPremium,
    role: user.role,
    clubId: user.clubId,
    teamId: user.teamId,
    managedTeamIds: user.managedTeamIds
  })
})

app.post('/auth/login', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password } = parsed.data
  const user = await prisma.user.findUnique({ where: { email } })
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
  const token = signToken(user.id)
  res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts())
  res.json({
    id: user.id,
    email: user.email,
    isPremium: user.isPremium,
    role: user.role,
    clubId: user.clubId,
    teamId: user.teamId,
    managedTeamIds: user.managedTeamIds
  })
})

app.get('/auth/invitations/:token', async (req, res) => {
  const invite = await prisma.accountInvite.findUnique({
    where: { token: req.params.token },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      phone: true,
      role: true,
      status: true,
      expiresAt: true,
      teamId: true,
      managedTeamIds: true,
      linkedPlayerUserId: true
    }
  })
  if (!invite) return res.status(404).json({ error: 'Invitation not found' })
  if (invite.status !== 'PENDING') return res.status(409).json({ error: `Invitation is ${invite.status.toLowerCase()}` })
  if (invite.expiresAt < new Date()) {
    await prisma.accountInvite.update({
      where: { id: invite.id },
      data: { status: 'EXPIRED' }
    })
    return res.status(410).json({ error: 'Invitation expired' })
  }
  res.json(invite)
})

app.post('/auth/invitations/accept', async (req, res) => {
  const schema = z.object({
    token: z.string().min(8),
    password: z.string().min(6)
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const invite = await prisma.accountInvite.findUnique({ where: { token: parsed.data.token } })
  if (!invite) return res.status(404).json({ error: 'Invitation not found' })
  if (invite.status !== 'PENDING') return res.status(409).json({ error: `Invitation is ${invite.status.toLowerCase()}` })
  if (invite.expiresAt < new Date()) {
    await prisma.accountInvite.update({
      where: { id: invite.id },
      data: { status: 'EXPIRED' }
    })
    return res.status(410).json({ error: 'Invitation expired' })
  }

  const existing = await prisma.user.findUnique({ where: { email: invite.email } })
  if (existing) return res.status(409).json({ error: 'Email already in use' })

  const passwordHash = await bcrypt.hash(parsed.data.password, 10)
  const { user } = await prisma.$transaction(async (tx) => {
    const createdUser = await tx.user.create({
      data: {
        email: invite.email,
        passwordHash,
        firstName: invite.firstName,
        lastName: invite.lastName,
        phone: invite.phone,
        role: invite.role,
        clubId: invite.clubId,
        teamId: invite.teamId,
        managedTeamIds: invite.managedTeamIds,
        linkedPlayerUserId: invite.linkedPlayerUserId
      }
    })

    await tx.accountInvite.update({
      where: { id: invite.id },
      data: {
        status: 'ACCEPTED',
        acceptedAt: new Date(),
        userId: createdUser.id
      }
    })

    await tx.accountInvite.updateMany({
      where: {
        clubId: invite.clubId,
        email: invite.email,
        status: 'PENDING',
        id: { not: invite.id }
      },
      data: { status: 'CANCELLED' }
    })

    return { user: createdUser }
  })

  const token = signToken(user.id)
  res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts())
  res.json({
    id: user.id,
    email: user.email,
    isPremium: user.isPremium,
    role: user.role,
    clubId: user.clubId,
    teamId: user.teamId,
    managedTeamIds: user.managedTeamIds
  })
})

app.post('/auth/logout', (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME, authClearCookieOpts())
  res.json({ ok: true })
})

app.get('/me', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) {
    return res.json({
      id: null,
      email: null,
      isPremium: false,
      planningCount: 0,
      anonymous: true,
      role: null,
      clubId: null,
      teamId: null,
      managedTeamIds: []
    })
  }
  return next()
}, authMiddleware, async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } })
  if (!user) return res.status(404).json({ error: 'User not found' })
  const planningCount = user.plannings.length
  res.json({
    id: user.id,
    email: user.email,
    isPremium: user.isPremium,
    planningCount,
    role: user.role,
    clubId: user.clubId,
    teamId: user.teamId,
    managedTeamIds: user.managedTeamIds
  })
})

app.put('/me/team', authMiddleware, async (req: any, res) => {
  if (!req.auth?.clubId) return res.status(400).json({ error: 'No club attached to account' })
  if (req.auth?.role !== 'DIRECTION' && req.auth?.role !== 'COACH') {
    return res.status(403).json({ error: 'Only direction and coach accounts can change active team' })
  }

  const schema = z.object({ teamId: z.string().min(1) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const requestedTeamId = parsed.data.teamId
  if (req.auth.role === 'COACH') {
    const managedIds = Array.isArray(req.auth.managedTeamIds) ? req.auth.managedTeamIds : []
    if (!managedIds.includes(requestedTeamId)) {
      return res.status(403).json({ error: 'Coach cannot select an unmanaged team' })
    }
  }

  const team = await prisma.team.findFirst({
    where: {
      id: requestedTeamId,
      clubId: req.auth.clubId
    },
    select: { id: true }
  })
  if (!team) return res.status(404).json({ error: 'Team not found in club' })

  const updated = await prisma.user.update({
    where: { id: req.auth.id },
    data: { teamId: team.id },
    select: {
      id: true,
      email: true,
      role: true,
      clubId: true,
      teamId: true,
      managedTeamIds: true
    }
  })
  res.json(updated)
})

app.get('/clubs/me', authMiddleware, async (req: any, res) => {
  if (!req.auth?.clubId) return res.status(404).json({ error: 'Club not found' })
  const club = await prisma.club.findUnique({
    where: { id: req.auth.clubId },
    include: {
      teams: { orderBy: { name: 'asc' } },
      users: {
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          phone: true,
          role: true,
          teamId: true,
          managedTeamIds: true,
          linkedPlayerUserId: true,
          createdAt: true
        },
        orderBy: { createdAt: 'asc' }
      }
    }
  })
  if (!club) return res.status(404).json({ error: 'Club not found' })
  res.json({
    ...club,
    teams: (club.teams || []).map(withTeamFormatAliases),
  })
})

app.get('/clubs/me/coaches', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(404).json({ error: 'Club not found' })

  await prisma.accountInvite.updateMany({
    where: {
      clubId: req.auth.clubId,
      role: 'COACH',
      status: 'PENDING',
      expiresAt: { lt: new Date() }
    },
    data: { status: 'EXPIRED' }
  })

  const [coaches, invites] = await Promise.all([
    prisma.user.findMany({
      where: { clubId: req.auth.clubId, role: 'COACH' },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        phone: true,
        teamId: true,
        managedTeamIds: true,
        createdAt: true,
        team: { select: { name: true } },
      },
      orderBy: [{ createdAt: 'desc' }, { email: 'asc' }]
    }),
    prisma.accountInvite.findMany({
      where: { clubId: req.auth.clubId, role: 'COACH' },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        phone: true,
        teamId: true,
        status: true,
        managedTeamIds: true,
        createdAt: true,
      },
      orderBy: [{ createdAt: 'desc' }]
    })
  ])

  const teamIds = new Set<string>()
  for (const coach of coaches) if (coach.teamId) teamIds.add(coach.teamId)
  for (const invite of invites) if (invite.teamId) teamIds.add(invite.teamId)

  const teams = teamIds.size
    ? await prisma.team.findMany({
      where: { id: { in: Array.from(teamIds) }, clubId: req.auth.clubId },
      select: { id: true, name: true }
    })
    : []
  const teamNameById = new Map(teams.map((team) => [team.id, team.name]))

  const acceptedEmails = new Set(coaches.map((coach) => normEmail(coach.email)))
  const seenInviteEmails = new Set<string>()
  const pendingItems = invites.filter((invite) => {
    const email = normEmail(invite.email)
    if (acceptedEmails.has(email)) return false
    if (seenInviteEmails.has(email)) return false
    seenInviteEmails.add(email)
    return true
  })

  res.json([
    ...coaches.map(toCoachSummaryFromUser),
    ...pendingItems.map((invite) =>
      toCoachSummaryFromInvite({
        ...invite,
        teamName: invite.teamId ? (teamNameById.get(invite.teamId) ?? null) : null
      })
    ),
  ])
})

app.get('/coaches/:id', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(404).json({ error: 'Club not found' })

  await prisma.accountInvite.updateMany({
    where: {
      clubId: req.auth.clubId,
      role: 'COACH',
      status: 'PENDING',
      expiresAt: { lt: new Date() }
    },
    data: { status: 'EXPIRED' }
  })

  const coach = await prisma.user.findFirst({
    where: {
      id: req.params.id,
      clubId: req.auth.clubId,
      role: 'COACH'
    },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      teamId: true,
      managedTeamIds: true,
      createdAt: true,
      team: { select: { name: true } },
    }
  })
  if (coach) {
    return res.json({
      ...toCoachSummaryFromUser(coach),
      role: 'COACH',
      managedTeamIds: coach.managedTeamIds,
      createdAt: coach.createdAt,
    })
  }

  const invite = await prisma.accountInvite.findFirst({
    where: {
      id: req.params.id,
      clubId: req.auth.clubId,
      role: 'COACH'
    },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      status: true,
      teamId: true,
      managedTeamIds: true,
      invitedByUserId: true,
      expiresAt: true,
      acceptedAt: true,
      createdAt: true,
      updatedAt: true,
    }
  })
  if (!invite) return res.status(404).json({ error: 'Coach not found' })

  const teamName = invite.teamId
    ? await prisma.team.findFirst({
      where: { id: invite.teamId, clubId: req.auth.clubId },
      select: { name: true }
    }).then((team) => team?.name ?? null)
    : null

  return res.json({
    ...toCoachSummaryFromInvite({ ...invite, teamName }),
    role: 'COACH',
    managedTeamIds: invite.managedTeamIds,
    invitedByUserId: invite.invitedByUserId,
    expiresAt: invite.expiresAt,
    acceptedAt: invite.acceptedAt,
    createdAt: invite.createdAt,
    updatedAt: invite.updatedAt,
  })
})

app.put('/clubs/me', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(404).json({ error: 'Club not found' })

  const schema = z.object({
    name: z.string().min(2).max(120)
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const updated = await prisma.club.update({
    where: { id: req.auth.clubId },
    data: { name: parsed.data.name.trim() }
  })
  res.json(updated)
})

app.get('/teams', authMiddleware, async (req: any, res) => {
  if (!req.auth?.clubId) return res.json([])
  const teams = await prisma.team.findMany({
    where: { clubId: req.auth.clubId },
    orderBy: { name: 'asc' },
    select: {
      id: true,
      name: true,
      category: true,
      format: true,
      clubId: true,
      createdAt: true,
    },
  })
  res.json(teams.map(normalizeTeamResponse))
})

app.post('/teams', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(400).json({ error: 'Direction account must be attached to a club' })
  const parsed = teamUpsertPayloadSchema.safeParse(req.body)
  if (!parsed.success) {
    const message = parsed.error.issues[0]?.message || 'Invalid team payload'
    logTeamValidationFailure('POST /teams', message, { clubId: req.auth.clubId })
    return res.status(400).json({ error: message })
  }

  const categoryResult = normalizeTeamCategory(parsed.data.category)
  if (!categoryResult.ok) {
    logTeamValidationFailure('POST /teams', categoryResult.error, {
      clubId: req.auth.clubId,
      category: parsed.data.category,
    })
    return res.status(400).json({ error: categoryResult.error })
  }

  const formatResult = normalizeTeamFormat(parsed.data.format)
  if (!formatResult.ok) {
    logTeamValidationFailure('POST /teams', formatResult.error, {
      clubId: req.auth.clubId,
      format: parsed.data.format,
    })
    return res.status(400).json({ error: formatResult.error })
  }

  const providedName = typeof parsed.data.name === 'string' ? parsed.data.name.trim() : ''
  const finalName = providedName || await generateAutoTeamName(req.auth.clubId, categoryResult.category)

  try {
    const team = await prisma.team.create({
      data: { name: finalName, category: categoryResult.category, format: formatResult.format, clubId: req.auth.clubId },
      select: {
        id: true,
        name: true,
        category: true,
        format: true,
        clubId: true,
        createdAt: true,
      },
    })
    return res.status(201).json(normalizeTeamResponse(team))
  } catch (e: any) {
    if (e?.code === 'P2002') {
      return res.status(409).json({ error: 'Team name already exists in this club' })
    }
    throw e
  }
})

app.put('/teams/:id', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(400).json({ error: 'Direction account must be attached to a club' })

  const parsed = teamUpsertPayloadSchema.safeParse(req.body)
  if (!parsed.success) {
    const message = parsed.error.issues[0]?.message || 'Invalid team payload'
    logTeamValidationFailure('PUT /teams/:id', message, {
      clubId: req.auth.clubId,
      teamId: req.params.id,
    })
    return res.status(400).json({ error: message })
  }

  const categoryResult = normalizeTeamCategory(parsed.data.category)
  if (!categoryResult.ok) {
    logTeamValidationFailure('PUT /teams/:id', categoryResult.error, {
      clubId: req.auth.clubId,
      teamId: req.params.id,
      category: parsed.data.category,
    })
    return res.status(400).json({ error: categoryResult.error })
  }

  const formatResult = normalizeTeamFormat(parsed.data.format)
  if (!formatResult.ok) {
    logTeamValidationFailure('PUT /teams/:id', formatResult.error, {
      clubId: req.auth.clubId,
      teamId: req.params.id,
      format: parsed.data.format,
    })
    return res.status(400).json({ error: formatResult.error })
  }

  const existingTeam = await prisma.team.findFirst({
    where: { id: req.params.id, clubId: req.auth.clubId },
    select: { id: true },
  })
  if (!existingTeam) return res.status(404).json({ error: 'Team not found' })

  const providedName = typeof parsed.data.name === 'string' ? parsed.data.name.trim() : ''
  const finalName = providedName || await generateAutoTeamName(req.auth.clubId, categoryResult.category, { excludeTeamId: existingTeam.id })

  try {
    const updated = await prisma.team.update({
      where: { id: existingTeam.id },
      data: {
        name: finalName,
        category: categoryResult.category,
        format: formatResult.format,
      },
      select: {
        id: true,
        name: true,
        category: true,
        format: true,
        clubId: true,
        createdAt: true,
      },
    })
    return res.json(normalizeTeamResponse(updated))
  } catch (e: any) {
    if (e?.code === 'P2002') {
      return res.status(409).json({ error: 'Team name already exists in this club' })
    }
    throw e
  }
})

app.delete('/teams/:id', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(400).json({ error: 'Direction account must be attached to a club' })

  const team = await prisma.team.findFirst({
    where: { id: req.params.id, clubId: req.auth.clubId },
    select: { id: true },
  })
  if (!team) return res.status(404).json({ error: 'Team not found' })

  try {
    await prisma.team.delete({ where: { id: team.id } })
    return res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2003' || e?.code === 'P2014') {
      return res.status(409).json({ error: 'Cannot delete team because it is still referenced by related data' })
    }
    throw e
  }
})

app.post('/accounts', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.status(400).json({ error: 'Direction account must be attached to a club' })

  const normalized = normalizeCoachPayload(req.body)
  const schema = z.object({
    role: z.enum(['COACH']),
    firstName: z.string().min(1, 'firstName is required').max(80),
    lastName: z.string().min(1, 'lastName is required').max(80),
    email: z.string().email('Invalid email format'),
    phone: z.string().min(3).max(32).nullable().optional(),
    teamId: z.string().min(1, 'teamId is required'),
    managedTeamIds: z.array(z.string().min(1)).optional(),
    expiresInDays: z.coerce.number().int().min(1).max(30).optional()
  })
  const parsed = schema.safeParse(normalized)
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0]
    return res.status(400).json({ error: firstIssue?.message || parsed.error.flatten() })
  }

  const email = normEmail(parsed.data.email)
  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) return res.status(409).json({ error: 'Email already in use' })

  const selectedTeam = await prisma.team.findFirst({
    where: {
      id: parsed.data.teamId,
      clubId: req.auth.clubId
    },
    select: { id: true, name: true }
  })
  if (!selectedTeam) return res.status(404).json({ error: 'Team not found in club' })

  const requestedManagedTeamIds = parsed.data.managedTeamIds || []
  const filteredManagedTeamIds = requestedManagedTeamIds.length
    ? await prisma.team.findMany({
      where: {
        id: { in: requestedManagedTeamIds },
        clubId: req.auth.clubId
      },
      select: { id: true }
    }).then((rows) => rows.map((row) => row.id))
    : []
  const managedTeamIds = Array.from(new Set([selectedTeam.id, ...filteredManagedTeamIds]))

  await prisma.accountInvite.updateMany({
    where: {
      clubId: req.auth.clubId,
      email,
      status: 'PENDING'
    },
    data: { status: 'CANCELLED' }
  })

  const inviteToken = nanoid(48)
  const expiresAt = addDays(new Date(), parsed.data.expiresInDays ?? 7)
  const created = await prisma.accountInvite.create({
    data: {
      email,
      firstName: parsed.data.firstName,
      lastName: parsed.data.lastName,
      phone: parsed.data.phone ?? null,
      token: inviteToken,
      role: 'COACH',
      clubId: req.auth.clubId,
      invitedByUserId: req.auth.id,
      teamId: selectedTeam.id,
      managedTeamIds,
      expiresAt
    },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      phone: true,
      token: true,
      role: true,
      clubId: true,
      teamId: true,
      managedTeamIds: true,
      linkedPlayerUserId: true,
      status: true,
      expiresAt: true,
      createdAt: true
    }
  })

  const acceptPath = process.env.INVITE_ACCEPT_PATH || '/invite/accept'
  const inviteUrl = `${APP_BASE_URL.replace(/\/+$/, '')}${acceptPath}?token=${encodeURIComponent(created.token)}`

  if (transporter) {
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || 'no-reply@example.com',
        to: created.email,
        subject: 'Invitation Izifoot',
        html: `<p>Vous avez ete invite sur Izifoot.</p>
<p>Pour finaliser votre compte et definir votre mot de passe, cliquez ici :</p>
<p><a href="${inviteUrl}">${inviteUrl}</a></p>
<p>Ce lien expire le ${created.expiresAt.toISOString()}.</p>`
      })
    } catch (e) {
      console.warn('[accounts invite] email failed:', e)
    }
  }

  res.status(201).json({ ...created, inviteUrl })
})

app.get('/accounts/invitations', authMiddleware, async (req: any, res) => {
  if (!ensureDirection(req, res)) return
  if (!req.auth?.clubId) return res.json([])

  await prisma.accountInvite.updateMany({
    where: {
      clubId: req.auth.clubId,
      status: 'PENDING',
      expiresAt: { lt: new Date() }
    },
    data: { status: 'EXPIRED' }
  })

  const invites = await prisma.accountInvite.findMany({
    where: { clubId: req.auth.clubId },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      phone: true,
      role: true,
      status: true,
      teamId: true,
      managedTeamIds: true,
      linkedPlayerUserId: true,
      expiresAt: true,
      acceptedAt: true,
      createdAt: true,
      user: {
        select: {
          id: true,
          email: true,
          createdAt: true
        }
      }
    },
    orderBy: { createdAt: 'desc' }
  })
  res.json(invites)
})

// Collect waitlist emails
app.post('/waitlist', async (req, res) => {
  try {
    const schema = z.object({ email: z.string().email(), source: z.string().optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    const email = normEmail(parsed.data.email);

    const now = Date.now();
    const last = waitlistSeen.get(email) || 0;
    if (now - last < WAITLIST_COOLDOWN_MS) {
      return res.status(202).json({ ok: true, message: 'Already registered recently' });
    }
    waitlistSeen.set(email, now);

    // If SMTP is configured, send a notification email; otherwise log to console.
    if (transporter) {
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM || 'no-reply@example.com',
          to: process.env.NOTIFY_EMAIL || process.env.WAITLIST_NOTIFY_TO || process.env.SMTP_FROM || 'no-reply@example.com',
          replyTo: email,
          subject: 'Nouveau contact – inscription email',
          text: `Adresse saisie: ${email}`,
          html: `<p><strong>Adresse saisie:</strong> ${email}</p>`
        });
      } catch (err) {
        console.error('Failed to send waitlist email', err);
        // Non-fatal; continue
      }
    } else {
      console.log('[waitlist] new signup (no SMTP configured):', { email });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.use(async (req: any, res: any, next: any) => {
  if (!isWriteMethod(req.method)) return next()

  const guardedPrefixes = [
    '/plannings',
    '/players',
    '/trainings',
    '/plateaus',
    '/attendance',
    '/matches',
    '/schedule',
    '/drills',
    '/training-drills',
    '/diagrams',
    '/tactics',
  ]
  const isGuarded = guardedPrefixes.some((prefix) => pathStartsWith(req.path, prefix))
  if (!isGuarded) return next()

  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) return next()

  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    const auth = await resolveUserAuthContext(payload.sub)
    if (!auth) return res.status(401).json({ error: 'Unauthorized' })
    if (isReadOnlyRole(auth)) {
      return res.status(403).json({ error: 'Read-only account: write access is not allowed' })
    }
    const allowsExplicitTeamOnPlayersCreate =
      req.method === 'POST' &&
      req.path === '/players' &&
      typeof req.body?.teamId === 'string' &&
      req.body.teamId.trim().length > 0
    if ((auth.role === 'DIRECTION' || auth.role === 'COACH') && !getActiveTeamIdForAuth(auth) && !allowsExplicitTeamOnPlayersCreate) {
      return res.status(400).json({ error: 'Select an active team before making changes' })
    }
  } catch {
    return res.status(401).json({ error: 'Invalid token' })
  }
  return next()
})

app.post('/plannings', authMiddleware, async (req: any, res) => {
  const schema = z.object({ date: z.string(), data: z.any() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { date, data } = parsed.data
  const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } })
  if (!user) return res.status(404).json({ error: 'User not found' })

  const isoDate = new Date(date)
  const planning = await prisma.planning.upsert({
    where: { userId_date: { userId: user.id, date: isoDate } },
    update: { data: JSON.stringify(data) },
    create: { userId: user.id, date: isoDate, data: JSON.stringify(data) },
  })
  res.json({ ...planning, data })
})

app.get('/plannings', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) {
    return res.json([])
  }
  return next()
}, authMiddleware, async (req: any, res) => {
  const plans = await prisma.planning.findMany({ where: { userId: req.userId }, orderBy: { date: 'asc' } })
  const mapped = plans.map((p) => ({ ...p, data: safeParseJSON(p.data) }))
  res.json(mapped)
})

app.get('/plannings/:id', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) {
    return res.status(404).json({ error: 'Not found' })
  }
  return next()
}, authMiddleware, async (req: any, res) => {
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  res.json({ ...p, data: safeParseJSON(p.data) })
})

app.put('/plannings/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({ data: z.any() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  const updated = await prisma.planning.update({ where: { id: p.id }, data: { data: JSON.stringify(parsed.data.data) } })
  res.json({ ...updated, data: parsed.data.data })
})

app.delete('/plannings/:id', authMiddleware, async (req: any, res) => {
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  await prisma.shareToken.deleteMany({ where: { planningId: p.id } })
  await prisma.planning.delete({ where: { id: p.id } })
  res.json({ ok: true })
})

// Sharing: create a share token (optional email)
app.post('/plannings/:id/share', authMiddleware, async (req: any, res) => {
  const schema = z.object({ expiresInDays: z.number().int().min(1).max(365).optional(), email: z.string().email().optional() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })

  const token = nanoid(24)
  const expiresAt = parsed.data.expiresInDays ? addDays(new Date(), parsed.data.expiresInDays) : null
  const share = await prisma.shareToken.create({ data: { planningId: p.id, token, expiresAt: expiresAt ?? undefined } })
  const url = `${API_BASE_URL}/s/${token}`

  if (parsed.data.email && transporter) {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'no-reply@example.com',
      to: parsed.data.email,
      subject: 'Partage de planning U9',
      text: `Consultez le planning : ${url}`,
      html: `<p>Consultez le planning :</p><p><a href="${url}">${url}</a></p>`
    })
  }

  res.json({ token, url, expiresAt })
})

// Public share endpoint
app.get('/s/:token', async (req, res) => {
  const s = await prisma.shareToken.findUnique({ where: { token: req.params.token }, include: { planning: true } })
  if (!s) return res.status(404).json({ error: 'Invalid link' })
  if (s.expiresAt && s.expiresAt < new Date()) return res.status(410).json({ error: 'Link expired' })
  res.json({ planning: { ...s.planning, data: safeParseJSON(s.planning.data) } })
})

// QR code PNG for sharing URL
app.get('/plannings/:id/qr', authMiddleware, async (req: any, res) => {
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  const existing = await prisma.shareToken.findFirst({ where: { planningId: p.id }, orderBy: { createdAt: 'asc' } })
  let token = existing?.token
  if (!token) {
    token = nanoid(24)
    await prisma.shareToken.create({ data: { planningId: p.id, token } })
  }
  const url = `${API_BASE_URL}/s/${token}`
  const png = await QRCode.toBuffer(url, { width: 512 })
  res.type('image/png').send(png)
})

// === FOOT DOMAIN API ===
// ---- Drills (exercises) ----

app.get('/drills', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const q = (req.query.q as string | undefined)?.toLowerCase().trim()
  const cat = (req.query.category as string | undefined)?.toLowerCase().trim()
  const tag = (req.query.tag as string | undefined)?.toLowerCase().trim()

  const catalog = await drillFindManyForUser(prisma, req.auth, { orderBy: { createdAt: 'asc' } })
  let items = catalog.slice()
  if (q) {
    items = items.filter(d =>
      d.title.toLowerCase().includes(q) ||
      d.description.toLowerCase().includes(q) ||
      d.tags.some((t: string) => t.toLowerCase().includes(q))
    )
  }
  if (cat) items = items.filter(d => d.category.toLowerCase() === cat)
  if (tag) items = items.filter(d => d.tags.map((t: string) => t.toLowerCase()).includes(tag))
  const renderedItems = items.map((d: any) => withDrillDescriptionHtml(d))
  const renderedCatalog = catalog.map((d: any) => withDrillDescriptionHtml(d))

  res.json({
    items: renderedItems,
    categories: Array.from(new Set(renderedCatalog.map(d => d.category))).sort(),
    tags: Array.from(new Set(renderedCatalog.flatMap(d => d.tags))).sort()
  })
})

app.get('/drills/:id', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const d = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!d) return res.status(404).json({ error: 'Not found' })
  res.json(withDrillDescriptionHtml(d))
})

app.put('/drills/:id', authMiddleware, async (req: any, res) => {
  const existing = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!existing) return res.status(404).json({ error: 'Not found' })

  const schema = z.object({
    title: z.string().min(1).max(100).optional(),
    category: z.string().min(1).max(50).optional(),
    duration: z.coerce.number().int().min(1).max(180).optional(),
    players: z.string().min(1).max(50).optional(),
    description: z.string().min(1).max(2000).optional(),
    tags: z.array(z.string().min(1).max(32)).max(20).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const patch: any = {}
  if (parsed.data.title !== undefined) patch.title = parsed.data.title
  if (parsed.data.category !== undefined) patch.category = parsed.data.category
  if (parsed.data.duration !== undefined) patch.duration = parsed.data.duration
  if (parsed.data.players !== undefined) patch.players = parsed.data.players
  if (parsed.data.description !== undefined) patch.description = parsed.data.description
  if (parsed.data.tags !== undefined) patch.tags = parsed.data.tags

  const updated = await prisma.drill.update({
    where: { id: existing.id },
    data: patch
  })
  res.json(withDrillDescriptionHtml(updated))
})

app.delete('/drills/:id', authMiddleware, async (req: any, res) => {
  const existing = await drillFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!existing) return res.status(404).json({ error: 'Not found' })

  const drillId = existing.id
  const rows = await trainingDrillFindManyForUser(prisma, req.auth, {
    where: { drillId },
    select: { id: true }
  })
  const trainingDrillIds = rows.map((row: any) => row.id)

  await prisma.$transaction([
    prisma.diagram.deleteMany({ where: applyScopeWhere(req.auth, { drillId }, { includeLegacyOwner: true }) }),
    prisma.diagram.deleteMany({ where: applyScopeWhere(req.auth, { trainingDrillId: { in: trainingDrillIds } }, { includeLegacyOwner: true }) }),
    prisma.trainingDrill.deleteMany({ where: applyScopeWhere(req.auth, { drillId }, { includeLegacyOwner: true }) }),
    prisma.drill.deleteMany({ where: applyScopeWhere(req.auth, { id: drillId }, { includeLegacyOwner: true }) }),
  ])

  res.json({ ok: true })
})

app.post('/drills', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({
    title: z.string().min(1).max(100),
    category: z.string().min(1).max(50),
    duration: z.coerce.number().int().min(1).max(180),
    players: z.string().min(1).max(50),
    description: z.string().min(1).max(2000),
    tags: z.array(z.string().min(1).max(32)).max(20).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }

  const id = await buildUniqueDrillId(prisma, req.auth, parsed.data.title)

  try {
    const drill = await drillCreateForUser(prisma, req.auth, {
      id,
      clubId: team.clubId,
      teamId: team.id,
      title: parsed.data.title,
      category: parsed.data.category,
      duration: parsed.data.duration,
      players: parsed.data.players,
      description: parsed.data.description,
      tags: (parsed.data.tags && parsed.data.tags.length) ? parsed.data.tags : []
    })
    res.status(201).json(withDrillDescriptionHtml(drill))
  } catch (e: any) {
    if (e?.code === 'DRILL_STORAGE_UNAVAILABLE') {
      return res.status(503).json({ error: 'Drill storage unavailable' })
    }
    throw e
  }
})
// Models used: Player, Training, Plateau, Attendance, Match, MatchTeam, MatchTeamPlayer, Scorer
// All endpoints are protected (same as plannings). Adjust if you want some public.

// ---- Players ----
app.get('/players', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const players = await playerFindManyForUser(prisma, req.auth, { orderBy: { name: 'asc' } })
  res.json(players)
})

app.post('/players', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({
    name: z.string().min(1),
    primary_position: z.string().min(1),
    secondary_position: z.string().optional(),
    teamId: z.string().min(1).optional(),
    email: z.string().email().optional(),
    phone: z.string().min(5).max(32).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  let team: any
  try {
    team = await resolveTeamForWrite(req.auth, parsed.data.teamId)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }
  const baseData: any = {
    clubId: team.clubId,
    teamId: team.id,
    name: parsed.data.name,
    primary_position: parsed.data.primary_position,
    secondary_position: parsed.data.secondary_position
  }
  if ('email' in parsed.data) baseData.email = parsed.data.email
  if ('phone' in parsed.data) baseData.phone = parsed.data.phone
  const p = await playerCreateForUser(prisma, req.auth, baseData)
  res.json(p)
})

app.put('/players/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    name: z.string().min(1).optional(),
    primary_position: z.string().optional(),
    secondary_position: z.string().nullable().optional(),
    email: z.string().email().nullable().optional(),
    phone: z.string().min(5).max(32).nullable().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { id } = req.params
  const existing = await playerFindFirstForUser(prisma, req.auth, { where: { id } })
  if (!existing) return res.status(404).json({ error: 'Player not found' })
  const patch: any = {}
  if (parsed.data.name !== undefined) patch.name = parsed.data.name
  if (parsed.data.primary_position !== undefined) patch.primary_position = parsed.data.primary_position
  if (parsed.data.secondary_position !== undefined) patch.secondary_position = parsed.data.secondary_position
  if ('email' in parsed.data) patch.email = parsed.data.email ?? null
  if ('phone' in parsed.data) patch.phone = parsed.data.phone ?? null
  const updated = await prisma.player.update({ where: { id: existing.id }, data: patch })
  res.json(updated)
})
// --- Player invite JWT and playerAuth ---
function signPlayerInvite(playerId: string, plateauId?: string | null, email?: string | null) {
  return jwt.sign({ aud: 'player_invite', pid: playerId, plid: plateauId || null, em: email || null }, JWT_SECRET, { expiresIn: '30d' })
}

function signRsvpToken(playerId: string, plateauId: string, status: 'present' | 'absent') {
  return jwt.sign({ aud: 'player_rsvp', pid: playerId, plid: plateauId, st: status }, JWT_SECRET, { expiresIn: '60d' })
}
async function playerAuth(req: any, res: any, next: any) {
  const token = req.cookies?.player_token || (req.headers['x-player-token'] as string | undefined)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    if (payload?.aud !== 'player_invite' || !payload?.pid) return res.status(401).json({ error: 'Invalid token' })
    const player = await playerFindByIdCompat(prisma, payload.pid)
    if (!player) return res.status(401).json({ error: 'Invalid token' })
    req.playerId = payload.pid
    req.playerUserId = player.userId
    req.scopePlateauId = payload.plid || null
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// --- Player invite endpoint ---
app.post('/players/:id/invite', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  const schema = z.object({ plateauId: z.string().optional(), email: z.string().email().optional() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const player = await playerFindFirstForUser(prisma, req.auth, { where: { id } })
  if (!player) return res.status(404).json({ error: 'Player not found' })
  const base = `${req.protocol}://${req.get('host')}`
  const inviteEmail = parsed.data.email || (player as any).email || null
  if (!parsed.data.plateauId) {
    return res.status(400).json({ error: 'plateauId is required to generate RSVP links' })
  }
  const presentToken = signRsvpToken(id, parsed.data.plateauId, 'present')
  const absentToken = signRsvpToken(id, parsed.data.plateauId, 'absent')
  const presentUrl = `${base}/rsvp/p?token=${encodeURIComponent(presentToken)}`
  const absentUrl = `${base}/rsvp/a?token=${encodeURIComponent(absentToken)}`

  // Mark player as convoked for this plateau
  try {
    await attendanceUpsertMarkerForUser(prisma, req.auth, {
      session_type: 'PLATEAU_CONVOKE',
      session_id: parsed.data.plateauId,
      playerId: id,
    })
  } catch (e) {
    console.warn('[invite] failed to upsert convocation marker', e)
  }

  // Try email if requested and SMTP is configured
  if (inviteEmail && transporter) {
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || 'no-reply@example.com',
        to: inviteEmail,
        subject: 'Confirmation de présence – Izifoot',
        html: `<p>Bonjour${player.name ? ' ' + player.name : ''},</p>
<p>Merci d'indiquer votre présence pour le plateau.</p>
<p><a href="${presentUrl}">Je serai présent</a> &nbsp;|&nbsp; <a href="${absentUrl}">Je serai absent</a></p>
<p>(Ces liens sont valables 60 jours)</p>`
      })
    } catch (e) {
      console.warn('[invite] email failed:', e)
    }
  }
  res.json({ ok: true, presentUrl, absentUrl })
})

// --- Public endpoint to accept invite and set player_token cookie ---
app.get('/player/accept', async (req: any, res) => {
  const token = req.query.token as string | undefined
  if (!token) return res.status(400).json({ error: 'Missing token' })
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    if (payload?.aud !== 'player_invite' || !payload?.pid) return res.status(400).json({ error: 'Invalid token' })
    res.cookie('player_token', token, playerCookieOpts())
    const r = (req.query.r as string | undefined)
    const redirectTo = (r && r.startsWith(APP_BASE_URL)) ? r : undefined
    res.json({ ok: true, redirectTo })
  } catch {
    return res.status(400).json({ error: 'Invalid token' })
  }
})

app.get('/player/login', async (req: any, res) => {
  const token = req.query.token as string | undefined
  const r = (req.query.r as string | undefined) || ''
  let redirectTo = process.env.PLAYER_PORTAL_REDIRECT || APP_BASE_URL
  // If a custom redirect is provided and starts with APP_BASE_URL, use it
  if (r && r.startsWith(APP_BASE_URL)) redirectTo = r
  if (!token) return res.redirect(302, redirectTo)
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    if (payload?.aud !== 'player_invite' || !payload?.pid) return res.redirect(302, redirectTo)
    res.cookie('player_token', token, playerCookieOpts())
    // If token is scoped to a plateau, send the user straight to that MatchDay
    if (payload?.plid) {
      const dest = `${APP_BASE_URL}/match-day/${payload.plid}`
      return res.redirect(302, dest)
    }
    return res.redirect(302, redirectTo)
  } catch {
    return res.redirect(302, redirectTo)
  }
})

// --- RSVP endpoints ---
app.get('/rsvp/p', async (req: any, res) => {
  const token = req.query.token as string | undefined
  const redirectBase = APP_BASE_URL
  if (!token) return res.redirect(302, redirectBase)
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    if (payload?.aud !== 'player_rsvp' || payload?.st !== 'present' || !payload?.pid || !payload?.plid) {
      return res.redirect(302, redirectBase)
    }
    const player = await playerFindByIdCompat(prisma, payload.pid)
    if (!player?.userId) return res.redirect(302, redirectBase)
    try {
      await attendanceSetPlateauRsvpForUser(prisma, player.userId, payload.plid, payload.pid, true)
    } catch (e) {
      // Ignore, always redirect anyway
    }
    return res.redirect(302, `${redirectBase}/match-day/${payload.plid}?rsvp=present`)
  } catch {
    return res.redirect(302, redirectBase)
  }
})

app.get('/rsvp/a', async (req: any, res) => {
  const token = req.query.token as string | undefined
  const redirectBase = APP_BASE_URL
  if (!token) return res.redirect(302, redirectBase)
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    if (payload?.aud !== 'player_rsvp' || payload?.st !== 'absent' || !payload?.pid || !payload?.plid) {
      return res.redirect(302, redirectBase)
    }
    const player = await playerFindByIdCompat(prisma, payload.pid)
    if (!player?.userId) return res.redirect(302, redirectBase)
    try {
      await attendanceSetPlateauRsvpForUser(prisma, player.userId, payload.plid, payload.pid, false)
    } catch (e) {
      console.warn('[RSVP absent] failed', e)
    }
    return res.redirect(302, `${redirectBase}/match-day/${payload.plid}?rsvp=absent`)
  } catch {
    return res.redirect(302, redirectBase)
  }
})

// --- Debug route for cookie visibility ---
app.get('/player/debug', (req: any, res) => {
  res.json({ hasCookie: Boolean(req.cookies?.player_token), cookies: Object.keys(req.cookies || {}) })
})
// --- Scoped player endpoints ---
app.get('/player/me', playerAuth, async (req: any, res) => {
  const p = await playerFindFirstForUser(prisma, req.playerUserId, { where: { id: req.playerId } })
  if (!p) return res.status(404).json({ error: 'Player not found' })
  res.json({ id: p.id, name: (p as any).name || '', email: (p as any).email || null, phone: (p as any).phone || null })
})

app.get('/player/plateaus', playerAuth, async (req: any, res) => {
  const playerId = req.playerId as string
  // Plateaus via attendance
  const att = await attendanceFindManyForUser(prisma, req.playerUserId, {
    where: { session_type: 'PLATEAU', playerId },
    select: { session_id: true }
  })
  const plateauIdsFromAttendance = Array.from(new Set(att.map(a => a.session_id)))

  // Plateaus via match participation
  const mtps = await prisma.matchTeamPlayer.findMany({ where: { playerId }, select: { matchTeamId: true } })
  const teamIds = mtps.map(m => m.matchTeamId)
  let plateauIdsFromMatches: string[] = []
  if (teamIds.length) {
    const teams = await prisma.matchTeam.findMany({ where: { id: { in: teamIds } }, select: { matchId: true } })
    const matchIds = teams.map(t => t.matchId)
    if (matchIds.length) {
      const matches = await matchFindManyForUser(prisma, req.playerUserId, { where: { id: { in: matchIds } }, select: { plateauId: true } })
      plateauIdsFromMatches = matches.map(m => m.plateauId!).filter(Boolean) as string[]
    }
  }

  const set = new Set<string>([...plateauIdsFromAttendance, ...plateauIdsFromMatches])
  const ids = Array.from(set)
  if (!ids.length) return res.json([])
  const plateaus = await plateauFindManyForUser(prisma, req.playerUserId, { where: { id: { in: ids } }, orderBy: { date: 'desc' } })
  res.json(plateaus)
})

app.get('/player/plateaus/:id/summary', playerAuth, async (req: any, res) => {
  const plateauId = req.params.id
  // If token is scoped to a specific plateau, enforce it
  if (req.scopePlateauId && req.scopePlateauId !== plateauId) return res.status(403).json({ error: 'Forbidden' })

  // Reuse the same build as /plateaus/:id/summary
  const ctxRes: any = {}
  const fakeReq: any = { params: { id: plateauId }, userId: req.playerUserId }
  const fakeRes: any = {
    statusCode: 200,
    _json: null,
    status(c: number) { this.statusCode = c; return this },
    json(v: any) { this._json = v; return this }
  }
  await (app as any)._router.handle({ ...fakeReq, method: 'GET', url: `/plateaus/${plateauId}/summary` }, fakeRes, () => { })
  const summary = fakeRes._json
  if (!summary || fakeRes.statusCode !== 200) return res.status(fakeRes.statusCode || 500).json(summary || { error: 'Failed' })

  // Check convocation: present in attendance OR in any team players
  const isConvocated = Boolean(
    (summary.convocations || []).some((c: any) => c.player?.id === req.playerId) ||
    (summary.matches || []).some((m: any) => (m.teams || []).some((t: any) => (t.players || []).some((p: any) => p.playerId === req.playerId)))
  )
  if (!isConvocated) return res.status(403).json({ error: 'Not convocated for this plateau' })

  // Optionally, we could filter convocations to only the player
  const filtered = { ...summary, convocations: (summary.convocations || []).filter((c: any) => c.player?.id === req.playerId) }
  res.json(filtered)
})

app.delete('/players/:id', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    // Ensure the player exists first
    const exists = await playerFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!exists) return res.status(404).json({ error: 'Player not found' })

    await prisma.$transaction(async (tx) => {
      await tx.scorer.deleteMany({ where: { playerId: id } })
      await tx.matchTeamPlayer.deleteMany({ where: { playerId: id } })
      await attendanceDeleteManyForUser(tx, req.auth, { playerId: id })
      await tx.player.delete({ where: { id: exists.id } })
    })
    res.json({ ok: true })
  } catch (e: any) {
    console.error('[DELETE /players/:id] failed', e)
    // If it still fails due to referential integrity, surface 409
    return res.status(409).json({ error: 'Cannot delete player due to related data' })
  }
})

// ---- Trainings ----
app.get('/trainings', authMiddleware, async (req: any, res) => {
  const trainings = await trainingFindManyForUser(prisma, req.auth, { orderBy: { date: 'desc' } })
  res.json(trainings)
})

// Get single training
app.get('/trainings/:id', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!training) return res.status(404).json({ error: 'Training not found' })
    res.json(training)
  } catch (e: any) {
    console.error('[GET /trainings/:id] failed', e)
    return res.status(500).json({ error: 'Failed to fetch training' })
  }
})


app.post('/trainings', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({ date: z.string().or(z.date()) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }
  const date = new Date(parsed.data.date as any)
  const t = await trainingCreateForUser(prisma, req.auth, {
    date,
    status: 'PLANNED',
    clubId: team.clubId,
    teamId: team.id
  })
  res.json(t)
})

// Update a training (date/status)
app.put('/trainings/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    date: z.string().or(z.date()).optional(),
    status: z.enum(['PLANNED', 'CANCELLED']).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const data: any = {}
  if (parsed.data.date !== undefined) data.date = new Date(parsed.data.date as any)
  if (parsed.data.status !== undefined) data.status = parsed.data.status

  try {
    const existing = await trainingFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
    if (!existing) return res.status(404).json({ error: 'Training not found' })
    const updated = await trainingUpdateCompat(prisma, existing.id, data)
    res.json(updated)
  } catch (e: any) {
    if (e?.code === 'P2025') {
      return res.status(404).json({ error: 'Training not found' })
    }
    console.error('[PUT /trainings/:id] update failed', e)
    return res.status(500).json({ error: 'Failed to update training' })
  }
})

// Delete a training (and clean related attendance + drills)
app.delete('/trainings/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    const existing = await trainingFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!existing) return res.status(404).json({ error: 'Training not found' })
    await prisma.$transaction(async (tx) => {
      await attendanceDeleteManyForUser(tx, req.auth, { session_type: 'TRAINING', session_id: id })
      await tx.trainingDrill.deleteMany({ where: applyScopeWhere(req.auth, { trainingId: id }, { includeLegacyOwner: true }) })
      await tx.training.delete({ where: { id: existing.id } })
    })
    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') {
      return res.status(404).json({ error: 'Training not found' })
    }
    console.error('[DELETE /trainings/:id] delete failed', e)
    return res.status(500).json({ error: 'Failed to delete training' })
  }
})

app.get('/trainings/:id/roles', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const trainingId = req.params.id
  try {
    const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } })
    if (!training) return res.status(404).json({ error: 'Training not found' })

    const rows = await trainingRoleAssignmentFindManyForUser(prisma, req.auth, {
      where: { trainingId },
      include: { player: { select: { id: true, name: true } } },
      orderBy: [{ role: 'asc' }, { id: 'asc' }],
    })
    return res.json({ items: rows.map(toTrainingRoleAssignmentResponseItem) })
  } catch (e) {
    if ((e as any)?.code === 'TRAINING_ROLE_STORAGE_UNAVAILABLE') {
      return res.status(503).json({ error: 'Training role storage unavailable' })
    }
    console.error('[GET /trainings/:id/roles] failed', {
      trainingId,
      error: e,
    })
    return res.status(500).json({ error: 'Failed to fetch training roles' })
  }
})

app.put('/trainings/:id/roles', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const trainingId = req.params.id

  const parsed = trainingRolesPutBodySchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() })
  }

  const items = normalizeTrainingRoleItems(parsed.data.items)
  try {
    validateNoDuplicatePlayers(items)
  } catch (e: any) {
    return res.status(400).json({ error: e?.message || 'Invalid role assignments payload' })
  }

  try {
    const training = await trainingFindFirstForUser(prisma, req.auth, {
      where: { id: trainingId },
      select: { id: true, clubId: true, teamId: true },
    })
    if (!training) return res.status(404).json({ error: 'Training not found' })

    const playerIds = Array.from(new Set(items.map((item) => item.playerId)))
    if (playerIds.length > 0) {
      const players = await playerFindManyForUser(prisma, req.auth, {
        where: {
          id: { in: playerIds },
          teamId: training.teamId,
        },
        select: { id: true },
      })
      if (players.length !== playerIds.length) {
        return res.status(400).json({ error: 'One or more players do not belong to the training team' })
      }
    }

    const savedRows = await prisma.$transaction(async (tx) => {
      await tx.trainingRoleAssignment.deleteMany({
        where: applyScopeWhere(req.auth, { trainingId }, { includeLegacyOwner: true }),
      })

      if (items.length > 0) {
        await tx.trainingRoleAssignment.createMany({
          data: items.map((item) => ({
            userId: req.auth?.id ?? null,
            clubId: training.clubId ?? null,
            teamId: training.teamId ?? null,
            trainingId,
            role: item.role,
            playerId: item.playerId,
          })),
        })
      }

      return trainingRoleAssignmentFindManyForUser(tx, req.auth, {
        where: { trainingId },
        include: { player: { select: { id: true, name: true } } },
        orderBy: [{ role: 'asc' }, { id: 'asc' }],
      })
    })

    return res.json({ items: savedRows.map(toTrainingRoleAssignmentResponseItem) })
  } catch (e: any) {
    if (e?.code === 'P2021' || e?.code === 'TRAINING_ROLE_STORAGE_UNAVAILABLE') {
      return res.status(503).json({ error: 'Training role storage unavailable' })
    }
    if (e?.code === 'P2002') {
      return res.status(409).json({ error: 'Role assignments conflict with uniqueness constraints' })
    }
    if (e?.code === 'P2003') {
      return res.status(409).json({ error: 'Invalid player reference in role assignments' })
    }
    console.error('[PUT /trainings/:id/roles] failed', {
      trainingId,
      body: req.body,
      error: e,
    })
    return res.status(500).json({ error: 'Failed to save training roles' })
  }
})

// ---- Plateaus ----
app.get('/plateaus', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) return res.json([])
  return next()
}, authMiddleware, async (req: any, res) => {
  const plateaus = await plateauFindManyForUser(prisma, req.auth, { orderBy: { date: 'desc' } })
  res.json(plateaus)
})


app.post('/plateaus', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({
    date: z.string().or(z.date()),
    lieu: z.string().min(1),
  }).merge(plateauMetadataSchema)
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }
  const date = new Date(parsed.data.date as any)
  const pl = await plateauCreateForUser(prisma, req.auth, {
    date,
    lieu: parsed.data.lieu,
    ...buildPlateauMetadataPatch(parsed.data),
    clubId: team.clubId,
    teamId: team.id
  })
  res.json(pl)
})

app.put('/plateaus/:id', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const parsed = plateauMetadataSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const data = buildPlateauMetadataPatch(parsed.data)
  if (Object.keys(data).length === 0) {
    return res.status(400).json({ error: 'No updatable fields provided' })
  }

  try {
    const existing = await plateauFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
    if (!existing) return res.status(404).json({ error: 'Plateau not found' })
    const updated = await prisma.plateau.update({ where: { id: existing.id }, data })
    res.json(updated)
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Plateau not found' })
    console.error('[PUT /plateaus/:id] update failed', e)
    return res.status(500).json({ error: 'Failed to update plateau' })
  }
})

app.post('/plateaus/:id/share', authMiddleware, async (req: any, res) => {
  const schema = z.object({ expiresInDays: z.number().int().min(1).max(365).optional() })
  const parsed = schema.safeParse(req.body ?? {})
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const plateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!plateau) return res.status(404).json({ error: 'Plateau not found' })

  const existing = await prisma.plateauShareToken.findFirst({
    where: { plateauId: plateau.id },
    orderBy: { createdAt: 'desc' }
  })

  let token = existing?.token || randomUUID()
  let expiresAt: Date | null = existing?.expiresAt ?? null

  if (parsed.data.expiresInDays) {
    expiresAt = addDays(new Date(), parsed.data.expiresInDays)
  } else if (existing?.expiresAt && existing.expiresAt < new Date()) {
    // Re-enable an expired link while keeping the same URL.
    expiresAt = null
  }

  if (existing) {
    await prisma.plateauShareToken.update({
      where: { id: existing.id },
      data: { expiresAt: expiresAt ?? null }
    })
  } else {
    await prisma.plateauShareToken.create({
      data: {
        plateauId: plateau.id,
        token,
        expiresAt: expiresAt ?? undefined
      }
    })
  }

  const url = `${APP_BASE_URL.replace(/\/+$/, '')}/plateau/public/${token}`
  res.json({ token, url, expiresAt })
})

app.delete('/plateaus/:id/share', authMiddleware, async (req: any, res) => {
  const plateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!plateau) return res.status(404).json({ error: 'Plateau not found' })
  await prisma.plateauShareToken.deleteMany({ where: { plateauId: plateau.id } })
  res.json({ ok: true })
})

app.get('/public/plateaus/:token', async (req, res) => {
  const result = await getPublicPlateauPayloadByToken(req.params.token)
  return res.status(result.status).json(result.body)
})

app.delete('/plateaus/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    // Ensure plateau exists
    const exists = await plateauFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!exists) return res.status(404).json({ error: 'Plateau not found' })

    // Collect related matches and teams
    const matches = await matchFindManyForUser(prisma, req.auth, { where: { plateauId: id }, include: { teams: true } })
    const matchIds = matches.map((m: any) => m.id)
    const teamIds = matches.flatMap((m: any) => m.teams.map((t: any) => t.id))

    await prisma.$transaction(async (tx) => {
      await tx.scorer.deleteMany({ where: { matchId: { in: matchIds } } })
      await tx.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } })
      await tx.matchTeam.deleteMany({ where: { matchId: { in: matchIds } } })
      await tx.match.deleteMany({ where: { id: { in: matchIds } } })
      await attendanceDeleteManyForUser(tx, req.auth, {
        session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] as any },
        session_id: id
      })
      await tx.plateau.delete({ where: { id: exists.id } })
    })

    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Plateau not found' })
    console.error('[DELETE /plateaus/:id] failed', e)
    return res.status(500).json({ error: 'Failed to delete plateau' })
  }
})

// Get a single plateau by id
app.get('/plateaus/:id', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (token) return next()
  const result = await getPublicPlateauPayloadByToken(req.params.id)
  if (result.status !== 200) return res.status(result.status).json(result.body)
  return res.json(result.body.plateau)
})

app.get('/plateaus/:id', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    const plateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!plateau) return res.status(404).json({ error: 'Plateau not found' })
    res.json(plateau)
  } catch (e) {
    console.error('[GET /plateaus/:id] failed', e)
    return res.status(500).json({ error: 'Failed to fetch plateau' })
  }
})

// Aggregated view for a match day (plateau)
app.get('/plateaus/:id/summary', async (req: any, res, next) => {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (token) return next()
  const result = await getPublicPlateauPayloadByToken(req.params.id)
  return res.status(result.status).json(result.body)
})

app.get('/plateaus/:id/summary', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    const plateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!plateau) return res.status(404).json({ error: 'Plateau not found' })

    // Attendance (present/absent records) for this plateau, include player info
    const attendance = await attendanceFindManyForUser(prisma, req.auth, {
      where: {
        session_id: id,
        session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] as any },
      },
      include: { player: true }
    })
    // Build attendancePlayers and playersById from attendance
    const attendancePlayers = attendance.map(a => a.player).filter(Boolean) as any[]
    const playersById: Record<string, { id: string; name: string; primary_position: string | null; secondary_position: string | null; email?: string | null; phone?: string | null }> = {}
    for (const pl of attendancePlayers) {
      playersById[pl.id] = {
        id: pl.id,
        name: pl.name,
        primary_position: pl.primary_position ?? null,
        secondary_position: pl.secondary_position ?? null,
        email: (pl as any).email ?? null,
        phone: (pl as any).phone ?? null
      }
    }

    // Matches for this plateau (with teams and scorers first)
    const matchesRaw = await matchFindManyForUser(prisma, req.auth, {
      where: { plateauId: id },
      include: {
        teams: true,
        scorers: true
      },
      orderBy: { createdAt: 'asc' }
    })

    // Fetch all team players in one query and attach player objects
    const allTeamIds = matchesRaw.flatMap((m: any) => m.teams.map((t: any) => t.id))
    const mtPlayers = allTeamIds.length ? await prisma.matchTeamPlayer.findMany({
      where: { matchTeamId: { in: allTeamIds } },
      include: { player: true }
    }) : []
    const byTeam: Record<string, typeof mtPlayers> = {}
    for (const row of mtPlayers) {
      if (!byTeam[row.matchTeamId]) byTeam[row.matchTeamId] = []
      byTeam[row.matchTeamId].push(row)
    }

    // Build enriched matches with teams[].players including player info
    const matches = matchesRaw.map((m: any) => ({
      ...m,
      teams: m.teams.map((t: any) => ({
        ...t,
        players: (byTeam[t.id] || []).map(p => ({
          playerId: p.playerId,
          role: p.role,
          player: p.player
        }))
      }))
    }))

    // Hydrate playersById from match teams and build convocations
    const convocatedMap: Record<string, { id: string; name: string; primary_position: string | null; secondary_position: string | null; email?: string | null; phone?: string | null }> = {}
    for (const m of matches) {
      for (const t of m.teams) {
        for (const p of t.players) {
          const pl = p.player as any
          if (pl) {
            playersById[pl.id] = playersById[pl.id] || {
              id: pl.id,
              name: pl.name,
              primary_position: pl.primary_position ?? null,
              secondary_position: pl.secondary_position ?? null,
              email: (pl as any).email ?? null,
              phone: (pl as any).phone ?? null
            }
            if (!convocatedMap[pl.id]) convocatedMap[pl.id] = playersById[pl.id]
          }
        }
      }
    }
    for (const pl of attendancePlayers) {
      if (!convocatedMap[pl.id]) convocatedMap[pl.id] = playersById[pl.id]
    }
    // Ensure we know all players (for listing). We do not auto-mark as convoked.
    try {
      const allPlayers = await playerFindManyForUser(prisma, req.auth, { orderBy: { name: 'asc' } })
      for (const pl of allPlayers) {
        if (!playersById[pl.id]) {
          playersById[pl.id] = {
            id: pl.id,
            name: (pl as any).name,
            primary_position: (pl as any).primary_position ?? null,
            secondary_position: (pl as any).secondary_position ?? null,
            email: (pl as any).email ?? null,
            phone: (pl as any).phone ?? null,
          } as any
        }
      }
    } catch (e) {
      // If fetching all players fails for any reason, proceed with partial list
      console.warn('[summary] failed to include full players list', (e as any)?.message || e)
    }

    // Mark presence/absence and convocation using attendance
    const attendanceMap = new Map<string, boolean | null>()
    const convokeSet = new Set<string>()
    for (const a of attendance as any[]) {
      if (a.session_type === 'PLATEAU_CONVOKE') { convokeSet.add(a.playerId); continue }
      if (a.present === true) { attendanceMap.set(a.playerId, true); continue }
      if (a.present === false) { attendanceMap.set(a.playerId, false); continue }
      // No `present` field: use session_type marker if available
      if (a.session_type === 'PLATEAU_ABSENT') { attendanceMap.set(a.playerId, false); continue }
      // Old schema "present" implied by existence of PLATEAU row
      if (a.session_type === 'PLATEAU') { attendanceMap.set(a.playerId, true); continue }
    }

    // Build convocations list for ALL players known in playersById
    const convocations = Object.values(playersById).map(pl => {
      const att = attendanceMap.get(pl.id)
      let status: 'present' | 'absent' | 'convoque' | 'non_convoque'
      if (att === true) status = 'present'
      else if (att === false) status = 'absent'
      else if (convokeSet.has(pl.id)) status = 'convoque'
      else status = 'non_convoque'
      return { player: pl, status, present: status === 'present' }
    })

    // Add scorersDetailed to each match, resolving playerName from playersById
    const matchesEnriched = matches.map(m => ({
      ...m,
      scorersDetailed: m.scorers.map((s: any) => ({
        ...s,
        playerName: playersById[s.playerId]?.name || null,
        assistName: s.assistId ? (playersById[s.assistId]?.name || null) : null
      }))
    }))

    res.json({ plateau, convocations, matches: matchesEnriched, playersById })
  } catch (e) {
    console.error('[GET /plateaus/:id/summary] failed', e)
    return res.status(500).json({ error: 'Failed to fetch plateau summary' })
  }
})

// ---- Attendance (TRAINING / PLATEAU) ----
app.get('/attendance', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    session_type: z.enum(['TRAINING', 'PLATEAU']).optional(),
    session_id: z.string().optional()
  })
  const parsed = schema.safeParse(req.query)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { session_type, session_id } = parsed.data
  let scopeAuth = req.auth
  if (session_type && session_id) {
    const resolved = await resolveAttendanceScopeFromSession(req.auth, session_type, session_id)
    if (!resolved) return res.status(404).json({ error: `${session_type === 'TRAINING' ? 'Training' : 'Plateau'} not found` })
    scopeAuth = resolved
  }
  const where: any = {}
  if (session_type) where.session_type = { in: attendanceSessionTypeVariants(session_type) } as any
  else where.session_type = { in: ['TRAINING', 'TRAINING_ABSENT', 'PLATEAU', 'PLATEAU_ABSENT'] } as any
  if (session_id) where.session_id = session_id
  const rows = await attendanceFindManyForUser(prisma, scopeAuth, { where })
  res.json(rows.map(normalizeAttendanceRow))
})
app.post('/attendance', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    session_type: z.enum(['TRAINING', 'PLATEAU']),
    session_id: z.string(),
    playerId: z.string(),
    // Some clients omit `present` when unchecking; treat missing as absent.
    present: z.boolean().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { session_type, session_id, playerId } = parsed.data
  const present = parsed.data.present ?? false
  const scopeAuth = await resolveAttendanceScopeFromSession(req.auth, session_type, session_id)
  if (!scopeAuth) return res.status(404).json({ error: `${session_type === 'TRAINING' ? 'Training' : 'Plateau'} not found` })
  await attendanceSetPresenceForUser(prisma, scopeAuth, { session_type, session_id, playerId, present })
  res.json({ ok: true })
})

// ---- Matches ----
function rowsForMatchTeam(matchTeamId: string, ids: string[], role: 'starter' | 'sub') {
  return ids.map((playerId) => ({ matchTeamId, playerId, role }))
}

function normalizeMatchState<T extends { score?: { home: number; away: number }; buteurs?: Array<{ playerId: string; side: 'home' | 'away'; assistId?: string | null }>; played?: boolean }>(
  payload: T,
  fallbackPlayed = false
) {
  const played = payload.played ?? fallbackPlayed
  return {
    played,
    score: played ? (payload.score ?? { home: 0, away: 0 }) : { home: 0, away: 0 },
    buteurs: played ? (payload.buteurs ?? []) : []
  }
}

const matchScorerPayloadSchema = z.object({
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

function toMatchEventResponse(row: any) {
  return {
    id: row.id,
    matchId: row.matchId,
    minute: row.minute,
    type: row.type,
    scorerId: row.scorerId ?? null,
    assistId: row.assistId ?? null,
    slotId: row.slotId ?? null,
    inPlayerId: row.inPlayerId ?? null,
    outPlayerId: row.outPlayerId ?? null,
    createdAt: row.createdAt,
  }
}

async function listMatchEventsByMatchId(db: any, matchId: string) {
  try {
    const rows = await db.matchEvent.findMany({
      where: { matchId },
      orderBy: [{ minute: 'asc' }, { createdAt: 'asc' }],
    })
    return rows.map(toMatchEventResponse)
  } catch (e: any) {
    if (e?.code === 'P2021') return []
    throw e
  }
}

async function listMatchEventsForUser(db: any, scopeOrUserId: any, matchId: string) {
  const match = await matchFindFirstForUser(db, scopeOrUserId, {
    where: { id: matchId },
    select: { id: true },
  })
  if (!match) return null
  return listMatchEventsByMatchId(db, matchId)
}

async function assertEventPlayerIdsInMatchScope(db: any, scopeOrUserId: any, matchId: string, playerIds: string[]) {
  const uniqueIds = Array.from(new Set(playerIds.filter(Boolean)))
  if (!uniqueIds.length) return

  const matchTeams = await db.matchTeam.findMany({
    where: { matchId },
    select: { id: true },
  })
  const matchTeamIds = matchTeams.map((row: any) => row.id)
  const rows = matchTeamIds.length
    ? await db.matchTeamPlayer.findMany({
      where: {
        matchTeamId: { in: matchTeamIds },
        playerId: { in: uniqueIds },
      },
      select: { playerId: true },
    })
    : []

  const foundIds = new Set(rows.map((row: any) => row.playerId))
  const missingInMatchTeams = uniqueIds.filter((id) => !foundIds.has(id))

  if (!missingInMatchTeams.length) return

  for (const playerId of missingInMatchTeams) {
    const player = await playerFindFirstForUser(db, scopeOrUserId, {
      where: { id: playerId },
      select: { id: true },
    })
    if (!player) {
      const err: any = new Error(`Player ${playerId} is outside match scope`)
      err.code = 'PLAYER_SCOPE_FORBIDDEN'
      throw err
    }
  }
}

async function assertPlayerIdsInMatchTeams(db: any, matchId: string, playerIds: string[]) {
  const uniqueIds = Array.from(new Set(playerIds.filter(Boolean)))
  if (!uniqueIds.length) return

  const matchTeams = await db.matchTeam.findMany({
    where: { matchId },
    select: { id: true },
  })
  const matchTeamIds = matchTeams.map((row: any) => row.id)
  const rows = matchTeamIds.length
    ? await db.matchTeamPlayer.findMany({
      where: {
        matchTeamId: { in: matchTeamIds },
        playerId: { in: uniqueIds },
      },
      select: { playerId: true },
    })
    : []

  const foundIds = new Set(rows.map((row: any) => row.playerId))
  const missing = uniqueIds.filter((id) => !foundIds.has(id))
  if (!missing.length) return

  const err: any = new Error(`Players not in match teams: ${missing.join(', ')}`)
  err.code = 'PLAYER_NOT_IN_MATCH_TEAMS'
  throw err
}

async function getMatchDetailForUser(db: any, scopeOrUserId: any, id: string) {
  const match = await matchFindFirstForUser(db, scopeOrUserId, {
    where: { id },
    include: { teams: true, scorers: true }
  })
  if (!match) return null

  let eligiblePlayerIds: Set<string> | null = null
  if (match.plateauId) {
    const attendanceRows = await attendanceFindManyForUser(db, scopeOrUserId, {
      where: {
        session_id: match.plateauId,
        session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] as any },
      },
      select: {
        playerId: true,
        session_type: true,
      },
    })
    eligiblePlayerIds = buildEligiblePlayerIdsFromPlateauAttendance(attendanceRows)
  }

  const teamIds = (match.teams || []).map((t: any) => t.id)
  const teamPlayers = teamIds.length ? await db.matchTeamPlayer.findMany({
    where: { matchTeamId: { in: teamIds } },
    include: { player: true }
  }) : []

  const byTeam: Record<string, any[]> = {}
  for (const row of teamPlayers) {
    if (!byTeam[row.matchTeamId]) byTeam[row.matchTeamId] = []
    byTeam[row.matchTeamId].push(row)
  }

  const allPlayersById: Record<string, { id: string; name: string; primary_position: string | null; secondary_position: string | null }> = {}
  for (const row of teamPlayers) {
    const pl = row.player
    if (!pl) continue
    allPlayersById[pl.id] = allPlayersById[pl.id] || {
      id: pl.id,
      name: pl.name,
      primary_position: pl.primary_position ?? null,
      secondary_position: pl.secondary_position ?? null
    }
  }

  const playersById: Record<string, { id: string; name: string; primary_position: string | null; secondary_position: string | null }> = {}
  const teams = (match.teams || []).map((team: any) => ({
    id: team.id,
    side: team.side,
    score: team.score,
    players: (byTeam[team.id] || []).filter((row: any) => {
      return !eligiblePlayerIds || eligiblePlayerIds.has(row.playerId)
    }).map((row: any) => {
      const pl = row.player
      if (pl) {
        playersById[pl.id] = playersById[pl.id] || {
          id: pl.id,
          name: pl.name,
          primary_position: pl.primary_position ?? null,
          secondary_position: pl.secondary_position ?? null
        }
      }
      return {
        playerId: row.playerId,
        role: row.role,
        player: pl ? allPlayersById[pl.id] : null
      }
    })
  }))

  const scorers = (match.scorers || []).map((s: any) => ({
    id: s.id,
    playerId: s.playerId,
    side: s.side,
    assistId: s.assistId ?? null,
    playerName: allPlayersById[s.playerId]?.name || playersById[s.playerId]?.name || null,
    assistName: s.assistId ? (allPlayersById[s.assistId]?.name || playersById[s.assistId]?.name || null) : null
  }))
  const events = await listMatchEventsByMatchId(db, id)

  return {
    id: match.id,
    createdAt: match.createdAt,
    type: match.type,
    played: Boolean(match.played),
    plateauId: match.plateauId ?? null,
    opponentName: match.opponentName ?? null,
    tactic: match.tactic ?? null,
    teams,
    scorers,
    events,
    playersById
  }
}

app.get('/matches', authMiddleware, async (req: any, res) => {
  const { plateauId } = req.query as { plateauId?: string }
  const where = plateauId ? { plateauId: String(plateauId) } : {}
  const matches = await matchFindManyForUser(prisma, req.auth, {
    where,
    include: { teams: { include: { players: { include: { player: true } } } }, scorers: true },
    orderBy: { createdAt: 'desc' }
  })
  res.json(matches)
})

app.get('/matches/:id', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    const match = await getMatchDetailForUser(prisma, req.auth, id)
    if (!match) return res.status(404).json({ error: 'Match not found' })
    return res.json(match)
  } catch (e) {
    console.error('[GET /matches/:id] failed', e)
    return res.status(500).json({ error: 'Failed to fetch match' })
  }
})

app.get('/matches/:id/events', authMiddleware, async (req: any, res) => {
  const { id: matchId } = req.params
  try {
    const events = await listMatchEventsForUser(prisma, req.auth, matchId)
    if (!events) return res.status(404).json({ error: 'Match not found' })
    return res.json(events)
  } catch (e) {
    console.error('[GET /matches/:id/events] failed', e)
    return res.status(500).json({ error: 'Failed to fetch match events' })
  }
})

app.post('/matches/:id/events', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const { id: matchId } = req.params
  const parsed = matchEventCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  try {
    const match = await matchFindFirstForUser(prisma, req.auth, {
      where: { id: matchId },
      select: { id: true },
    })
    if (!match) return res.status(404).json({ error: 'Match not found' })

    const payload = parsed.data
    const playerIds = [payload.scorerId, payload.assistId, payload.inPlayerId, payload.outPlayerId].filter(Boolean) as string[]
    await assertEventPlayerIdsInMatchScope(prisma, req.auth, matchId, playerIds)

    const created = await prisma.matchEvent.create({
      data: {
        matchId,
        minute: payload.minute,
        type: payload.type,
        scorerId: payload.scorerId ?? null,
        assistId: payload.assistId ?? null,
        slotId: payload.slotId ?? null,
        inPlayerId: payload.inPlayerId ?? null,
        outPlayerId: payload.outPlayerId ?? null,
      },
    })
    return res.status(201).json(toMatchEventResponse(created))
  } catch (e: any) {
    if (e?.code === 'PLAYER_SCOPE_FORBIDDEN') return res.status(400).json({ error: e.message })
    if (e?.code === 'P2003') return res.status(400).json({ error: 'Invalid foreign key reference in event payload' })
    if (e?.code === 'P2021') return res.status(503).json({ error: 'Match event storage unavailable' })
    console.error('[POST /matches/:id/events] failed', e)
    return res.status(500).json({ error: 'Failed to create match event' })
  }
})

app.delete('/matches/:id/events/:eventId', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const { id: matchId, eventId } = req.params
  try {
    const match = await matchFindFirstForUser(prisma, req.auth, {
      where: { id: matchId },
      select: { id: true },
    })
    if (!match) return res.status(404).json({ error: 'Match not found' })

    const deleted = await prisma.matchEvent.deleteMany({
      where: { id: eventId, matchId },
    })
    if (deleted.count === 0) return res.status(404).json({ error: 'Match event not found' })
    return res.json({ ok: true })
  } catch (e) {
    if ((e as any)?.code === 'P2021') return res.status(503).json({ error: 'Match event storage unavailable' })
    console.error('[DELETE /matches/:id/events/:eventId] failed', e)
    return res.status(500).json({ error: 'Failed to delete match event' })
  }
})

app.post('/matches', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({
    type: z.enum(['ENTRAINEMENT', 'PLATEAU']),
    played: z.boolean().optional(),
    plateauId: z.string().optional(),
    sides: z.object({
      home: z.object({
        starters: z.array(z.string()).default([]),
        subs: z.array(z.string()).default([])
      }).default({ starters: [], subs: [] }),
      away: z.object({
        starters: z.array(z.string()).default([]),
        subs: z.array(z.string()).default([])
      }).default({ starters: [], subs: [] })
    }),
    score: z.object({ home: z.number().int().min(0), away: z.number().int().min(0) }).optional(),
    buteurs: z.array(matchScorerPayloadSchema).optional(),
    opponentName: z.string().min(1).max(100).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { type, plateauId, sides, score, buteurs, opponentName, played } = parsed.data
  const normalized = normalizeMatchState({ played, score, buteurs })

  let team: any = null
  if (plateauId) {
    const ownedPlateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id: plateauId } })
    if (!ownedPlateau) return res.status(404).json({ error: 'Plateau not found' })
    team = { id: ownedPlateau.teamId, clubId: ownedPlateau.clubId }
  } else {
    try {
      team = await resolveTeamForWrite(req.auth)
    } catch (e: any) {
      return res.status(400).json({ error: e.message })
    }
  }

  try {
    const match = await matchCreateForUser(prisma, req.auth, {
      type, plateauId, opponentName, played: normalized.played,
      clubId: team?.clubId ?? req.auth.clubId ?? null,
      teamId: team?.id ?? null
    })
    const home = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'home', score: normalized.score.home } })
    const away = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'away', score: normalized.score.away } })

    const toMTP = (matchTeamId: string, ids: string[], role: 'starter' | 'sub') => ids.map(playerId => ({ matchTeamId, playerId, role }))
    const mtps = [
      ...toMTP(home.id, sides.home.starters, 'starter'),
      ...toMTP(home.id, sides.home.subs, 'sub'),
      ...toMTP(away.id, sides.away.starters, 'starter'),
      ...toMTP(away.id, sides.away.subs, 'sub'),
    ]
    const uniqueMtps = Array.from(
      new Map(mtps.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values()
    )
    if (uniqueMtps.length) await prisma.matchTeamPlayer.createMany({ data: uniqueMtps })

    if (normalized.buteurs.length) {
      const scorerPlayerIds = normalized.buteurs.flatMap((b) => [b.playerId, b.assistId ?? null].filter(Boolean) as string[])
      await assertPlayerIdsInMatchTeams(prisma, match.id, scorerPlayerIds)
      await prisma.scorer.createMany({
        data: normalized.buteurs.map((b) => ({
          matchId: match.id,
          playerId: b.playerId,
          assistId: b.assistId ?? null,
          side: b.side,
        }))
      })
    }

    const full = await matchFindUniqueCompat(prisma, {
      where: { id: match.id },
      include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
    })
    res.json(full)
  } catch (e: any) {
    if (e?.code === 'PLAYER_NOT_IN_MATCH_TEAMS') return res.status(400).json({ error: e.message })
    if (e?.code === 'P2003') return res.status(400).json({ error: 'Invalid scorer reference in payload' })
    console.error('[POST /matches] failed', e)
    return res.status(500).json({ error: 'Failed to create match' })
  }
})

// Update a match: score, opponentName, and (optionally) scorers (replace all)
app.put('/matches/:id', authMiddleware, async (req: any, res) => {
  const matchId = req.params.id
  const schema = z.object({
    type: z.enum(['ENTRAINEMENT', 'PLATEAU']).optional(),
    played: z.boolean().optional(),
    plateauId: z.string().nullable().optional(),
    sides: z.object({
      home: z.object({
        starters: z.array(z.string()).default([]),
        subs: z.array(z.string()).default([])
      }),
      away: z.object({
        starters: z.array(z.string()).default([]),
        subs: z.array(z.string()).default([])
      })
    }),
    score: z.object({ home: z.number().int().min(0), away: z.number().int().min(0) }),
    buteurs: z.array(matchScorerPayloadSchema).default([]),
    opponentName: z.string().max(100).optional(),
    tactic: matchTacticSchema.nullable().optional(),
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  try {
    const payload = parsed.data
    const updatedId = await prisma.$transaction(async (tx) => {
      const existing = await matchFindFirstForUser(tx, req.auth, {
        where: { id: matchId },
        include: { teams: { select: { id: true, side: true } } }
      })
      if (!existing) {
        const err: any = new Error('Match not found')
        err.code = 'MATCH_NOT_FOUND'
        throw err
      }

      const owningTeam = existing.teamId
        ? await tx.team.findFirst({
          where: { id: existing.teamId, clubId: req.auth.clubId },
          select: { format: true },
        })
        : null
      const payloadValidation = validateMatchUpdatePayloadForTeamFormat({
        teamFormat: owningTeam?.format,
        sides: payload.sides,
        tactic: payload.tactic,
      })
      if (!payloadValidation.ok) {
        const err: any = new Error(payloadValidation.error)
        err.code = 'MATCH_PAYLOAD_INVALID'
        throw err
      }
      if (payloadValidation.usedFallback) {
        console.warn('[PUT /matches/:id] invalid or missing team format, fallback applied', {
          matchId,
          fallbackFormat: payloadValidation.format,
        })
      }

      const normalized = normalizeMatchState(payload, Boolean(existing.played))

      if (payload.plateauId !== undefined && payload.plateauId) {
        const plateau = await plateauFindFirstForUser(tx, req.auth, { where: { id: payload.plateauId }, select: { id: true } })
        if (!plateau) {
          const err: any = new Error('Plateau not found')
          err.code = 'PLATEAU_NOT_FOUND'
          throw err
        }
      }

      const teamBySide: Record<'home' | 'away', any> = { home: null, away: null }
      for (const team of existing.teams || []) {
        if (team.side === 'home' || team.side === 'away') {
          const side = team.side as 'home' | 'away'
          teamBySide[side] = team
        }
      }

      if (!teamBySide.home) {
        teamBySide.home = await tx.matchTeam.create({ data: { matchId, side: 'home', score: normalized.score.home }, select: { id: true, side: true } })
      }
      if (!teamBySide.away) {
        teamBySide.away = await tx.matchTeam.create({ data: { matchId, side: 'away', score: normalized.score.away }, select: { id: true, side: true } })
      }

      const matchPatch: any = {}
      if (payload.type !== undefined) matchPatch.type = payload.type
      if (payload.played !== undefined) matchPatch.played = normalized.played
      if (payload.plateauId !== undefined) {
        matchPatch.plateau = payload.plateauId
          ? { connect: { id: payload.plateauId } }
          : { disconnect: true }
      }
      if (payload.opponentName !== undefined) matchPatch.opponentName = payload.opponentName
      if (payload.tactic !== undefined) matchPatch.tactic = payload.tactic
      if (Object.keys(matchPatch).length > 0) {
        await tx.match.update({ where: { id: matchId }, data: matchPatch })
      }

      await Promise.all([
        tx.matchTeam.update({ where: { id: teamBySide.home.id }, data: { score: normalized.score.home } }),
        tx.matchTeam.update({ where: { id: teamBySide.away.id }, data: { score: normalized.score.away } })
      ])

      await tx.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: [teamBySide.home.id, teamBySide.away.id] } } })
      const mtps = [
        ...rowsForMatchTeam(teamBySide.home.id, payload.sides.home.starters, 'starter'),
        ...rowsForMatchTeam(teamBySide.home.id, payload.sides.home.subs, 'sub'),
        ...rowsForMatchTeam(teamBySide.away.id, payload.sides.away.starters, 'starter'),
        ...rowsForMatchTeam(teamBySide.away.id, payload.sides.away.subs, 'sub'),
      ]
      const uniqueMtps = Array.from(new Map(mtps.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values())
      if (uniqueMtps.length) {
        await tx.matchTeamPlayer.createMany({ data: uniqueMtps })
      }

      await tx.scorer.deleteMany({ where: { matchId } })
      if (normalized.buteurs.length) {
        const scorerPlayerIds = normalized.buteurs.flatMap((b) => [b.playerId, b.assistId ?? null].filter(Boolean) as string[])
        await assertPlayerIdsInMatchTeams(tx, matchId, scorerPlayerIds)
        await tx.scorer.createMany({
          data: normalized.buteurs.map((b) => ({
            matchId,
            playerId: b.playerId,
            assistId: b.assistId ?? null,
            side: b.side,
          }))
        })
      }

      try {
        const [goalForCount, goalAgainstCount] = await Promise.all([
          tx.matchEvent.count({ where: { matchId, type: 'GOAL_FOR' } }),
          tx.matchEvent.count({ where: { matchId, type: 'GOAL_AGAINST' } }),
        ])
        if (goalForCount !== normalized.score.home || goalAgainstCount !== normalized.score.away) {
          console.warn('[PUT /matches/:id] score/events mismatch', {
            matchId,
            expected: normalized.score,
            eventsCount: { GOAL_FOR: goalForCount, GOAL_AGAINST: goalAgainstCount },
          })
        }
      } catch (e: any) {
        if (e?.code !== 'P2021') throw e
      }

      return existing.id
    })

    const updated = await getMatchDetailForUser(prisma, req.auth, updatedId)
    if (!updated) return res.status(404).json({ error: 'Match not found' })
    return res.json(updated)
  } catch (e) {
    if ((e as any)?.code === 'MATCH_NOT_FOUND') return res.status(404).json({ error: 'Match not found' })
    if ((e as any)?.code === 'PLATEAU_NOT_FOUND') return res.status(404).json({ error: 'Plateau not found' })
    if ((e as any)?.code === 'MATCH_PAYLOAD_INVALID') return res.status(400).json({ error: (e as any).message })
    if ((e as any)?.code === 'PLAYER_NOT_IN_MATCH_TEAMS') return res.status(400).json({ error: (e as any).message })
    if ((e as any)?.code === 'P2003') return res.status(400).json({ error: 'Invalid scorer reference in payload' })
    console.error('[PUT /matches/:id] failed', e)
    return res.status(500).json({ error: 'Failed to update match' })
  }
})

// Delete a match (cascade delete teams, players, scorers)
app.delete('/matches/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    const exists = await matchFindFirstForUser(prisma, req.auth, { where: { id } })
    if (!exists) return res.status(404).json({ error: 'Match not found' })

    const teams = await prisma.matchTeam.findMany({ where: { matchId: id } })
    const teamIds = teams.map(t => t.id)

    await prisma.$transaction([
      prisma.scorer.deleteMany({ where: { matchId: id } }),
      prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
      prisma.matchTeam.deleteMany({ where: { matchId: id } }),
      prisma.match.delete({ where: { id: exists.id } })
    ])

    res.json({ ok: true })
  } catch (e) {
    console.error('[DELETE /matches/:id] failed', e)
    return res.status(500).json({ error: 'Failed to delete match' })
  }
})

// ---- Schedule generator (pairings only) ----
function shuffle<T>(arr: T[]) {
  const a = arr.slice()
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
      ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

app.post('/schedule/generate', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    teams: z.array(z.array(z.string().min(1))).min(2),
    options: z.object({ m: z.number().int().min(1), allowRematch: z.boolean().optional() }).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { teams, options } = parsed.data
  const n = teams.length
  const m = options?.m ?? Math.max(1, n - 1)
  const allowRematch = options?.allowRematch ?? false

  const idx = shuffle(Array.from({ length: n }, (_, i) => i))
  const pairs: { home: number; away: number }[] = []
  const played = new Set<string>()

  outer: for (let round = 0; round < m; round++) {
    for (let a = 0; a < n; a++) {
      for (let b = a + 1; b < n; b++) {
        const i = idx[a], j = idx[b]
        const key = i < j ? `${i}-${j}` : `${j}-${i}`
        if (!allowRematch && played.has(key)) continue
        pairs.push({ home: i, away: j })
        played.add(key)
        if (pairs.length >= Math.ceil((m * n) / 2)) break outer
      }
    }
  }

  res.json({ matches: pairs, teamCount: n })
})
app.post('/schedule/commit', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const schema = z.object({
    plateauId: z.string().optional(),
    teams: z.array(z.array(z.string().min(1))).min(2),
    schedule: z.object({ matches: z.array(z.object({ home: z.number().int().min(0), away: z.number().int().min(0) })) }),
    defaults: z.object({ startersPerTeam: z.number().int().min(1).max(11).default(5) }).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { plateauId, teams, schedule, defaults } = parsed.data
  const startersPerTeam = defaults?.startersPerTeam ?? 5
  let targetTeam: any = null
  if (plateauId) {
    const ownedPlateau = await plateauFindFirstForUser(prisma, req.auth, { where: { id: plateauId } })
    if (!ownedPlateau) return res.status(404).json({ error: 'Plateau not found' })
    targetTeam = { id: ownedPlateau.teamId, clubId: ownedPlateau.clubId }
  } else {
    try {
      targetTeam = await resolveTeamForWrite(req.auth)
    } catch (e: any) {
      return res.status(400).json({ error: e.message })
    }
  }

  const createdIds = await prisma.$transaction(async (db) => {
    const ids: string[] = []
    for (const m of schedule.matches) {
      const match = await matchCreateForUser(db, req.auth, {
        type: plateauId ? 'PLATEAU' : 'ENTRAINEMENT',
        plateauId,
        clubId: targetTeam?.clubId ?? req.auth.clubId ?? null,
        teamId: targetTeam?.id ?? null
      })
      const home = await db.matchTeam.create({ data: { matchId: match.id, side: 'home', score: 0 } })
      const away = await db.matchTeam.create({ data: { matchId: match.id, side: 'away', score: 0 } })

      const pick = (arr: string[]) => arr.slice(0, startersPerTeam)
      const toMTP = (matchTeamId: string, ids: string[], role: 'starter' | 'sub') => ids.map(playerId => ({ matchTeamId, playerId, role }))

      const homeIds = teams[m.home] ?? []
      const awayIds = teams[m.away] ?? []
      const rows = [
        ...toMTP(home.id, pick(homeIds), 'starter'),
        ...toMTP(away.id, pick(awayIds), 'starter'),
      ]
      const uniqueRows = Array.from(
        new Map(rows.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values()
      )
      if (uniqueRows.length) await db.matchTeamPlayer.createMany({ data: uniqueRows })
      ids.push(match.id)
    }
    return ids
  })

  const matches = await matchFindManyForUser(prisma, req.auth, {
    where: { id: { in: createdIds } },
    include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
  })

  res.json({ ok: true, createdCount: createdIds.length, matches })
})

// ---- Training drills (exercices attachés à une séance) ----

app.post('/trainings/:id/drills/generate-ai', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const trainingId = req.params.id
  const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } })
  if (!training) return res.status(404).json({ error: 'Training not found' })

  const schema = z.object({
    objective: z.string().min(10).max(400),
    includeDiagrams: z.boolean().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const team = await prisma.team.findFirst({
    where: {
      id: training.teamId,
      ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}),
    },
    select: { id: true, name: true }
  })
  if (!team) return res.status(404).json({ error: 'Team not found' })

  const ageBand = inferAgeBandFromTeamName(team.name)
  const includeDiagrams = parsed.data.includeDiagrams === true
  const aiRequestId = randomUUID().slice(0, 8)
  const aiStartAt = Date.now()
  let generated: Array<{
    title: string,
    category: string,
    duration: number,
    players: string,
    description: string,
    descriptionHtml: string,
    tags: string[],
    animation?: { p?: Array<[number, number]>, s?: Array<[number, number]>, c?: Array<[number, number]> },
    tacticalPlan?: { phases?: Array<{ a: string, t: [number, number] }> },
    visualPlan?: { c?: Array<[number, number]>, f?: Array<{ p1: [number, number], p2: [number, number], b?: [number, number] }> },
  }>
  try {
    generated = await generateDrillsWithOpenAI({
      objective: parsed.data.objective,
      ageBand,
      teamName: team.name || 'Equipe',
    }, { includeVisualPlan: false })
    console.log('[POST /trainings/:id/drills/generate-ai] OpenAI success', {
      requestId: aiRequestId,
      durationMs: Date.now() - aiStartAt,
      count: generated.length,
    })
  } catch (e: any) {
    const logError = summarizeErrorForLog(e)
    console.error('[POST /trainings/:id/drills/generate-ai] OpenAI failed', {
      requestId: aiRequestId,
      durationMs: Date.now() - aiStartAt,
      ...logError,
    })
    if (e?.code === 'OPENAI_API_KEY_MISSING') {
      return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' })
    }
    if (e?.code === 'OPENAI_TIMEOUT') {
      return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' })
    }
    if (e?.code === 'OPENAI_NETWORK_ERROR') {
      return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' })
    }
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota') {
      return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' })
    }
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401) {
      return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' })
    }
    if (e?.code === 'OPENAI_INVALID_JSON') {
      return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' })
    }
    if (e?.code === 'OPENAI_SCHEMA_MISMATCH') {
      return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' })
    }
    return res.status(502).json({ error: 'Failed to generate drills with AI' })
  }

  const created = await prisma.$transaction(async (tx) => {
    const existingRows = await trainingDrillFindManyForUser(tx, req.auth, {
      where: { trainingId },
      select: { order: true }
    })
    let nextOrder = existingRows.reduce((max: number, row: any) => Math.max(max, row.order ?? -1), -1) + 1
    const items: any[] = []

    for (const [index, item] of generated.entries()) {
      const id = await buildUniqueDrillId(tx, req.auth, item.title)
      const drill = await drillCreateForUser(tx, req.auth, {
        id,
        clubId: training.clubId,
        teamId: training.teamId,
        title: item.title,
        category: item.category,
        duration: item.duration,
        players: item.players,
        description: item.description,
        tags: item.tags,
      })

      const trainingDrill = await trainingDrillCreateForUser(tx, req.auth, {
        trainingId,
        drillId: drill.id,
        duration: item.duration,
        notes: null,
        order: nextOrder++,
      })

      items.push({
        drill: { ...drill, descriptionHtml: item.descriptionHtml },
        trainingDrill,
        diagram: null as any
      })

      if (includeDiagrams) {
        const diagramData = buildDefaultDiagramData(index, item)
        const diagram = await diagramCreateForUser(tx, req.auth, {
          drillId: drill.id,
          title: `${drill.title} - Diagramme`,
          data: JSON.stringify(diagramData),
        })
        items[items.length - 1].diagram = { ...diagram, data: diagramData }
      }
    }
    return items
  })

  res.status(201).json({
    objective: parsed.data.objective,
    ageBand,
    includeDiagrams,
    count: created.length,
    items: created
  })
})

// Lister les exercices d'une séance (avec enrichissement à partir du catalogue Drill)
app.get('/trainings/:id/drills', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } })
  if (!training) return res.status(404).json({ error: 'Training not found' })
  const rows = await listTrainingDrillsInOrder(prisma, req.auth, trainingId)
  const catalog = await drillFindManyForUser(prisma, req.auth, { orderBy: { createdAt: 'asc' } })
  const catalogById = new Map(catalog.map((drill: any) => [drill.id, withDrillDescriptionHtml(drill)]))
  const items = rows.map(r => {
    const meta = catalogById.get(r.drillId) || null
    return { ...r, meta }
  })
  res.json(items)
})

// Ajouter un exercice à une séance
app.post('/trainings/:id/drills', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const training = await trainingFindFirstForUser(prisma, req.auth, { where: { id: trainingId } })
  if (!training) return res.status(404).json({ error: 'Training not found' })
  const schema = z.object({
    drillId: z.string().min(1),
    duration: z.number().int().min(1).max(120).optional(),
    notes: z.string().max(1000).optional(),
    trainingDrillId: z.string().min(1).optional(),
    replaceTrainingDrillId: z.string().min(1).optional(),
    id: z.string().min(1).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: parsed.data.drillId } })
  if (!drill) return res.status(404).json({ error: 'Drill not found' })

  const requestedTrainingDrillRef =
    parsed.data.trainingDrillId ||
    parsed.data.replaceTrainingDrillId ||
    (parsed.data.id && parsed.data.id !== parsed.data.drillId ? parsed.data.id : undefined)

  if (requestedTrainingDrillRef) {
    const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, requestedTrainingDrillRef)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    const updated = await prisma.trainingDrill.update({
      where: { id: existing.id },
      data: {
        drillId: parsed.data.drillId,
        ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration } : {}),
        ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes } : {}),
      }
    })
    const meta = drill
    return res.json({ ...updated, meta })
  }

  const row = await prisma.$transaction(async (tx) => {
    const existingRows = await trainingDrillFindManyForUser(tx, req.auth, {
      where: { trainingId },
      select: { order: true }
    })
    const nextOrder = existingRows.reduce((max: number, currentRow: any) => Math.max(max, currentRow.order ?? -1), -1) + 1

    return trainingDrillCreateForUser(tx, req.auth, {
      trainingId, drillId: parsed.data.drillId, duration: parsed.data.duration, notes: parsed.data.notes, order: nextOrder
    })
  })
  const meta = drill
  res.json({ ...row, meta })
})

// Modifier (notes/duration/order)
app.put('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const trainingDrillId = req.params.trainingDrillId
  const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, trainingDrillId)
  if (!existing) return res.status(404).json({ error: 'Not found' })
  const schema = z.object({
    drillId: z.string().min(1).optional(),
    duration: z.number().int().min(1).max(120).nullable().optional(),
    notes: z.string().max(1000).nullable().optional(),
    order: z.number().int().min(0).optional()
  }).refine((data) => (
    data.drillId !== undefined ||
    data.duration !== undefined ||
    data.notes !== undefined ||
    data.order !== undefined
  ), {
    message: 'At least one field must be provided',
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  if (parsed.data.drillId !== undefined) {
    const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: parsed.data.drillId } })
    if (!drill) return res.status(404).json({ error: 'Drill not found' })
  }

  try {
    const updateData = {
      ...(parsed.data.drillId !== undefined ? { drillId: parsed.data.drillId } : {}),
      ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration ?? null } : {}),
      ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes ?? null } : {}),
    }

    const updated = await prisma.$transaction(async (tx) => {
      if (parsed.data.order !== undefined) {
        await moveTrainingDrillToOrder(tx, req.auth, trainingId, existing.id, parsed.data.order)
      }

      if (Object.keys(updateData).length > 0) {
        return tx.trainingDrill.update({
          where: { id: existing.id },
          data: updateData
        })
      }

      return tx.trainingDrill.findUnique({
        where: { id: existing.id }
      })
    })
    if (!updated) return res.status(404).json({ error: 'Not found' })
    const meta = await drillFindFirstForUser(prisma, req.auth, { where: { id: updated.drillId } })
    res.json({ ...updated, meta })
  } catch (e: any) {
    if (e?.code === 'INVALID_ORDER') {
      return res.status(400).json({ error: 'Invalid order' })
    }
    res.status(404).json({ error: 'Not found' })
  }
})

// Supprimer un exercice d'une séance
app.delete('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const trainingDrillId = req.params.trainingDrillId
  try {
    const existing = await resolveTrainingDrillForRouteRef(prisma, req.auth, trainingId, trainingDrillId)
    if (!existing) return res.status(404).json({ error: 'Not found' })
    const deleted = await prisma.$transaction(async (tx) => {
      await tx.diagram.deleteMany({ where: applyScopeWhere(req.auth, { trainingDrillId: existing.id }, { includeLegacyOwner: true }) })
      const removed = await tx.trainingDrill.deleteMany({ where: { id: existing.id } })
      if (removed.count) {
        await normalizeTrainingDrillOrders(tx, req.auth, trainingId)
      }
      return removed
    })
    if (!deleted.count) return res.status(404).json({ error: 'Not found' })
    res.json({ ok: true })
  } catch (e) {
    console.error('[DELETE /trainings/:id/drills/:trainingDrillId] failed', e)
    res.status(500).json({ error: 'Failed to delete training drill' })
  }
})

// ---- Diagrams (exercices) ----
app.post('/drills/:id/diagrams/generate-ai', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const drillId = req.params.id
  const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: drillId } })
  if (!drill) return res.status(404).json({ error: 'Drill not found' })

  const schema = z.object({
    objective: z.string().min(3).max(400).optional(),
  })
  const parsed = schema.safeParse(req.body || {})
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  let ageBand = 'U9-U11'
  if (drill.teamId) {
    const team = await prisma.team.findFirst({
      where: { id: drill.teamId, ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}) },
      select: { name: true }
    })
    if (team?.name) ageBand = inferAgeBandFromTeamName(team.name)
  }

  const requestId = randomUUID().slice(0, 8)
  const startAt = Date.now()
  try {
    const visualPlan = await generateVisualPlanWithOpenAI({
      title: drill.title,
      category: drill.category,
      description: drill.description,
      tags: Array.isArray(drill.tags) ? drill.tags : [],
      ageBand,
      objective: parsed.data.objective,
    })

    const diagramData = buildDefaultDiagramData(0, {
      title: drill.title,
      category: drill.category,
      tags: Array.isArray(drill.tags) ? drill.tags : [],
      visualPlan
    })
    const created = await diagramCreateForUser(prisma, req.auth, {
      drillId: drill.id,
      title: `${drill.title} - Diagramme IA`,
      data: JSON.stringify(diagramData),
    })
    console.log('[POST /drills/:id/diagrams/generate-ai] OpenAI success', {
      requestId,
      durationMs: Date.now() - startAt,
      drillId: drill.id,
    })
    return res.status(201).json({ ...created, data: diagramData })
  } catch (e: any) {
    console.error('[POST /drills/:id/diagrams/generate-ai] OpenAI failed', {
      requestId,
      durationMs: Date.now() - startAt,
      ...summarizeErrorForLog(e),
    })
    if (e?.code === 'OPENAI_API_KEY_MISSING') return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' })
    if (e?.code === 'OPENAI_TIMEOUT') return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' })
    if (e?.code === 'OPENAI_NETWORK_ERROR') return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' })
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota') return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' })
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401) return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' })
    if (e?.code === 'OPENAI_INVALID_JSON') return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' })
    if (e?.code === 'OPENAI_SCHEMA_MISMATCH') return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' })
    return res.status(502).json({ error: 'Failed to generate diagram with AI' })
  }
})

app.post('/training-drills/:id/diagrams/generate-ai', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return
  const trainingDrillId = req.params.id
  const trainingDrill = await trainingDrillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrillId } })
  if (!trainingDrill) return res.status(404).json({ error: 'Training drill not found' })
  const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrill.drillId } })
  if (!drill) return res.status(404).json({ error: 'Drill not found' })

  const schema = z.object({
    objective: z.string().min(3).max(400).optional(),
  })
  const parsed = schema.safeParse(req.body || {})
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  let ageBand = 'U9-U11'
  if (trainingDrill.teamId || drill.teamId) {
    const team = await prisma.team.findFirst({
      where: { id: trainingDrill.teamId || drill.teamId, ...(req.auth?.clubId ? { clubId: req.auth.clubId } : {}) },
      select: { name: true }
    })
    if (team?.name) ageBand = inferAgeBandFromTeamName(team.name)
  }

  const requestId = randomUUID().slice(0, 8)
  const startAt = Date.now()
  try {
    const visualPlan = await generateVisualPlanWithOpenAI({
      title: drill.title,
      category: drill.category,
      description: drill.description,
      tags: Array.isArray(drill.tags) ? drill.tags : [],
      ageBand,
      objective: parsed.data.objective,
    })

    const diagramData = buildDefaultDiagramData(0, {
      title: drill.title,
      category: drill.category,
      tags: Array.isArray(drill.tags) ? drill.tags : [],
      visualPlan
    })
    const created = await diagramCreateForUser(prisma, req.auth, {
      trainingDrillId: trainingDrill.id,
      title: `${drill.title} - Diagramme IA`,
      data: JSON.stringify(diagramData),
    })
    console.log('[POST /training-drills/:id/diagrams/generate-ai] OpenAI success', {
      requestId,
      durationMs: Date.now() - startAt,
      trainingDrillId: trainingDrill.id,
    })
    return res.status(201).json({ ...created, data: diagramData })
  } catch (e: any) {
    console.error('[POST /training-drills/:id/diagrams/generate-ai] OpenAI failed', {
      requestId,
      durationMs: Date.now() - startAt,
      ...summarizeErrorForLog(e),
    })
    if (e?.code === 'OPENAI_API_KEY_MISSING') return res.status(503).json({ error: 'AI service unavailable (missing OPENAI_API_KEY)' })
    if (e?.code === 'OPENAI_TIMEOUT') return res.status(504).json({ error: 'AI timeout', code: 'OPENAI_TIMEOUT' })
    if (e?.code === 'OPENAI_NETWORK_ERROR') return res.status(503).json({ error: 'AI network error', code: 'OPENAI_NETWORK_ERROR' })
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.openai?.code === 'insufficient_quota') return res.status(503).json({ error: 'AI quota exceeded', code: 'INSUFFICIENT_QUOTA' })
    if (e?.code === 'OPENAI_REQUEST_FAILED' && e?.status === 401) return res.status(503).json({ error: 'AI authentication failed', code: 'OPENAI_AUTH_FAILED' })
    if (e?.code === 'OPENAI_INVALID_JSON') return res.status(502).json({ error: 'AI returned invalid JSON', code: 'OPENAI_INVALID_JSON' })
    if (e?.code === 'OPENAI_SCHEMA_MISMATCH') return res.status(502).json({ error: 'AI response schema mismatch', code: 'OPENAI_SCHEMA_MISMATCH' })
    return res.status(502).json({ error: 'Failed to generate diagram with AI' })
  }
})

app.get('/drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const drillId = req.params.id
  const rows = await diagramFindManyForUser(prisma, req.auth, { where: { drillId }, orderBy: { updatedAt: 'desc' } })
  res.json(rows)
})

app.get('/training-drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const trainingDrillId = req.params.id
  const rows = await diagramFindManyForUser(prisma, req.auth, { where: { trainingDrillId }, orderBy: { updatedAt: 'desc' } })
  res.json(rows)
})

app.get('/diagrams/:id', authMiddleware, async (req: any, res) => {
  const d = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
  if (!d) return res.status(404).json({ error: 'Not found' })
  res.json(d)
})

app.post('/drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const drillId = req.params.id
  const drill = await drillFindFirstForUser(prisma, req.auth, { where: { id: drillId } })
  if (!drill) return res.status(404).json({ error: 'Drill not found' })
  const schema = z.object({
    title: z.string().min(1).max(100),
    data: z.any() // JSON
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const created = await diagramCreateForUser(prisma, req.auth, {
    drillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data)
  })
  res.json({ ...created, data: parsed.data.data })
})

app.post('/training-drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const trainingDrillId = req.params.id
  const trainingDrill = await trainingDrillFindFirstForUser(prisma, req.auth, { where: { id: trainingDrillId } })
  if (!trainingDrill) return res.status(404).json({ error: 'Training drill not found' })
  const schema = z.object({
    title: z.string().min(1).max(100),
    data: z.any()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const created = await diagramCreateForUser(prisma, req.auth, {
    trainingDrillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data)
  })
  res.json({ ...created, data: parsed.data.data })
})

app.put('/diagrams/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    title: z.string().min(1).max(100).optional(),
    data: z.any().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const patch: any = {}
  if (parsed.data.title !== undefined) patch.title = parsed.data.title
  if (parsed.data.data !== undefined) patch.data = JSON.stringify(parsed.data.data)

  try {
    const existing = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
    if (!existing) return res.status(404).json({ error: 'Not found' })
    const updated = await prisma.diagram.update({ where: { id: existing.id }, data: patch })
    res.json({ ...updated, data: parsed.data.data ?? JSON.parse(updated.data) })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Not found' })
    console.error('[PUT /diagrams/:id] failed', e)
    return res.status(500).json({ error: 'Failed to update diagram' })
  }
})

app.delete('/diagrams/:id', authMiddleware, async (req: any, res) => {
  try {
    const existing = await diagramFindFirstForUser(prisma, req.auth, { where: { id: req.params.id } })
    if (!existing) return res.status(404).json({ error: 'Not found' })
    const deleted = await prisma.diagram.deleteMany({ where: { id: existing.id } })
    if (!deleted.count) return res.status(404).json({ error: 'Not found' })
    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Not found' })
    console.error('[DELETE /diagrams/:id] failed', e)
    return res.status(500).json({ error: 'Failed to delete diagram' })
  }
})

app.get('/tactics', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return

  const parsed = z.object({ teamId: z.string().min(1) }).safeParse(req.query)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  const { teamId } = parsed.data
  if (!canWriteTacticForTeam(req.auth, teamId)) {
    return res.status(403).json({ error: 'Forbidden team scope for tactics' })
  }

  const rows = await prisma.tactic.findMany({
    where: { teamId },
    orderBy: { updatedAt: 'desc' },
  })
  return res.json(rows)
})

app.get('/tactics/:id', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return

  const activeTeamId = getActiveTeamIdForAuth(req.auth)
  if (!activeTeamId) return res.status(400).json({ error: 'Active team selection is required' })

  const row = await prisma.tactic.findFirst({
    where: { id: req.params.id, teamId: activeTeamId },
  })
  if (!row) return res.status(404).json({ error: 'Tactic not found' })
  return res.json(row)
})

app.post('/tactics', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return

  const parsed = tacticPayloadSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }
  if (parsed.data.teamId !== team.id || !canWriteTacticForTeam(req.auth, parsed.data.teamId)) {
    return res.status(403).json({ error: 'Forbidden team scope for tactics' })
  }

  try {
    const saved = await upsertTacticByTeamAndName(prisma.tactic, parsed.data)
    return res.json(saved)
  } catch (e: any) {
    if (e?.code === 'P2002') {
      const existing = await prisma.tactic.findFirst({
        where: {
          teamId: parsed.data.teamId,
          name: {
            equals: parsed.data.name,
            mode: 'insensitive',
          },
        },
      })
      if (existing) {
        const updated = await prisma.tactic.update({
          where: { id: existing.id },
          data: {
            name: parsed.data.name,
            formation: parsed.data.formation,
            points: parsed.data.points,
          },
        })
        return res.json(updated)
      }
      return res.status(409).json({ error: 'Tactic name conflict for this team' })
    }
    console.error('[POST /tactics] failed', e)
    return res.status(500).json({ error: 'Failed to save tactic' })
  }
})

app.put('/tactics/:id', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return

  const parsed = tacticPayloadSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }
  if (parsed.data.teamId !== team.id || !canWriteTacticForTeam(req.auth, parsed.data.teamId)) {
    return res.status(403).json({ error: 'Forbidden team scope for tactics' })
  }

  const existing = await prisma.tactic.findFirst({
    where: { id: req.params.id, teamId: parsed.data.teamId },
  })
  if (!existing) return res.status(404).json({ error: 'Tactic not found' })

  try {
    const updated = await prisma.tactic.update({
      where: { id: existing.id },
      data: {
        name: parsed.data.name,
        formation: parsed.data.formation,
        points: parsed.data.points,
      },
    })
    return res.json(updated)
  } catch (e: any) {
    if (e?.code === 'P2002') return res.status(409).json({ error: 'Tactic name conflict for this team' })
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Tactic not found' })
    console.error('[PUT /tactics/:id] failed', e)
    return res.status(500).json({ error: 'Failed to update tactic' })
  }
})

app.delete('/tactics/:id', authMiddleware, async (req: any, res) => {
  if (!ensureStaff(req, res)) return

  let team: any
  try {
    team = await resolveTeamForWrite(req.auth)
  } catch (e: any) {
    return res.status(400).json({ error: e.message })
  }

  const deleted = await prisma.tactic.deleteMany({
    where: { id: req.params.id, teamId: team.id },
  })
  if (!deleted.count) return res.status(404).json({ error: 'Tactic not found' })
  return res.json({ ok: true })
})
// === END FOOT DOMAIN API ===

app.get('/health', (_req, res) => res.json({ ok: true }))

app.use((err: any, _req: any, res: any, _next: any) => {
  console.error('[unhandled]', err)
  if (res.headersSent) return
  const status = err?.statusCode || err?.status || 500
  res.status(status).json({
    error: status >= 500 ? 'Internal error' : (err?.message || 'Request failed')
  })
})

app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`)
})
