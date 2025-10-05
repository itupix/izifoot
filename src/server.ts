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

const app = express()
const prisma = new PrismaClient()
const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret'
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:5173'
const API_BASE_URL = process.env.API_BASE_URL || `http://localhost:${PORT}`

app.use(helmet())
app.use(cors({ origin: APP_BASE_URL, credentials: true }))
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

// --- Auth helpers ---
function signToken(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' })
}

function authMiddleware(req: any, res: any, next: any) {
  const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any
    req.userId = payload.sub
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
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

// --- Routes ---
function safeParseJSON(s: string | null) {
  if (!s) return null
  try { return JSON.parse(s) } catch { return null }
}
app.post('/api/auth/register', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(6) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password } = parsed.data
  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) return res.status(409).json({ error: 'Email already in use' })
  const passwordHash = await bcrypt.hash(password, 10)
  const user = await prisma.user.create({ data: { email, passwordHash } })
  const token = signToken(user.id)
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 3600 * 1000 })
  res.json({ id: user.id, email: user.email, isPremium: user.isPremium })
})

app.post('/api/auth/login', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { email, password } = parsed.data
  const user = await prisma.user.findUnique({ where: { email } })
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
  const token = signToken(user.id)
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 24 * 3600 * 1000 })
  res.json({ id: user.id, email: user.email, isPremium: user.isPremium })
})

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token')
  res.json({ ok: true })
})

app.get('/api/me', authMiddleware, async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } })
  if (!user) return res.status(404).json({ error: 'User not found' })
  const planningCount = user.plannings.length
  res.json({ id: user.id, email: user.email, isPremium: user.isPremium, planningCount })
})

// Collect waitlist emails
app.post('/api/waitlist', async (req, res) => {
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

// FREE TIER RULE: non-premium users can create **one planning total** (for any chosen date). They can update it, but not create a second one.

app.post('/api/plannings', authMiddleware, async (req: any, res) => {
  const schema = z.object({ date: z.string(), data: z.any() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { date, data } = parsed.data
  const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } })
  if (!user) return res.status(404).json({ error: 'User not found' })

  if (!user.isPremium && user.plannings.length >= 1) {
    return res.status(402).json({ error: 'Free tier: only one planning allowed. Upgrade to premium.' })
  }

  const isoDate = new Date(date)
  const existsForDate = await prisma.planning.findFirst({ where: { userId: user.id, date: isoDate } })
  if (existsForDate) return res.status(409).json({ error: 'Planning already exists for this date' })

  const planning = await prisma.planning.create({ data: { userId: user.id, date: isoDate, data: JSON.stringify(data) } })
  res.json({ ...planning, data })
})

app.get('/api/plannings', authMiddleware, async (req: any, res) => {
  const plans = await prisma.planning.findMany({ where: { userId: req.userId }, orderBy: { date: 'asc' } })
  const mapped = plans.map((p) => ({ ...p, data: safeParseJSON(p.data) }))
  res.json(mapped)
})

app.get('/api/plannings/:id', authMiddleware, async (req: any, res) => {
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  res.json({ ...p, data: safeParseJSON(p.data) })
})

app.put('/api/plannings/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({ data: z.any() })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  const updated = await prisma.planning.update({ where: { id: p.id }, data: { data: JSON.stringify(parsed.data.data) } })
  res.json({ ...updated, data: parsed.data.data })
})

app.delete('/api/plannings/:id', authMiddleware, async (req: any, res) => {
  const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } })
  if (!p) return res.status(404).json({ error: 'Not found' })
  await prisma.shareToken.deleteMany({ where: { planningId: p.id } })
  await prisma.planning.delete({ where: { id: p.id } })
  res.json({ ok: true })
})

// Sharing: create a share token (optional email)
app.post('/api/plannings/:id/share', authMiddleware, async (req: any, res) => {
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
app.get('/api/plannings/:id/qr', authMiddleware, async (req: any, res) => {
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
// Simple in-memory catalog to mirror the old app behaviour. Move to DB later if needed.
// id, title, category, duration (min), players (min-max or text), description, tags
const DRILLS = [
  {
    id: 'd_warmup_circle',
    title: 'Échauffement en cercle',
    category: 'Échauffement',
    duration: 10,
    players: '8–16',
    description: 'Les joueurs en cercle se passent le ballon en une touche. Varier pied droit/gauche, contrôle-orientation.',
    tags: ['passes', 'une-touche', 'coordination']
  },
  {
    id: 'd_conduite_portes',
    title: 'Conduite à travers portes',
    category: 'Technique individuelle',
    duration: 12,
    players: '6–12',
    description: 'Installer 8–12 portes (2 coupelles). Conduire balle à travers un max de portes en 45s, récupérer, répéter.',
    tags: ['conduite', 'dribble', 'vision']
  },
  {
    id: 'd_rondo_4v1',
    title: 'Rondo 4v1',
    category: 'Conservation',
    duration: 12,
    players: '5',
    description: 'Carré 8x8m. 4 extérieurs conservent face à 1 chasseur. 2 touches max. Le perdant devient chasseur.',
    tags: ['rondo', 'passes', 'pression']
  },
  {
    id: 'd_tir_relai',
    title: 'Relais de tirs',
    category: 'Finition',
    duration: 15,
    players: '6–12',
    description: 'Deux colonnes face au but. Conduite, passe en retrait, frappe. Comptage des buts par équipe.',
    tags: ['frappe', 'coordination', 'vitesse']
  },
  {
    id: 'd_3v3_jeu_reduit',
    title: '3v3 terrain réduit',
    category: 'Jeu',
    duration: 18,
    players: '6',
    description: 'Terrain 25x18m, buts mini. Jeux de 2–3 minutes, rotations rapides. Objectif: transitions rapides.',
    tags: ['intensité', 'transition', 'duels']
  }
] as const

type Drill = typeof DRILLS[number]

app.get('/api/drills', authMiddleware, async (req: any, res) => {
  const q = (req.query.q as string | undefined)?.toLowerCase().trim()
  const cat = (req.query.category as string | undefined)?.toLowerCase().trim()
  const tag = (req.query.tag as string | undefined)?.toLowerCase().trim()

  let items: Drill[] = DRILLS.slice()
  if (q) {
    items = items.filter(d =>
      d.title.toLowerCase().includes(q) ||
      d.description.toLowerCase().includes(q) ||
      d.tags.some(t => t.toLowerCase().includes(q))
    )
  }
  if (cat) items = items.filter(d => d.category.toLowerCase() === cat)
  if (tag) items = items.filter(d => d.tags.map(t => t.toLowerCase()).includes(tag))

  res.json({
    items,
    categories: Array.from(new Set(DRILLS.map(d => d.category))).sort(),
    tags: Array.from(new Set(DRILLS.flatMap(d => d.tags))).sort()
  })
})

app.get('/api/drills/:id', authMiddleware, async (req: any, res) => {
  const d = DRILLS.find(x => x.id === req.params.id)
  if (!d) return res.status(404).json({ error: 'Not found' })
  res.json(d)
})
// Models used: Player, Training, Plateau, Attendance, Match, MatchTeam, MatchTeamPlayer, Scorer
// All endpoints are protected (same as plannings). Adjust if you want some public.

// ---- Players ----
app.get('/api/players', authMiddleware, async (_req: any, res) => {
  const players = await prisma.player.findMany({ orderBy: { name: 'asc' } })
  res.json(players)
})

app.post('/api/players', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    name: z.string().min(1),
    primary_position: z.string().min(1),
    secondary_position: z.string().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const p = await prisma.player.create({ data: parsed.data })
  res.json(p)
})

app.put('/api/players/:id', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    name: z.string().min(1).optional(),
    primary_position: z.string().optional(),
    secondary_position: z.string().nullable().optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { id } = req.params
  try {
    const updated = await prisma.player.update({ where: { id }, data: parsed.data as any })
    res.json(updated)
  } catch {
    res.status(404).json({ error: 'Player not found' })
  }
})

app.delete('/api/players/:id', authMiddleware, async (req: any, res) => {
  const { id } = req.params
  try {
    // Ensure the player exists first
    const exists = await prisma.player.findUnique({ where: { id } })
    if (!exists) return res.status(404).json({ error: 'Player not found' })

    await prisma.$transaction([
      prisma.scorer.deleteMany({ where: { playerId: id } }),
      prisma.matchTeamPlayer.deleteMany({ where: { playerId: id } }),
      prisma.attendance.deleteMany({ where: { playerId: id } }),
      prisma.player.delete({ where: { id } })
    ])
    res.json({ ok: true })
  } catch (e: any) {
    console.error('[DELETE /api/players/:id] failed', e)
    // If it still fails due to referential integrity, surface 409
    return res.status(409).json({ error: 'Cannot delete player due to related data' })
  }
})

// ---- Trainings ----
app.get('/api/trainings', authMiddleware, async (_req: any, res) => {
  const trainings = await prisma.training.findMany({ orderBy: { date: 'desc' } })
  res.json(trainings)
})


app.post('/api/trainings', authMiddleware, async (req: any, res) => {
  const schema = z.object({ date: z.string().or(z.date()) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const date = new Date(parsed.data.date as any)
  const t = await prisma.training.create({ data: { date } })
  res.json(t)
})

// Update a training (date/status)
app.put('/api/trainings/:id', authMiddleware, async (req: any, res) => {
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
    const updated = await prisma.training.update({ where: { id: req.params.id }, data })
    res.json(updated)
  } catch (e: any) {
    if (e?.code === 'P2025') {
      return res.status(404).json({ error: 'Training not found' })
    }
    console.error('[PUT /api/trainings/:id] update failed', e)
    return res.status(500).json({ error: 'Failed to update training' })
  }
})

// Delete a training (and clean related attendance + drills)
app.delete('/api/trainings/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    await prisma.$transaction([
      prisma.attendance.deleteMany({ where: { session_type: 'TRAINING', session_id: id } }),
      prisma.trainingDrill.deleteMany({ where: { trainingId: id } }),
      prisma.training.delete({ where: { id } })
    ])
    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') {
      return res.status(404).json({ error: 'Training not found' })
    }
    console.error('[DELETE /api/trainings/:id] delete failed', e)
    return res.status(500).json({ error: 'Failed to delete training' })
  }
})

// ---- Plateaus ----
app.get('/api/plateaus', authMiddleware, async (_req: any, res) => {
  const plateaus = await prisma.plateau.findMany({ orderBy: { date: 'desc' } })
  res.json(plateaus)
})


app.post('/api/plateaus', authMiddleware, async (req: any, res) => {
  const schema = z.object({ date: z.string().or(z.date()), lieu: z.string().min(1) })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const date = new Date(parsed.data.date as any)
  const pl = await prisma.plateau.create({ data: { date, lieu: parsed.data.lieu } })
  res.json(pl)
})

app.delete('/api/plateaus/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    // Ensure plateau exists
    const exists = await prisma.plateau.findUnique({ where: { id } })
    if (!exists) return res.status(404).json({ error: 'Plateau not found' })

    // Collect related matches and teams
    const matches = await prisma.match.findMany({ where: { plateauId: id }, include: { teams: true } })
    const matchIds = matches.map(m => m.id)
    const teamIds = matches.flatMap(m => m.teams.map(t => t.id))

    await prisma.$transaction([
      prisma.scorer.deleteMany({ where: { matchId: { in: matchIds } } }),
      prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
      prisma.matchTeam.deleteMany({ where: { matchId: { in: matchIds } } }),
      prisma.match.deleteMany({ where: { id: { in: matchIds } } }),
      prisma.attendance.deleteMany({ where: { session_type: 'PLATEAU', session_id: id } }),
      prisma.plateau.delete({ where: { id } })
    ])

    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Plateau not found' })
    console.error('[DELETE /api/plateaus/:id] failed', e)
    return res.status(500).json({ error: 'Failed to delete plateau' })
  }
})

// ---- Attendance (TRAINING / PLATEAU) ----
app.get('/api/attendance', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    session_type: z.enum(['TRAINING', 'PLATEAU']).optional(),
    session_id: z.string().optional()
  })
  const parsed = schema.safeParse(req.query)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { session_type, session_id } = parsed.data
  const where: any = {}
  if (session_type) where.session_type = session_type
  if (session_id) where.session_id = session_id
  const rows = await prisma.attendance.findMany({ where })
  res.json(rows)
})
app.post('/api/attendance', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    session_type: z.enum(['TRAINING', 'PLATEAU']),
    session_id: z.string(),
    playerId: z.string(),
    present: z.boolean().default(true)
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { session_type, session_id, playerId, present } = parsed.data
  if (present) {
    await prisma.attendance.upsert({
      where: { session_type_session_id_playerId: { session_type, session_id, playerId } },
      create: { session_type, session_id, playerId },
      update: {}
    })
  } else {
    await prisma.attendance.deleteMany({ where: { session_type, session_id, playerId } })
  }
  res.json({ ok: true })
})

// ---- Matches ----
app.get('/api/matches', authMiddleware, async (req: any, res) => {
  const { plateauId } = req.query as { plateauId?: string }
  const where = plateauId ? { plateauId: String(plateauId) } : {}
  const matches = await prisma.match.findMany({
    where,
    include: { teams: { include: { players: { include: { player: true } } } }, scorers: true },
    orderBy: { createdAt: 'desc' }
  })
  res.json(matches)
})

app.post('/api/matches', authMiddleware, async (req: any, res) => {
  const schema = z.object({
    type: z.enum(['ENTRAINEMENT', 'PLATEAU']),
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
    buteurs: z.array(z.object({ playerId: z.string(), side: z.enum(['home', 'away']) })).optional(),
    opponentName: z.string().min(1).max(100).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const { type, plateauId, sides, score, buteurs, opponentName } = parsed.data

  const match = await prisma.match.create({ data: { type, plateauId, opponentName } })
  const home = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'home', score: score?.home ?? 0 } })
  const away = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'away', score: score?.away ?? 0 } })

  const toMTP = (matchTeamId: string, ids: string[], role: 'starter' | 'sub') => ids.map(playerId => ({ matchTeamId, playerId, role }))
  const mtps = [
    ...toMTP(home.id, sides.home.starters, 'starter'),
    ...toMTP(home.id, sides.home.subs, 'sub'),
    ...toMTP(away.id, sides.away.starters, 'starter'),
    ...toMTP(away.id, sides.away.subs, 'sub'),
  ]
  if (mtps.length) await prisma.matchTeamPlayer.createMany({ data: mtps, skipDuplicates: true })

  if (buteurs?.length) {
    await prisma.scorer.createMany({ data: buteurs.map(b => ({ matchId: match.id, playerId: b.playerId, side: b.side })) })
  }

  const full = await prisma.match.findUnique({
    where: { id: match.id },
    include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
  })
  res.json(full)
})

// Update a match: score, opponentName, and (optionally) scorers (replace all)
app.put('/api/matches/:id', authMiddleware, async (req: any, res) => {
  const matchId = req.params.id
  const schema = z.object({
    score: z.object({ home: z.number().int().min(0), away: z.number().int().min(0) }).optional(),
    opponentName: z.string().min(1).max(100).optional(),
    buteurs: z.array(z.object({ playerId: z.string(), side: z.enum(['home', 'away']) })).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  try {
    // ensure exists
    const exists = await prisma.match.findUnique({ where: { id: matchId } })
    if (!exists) return res.status(404).json({ error: 'Match not found' })

    // update fields
    if (parsed.data.opponentName !== undefined) {
      await prisma.match.update({ where: { id: matchId }, data: { opponentName: parsed.data.opponentName } })
    }
    if (parsed.data.score) {
      await prisma.$transaction([
        prisma.matchTeam.updateMany({ where: { matchId, side: 'home' }, data: { score: parsed.data.score.home } }),
        prisma.matchTeam.updateMany({ where: { matchId, side: 'away' }, data: { score: parsed.data.score.away } }),
      ])
    }
    if (parsed.data.buteurs) {
      await prisma.$transaction([
        prisma.scorer.deleteMany({ where: { matchId } }),
        prisma.scorer.createMany({ data: parsed.data.buteurs.map(b => ({ matchId, playerId: b.playerId, side: b.side })) })
      ])
    }

    const full = await prisma.match.findUnique({
      where: { id: matchId },
      include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
    })
    res.json(full)
  } catch (e) {
    console.error('[PUT /api/matches/:id] failed', e)
    return res.status(500).json({ error: 'Failed to update match' })
  }
})

// Delete a match (cascade delete teams, players, scorers)
app.delete('/api/matches/:id', authMiddleware, async (req: any, res) => {
  const id = req.params.id
  try {
    const exists = await prisma.match.findUnique({ where: { id } })
    if (!exists) return res.status(404).json({ error: 'Match not found' })

    const teams = await prisma.matchTeam.findMany({ where: { matchId: id } })
    const teamIds = teams.map(t => t.id)

    await prisma.$transaction([
      prisma.scorer.deleteMany({ where: { matchId: id } }),
      prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
      prisma.matchTeam.deleteMany({ where: { matchId: id } }),
      prisma.match.delete({ where: { id } })
    ])

    res.json({ ok: true })
  } catch (e) {
    console.error('[DELETE /api/matches/:id] failed', e)
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

app.post('/api/schedule/generate', authMiddleware, async (req: any, res) => {
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
app.post('/api/schedule/commit', authMiddleware, async (req: any, res) => {
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

  const createdIds = await prisma.$transaction(async (db) => {
    const ids: string[] = []
    for (const m of schedule.matches) {
      const match = await db.match.create({ data: { type: plateauId ? 'PLATEAU' : 'ENTRAINEMENT', plateauId } })
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
      if (rows.length) await db.matchTeamPlayer.createMany({ data: rows, skipDuplicates: true })
      ids.push(match.id)
    }
    return ids
  })

  const matches = await prisma.match.findMany({
    where: { id: { in: createdIds } },
    include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
  })

  res.json({ ok: true, createdCount: createdIds.length, matches })
})

// ---- Training drills (exercices attachés à une séance) ----

// Lister les exercices d'une séance (avec enrichissement à partir du catalogue DRILLS)
app.get('/api/trainings/:id/drills', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const rows = await prisma.trainingDrill.findMany({
    where: { trainingId },
    orderBy: { order: 'asc' },
  })
  const items = rows.map(r => {
    const meta = (DRILLS as readonly any[]).find(d => d.id === r.drillId) || null
    return { ...r, meta }
  })
  res.json(items)
})

// Ajouter un exercice à une séance
app.post('/api/trainings/:id/drills', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const schema = z.object({
    drillId: z.string().min(1),
    duration: z.number().int().min(1).max(120).optional(),
    notes: z.string().max(1000).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  // order auto-incrémental simple
  const max = await prisma.trainingDrill.aggregate({
    where: { trainingId },
    _max: { order: true }
  })
  const nextOrder = (max._max.order ?? -1) + 1

  const row = await prisma.trainingDrill.create({
    data: { trainingId, drillId: parsed.data.drillId, duration: parsed.data.duration, notes: parsed.data.notes, order: nextOrder }
  })
  const meta = (DRILLS as readonly any[]).find(d => d.id === row.drillId) || null
  res.json({ ...row, meta })
})

// Modifier (notes/duration/order)
app.put('/api/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req: any, res) => {
  const trainingId = req.params.id
  const trainingDrillId = req.params.trainingDrillId
  const schema = z.object({
    duration: z.number().int().min(1).max(120).nullable().optional(),
    notes: z.string().max(1000).nullable().optional(),
    order: z.number().int().min(0).optional()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })

  try {
    const updated = await prisma.trainingDrill.update({
      where: { id: trainingDrillId },
      data: {
        ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration ?? null } : {}),
        ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes ?? null } : {}),
        ...(parsed.data.order !== undefined ? { order: parsed.data.order } : {})
      }
    })
    const meta = (DRILLS as readonly any[]).find(d => d.id === updated.drillId) || null
    res.json({ ...updated, meta })
  } catch {
    res.status(404).json({ error: 'Not found' })
  }
})

// Supprimer un exercice d'une séance
app.delete('/api/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req: any, res) => {
  const trainingDrillId = req.params.trainingDrillId
  try {
    await prisma.trainingDrill.delete({ where: { id: trainingDrillId } })
    res.json({ ok: true })
  } catch {
    res.status(404).json({ error: 'Not found' })
  }
})

// ---- Diagrams (exercices) ----
app.get('/api/drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const drillId = req.params.id
  const rows = await prisma.diagram.findMany({ where: { drillId }, orderBy: { updatedAt: 'desc' } })
  res.json(rows)
})

app.get('/api/training-drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const trainingDrillId = req.params.id
  const rows = await prisma.diagram.findMany({ where: { trainingDrillId }, orderBy: { updatedAt: 'desc' } })
  res.json(rows)
})

app.get('/api/diagrams/:id', authMiddleware, async (req: any, res) => {
  const d = await prisma.diagram.findUnique({ where: { id: req.params.id } })
  if (!d) return res.status(404).json({ error: 'Not found' })
  res.json(d)
})

app.post('/api/drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const drillId = req.params.id
  const schema = z.object({
    title: z.string().min(1).max(100),
    data: z.any() // JSON
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const created = await prisma.diagram.create({
    data: { drillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data) }
  })
  res.json({ ...created, data: parsed.data.data })
})

app.post('/api/training-drills/:id/diagrams', authMiddleware, async (req: any, res) => {
  const trainingDrillId = req.params.id
  const schema = z.object({
    title: z.string().min(1).max(100),
    data: z.any()
  })
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() })
  const created = await prisma.diagram.create({
    data: { trainingDrillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data) }
  })
  res.json({ ...created, data: parsed.data.data })
})

app.put('/api/diagrams/:id', authMiddleware, async (req: any, res) => {
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
    const updated = await prisma.diagram.update({ where: { id: req.params.id }, data: patch })
    res.json({ ...updated, data: parsed.data.data ?? JSON.parse(updated.data) })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Not found' })
    console.error('[PUT /api/diagrams/:id] failed', e)
    return res.status(500).json({ error: 'Failed to update diagram' })
  }
})

app.delete('/api/diagrams/:id', authMiddleware, async (req: any, res) => {
  try {
    await prisma.diagram.delete({ where: { id: req.params.id } })
    res.json({ ok: true })
  } catch (e: any) {
    if (e?.code === 'P2025') return res.status(404).json({ error: 'Not found' })
    console.error('[DELETE /api/diagrams/:id] failed', e)
    return res.status(500).json({ error: 'Failed to delete diagram' })
  }
})
// === END FOOT DOMAIN API ===

app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`)
})