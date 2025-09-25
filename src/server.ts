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
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  })
}

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

app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`)
})