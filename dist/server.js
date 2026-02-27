"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const client_1 = require("@prisma/client");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const nanoid_1 = require("nanoid");
const qrcode_1 = __importDefault(require("qrcode"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const date_fns_1 = require("date-fns");
const app = (0, express_1.default)();
const prisma = new client_1.PrismaClient();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const IS_PROD = process.env.NODE_ENV === 'production';
const DEFAULT_DEV_APP_BASE_URL = 'http://localhost:5173';
const APP_BASE_URL = process.env.APP_BASE_URL || DEFAULT_DEV_APP_BASE_URL;
const API_BASE_URL = process.env.API_BASE_URL || `http://localhost:${PORT}`;
const AUTH_COOKIE_NAME = 'token';
// Railway/Reverse proxy support so secure cookies can be set correctly.
app.set('trust proxy', 1);
function toOrigin(raw) {
    const s = raw.trim();
    if (!s)
        return null;
    try {
        return new URL(s).origin;
    }
    catch {
        return null;
    }
}
function toWildcardRule(raw) {
    const s = raw.trim();
    if (!s.includes('*'))
        return null;
    const m = s.match(/^(https?):\/\/\*\.(.+?)(?::(\d+))?$/i);
    if (!m)
        return null;
    return {
        protocol: m[1].toLowerCase(),
        hostnameSuffix: m[2].toLowerCase(),
        port: m[3] || '',
    };
}
const exactFrontOrigins = new Set();
const wildcardFrontOrigins = [];
const configuredFrontOrigins = [
    ...(IS_PROD ? [] : [APP_BASE_URL]),
    ...(!IS_PROD && !process.env.APP_BASE_URL ? [] : [process.env.APP_BASE_URL || '']),
    ...(process.env.APP_BASE_URLS || '').split(','),
];
for (const rawOrigin of configuredFrontOrigins) {
    const wildcardRule = toWildcardRule(rawOrigin);
    if (wildcardRule) {
        wildcardFrontOrigins.push(wildcardRule);
        continue;
    }
    const normalizedOrigin = toOrigin(rawOrigin);
    if (!normalizedOrigin)
        continue;
    exactFrontOrigins.add(normalizedOrigin);
    const u = new URL(normalizedOrigin);
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
        const port = u.port || '5173';
        exactFrontOrigins.add(`http://localhost:${port}`);
        exactFrontOrigins.add(`http://127.0.0.1:${port}`);
        exactFrontOrigins.add(`https://localhost:${port}`);
        exactFrontOrigins.add(`https://127.0.0.1:${port}`);
    }
}
function isAllowedOrigin(origin) {
    if (exactFrontOrigins.has(origin))
        return true;
    let parsed;
    try {
        parsed = new URL(origin);
    }
    catch {
        return false;
    }
    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.replace(/:$/, '').toLowerCase();
    const port = parsed.port || '';
    return wildcardFrontOrigins.some((rule) => {
        if (!rule)
            return false;
        if (rule.protocol !== protocol)
            return false;
        if (rule.port !== port)
            return false;
        if (hostname === rule.hostnameSuffix)
            return false;
        return hostname.endsWith(`.${rule.hostnameSuffix}`);
    });
}
if (IS_PROD && exactFrontOrigins.size === 0 && wildcardFrontOrigins.length === 0) {
    console.warn('[cors] No front-end origin configured. Set APP_BASE_URL or APP_BASE_URLS in production.');
}
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)({
    origin(origin, callback) {
        if (!origin)
            return callback(null, true);
        if (isAllowedOrigin(origin))
            return callback(null, true);
        console.warn(`[cors] Blocked origin: ${origin}`);
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
}));
app.use(express_1.default.json({ limit: '1mb' }));
app.use((0, cookie_parser_1.default)());
app.use((0, morgan_1.default)('dev'));
// Anti-cache pour l'API (évite les 304 Not Modified sur GET protégés)
app.set('etag', false);
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    // Important si tu utilises Authorization ou cookies
    res.setHeader('Vary', 'Authorization, Origin');
    next();
});
// --- Cookie helper for robust cross-site cookie options ---
function authCookieOpts() {
    const isProd = process.env.NODE_ENV === 'production';
    const sameSite = isProd ? 'none' : 'lax';
    return {
        httpOnly: true,
        sameSite,
        secure: isProd,
        path: '/',
        maxAge: 7 * 24 * 3600 * 1000
    };
}
function authClearCookieOpts() {
    const { maxAge, ...opts } = authCookieOpts();
    return opts;
}
function playerCookieOpts() {
    const isProd = process.env.NODE_ENV === 'production';
    const sameSite = isProd ? 'none' : 'lax';
    return {
        httpOnly: true,
        sameSite,
        secure: isProd,
        path: '/',
        maxAge: 30 * 24 * 3600 * 1000
    };
}
// --- Auth helpers ---
function signToken(userId) {
    return jsonwebtoken_1.default.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' });
}
function authMiddleware(req, res, next) {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!token)
        return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.userId = payload.sub;
        next();
    }
    catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
// --- Nodemailer (optional) ---
let transporter = null;
const SMTP_URL = process.env.SMTP_URL;
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
try {
    if (SMTP_URL) {
        transporter = nodemailer_1.default.createTransport(SMTP_URL);
    }
    else if (SMTP_HOST && SMTP_HOST !== 'smtp.example.com') {
        transporter = nodemailer_1.default.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_SECURE,
            auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
            connectionTimeout: 10000,
        });
    }
    else if (SMTP_HOST === 'smtp.example.com') {
        console.warn('[smtp] Placeholder SMTP_HOST detected (smtp.example.com). Email notifications disabled. Set real creds or unset SMTP_HOST.');
    }
    if (transporter) {
        // Verify at startup; if it fails, disable transporter to avoid noisy errors at runtime.
        transporter.verify().then(() => {
            console.log('[smtp] Transport ready');
        }).catch((err) => {
            console.warn('[smtp] Verification failed. Disabling email notifications.', err?.message || err);
            transporter = null;
        });
    }
}
catch (e) {
    console.warn('[smtp] Failed to initialize transporter. Email notifications disabled.', e?.message || e);
    transporter = null;
}
// --- Waitlist helpers (in‑memory) ---
const waitlistSeen = new Map(); // email -> timestamp
const WAITLIST_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutes
function normEmail(e) { return e.trim().toLowerCase(); }
// --- Routes ---
function safeParseJSON(s) {
    if (!s)
        return null;
    try {
        return JSON.parse(s);
    }
    catch {
        return null;
    }
}
app.post('/auth/register', async (req, res) => {
    const schema = zod_1.z.object({ email: zod_1.z.string().email(), password: zod_1.z.string().min(6) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { email, password } = parsed.data;
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
        return res.status(409).json({ error: 'Email already in use' });
    const passwordHash = await bcryptjs_1.default.hash(password, 10);
    const user = await prisma.user.create({ data: { email, passwordHash } });
    const token = signToken(user.id);
    res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts());
    res.json({ id: user.id, email: user.email, isPremium: user.isPremium });
});
app.post('/auth/login', async (req, res) => {
    const schema = zod_1.z.object({ email: zod_1.z.string().email(), password: zod_1.z.string() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { email, password } = parsed.data;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
        return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcryptjs_1.default.compare(password, user.passwordHash);
    if (!ok)
        return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken(user.id);
    res.cookie(AUTH_COOKIE_NAME, token, authCookieOpts());
    res.json({ id: user.id, email: user.email, isPremium: user.isPremium });
});
app.post('/auth/logout', (req, res) => {
    res.clearCookie(AUTH_COOKIE_NAME, authClearCookieOpts());
    res.json({ ok: true });
});
app.get('/me', authMiddleware, async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } });
    if (!user)
        return res.status(404).json({ error: 'User not found' });
    const planningCount = user.plannings.length;
    res.json({ id: user.id, email: user.email, isPremium: user.isPremium, planningCount });
});
// Collect waitlist emails
app.post('/waitlist', async (req, res) => {
    try {
        const schema = zod_1.z.object({ email: zod_1.z.string().email(), source: zod_1.z.string().optional() });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json({ error: parsed.error.flatten() });
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
            }
            catch (err) {
                console.error('Failed to send waitlist email', err);
                // Non-fatal; continue
            }
        }
        else {
            console.log('[waitlist] new signup (no SMTP configured):', { email });
        }
        return res.json({ ok: true });
    }
    catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Internal error' });
    }
});
// FREE TIER RULE: non-premium users can create **one planning total** (for any chosen date). They can update it, but not create a second one.
app.post('/plannings', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ date: zod_1.z.string(), data: zod_1.z.any() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { date, data } = parsed.data;
    const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { plannings: true } });
    if (!user)
        return res.status(404).json({ error: 'User not found' });
    if (!user.isPremium && user.plannings.length >= 1) {
        return res.status(402).json({ error: 'Free tier: only one planning allowed. Upgrade to premium.' });
    }
    const isoDate = new Date(date);
    const existsForDate = await prisma.planning.findFirst({ where: { userId: user.id, date: isoDate } });
    if (existsForDate)
        return res.status(409).json({ error: 'Planning already exists for this date' });
    const planning = await prisma.planning.create({ data: { userId: user.id, date: isoDate, data: JSON.stringify(data) } });
    res.json({ ...planning, data });
});
app.get('/plannings', authMiddleware, async (req, res) => {
    const plans = await prisma.planning.findMany({ where: { userId: req.userId }, orderBy: { date: 'asc' } });
    const mapped = plans.map((p) => ({ ...p, data: safeParseJSON(p.data) }));
    res.json(mapped);
});
app.get('/plannings/:id', authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    res.json({ ...p, data: safeParseJSON(p.data) });
});
app.put('/plannings/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ data: zod_1.z.any() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    const updated = await prisma.planning.update({ where: { id: p.id }, data: { data: JSON.stringify(parsed.data.data) } });
    res.json({ ...updated, data: parsed.data.data });
});
app.delete('/plannings/:id', authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    await prisma.shareToken.deleteMany({ where: { planningId: p.id } });
    await prisma.planning.delete({ where: { id: p.id } });
    res.json({ ok: true });
});
// Sharing: create a share token (optional email)
app.post('/plannings/:id/share', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ expiresInDays: zod_1.z.number().int().min(1).max(365).optional(), email: zod_1.z.string().email().optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    const token = (0, nanoid_1.nanoid)(24);
    const expiresAt = parsed.data.expiresInDays ? (0, date_fns_1.addDays)(new Date(), parsed.data.expiresInDays) : null;
    const share = await prisma.shareToken.create({ data: { planningId: p.id, token, expiresAt: expiresAt ?? undefined } });
    const url = `${API_BASE_URL}/s/${token}`;
    if (parsed.data.email && transporter) {
        await transporter.sendMail({
            from: process.env.SMTP_FROM || 'no-reply@example.com',
            to: parsed.data.email,
            subject: 'Partage de planning U9',
            text: `Consultez le planning : ${url}`,
            html: `<p>Consultez le planning :</p><p><a href="${url}">${url}</a></p>`
        });
    }
    res.json({ token, url, expiresAt });
});
// Public share endpoint
app.get('/s/:token', async (req, res) => {
    const s = await prisma.shareToken.findUnique({ where: { token: req.params.token }, include: { planning: true } });
    if (!s)
        return res.status(404).json({ error: 'Invalid link' });
    if (s.expiresAt && s.expiresAt < new Date())
        return res.status(410).json({ error: 'Link expired' });
    res.json({ planning: { ...s.planning, data: safeParseJSON(s.planning.data) } });
});
// QR code PNG for sharing URL
app.get('/plannings/:id/qr', authMiddleware, async (req, res) => {
    const p = await prisma.planning.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!p)
        return res.status(404).json({ error: 'Not found' });
    const existing = await prisma.shareToken.findFirst({ where: { planningId: p.id }, orderBy: { createdAt: 'asc' } });
    let token = existing?.token;
    if (!token) {
        token = (0, nanoid_1.nanoid)(24);
        await prisma.shareToken.create({ data: { planningId: p.id, token } });
    }
    const url = `${API_BASE_URL}/s/${token}`;
    const png = await qrcode_1.default.toBuffer(url, { width: 512 });
    res.type('image/png').send(png);
});
const EXTRA_DRILLS = [];
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
];
app.get('/drills', authMiddleware, async (req, res) => {
    const q = req.query.q?.toLowerCase().trim();
    const cat = req.query.category?.toLowerCase().trim();
    const tag = req.query.tag?.toLowerCase().trim();
    let items = DRILLS.concat(EXTRA_DRILLS);
    if (q) {
        items = items.filter(d => d.title.toLowerCase().includes(q) ||
            d.description.toLowerCase().includes(q) ||
            d.tags.some(t => t.toLowerCase().includes(q)));
    }
    if (cat)
        items = items.filter(d => d.category.toLowerCase() === cat);
    if (tag)
        items = items.filter(d => d.tags.map(t => t.toLowerCase()).includes(tag));
    res.json({
        items,
        categories: Array.from(new Set(DRILLS.map(d => d.category))).sort(),
        tags: Array.from(new Set(DRILLS.flatMap(d => d.tags))).sort()
    });
});
app.get('/drills/:id', authMiddleware, async (req, res) => {
    const d = DRILLS.find(x => x.id === req.params.id) || EXTRA_DRILLS.find(x => x.id === req.params.id);
    if (!d)
        return res.status(404).json({ error: 'Not found' });
    res.json(d);
});
app.post('/drills', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        category: zod_1.z.string().min(1).max(50),
        duration: zod_1.z.number().int().min(1).max(180),
        players: zod_1.z.string().min(1).max(50),
        description: zod_1.z.string().min(1).max(2000),
        tags: zod_1.z.array(zod_1.z.string().min(1).max(32)).max(20).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    // naive unique id; ensure no collision with seed ones
    const base = parsed.data.title.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
    let id = `d_${base || 'new'}`;
    let i = 1;
    while (DRILLS.some(d => d.id === id) || EXTRA_DRILLS.some(d => d.id === id)) {
        id = `d_${base}_${i++}`;
    }
    const drill = {
        id,
        title: parsed.data.title,
        category: parsed.data.category,
        duration: parsed.data.duration,
        players: parsed.data.players,
        description: parsed.data.description,
        tags: (parsed.data.tags && parsed.data.tags.length) ? parsed.data.tags : []
    };
    EXTRA_DRILLS.push(drill);
    res.status(201).json(drill);
});
// Models used: Player, Training, Plateau, Attendance, Match, MatchTeam, MatchTeamPlayer, Scorer
// All endpoints are protected (same as plannings). Adjust if you want some public.
// ---- Players ----
app.get('/players', authMiddleware, async (req, res) => {
    const players = await prisma.player.findMany({ where: { userId: req.userId }, orderBy: { name: 'asc' } });
    res.json(players);
});
app.post('/players', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        name: zod_1.z.string().min(1),
        primary_position: zod_1.z.string().min(1),
        secondary_position: zod_1.z.string().optional(),
        email: zod_1.z.string().email().optional(),
        phone: zod_1.z.string().min(5).max(32).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const baseData = {
        userId: req.userId,
        name: parsed.data.name,
        primary_position: parsed.data.primary_position,
        secondary_position: parsed.data.secondary_position
    };
    if ('email' in parsed.data)
        baseData.email = parsed.data.email;
    if ('phone' in parsed.data)
        baseData.phone = parsed.data.phone;
    let p;
    try {
        p = await prisma.player.create({ data: baseData });
    }
    catch (e) {
        // Fallback if schema lacks columns: remove and retry
        const fallback = { name: baseData.name, primary_position: baseData.primary_position };
        if (baseData.secondary_position !== undefined)
            fallback.secondary_position = baseData.secondary_position;
        p = await prisma.player.create({ data: fallback });
    }
    res.json(p);
});
app.put('/players/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        name: zod_1.z.string().min(1).optional(),
        primary_position: zod_1.z.string().optional(),
        secondary_position: zod_1.z.string().nullable().optional(),
        email: zod_1.z.string().email().nullable().optional(),
        phone: zod_1.z.string().min(5).max(32).nullable().optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { id } = req.params;
    const existing = await prisma.player.findFirst({ where: { id, userId: req.userId } });
    if (!existing)
        return res.status(404).json({ error: 'Player not found' });
    const patch = {};
    if (parsed.data.name !== undefined)
        patch.name = parsed.data.name;
    if (parsed.data.primary_position !== undefined)
        patch.primary_position = parsed.data.primary_position;
    if (parsed.data.secondary_position !== undefined)
        patch.secondary_position = parsed.data.secondary_position;
    if ('email' in parsed.data)
        patch.email = parsed.data.email ?? null;
    if ('phone' in parsed.data)
        patch.phone = parsed.data.phone ?? null;
    let updated;
    try {
        updated = await prisma.player.update({ where: { id: existing.id }, data: patch });
    }
    catch (e) {
        // Retry without email/phone if columns absent
        const fallback = { ...patch };
        delete fallback.email;
        delete fallback.phone;
        updated = await prisma.player.update({ where: { id: existing.id }, data: fallback });
    }
    res.json(updated);
});
// --- Player invite JWT and playerAuth ---
function signPlayerInvite(playerId, plateauId, email) {
    return jsonwebtoken_1.default.sign({ aud: 'player_invite', pid: playerId, plid: plateauId || null, em: email || null }, JWT_SECRET, { expiresIn: '30d' });
}
function signRsvpToken(playerId, plateauId, status) {
    return jsonwebtoken_1.default.sign({ aud: 'player_rsvp', pid: playerId, plid: plateauId, st: status }, JWT_SECRET, { expiresIn: '60d' });
}
async function playerAuth(req, res, next) {
    const token = req.cookies?.player_token || req.headers['x-player-token'];
    if (!token)
        return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.status(401).json({ error: 'Invalid token' });
        const player = await prisma.player.findUnique({ where: { id: payload.pid }, select: { userId: true } });
        if (!player)
            return res.status(401).json({ error: 'Invalid token' });
        req.playerId = payload.pid;
        req.playerUserId = player.userId;
        req.scopePlateauId = payload.plid || null;
        next();
    }
    catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}
// --- Player invite endpoint ---
app.post('/players/:id/invite', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const schema = zod_1.z.object({ plateauId: zod_1.z.string().optional(), email: zod_1.z.string().email().optional() });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const player = await prisma.player.findFirst({ where: { id, userId: req.userId } });
    if (!player)
        return res.status(404).json({ error: 'Player not found' });
    const base = `${req.protocol}://${req.get('host')}`;
    const inviteEmail = parsed.data.email || player.email || null;
    if (!parsed.data.plateauId) {
        return res.status(400).json({ error: 'plateauId is required to generate RSVP links' });
    }
    const presentToken = signRsvpToken(id, parsed.data.plateauId, 'present');
    const absentToken = signRsvpToken(id, parsed.data.plateauId, 'absent');
    const presentUrl = `${base}/rsvp/p?token=${encodeURIComponent(presentToken)}`;
    const absentUrl = `${base}/rsvp/a?token=${encodeURIComponent(absentToken)}`;
    // Mark player as convoked for this plateau
    try {
        await prisma.attendance.upsert({
            where: { userId_session_type_session_id_playerId: { userId: req.userId, session_type: 'PLATEAU_CONVOKE', session_id: parsed.data.plateauId, playerId: id } },
            create: { userId: req.userId, session_type: 'PLATEAU_CONVOKE', session_id: parsed.data.plateauId, playerId: id },
            update: {},
        });
    }
    catch (e) {
        console.warn('[invite] failed to upsert convocation marker', e);
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
            });
        }
        catch (e) {
            console.warn('[invite] email failed:', e);
        }
    }
    res.json({ ok: true, presentUrl, absentUrl });
});
// --- Public endpoint to accept invite and set player_token cookie ---
app.get('/player/accept', async (req, res) => {
    const token = req.query.token;
    if (!token)
        return res.status(400).json({ error: 'Missing token' });
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.status(400).json({ error: 'Invalid token' });
        res.cookie('player_token', token, playerCookieOpts());
        const r = req.query.r;
        const redirectTo = (r && r.startsWith(APP_BASE_URL)) ? r : undefined;
        res.json({ ok: true, redirectTo });
    }
    catch {
        return res.status(400).json({ error: 'Invalid token' });
    }
});
app.get('/player/login', async (req, res) => {
    const token = req.query.token;
    const r = req.query.r || '';
    let redirectTo = process.env.PLAYER_PORTAL_REDIRECT || APP_BASE_URL;
    // If a custom redirect is provided and starts with APP_BASE_URL, use it
    if (r && r.startsWith(APP_BASE_URL))
        redirectTo = r;
    if (!token)
        return res.redirect(302, redirectTo);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_invite' || !payload?.pid)
            return res.redirect(302, redirectTo);
        res.cookie('player_token', token, playerCookieOpts());
        // If token is scoped to a plateau, send the user straight to that MatchDay
        if (payload?.plid) {
            const dest = `${APP_BASE_URL}/match-day/${payload.plid}`;
            return res.redirect(302, dest);
        }
        return res.redirect(302, redirectTo);
    }
    catch {
        return res.redirect(302, redirectTo);
    }
});
// --- RSVP endpoints ---
app.get('/rsvp/p', async (req, res) => {
    const token = req.query.token;
    const redirectBase = APP_BASE_URL;
    if (!token)
        return res.redirect(302, redirectBase);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_rsvp' || payload?.st !== 'present' || !payload?.pid || !payload?.plid) {
            return res.redirect(302, redirectBase);
        }
        const player = await prisma.player.findUnique({ where: { id: payload.pid }, select: { userId: true } });
        if (!player?.userId)
            return res.redirect(302, redirectBase);
        try {
            await prisma.attendance.upsert({
                where: { userId_session_type_session_id_playerId: { userId: player.userId, session_type: 'PLATEAU', session_id: payload.plid, playerId: payload.pid } },
                create: { userId: player.userId, session_type: 'PLATEAU', session_id: payload.plid, playerId: payload.pid, present: true },
                update: { present: true },
            });
        }
        catch (e) {
            // Fallback for schemas without `present` column
            try {
                // Mark present by ensuring a PLATEAU row exists
                await prisma.attendance.upsert({
                    where: { userId_session_type_session_id_playerId: { userId: player.userId, session_type: 'PLATEAU', session_id: payload.plid, playerId: payload.pid } },
                    create: { userId: player.userId, session_type: 'PLATEAU', session_id: payload.plid, playerId: payload.pid },
                    update: {},
                });
                // Remove any absence marker
                await prisma.attendance.deleteMany({ where: { userId: player.userId, session_type: 'PLATEAU_ABSENT', session_id: payload.plid, playerId: payload.pid } });
            }
            catch (e2) {
                // Ignore, always redirect anyway
            }
        }
        return res.redirect(302, `${redirectBase}/match-day/${payload.plid}?rsvp=present`);
    }
    catch {
        return res.redirect(302, redirectBase);
    }
});
app.get('/rsvp/a', async (req, res) => {
    const token = req.query.token;
    const redirectBase = APP_BASE_URL;
    if (!token)
        return res.redirect(302, redirectBase);
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (payload?.aud !== 'player_rsvp' || payload?.st !== 'absent' || !payload?.pid || !payload?.plid) {
            return res.redirect(302, redirectBase);
        }
        const player = await prisma.player.findUnique({ where: { id: payload.pid }, select: { userId: true } });
        if (!player?.userId)
            return res.redirect(302, redirectBase);
        try {
            await prisma.attendance.upsert({
                where: {
                    userId_session_type_session_id_playerId: {
                        userId: player.userId,
                        session_type: 'PLATEAU',
                        session_id: payload.plid,
                        playerId: payload.pid,
                    },
                },
                create: {
                    userId: player.userId,
                    session_type: 'PLATEAU',
                    session_id: payload.plid,
                    playerId: payload.pid,
                    present: false,
                },
                update: {
                    present: false,
                },
            });
        }
        catch (e) {
            // Fallback when `present` column doesn't exist: mark absence with a dedicated row
            try {
                // Remove any present marker for old schema
                await prisma.attendance.deleteMany({ where: { userId: player.userId, session_type: 'PLATEAU', session_id: payload.plid, playerId: payload.pid } });
                // Upsert an ABSENT marker
                await prisma.attendance.upsert({
                    where: {
                        userId_session_type_session_id_playerId: {
                            userId: player.userId,
                            session_type: 'PLATEAU_ABSENT',
                            session_id: payload.plid,
                            playerId: payload.pid,
                        },
                    },
                    create: {
                        userId: player.userId,
                        session_type: 'PLATEAU_ABSENT',
                        session_id: payload.plid,
                        playerId: payload.pid,
                    },
                    update: {},
                });
            }
            catch (err) {
                console.warn('[RSVP absent] fallback failed', err);
            }
        }
        return res.redirect(302, `${redirectBase}/match-day/${payload.plid}?rsvp=absent`);
    }
    catch {
        return res.redirect(302, redirectBase);
    }
});
// --- Debug route for cookie visibility ---
app.get('/player/debug', (req, res) => {
    res.json({ hasCookie: Boolean(req.cookies?.player_token), cookies: Object.keys(req.cookies || {}) });
});
// --- Scoped player endpoints ---
app.get('/player/me', playerAuth, async (req, res) => {
    const p = await prisma.player.findFirst({ where: { id: req.playerId, userId: req.playerUserId } });
    if (!p)
        return res.status(404).json({ error: 'Player not found' });
    res.json({ id: p.id, name: p.name || '', email: p.email || null, phone: p.phone || null });
});
app.get('/player/plateaus', playerAuth, async (req, res) => {
    const playerId = req.playerId;
    // Plateaus via attendance
    const att = await prisma.attendance.findMany({ where: { userId: req.playerUserId, session_type: 'PLATEAU', playerId }, select: { session_id: true } });
    const plateauIdsFromAttendance = Array.from(new Set(att.map(a => a.session_id)));
    // Plateaus via match participation
    const mtps = await prisma.matchTeamPlayer.findMany({ where: { playerId }, select: { matchTeamId: true } });
    const teamIds = mtps.map(m => m.matchTeamId);
    let plateauIdsFromMatches = [];
    if (teamIds.length) {
        const teams = await prisma.matchTeam.findMany({ where: { id: { in: teamIds } }, select: { matchId: true } });
        const matchIds = teams.map(t => t.matchId);
        if (matchIds.length) {
            const matches = await prisma.match.findMany({ where: { userId: req.playerUserId, id: { in: matchIds } }, select: { plateauId: true } });
            plateauIdsFromMatches = matches.map(m => m.plateauId).filter(Boolean);
        }
    }
    const set = new Set([...plateauIdsFromAttendance, ...plateauIdsFromMatches]);
    const ids = Array.from(set);
    if (!ids.length)
        return res.json([]);
    const plateaus = await prisma.plateau.findMany({ where: { userId: req.playerUserId, id: { in: ids } }, orderBy: { date: 'desc' } });
    res.json(plateaus);
});
app.get('/player/plateaus/:id/summary', playerAuth, async (req, res) => {
    const plateauId = req.params.id;
    // If token is scoped to a specific plateau, enforce it
    if (req.scopePlateauId && req.scopePlateauId !== plateauId)
        return res.status(403).json({ error: 'Forbidden' });
    // Reuse the same build as /plateaus/:id/summary
    const ctxRes = {};
    const fakeReq = { params: { id: plateauId }, userId: req.playerUserId };
    const fakeRes = {
        statusCode: 200,
        _json: null,
        status(c) { this.statusCode = c; return this; },
        json(v) { this._json = v; return this; }
    };
    await app._router.handle({ ...fakeReq, method: 'GET', url: `/plateaus/${plateauId}/summary` }, fakeRes, () => { });
    const summary = fakeRes._json;
    if (!summary || fakeRes.statusCode !== 200)
        return res.status(fakeRes.statusCode || 500).json(summary || { error: 'Failed' });
    // Check convocation: present in attendance OR in any team players
    const isConvocated = Boolean((summary.convocations || []).some((c) => c.player?.id === req.playerId) ||
        (summary.matches || []).some((m) => (m.teams || []).some((t) => (t.players || []).some((p) => p.playerId === req.playerId))));
    if (!isConvocated)
        return res.status(403).json({ error: 'Not convocated for this plateau' });
    // Optionally, we could filter convocations to only the player
    const filtered = { ...summary, convocations: (summary.convocations || []).filter((c) => c.player?.id === req.playerId) };
    res.json(filtered);
});
app.delete('/players/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        // Ensure the player exists first
        const exists = await prisma.player.findFirst({ where: { id, userId: req.userId } });
        if (!exists)
            return res.status(404).json({ error: 'Player not found' });
        await prisma.$transaction([
            prisma.scorer.deleteMany({ where: { playerId: id } }),
            prisma.matchTeamPlayer.deleteMany({ where: { playerId: id } }),
            prisma.attendance.deleteMany({ where: { userId: req.userId, playerId: id } }),
            prisma.player.delete({ where: { id: exists.id } })
        ]);
        res.json({ ok: true });
    }
    catch (e) {
        console.error('[DELETE /players/:id] failed', e);
        // If it still fails due to referential integrity, surface 409
        return res.status(409).json({ error: 'Cannot delete player due to related data' });
    }
});
// ---- Trainings ----
app.get('/trainings', authMiddleware, async (req, res) => {
    const trainings = await prisma.training.findMany({ where: { userId: req.userId }, orderBy: { date: 'desc' } });
    res.json(trainings);
});
// Get single training
app.get('/trainings/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const training = await prisma.training.findFirst({ where: { id, userId: req.userId } });
        if (!training)
            return res.status(404).json({ error: 'Training not found' });
        res.json(training);
    }
    catch (e) {
        console.error('[GET /trainings/:id] failed', e);
        return res.status(500).json({ error: 'Failed to fetch training' });
    }
});
app.post('/trainings', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ date: zod_1.z.string().or(zod_1.z.date()) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const date = new Date(parsed.data.date);
    const t = await prisma.training.create({ data: { userId: req.userId, date } });
    res.json(t);
});
// Update a training (date/status)
app.put('/trainings/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        date: zod_1.z.string().or(zod_1.z.date()).optional(),
        status: zod_1.z.enum(['PLANNED', 'CANCELLED']).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const data = {};
    if (parsed.data.date !== undefined)
        data.date = new Date(parsed.data.date);
    if (parsed.data.status !== undefined)
        data.status = parsed.data.status;
    try {
        const existing = await prisma.training.findFirst({ where: { id: req.params.id, userId: req.userId } });
        if (!existing)
            return res.status(404).json({ error: 'Training not found' });
        const updated = await prisma.training.update({ where: { id: existing.id }, data });
        res.json(updated);
    }
    catch (e) {
        if (e?.code === 'P2025') {
            return res.status(404).json({ error: 'Training not found' });
        }
        console.error('[PUT /trainings/:id] update failed', e);
        return res.status(500).json({ error: 'Failed to update training' });
    }
});
// Delete a training (and clean related attendance + drills)
app.delete('/trainings/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        const existing = await prisma.training.findFirst({ where: { id, userId: req.userId } });
        if (!existing)
            return res.status(404).json({ error: 'Training not found' });
        await prisma.$transaction([
            prisma.attendance.deleteMany({ where: { userId: req.userId, session_type: 'TRAINING', session_id: id } }),
            prisma.trainingDrill.deleteMany({ where: { userId: req.userId, trainingId: id } }),
            prisma.training.delete({ where: { id: existing.id } })
        ]);
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025') {
            return res.status(404).json({ error: 'Training not found' });
        }
        console.error('[DELETE /trainings/:id] delete failed', e);
        return res.status(500).json({ error: 'Failed to delete training' });
    }
});
// ---- Plateaus ----
app.get('/plateaus', authMiddleware, async (req, res) => {
    const plateaus = await prisma.plateau.findMany({ where: { userId: req.userId }, orderBy: { date: 'desc' } });
    res.json(plateaus);
});
app.post('/plateaus', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({ date: zod_1.z.string().or(zod_1.z.date()), lieu: zod_1.z.string().min(1) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const date = new Date(parsed.data.date);
    const pl = await prisma.plateau.create({ data: { userId: req.userId, date, lieu: parsed.data.lieu } });
    res.json(pl);
});
app.delete('/plateaus/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        // Ensure plateau exists
        const exists = await prisma.plateau.findFirst({ where: { id, userId: req.userId } });
        if (!exists)
            return res.status(404).json({ error: 'Plateau not found' });
        // Collect related matches and teams
        const matches = await prisma.match.findMany({ where: { userId: req.userId, plateauId: id }, include: { teams: true } });
        const matchIds = matches.map(m => m.id);
        const teamIds = matches.flatMap(m => m.teams.map(t => t.id));
        await prisma.$transaction([
            prisma.scorer.deleteMany({ where: { matchId: { in: matchIds } } }),
            prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
            prisma.matchTeam.deleteMany({ where: { matchId: { in: matchIds } } }),
            prisma.match.deleteMany({ where: { id: { in: matchIds } } }),
            prisma.attendance.deleteMany({ where: { userId: req.userId, session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] }, session_id: id } }),
            prisma.plateau.delete({ where: { id: exists.id } })
        ]);
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Plateau not found' });
        console.error('[DELETE /plateaus/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete plateau' });
    }
});
// Get a single plateau by id
app.get('/plateaus/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const plateau = await prisma.plateau.findFirst({ where: { id, userId: req.userId } });
        if (!plateau)
            return res.status(404).json({ error: 'Plateau not found' });
        res.json(plateau);
    }
    catch (e) {
        console.error('[GET /plateaus/:id] failed', e);
        return res.status(500).json({ error: 'Failed to fetch plateau' });
    }
});
// Aggregated view for a match day (plateau)
app.get('/plateaus/:id/summary', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const plateau = await prisma.plateau.findFirst({ where: { id, userId: req.userId } });
        if (!plateau)
            return res.status(404).json({ error: 'Plateau not found' });
        // Attendance (present/absent records) for this plateau, include player info
        const attendance = await prisma.attendance.findMany({
            where: {
                userId: req.userId,
                session_id: id,
                session_type: { in: ['PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE'] },
            },
            include: { player: true }
        });
        // Build attendancePlayers and playersById from attendance
        const attendancePlayers = attendance.map(a => a.player).filter(Boolean);
        const playersById = {};
        for (const pl of attendancePlayers) {
            playersById[pl.id] = {
                id: pl.id,
                name: pl.name,
                primary_position: pl.primary_position ?? null,
                secondary_position: pl.secondary_position ?? null,
                email: pl.email ?? null,
                phone: pl.phone ?? null
            };
        }
        // Matches for this plateau (with teams and scorers first)
        const matchesRaw = await prisma.match.findMany({
            where: { userId: req.userId, plateauId: id },
            include: {
                teams: true,
                scorers: true
            },
            orderBy: { createdAt: 'asc' }
        });
        // Fetch all team players in one query and attach player objects
        const allTeamIds = matchesRaw.flatMap(m => m.teams.map(t => t.id));
        const mtPlayers = allTeamIds.length ? await prisma.matchTeamPlayer.findMany({
            where: { matchTeamId: { in: allTeamIds } },
            include: { player: true }
        }) : [];
        const byTeam = {};
        for (const row of mtPlayers) {
            if (!byTeam[row.matchTeamId])
                byTeam[row.matchTeamId] = [];
            byTeam[row.matchTeamId].push(row);
        }
        // Build enriched matches with teams[].players including player info
        const matches = matchesRaw.map(m => ({
            ...m,
            teams: m.teams.map(t => ({
                ...t,
                players: (byTeam[t.id] || []).map(p => ({
                    playerId: p.playerId,
                    role: p.role,
                    player: p.player
                }))
            }))
        }));
        // Hydrate playersById from match teams and build convocations
        const convocatedMap = {};
        for (const m of matches) {
            for (const t of m.teams) {
                for (const p of t.players) {
                    const pl = p.player;
                    if (pl) {
                        playersById[pl.id] = playersById[pl.id] || {
                            id: pl.id,
                            name: pl.name,
                            primary_position: pl.primary_position ?? null,
                            secondary_position: pl.secondary_position ?? null,
                            email: pl.email ?? null,
                            phone: pl.phone ?? null
                        };
                        if (!convocatedMap[pl.id])
                            convocatedMap[pl.id] = playersById[pl.id];
                    }
                }
            }
        }
        for (const pl of attendancePlayers) {
            if (!convocatedMap[pl.id])
                convocatedMap[pl.id] = playersById[pl.id];
        }
        // Ensure we know all players (for listing). We do not auto-mark as convoked.
        try {
            const allPlayers = await prisma.player.findMany({ where: { userId: req.userId }, orderBy: { name: 'asc' } });
            for (const pl of allPlayers) {
                if (!playersById[pl.id]) {
                    playersById[pl.id] = {
                        id: pl.id,
                        name: pl.name,
                        primary_position: pl.primary_position ?? null,
                        secondary_position: pl.secondary_position ?? null,
                        email: pl.email ?? null,
                        phone: pl.phone ?? null,
                    };
                }
            }
        }
        catch (e) {
            // If fetching all players fails for any reason, proceed with partial list
            console.warn('[summary] failed to include full players list', e?.message || e);
        }
        // Mark presence/absence and convocation using attendance
        const attendanceMap = new Map();
        const convokeSet = new Set();
        for (const a of attendance) {
            if (a.session_type === 'PLATEAU_CONVOKE') {
                convokeSet.add(a.playerId);
                continue;
            }
            if (a.present === true) {
                attendanceMap.set(a.playerId, true);
                continue;
            }
            if (a.present === false) {
                attendanceMap.set(a.playerId, false);
                continue;
            }
            // No `present` field: use session_type marker if available
            if (a.session_type === 'PLATEAU_ABSENT') {
                attendanceMap.set(a.playerId, false);
                continue;
            }
            // Old schema "present" implied by existence of PLATEAU row
            if (a.session_type === 'PLATEAU') {
                attendanceMap.set(a.playerId, true);
                continue;
            }
        }
        // Build convocations list for ALL players known in playersById
        const convocations = Object.values(playersById).map(pl => {
            const att = attendanceMap.get(pl.id);
            let status;
            if (att === true)
                status = 'present';
            else if (att === false)
                status = 'absent';
            else if (convokeSet.has(pl.id))
                status = 'convoque';
            else
                status = 'non_convoque';
            return { player: pl, status, present: status === 'present' };
        });
        // Add scorersDetailed to each match, resolving playerName from playersById
        const matchesEnriched = matches.map(m => ({
            ...m,
            scorersDetailed: m.scorers.map(s => ({
                ...s,
                playerName: playersById[s.playerId]?.name || null
            }))
        }));
        res.json({ plateau, convocations, matches: matchesEnriched, playersById });
    }
    catch (e) {
        console.error('[GET /plateaus/:id/summary] failed', e);
        return res.status(500).json({ error: 'Failed to fetch plateau summary' });
    }
});
// ---- Attendance (TRAINING / PLATEAU) ----
app.get('/attendance', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        session_type: zod_1.z.enum(['TRAINING', 'PLATEAU']).optional(),
        session_id: zod_1.z.string().optional()
    });
    const parsed = schema.safeParse(req.query);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { session_type, session_id } = parsed.data;
    const where = { userId: req.userId };
    if (session_type)
        where.session_type = session_type;
    if (session_id)
        where.session_id = session_id;
    const rows = await prisma.attendance.findMany({ where });
    res.json(rows);
});
app.post('/attendance', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        session_type: zod_1.z.enum(['TRAINING', 'PLATEAU']),
        session_id: zod_1.z.string(),
        playerId: zod_1.z.string(),
        present: zod_1.z.boolean().default(true)
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { session_type, session_id, playerId, present } = parsed.data;
    try {
        await prisma.attendance.upsert({
            where: { userId_session_type_session_id_playerId: { userId: req.userId, session_type, session_id, playerId } },
            create: { userId: req.userId, session_type, session_id, playerId, present },
            update: { present }
        });
    }
    catch (e) {
        // Fallback if `present` column doesn't exist
        if (present) {
            await prisma.attendance.upsert({
                where: { userId_session_type_session_id_playerId: { userId: req.userId, session_type, session_id, playerId } },
                create: { userId: req.userId, session_type, session_id, playerId },
                update: {}
            });
        }
        else {
            await prisma.attendance.deleteMany({ where: { userId: req.userId, session_type, session_id, playerId } });
        }
    }
    res.json({ ok: true });
});
// ---- Matches ----
app.get('/matches', authMiddleware, async (req, res) => {
    const { plateauId } = req.query;
    const where = plateauId ? { userId: req.userId, plateauId: String(plateauId) } : { userId: req.userId };
    const matches = await prisma.match.findMany({
        where,
        include: { teams: { include: { players: { include: { player: true } } } }, scorers: true },
        orderBy: { createdAt: 'desc' }
    });
    res.json(matches);
});
app.post('/matches', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        type: zod_1.z.enum(['ENTRAINEMENT', 'PLATEAU']),
        plateauId: zod_1.z.string().optional(),
        sides: zod_1.z.object({
            home: zod_1.z.object({
                starters: zod_1.z.array(zod_1.z.string()).default([]),
                subs: zod_1.z.array(zod_1.z.string()).default([])
            }).default({ starters: [], subs: [] }),
            away: zod_1.z.object({
                starters: zod_1.z.array(zod_1.z.string()).default([]),
                subs: zod_1.z.array(zod_1.z.string()).default([])
            }).default({ starters: [], subs: [] })
        }),
        score: zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) }).optional(),
        buteurs: zod_1.z.array(zod_1.z.object({ playerId: zod_1.z.string(), side: zod_1.z.enum(['home', 'away']) })).optional(),
        opponentName: zod_1.z.string().min(1).max(100).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { type, plateauId, sides, score, buteurs, opponentName } = parsed.data;
    if (plateauId) {
        const ownedPlateau = await prisma.plateau.findFirst({ where: { id: plateauId, userId: req.userId } });
        if (!ownedPlateau)
            return res.status(404).json({ error: 'Plateau not found' });
    }
    const match = await prisma.match.create({ data: { userId: req.userId, type, plateauId, opponentName } });
    const home = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'home', score: score?.home ?? 0 } });
    const away = await prisma.matchTeam.create({ data: { matchId: match.id, side: 'away', score: score?.away ?? 0 } });
    const toMTP = (matchTeamId, ids, role) => ids.map(playerId => ({ matchTeamId, playerId, role }));
    const mtps = [
        ...toMTP(home.id, sides.home.starters, 'starter'),
        ...toMTP(home.id, sides.home.subs, 'sub'),
        ...toMTP(away.id, sides.away.starters, 'starter'),
        ...toMTP(away.id, sides.away.subs, 'sub'),
    ];
    const uniqueMtps = Array.from(new Map(mtps.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values());
    if (uniqueMtps.length)
        await prisma.matchTeamPlayer.createMany({ data: uniqueMtps });
    if (buteurs?.length) {
        await prisma.scorer.createMany({ data: buteurs.map(b => ({ matchId: match.id, playerId: b.playerId, side: b.side })) });
    }
    const full = await prisma.match.findUnique({
        where: { id: match.id },
        include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
    });
    res.json(full);
});
// Update a match: score, opponentName, and (optionally) scorers (replace all)
app.put('/matches/:id', authMiddleware, async (req, res) => {
    const matchId = req.params.id;
    const schema = zod_1.z.object({
        score: zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) }).optional(),
        opponentName: zod_1.z.string().min(1).max(100).optional(),
        buteurs: zod_1.z.array(zod_1.z.object({ playerId: zod_1.z.string(), side: zod_1.z.enum(['home', 'away']) })).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    try {
        // ensure exists
        const exists = await prisma.match.findFirst({ where: { id: matchId, userId: req.userId } });
        if (!exists)
            return res.status(404).json({ error: 'Match not found' });
        // update fields
        if (parsed.data.opponentName !== undefined) {
            await prisma.match.update({ where: { id: exists.id }, data: { opponentName: parsed.data.opponentName } });
        }
        if (parsed.data.score) {
            await prisma.$transaction([
                prisma.matchTeam.updateMany({ where: { matchId, side: 'home' }, data: { score: parsed.data.score.home } }),
                prisma.matchTeam.updateMany({ where: { matchId, side: 'away' }, data: { score: parsed.data.score.away } }),
            ]);
        }
        if (parsed.data.buteurs) {
            await prisma.$transaction([
                prisma.scorer.deleteMany({ where: { matchId } }),
                prisma.scorer.createMany({ data: parsed.data.buteurs.map(b => ({ matchId, playerId: b.playerId, side: b.side })) })
            ]);
        }
        const full = await prisma.match.findFirst({
            where: { id: matchId, userId: req.userId },
            include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
        });
        res.json(full);
    }
    catch (e) {
        console.error('[PUT /matches/:id] failed', e);
        return res.status(500).json({ error: 'Failed to update match' });
    }
});
// Delete a match (cascade delete teams, players, scorers)
app.delete('/matches/:id', authMiddleware, async (req, res) => {
    const id = req.params.id;
    try {
        const exists = await prisma.match.findFirst({ where: { id, userId: req.userId } });
        if (!exists)
            return res.status(404).json({ error: 'Match not found' });
        const teams = await prisma.matchTeam.findMany({ where: { matchId: id } });
        const teamIds = teams.map(t => t.id);
        await prisma.$transaction([
            prisma.scorer.deleteMany({ where: { matchId: id } }),
            prisma.matchTeamPlayer.deleteMany({ where: { matchTeamId: { in: teamIds } } }),
            prisma.matchTeam.deleteMany({ where: { matchId: id } }),
            prisma.match.delete({ where: { id: exists.id } })
        ]);
        res.json({ ok: true });
    }
    catch (e) {
        console.error('[DELETE /matches/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete match' });
    }
});
// ---- Schedule generator (pairings only) ----
function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}
app.post('/schedule/generate', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        teams: zod_1.z.array(zod_1.z.array(zod_1.z.string().min(1))).min(2),
        options: zod_1.z.object({ m: zod_1.z.number().int().min(1), allowRematch: zod_1.z.boolean().optional() }).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { teams, options } = parsed.data;
    const n = teams.length;
    const m = options?.m ?? Math.max(1, n - 1);
    const allowRematch = options?.allowRematch ?? false;
    const idx = shuffle(Array.from({ length: n }, (_, i) => i));
    const pairs = [];
    const played = new Set();
    outer: for (let round = 0; round < m; round++) {
        for (let a = 0; a < n; a++) {
            for (let b = a + 1; b < n; b++) {
                const i = idx[a], j = idx[b];
                const key = i < j ? `${i}-${j}` : `${j}-${i}`;
                if (!allowRematch && played.has(key))
                    continue;
                pairs.push({ home: i, away: j });
                played.add(key);
                if (pairs.length >= Math.ceil((m * n) / 2))
                    break outer;
            }
        }
    }
    res.json({ matches: pairs, teamCount: n });
});
app.post('/schedule/commit', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        plateauId: zod_1.z.string().optional(),
        teams: zod_1.z.array(zod_1.z.array(zod_1.z.string().min(1))).min(2),
        schedule: zod_1.z.object({ matches: zod_1.z.array(zod_1.z.object({ home: zod_1.z.number().int().min(0), away: zod_1.z.number().int().min(0) })) }),
        defaults: zod_1.z.object({ startersPerTeam: zod_1.z.number().int().min(1).max(11).default(5) }).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const { plateauId, teams, schedule, defaults } = parsed.data;
    const startersPerTeam = defaults?.startersPerTeam ?? 5;
    if (plateauId) {
        const ownedPlateau = await prisma.plateau.findFirst({ where: { id: plateauId, userId: req.userId } });
        if (!ownedPlateau)
            return res.status(404).json({ error: 'Plateau not found' });
    }
    const createdIds = await prisma.$transaction(async (db) => {
        const ids = [];
        for (const m of schedule.matches) {
            const match = await db.match.create({ data: { userId: req.userId, type: plateauId ? 'PLATEAU' : 'ENTRAINEMENT', plateauId } });
            const home = await db.matchTeam.create({ data: { matchId: match.id, side: 'home', score: 0 } });
            const away = await db.matchTeam.create({ data: { matchId: match.id, side: 'away', score: 0 } });
            const pick = (arr) => arr.slice(0, startersPerTeam);
            const toMTP = (matchTeamId, ids, role) => ids.map(playerId => ({ matchTeamId, playerId, role }));
            const homeIds = teams[m.home] ?? [];
            const awayIds = teams[m.away] ?? [];
            const rows = [
                ...toMTP(home.id, pick(homeIds), 'starter'),
                ...toMTP(away.id, pick(awayIds), 'starter'),
            ];
            const uniqueRows = Array.from(new Map(rows.map((r) => [`${r.matchTeamId}:${r.playerId}:${r.role}`, r])).values());
            if (uniqueRows.length)
                await db.matchTeamPlayer.createMany({ data: uniqueRows });
            ids.push(match.id);
        }
        return ids;
    });
    const matches = await prisma.match.findMany({
        where: { userId: req.userId, id: { in: createdIds } },
        include: { teams: { include: { players: { include: { player: true } } } }, scorers: true }
    });
    res.json({ ok: true, createdCount: createdIds.length, matches });
});
// ---- Training drills (exercices attachés à une séance) ----
// Lister les exercices d'une séance (avec enrichissement à partir du catalogue DRILLS)
app.get('/trainings/:id/drills', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const training = await prisma.training.findFirst({ where: { id: trainingId, userId: req.userId } });
    if (!training)
        return res.status(404).json({ error: 'Training not found' });
    const rows = await prisma.trainingDrill.findMany({
        where: { userId: req.userId, trainingId },
        orderBy: { order: 'asc' },
    });
    const catalog = DRILLS.concat(EXTRA_DRILLS);
    const items = rows.map(r => {
        const meta = catalog.find(d => d.id === r.drillId) || null;
        return { ...r, meta };
    });
    res.json(items);
});
// Ajouter un exercice à une séance
app.post('/trainings/:id/drills', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const training = await prisma.training.findFirst({ where: { id: trainingId, userId: req.userId } });
    if (!training)
        return res.status(404).json({ error: 'Training not found' });
    const schema = zod_1.z.object({
        drillId: zod_1.z.string().min(1),
        duration: zod_1.z.number().int().min(1).max(120).optional(),
        notes: zod_1.z.string().max(1000).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    // order auto-incrémental simple
    const max = await prisma.trainingDrill.aggregate({
        where: { userId: req.userId, trainingId },
        _max: { order: true }
    });
    const nextOrder = (max._max.order ?? -1) + 1;
    const row = await prisma.trainingDrill.create({
        data: { userId: req.userId, trainingId, drillId: parsed.data.drillId, duration: parsed.data.duration, notes: parsed.data.notes, order: nextOrder }
    });
    const meta = (DRILLS.concat(EXTRA_DRILLS)).find(d => d.id === row.drillId) || null;
    res.json({ ...row, meta });
});
// Modifier (notes/duration/order)
app.put('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const trainingDrillId = req.params.trainingDrillId;
    const existing = await prisma.trainingDrill.findFirst({ where: { id: trainingDrillId, trainingId, userId: req.userId } });
    if (!existing)
        return res.status(404).json({ error: 'Not found' });
    const schema = zod_1.z.object({
        duration: zod_1.z.number().int().min(1).max(120).nullable().optional(),
        notes: zod_1.z.string().max(1000).nullable().optional(),
        order: zod_1.z.number().int().min(0).optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    try {
        const updated = await prisma.trainingDrill.update({
            where: { id: existing.id },
            data: {
                ...(parsed.data.duration !== undefined ? { duration: parsed.data.duration ?? null } : {}),
                ...(parsed.data.notes !== undefined ? { notes: parsed.data.notes ?? null } : {}),
                ...(parsed.data.order !== undefined ? { order: parsed.data.order } : {})
            }
        });
        const meta = (DRILLS.concat(EXTRA_DRILLS)).find(d => d.id === updated.drillId) || null;
        res.json({ ...updated, meta });
    }
    catch {
        res.status(404).json({ error: 'Not found' });
    }
});
// Supprimer un exercice d'une séance
app.delete('/trainings/:id/drills/:trainingDrillId', authMiddleware, async (req, res) => {
    const trainingId = req.params.id;
    const trainingDrillId = req.params.trainingDrillId;
    try {
        const existing = await prisma.trainingDrill.findFirst({ where: { id: trainingDrillId, trainingId, userId: req.userId } });
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        await prisma.trainingDrill.delete({ where: { id: existing.id } });
        res.json({ ok: true });
    }
    catch {
        res.status(404).json({ error: 'Not found' });
    }
});
// ---- Diagrams (exercices) ----
app.get('/drills/:id/diagrams', authMiddleware, async (req, res) => {
    const drillId = req.params.id;
    const rows = await prisma.diagram.findMany({ where: { userId: req.userId, drillId }, orderBy: { updatedAt: 'desc' } });
    res.json(rows);
});
app.get('/training-drills/:id/diagrams', authMiddleware, async (req, res) => {
    const trainingDrillId = req.params.id;
    const rows = await prisma.diagram.findMany({ where: { userId: req.userId, trainingDrillId }, orderBy: { updatedAt: 'desc' } });
    res.json(rows);
});
app.get('/diagrams/:id', authMiddleware, async (req, res) => {
    const d = await prisma.diagram.findFirst({ where: { id: req.params.id, userId: req.userId } });
    if (!d)
        return res.status(404).json({ error: 'Not found' });
    res.json(d);
});
app.post('/drills/:id/diagrams', authMiddleware, async (req, res) => {
    const drillId = req.params.id;
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        data: zod_1.z.any() // JSON
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const created = await prisma.diagram.create({
        data: { userId: req.userId, drillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data) }
    });
    res.json({ ...created, data: parsed.data.data });
});
app.post('/training-drills/:id/diagrams', authMiddleware, async (req, res) => {
    const trainingDrillId = req.params.id;
    const trainingDrill = await prisma.trainingDrill.findFirst({ where: { id: trainingDrillId, userId: req.userId } });
    if (!trainingDrill)
        return res.status(404).json({ error: 'Training drill not found' });
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100),
        data: zod_1.z.any()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const created = await prisma.diagram.create({
        data: { userId: req.userId, trainingDrillId, title: parsed.data.title, data: JSON.stringify(parsed.data.data) }
    });
    res.json({ ...created, data: parsed.data.data });
});
app.put('/diagrams/:id', authMiddleware, async (req, res) => {
    const schema = zod_1.z.object({
        title: zod_1.z.string().min(1).max(100).optional(),
        data: zod_1.z.any().optional()
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: parsed.error.flatten() });
    const patch = {};
    if (parsed.data.title !== undefined)
        patch.title = parsed.data.title;
    if (parsed.data.data !== undefined)
        patch.data = JSON.stringify(parsed.data.data);
    try {
        const existing = await prisma.diagram.findFirst({ where: { id: req.params.id, userId: req.userId } });
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        const updated = await prisma.diagram.update({ where: { id: existing.id }, data: patch });
        res.json({ ...updated, data: parsed.data.data ?? JSON.parse(updated.data) });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Not found' });
        console.error('[PUT /diagrams/:id] failed', e);
        return res.status(500).json({ error: 'Failed to update diagram' });
    }
});
app.delete('/diagrams/:id', authMiddleware, async (req, res) => {
    try {
        const existing = await prisma.diagram.findFirst({ where: { id: req.params.id, userId: req.userId } });
        if (!existing)
            return res.status(404).json({ error: 'Not found' });
        await prisma.diagram.delete({ where: { id: existing.id } });
        res.json({ ok: true });
    }
    catch (e) {
        if (e?.code === 'P2025')
            return res.status(404).json({ error: 'Not found' });
        console.error('[DELETE /diagrams/:id] failed', e);
        return res.status(500).json({ error: 'Failed to delete diagram' });
    }
});
// === END FOOT DOMAIN API ===
app.get('/health', (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => {
    console.log(`API listening on ${PORT}`);
});
