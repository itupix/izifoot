"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerChampionshipRoutes = registerChampionshipRoutes;
const crypto_1 = require("crypto");
const zod_1 = require("zod");
const championship_domain_1 = require("./championship-domain");
const createSchema = zod_1.z.object({ teamId: zod_1.z.string().min(1), seasonId: zod_1.z.string().min(1).optional(), name: zod_1.z.string().trim().min(1).max(120), teams: zod_1.z.array(zod_1.z.string().trim().min(1).max(120)).min(1).max(31), doubleRoundRobin: zod_1.z.boolean().default(true) }).strict();
const revisionSchema = zod_1.z.object({ revision: zod_1.z.number().int().min(1) });
const kickoffSchema = revisionSchema.extend({ kickoffAt: zod_1.z.string().datetime({ offset: true }).nullable() }).strict();
const orderSchema = revisionSchema.extend({ fixtureIds: zod_1.z.array(zod_1.z.string()).max(992) }).strict();
const resultSchema = revisionSchema.extend({ homeScore: zod_1.z.number().int().min(0).max(999).nullable(), awayScore: zod_1.z.number().int().min(0).max(999).nullable() }).strict().refine(value => (value.homeScore === null) === (value.awayScore === null), 'Both scores are required together');
function fail(status, code, message) { throw Object.assign(new Error(message), { status, code }); }
function registerChampionshipRoutes(app, deps) {
    const { db, auth, scope, writeTeam, season } = deps;
    const manage = (user, teamId) => user.role === 'DIRECTION' || (user.role === 'COACH' && (user.managedTeamIds || []).includes(teamId));
    const wrap = (handler) => async (req, res) => {
        try {
            await handler(req, res);
        }
        catch (error) {
            if (error instanceof zod_1.z.ZodError)
                return res.status(400).json({ error: error.issues[0]?.message || 'Invalid input', code: 'INVALID_INPUT' });
            if (error.code === 'P2002')
                return res.status(409).json({ error: 'A championship already exists for this team and season', code: 'CHAMPIONSHIP_EXISTS' });
            if (error.code === 'P2034')
                return res.status(409).json({ error: 'Reload the championship before saving', code: 'REVISION_CONFLICT' });
            if (error.status)
                return res.status(error.status).json({ error: error.message, code: error.code });
            console.error('[championship]', error);
            return res.status(500).json({ error: 'Championship operation failed', code: 'INTERNAL_ERROR' });
        }
    };
    async function checkedTeam(user, teamId, writing = false) {
        if (!teamId)
            fail(400, 'INVALID_INPUT', 'Team is required');
        const team = await db.team.findFirst({ where: { id: teamId, clubId: user.clubId || '__none__' } });
        if (!team)
            fail(404, 'NOT_FOUND', 'Team not found');
        const scoped = scope(user, {});
        const filter = scoped.teamId;
        if (filter && (typeof filter === 'string' ? filter !== teamId : !filter.in?.includes(teamId)))
            fail(403, 'FORBIDDEN', 'Team access forbidden');
        if (writing) {
            if (!manage(user, teamId))
                fail(403, 'FORBIDDEN', 'Staff access required');
            try {
                await writeTeam(user, teamId);
            }
            catch {
                fail(403, 'FORBIDDEN', 'Team access forbidden');
            }
        }
        return team;
    }
    async function selectedSeason(user, id) {
        const selected = id ? await db.season.findFirst({ where: { id, clubId: user.clubId || '__none__' } }) : await season(db, user.clubId, new Date());
        if (!selected)
            fail(404, 'NOT_FOUND', 'Season not found');
        return selected;
    }
    async function hydrate(row, tx = db) {
        const data = structuredClone(row.data);
        const linked = data.fixtures.filter(f => f.matchId).map(f => f.matchId);
        const matches = linked.length ? await tx.match.findMany({ where: { id: { in: linked } }, include: { teams: true } }) : [];
        for (const fixture of data.fixtures) {
            const match = matches.find((m) => m.id === fixture.matchId);
            if (!match) {
                if (fixture.matchId) {
                    fixture.matchId = null;
                    fixture.homeScore = null;
                    fixture.awayScore = null;
                }
                ;
                continue;
            }
            fixture.kickoffAt = match.date ? new Date(match.date).toISOString() : null;
            const scored = match.status === 'PLAYED';
            fixture.homeScore = scored ? match.teams.find((t) => t.side === 'home')?.score ?? null : null;
            fixture.awayScore = scored ? match.teams.find((t) => t.side === 'away')?.score ?? null : null;
        }
        return data;
    }
    async function envelope(row, user, tx = db) {
        if (!row)
            return { championship: null, canManage: false };
        const data = await hydrate(row, tx);
        return { championship: { id: row.id, teamId: row.teamId, seasonId: row.seasonId, name: row.name, doubleRoundRobin: row.doubleRoundRobin, status: row.status, revision: row.revision, ...data, standings: (0, championship_domain_1.standings)(data) }, canManage: manage(user, row.teamId) };
    }
    app.get('/championship', auth, wrap(async (req, res) => {
        const teamId = zod_1.z.string().min(1).parse(req.query.teamId);
        const team = await checkedTeam(req.auth, teamId);
        const selected = await selectedSeason(req.auth, req.query.seasonId);
        const row = await db.championship.findUnique({ where: { teamId_seasonId: { teamId, seasonId: selected.id } } });
        res.json(row ? await envelope(row, req.auth) : { championship: null, canManage: manage(req.auth, team.id) });
    }));
    app.post('/championship', auth, wrap(async (req, res) => {
        const input = createSchema.parse(req.body), team = await checkedTeam(req.auth, input.teamId, true), selected = await selectedSeason(req.auth, input.seasonId);
        const names = [team.name, ...input.teams], normalized = names.map(name => name.normalize('NFKC').toLocaleLowerCase('fr').trim());
        if (new Set(normalized).size !== names.length)
            fail(400, 'INVALID_INPUT', 'Team names must be unique');
        const data = (0, championship_domain_1.generateSchedule)(names.map((name, index) => ({ id: (0, crypto_1.randomUUID)(), name, isOwnTeam: index === 0 })), input.doubleRoundRobin);
        const row = await db.championship.create({ data: { clubId: team.clubId, teamId: team.id, seasonId: selected.id, name: input.name, doubleRoundRobin: input.doubleRoundRobin, data } });
        res.status(201).json(await envelope(row, req.auth));
    }));
    async function mutate(req, kind) {
        const input = kind === 'kickoff' ? kickoffSchema.parse(req.body) : kind === 'order' ? orderSchema.parse(req.body) : kind === 'result' ? resultSchema.parse(req.body) : revisionSchema.strict().parse(req.body);
        return db.$transaction(async (tx) => {
            const row = await tx.championship.findUnique({ where: { id: req.params.id } });
            if (!row)
                fail(404, 'NOT_FOUND', 'Championship not found');
            await checkedTeam(req.auth, row.teamId, true);
            if (row.revision !== input.revision)
                fail(409, 'REVISION_CONFLICT', 'Reload the championship before saving');
            if (kind === 'validate' && row.status === 'VALIDATED')
                return envelope(row, req.auth, tx);
            const lock = await tx.championship.updateMany({ where: { id: row.id, revision: input.revision }, data: { revision: { increment: 1 } } });
            if (lock.count !== 1)
                fail(409, 'REVISION_CONFLICT', 'Reload the championship before saving');
            const data = await hydrate(row, tx), fixture = data.fixtures.find(f => f.id === req.params.fixtureId);
            if (kind === 'kickoff' || kind === 'result') {
                if (!fixture)
                    fail(404, 'NOT_FOUND', 'Fixture not found');
            }
            if (kind === 'kickoff') {
                const kickoff = input.kickoffAt;
                if (kickoff) {
                    const selected = await tx.season.findUnique({ where: { id: row.seasonId } });
                    if (!selected || new Date(kickoff) < selected.startDate || new Date(kickoff) > selected.endDate)
                        fail(400, 'INVALID_INPUT', 'Kickoff must be within the season');
                }
                fixture.kickoffAt = kickoff ? new Date(kickoff).toISOString() : null;
                if (fixture.matchId)
                    await tx.match.update({ where: { id: fixture.matchId }, data: { date: kickoff ? new Date(kickoff) : null } });
            }
            if (kind === 'order') {
                try {
                    (0, championship_domain_1.reorderFixtures)(data, input.fixtureIds);
                }
                catch (error) {
                    fail(400, 'INVALID_INPUT', error.message);
                }
            }
            if (kind === 'validate') {
                const own = data.teams.find(t => t.isOwnTeam);
                for (const f of data.fixtures.filter(f => f.homeTeamId === own.id || f.awayTeamId === own.id)) {
                    const opponent = data.teams.find(t => t.id === (f.homeTeamId === own.id ? f.awayTeamId : f.homeTeamId));
                    const match = await tx.match.create({ data: { userId: req.auth.id, clubId: row.clubId, teamId: row.teamId, seasonId: row.seasonId, date: f.kickoffAt ? new Date(f.kickoffAt) : null, type: 'CHAMPIONSHIP', opponentName: opponent.name, teams: { create: [{ side: 'home', score: 0 }, { side: 'away', score: 0 }] } } });
                    f.matchId = match.id;
                }
                row.status = 'VALIDATED';
            }
            if (kind === 'result') {
                if (row.status !== 'VALIDATED')
                    fail(409, 'INVALID_STATE', 'Validate the championship before entering results');
                const scores = input;
                fixture.homeScore = scores.homeScore;
                fixture.awayScore = scores.awayScore;
                if (fixture.matchId) {
                    await tx.match.update({ where: { id: fixture.matchId }, data: { played: scores.homeScore !== null, status: scores.homeScore !== null ? 'PLAYED' : 'PLANNED' } });
                    for (const side of ['home', 'away'])
                        await tx.matchTeam.updateMany({ where: { matchId: fixture.matchId, side }, data: { score: (side === 'home' ? scores.homeScore : scores.awayScore) ?? 0 } });
                }
            }
            const updated = await tx.championship.update({ where: { id: row.id }, data: { data, status: row.status } });
            return envelope(updated, req.auth, tx);
        }, { maxWait: 10000, timeout: 30000 });
    }
    app.patch('/championship/:id/fixtures/:fixtureId', auth, wrap(async (req, res) => { res.json(await mutate(req, 'kickoff')); }));
    app.put('/championship/:id/order', auth, wrap(async (req, res) => { res.json(await mutate(req, 'order')); }));
    app.post('/championship/:id/validate', auth, wrap(async (req, res) => { res.json(await mutate(req, 'validate')); }));
    app.put('/championship/:id/fixtures/:fixtureId/result', auth, wrap(async (req, res) => { res.json(await mutate(req, 'result')); }));
}
