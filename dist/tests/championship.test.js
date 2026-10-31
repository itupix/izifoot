"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const championship_domain_1 = require("../championship-domain");
const teams = (count) => Array.from({ length: count }, (_, i) => ({ id: String(i), name: `Team ${i}`, isOwnTeam: i === 0 }));
for (const count of [2, 3, 4, 5, 16, 31, 32]) {
    for (const double of [false, true])
        (0, node_test_1.default)(`round robin ${count} teams, return=${double}`, () => {
            const data = (0, championship_domain_1.generateSchedule)(teams(count), double);
            strict_1.default.equal(data.fixtures.length, count * (count - 1) / 2 * (double ? 2 : 1));
            const pairs = new Set(data.fixtures.map(f => double ? `${f.homeTeamId}:${f.awayTeamId}` : [f.homeTeamId, f.awayTeamId].sort().join(':')));
            strict_1.default.equal(pairs.size, data.fixtures.length);
            for (const round of new Set(data.fixtures.map(f => f.round))) {
                const active = data.fixtures.filter(f => f.round === round).flatMap(f => [f.homeTeamId, f.awayTeamId]);
                strict_1.default.equal(new Set(active).size, active.length);
                strict_1.default.equal(active.length + (count % 2), count);
            }
            strict_1.default.equal(data.byeRounds.length, count % 2 ? count * (double ? 2 : 1) : 0);
            strict_1.default.equal(data.fixtures.filter(f => f.homeTeamId === '0' || f.awayTeamId === '0').length, (count - 1) * (double ? 2 : 1));
        });
}
(0, node_test_1.default)('standings count only scored fixtures and use 3/1/0', () => {
    const data = (0, championship_domain_1.generateSchedule)(teams(3), false);
    const f = data.fixtures[0];
    f.homeScore = 2;
    f.awayScore = 0;
    const rows = (0, championship_domain_1.standings)(data);
    strict_1.default.equal(rows[0].teamId, f.homeTeamId);
    strict_1.default.equal(rows[0].points, 3);
    strict_1.default.equal(rows[0].goalDifference, 2);
    strict_1.default.equal(rows.find(r => r.teamId === f.awayTeamId)?.lost, 1);
    f.homeScore = 1;
    f.awayScore = 1;
    strict_1.default.equal((0, championship_domain_1.standings)(data).filter(r => r.points === 1).length, 2);
    f.homeScore = null;
    f.awayScore = null;
    strict_1.default.ok((0, championship_domain_1.standings)(data).every(r => r.played === 0));
});
(0, node_test_1.default)('reordering is an exact permutation, dated positions locked, rounds retained', () => {
    const data = (0, championship_domain_1.generateSchedule)(teams(4), false), ids = data.fixtures.map(f => f.id);
    data.fixtures[0].kickoffAt = '2026-11-01T12:00:00Z';
    strict_1.default.throws(() => (0, championship_domain_1.reorderFixtures)(data, [...ids].reverse()));
    strict_1.default.throws(() => (0, championship_domain_1.reorderFixtures)(data, ids.slice(1)));
    strict_1.default.throws(() => (0, championship_domain_1.reorderFixtures)(data, ids.map(() => ids[0])));
    const rounds = new Map(data.fixtures.map(f => [f.id, f.round]));
    const next = [ids[0], ...ids.slice(1).reverse()];
    (0, championship_domain_1.reorderFixtures)(data, next);
    strict_1.default.deepEqual(data.fixtures.map(f => f.id), next);
    strict_1.default.ok(data.fixtures.every(f => f.round === rounds.get(f.id)));
});
