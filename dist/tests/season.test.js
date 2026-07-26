"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const season_1 = require("../season");
(0, node_test_1.default)('normalizeClubSeasonConfig falls back to defaults', () => {
    const config = (0, season_1.normalizeClubSeasonConfig)({});
    strict_1.default.deepEqual(config, {
        startMonth: 8,
        startDay: 1,
        endMonth: 7,
        endDay: 31,
        timezone: 'Europe/Paris',
    });
});
(0, node_test_1.default)('resolveSeasonWindowForDate keeps July 26 2026 in season 2025-2026 with default config', () => {
    const season = (0, season_1.resolveSeasonWindowForDate)('2026-07-26T10:00:00.000Z', {});
    strict_1.default.equal(season.key, '2025-2026');
});
(0, node_test_1.default)('resolveSeasonWindowForDate maps August 1 2026 to season 2026-2027 with default config', () => {
    const season = (0, season_1.resolveSeasonWindowForDate)('2026-08-01T10:00:00.000Z', {});
    strict_1.default.equal(season.key, '2026-2027');
});
(0, node_test_1.default)('compareMonthDay compares month/day tuples', () => {
    strict_1.default.equal((0, season_1.compareMonthDay)(7, 31, 8, 1) < 0, true);
    strict_1.default.equal((0, season_1.compareMonthDay)(8, 1, 8, 1), 0);
    strict_1.default.equal((0, season_1.compareMonthDay)(8, 2, 8, 1) > 0, true);
});
