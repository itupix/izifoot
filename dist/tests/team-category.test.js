"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const team_category_1 = require("../team-category");
(0, node_test_1.default)('normalizeTeamCategory accepts single U category', () => {
    const parsed = (0, team_category_1.normalizeTeamCategory)('u8');
    strict_1.default.equal(parsed.ok, true);
    if (parsed.ok)
        strict_1.default.equal(parsed.category, 'U8');
});
(0, node_test_1.default)('normalizeTeamCategory accepts contiguous U range', () => {
    const parsed = (0, team_category_1.normalizeTeamCategory)('U8 - U10');
    strict_1.default.equal(parsed.ok, true);
    if (parsed.ok)
        strict_1.default.equal(parsed.category, 'U8-U10');
});
(0, node_test_1.default)('normalizeTeamCategory accepts Vétérans without diacritics', () => {
    const parsed = (0, team_category_1.normalizeTeamCategory)('veterans');
    strict_1.default.equal(parsed.ok, true);
    if (parsed.ok)
        strict_1.default.equal(parsed.category, 'Vétérans');
});
(0, node_test_1.default)('normalizeTeamCategory rejects non-U range', () => {
    const parsed = (0, team_category_1.normalizeTeamCategory)('U8-Vétérans');
    strict_1.default.equal(parsed.ok, false);
});
(0, node_test_1.default)('normalizeTeamCategory rejects reversed U range', () => {
    const parsed = (0, team_category_1.normalizeTeamCategory)('U10-U8');
    strict_1.default.equal(parsed.ok, false);
});
