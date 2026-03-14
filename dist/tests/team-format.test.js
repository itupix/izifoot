"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const team_format_1 = require("../team-format");
(0, node_test_1.default)('normalizeTeamFormat accepts allowed values', () => {
    const parsed = (0, team_format_1.normalizeTeamFormat)('5v5');
    strict_1.default.equal(parsed.ok, true);
    if (parsed.ok)
        strict_1.default.equal(parsed.format, '5v5');
});
(0, node_test_1.default)('normalizeTeamFormat normalizes case and spaces', () => {
    const parsed = (0, team_format_1.normalizeTeamFormat)(' 11V11 ');
    strict_1.default.equal(parsed.ok, true);
    if (parsed.ok)
        strict_1.default.equal(parsed.format, '11v11');
});
(0, node_test_1.default)('normalizeTeamFormat rejects invalid value', () => {
    const parsed = (0, team_format_1.normalizeTeamFormat)('7v7');
    strict_1.default.equal(parsed.ok, false);
});
(0, node_test_1.default)('normalizeTeamFormat rejects missing value', () => {
    const parsed = (0, team_format_1.normalizeTeamFormat)('');
    strict_1.default.equal(parsed.ok, false);
});
