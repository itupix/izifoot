"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const team_name_1 = require("../team-name");
(0, node_test_1.default)('foldTeamNameForCompare removes accents and normalizes case', () => {
    strict_1.default.equal((0, team_name_1.foldTeamNameForCompare)('  Vétérans  '), 'veterans');
    strict_1.default.equal((0, team_name_1.foldTeamNameForCompare)('VETERANS'), 'veterans');
});
(0, node_test_1.default)('computeAutoTeamName keeps base name when available', () => {
    strict_1.default.equal((0, team_name_1.computeAutoTeamName)('U8-U9', ['U10-U11', 'Seniors']), 'U8-U9');
});
(0, node_test_1.default)('computeAutoTeamName increments suffix when base name already exists', () => {
    strict_1.default.equal((0, team_name_1.computeAutoTeamName)('Vétérans', ['Vétérans']), 'Vétérans 2');
});
(0, node_test_1.default)('computeAutoTeamName increments with accent/case-insensitive comparison', () => {
    strict_1.default.equal((0, team_name_1.computeAutoTeamName)('Vétérans', ['veterans', 'Vétérans 2', 'VETERANS 3']), 'Vétérans 4');
});
