"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const drill_contract_1 = require("../drill-contract");
(0, node_test_1.default)('catalogue accepts only the four categories and requires no duration or player count', () => {
    for (const category of drill_contract_1.DRILL_CATEGORIES) {
        strict_1.default.equal(drill_contract_1.drillCreateSchema.parse({ title: 'Passes', category, description: 'Circulation du ballon' }).category, category);
    }
    for (const category of ['autre', 'echauffement', 'Technique', '', null]) {
        strict_1.default.equal(drill_contract_1.drillCreateSchema.safeParse({ title: 'Passes', category, description: 'Circulation' }).success, false);
        strict_1.default.equal(drill_contract_1.drillUpdateSchema.safeParse({ category }).success, false);
    }
});
(0, node_test_1.default)('legacy clients cannot persist retired drill metadata', () => {
    const result = drill_contract_1.drillCreateSchema.parse({ title: 'Passes', category: 'autres', description: 'Circulation', duration: 20, players: 'Tous' });
    strict_1.default.equal('duration' in result, false);
    strict_1.default.equal('players' in result, false);
    strict_1.default.deepEqual(drill_contract_1.drillUpdateSchema.parse({ title: 'Nouveau titre', duration: 1, players: 'Variable' }), { title: 'Nouveau titre' });
});
(0, node_test_1.default)('training linkage drops legacy duration and retains replacement identifiers', () => {
    strict_1.default.deepEqual(drill_contract_1.trainingDrillCreateSchema.parse({ drillId: 'passes', duration: 20, trainingDrillId: 'existing', notes: 'Consigne' }), { drillId: 'passes', trainingDrillId: 'existing', notes: 'Consigne' });
    strict_1.default.equal(drill_contract_1.trainingDrillUpdateSchema.safeParse({ duration: 20 }).success, false);
    strict_1.default.equal(drill_contract_1.trainingDrillUpdateSchema.safeParse({}).success, false);
    strict_1.default.deepEqual(drill_contract_1.trainingDrillUpdateSchema.parse({ notes: null, order: 0, duration: 20 }), { notes: null, order: 0 });
});
