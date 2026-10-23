"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const training_materials_1 = require("../training-materials");
const drill = (id) => ({ id, drillId: `catalog-${id}` });
const diagram = (id, frames) => ({ trainingDrillId: id, data: JSON.stringify({ frames }) });
const cones = (n) => Array.from({ length: n }, () => ({ type: 'cone' }));
(0, node_test_1.default)('equipment uses maxima across steps and successive exercises, with stable order', () => {
    const result = (0, training_materials_1.trainingMaterials)([drill('a'), drill('b')], [
        diagram('a', [{ items: cones(3) }, { items: [...cones(5), { type: 'ball' }] }]),
        diagram('b', [{ items: [...cones(2), { type: 'cup' }, { type: 'post' }, { type: 'player', color: 'red' }, { type: 'player', color: 'blue' }] }]),
    ]);
    strict_1.default.deepEqual(result, { items: [
            { type: 'cup', label: 'Coupelle', quantity: 1 }, { type: 'cone', label: 'Cônes', quantity: 5 },
            { type: 'ball', label: 'Ballon', quantity: 1 }, { type: 'post', label: 'Poteau', quantity: 1 },
            { type: 'bib', label: 'Chasubles', quantity: null },
        ], drillCount: 2, missingDiagramCount: 0 });
});
(0, node_test_1.default)('session override takes precedence over catalog and latest diagram wins', () => {
    strict_1.default.equal((0, training_materials_1.trainingMaterials)([drill('a')], [
        { drillId: 'catalog-a', data: { items: cones(9) } },
        diagram('a', [{ items: cones(2) }]), diagram('a', [{ items: cones(4) }]),
    ]).items[0].quantity, 2);
});
(0, node_test_1.default)('catalog fallback accepts legacy items, without counting players as equipment', () => {
    strict_1.default.deepEqual((0, training_materials_1.trainingMaterials)([drill('a')], [{ drillId: 'catalog-a', data: { items: [{ type: 'player' }, { type: 'arrow' }] } }]), { items: [], drillCount: 1, missingDiagramCount: 0 });
});
(0, node_test_1.default)('missing and malformed diagrams expose partial completeness; empty diagrams are valid', () => {
    const result = (0, training_materials_1.trainingMaterials)([drill('a'), drill('b'), drill('c'), drill('d')], [
        { trainingDrillId: 'a', data: '{bad json' }, { trainingDrillId: 'b', data: { frames: [{ items: null }] } },
        diagram('c', [{ items: [] }]),
    ]);
    strict_1.default.deepEqual(result, { items: [], drillCount: 4, missingDiagramCount: 3 });
    strict_1.default.deepEqual((0, training_materials_1.trainingMaterials)([], []), { items: [], drillCount: 0, missingDiagramCount: 0 });
});
