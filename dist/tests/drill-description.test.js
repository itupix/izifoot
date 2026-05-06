"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const drill_description_1 = require("../drill-description");
(0, node_test_1.default)('withDrillDescriptionHtml preserves manual drill description without injecting sections', () => {
    const raw = 'Jeu de passes en triangle avec appui-remise et finition rapide.';
    const rendered = (0, drill_description_1.withDrillDescriptionHtml)({ description: raw });
    strict_1.default.equal(rendered.description, raw);
    strict_1.default.equal(rendered.descriptionHtml, `<p>${raw}</p>`);
});
(0, node_test_1.default)('normalizeDrillDescription keeps paragraph breaks while trimming noisy whitespace', () => {
    const raw = '  Organisation simple  \n\n  Passe et va   ';
    const normalized = (0, drill_description_1.normalizeDrillDescription)(raw);
    strict_1.default.equal(normalized, 'Organisation simple\nPasse et va');
});
(0, node_test_1.default)('toDrillDescriptionHtml keeps explicit labels when the author wrote them', () => {
    const raw = 'Organisation: carré de 20m\nConsignes: jouer en deux touches';
    const html = (0, drill_description_1.toDrillDescriptionHtml)(raw);
    strict_1.default.equal(html, '<p><strong>Organisation :</strong> carré de 20m</p><p><strong>Consignes :</strong> jouer en deux touches</p>');
});
