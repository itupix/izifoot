"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const player_route_aliases_1 = require("../player-route-aliases");
(0, node_test_1.default)('player collection aliases keep canonical and legacy endpoints aligned', () => {
    strict_1.default.deepEqual([...player_route_aliases_1.playerCollectionRouteAliases], [
        '/players',
        '/effectif',
        '/api/players',
        '/api/effectif',
    ]);
});
(0, node_test_1.default)('player detail aliases keep canonical and legacy endpoints aligned', () => {
    strict_1.default.deepEqual([...player_route_aliases_1.playerDetailRouteAliases], [
        '/players/:id',
        '/effectif/:id',
        '/api/players/:id',
        '/api/effectif/:id',
    ]);
});
