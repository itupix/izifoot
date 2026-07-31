"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const client_1 = require("@prisma/client");
const prisma_json_1 = require("../prisma-json");
(0, node_test_1.default)('toPrismaNullableJsonValue converts null to Prisma.DbNull', () => {
    strict_1.default.equal((0, prisma_json_1.toPrismaNullableJsonValue)(null), client_1.Prisma.DbNull);
});
(0, node_test_1.default)('toPrismaNullableJsonValue keeps JSON payloads unchanged', () => {
    const tactic = {
        formation: '2-3-1',
        points: {
            gk: { x: 10, y: 10 },
            p1: { x: 20, y: 20 },
        },
    };
    strict_1.default.equal((0, prisma_json_1.toPrismaNullableJsonValue)(tactic), tactic);
});
