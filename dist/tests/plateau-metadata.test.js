"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const plateau_metadata_1 = require("../plateau-metadata");
(0, node_test_1.default)('plateau metadata validation accepts strict HH:MM and null values', () => {
    const parsed = plateau_metadata_1.plateauMetadataSchema.safeParse({
        address: 'Stade Jean Moulin',
        startTime: '09:30',
        meetingTime: null,
    });
    strict_1.default.equal(parsed.success, true);
    if (!parsed.success)
        return;
    strict_1.default.equal(parsed.data.startTime, '09:30');
    strict_1.default.equal(parsed.data.meetingTime, null);
});
(0, node_test_1.default)('plateau metadata validation rejects invalid time formats', () => {
    const invalidValues = ['9:30', '24:00', '23:60', '12-30', 'ab:cd'];
    for (const value of invalidValues) {
        const parsed = plateau_metadata_1.plateauMetadataSchema.safeParse({ startTime: value });
        strict_1.default.equal(parsed.success, false);
    }
});
(0, node_test_1.default)('partial metadata patch updates only provided fields', () => {
    const patch = (0, plateau_metadata_1.buildPlateauMetadataPatch)({ startTime: '10:15' });
    strict_1.default.deepEqual(patch, { startTime: '10:15' });
    strict_1.default.equal('address' in patch, false);
    strict_1.default.equal('meetingTime' in patch, false);
});
(0, node_test_1.default)('public plateau shape includes new metadata fields', () => {
    const plateau = (0, plateau_metadata_1.toPublicPlateau)({
        id: 'pl_1',
        date: new Date('2026-03-06T10:00:00.000Z'),
        lieu: 'Terrain central',
        address: '1 rue du Stade',
        startTime: '10:00',
        meetingTime: '09:30',
    });
    strict_1.default.equal(plateau.address, '1 rue du Stade');
    strict_1.default.equal(plateau.startTime, '10:00');
    strict_1.default.equal(plateau.meetingTime, '09:30');
});
