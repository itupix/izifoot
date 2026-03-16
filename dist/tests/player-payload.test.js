"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const player_payload_1 = require("../player-payload");
(0, node_test_1.default)('POST payload refuses missing email', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.parsePlayerCreatePayload)({
            firstName: 'Lina',
            lastName: 'Martin',
            phone: '0611223344',
            primary_position: 'NON DEFINI',
            isChild: false,
        });
    });
});
(0, node_test_1.default)('POST payload refuses missing phone', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.parsePlayerCreatePayload)({
            firstName: 'Lina',
            lastName: 'Martin',
            email: 'lina@example.com',
            primary_position: 'NON DEFINI',
            isChild: false,
        });
    });
});
(0, node_test_1.default)('POST payload refuses child without parent names', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.parsePlayerCreatePayload)({
            firstName: 'Lina',
            lastName: 'Martin',
            email: 'lina@example.com',
            phone: '0611223344',
            primary_position: 'NON DEFINI',
            isChild: true,
            parentFirstName: 'Claire',
        });
    });
});
(0, node_test_1.default)('POST payload accepts primary_position = NON DEFINI', () => {
    const parsed = (0, player_payload_1.parsePlayerCreatePayload)({
        firstName: 'Lina',
        lastName: 'Martin',
        email: 'lina@example.com',
        phone: '0611223344',
        primary_position: 'NON DEFINI',
        isChild: false,
    });
    strict_1.default.equal(parsed.primary_position, 'NON DEFINI');
});
(0, node_test_1.default)('normalizePlayerForApi returns coherent firstName + lastName + name', () => {
    const normalized = (0, player_payload_1.normalizePlayerForApi)({
        id: 'p1',
        first_name: 'Lina',
        last_name: 'Martin',
        name: 'Legacy Name',
        is_child: false,
    });
    strict_1.default.equal(normalized.firstName, 'Lina');
    strict_1.default.equal(normalized.lastName, 'Martin');
    strict_1.default.equal(normalized.name, 'Lina Martin');
});
(0, node_test_1.default)('compatibility aliases are accepted', () => {
    const parsed = (0, player_payload_1.parsePlayerCreatePayload)({
        prenom: 'Noah',
        nom: 'Dupont',
        email: 'noah@example.com',
        phone: '0600000000',
        primary_position: 'NON DEFINI',
        enfant: true,
        parent_first_name: 'Marie',
        parent_last_name: 'Dupont',
        license: 'F12345',
    });
    strict_1.default.equal(parsed.firstName, 'Noah');
    strict_1.default.equal(parsed.lastName, 'Dupont');
    strict_1.default.equal(parsed.isChild, true);
    strict_1.default.equal(parsed.parentFirstName, 'Marie');
    strict_1.default.equal(parsed.parentLastName, 'Dupont');
    strict_1.default.equal(parsed.licence, 'F12345');
});
(0, node_test_1.default)('PUT payload refuses missing email', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.parsePlayerUpdatePayload)({
            firstName: 'Lina',
            lastName: 'Martin',
            phone: '0611223344',
            primary_position: 'NON DEFINI',
            isChild: false,
        }, {});
    });
});
(0, node_test_1.default)('PUT payload updates concatenated name fields from aliases', () => {
    const parsed = (0, player_payload_1.parsePlayerUpdatePayload)({
        first_name: 'Lina',
        last_name: 'Martin',
        email: 'lina@example.com',
        phone: '0611223344',
        primary_position: 'NON DEFINI',
        enfant: false,
    }, {});
    const normalized = (0, player_payload_1.normalizePlayerForApi)({
        ...parsed,
        first_name: parsed.firstName,
        last_name: parsed.lastName,
        name: `${parsed.firstName} ${parsed.lastName}`.trim(),
        is_child: parsed.isChild,
    });
    strict_1.default.equal(normalized.name, 'Lina Martin');
});
(0, node_test_1.default)('PUT payload accepts parentPrenom/parentNom aliases when child', () => {
    const parsed = (0, player_payload_1.parsePlayerUpdatePayload)({
        firstName: 'Noah',
        lastName: 'Dupont',
        email: 'noah@example.com',
        phone: '0600000000',
        primary_position: 'NON DEFINI',
        isChild: true,
        parentPrenom: 'Marie',
        parentNom: 'Dupont',
    }, {});
    strict_1.default.equal(parsed.parentFirstName, 'Marie');
    strict_1.default.equal(parsed.parentLastName, 'Dupont');
});
