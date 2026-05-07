"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = __importDefault(require("node:test"));
const strict_1 = __importDefault(require("node:assert/strict"));
const player_payload_1 = require("../player-payload");
(0, node_test_1.default)('POST payload only requires firstName', () => {
    const parsed = (0, player_payload_1.parsePlayerCreatePayload)({
        firstName: 'Lina',
    });
    strict_1.default.equal(parsed.firstName, 'Lina');
    strict_1.default.equal(parsed.lastName, '');
    strict_1.default.equal(parsed.email, '');
    strict_1.default.equal(parsed.phone, '');
    strict_1.default.equal(parsed.primary_position, player_payload_1.DEFAULT_PLAYER_PRIMARY_POSITION);
});
(0, node_test_1.default)('POST payload refuses child without parent names', () => {
    const parsed = (0, player_payload_1.parsePlayerCreatePayload)({
        firstName: 'Lina',
        lastName: 'Martin',
        email: 'lina@example.com',
        phone: '0611223344',
        primary_position: 'NON DEFINI',
        isChild: true,
    });
    strict_1.default.equal(parsed.parentFirstName, null);
    strict_1.default.equal(parsed.parentLastName, null);
    strict_1.default.equal(parsed.email, '');
    strict_1.default.equal(parsed.phone, '');
});
(0, node_test_1.default)('POST payload defaults missing primary_position to NON DEFINI', () => {
    const parsed = (0, player_payload_1.parsePlayerCreatePayload)({
        firstName: 'Lina',
        lastName: 'Martin',
    });
    strict_1.default.equal(parsed.primary_position, player_payload_1.DEFAULT_PLAYER_PRIMARY_POSITION);
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
    strict_1.default.equal(parsed.parentFirstName, null);
    strict_1.default.equal(parsed.parentLastName, null);
    strict_1.default.equal(parsed.licence, 'F12345');
});
(0, node_test_1.default)('POST payload refuses invalid email when provided', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.parsePlayerCreatePayload)({
            firstName: 'Lina',
            email: 'invalid-email',
        });
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
(0, node_test_1.default)('PUT payload preserves existing optional fields when omitted', () => {
    const parsed = (0, player_payload_1.parsePlayerUpdatePayload)({
        firstName: 'Lina',
        email: 'lina.new@example.com',
    }, {
        first_name: 'Lina',
        last_name: 'Martin',
        email: 'lina.old@example.com',
        phone: '0611223344',
        primary_position: 'ATTAQUANT',
        is_child: false,
    });
    strict_1.default.equal(parsed.lastName, 'Martin');
    strict_1.default.equal(parsed.email, 'lina.new@example.com');
    strict_1.default.equal(parsed.phone, '0611223344');
    strict_1.default.equal(parsed.primary_position, 'ATTAQUANT');
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
    strict_1.default.equal(parsed.parentFirstName, null);
    strict_1.default.equal(parsed.parentLastName, null);
});
(0, node_test_1.default)('player account invite requires lastName, email and phone for non-child players', () => {
    strict_1.default.throws(() => {
        (0, player_payload_1.assertPlayerAccountInvitePrerequisites)({
            first_name: 'Lina',
            last_name: '',
            email: null,
            phone: null,
            is_child: false,
        });
    });
});
(0, node_test_1.default)('player account invite accepts request email and phone overrides for non-child players', () => {
    strict_1.default.doesNotThrow(() => {
        (0, player_payload_1.assertPlayerAccountInvitePrerequisites)({
            first_name: 'Lina',
            last_name: 'Martin',
            email: null,
            phone: null,
            is_child: false,
        }, {
            email: 'lina@example.com',
            phone: '0611223344',
        });
    });
});
(0, node_test_1.default)('player account invite keeps child flow unchanged', () => {
    strict_1.default.doesNotThrow(() => {
        (0, player_payload_1.assertPlayerAccountInvitePrerequisites)({
            first_name: 'Noah',
            is_child: true,
        });
    });
});
