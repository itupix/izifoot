"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toPrismaNullableJsonValue = toPrismaNullableJsonValue;
const client_1 = require("@prisma/client");
function toPrismaNullableJsonValue(value) {
    return value === null ? client_1.Prisma.DbNull : value;
}
