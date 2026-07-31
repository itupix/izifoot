import { Prisma } from '@prisma/client'

export function toPrismaNullableJsonValue<T>(value: T) {
  return value === null ? Prisma.DbNull : value
}
