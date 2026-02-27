import 'dotenv/config'
import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'

const connectionString = process.env.DATABASE_URL
if (!connectionString) {
  throw new Error('DATABASE_URL is not set')
}
const adapter = new PrismaPg({ connectionString })
const prisma = new PrismaClient({ adapter })
async function main() {
  const p1 = await prisma.player.create({ data: { name: 'Axel', primary_position: 'ATTAQUANT' } })
  const p2 = await prisma.player.create({ data: { name: 'Léon', primary_position: 'DEFENSEUR' } })
  const tr = await prisma.training.create({ data: { date: new Date() } })
  await prisma.attendance.createMany({
    data: [
      { session_type: 'TRAINING', session_id: tr.id, playerId: p1.id },
      { session_type: 'TRAINING', session_id: tr.id, playerId: p2.id },
    ]
  })
}
main().finally(() => prisma.$disconnect())
