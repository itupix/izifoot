import 'dotenv/config'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
async function main() {
  const club = await prisma.club.create({ data: { name: 'Seed Club' } })
  const team = await prisma.team.create({ data: { name: 'U9 A', category: 'U9', clubId: club.id } })
  const user = await prisma.user.create({
    data: {
      email: 'seed-direction@example.com',
      passwordHash: 'seed',
      role: 'DIRECTION',
      clubId: club.id,
      teamId: team.id
    }
  })
  const p1 = await prisma.player.create({
    data: { userId: user.id, clubId: club.id, teamId: team.id, name: 'Axel', primary_position: 'ATTAQUANT' }
  })
  const p2 = await prisma.player.create({
    data: { userId: user.id, clubId: club.id, teamId: team.id, name: 'Léon', primary_position: 'DEFENSEUR' }
  })
  const tr = await prisma.training.create({ data: { userId: user.id, clubId: club.id, teamId: team.id, date: new Date() } })
  await prisma.attendance.createMany({
    data: [
      { userId: user.id, clubId: club.id, teamId: team.id, session_type: 'TRAINING', session_id: tr.id, playerId: p1.id },
      { userId: user.id, clubId: club.id, teamId: team.id, session_type: 'TRAINING', session_id: tr.id, playerId: p2.id },
    ]
  })
}
main().finally(() => prisma.$disconnect())
