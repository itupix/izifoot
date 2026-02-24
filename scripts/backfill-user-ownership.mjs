import 'dotenv/config'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function resolveTargetUser() {
  const rawEmail = process.env.BACKFILL_USER_EMAIL?.trim().toLowerCase()
  if (rawEmail) {
    const byEmail = await prisma.user.findFirst({
      where: { email: { equals: rawEmail, mode: 'insensitive' } },
      select: { id: true, email: true, createdAt: true }
    })
    if (!byEmail) {
      throw new Error(`No user found for BACKFILL_USER_EMAIL=${rawEmail}`)
    }
    return byEmail
  }

  const oldest = await prisma.user.findFirst({
    orderBy: { createdAt: 'asc' },
    select: { id: true, email: true, createdAt: true }
  })
  if (!oldest) {
    throw new Error('No users found. Create at least one account before running backfill.')
  }
  return oldest
}

async function main() {
  const target = await resolveTargetUser()
  console.log(`[backfill] target user: ${target.email} (${target.id})`)

  const result = await prisma.$transaction(async (tx) => {
    const players = await tx.player.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const trainings = await tx.training.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const plateaus = await tx.plateau.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const matches = await tx.match.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const attendance = await tx.attendance.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const trainingDrills = await tx.trainingDrill.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })
    const diagrams = await tx.diagram.updateMany({
      where: { userId: null },
      data: { userId: target.id }
    })

    return {
      players: players.count,
      trainings: trainings.count,
      plateaus: plateaus.count,
      matches: matches.count,
      attendance: attendance.count,
      trainingDrills: trainingDrills.count,
      diagrams: diagrams.count,
    }
  })

  console.log('[backfill] updated rows:', result)
  console.log('[backfill] done')
}

main()
  .catch((err) => {
    console.error('[backfill] failed:', err.message)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
