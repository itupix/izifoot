CREATE TABLE "Championship" (
 "id" TEXT NOT NULL, "clubId" TEXT NOT NULL, "teamId" TEXT NOT NULL, "seasonId" TEXT NOT NULL,
 "name" TEXT NOT NULL, "doubleRoundRobin" BOOLEAN NOT NULL DEFAULT true,
 "status" TEXT NOT NULL DEFAULT 'DRAFT', "revision" INTEGER NOT NULL DEFAULT 1,
 "data" JSONB NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "Championship_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "Championship_teamId_fkey" FOREIGN KEY ("teamId") REFERENCES "Team"("id") ON DELETE CASCADE,
 CONSTRAINT "Championship_seasonId_fkey" FOREIGN KEY ("seasonId") REFERENCES "Season"("id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX "Championship_teamId_seasonId_key" ON "Championship"("teamId", "seasonId");
CREATE INDEX "Championship_clubId_teamId_idx" ON "Championship"("clubId", "teamId");
