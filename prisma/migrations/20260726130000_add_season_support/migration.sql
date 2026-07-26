CREATE TABLE "Season" (
  "id" TEXT NOT NULL,
  "clubId" TEXT NOT NULL,
  "key" TEXT NOT NULL,
  "label" TEXT NOT NULL,
  "startDate" TIMESTAMP(3) NOT NULL,
  "endDate" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "Season_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "Club"
  ADD COLUMN IF NOT EXISTS "seasonStartMonth" INTEGER NOT NULL DEFAULT 8,
  ADD COLUMN IF NOT EXISTS "seasonStartDay" INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS "seasonEndMonth" INTEGER NOT NULL DEFAULT 7,
  ADD COLUMN IF NOT EXISTS "seasonEndDay" INTEGER NOT NULL DEFAULT 31,
  ADD COLUMN IF NOT EXISTS "seasonTimezone" TEXT NOT NULL DEFAULT 'Europe/Paris';

ALTER TABLE "Training" ADD COLUMN IF NOT EXISTS "seasonId" TEXT;
ALTER TABLE "Plateau" ADD COLUMN IF NOT EXISTS "seasonId" TEXT;
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "seasonId" TEXT;
ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "date" TIMESTAMP(3);

CREATE UNIQUE INDEX "Season_clubId_key_key" ON "Season"("clubId", "key");
CREATE UNIQUE INDEX "Season_clubId_startDate_endDate_key" ON "Season"("clubId", "startDate", "endDate");
CREATE INDEX "Season_clubId_startDate_idx" ON "Season"("clubId", "startDate" DESC);
CREATE INDEX "Training_seasonId_date_idx" ON "Training"("seasonId", "date");
CREATE INDEX "Plateau_seasonId_date_idx" ON "Plateau"("seasonId", "date");
CREATE INDEX "Match_seasonId_date_idx" ON "Match"("seasonId", "date");

ALTER TABLE "Season"
  ADD CONSTRAINT "Season_clubId_fkey"
  FOREIGN KEY ("clubId") REFERENCES "Club"("id")
  ON DELETE CASCADE
  ON UPDATE CASCADE;

ALTER TABLE "Training"
  ADD CONSTRAINT "Training_seasonId_fkey"
  FOREIGN KEY ("seasonId") REFERENCES "Season"("id")
  ON DELETE SET NULL
  ON UPDATE CASCADE;

ALTER TABLE "Plateau"
  ADD CONSTRAINT "Plateau_seasonId_fkey"
  FOREIGN KEY ("seasonId") REFERENCES "Season"("id")
  ON DELETE SET NULL
  ON UPDATE CASCADE;

ALTER TABLE "Match"
  ADD CONSTRAINT "Match_seasonId_fkey"
  FOREIGN KEY ("seasonId") REFERENCES "Season"("id")
  ON DELETE SET NULL
  ON UPDATE CASCADE;
