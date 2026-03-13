DO $$ BEGIN
  CREATE TYPE "MatchEventType" AS ENUM ('GOAL_FOR', 'GOAL_AGAINST', 'SUBSTITUTION');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS "MatchEvent" (
  "id" TEXT NOT NULL,
  "matchId" TEXT NOT NULL,
  "minute" INTEGER NOT NULL,
  "type" "MatchEventType" NOT NULL,
  "scorerId" TEXT,
  "assistId" TEXT,
  "slotId" TEXT,
  "inPlayerId" TEXT,
  "outPlayerId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "MatchEvent_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "MatchEvent_matchId_minute_createdAt_idx"
  ON "MatchEvent"("matchId", "minute", "createdAt");

DO $$ BEGIN
  ALTER TABLE "MatchEvent"
    ADD CONSTRAINT "MatchEvent_matchId_fkey"
    FOREIGN KEY ("matchId") REFERENCES "Match"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;
