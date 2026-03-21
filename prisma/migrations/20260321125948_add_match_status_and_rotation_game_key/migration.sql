-- Add explicit match status and robust technical key for rotation-game linkage.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'MatchStatus') THEN
    CREATE TYPE "MatchStatus" AS ENUM ('PLANNED', 'PLAYED', 'CANCELLED');
  END IF;
END $$;

ALTER TABLE "Match"
  ADD COLUMN IF NOT EXISTS "status" "MatchStatus" NOT NULL DEFAULT 'PLANNED',
  ADD COLUMN IF NOT EXISTS "rotationGameKey" TEXT;

-- Backfill from legacy boolean source of truth.
UPDATE "Match"
SET "status" = CASE WHEN "played" = true THEN 'PLAYED'::"MatchStatus" ELSE 'PLANNED'::"MatchStatus" END
WHERE "status" IS NULL OR "status" = 'PLANNED'::"MatchStatus";

CREATE INDEX IF NOT EXISTS "Match_plateauId_rotationGameKey_idx"
  ON "Match" ("plateauId", "rotationGameKey");
