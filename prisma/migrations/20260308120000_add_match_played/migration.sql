ALTER TABLE "Match" ADD COLUMN IF NOT EXISTS "played" BOOLEAN NOT NULL DEFAULT false;

UPDATE "Match" m
SET "played" = CASE
  WHEN EXISTS (
    SELECT 1
    FROM "MatchTeam" mt
    WHERE mt."matchId" = m."id"
      AND mt."score" <> 0
  ) THEN true
  WHEN EXISTS (
    SELECT 1
    FROM "Scorer" s
    WHERE s."matchId" = m."id"
  ) THEN true
  ELSE false
END;
