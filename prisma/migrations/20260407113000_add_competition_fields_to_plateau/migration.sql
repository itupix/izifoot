-- Add competition metadata on Plateau while keeping backward compatibility with existing "plateau" flow.
ALTER TABLE "Plateau"
ADD COLUMN "competition_type" TEXT NOT NULL DEFAULT 'PLATEAU',
ADD COLUMN "tournament_has_group_stage" BOOLEAN,
ADD COLUMN "tournament_knockout_mode" TEXT;

-- Normalize legacy rows explicitly.
UPDATE "Plateau"
SET "competition_type" = 'PLATEAU'
WHERE "competition_type" IS NULL OR btrim("competition_type") = '';
