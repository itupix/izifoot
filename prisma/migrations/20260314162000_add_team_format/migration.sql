-- Add explicit team format to enforce server-side business rules.
ALTER TABLE "Team" ADD COLUMN "format" TEXT;

UPDATE "Team"
SET "format" = '11v11'
WHERE "format" IS NULL;

ALTER TABLE "Team" ALTER COLUMN "format" SET NOT NULL;

ALTER TABLE "Team"
ADD CONSTRAINT "Team_format_check"
CHECK ("format" IN ('3v3', '5v5', '8v8', '11v11'));
