-- Add explicit team category to enforce server-side business rules.
ALTER TABLE "Team" ADD COLUMN "category" TEXT;

UPDATE "Team"
SET "category" = 'Seniors'
WHERE "category" IS NULL;

ALTER TABLE "Team" ALTER COLUMN "category" SET NOT NULL;
