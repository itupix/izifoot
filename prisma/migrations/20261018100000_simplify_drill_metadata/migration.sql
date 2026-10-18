-- All previously created drills move to Autres, including already valid categories.
UPDATE "Drill" SET "category" = 'autres';
ALTER TABLE "Drill" ALTER COLUMN "category" SET DEFAULT 'autres';
ALTER TABLE "Drill" ADD CONSTRAINT "Drill_category_check"
  CHECK ("category" IN ('collectif', 'technique', 'jeu', 'autres'));
ALTER TABLE "Drill" DROP COLUMN "duration", DROP COLUMN "players";
ALTER TABLE "TrainingDrill" DROP COLUMN "duration";
