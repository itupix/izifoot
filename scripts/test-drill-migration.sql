-- Run against an isolated PostgreSQL test database:
-- psql "$TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-drill-migration.sql
-- Temporary tables shadow application tables; the transaction always rolls back.
BEGIN;
CREATE TEMP TABLE "Drill" (
  "id" text PRIMARY KEY, "category" text NOT NULL, "duration" integer NOT NULL,
  "players" text NOT NULL, "description" text NOT NULL
);
CREATE TEMP TABLE "Training" ("id" text PRIMARY KEY, "duration" integer);
CREATE TEMP TABLE "TrainingDrill" (
  "id" text PRIMARY KEY, "trainingId" text NOT NULL REFERENCES "Training"("id"),
  "drillId" text NOT NULL REFERENCES "Drill"("id"), "duration" integer,
  "order" integer NOT NULL, "notes" text
);
INSERT INTO "Drill" VALUES
 ('legacy', 'echauffement', 15, '8', 'Description intacte'),
 ('valid', 'technique', 20, 'Tous', 'Texte existant');
INSERT INTO "Training" VALUES ('session', 90);
INSERT INTO "TrainingDrill" VALUES ('linked', 'session', 'legacy', 10, 3, 'Note intacte');
\ir ../prisma/migrations/20261018100000_simplify_drill_metadata/migration.sql
DO $$
BEGIN
  IF (SELECT count(*) FROM "Drill" WHERE "category" = 'autres') <> 2 THEN
    RAISE EXCEPTION 'Every existing drill must migrate to autres';
  END IF;
  IF (SELECT "description" FROM "Drill" WHERE "id" = 'legacy') <> 'Description intacte' THEN
    RAISE EXCEPTION 'Description was changed';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM "TrainingDrill" WHERE "id"='linked' AND "drillId"='legacy' AND "trainingId"='session' AND "order"=3 AND "notes"='Note intacte') THEN
    RAISE EXCEPTION 'Training linkage metadata was changed';
  END IF;
  IF (SELECT "duration" FROM "Training" WHERE "id"='session') <> 90 THEN
    RAISE EXCEPTION 'Session duration was changed';
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema LIKE 'pg_temp_%' AND ((table_name='Drill' AND column_name IN ('duration','players')) OR (table_name='TrainingDrill' AND column_name='duration'))) THEN
    RAISE EXCEPTION 'Retired metadata columns remain';
  END IF;
  INSERT INTO "Drill" ("id", "description") VALUES ('default', 'Default category');
  IF (SELECT "category" FROM "Drill" WHERE "id"='default') <> 'autres' THEN
    RAISE EXCEPTION 'Default category must be autres';
  END IF;
  INSERT INTO "Drill" VALUES ('collectif', 'collectif', 'Collectif'), ('technique', 'technique', 'Technique'), ('jeu', 'jeu', 'Jeu');
  BEGIN
    INSERT INTO "Drill" VALUES ('invalid', 'autre', 'Invalid');
    RAISE EXCEPTION 'Invalid category was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END $$;
ROLLBACK;
