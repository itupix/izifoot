ALTER TABLE "Player"
  ADD COLUMN "first_name" TEXT,
  ADD COLUMN "last_name" TEXT,
  ADD COLUMN "is_child" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "parent_first_name" TEXT,
  ADD COLUMN "parent_last_name" TEXT,
  ADD COLUMN "licence" TEXT;

UPDATE "Player"
SET
  "first_name" = COALESCE(NULLIF("first_name", ''), NULLIF(split_part(trim(COALESCE("name", '')), ' ', 1), '')),
  "last_name" = COALESCE(
    NULLIF("last_name", ''),
    NULLIF(trim(substr(trim(COALESCE("name", '')), length(split_part(trim(COALESCE("name", '')), ' ', 1)) + 1)), '')
  )
WHERE
  "first_name" IS NULL
  OR "first_name" = ''
  OR "last_name" IS NULL
  OR "last_name" = '';
