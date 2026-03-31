UPDATE "Player"
SET
  "email" = NULL,
  "phone" = NULL,
  "parent_first_name" = NULL,
  "parent_last_name" = NULL
WHERE "is_child" = TRUE;
