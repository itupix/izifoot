#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL is required."
  echo "Example: DATABASE_URL='postgresql://postgres:postgres@localhost:5432/izifoot?schema=public' MATCHDAY_ID='c...' npm run perf:explain"
  exit 1
fi

if [[ -z "${MATCHDAY_ID:-}" ]]; then
  echo "ERROR: MATCHDAY_ID is required."
  echo "Provide a matchday id to benchmark list/summary queries."
  exit 1
fi

TEAM_ID="${TEAM_ID:-}"
CLUB_ID="${CLUB_ID:-}"
USER_ID="${USER_ID:-}"

if [[ -z "$TEAM_ID" || -z "$CLUB_ID" || -z "$USER_ID" ]]; then
  DISCOVERED=$(
    psql "$DATABASE_URL" -At -F '|' -v ON_ERROR_STOP=1 -v matchday_id="$MATCHDAY_ID" \
      -c "SELECT COALESCE(\"teamId\",''), COALESCE(\"clubId\",''), COALESCE(\"userId\",'') FROM \"Attendance\" WHERE \"session_id\" = :'matchday_id' LIMIT 1;"
  )
  IFS='|' read -r AUTO_TEAM_ID AUTO_CLUB_ID AUTO_USER_ID <<< "$DISCOVERED"
  TEAM_ID="${TEAM_ID:-$AUTO_TEAM_ID}"
  CLUB_ID="${CLUB_ID:-$AUTO_CLUB_ID}"
  USER_ID="${USER_ID:-$AUTO_USER_ID}"
fi

if [[ -z "$TEAM_ID" ]]; then
  echo "ERROR: TEAM_ID could not be auto-discovered. Set TEAM_ID explicitly."
  exit 1
fi

if [[ -z "$CLUB_ID" ]]; then
  echo "ERROR: CLUB_ID could not be auto-discovered. Set CLUB_ID explicitly."
  exit 1
fi

if [[ -z "$USER_ID" ]]; then
  echo "ERROR: USER_ID could not be auto-discovered. Set USER_ID explicitly."
  exit 1
fi

echo "Running EXPLAIN ANALYZE with:"
echo "  MATCHDAY_ID=$MATCHDAY_ID"
echo "  TEAM_ID=$TEAM_ID"
echo "  CLUB_ID=$CLUB_ID"
echo "  USER_ID=$USER_ID"
echo

psql "$DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v matchday_id="$MATCHDAY_ID" \
  -v team_id="$TEAM_ID" \
  -v club_id="$CLUB_ID" \
  -v user_id="$USER_ID" <<'SQL'
\timing on

SELECT 'Q1 - matches list by matchday ordered by createdAt desc' AS benchmark;
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM "Match"
WHERE "plateauId" = :'matchday_id'
ORDER BY "createdAt" DESC
LIMIT 50;

SELECT 'Q2 - attendance by session and team' AS benchmark;
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM "Attendance"
WHERE "session_id" = :'matchday_id'
  AND "session_type" IN ('PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE')
  AND "teamId" = :'team_id';

SELECT 'Q3 - attendance scoped by club OR user (legacy-compatible scope)' AS benchmark;
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM "Attendance"
WHERE (
  ("session_id" = :'matchday_id'
   AND "session_type" IN ('PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE')
   AND "clubId" = :'club_id')
  OR
  ("session_id" = :'matchday_id'
   AND "session_type" IN ('PLATEAU', 'PLATEAU_ABSENT', 'PLATEAU_CONVOKE')
   AND "userId" = :'user_id')
);

SELECT 'Q4 - players list by team with sort' AS benchmark;
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM "Player"
WHERE "teamId" = :'team_id'
ORDER BY "first_name" ASC, "last_name" ASC, "name" ASC
LIMIT 100;

SELECT 'Q5 - trainings list by team ordered by date desc' AS benchmark;
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM "Training"
WHERE "teamId" = :'team_id'
ORDER BY "date" DESC
LIMIT 50;
SQL
