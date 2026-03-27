# Performance Benchmarks (EXPLAIN ANALYZE)

Use this to measure the critical queries behind:
- `GET /matches`
- `GET /attendance`
- `GET /players`
- `GET /trainings`

## Prerequisites

- A reachable PostgreSQL instance via `DATABASE_URL`.
- A real matchday id in `MATCHDAY_ID`.

## Run

```bash
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/izifoot?schema=public" \
MATCHDAY_ID="cmmxwx23a0001ounbhvjbnbv4" \
npm run perf:explain
```

Optional explicit scope values:

```bash
DATABASE_URL="..." \
MATCHDAY_ID="..." \
TEAM_ID="..." \
CLUB_ID="..." \
USER_ID="..." \
npm run perf:explain
```

If `TEAM_ID` / `CLUB_ID` / `USER_ID` are missing, the script tries to discover them from `Attendance`.

## Output interpretation

- `Execution Time` is the final latency for each query.
- `Seq Scan` on tiny datasets is normal.
- On larger datasets, you should see index usage (`Index Scan` / `Bitmap Index Scan`) on:
  - `Match(plateauId, createdAt)`
  - `Attendance(session_type, session_id, teamId)`
  - `Player(teamId, last_name, first_name, name)`
  - `Training(teamId, date)`
