# Training attendance sync endpoint

## Endpoint

- Method: `PUT`
- Route: `/trainings/:trainingId/attendance`
- Auth: same auth middleware as existing coach/direction write endpoints (`ensureStaff`)

## Request body

```json
{
  "playerIds": ["player-1", "player-2", "player-3"]
}
```

`playerIds` is the full list of players marked present for this training.

## Behavior

- The endpoint resolves the training in the caller scope. If not found/in scope: `404`.
- Only `DIRECTION` and `COACH` can write. Other roles: `403`.
- The backend computes a full attendance snapshot for the training team:
  - listed players => `TRAINING` (present)
  - non-listed team players => `TRAINING_ABSENT` (present = false in API response)
- Synchronization is transactional and idempotent (same input => same final state, no duplicates).
- Existing `POST /attendance` remains unchanged for single-player updates.

## Response

HTTP `200`

```json
{
  "items": [
    {
      "id": "...",
      "session_type": "TRAINING",
      "session_id": "training-123",
      "playerId": "player-1",
      "present": true
    }
  ]
}
```

`present` is derived from stored session type (`TRAINING` / `TRAINING_ABSENT`).
