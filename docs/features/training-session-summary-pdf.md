# Training session summary PDF

## API contract

`GET /trainings/:id/summary.pdf?timeZone=Europe%2FParis` generates a fresh PDF without storing it. No request body. `timeZone` is an optional valid IANA timezone, default `Europe/Paris`.

Authentication uses the existing cookie or Bearer token. Only `COACH` and `DIRECTION` can download summaries, within existing club/team scope. Parent/player accounts cannot access named attendance exports.

Success: `200`, `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="resume-seance-YYYY-MM-DD.pdf"`, `Cache-Control: private, no-store`. Clients handle the binary response and download/share it.

Errors are JSON: `400 {"error":"Invalid time zone"}`, existing `401` auth errors, existing `403` staff-only error, `404 {"error":"Training not found"}` for missing or inaccessible sessions, `500 {"error":"Failed to generate training summary"}`.

## Content semantics

French date/start time are formatted in the requested timezone. End time uses the saved wall-clock `Training.endTime`; missing end time is explicit. Cancelled sessions display `Statut : Annulée`.

Present players come exclusively from actual `Attendance.session_type=TRAINING`, scoped to the session and team, deduplicated and sorted by name. Neither attendance intentions nor absent rows count. Historical inactive players remain included if marked present.

Exercises are saved `TrainingDrill` attachments in existing `order ASC, id ASC` order, numbered consecutively, with the current catalogue title and description. There is no completed-exercise flag in the model: the summary reports the session's saved exercises. HTML paragraph/list formatting becomes readable text. Missing catalogue entries preserve their position with explicit placeholders. Empty sections are explicit. PDFs paginate and embed DejaVu Sans for accented names and Unicode text; no schema migration is required.

## Validation

`npm test` covers timezone validation, actual attendance scoping/deduplication, exercise ordering/placeholders, rich description conversion and multipage rendering. Visual PDF review covers long exercises, lists, accents and empty/cancelled sessions.
