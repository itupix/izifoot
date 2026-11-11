# API CONTRACT — Team season training attendance

`GET /teams/:teamId/attendance-report` is read-only and returns the complete selected team's **current season** without pagination or season selection. The server resolves/creates the current club season using the club calendar and Europe/Paris at `generatedAt`. An optional legacy `seasonId` is accepted only when equal to that current season; another ID returns 400 `{error:'Only the current season is available'}`. Malformed seasonId returns 400. Authentication is required; only DIRECTION and COACH may use it. Direction can access teams in its club; coach only managed teams in its club. Never exposes another club. Missing/inaccessible team or club/current season: 404 `{error:string}`; unauthorized role: 403; unauthenticated: 401; unexpected: 500. Normally the current season is created if absent, so no historical fallback occurs.

```ts
type Stats = { presentCount:number; absentCount:number; unrecordedCount:number; recordedCount:number; attendanceRate:number|null }
type AttendanceStatus = 'PRESENT'|'ABSENT'|'UNRECORDED'|'UPCOMING'|'CANCELLED'|'NOT_APPLICABLE'
type Report = {
  teamId:string;
  season:{id:string;key:string;label:string;startDate:string;endDate:string};
  generatedAt:string;
  summary:Stats;
  months:{month:string;summary:Stats}[];
  trainings:{id:string;date:string;endTime:string|null;status:string;month:string;includedInRate:boolean}[];
  players:{id:string;name:string;first_name:string|null;last_name:string|null;is_active:boolean;summary:Stats;months:{month:string;summary:Stats}[];attendances:{trainingId:string;status:AttendanceStatus}[]}[];
}
```

`recordedCount = presentCount + absentCount`. `attendanceRate` is present/recorded × 100 rounded to one decimal; null for no recorded observations. Team/month summary is weighted by player-session observations, never averages of percentages. Unknown observations are shown separately and never counted absent. Cancelled and future sessions are excluded even when they have saved attendance. A past session means `date <= generatedAt` (started, not necessarily completed: Training has no completed state). Only TRAINING/TRAINING_ABSENT records count; intent is excluded. Contradictory legacy records conservatively count ABSENT.

All current season/selected team trainings are returned, ordered by date then id; months are YYYY-MM in Europe/Paris and include months having trainings. Roster includes only current team players with `is_active=true`, alphabetically. Inactive/out-of-roster players and all their attendance observations are excluded from player lists and every team/month/season total; the existing roster flag is authoritative. Dates before player creation or after deactivation are NOT_APPLICABLE unless an explicit historical record exists. Deleted/transferred players cannot be reconstructed because the schema has no historical roster; inactive, transferred and deleted players are not included. Historical percentages describe available data, not a guarantee of complete season records.

The existing `GET /clubs/me/seasons` API is unchanged but is not needed for this report. Web and iOS call the report without seasonId, display the response season label as plain text and provide no season picker. Empty roster text: « Aucun joueur dans l’effectif actuel. ». No season catalogue or historical fallback is used.

Web and iOS must render the same server percentages and status meanings. Use — for null and explain “Présences / présences et absences renseignées ; séances non renseignées exclues”. Par mois: month > dated session > player statuses. Par joueur: searchable player > monthly/session details. Report does not mutate attendance.

## Validation

`npm test` builds and runs backend tests, including report rate, calendar, eligibility and scope cases. No migration required.

## API CONTRACT — monthly PDF

`GET /teams/:teamId/attendance-report/pdf?month=YYYY-MM` requires an explicit valid calendar month. It uses the same authenticated DIRECTION/COACH scope, current club season, active-only roster, status rules and server monthly percentages as the JSON report. Missing/malformed month returns 400; month outside the current season returns 400 `{error:'Month is outside the current season'}`; missing/inaccessible team/club/season 404; unauthorized role 403; unauthenticated 401; unexpected errors 500. An allowed month without trainings produces a valid PDF with an empty-state message.

Success: binary `application/pdf`, `Content-Disposition: attachment; filename="presences-YYYY-MM.pdf"`, `Cache-Control: private, no-store`. No request body or season selector. PDF includes the selected team, current season, French month, alphabetical active players, chronological dates without times, monthly server percentages and six-status legend. No counters, calculation helper or historical disclaimer. A4 landscape, at most five date columns per group, with repeated headers and all players/dates preserved across pages. Web downloads the file; iOS uses its system preview/share flow. Both clients must discard stale results after team/month changes.
