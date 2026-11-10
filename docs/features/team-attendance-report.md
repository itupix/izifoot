# API CONTRACT — Team season training attendance

`GET /teams/:teamId/attendance-report?seasonId=<required>` is read-only and returns the complete selected team/season without pagination. Authentication is required; only DIRECTION and COACH may use it. Direction can access teams in its club; coach only managed teams in its club. Never exposes another club. Missing/inaccessible team or season: 404 `{error:string}`; invalid/missing seasonId: 400; unauthorized role: 403; unauthenticated: 401; unexpected: 500.

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

All selected season/team trainings are returned, ordered by date then id; months are YYYY-MM in Europe/Paris and include months having trainings. Roster includes active and inactive players, alphabetically. Dates before player creation or after deactivation are NOT_APPLICABLE unless an explicit historical record exists. Deleted/transferred players cannot be reconstructed because the schema has no historical roster; inactive players remain visible. Historical percentages describe available data, not a guarantee of complete season records.

Existing season picker API: `GET /clubs/me/seasons?limit=200&offset=0` (paginated default 50 max 200) returns `{items:[{id,clubId,key,label,startDate,endDate,isCurrent}],pagination:{limit,offset,returned}}` ordered startDate descending. It creates the current club season if absent. Select isCurrent by default, otherwise first available; fetch successive pages while returned equals limit. Pass its id explicitly to report.

Web and iOS must render the same server percentages and status meanings. Use — for null and explain “Présences / présences et absences renseignées ; séances non renseignées exclues”. Par mois: month > dated session > player statuses. Par joueur: searchable player > monthly/session details. Report does not mutate attendance.

## Validation

`npm test` builds and runs backend tests, including report rate, calendar, eligibility and scope cases. No migration required.
