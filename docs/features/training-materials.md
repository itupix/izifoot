# Training materials

## API CONTRACT

`GET /trainings/:id/materials` requires the existing authenticated session. No request body or query parameters. Training visibility and diagram access use the existing user/team/club scope.

Success (`200`):

```json
{"items":[{"type":"cone","label":"Cônes","quantity":4},{"type":"bib","label":"Chasubles","quantity":null}],"drillCount":3,"missingDiagramCount":1}
```

`items` has stable order: `cup`, `cone`, `ball`, `post`, `bib`. Labels are French nouns, without quantities. Equipment quantities are positive integers. Bibs have unknown quantity (`null`), indicated by multiple player colors using the existing exercise diagram convention; players and arrows are not equipment.

For each selected training exercise, select the latest session-specific diagram, falling back to the latest catalog diagram only if none exists. Ties sort by ascending diagram ID. Count each equipment type per frame and retain the maximum across all frames and exercises: successive exercises reuse equipment. Legacy root `items` is supported. Only diagram declarations are counted; free text is never interpreted or estimated. A malformed session override is reported as missing rather than silently replaced by a catalog diagram.

`drillCount` counts selected exercise occurrences. `missingDiagramCount` counts occurrences without a usable diagram; valid empty diagrams count as available. Empty selection yields zero counts and empty items. Partial results retain known equipment and expose the incomplete count.

Errors: existing authentication `401`; `404` with `{"error":"Training not found"}` for missing/inaccessible training; unexpected loading failures `500` with `{"error":"Failed to load training materials"}`.

## Clients and UX

Display a Matériel card after exercises, with a short explanation that quantities are maxima because equipment is reused. Distinguish no selected exercises, no declared material, and incomplete diagram coverage. Fetch again after adding, removing, replacing or editing exercise diagrams; loading failures must not be presented as an empty equipment list. Web and iOS share this contract and never derive guessed quantities from exercise prose.

## Validation

`npm test` covers all backend tests, including maximum aggregation, ordering, session precedence, catalog fallback, legacy diagrams, bibs, empty states and malformed data.
