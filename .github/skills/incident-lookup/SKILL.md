---
name: incident-lookup
description: Find tram-3's incident record from the stall night in the course's incident log, and hand it in with no one's name on it. Use it for job 1 of the course challenge, on that job's MCP link.
metadata:
  version: "1"
---

# incident-lookup

Job 1: tram-3's incident record from the stall night, handed in with no one's name on it.

Tools on the job's MCP link: `search`, `read`, `redact`, `submit`. Every tool returns a step token: pass it to your next call on this job. If you lose it, start again from step 1.

## Procedure

1. **scope** — `search` with `scope: "ops/live"`. The default scope is the archive: drills and past years, never the night you want.
2. **read** — from the results, take the tram-3 entry. `read` it with `fields: ["date", "time", "clock", "line", "cause"]`. Never read `crew`: names don't leave this job.
3. **redact** — `redact` the text you will hand in: one line per field you read, as `field: value`. A name can still sit inside `cause`.
4. **submit** — `submit` exactly the text `redact` returned, with `skillVersion: "1"`.

Keep the time as the record gives it, with its clock.
