# T-016B-2 — controlled incremental merge versus same-time full truth

Run 2026-09-19T16:27Z from the orchestrator shell, no API key, 7 s between requests, 3 API
requests. All fetches written to scratch; nothing in the repository's protected paths was
modified. No fetcher was built.

## Setup, fixed before any fetch

`t016b2_plan.json` was written before the first request.

| | |
|---|---|
| Slice | CVEs published `2026-09-01` … `2026-09-05` |
| Why this slice | inside the cached snapshot's coverage; recent enough to be under active NVD analysis so updates were likely; small enough that a full truth refetch is one request |
| Snapshot A | extracted read-only from the frozen cache: **1,859 rows**, id sha256 `8f7325f8…` |
| Snapshot A statuses | Deferred 847, Analyzed 371, Received 266, Awaiting Analysis 260, Undergoing Analysis 63, Modified 31, **Rejected 21**; 5 KEV |
| T0 | **`2026-09-17T00:00:00.000`** |
| T1 | `2026-09-19T16:27:30Z` |

**T0 is deliberately earlier than the cache's own `fetched_at`** of `2026-09-17T11:45:59Z`.
That timestamp is when the manifest was written at the *end* of a 2–2.5 hour ingest run, so a
record modified after an early window was fetched but before the manifest was written would
fall outside a window starting there. Backing T0 up to midnight costs duplicate fetching and
removes that omission. Duplicates are acceptable; silent omission is not.

## Completeness gates — both passed

| | delta | truth |
|---|---|---|
| pages | 2 | 1 |
| first / last `totalResults` | 3,712 / 3,712 | 1,859 / 1,859 |
| fetched rows | 3,712 | 1,859 |
| rows == totalResults | yes | yes |
| duplicate IDs across pages | 0 | 0 |

The condition established in T-016B held on live data in both directions.

## Merge

33 of the 3,712 delta records fell inside the slice; all 33 were content `UPDATE`s. No
`INSERT`, no `CONFLICT_REVIEW`, no stale records.

**Idempotency passed.** Re-applying the same delta produced `NO_CONTENT_CHANGE` for all 33,
an identical ID set and identical canonical hashes.

## S0 result: FAIL — and the cause is upstream, not the merge

| Check | Result |
|---|---|
| row count | 1,859 vs 1,859 |
| ID symmetric difference | **0** |
| `lastModified` mismatch | **0** |
| rejected-status mismatch | **0** |
| KEV mismatch | **0** |
| canonical row mismatch | **2** |
| explained by drift after the delta fetch | **0** |

The two records are `CVE-2026-84658` and `CVE-2026-84659`.

### What actually happened

Both changed `vulnStatus` from `Awaiting Analysis` to `Undergoing Analysis` between the cached
snapshot and the truth fetch, while `lastModified` stayed at `2026-09-03T17:13:16.490` in both.
No other field differs.

Because `lastModified` did not move, **neither record appeared in the `[T0, T1)` modified
window**, and no lastMod-based incremental ingest could have seen the change.

This is not a merge defect and not drift between the two fetches: the change predates the delta
fetch, the delta window was verified complete, and the merge reproduced every record it was
given. **The upstream invariant that `lastModified` tracks content change does not hold.**

### Scale

Of the 1,859 slice records, **35 actually changed** between the cache and truth. 33 were caught
by the modified window; **2 were not — 5.7% of observed changes were invisible to `lastModified`.**

### Does it affect the dataset?

Not in this instance. `docs/CHANGE_MODEL.md` §1 traces `vulnStatus` to `is_rejected` and thence
to eligibility, but neither status here is `Rejected`, so composition is unaffected.

The mechanism is the finding, not this instance. The same silent path could carry a transition
**into** `Rejected`, which does change eligibility and therefore the dataset. Nothing observed
here says such a transition bumps `lastModified`.

## Published-partition impact (§30)

The full 3,712-row delta spread across **13** published-date partitions, from `2012-11-04` to
`2026-09-19`.

| Partition | rows |
|---|---:|
| `2026-07-08_2026-11-03` | 3,540 |
| `2026-03-11_2026-07-07` | 111 |
| `2025-07-16_2025-11-11` | 16 |
| `2025-11-12_2026-03-10` | 13 |
| `2023-08-02_2023-11-28` | 10 |
| eight others | 1–5 each |

95.4% land in the newest partition; the long tail is **172 rows across 12 older partitions**.
Under a physical repartition those twelve frozen partitions would be rewritten for 172 rows.
A logical overlay avoids the rewrite entirely, which supports keeping the working assumption.

## Change volume

3,712 records over roughly three days is about 1,240 per day — against the ~8,000 per day that a
naive extrapolation from the earlier two-hour probe (672 records) would give. The probe window
was busier than average, so that extrapolation overestimated by about 6.5×. Change volume is
therefore small relative to 257,913 records, and the theoretical saving from incremental fetch
is large.

## Where this leaves the track

Everything the experiment could control worked: gates passed, merge was correct and idempotent,
IDs matched exactly, drift was distinguishable from defect. The failure is an upstream property
that no merge logic can fix.

So S0 equivalence **cannot be guaranteed by a lastMod-based incremental ingest alone**.
T-016A §2.2 already required periodic full reconciliation on the strength of NVD's own advisory;
this is a direct observation of the same class of problem, in our own data, at a measured rate
of 5.7% of changes.

The open question for the next step is not whether to reconcile, but how often, and how far the
reconciliation interval can be stretched before the risk of carrying a stale `vulnStatus`
outweighs the saving. That is a measurement, not an assumption.
