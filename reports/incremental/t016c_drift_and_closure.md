# T-016C — reconciliation interval risk, and T-016 closure

Run 2026-09-19T16:41Z from the orchestrator shell, no API key, 7 s between requests, 18 API
requests. Everything written to scratch; nothing in the repository's protected paths was
modified. No scheduler or fetcher was built.

## Path taken: §39 Case C — historical replay is not possible

Only one historical full snapshot exists (`data/raw/nvd`, snapshot date 2026-09-17), and no
archived delta windows. The 1-day / 3-day / 7-day comparison in the plan cannot be run, and a
synthetic history was not manufactured to substitute for it.

**One gap is measurable**, and only that gap is reported:

| | |
|---|---|
| T0 | `2026-09-17T00:00:00.000` |
| T1 | `2026-09-19T16:41:53.000` |
| Gap | **64.7 hours** (2.7 days) |
| Population | CVEs published 2026-07-08 … 2026-09-17 |
| Baseline | 30,216 rows from the frozen cache, matching its manifest exactly |
| Truth | 31,175 rows, fetched now |

Nothing here is projected to a longer interval.

## Completeness gates — both passed

| | delta | truth |
|---|---|---|
| pages | 2 | 16 |
| first / last `totalResults` | 3,712 / 3,712 | 31,175 / 31,175 |
| fetched rows | 3,712 | 31,175 |
| rows == totalResults | yes | yes |
| duplicate IDs | 0 | 0 |

## Overlay merge

Of 3,712 delta records, 2,922 fell in this population.

| Outcome | Count |
|---|---:|
| INSERT | **959** |
| UPDATE | 1,900 |
| NO_CONTENT_CHANGE | 49 |
| **CONFLICT_REVIEW** | **14** |

Idempotent on re-application. **ID symmetric difference is 0 in both directions** — every one
of the 959 new CVEs was caught by the modified window, and the incremental view invented
nothing.

The 14 conflicts are records whose `lastModified` matched the baseline while their content
differed. They were surfaced rather than silently resolved, which is the behaviour the rule was
written for.

## Drift, separated into three layers

| Layer | Count | Rate |
|---|---:|---:|
| **D0** source drift | **356** | 1.14% |
| **D1** dataset-relevant field drift | **356** | 1.14% |
| **D2** composition impact | **0** | 0.00% |

**All 356 carry an identical `lastModified` on both sides.** Every one is a silent change that
no lastMod-based fetch could see.

**All 356 are `vulnStatus`-only changes.** No description, weakness, published, KEV or
multi-field drift appeared, and the classifier recorded no `rejected_transition`.

D2 was computed by running the pipeline's own `normalize_record` over both versions of every
D1 record and comparing the fields that drive composition — `is_rejected`, `label_status`,
`cwe_id`, `published`, `description_norm_hash`, `cwe_all`. None differed.

That is consistent by construction: `vulnStatus` reaches the dataset only through
`is_rejected`, and none of the 356 crossed the `Rejected` boundary.

## What a full reconciliation would recover

| | |
|---|---:|
| Rows replaced | 356 |
| Dataset-relevant corrections | 356 |
| **Composition corrections** | **0** |
| New IDs recovered | 0 |

Over this gap, reconciliation would have corrected 356 stale `vulnStatus` values and changed
nothing about the dataset.

## The risk that remains, stated honestly

The exposure is narrow. `vulnStatus` matters to the dataset only when it crosses `Rejected`,
and **zero of 356 silent changes did** over 2.7 days on 31,175 records. The baseline holds 661
Rejected records, so the state is common; what was not observed is a *silent transition into
it*.

Zero observations do not bound the rate tightly. By the rule of three, 0 events in 356 gives a
95% upper bound of about **0.84%** of silent changes, i.e. **up to roughly 3 missed Rejected
transitions per 2.7 days** at that bound. That is a confidence bound derived from zero
observations, not a measurement, and it is the number a reconciliation policy would have to be
comfortable with.

## Cost measured

| | requests | rows | wall |
|---|---:|---:|---:|
| Incremental delta | 2 | 3,712 | 17.3 s |
| Truth (this window only) | 16 | 31,175 | 138.2 s |

The truth figure covers one published window, not a full ingest. Full ingest remains the 2 to
2.5 hours recorded earlier, dominated by rate-limited pagination across all windows.

## Can an interval be fixed? No.

One gap was measured. Nothing here shows how D2 risk *accumulates* with interval length,
because there is no second or third point to draw a curve through. Per the plan's §33, the
honest conclusion is:

> **A specific reconciliation interval cannot be determined from this data.**

What *is* established: silent source drift is common (1.14% in 2.7 days), it was confined to
`vulnStatus`, and it produced no dataset-composition change in this observation. Establishing
an interval needs repeated measurements at different gaps, which needs snapshot history this
repository does not have.

## T-016 final architecture

```
periodic validated full fetch
        ↓
immutable trusted base            (published-date partitions, never rewritten)
        ↓
lastModified incremental windows  (query hint only — NOT a version identity)
        ↓
validated update overlay          (completeness gate, deterministic merge, conflicts surfaced)
        ↓
logical current source view
        ↓
deterministic full downstream rebuild   (T-015 Case B: ~56 s, no incremental)
        ↓
periodic full reconciliation      (mandatory — recovers what lastModified cannot signal)
```

Fixed by measurement:

- **`lastModified` is a query hint.** Not a content version, not a change log, not a source
  equivalence key. T-016B-2 and T-016C both observed content changing while it did not.
- **Full reconciliation is part of correctness**, not a safety extra. Its interval is
  undetermined.
- **Immutable base plus overlay**, not physical repartition. The delta touched 13 published
  partitions but 95.4% landed in the newest; rewriting twelve frozen partitions for 172 rows is
  not worth it.
- **Completeness is `sum(page rows) == totalResults`** with `totalResults` equal on the first
  and last page — the literal `"complete": True` in `ingest_nvd.py` is not evidence.
- **Boundaries are `[start, end)`**; the next start reuses the previous last record's exact
  timestamp. Never add a millisecond.
- **`MISSING` is not `DELETE`.** No deletion signal was ever established.

## Track closed

Incremental ingest works as a freshness mechanism: gates hold, merges are deterministic and
idempotent, new IDs are caught completely, and the cost is small. It does **not** replace a
full fetch, because the upstream change signal is incomplete in a way no client-side logic can
repair.

No scheduler, storage engine or orchestration was built, and downstream incremental rebuild
stays closed under T-015 Case B.
