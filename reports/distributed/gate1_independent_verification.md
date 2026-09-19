# Gate 1 — independent verification

The harness in `src/security_llm/bench/near_duplicate_scaling.py` produced
`gate1_scaling.{json,md}`. This file records a separate re-measurement run by the
orchestrator against the same harness, on the same host, to check whether the Case A
conclusion holds independently of the original run.

It is kept separate because `gate1_scaling.md` is generated; an addendum written into it
would be lost on the next run.

## Re-measured `internal_all_pairs`, similarity phase

| N | similarity s | ratio vs previous | N ratio |
|---:|---:|---:|---:|
| 1,000 | 0.0103 | — | — |
| 2,500 | 0.0533 | 5.175× | 2.50× |
| 5,000 | 0.2087 | 3.916× | 2.00× |
| 10,000 | 0.9020 | 4.322× | 2.00× |

Log-log slope **1.940**, R² **0.9985**, against the original run's 1.870 and 0.9995.
The 2,500 → 5,000 similarity ratio is 3.916× here and 3.915× in the original run.

**The quadratic conclusion reproduces.** Case A stands.

## Two corrections to how the original numbers should be read

**1. Absolute wall times are load-dependent; the ratios are not.**

The same `internal_all_pairs, N=5,000` point measured 0.658 s in the original run and
0.2087 s here — roughly a 3× difference — while peak RSS agreed (0.407 vs 0.409 GiB). The
original run was measured while the machine was busier. A uniform slowdown shifts the
intercept of a log-log fit but not its slope, which is why both runs agree on the slope and
on the step ratios.

Read the absolute seconds in `gate1_scaling.md` as one observation under that run's
conditions, not as a stable property of the workload. The growth ratios are the durable
result.

**2. `N=10,000` was measured after all, and it runs.**

The harness stopped `internal_all_pairs` after `N=5,000` on the implemented information
stop, having established the trend over four points, and recorded a *projected* peak of
1.304 GiB for `N=10,000`.

Measured here: **0.902 s and 0.996 GiB** — the projection over-estimated memory by about
31%, and the step costs about a second. The stop was defensible under the stated rule but
conservative in hindsight: this point cost almost nothing and replaces a projection with a
measurement, which is the stronger form of evidence. It also extends the confirmed
quadratic trend to 49,995,000 unique pairs.

`N=24,975` remains unmeasured. Nothing here claims it would complete.

## What this does not change

The recommendation is unchanged: end the dense exact all-pairs track and measure bounded-memory
candidate reduction (blockwise exact top-k, LSH, ANN, or candidate generation with exact
refinement) next. These are single-node measurements on one machine.
