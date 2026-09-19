# Gate 1 exact near-duplicate audit scaling baseline

## Decision

**Case A holds.** The dense exact `internal_all_pairs` similarity phase has a
log-log time slope of **1.870** with **R² = 0.9995** over four measured points.
The all-pairs experiment therefore stopped after `N=5,000`; `N=10,000` and
`N=24,975` were rejected before launch because another dense point would not
change the decision. The next track should reduce candidates first, using a
blockwise exact top-k method, LSH, ANN, or candidate generation followed by
exact refinement.

The result is different for the shape used by the current audit.
`query_vs_reference` completed the full `Q=24,975` test population against the
fixed `R=12,000` train reference in **15.163 s** with **2.619 GiB** peak RSS.
Its similarity-phase slope was **1.086** with **R² = 0.9908**, consistent with
linear growth in `Q` when `R` is fixed.

Case C was not observed: no run failed, swapped, or showed a second dense copy
binding before the algorithmic trend. Dense materialization is still the
scaling constraint, but it did not cross the 12 GiB ceiling in a measured run.

## Method and environment

- Implementation commit: `73a8948c2680ced114f239657e340784b11a1f34` on
  `feat/distributed-pipeline`.
- Host: Linux 5.15, 12 logical CPUs, 31.18 GiB RAM, 2.00 GiB swap; 26.00 GiB
  was available at the start of the clean run. Python 3.11.15, NumPy 2.4.6,
  scikit-learn 1.9.1.
- Every executed `(N, shape)` ran in a fresh subprocess. Child
  `resource.getrusage(...).ru_maxrss` supplied peak RSS; the parent independently
  monitored process RSS, thread count, host swap, available memory, load, exit
  status, and elapsed time.
- The computation is the audit computation: `TfidfVectorizer(ngram_range=(1,
  2), sublinear_tf=True, min_df=2, stop_words=None)` followed by
  `cosine_similarity(..., dense_output=True)` and `argmax`. The harness imports
  these implementations from the protected audit module and uses an AST guard
  to refuse execution if the settings drift.
- Sampling used `random.Random(42).sample(range(24_975), N)` over
  `data/sft/test.jsonl`, preserving sampled-index order. For
  `query_vs_reference`, those rows were compared with all 12,000 rows of
  `data/sft/train.jsonl`. For `internal_all_pairs`, the sampled test rows were
  compared internally, the diagonal was changed in place to exclude self
  matches, and each unordered pair was counted once for throughput.
- The parent refused a step if projected peak RSS exceeded 12 GiB, projected
  wall time exceeded 1,800 s, swap grew, a major fault appeared, available
  memory fell below 2 GiB, a process failed, or the quadratic trend was already
  decision-complete. The clean run had zero swap growth and zero major faults.
- A preliminary cold invocation stopped after `query_vs_reference, N=300`
  recorded two major faults (with no swap change). It is not included in the
  table. A new invocation against the warmed local files and libraries retained
  the same zero-tolerance pressure gates and produced the results below.

## Results: query versus fixed reference

Counts and throughput are `Q × 12,000` scores. Times are seconds; RSS is GiB.
Growth columns compare with the previous row of the same shape.

| Q | R | Scores | Load | TF-IDF fit/transform | Similarity | Argmax | Total | Peak RSS | M scores/s, total | Q growth | Wall growth | RSS growth |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 12,000 | 3,600,000 | 0.394 | 0.987 | 0.093 | 0.002 | 1.479 | 0.286 | 2.43 | — | — | — |
| 1,000 | 12,000 | 12,000,000 | 0.393 | 1.074 | 0.273 | 0.006 | 1.749 | 0.352 | 6.86 | 3.333× | 1.182× | 1.233× |
| 2,500 | 12,000 | 30,000,000 | 0.388 | 1.212 | 0.648 | 0.015 | 2.266 | 0.494 | 13.24 | 2.500× | 1.296× | 1.404× |
| 5,000 | 12,000 | 60,000,000 | 0.394 | 1.525 | 1.338 | 0.030 | 3.291 | 0.730 | 18.23 | 2.000× | 1.452× | 1.477× |
| 10,000 | 12,000 | 120,000,000 | 0.395 | 1.985 | 3.809 | 0.060 | 6.252 | 1.200 | 19.19 | 2.000× | 1.900× | 1.643× |
| 24,975 | 12,000 | 299,700,000 | 0.411 | 3.555 | 11.018 | 0.175 | 15.163 | 2.619 | 19.77 | 2.498× | 2.425× | 2.183× |

At the largest step, `Q` grew 2.498×, total wall time grew 2.425×, and the
similarity phase grew 2.893×. Across all six points, the similarity phase's
slope of 1.086 is close to the linear expectation. The total-time slope is only
0.518 across the entire ladder because the roughly 0.4 s input phase and the
reference-side vectorizer work are fixed or shared overheads; the largest-step
ratio is the more informative asymptotic observation.

Similarity became the dominant phase at scale. At `Q=24,975`, it consumed
11.018 s (72.7% of child wall time), versus 3.555 s (23.4%) for vectorization
and 0.175 s (1.2%) for reduction. The dense `24,975 × 12,000` float64 result was
2,397,600,000 bytes (2.233 GiB); the measured process peak was 2.619 GiB.

## Results: internal all-pairs

Counts and throughput use `N(N-1)/2` unique unordered pairs even though the
unchanged dense computation materializes `N²` scores. Times are seconds; RSS is
GiB.

| N | Unique pairs | Load | TF-IDF fit/transform | Similarity | Argmax | Total | Peak RSS | M pairs/s, total | N growth | Wall growth | RSS growth | Outcome |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---|
| 300 | 44,850 | 0.273 | 0.041 | 0.003 | <0.001 | 0.321 | 0.193 | 0.14 | — | — | — | completed |
| 1,000 | 499,500 | 0.271 | 0.144 | 0.029 | 0.001 | 0.449 | 0.206 | 1.11 | 3.333× | 1.400× | 1.066× | completed |
| 2,500 | 3,123,750 | 0.267 | 0.290 | 0.168 | 0.003 | 0.732 | 0.254 | 4.27 | 2.500× | 1.632× | 1.234× | completed |
| 5,000 | 12,497,500 | 0.268 | 0.568 | 0.658 | 0.012 | 1.510 | 0.407 | 8.28 | 2.000× | 2.063× | 1.601× | completed |
| 10,000 | 49,995,000 | — | — | — | — | — | — | — | 2.000× | — | — | stopped before launch: quadratic trend established |
| 24,975 | 311,862,825 | — | — | — | — | — | — | — | 2.498× | — | — | stopped before launch: quadratic trend established |

When `N` doubled from 2,500 to 5,000, unique pairs grew 4.001× and similarity
wall time grew from 0.168 s to 0.658 s, or **3.915×**. That is the directly
observed quadratic effect. Total child wall time grew only 2.063× because at
`N=5,000` input loading still took 17.8% and vectorization 37.6%; similarity was
the largest phase at 43.6% but had not yet overwhelmed the linear and fixed
phases. It would be incorrect to describe this total-time segment alone as a
4× curve; the isolated similarity phase is the quadratic evidence.

The `N=5,000` dense result was 200,000,000 bytes (0.186 GiB), while process peak
RSS was 0.407 GiB. Before `N=10,000`, four similarity measurements already gave
a slope of 1.870 and R² of 0.9995, so the implemented information stop fired.
The observed-overhead projection was 1.304 GiB at `N=10,000` and 6.323 GiB at
`N=24,975`, both below the hard ceiling; these are projections, not
measurements. No claim is made that the unrun points would complete.

## Resource observations and conclusion

Completed children used 99.66–100.00% of one CPU core by CPU-time/wall-time and
reported a peak of 24 process threads; the additional threads were not reflected
as multi-core CPU utilization. No clean-run child had a major fault, swap usage
did not increase, and minimum available memory remained above the stability
floor. The argmax reduction was never material: 1.2% of wall time at the
largest query/reference point and 0.8% at the largest all-pairs point.

The current `query_vs_reference` audit shape can cover all 24,975 test rows on
this host under the measured conditions. The internal exact-dense path has a
clear quadratic similarity kernel and should stop here under Case A. The next
measurement should compare bounded-memory candidate-reduction designs while
retaining exact cosine refinement for the candidates.

