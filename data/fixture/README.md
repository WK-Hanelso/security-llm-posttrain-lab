# T-015B controlled fixture

`snapshot_a` and `snapshot_b` are offline raw-page fixtures derived from the cached
2026-09-17 NVD snapshot. The committed ID lists, config-override maps, ingest manifests,
dataset manifests, and hash manifests define the snapshots. Bulky raw pages and generated
normalized/processed/SFT files are intentionally ignored.

Reproduction uses `.venv/bin/python`, `agent/t015b_fixture.py`, and
`agent/t015b_validate.py`. The exact commands and observed results are recorded in
`agent/T-015B_EXEC.md`.
