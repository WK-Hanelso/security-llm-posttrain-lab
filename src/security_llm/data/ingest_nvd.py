"""Download paginated NVD API 2.0 data into an idempotent raw cache."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import requests

from security_llm.config import load_config
from security_llm.utils.io import atomic_write_json

LOG = logging.getLogger(__name__)


def date_windows(start: str, end: str, window_days: int) -> Iterator[tuple[str, str]]:
    current = date.fromisoformat(start)
    final = date.fromisoformat(end)
    if current > final:
        raise ValueError("start date must not be after end date")
    if window_days < 1:
        raise ValueError("window_days must be positive")
    while current <= final:
        window_end = min(current + timedelta(days=window_days - 1), final)
        yield current.isoformat(), window_end.isoformat()
        current = window_end + timedelta(days=1)


def fetch_page(
    session: requests.Session,
    nvd_cfg: dict[str, Any],
    pub_start: str,
    pub_end: str,
    start_index: int,
    headers: dict[str, str],
    sleep_seconds: float,
) -> dict[str, Any]:
    params = {
        "pubStartDate": f"{pub_start}T00:00:00.000",
        "pubEndDate": f"{pub_end}T23:59:59.999",
        "resultsPerPage": nvd_cfg["results_per_page"],
        "startIndex": start_index,
    }
    for attempt in range(int(nvd_cfg["max_retries"])):
        response = session.get(
            nvd_cfg["base_url"], params=params, headers=headers, timeout=180
        )
        time.sleep(sleep_seconds)
        if response.status_code == 200:
            return response.json()
        if response.status_code in {403, 429, 500, 502, 503, 504}:
            LOG.warning("NVD status %s; retry %s", response.status_code, attempt + 1)
            time.sleep(sleep_seconds * (2**attempt))
            continue
        raise RuntimeError(f"NVD status {response.status_code}: {response.text[:200]}")
    raise RuntimeError(f"NVD max retries exceeded for {pub_start}..{pub_end} index={start_index}")


def ingest(
    cfg: dict[str, Any], start: str, end: str, force: bool = False
) -> dict[str, Any]:
    nvd_cfg = cfg["nvd"]
    raw_dir = Path(nvd_cfg["raw_dir"])
    raw_dir.mkdir(parents=True, exist_ok=True)
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    sleep_seconds = float(
        nvd_cfg["sleep_seconds_with_key"] if api_key else nvd_cfg["sleep_seconds_without_key"]
    )
    entries: list[dict[str, Any]] = []
    with requests.Session() as session:
        for pub_start, pub_end in date_windows(start, end, int(nvd_cfg["window_days"])):
            window_dir = raw_dir / f"{pub_start}_{pub_end}"
            window_dir.mkdir(parents=True, exist_ok=True)
            start_index = 0
            total = 0
            pages = 0
            while True:
                page_file = window_dir / f"page_{start_index:07d}.json"
                if page_file.exists() and not force:
                    with page_file.open(encoding="utf-8") as handle:
                        body = json.load(handle)
                else:
                    body = fetch_page(
                        session, nvd_cfg, pub_start, pub_end, start_index, headers, sleep_seconds
                    )
                    atomic_write_json(page_file, body)
                total = int(body["totalResults"])
                results_per_page = int(body["resultsPerPage"])
                pages += 1
                LOG.info(
                    "page window=%s..%s startIndex=%d totalResults=%d",
                    pub_start,
                    pub_end,
                    start_index,
                    total,
                )
                start_index += results_per_page
                if start_index >= total or results_per_page == 0:
                    break
            entries.append(
                {
                    "pub_start": pub_start,
                    "pub_end": pub_end,
                    "total_results": total,
                    "pages": pages,
                    "complete": True,
                }
            )
            LOG.info("window %s..%s total=%d pages=%d", pub_start, pub_end, total, pages)
    manifest = {
        "snapshot_date": end,
        "start_date": start,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "windows": entries,
        "total_cves": sum(entry["total_results"] for entry in entries),
        "api_key_used": bool(api_key),
    }
    atomic_write_json(raw_dir / "ingest_manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    cfg = load_config(args.config, args.override)
    start = args.start or cfg["nvd"]["start_date"]
    end = args.end or cfg["nvd"].get("end_date") or date.today().isoformat()
    ingest(cfg, start, end, args.force)


if __name__ == "__main__":
    main()

