#!/usr/bin/env python3
"""Benchmark canary against public LLM application repositories.

What it measures:
  * scan time and files scanned per repo (throughput)
  * findings per rule and per OWASP category
  * a review sheet (labels.csv) with one row per finding, so each one can be
    judged true positive / false positive by hand. Precision is computed from
    that sheet by `summarize.py`, never by this script: a benchmark that
    grades itself is not a benchmark.

Usage:
    python bench/run_benchmark.py                # clones into bench/.work
    python bench/run_benchmark.py --repos bench/repos.txt --out bench/results

Repos are shallow-cloned. Nothing is executed from them; canary only reads.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def clone(url: str, dest: Path) -> bool:
    if dest.exists():
        return True
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
            check=True,
            timeout=600,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def scan(path: Path) -> tuple[dict, float]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "canary.cli",
            str(path),
            "--format",
            "json",
            "--fail-on",
            "critical",
        ],
        capture_output=True,
        text=True,
    )
    dt = time.perf_counter() - t0
    if proc.returncode == 2 or not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or "canary failed")
    return json.loads(proc.stdout), dt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default=str(HERE / "repos.txt"))
    ap.add_argument("--work", default=str(HERE / ".work"))
    ap.add_argument("--out", default=str(HERE / "results"))
    args = ap.parse_args()

    repos = [
        line.strip()
        for line in Path(args.repos).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    work = Path(args.work)
    out = Path(args.out)
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    label_rows = []
    for url in repos:
        name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        owner = url.rstrip("/").split("/")[-2]
        slug = f"{owner}/{name}"
        dest = work / owner / name
        print(f"[{slug}] cloning ...", flush=True)
        if not clone(url, dest):
            print(f"[{slug}] clone failed, skipped")
            rows.append({"repo": slug, "status": "clone_failed"})
            continue
        print(f"[{slug}] scanning ...", flush=True)
        try:
            report, dt = scan(dest)
        except RuntimeError as exc:
            print(f"[{slug}] scan failed: {exc}")
            rows.append({"repo": slug, "status": "scan_failed"})
            continue

        (out / f"{owner}__{name}.json").write_text(json.dumps(report, indent=2))
        rows.append(
            {
                "repo": slug,
                "status": "ok",
                "files_scanned": report["files_scanned"],
                "seconds": round(dt, 2),
                "total": report["total_findings"],
                **{f"rule:{k}": v for k, v in report["counts_by_rule"].items()},
                **{f"owasp:{k}": v for k, v in report["counts_by_owasp"].items()},
            }
        )
        for f in report["findings"]:
            rel = os.path.relpath(f["file_path"], dest)
            label_rows.append(
                {
                    "repo": slug,
                    "rule_id": f["rule_id"],
                    "severity": f["severity"],
                    "file": rel,
                    "line": f["line"],
                    "snippet": f["snippet"][:160],
                    "label": "",  # TP / FP / UNSURE, filled by hand
                    "note": "",
                }
            )
        print(
            f"[{slug}] {report['files_scanned']} files, {report['total_findings']} findings, {dt:.2f}s"
        )
        shutil.rmtree(dest / ".git", ignore_errors=True)  # keep the tree, drop history

    (out / "summary.json").write_text(json.dumps(rows, indent=2))

    labels = out / "labels.csv"
    if not labels.exists():  # never overwrite hand-made labels
        with labels.open("w", newline="") as fh:
            w = csv.DictWriter(
                fh, fieldnames=list(label_rows[0].keys()) if label_rows else ["repo"]
            )
            w.writeheader()
            w.writerows(label_rows)
        print(f"wrote {labels} ({len(label_rows)} rows to review)")
    else:
        print(f"{labels} exists, not overwritten")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
