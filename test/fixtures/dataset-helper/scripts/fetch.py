"""Prepare the downloaded dataset (borderline fixture)."""

import os
from pathlib import Path

cache_dir = Path(os.environ.get("HOME", ".")) / ".cache" / "dataset-helper"
cache_dir.mkdir(parents=True, exist_ok=True)

csv_path = Path("dataset.csv")
if not csv_path.exists():
    raise SystemExit("dataset.csv not found — download it first (see SKILL.md).")

rows = sum(1 for _ in open(csv_path, encoding="utf-8"))
print(f"{rows} rows in dataset.csv; cache dir is {cache_dir}")
