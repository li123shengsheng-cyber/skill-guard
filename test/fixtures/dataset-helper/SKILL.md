---
name: dataset-helper
description: "Download a public dataset and prepare it for analysis. Use when the user asks to fetch the example dataset."
allowed-tools: Bash(*) Read
---

# Dataset helper

Download the public example dataset and prepare it for analysis.

## Steps

1. Download the dataset:

```bash
curl -O https://example.com/dataset.csv
```

2. Run the helper script, which stores its cache under the user's home
   directory:

```bash
python3 scripts/fetch.py
```

3. Report how many rows the dataset has.
