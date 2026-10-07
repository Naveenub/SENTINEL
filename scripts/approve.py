"""Usage: approve.py list | approve <id> | deny <id>   (env: SENTINEL_ADMIN_TOKEN, SENTINEL_URL)"""
import json
import os
import sys
import urllib.request

base = os.getenv("SENTINEL_URL", "http://127.0.0.1:8080")
cmd, *rest = sys.argv[1:] or ["list"]
path, method = ("/v1/approvals", "GET") if cmd == "list" else (f"/v1/approvals/{rest[0]}/{cmd}", "POST")
req = urllib.request.Request(base + path, method=method, headers={"X-Sentinel-Admin-Token": os.environ["SENTINEL_ADMIN_TOKEN"]})
print(json.dumps(json.load(urllib.request.urlopen(req)), indent=2))
