import os
import sys

from sentinel.audit.log import AuditLog

db = sys.argv[1] if len(sys.argv) > 1 else os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db")
ok, bad = AuditLog(db, os.environ["SENTINEL_AUDIT_KEY"].encode()).verify()
print("OK" if ok else f"TAMPERED at entry id {bad}")
sys.exit(0 if ok else 1)
