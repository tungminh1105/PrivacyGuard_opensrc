import sys
import sqlite3

sys.stdout.reconfigure(encoding="utf-8")

conn = sqlite3.connect("data/privacyguard.db")
rows = conn.execute(
    "SELECT path, extra_json FROM events WHERE path LIKE '%sentry%'"
).fetchall()

print("sentry rows:", len(rows))
for path, extra in rows[:5]:
    print(path, "|", extra)

conn.close()