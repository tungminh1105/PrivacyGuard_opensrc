import sqlite3
import sys

sys.stdout.reconfigure(encoding="utf-8")

c = sqlite3.connect("data/privacyguard.db")
print("Event types:")
for row in c.execute("SELECT type, COUNT(*) FROM events GROUP BY type"):
    print("  ", row)

print("File events in Downloads:")
for row in c.execute(
    "SELECT ts, path FROM events WHERE type LIKE 'file%' AND path LIKE '%Downloads%' LIMIT 5"
):
    print("  ", row)

c.close()