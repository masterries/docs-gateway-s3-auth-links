#!/usr/bin/env python3
"""Counts the access log: docker compose exec service sh -c 'cat /logs/access*' | python3 tools/access_report.py"""
import collections
import json
import sys

reads_by_source = collections.Counter()
reads_by_person = collections.Counter()
refused = collections.Counter()
for line in sys.stdin:
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    if not isinstance(entry, dict):
        continue
    person = entry.get("user") or entry.get("person") or "?"
    document = entry.get("document", "-")
    if entry.get("event") == "read":
        reads_by_source[(document, entry.get("source", "?"))] += 1
        reads_by_person[(document, person)] += 1
    elif entry.get("event") in ("refused", "keys_refused"):
        refused[(document, person)] += 1


def show(title, counter):
    print(f"\n{title}")
    for (first, second), count in counter.most_common():
        print(f"{count:6}  {first}  {second}")
    if not counter:
        print("     -")


show("Reads per document and source", reads_by_source)
show("Reads per document and person", reads_by_person)
show("Refused, per document and person", refused)
