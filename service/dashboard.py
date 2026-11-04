"""The access log as one page: no script, no external file, nothing but what the log already holds."""
import collections
import datetime
import html
import json
import urllib.parse

PERIODS = {"24h": 1, "7d": 7, "30d": 30, "all": None}
TOP = 15
RECENT = 30

STYLE = """
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--muted:#5d6a7b;--line:#dde2e8;--bar:#2563c9;--chip:#eef1f5}
@media(prefers-color-scheme:dark){:root{--bg:#14181e;--card:#1c222a;--ink:#e7ebf0;--muted:#9aa6b5;--line:#313a45;--bar:#6ea2f0;--chip:#2a323c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0;font-size:20px}h2{margin:0 0 12px;font-size:14px}
.top{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between;margin-bottom:16px}
.muted{color:var(--muted)}
nav a{display:inline-block;margin-left:4px;padding:4px 10px;border-radius:14px;color:inherit;text-decoration:none}
nav a[aria-current]{background:var(--chip);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:12px}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.tile b{display:block;font-size:24px;font-weight:600;font-variant-numeric:tabular-nums}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin-bottom:12px}
.days{display:flex;align-items:flex-end;gap:2px;height:96px;border-bottom:1px solid var(--line)}
.days span{flex:1;min-width:2px;max-width:32px;background:var(--bar);border-radius:4px 4px 0 0}
.axis{display:flex;justify-content:space-between;margin-top:4px;font-size:12px;color:var(--muted)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{font-size:12px;font-weight:500;color:var(--muted);text-align:left}
th,td{padding:5px 8px 5px 0;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
.name{overflow-wrap:anywhere}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.track{width:30%;min-width:60px}.track i{display:block;height:8px;min-width:2px;background:var(--bar);border-radius:0 4px 4px 0}
.empty{padding:32px 0;color:var(--muted);text-align:center}
"""


def read_entries(paths):
    """The log's lines, oldest file first. A damaged line is skipped."""
    entries = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as lines:
                for line in lines:
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(entry, dict) and entry.get("time"):
                        entries.append(entry)
        except FileNotFoundError:
            pass
    return entries


def _time(entry):
    try:
        return datetime.datetime.strptime(entry["time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def _person(entry):
    return str(entry.get("user") or entry.get("person") or "?")


def _esc(value):
    return html.escape(str(value))


def _ranked(title, heading, counter):
    if not counter:
        return f'<section class="card"><h2>{_esc(title)}</h2><p class="empty">Nothing yet</p></section>'
    largest = max(counter.values())
    rows = "".join(
        f'<tr title="{_esc(name)}: {count}"><td class="name">{_esc(name)}</td><td class="track"><i style="width:{100 * count / largest:.0f}%"></i></td><td class="num">{count}</td></tr>'
        for name, count in counter.most_common(TOP)
    )
    more = f'<p class="muted">Top {TOP} of {len(counter)}</p>' if len(counter) > TOP else ""
    return (
        f'<section class="card"><h2>{_esc(title)}</h2><table><thead><tr><th>{_esc(heading)}</th><th></th><th class="num">Count</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>{more}</section>"
    )


def _days(reads, now, days):
    counts = collections.Counter(t.date() for t, _ in reads)
    if not counts:
        return ""
    first = (now - datetime.timedelta(days=days - 1)).date() if days else min(counts)
    span = (now.date() - first).days + 1
    all_days = [first + datetime.timedelta(days=n) for n in range(max(span, 1))]
    largest = max(counts.values())
    bars = "".join(
        f'<span title="{day}: {counts[day]} reads" style="height:{100 * counts[day] / largest:.0f}%"></span>' for day in all_days
    )
    return (
        f'<section class="card" style="margin-bottom:12px"><h2>Reads per day</h2><div class="days">{bars}</div>'
        f'<div class="axis"><span>{all_days[0]}</span><span>most in a day: {largest}</span><span>{all_days[-1]}</span></div></section>'
    )


def render(entries, mode, period="7d", now=None):
    """The page for these log entries. Everything from the log is escaped: documents and sources are outside input."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    period = period if period in PERIODS else "7d"
    days = PERIODS[period]
    since = now - datetime.timedelta(days=days) if days else None
    timed = [(t, e) for t, e in ((_time(e), e) for e in entries) if t and (since is None or t >= since)]
    reads = [(t, e) for t, e in timed if e.get("event") == "read"]
    refused = [(t, e) for t, e in timed if e.get("event") in ("refused", "keys_refused")]
    documents = collections.Counter(e.get("document", "?") for _, e in reads)
    sources = collections.Counter(e.get("source", "?") for _, e in reads)
    people = collections.Counter(_person(e) for _, e in reads)
    pairs = collections.Counter(f"{e.get('document', '?')}  ·  {e.get('source', '?')}" for _, e in reads)
    denied = collections.Counter(f"{e.get('document', 'no access at all')}  ·  {_person(e)}" for _, e in refused)
    tiles = "".join(
        f'<div class="tile"><b>{value}</b><span class="muted">{label}</span></div>'
        for value, label in (
            (len(reads), "reads"), (len(documents), "documents"), (len(people), "people"),
            (len(sources), "sources"), (len(refused), "refused"),
        )
    )
    links = "".join(
        f'<a href="?{urllib.parse.urlencode({"period": key})}"{" aria-current=page" if key == period else ""}>{key}</a>' for key in PERIODS
    )
    person_title = "Reads per person" if mode == "full" else "Reads per person (coded)"
    recent = "".join(
        f"<tr><td>{_esc(e.get('time'))}</td><td>{_esc(e.get('event'))}</td><td>{_esc(_person(e))}</td><td>{_esc(e.get('ip', '?'))}</td>"
        f'<td>{_esc(e.get("source", "?"))}</td><td class="name">{_esc(e.get("document", "-"))}</td><td class="num">{_esc(e.get("status", "-"))}</td></tr>'
        for _, e in sorted(timed, key=lambda pair: pair[0], reverse=True)[:RECENT]
    )
    table = (
        '<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Person</th><th>IP</th><th>Source</th><th>Document</th><th class="num">Status</th></tr></thead>'
        f"<tbody>{recent}</tbody></table></div>" if recent else '<p class="empty">Nothing yet</p>'
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Access dashboard</title><style>{STYLE}</style></head><body><main>"
        f'<div class="top"><div><h1>Access dashboard</h1><span class="muted">Log mode: {_esc(mode)}</span></div><nav aria-label="Period">{links}</nav></div>'
        f'<div class="tiles">{tiles}</div>{_days(reads, now, days)}'
        f'<div class="grid">{_ranked("Most read documents", "Document", documents)}{_ranked("Reads per source", "Source", sources)}'
        f'{_ranked(person_title, "Person", people)}{_ranked("Document and source", "Document · source", pairs)}{_ranked("Refused", "Document · person", denied)}</div>'
        f'<section class="card"><h2>Latest events</h2>{table}</section></main></body></html>'
    )
