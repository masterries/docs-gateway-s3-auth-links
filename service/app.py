"""Serves one document from S3 storage to one logged-in person, with that person's own rights.

APISIX in front has done the login at Keycloak and hands over the raw ID token. This service swaps the
token at RustFS's STS for short-lived S3 keys of that person, signs the GET with them and streams the
answer. RustFS verifies the token and decides, from the person's groups, what they may read. So this
service holds no S3 key and no JWT library, and it makes no access decision of its own.

It trusts the header X-Raw-ID-Token only as far as RustFS does: a forged token gets no keys.
"""
import asyncio
import base64
import datetime
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
from pathlib import PurePosixPath
import re
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
import httpx
from starlette.background import BackgroundTask

import dashboard

LOG_FILE = "/logs/access.jsonl"
LOG_FILE_OLD = LOG_FILE + ".1"
LOG_FILE_BYTES = 50_000_000
S3_ENDPOINT = os.environ["S3_ENDPOINT"].rstrip("/")
S3_REGION = os.environ.get("S3_REGION", "us-east-1")
CA_FILE = os.environ.get("CA_FILE", "/certs/ca.pem")
# off: no record of who read what. anonymous: a stable code for each person and a shortened IP.
# full: the person's name and the whole IP. A wrong setting stops the service instead of logging too much.
ACCESS_LOG = os.environ.get("ACCESS_LOG") or "off"
ACCESS_LOG_KEY = os.environ.get("ACCESS_LOG_KEY", "")
# The Keycloak group that may open /.dashboard. Empty: there is no dashboard.
DASHBOARD_GROUP = os.environ.get("DASHBOARD_GROUP", "")
if ACCESS_LOG not in ("off", "anonymous", "full"):
    raise SystemExit("ACCESS_LOG must be off, anonymous or full.")
if ACCESS_LOG == "anonymous" and len(ACCESS_LOG_KEY) < 32:
    raise SystemExit("ACCESS_LOG=anonymous needs an ACCESS_LOG_KEY of at least 32 characters.")

KEY_SECONDS = 900
MAX_CACHED_KEYS = 1000
# The most these keys may ever do, whatever the person's groups say: read. RustFS intersects this with
# the group's policy. ListBucket lets RustFS answer 404 instead of 403 for a missing file the person
# could otherwise read. A constant, never built from a request.
SESSION_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::*"]},
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::*/*"]},
    ],
}, separators=(",", ":"))

TEXT = "text/plain; charset=utf-8"
# What opens in the browser. The type comes from this list and never from the object: a file must not
# be able to run as a page on this site. Everything else is a download.
INLINE_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    ".txt": TEXT, ".csv": TEXT, ".md": TEXT, ".log": TEXT,
}
# "sandbox" blanks the PDF viewers of Chromium browsers, and they need object-src. A PDF's own scripts run
# inside the viewer, without access to this site, so this policy is enough for PDFs.
PDF_POLICY = "default-src 'none'; object-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
FILE_POLICY = "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
PAGE_POLICY = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

VALID_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
VALID_KEY = re.compile(r"[^\x00-\x1f\x7f]{1,1024}")
# RustFS answers these first path segments itself (admin API, health). A link must only reach objects.
NOT_A_BUCKET = {"rustfs", "minio", "profile", "health", "iceberg"}
VALID_SOURCE = re.compile(r"[A-Za-z0-9._-]{1,64}")
PASSED_ON = ("range", "if-range", "if-none-match", "if-modified-since")
KEPT = ("content-length", "content-range", "content-encoding", "accept-ranges", "etag", "last-modified")

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("docs-gateway")
# One line per read is enough, and these would name each signed request too.
logging.getLogger("httpx").setLevel(logging.WARNING)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_tls = ssl.create_default_context(cafile=CA_FILE) if S3_ENDPOINT.startswith("https:") else False
if _tls:
    # Python 3.13's stricter check refuses some company CAs that APISIX accepts.
    _tls.verify_flags &= ~ssl.VERIFY_X509_STRICT
# No redirects: a signed request must not travel to another host.
_http = httpx.AsyncClient(verify=_tls, trust_env=False, follow_redirects=False, timeout=httpx.Timeout(15, read=120))
_keys = {}  # sha256 of an ID token -> its S3 keys


class Unavailable(Exception):
    pass


def short_ip(address):
    """The network, not the machine: /24 for IPv4, /48 for IPv6."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "?"
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))


def source_of(request):
    """Which application a link came from. Its own word, not proof: anyone can write ?source= into a link."""
    tag = request.query_params.get("source", "")
    if VALID_SOURCE.fullmatch(tag):
        return tag
    host = urllib.parse.urlsplit(request.headers.get("referer", "")).hostname
    return host if host and host != request.headers.get("host", "").split(":")[0] else "direct"


def write_log_line(line):
    """For the dashboard. Two files at most, so the log cannot fill the disk. Reading a document does not
    depend on this: a full disk costs log lines, not access."""
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= LOG_FILE_BYTES:
            os.replace(LOG_FILE, LOG_FILE_OLD)
        with open(LOG_FILE, "a", encoding="utf-8") as output:
            output.write(line + "\n")
    except OSError as failure:
        log.warning("Access log file: %s", type(failure).__name__)


def audit(event, request, token, **fields):
    if ACCESS_LOG == "off":
        return
    ip = request.headers.get("x-real-ip", "")
    user = username(token)
    who = (
        {"user": user, "ip": ip or "?"} if ACCESS_LOG == "full"
        else {"person": hmac.new(ACCESS_LOG_KEY.encode(), user.encode(), hashlib.sha256).hexdigest()[:16], "ip": short_ip(ip)}
    )
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = json.dumps({"event": event, "time": stamp, **who, "source": source_of(request), **fields}, ensure_ascii=False)
    log.info(line)
    write_log_line(line)


def claims_of(token):
    """What the token says, unchecked. Only RustFS's STS proves that it is genuine."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}
    return claims if isinstance(claims, dict) else {}


def username(token):
    """For the log only. RustFS has verified the token, or will refuse it."""
    claims = claims_of(token)
    return str(claims.get("preferred_username") or claims.get("sub") or "?")


async def s3_keys(token, request):
    """This person's S3 keys, or None if RustFS gives them none. A renewed token gets new keys, so a changed
    group takes effect with the renewal."""
    now = time.time()
    cache_id = hashlib.sha256(token.encode()).hexdigest()
    keys = _keys.get(cache_id)
    if keys and keys["expires"] > now:
        return keys
    form = {
        "Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "DurationSeconds": KEY_SECONDS,
        "WebIdentityToken": token, "Policy": SESSION_POLICY,
    }
    try:
        answer = await _http.post(f"{S3_ENDPOINT}/", data=form)
        fields = {element.tag.rsplit("}", 1)[-1]: element.text for element in ET.fromstring(answer.content).iter()}
    except (httpx.HTTPError, ET.ParseError) as failure:
        raise Unavailable(f"STS: {type(failure).__name__}") from failure
    # RustFS's answer for a valid token whose groups name no policy.
    if answer.status_code == 400 and fields.get("Code") == "InvalidArgument":
        audit("keys_refused", request, token, code=fields.get("Code"))
        return None
    if answer.status_code != 200 or not all(fields.get(n) for n in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise Unavailable(f"STS: HTTP {answer.status_code} {fields.get('Code')}")
    for old in [k for k, v in _keys.items() if v["expires"] <= now]:
        del _keys[old]
    while len(_keys) >= MAX_CACHED_KEYS:
        del _keys[next(iter(_keys))]
    keys = {
        "access": fields["AccessKeyId"], "secret": fields["SecretAccessKey"], "token": fields["SessionToken"],
        "expires": now + KEY_SECONDS - 60,
    }
    _keys[cache_id] = keys
    return keys


def signed_headers(method, path, keys):
    """AWS Signature Version 4 for a request without a body."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = stamp[:8]
    digest = hashlib.sha256(b"").hexdigest()
    signed = {
        # Spelled as httpx will send it: without a default port, in lower case.
        "host": httpx.URL(S3_ENDPOINT).netloc.decode(), "x-amz-content-sha256": digest,
        "x-amz-date": stamp, "x-amz-security-token": keys["token"],
    }
    names = ";".join(sorted(signed))
    lines = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
    canonical = "\n".join((method, path, "", lines, names, digest))
    scope = f"{day}/{S3_REGION}/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = ("AWS4" + keys["secret"]).encode()
    for value in (day, S3_REGION, "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    del signed["host"]
    return {
        **signed,
        "Authorization": f"AWS4-HMAC-SHA256 Credential={keys['access']}/{scope}, SignedHeaders={names}, Signature={signature}",
    }


def page(status, title, text):
    """A plain answer for a person who followed a link. No script, no token, nothing from the bucket."""
    body = (
        f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem}}</style></head>"
        f'<body><h1>{html.escape(title)}</h1><p>{html.escape(text)}</p><p><a href="/.auth/logout">Sign in as someone else</a></p></body></html>'
    )
    return HTMLResponse(body, status, headers={
        "Content-Security-Policy": PAGE_POLICY, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
    })


def file_headers(key, upstream):
    """What the browser gets: the type from our list, shown in place or downloaded, never framed."""
    name = PurePosixPath(key).name
    kind = INLINE_TYPES.get(PurePosixPath(name).suffix.lower())
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', "_", name)
    headers = {k: upstream.headers[k] for k in KEPT if k in upstream.headers}
    headers.update({
        "Content-Type": kind or "application/octet-stream",
        "Content-Disposition": f"{'inline' if kind else 'attachment'}; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name, safe='')}",
        "Content-Security-Policy": PDF_POLICY if kind == "application/pdf" else FILE_POLICY,
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "private, no-store",
    })
    return headers


@app.get("/.health")
def health():
    return {"status": "ok"}


@app.get("/.auth/signed-out")
def signed_out():
    return page(200, "Signed out", "You are signed out. Open a document link to sign in again.")


@app.get("/")
def root():
    return page(404, "Not a document", "This address serves documents by link: /<bucket>/<file>.")


@app.get("/.dashboard")
async def access_dashboard(request: Request):
    if not DASHBOARD_GROUP or ACCESS_LOG == "off":
        return page(404, "No dashboard", "The dashboard needs ACCESS_LOG and DASHBOARD_GROUP to be set.")
    token = request.headers.get("x-raw-id-token")
    if not token:
        return page(401, "Not signed in", "Open this link again to sign in.")
    # RustFS giving keys for this token proves that Keycloak signed it, so its groups can be believed.
    # The group therefore needs a policy in RustFS, like any group here.
    try:
        keys = await s3_keys(token, request)
    except Unavailable:
        return page(503, "Try again in a moment", "The document store does not answer right now.")
    groups = claims_of(token).get("groups")
    if keys is None or not isinstance(groups, list) or DASHBOARD_GROUP not in groups:
        audit("dashboard_refused", request, token)
        return page(403, "No access", "This page is for another group.")
    audit("dashboard", request, token)
    entries = await asyncio.to_thread(dashboard.read_entries, [LOG_FILE_OLD, LOG_FILE])
    body = await asyncio.to_thread(dashboard.render, entries, ACCESS_LOG, request.query_params.get("period", "7d"))
    return HTMLResponse(body, headers={
        "Content-Security-Policy": PAGE_POLICY, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
    })


@app.api_route("/{bucket}/{key:path}", methods=["GET", "HEAD"])
async def document(bucket: str, key: str, request: Request):
    name = f"{bucket}/{key}"
    if (
        not VALID_BUCKET.fullmatch(bucket) or bucket in NOT_A_BUCKET or not VALID_KEY.fullmatch(key)
        or len(key.encode()) > 1024 or key.endswith("/") or any(part in (".", "..") for part in key.split("/"))
    ):
        return page(400, "Not a document", "This link does not name a document.")
    token = request.headers.get("x-raw-id-token")
    if not token:
        return page(401, "Not signed in", "Open this link again to sign in.")
    user = username(token)
    unavailable = page(503, "Try again in a moment", "The document store does not answer right now.")
    try:
        keys = await s3_keys(token, request)
    except Unavailable as failure:
        log.warning("%s", failure)
        return unavailable
    if keys is None:
        return page(403, "No access", f"You are signed in as {user}, but your account has no right to any documents.")
    path = "/" + "/".join(urllib.parse.quote(part, safe="-_.~") for part in name.split("/"))
    headers = signed_headers(request.method, path, keys)
    headers.update({h: request.headers[h] for h in PASSED_ON if h in request.headers})
    headers["Accept-Encoding"] = "identity"
    try:
        upstream = await _http.send(_http.build_request(request.method, S3_ENDPOINT + path, headers=headers), stream=True)
    except httpx.HTTPError as failure:
        log.warning("S3: %s", type(failure).__name__)
        return unavailable
    status = upstream.status_code
    if status not in (200, 206, 304, 416):
        try:
            found = re.search(rb"<Code>([A-Za-z]+)</Code>", await upstream.aread())
        except httpx.HTTPError:
            found = None
        finally:
            await upstream.aclose()
        code = found.group(1).decode() if found else ""
        audit("refused", request, token, document=name, status=status, code=code)
        if status == 403 and (code == "AccessDenied" or request.method == "HEAD"):
            return page(403, "No access", f"You are signed in as {user}. RustFS refused {name}: your groups have no right to this document.")
        if status == 404:
            return page(404, "Not found", f"There is no document {name}.")
        return page(502, "Try again in a moment", "The document store could not answer this request.")
    # A PDF viewer loads more parts with Range requests. Only opening the file counts as a read.
    if request.method == "GET" and status == 200:
        audit("read", request, token, document=name, status=status)
    answer_headers = file_headers(key, upstream)
    if request.method == "HEAD" or status == 304:
        await upstream.aclose()
        return Response(status_code=status, headers=answer_headers)
    return StreamingResponse(upstream.aiter_raw(), status, headers=answer_headers, background=BackgroundTask(upstream.aclose))
