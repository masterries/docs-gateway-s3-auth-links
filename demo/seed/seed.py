"""Puts the demo's bucket, files and policies into RustFS, once it knows Keycloak. Standard library only."""
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "http://rustfs:9000"
ACCESS_KEY = "demo-admin"
SECRET_KEY = "demo-admin-secret"
REGION = "us-east-1"
BUCKET = "demo-data"
DEMO = Path("/demo")


def quote(value):
    return urllib.parse.quote(value, safe="-_.~")


def s3(method, path, query=None, data=b""):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = stamp[:8]
    digest = hashlib.sha256(data).hexdigest()
    canonical_path = "/".join(quote(part) for part in path.split("/"))
    canonical_query = "&".join(f"{quote(k)}={quote(v)}" for k, v in sorted((query or {}).items()))
    signed = {"host": "rustfs:9000", "x-amz-content-sha256": digest, "x-amz-date": stamp}
    names = ";".join(sorted(signed))
    lines = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
    canonical = "\n".join((method, canonical_path, canonical_query, lines, names, digest))
    scope = f"{day}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = ("AWS4" + SECRET_KEY).encode()
    for value in (day, REGION, "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers = dict(signed)
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, SignedHeaders={names}, Signature={signature}"
    url = ENDPOINT + canonical_path + (f"?{canonical_query}" if canonical_query else "")
    request = urllib.request.Request(url, headers=headers, data=data if method == "PUT" else None, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def wait_for_keycloak_in_rustfs():
    """A forged token from the right issuer: refused with "no OIDC provider" until RustFS has found Keycloak."""
    def part(value):
        import base64
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    forged = ".".join((part({"alg": "RS256", "kid": "x"}), part({"iss": os.environ["KEYCLOAK_ISSUER"], "sub": "x", "aud": "x", "exp": 4102444800}), "eA"))
    form = urllib.parse.urlencode({"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "WebIdentityToken": forged}).encode()
    answer = ""
    for _ in range(60):
        try:
            with urllib.request.urlopen(ENDPOINT + "/", data=form, timeout=10) as response:
                raise SystemExit(f"RustFS accepted a forged token (HTTP {response.status}).")
        except urllib.error.HTTPError as error:
            answer = error.read().decode(errors="replace")
            if "no OIDC provider" not in answer:
                return
        except OSError as error:
            answer = str(error)
        time.sleep(2)
    raise SystemExit(f"RustFS did not find Keycloak: {answer[:300]}")


wait_for_keycloak_in_rustfs()
status = s3("HEAD", f"/{BUCKET}")
if status != 200 and s3("PUT", f"/{BUCKET}") != 200:
    raise SystemExit("Could not create the bucket.")
for path in sorted(p for p in (DEMO / "data").rglob("*") if p.is_file()):
    key = path.relative_to(DEMO / "data").as_posix()
    if s3("PUT", f"/{BUCKET}/{key}", data=path.read_bytes()) != 200:
        raise SystemExit(f"Could not upload {key}.")
for path in sorted((DEMO / "policies").glob("*.json")):
    if s3("PUT", "/rustfs/admin/v3/add-canned-policy", {"name": path.stem}, path.read_bytes()) not in (200, 204):
        raise SystemExit(f"Could not write the policy {path.stem}.")
print("The demo data and policies are in place.")
