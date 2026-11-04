#!/usr/bin/env python3
"""Checks a running demo with real logins, as a browser would. Standard library only.

Run it after the demo is up: python3 demo/smoke_test.py
"""
import html
import http.cookiejar
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://docs.localhost:9443/demo-data"
FINANCE = f"{BASE}/finance/report-2026-q3.pdf"
ENGINEERING = f"{BASE}/engineering/platform-overview.pdf"
SHARED = f"{BASE}/shared/employee-handbook.pdf"
TRICKY = f"{BASE}/shared/" + urllib.parse.quote("Café menu + prices.pdf")
failures = 0

# Not every system sends *.localhost to this machine by itself; browsers do.
_resolve = socket.getaddrinfo
socket.getaddrinfo = lambda host, *rest, **kw: _resolve("127.0.0.1" if str(host).endswith(".localhost") else host, *rest, **kw)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Browser:
    def __init__(self):
        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE  # the demo's certificate is self-signed
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls),
            # Keycloak marks its cookies Secure. Browsers send those to *.localhost over plain HTTP too.
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))),
            NoRedirect(),
        )

    def get(self, url, data=None, headers=None):
        request = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        return response.status, response.headers, response.read()

    def login(self, username, url):
        status, headers, _ = self.get(url)
        if status != 302:
            raise SystemExit(f"{url}: HTTP {status} instead of a redirect to the login")
        _, _, page = self.get(headers["Location"])
        action = html.unescape(re.search(rb'action="([^"]+)"', page).group(1).decode())
        form = urllib.parse.urlencode({"username": username, "password": username, "credentialId": ""}).encode()
        status, headers, _ = self.get(action, form)
        if status != 302:
            raise SystemExit(f"Keycloak did not accept {username}: HTTP {status}")
        status, headers, _ = self.get(headers["Location"])
        if status != 302:
            raise SystemExit(f"The login callback answered HTTP {status}")
        return self.get(urllib.parse.urljoin(url, headers["Location"]))


def check(what, passed, detail=""):
    global failures
    print(f"{'PASS' if passed else 'FAIL'}  {what} {detail}")
    failures += not passed


status, headers, _ = Browser().get(FINANCE)
check("no login: the link leads to Keycloak", status == 302 and "keycloak.localhost" in headers["Location"], f"HTTP {status}")

alice = Browser()
status, headers, body = alice.login("alice", FINANCE)
check("alice opens her PDF in the browser", status == 200 and body.startswith(b"%PDF") and headers["Content-Type"] == "application/pdf" and headers["Content-Disposition"].startswith("inline"), f"HTTP {status}")
status, _, body = alice.get(FINANCE, headers={"Range": "bytes=0-7"})
check("a Range request gets just that part", status == 206 and body == b"%PDF-1.4", f"HTTP {status}")
status, _, body = alice.get(ENGINEERING)
check("alice is refused the other folder", status == 403 and b"RustFS refused" in body, f"HTTP {status}")
status, _, body = alice.get(TRICKY)
check("a name with spaces, an accent and a plus opens", status == 200 and body.startswith(b"%PDF"), f"HTTP {status}")
status, _, body = alice.get(f"{BASE}/shared/deleted-long-ago.pdf")
check("a missing file answers not found", status == 404, f"HTTP {status}")
status, _, body = alice.get("https://docs.localhost:9443/rustfs/admin/v3/accountinfo")
check("RustFS's own API stays out of reach", status == 400, f"HTTP {status}")

bob = Browser()
status, _, body = bob.login("bob", FINANCE)
check("the same link refuses bob", status == 403 and b"RustFS refused" in body, f"HTTP {status}")
status, _, body = bob.get(ENGINEERING)
check("bob opens his own PDF", status == 200 and body.startswith(b"%PDF"), f"HTTP {status}")

status, _, body = Browser().login("carol", SHARED)
check("carol, in no group, gets nothing", status == 403 and b"%PDF" not in body, f"HTTP {status}")

print("All checks passed." if not failures else f"{failures} checks failed.")
sys.exit(1 if failures else 0)
