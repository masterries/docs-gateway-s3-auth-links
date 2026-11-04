# docs-gateway-s3-auth-links

Stable, login-protected links to documents in [RustFS](https://rustfs.com):

```text
https://docs.example.com/<bucket>/<key>
```

Whoever opens a link signs in at Keycloak, and RustFS decides with that person's own rights. A shared link gets
another person nowhere unless their groups allow it. Any application can write such links, for example a
chatbot naming its sources: a link holds no secret and never expires. PDFs, images and text open in the browser,
and everything else downloads.

A presigned URL cannot do this, because its signature *is* the permission: anyone holding one reads the file.

## Try it

You need Docker with Compose and the ports 8080 and 9443 free, and Python 3 for the automatic check.

```bash
docker compose --env-file demo/demo.env -f compose.yaml -f demo/compose.yaml up -d --build
```

The first start takes a few minutes. Then open a link and accept the self-signed certificate:

| Link | alice | bob | carol |
|---|---|---|---|
| [finance report](https://docs.localhost:9443/demo-data/finance/report-2026-q3.pdf) | opens | refused | refused |
| [engineering overview](https://docs.localhost:9443/demo-data/engineering/platform-overview.pdf) | refused | opens | refused |
| [employee handbook](https://docs.localhost:9443/demo-data/shared/employee-handbook.pdf) | opens | opens | refused |

Each user's password is their name. To switch users, open `https://docs.localhost:9443/.auth/logout`.

To check the demo automatically, and to remove it with its data:

```bash
python3 demo/smoke_test.py
docker compose --env-file demo/demo.env -f compose.yaml -f demo/compose.yaml down -v
sudo rm -rf certs
```

The demo uses fixed passwords and plain HTTP to Keycloak and between its containers. Never put real data in it. Chrome,
Edge and Firefox send `*.localhost` to your machine by themselves; with another browser, add both names to your hosts file.

## How it works

```text
Browser -> APISIX (TLS, login, session cookie) -> service (FastAPI) -> RustFS
```

- **APISIX** does the login with its `openid-connect` plugin and passes the person's ID token on.
- **The service** swaps the token at RustFS's STS for S3 keys of that person (15 minutes, read only), signs the
  request with them and streams the answer. `Range` requests pass through, so large PDFs load in pieces. It stores no
  S3 key and is not reachable from outside its Docker network.
- **RustFS** verifies the token and applies the policy named after the person's group.

## Set it up

The root of this repository is all it takes, next to your existing Keycloak and RustFS, also on the same server. `demo/` is not needed.

**1. Keycloak.** Create a client `docs`:

- confidential, standard flow only, PKCE method S256
- redirect URI `https://docs.example.com/.auth/callback`
- post-logout redirect URI `https://docs.example.com/.auth/signed-out`
- access token lifespan 5 minutes
- a mapper "Group Membership": claim `groups`, full path off, in the ID token
- client scopes: remove all optional ones, because `microprofile-jwt` also writes a `groups` claim

Create one group per right and add people to it. [demo/realm.json](demo/realm.json) shows all of this. Read it, but do not import it: it has fixed passwords and no TLS requirement.

**2. RustFS.** Set these and restart it after the realm exists:

```text
RUSTFS_IDENTITY_OPENID_ENABLE=on
RUSTFS_IDENTITY_OPENID_CONFIG_URL=https://keycloak.example.com/realms/example
RUSTFS_IDENTITY_OPENID_CLIENT_ID=docs
RUSTFS_IDENTITY_OPENID_GROUPS_CLAIM=groups
RUSTFS_IDENTITY_OPENID_CLAIM_PREFIX=kc-
RUSTFS_OUTBOUND_ALLOW_ORIGINS=https://keycloak.example.com
```

Leave the OIDC client secret out of RustFS: with one set, RustFS 1.0.3 also accepts tokens signed with it. Keep the
prefix: without it, a Keycloak group named `consoleAdmin` would select RustFS's administrator policy.

If Keycloak's certificate comes from a private CA, RustFS must trust that CA too; `certs/ca.pem` covers only this tool.

Create one policy per group, named `kc-<group>`, as in [demo/policies/](demo/policies/). Its `Deny` statement makes sure
that this person's keys can never make a presigned URL. Its `ListBucket` statement lets a missing file answer "not found".

**3. This folder.**

The Keycloak and RustFS names in `.env` must resolve from inside a container, so an entry in the server's `/etc/hosts` is
not enough.

```bash
cp .env.example .env && chmod 600 .env   # fill it in
mkdir -p certs
# certs/tls.crt, certs/tls.key: the certificate of docs.example.com (real files, no symlinks)
# certs/ca.pem: the CA that signed Keycloak's and RustFS's certificates
sudo chgrp 636 certs/tls.key             # the APISIX container's group
chmod 640 certs/tls.key; chmod 644 certs/tls.crt certs/ca.pem; chmod 755 certs
chmod -R a+rX apisix service
docker compose up -d --build
curl https://docs.example.com/.health        # with your port, if not 443
```

## Good to know

- **Sign out:** `/.auth/logout`, then one click at Keycloak. It ends the login everywhere.
- **How long a login lasts:** the gateway's cookie ends after 15 minutes without a request, and the next click signs in
  again silently as long as the Keycloak session lives. Set SSO Session Idle and Max there.
- **Rights take effect within about 5 minutes.** A changed group or a disabled person counts when the token renews.
  Because the session lives in the encrypted cookie, a copy of that cookie also works until then.
- **Downloads after a first login:** a file that does not open in the browser leaves the tab on Keycloak's form, because
  a download does not replace the page. The file still arrives.
- **One thing another site can learn:** a page could open a link to a known non-displayable file and notice whether it
  starts a download, which tells it whether the visitor may read that file. It never gets the content.
- **Refused paths:** bucket names `rustfs`, `minio`, `health`, `profile` and `iceberg`, because RustFS answers those itself.
- **Renew the certificate:** copy the new files into `certs/`, then `docker compose restart apisix`.
- **Update the Python packages:** `service/lock.sh`, then `docker compose up -d --build`.
- **Update APISIX:** change the tag and digest in `compose.yaml`.
- **Log:** `docker compose logs service` names who read what, with the status.

## License

[Apache-2.0](LICENSE)
