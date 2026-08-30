# Smoke tests

Live end-to-end tests for the omniauth-authify strategy against a **real
Authify server**. CI runs these automatically in the `Smoke` workflow, which
starts `ghcr.io/authify/authify:latest` with a MySQL service, bootstraps a
full tenancy (global admin, organization, user, OAuth application), and
exercises the flows below. The same steps can be run locally:

## Files

- `bootstrap_authify.sh` — provisions a freshly-migrated Authify from zero
  (setup wizard, org, invited user, OAuth app) and prints its credentials.
  Requires `DB_CONTAINER`/`DB_USER`/`DB_PASS` to read the invitation token
  from the database (no SMTP is configured in CI, so invitation emails are
  not sent).
- `run_smoke_tests.sh` — runs the strategy through a local Sinatra app:
  the happy path (code + PKCE + nonce, with ID-token verification against
  the live JWKS), consent denial, and code replay.
- `smoke_app.rb` — a minimal Rack app mounting the strategy; failures are
  rendered as JSON at `/auth/failure`.

## Local usage

```bash
# 1. Database
docker network create authify-ci
docker run -d --name authify-mysql --network authify-ci \
  -e MYSQL_ROOT_PASSWORD=ci_root_pw -e MYSQL_DATABASE=authify_prod \
  -e MYSQL_USER=authify -e MYSQL_PASSWORD=ci_db_pw mysql:8.4

# 2. Authify (patched runtime.exs lets the strategy reach plain http)
docker run -d --name authify --network authify-ci -p 4000:4000 \
  -e DATABASE_URL="ecto://authify:ci_db_pw@authify-mysql:3306/authify_prod" \
  -e SECRET_KEY_BASE="$(ruby -rsecurerandom -e 'print SecureRandom.hex(64)')" \
  -e PHX_HOST=localhost -e PORT=4000 -e URL_SCHEME=http \
  ghcr.io/authify/authify:latest sh -c "
    sed -i 's/url: \[host: host, port: 443, scheme: \"https\"\]/url: [host: host, port: String.to_integer(System.get_env(\"PORT\")), scheme: \"http\"]/' /app/releases/*/runtime.exs &&
    /app/bin/authify eval 'Authify.Release.migrate' && /app/bin/server"

# 3. Bootstrap + test
export DB_CONTAINER=authify-mysql DB_USER=root DB_PASS=ci_root_pw
eval "$(bash spec/smoke/bootstrap_authify.sh | grep -E '^(ORG_SLUG|CLIENT_ID|CLIENT_SECRET|USER_EMAIL|USER_PASSWORD)=')"
bash spec/smoke/run_smoke_tests.sh
```

Note: `URL_SCHEME=http` is required because the docker image's default
endpoint URL scheme is `https`, which would otherwise leak into the OIDC
issuer (and thus into the strategy's ID-token issuer check).
