#!/usr/bin/env bash
# Bootstrap a freshly-migrated Authify instance for omniauth-authify smoke tests.
#
# Performs, via the web UI (the only provisioning surface available on a
# fresh install):
#   1. Initial setup wizard (creates the authify-global admin)
#   2. Creates the smoke-test organization
#   3. Invites + accepts a regular user for flow testing
#   4. Creates the OAuth2 application and echoes its credentials
#
# Env:
#   AUTHIFY_URL   - base URL of the running Authify (default http://localhost:4000)
#   ORG_SLUG      - organization slug to create (default ci-org)
#   Mysql access is only needed for invitation tokens; accepted via:
#   DB_CONTAINER  - MySQL container name (token extraction; optional but
#                   required since invitation emails are not sent without SMTP)
#   DB_USER/DB_PASS - credentials for that container's root user
#
# Outputs (stdout, KEY=value lines):
#   ORG_SLUG=, ADMIN_EMAIL=, ADMIN_PASSWORD=, USER_EMAIL=, USER_PASSWORD=,
#   CLIENT_ID=, CLIENT_SECRET=
set -eu

AUTHIFY_URL="${AUTHIFY_URL:-http://localhost:4000}"
ORG_SLUG="${ORG_SLUG:-ci-org}"
ORG_NAME="${ORG_NAME:-CI Org}"

ADMIN_EMAIL="ci-admin@${ORG_SLUG}.test"
# Throwaway credentials for an Authify instance that only exists for the
# duration of the test run (bootstrapped from an empty database and discarded
# afterwards). Override via env if your local instance has stricter policy.
ADMIN_PASSWORD="${ADMIN_PASSWORD:-CI-Boot5trap-Pw!}"
USER_EMAIL="ci-user@${ORG_SLUG}.test"
USER_PASSWORD="${USER_PASSWORD:-CI-User7-Pw!}"

D="$(mktemp -d)"
JAR="$D/cookies.txt"

get_loc() { grep -i "^location" "$1" 2>/dev/null | sed 's/^[Ll]ocation: //; s/\r//' | head -1; }
csrf_from() { grep -o 'name="_csrf_token"[^>]*value="[^"]*"' "$1" | head -1 | sed 's/.*value="//; s/"$//'; }

extract_client_secret() { # $1 = application show page HTML
  grep -A 8 'fw-bold">Client Secret' "$1" | grep -oE 'value="[A-Za-z0-9=]{20,}"' | head -1 | sed 's/value="//; s/"$//'
}

db_token_for() { # $1 = email
  docker exec "$DB_CONTAINER" mysql -u "$DB_USER" -p"$DB_PASS" authify_prod -N \
    -e "SELECT token FROM invitations WHERE email='$1' ORDER BY id DESC LIMIT 1" 2>/dev/null | tr -d '[:space:]'
}

echo "> waiting for Authify at $AUTHIFY_URL ..."
for i in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$AUTHIFY_URL/setup" 2>/dev/null || echo 000)"
  # 200 = setup wizard pending; 302 = already set up; both mean the app is up
  [ "$code" = "200" ] || [ "$code" = "302" ] && break
  [ "$i" = "60" ] && { echo "FAIL: Authify never became ready (last: $code)"; exit 1; }
  sleep 2
done

echo "> 1. running setup wizard (global admin)"
curl -s -c "$JAR" "$AUTHIFY_URL/setup" -o "$D/setup.html"
CS="$(csrf_from "$D/setup.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/setup" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "tenant_base_domain=ci.local.test" \
  --data-urlencode "user[first_name]=CI" \
  --data-urlencode "user[last_name]=Admin" \
  --data-urlencode "user[email]=$ADMIN_EMAIL" \
  --data-urlencode "user[password]=$ADMIN_PASSWORD" \
  --data-urlencode "user[password_confirmation]=$ADMIN_PASSWORD" \
  -D "$D/1.txt" -o /dev/null
grep -q "login" <(get_loc "$D/1.txt") || { echo "FAIL: setup wizard POST failed"; exit 1; }

echo "> 2. logging in as global admin"
curl -s -b "$JAR" -c "$JAR" "$AUTHIFY_URL/login?org_slug=authify-global" -o "$D/login.html"
CS="$(csrf_from "$D/login.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/login" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "login[organization_slug]=authify-global" \
  --data-urlencode "login[email]=$ADMIN_EMAIL" \
  --data-urlencode "login[password]=$ADMIN_PASSWORD" \
  -D "$D/2.txt" -o /dev/null
[[ "$(get_loc "$D/2.txt")" == *dashboard* ]] || { echo "FAIL: global login failed"; exit 1; }

echo "> 3. creating organization $ORG_SLUG"
curl -s -b "$JAR" -c "$JAR" "$AUTHIFY_URL/authify-global/organizations/new" -o "$D/orgform.html"
CS="$(csrf_from "$D/orgform.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/authify-global/organizations" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "organization[name]=$ORG_NAME" \
  --data-urlencode "organization[slug]=$ORG_SLUG" \
  -D "$D/3.txt" -o /dev/null
[[ "$(get_loc "$D/3.txt")" == *organizations ]] || { echo "FAIL: org creation failed"; exit 1; }

# Switch into the new org
curl -s -b "$JAR" -c "$JAR" "$AUTHIFY_URL/authify-global/organizations" -o "$D/orgs.html"
ORG_ID="$(grep -oE "organizations/[0-9]+/switch" "$D/orgs.html" | tail -1 | grep -oE '[0-9]+')"
CS="$(csrf_from "$D/orgs.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/authify-global/organizations/$ORG_ID/switch" \
  --data-urlencode "_csrf_token=$CS" -D "$D/4.txt" -o /dev/null
[[ "$(get_loc "$D/4.txt")" == *"/dashboard" ]] || { echo "FAIL: org switch failed"; exit 1; }

echo "> 4. inviting the flow user ($USER_EMAIL)"
curl -s -b "$JAR" -c "$JAR" "$AUTHIFY_URL/$ORG_SLUG/invitations/new" -o "$D/invite.html"
CS="$(csrf_from "$D/invite.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/$ORG_SLUG/invitations" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "invitation[email]=$USER_EMAIL" \
  --data-urlencode "invitation[role]=user" \
  -D "$D/5.txt" -o /dev/null
grep -q "invitations" <(get_loc "$D/5.txt") || { echo "FAIL: invitation failed"; exit 1; }

echo "> 5. accepting the invitation (token via DB; no SMTP in CI)"
[ -n "$DB_CONTAINER" ] || { echo "FAIL: DB_CONTAINER required for invitation token extraction"; exit 1; }
TOKEN="$(db_token_for "$USER_EMAIL")"
[ -n "$TOKEN" ] || { echo "FAIL: no invitation token found"; exit 1; }
curl -s "$AUTHIFY_URL/invite/$TOKEN" -c "$D/accept.jar" -o "$D/accept.html"
CS="$(csrf_from "$D/accept.html")"
curl -s -b "$D/accept.jar" -X POST "$AUTHIFY_URL/invite/$TOKEN/accept" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "user[first_name]=CI" \
  --data-urlencode "user[last_name]=User" \
  --data-urlencode "user[username]=ci-user" \
  --data-urlencode "user[password]=$USER_PASSWORD" \
  --data-urlencode "user[password_confirmation]=$USER_PASSWORD" \
  -D "$D/6.txt" -o /dev/null
code="$(head -1 "$D/6.txt" | awk '{print $2}')"
[ "$code" = "302" ] || { echo "FAIL: invitation acceptance failed ($code)"; exit 1; }

echo "> 6. creating the OAuth2 application"
curl -s -b "$JAR" -c "$JAR" "$AUTHIFY_URL/$ORG_SLUG/applications/new" -o "$D/app.html"
CS="$(csrf_from "$D/app.html")"
curl -s -b "$JAR" -c "$JAR" -X POST "$AUTHIFY_URL/$ORG_SLUG/applications" \
  --data-urlencode "_csrf_token=$CS" \
  --data-urlencode "application[name]=omniauth-authify smoke" \
  --data-urlencode "application[redirect_uris]=http://localhost:9292/auth/authify/callback
http://127.0.0.1:9292/auth/authify/callback" \
  --data-urlencode "application[homepage_url]=http://localhost:9292" \
  --data-urlencode "application[description]=CI smoke test app" \
  --data-urlencode "application[is_active]=true" \
  --data-urlencode "application[scopes][]=openid" \
  --data-urlencode "application[scopes][]=profile" \
  --data-urlencode "application[scopes][]=email" \
  --data-urlencode "application[scopes][]=groups" \
  -D "$D/7.txt" -o "$D/app_show.html"
APP_PATH="$(get_loc "$D/7.txt")"
[[ "$APP_PATH" != "" ]] || true
[[ "$APP_PATH" == *applications/* ]] || { echo "FAIL: app creation failed"; exit 1; }
# Re-fetch the show page to make sure we have it (the create 302s to it)
APP_ID="${APP_PATH##*/}"
curl -s -b "$JAR" "$AUTHIFY_URL/$ORG_SLUG/applications/$APP_ID" -o "$D/app_show.html"
CLIENT_SECRET="$(extract_client_secret "$D/app_show.html")"
CLIENT_ID="$(grep -oE '[a-z0-9]{26}======|\b[a-z0-9]{26}\b' "$D/app_show.html" | head -1)"
[ -n "$CLIENT_SECRET" ] || { echo "FAIL: could not extract client secret"; exit 1; }

echo "> bootstrap complete"
cat <<EOS
ORG_SLUG=$ORG_SLUG
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
USER_EMAIL=$USER_EMAIL
USER_PASSWORD=$USER_PASSWORD
CLIENT_ID=$CLIENT_ID
CLIENT_SECRET=$CLIENT_SECRET
EOS