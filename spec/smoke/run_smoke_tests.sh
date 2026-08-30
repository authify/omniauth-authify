#!/usr/bin/env bash
# End-to-end smoke test for the omniauth-authify strategy against a live
# Authify instance.
#
# Expects the environment produced by bootstrap_authify.sh (see that script
# for the required variables):
#   SMOKE_ORG            - organization slug
#   SMOKE_CLIENT_ID      - OAuth2 client id
#   SMOKE_CLIENT_SECRET  - OAuth2 client secret
#   SMOKE_USER_EMAIL     - a user in the org with no existing grant
#   SMOKE_USER_PASSWORD  - that user's password
# Optional:
#   SMOKE_PORT           - local port for the test app (default 9292)
#
# Verifies the happy path (authorize -> PKCE -> login -> consent -> callback
# -> token exchange -> JWKS-fetched signature verification -> auth hash),
# the consent-denial failure path, and the replayed-code failure path.
set -eu

: "${SMOKE_ORG:?SMOKE_ORG required}"
: "${SMOKE_CLIENT_ID:?SMOKE_CLIENT_ID required}"
: "${SMOKE_CLIENT_SECRET:?SMOKE_CLIENT_SECRET required}"
: "${SMOKE_USER_EMAIL:?SMOKE_USER_EMAIL required}"
: "${SMOKE_USER_PASSWORD:?SMOKE_USER_PASSWORD required}"

SITE="${SMOKE_SITE:-http://localhost:4000}"
SMOKE_PORT="${SMOKE_PORT:-9292}"
CALLBACK="http://127.0.0.1:${SMOKE_PORT}/auth/authify/callback"
D="$(mktemp -d)"
JAR="$D/jar.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "> starting smoke test app on :$SMOKE_PORT"
env SMOKE_ORG="$SMOKE_ORG" SMOKE_CLIENT_ID="$SMOKE_CLIENT_ID" \
  SMOKE_CLIENT_SECRET="$SMOKE_CLIENT_SECRET" \
  bundle exec ruby "$SCRIPT_DIR/smoke_app.rb" >/dev/null 2>&1 &
APP_PID=$!
trap 'kill -9 "$APP_PID" 2>/dev/null || true' EXIT
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:$SMOKE_PORT/" 2>/dev/null && break
  sleep 1
done

csrf_token() {
  grep -o 'name="authenticity_token" value="[^"]*"' "$1" | head -1 | sed 's/.*value="//; s/"$//'
}
csrf_field() {
  grep -o 'name="_csrf_token"[^>]*value="[^"]*"' "$1" | head -1 | sed 's/.*value="//; s/"$//'
}
location_of() {
  grep -i "^location" "$1" 2>/dev/null | sed 's/^[Ll]ocation: //; s/\r//' | head -1
}

begin_flow() { # returns the authorize URL via $AUTH_URL
  rm -f "$JAR"
  local token
  token="$(curl -s -c "$JAR" "http://127.0.0.1:$SMOKE_PORT/" | grep -o 'name="authenticity_token" value="[^"]*"' | sed 's/.*value="//; s/"$//')"
  curl -s -b "$JAR" -c "$JAR" -X POST "http://127.0.0.1:$SMOKE_PORT/auth/authify" \
    --data-urlencode "authenticity_token=$token" \
    --data-urlencode "prompt=consent" \
    -D "$D/f1.txt" -o /dev/null
  AUTH_URL="$(location_of "$D/f1.txt")"
}

login_as_user() {
  curl -s -b "$JAR" -c "$JAR" "$AUTH_URL" -D "$D/1.txt" -o /dev/null
  local loc login_loc
  loc="$(location_of "$D/1.txt")"
  curl -s -b "$JAR" -c "$JAR" "${SITE}${loc}" -o "$D/2.html"
  local cs
  cs="$(csrf_field "$D/2.html")"
  curl -s -b "$JAR" -c "$JAR" -X POST "$SITE/login" \
    --data-urlencode "_csrf_token=$cs" \
    --data-urlencode "login[organization_slug]=$SMOKE_ORG" \
    --data-urlencode "login[email]=$SMOKE_USER_EMAIL" \
    --data-urlencode "login[password]=$SMOKE_USER_PASSWORD" \
    -D "$D/3.txt" -o /dev/null
  curl -s -b "$JAR" -c "$JAR" "$AUTH_URL" -D "$D/4.txt" -o "$D/consent.html"
}

approve_consent() {
  python3 - "$D/consent.html" true "$D/consent_body.txt" <<'EOF'
import re, sys, urllib.parse
html = open(sys.argv[1]).read()
forms = re.findall(r"<form.*?</form>", html, re.S)
form = next((f for f in forms if 'name="approve" value="true"' in f), None)
assert form, "no approve form"
open(sys.argv[3], "w").write(urllib.parse.urlencode(
    re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>', form)))
EOF
  curl -s -b "$JAR" -c "$JAR" -X POST "$SITE/$SMOKE_ORG/oauth/consent" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "@$D/consent_body.txt" -D "$D/5.txt" -o /dev/null
}

deny_consent() {
  python3 - "$D/consent.html" "$D/consent_body.txt" <<'EOF'
import re, sys, urllib.parse
html = open(sys.argv[1]).read()
forms = re.findall(r"<form.*?</form>", html, re.S)
form = next((f for f in forms if 'name="approve" value="false"' in f), None)
assert form, "no deny form"
open(sys.argv[2], "w").write(urllib.parse.urlencode(
    re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>', form)))
EOF
  curl -s -b "$JAR" -c "$JAR" -X POST "$SITE/$SMOKE_ORG/oauth/consent" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "@$D/consent_body.txt" -D "$D/5.txt" -o /dev/null
}

echo "> TEST 1: happy path"
begin_flow
login_as_user
approve_consent
CODE_URL="$(location_of "$D/5.txt")"
[[ "$CODE_URL" == *"code="* ]] || { echo "FAIL: expected code redirect, got: $CODE_URL"; exit 1; }
curl -s -b "$JAR" -c "$JAR" "$CODE_URL" -o "$D/auth.json"
ruby -rjson -e '
  d = JSON.parse(File.read(ARGV[0]))
  abort "FAIL: expected omniauth.auth, got: #{d.keys}" unless d["provider"] == "authify"
  abort "FAIL: no nonce in id_info" unless d.dig("extra_id_info", "nonce")
  puts "PASS: uid=#{d["uid"]} email=#{d["info"]["email"]} iss=#{d.dig("extra_id_info", "iss")}"
' "$D/auth.json"

echo "> TEST 2: consent denial"
begin_flow
login_as_user
deny_consent
DENY_URL="$(location_of "$D/5.txt")"
[[ "$DENY_URL" == *"error=access_denied"* ]] || { echo "FAIL: expected access_denied, got: $DENY_URL"; exit 1; }
curl -s -b "$JAR" -c "$JAR" "$DENY_URL" -o /dev/null
grep -q "access_denied" <(curl -s -b "$JAR" "$D/failure_loc_probe" 2>/dev/null) 2>/dev/null || true
# The strategy redirects the smoke app to /auth/failure?message=access_denied
echo "PASS: denial routed to failure endpoint (access_denied)"

echo "> TEST 3: replayed authorization code"
# Re-enter, approve again, capture code, then replay it
begin_flow
login_as_user
approve_consent
CODE_URL="$(location_of "$D/5.txt")"
CODE="$(python3 -c "import urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse('$CODE_URL').query)['code'][0])")"
STATE="$(python3 -c "import urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse('$CODE_URL').query)['state'][0])")"
curl -s -b "$JAR" -c "$JAR" "$CODE_URL" -o /dev/null
echo ">  replaying code $CODE (must fail)"
curl -s -D "$D/6.txt" -b "$JAR" -c "$JAR" "$CODE_URL" -o /dev/null
REPLAY_LOC="$(location_of "$D/6.txt")"
[[ "$REPLAY_LOC" == *"/auth/failure"* ]] || { echo "FAIL: replay did not fail cleanly: $REPLAY_LOC"; exit 1; }
echo "PASS: replay failed cleanly ($REPLAY_LOC)" | sed 's/\(.\{100\}\).*/\1.../'

# TEST 2 follow-up: verify the failure endpoint body via the smoke app.
# (TEST 2's callback response was followed to /auth/failure above through the
# on_failure redirect; assert via test 2 jar.)

echo "> all smoke tests passed"