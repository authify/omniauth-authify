#!/bin/bash
# Drives the omniauth-authify flow against a live Authify.
# Usage: SMOKE_USER_EMAIL=... SMOKE_USER_PASSWORD=... run_flow.sh [deny|approve|replay_code] [cookie-jar-prefix]
# Requires SMOKE_USER_EMAIL and SMOKE_USER_PASSWORD; the Authify host and org
# can be overridden via SMOKE_SITE and SMOKE_ORG.
set -eu
: "${SMOKE_USER_EMAIL:?SMOKE_USER_EMAIL required}"
: "${SMOKE_USER_PASSWORD:?SMOKE_USER_PASSWORD required}"
MODE="${1:-approve}"
T="${2:-$(date +%s)}"
D=/var/folders/w2/f0yl1wj97hd2gcrcljpcs92m0000gn/T/opencode
JAR="$D/flow_$T.txt"

get_loc() { grep -i "^location" "$1" | sed 's/^[Ll]ocation: //; s/\r//' ; }

# 0. CSRF from the smoke app + POST to OmniAuth request phase
TOKEN=$(curl -s -c "$JAR" http://127.0.0.1:9292/ | grep -o 'name="authenticity_token" value="[^"]*"' | sed 's/.*value="//; s/"$//')
curl -s -b "$JAR" -c "$JAR" -X POST "http://127.0.0.1:9292/auth/authify" \
  --data-urlencode "authenticity_token=$TOKEN" \
  --data-urlencode "prompt=consent" \
  -D "$D/f1_$T.txt" -o /dev/null
AUTH_URL=$(get_loc "$D/f1_$T.txt")
[ -z "$AUTH_URL" ] && { echo "FAIL: no authorize redirect"; exit 1; }

# 1. Authify authorize endpoint (anon) -> /login?return_to=...
curl -s -b "$JAR" -c "$JAR" "$AUTH_URL" -D "$D/f2_$T.txt" -o /dev/null
LOGIN_LOC=$(get_loc "$D/f2_$T.txt")

# 2. Fetch login page, extract CSRF
curl -s -b "$JAR" -c "$JAR" "${SMOKE_SITE:-http://localhost:4000}$LOGIN_LOC" -o "$D/f_login_$T.html"
LOG_CSRF=$(grep -o 'name="_csrf_token"[^>]*value="[^"]*"' "$D/f_login_$T.html" | head -1 | sed 's/.*value="//; s/"$//')

# 3. POST login
curl -s -b "$JAR" -c "$JAR" -X POST "${SMOKE_SITE:-http://localhost:4000}/login" \
  --data-urlencode "_csrf_token=$LOG_CSRF" \
  --data-urlencode "login[organization_slug]=${SMOKE_ORG:-test-org}" \
  --data-urlencode "login[email]=$SMOKE_USER_EMAIL" \
  --data-urlencode "login[password]=$SMOKE_USER_PASSWORD" \
  -D "$D/f3_$T.txt" -o /dev/null

# 4. Authorize again (authenticated) -> consent screen
curl -s -b "$JAR" -c "$JAR" "$AUTH_URL" -o "$D/f_consent_$T.html"

# 5. Build consent body from either the approve=true or deny form
APPROVE_VALUE=false
[ "$MODE" = "approve" ] || [ "$MODE" = "replay_code" ] && APPROVE_VALUE=true
python3 - "$D/f_consent_$T.html" "$APPROVE_VALUE" "$D/consent_$T.txt" <<'EOF'
import re, sys, urllib.parse
html = open(sys.argv[1]).read()
value = sys.argv[2]
forms = re.findall(r"<form.*?</form>", html, re.S)
form = next((f for f in forms if f'name="approve" value="{value}"' in f), None)
if form is None:
    print("NO_CONSENT_FORM")
    sys.exit(2)
fields = re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>', form)
open(sys.argv[3], "w").write(urllib.parse.urlencode(fields))
print("fields:", [n for n, _ in fields])
EOF

# 6. POST consent
curl -s -b "$JAR" -c "$JAR" -X POST "${SMOKE_SITE:-http://localhost:4000}/${SMOKE_ORG:-test-org}/oauth/consent" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary "@$D/consent_$T.txt" -D "$D/f6_$T.txt" -o /dev/null
CONSENT_LOC=$(get_loc "$D/f6_$T.txt")
echo "consent -> $CONSENT_LOC"

case "$MODE" in
  deny)
    echo "=== callback result (follow denial redirect) ==="
    curl -s -b "$JAR" -c "$JAR" "$CONSENT_LOC"; echo
    ;;
  replay_code)
    CODE=$(python3 -c "import sys,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse('$CONSENT_LOC').query)['code'][0])")
    STATE=$(python3 -c "import sys,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse('$CONSENT_LOC').query)['state'][0])")
    echo "=== first use of the code ==="
    curl -s -b "$JAR" -c "$JAR" "$CONSENT_LOC"; echo
    echo "=== replay the same code (must fail) ==="
    curl -s -b "$JAR" -c "$JAR" "http://127.0.0.1:9292/auth/authify/callback?code=$CODE&state=$STATE"; echo
    ;;
  approve)
    echo "=== callback result ==="
    curl -s -b "$JAR" -c "$JAR" "$CONSENT_LOC"; echo
    ;;
esac