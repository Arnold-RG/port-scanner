#!/usr/bin/env bash
# Smoke tests for port-scan.sh / port-scan.ps1 against 127.0.0.1 only.
set -euo pipefail
cd "$(dirname "$0")/.."
WEB=18000; BAN=12222
python3 -m http.server "$WEB" --bind 127.0.0.1 >/dev/null 2>&1 & P1=$!
python3 tests/banner_server.py "$BAN" >/dev/null 2>&1 & P2=$!
OUT=$(mktemp -d)
trap 'kill $P1 $P2 2>/dev/null || true; rm -rf "$OUT"' EXIT
sleep 1
fail() { echo "FAIL: $*"; exit 1; }

echo "== bash: scan with banners"
./port-scan.sh -t 127.0.0.1 -p "1-1024,$WEB,$BAN" -b -o "$OUT/r.json" | tee "$OUT/console.txt"
grep -q "\"port\": $WEB" "$OUT/r.json" || fail "web port missing"
grep -q "SSH-2.0-TestBanner" "$OUT/r.json" || fail "banner not grabbed"
./port-scan.sh -t 127.0.0.1 -p "$WEB" -o "$OUT/r.csv" >/dev/null
grep -q "^127.0.0.1,$WEB,open" "$OUT/r.csv" || fail "CSV row missing"

echo "== bash: CIDR and range targets"
out=$(./port-scan.sh -t 127.0.0.0/30 -p "$WEB"); grep -q "127.0.0.1 .*$WEB .*open" <<< "$out" || fail "CIDR scan"
out=$(./port-scan.sh -t 127.0.0.1-2 -p "$WEB"); grep -q "127.0.0.1 .*$WEB .*open" <<< "$out" || fail "range scan"

echo "== bash: input validation"
./port-scan.sh -t 127.0.0.1 -p 0 >/dev/null 2>&1 && fail "port 0 accepted"
./port-scan.sh -t 127.0.0.1 -p 9-1 >/dev/null 2>&1 && fail "reversed range accepted"
./port-scan.sh -t '127.0.0.1;id' >/dev/null 2>&1 && fail "shell metacharacters accepted"
./port-scan.sh -t 10.0.0.0/16 >/dev/null 2>&1 && fail "/16 accepted"
grep -q Usage <<< "$(./port-scan.sh -h)" || fail "help missing"

if command -v pwsh >/dev/null 2>&1; then
    echo "== pwsh: scan with banners"
    pwsh -NoProfile -Command "
        \$r = ./port-scan.ps1 -Target 127.0.0.1 -Ports 1-1024,$WEB,$BAN -Banner
        if (-not (\$r | Where-Object Port -eq $WEB)) { Write-Error 'web port missing'; exit 1 }
        if (-not (\$r | Where-Object Banner -like 'SSH-2.0-TestBanner*')) { Write-Error 'banner missing'; exit 1 }
        \$c = ./port-scan.ps1 -Target 127.0.0.0/30 -Ports $WEB
        if (-not (\$c | Where-Object { \$_.Host -eq '127.0.0.1' -and \$_.Port -eq $WEB })) { Write-Error 'CIDR scan'; exit 1 }
    " || fail "pwsh scan"
fi
echo "All tests passed."
