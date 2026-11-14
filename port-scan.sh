#!/usr/bin/env bash
# =============================================================================
# port-scan.sh - TCP connect port scanner (host, IP range or CIDR)
# -----------------------------------------------------------------------------
# Purpose : Find open TCP ports on one or more hosts using full TCP connects
#           (bash /dev/tcp), with optional banner grabbing and CSV/JSON output.
# Usage   : ./port-scan.sh -t <target> [-p 22,80,443|1-1024] [-w 1] [-j 100]
#                          [-b] [-o results.csv] [-f csv|json] [-c]
#           ./port-scan.sh -h
# Targets : hostname (scanme.local), IP (10.0.0.5), last-octet range
#           (10.0.0.10-20) or CIDR (10.0.0.0/28). Max 1024 hosts per run.
# Requires: bash 4.3+, coreutils `timeout`. Optional: `getent` for names.
# Author  : Arnold Rurangwa - MIT License
# Legal   : Only scan hosts you own or are explicitly authorised to test.
# =============================================================================
set -uo pipefail

TARGET=""
PORT_SPEC="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080"
TIMEOUT=1
JOBS=100
BANNER=0
OUTFILE=""
FORMAT=""
SHOW_CLOSED=0
MAX_HOSTS=1024
MAX_PROBES=200000

usage() {
    cat <<USAGE
Usage: $(basename "$0") -t <target> [options]

TCP connect scan of a host, IP range or CIDR block.

  -t TARGET  hostname | IP | 10.0.0.10-20 | 10.0.0.0/28  (max $MAX_HOSTS hosts)
  -p PORTS   list and/or ranges, e.g. 22,80,443 or 1-1024 or 20-25,80
             (default: 20 common ports)
  -w SEC     connect timeout in seconds (default: $TIMEOUT, 1-10)
  -j N       parallel connections (default: $JOBS, 1-500)
  -b         grab a banner from open ports (sends HTTP HEAD on web ports)
  -o FILE    write results to FILE
  -f FMT     output format for -o: csv or json (default: from file extension)
  -c         also list closed ports in the console (filtered are never listed)
  -h         show this help

Examples:
  $(basename "$0") -t 127.0.0.1 -p 1-1024
  $(basename "$0") -t 192.168.1.10-20 -p 22,80,443 -b -o scan.json

Only scan hosts you own or are authorised to test.
USAGE
}

die() { echo "Error: $*" >&2; exit 2; }
is_int_between() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }

while getopts ":t:p:w:j:o:f:bch" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        p) PORT_SPEC="$OPTARG" ;;
        w) TIMEOUT="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        b) BANNER=1 ;;
        o) OUTFILE="$OPTARG" ;;
        f) FORMAT="$OPTARG" ;;
        c) SHOW_CLOSED=1 ;;
        h) usage; exit 0 ;;
        :) die "option -$OPTARG needs a value (see -h)" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
[[ -n "$TARGET" ]] || { usage >&2; exit 2; }
is_int_between "$TIMEOUT" 1 10 || die "-w must be 1-10"
is_int_between "$JOBS" 1 500 || die "-j must be 1-500"

if [[ -n "$OUTFILE" && -z "$FORMAT" ]]; then
    case "$OUTFILE" in *.json) FORMAT=json ;; *) FORMAT=csv ;; esac
fi
[[ -z "$FORMAT" || "$FORMAT" == csv || "$FORMAT" == json ]] || die "-f must be csv or json"

# ---- port list -----------------------------------------------------------------
# expand_ports "20-22,80" -> one port per line, de-duplicated, sorted
expand_ports() {
    local item a b
    [[ "$1" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || die "bad port list: $1"
    IFS=',' read -r -a items <<< "$1"
    for item in "${items[@]}"; do
        if [[ "$item" == *-* ]]; then a=${item%-*}; b=${item#*-}; else a=$item; b=$item; fi
        if ! is_int_between "$a" 1 65535 || ! is_int_between "$b" 1 65535; then
            die "port out of range: $item"
        fi
        (( 10#$a <= 10#$b )) || die "reversed range: $item"
        seq "$((10#$a))" "$((10#$b))"
    done | sort -nu
}
mapfile -t PORTS < <(expand_ports "$PORT_SPEC")
(( ${#PORTS[@]} > 0 )) || exit 2

# ---- target list ---------------------------------------------------------------
valid_ip() {
    local o x
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a o <<< "$1"
    for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
}
ip_to_int() { local a b c d; IFS=. read -r a b c d <<< "$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int_to_ip() { local n=$1; echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"; }

HOSTS=()
if [[ "$TARGET" =~ ^([0-9.]+)/([0-9]+)$ ]]; then                 # CIDR
    cidr_ip=${BASH_REMATCH[1]}; pfx=${BASH_REMATCH[2]}   # save before valid_ip reuses BASH_REMATCH
    valid_ip "$cidr_ip" || die "invalid IP in $TARGET"
    is_int_between "$pfx" 22 32 || die "CIDR prefix must be /22 - /32 (max $MAX_HOSTS hosts)"
    size=$(( 1 << (32 - pfx) ))
    net=$(( $(ip_to_int "$cidr_ip") / size * size ))
    if (( pfx >= 31 )); then first=$net; last=$(( net + size - 1 ))
    else first=$(( net + 1 )); last=$(( net + size - 2 )); fi
    for (( i = first; i <= last; i++ )); do HOSTS+=("$(int_to_ip "$i")"); done
elif [[ "$TARGET" =~ ^(([0-9]{1,3}\.){3})([0-9]{1,3})-([0-9]{1,3})$ ]]; then   # a.b.c.x-y
    pre=${BASH_REMATCH[1]}; s=${BASH_REMATCH[3]}; e=${BASH_REMATCH[4]}
    if ! valid_ip "${pre}${s}" || ! valid_ip "${pre}${e}" || (( 10#$s > 10#$e )); then
        die "bad range: $TARGET"
    fi
    for (( i = 10#$s; i <= 10#$e; i++ )); do HOSTS+=("${pre}${i}"); done
elif valid_ip "$TARGET"; then
    HOSTS=("$TARGET")
elif [[ "$TARGET" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$ ]]; then  # hostname
    HOSTS=("$TARGET")
else
    die "unrecognised target: $TARGET"
fi
(( ${#HOSTS[@]} <= MAX_HOSTS )) || die "too many hosts (${#HOSTS[@]})"
TOTAL=$(( ${#HOSTS[@]} * ${#PORTS[@]} ))
(( TOTAL <= MAX_PROBES )) || die "too many probes ($TOTAL > $MAX_PROBES); narrow hosts or ports"

# ---- probing -------------------------------------------------------------------
service_name() {
    local s=""
    command -v getent >/dev/null 2>&1 && s=$(getent services "$1/tcp" 2>/dev/null | awk '{print $1; exit}')
    echo "${s:-unknown}"
}

# grab_banner HOST PORT -> first line the service sends (or HTTP status line)
grab_banner() {
    local req=""
    case "$2" in 80|8000|8008|8080|8081|8888) req=$'HEAD / HTTP/1.0\r\n\r\n' ;; esac
    # Read at most one line; strip control characters so output stays clean.
    # shellcheck disable=SC2016  # $1..$3 are expanded by the inner bash
    timeout "$(( TIMEOUT + 2 ))" bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 1
        [[ -n "$3" ]] && printf "%s" "$3" >&3
        IFS= read -r -t 2 line <&3 && printf "%s" "$line"
    ' _ "$1" "$2" "$req" 2>/dev/null | tr -d '\r' | tr -c '[:print:]' ' ' | cut -c1-80
}

# probe HOST PORT -> writes a result line "host|port|state|service|banner"
probe() {
    local out rc state banner=""
    # shellcheck disable=SC2016  # $1/$2 are expanded by the inner bash
    out=$(timeout "$TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" 2>&1); rc=$?
    if (( rc == 0 )); then state=open
    elif [[ "$out" == *refused* ]]; then state=closed
    else state=filtered
    fi
    [[ "$state" == filtered ]] && return 0          # keep output small
    [[ "$state" == open && $BANNER -eq 1 ]] && banner=$(grab_banner "$1" "$2")
    printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$state" "$(service_name "$2")" "$banner" > "$TMP/$1_$2"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
trap 'echo; echo "Interrupted." >&2; exit 130' INT

echo "Scanning ${#HOSTS[@]} host(s) x ${#PORTS[@]} port(s) = $TOTAL probes (timeout ${TIMEOUT}s, $JOBS parallel)"
START=$(date +%s)
for h in "${HOSTS[@]}"; do
    for p in "${PORTS[@]}"; do
        probe "$h" "$p" &
        while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n; done
    done
done
wait

mapfile -t ROWS < <(cat "$TMP"/* 2>/dev/null | sort -t'|' -k1,1V -k2,2n)
OPEN=0
printf '\n%-20s %-7s %-9s %-14s %s\n' HOST PORT STATE SERVICE BANNER
for r in "${ROWS[@]}"; do
    IFS='|' read -r h p st svc ban <<< "$r"
    [[ "$st" == open ]] && OPEN=$(( OPEN + 1 ))
    [[ "$st" == closed && $SHOW_CLOSED -eq 0 ]] && continue
    printf '%-20s %-7s %-9s %-14s %s\n' "$h" "$p" "$st" "$svc" "$ban"
done
echo
echo "$OPEN open port(s) found in $(( $(date +%s) - START ))s."

# ---- file output -----------------------------------------------------------------
json_escape() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }
if [[ -n "$OUTFILE" ]]; then
    {
        if [[ "$FORMAT" == json ]]; then
            echo "["
            n=0
            for r in "${ROWS[@]}"; do
                IFS='|' read -r h p st svc ban <<< "$r"
                [[ "$st" == open ]] || continue
                (( n++ )) && echo ","
                printf '  {"host": "%s", "port": %s, "state": "%s", "service": "%s", "banner": "%s"}' \
                    "$(json_escape "$h")" "$p" "$st" "$(json_escape "$svc")" "$(json_escape "$ban")"
            done
            echo; echo "]"
        else
            echo "host,port,state,service,banner"
            for r in "${ROWS[@]}"; do
                IFS='|' read -r h p st svc ban <<< "$r"
                [[ "$st" == open ]] || continue
                echo "$h,$p,$st,$svc,\"${ban//\"/\"\"}\""
            done
        fi
    } > "$OUTFILE" || die "cannot write $OUTFILE"
    echo "Results ($FORMAT) written to $OUTFILE"
fi
