#!/usr/bin/env bash
set -uo pipefail
umask 077

# Resolve defaults relative to the checkout, including when launched by cron.
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
INPUT=${1:-"$BASE/ip-addresses.txt"}
OUTPUT=${2:-"$BASE/ip-results.csv"}
SECRETS_FILE=${IP_CHECKER_SECRETS:-"$BASE/.secrets"}

if (($# > 2)); then
    echo "Usage: $0 [input-file [output-csv]]" >&2
    exit 1
fi
for cmd in curl jq dig python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing dependency: $cmd" >&2; exit 1; }
done
[[ -f "$INPUT" && -r "$INPUT" && -s "$INPUT" ]] || { echo "Missing, unreadable or empty input: $INPUT" >&2; exit 1; }
[[ -f "$SECRETS_FILE" && -r "$SECRETS_FILE" ]] || {
    echo "Missing secrets file: $SECRETS_FILE. Copy .secrets.example to .secrets and fill in your keys." >&2
    exit 1
}
# This is a trusted Bash configuration file. Do not source untrusted files.
# shellcheck source=.secrets.example
source "$SECRETS_FILE" || { echo "Could not load secrets file." >&2; exit 1; }
for name in IPINFO_KEY IP2_KEY PROXY_KEY SPAMHAUS_KEY; do
    [[ -n "${!name:-}" ]] || { echo "Missing key in .secrets: $name" >&2; exit 1; }
done
# Protect the input and configuration from accidental output overwrites.
python3 - "$INPUT" "$OUTPUT" "$SECRETS_FILE" <<'PY'
from pathlib import Path
import os, sys
output = Path(sys.argv[2])
for source in (Path(sys.argv[1]), Path(sys.argv[3])):
    if output.resolve() == source.resolve() or (output.exists() and os.path.samefile(output, source)):
        sys.exit('Output must not overwrite the input or secrets file.')
PY
[[ $? == 0 ]] || exit 1

mapfile -t IPS < <(python3 - "$INPUT" <<'PY'
import ipaddress, sys
seen = set()
with open(sys.argv[1], encoding='utf-8-sig') as handle:
    for line in handle:
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                raise ValueError('not a public IPv4 address')
        except ValueError:
            print('Skipping invalid/non-public IP: ' + value, file=sys.stderr)
            continue
        value = str(address)
        if value not in seen:
            seen.add(value)
            print(value)
PY
)
((${#IPS[@]})) || { echo 'No valid public IPv4 addresses.' >&2; exit 1; }

# HTTP helper: valid JSON or {}. Errors do not become negative detections.
api_get() {
    local response
    response=$(curl -fsSL --connect-timeout 5 --max-time 18 "$@" 2>/dev/null) || { printf '{}\n'; return; }
    if jq -e . >/dev/null 2>&1 <<< "$response"; then
        printf '%s\n' "$response"
    else
        printf '{}\n'
    fi
}

# Read a dotted JSON field. Missing and null values are UNKNOWN.
json_flag() {
    local data="$1" path="$2"
    jq -r --arg path "$path" '
        def normalize:
          if . == true or . == 1 or . == "1" or . == "yes" or . == "YES" or . == "Y" then "YES"
          elif . == false or . == 0 or . == "0" or . == "no" or . == "NO" or . == "N" then "NO"
          else "UNKNOWN" end;
        getpath($path | split("."))? | normalize
    ' <<< "$data" 2>/dev/null || echo UNKNOWN
}

# RDAP registered allocation. Try redirect service, then registries.
get_cidr() {
    local ip="$1" url response cidr
    local urls=(
        "https://rdap.org/ip/$ip"
        "https://rdap.arin.net/registry/ip/$ip"
        "https://rdap.db.ripe.net/ip/$ip"
        "https://rdap.apnic.net/ip/$ip"
        "https://rdap.lacnic.net/rdap/ip/$ip"
        "https://rdap.afrinic.net/rdap/ip/$ip"
    )
    for url in "${urls[@]}"; do
        response=$(api_get -H 'Accept: application/rdap+json' "$url")
        cidr=$(python3 - "$ip" "$response" <<'PY'
import ipaddress, json, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    data = json.loads(sys.argv[2])
    matches = []
    for item in data.get('cidr0_cidrs', []):
        if 'v4prefix' in item and 'length' in item:
            network = ipaddress.ip_network(f"{item['v4prefix']}/{item['length']}", strict=False)
            if ip in network:
                matches.append(network)
    if matches:
        print(max(matches, key=lambda network: network.prefixlen))
    else:
        start = ipaddress.ip_address(data['startAddress'])
        end = ipaddress.ip_address(data['endAddress'])
        if start <= ip <= end:
            print(next(str(net) for net in ipaddress.summarize_address_range(start, end) if ip in net))
        else:
            print('UNKNOWN')
except (KeyError, ValueError, TypeError, StopIteration, json.JSONDecodeError):
    print('UNKNOWN')
PY
)
        if [[ -n "$cidr" && "$cidr" != UNKNOWN ]]; then
            printf '%s\n' "$cidr"
            return
        fi
    done
    echo UNKNOWN
}

# Return LISTS|STATE. Query status must be checked, not just empty answer.
spamhaus_lookup() {
    local ip="$1" reversed q response status codes code labels=() joined
    reversed=$(awk -F. '{print $4"."$3"."$2"."$1}' <<< "$ip")
    q="${reversed}.${SPAMHAUS_KEY}.zen.dq.spamhaus.net"
    response=$(dig +time=3 +tries=1 +noall +comments +answer "$q" A 2>/dev/null) || { echo 'UNKNOWN|UNKNOWN'; return; }
    status=$(sed -n 's/.*status: \([A-Z]*\),.*/\1/p' <<< "$response" | head -n 1)
    case "$status" in
        NXDOMAIN) echo 'NONE|NO'; return ;;
        NOERROR) ;;
        *) echo 'UNKNOWN|UNKNOWN'; return ;;
    esac
    codes=$(awk '$4 == "A" {print $5}' <<< "$response" | sort -u)
    [[ -n "$codes" ]] || { echo 'UNKNOWN|UNKNOWN'; return; }
    if grep -q '^127\.255\.255\.' <<< "$codes"; then
        echo 'QUERY_ERROR|UNKNOWN'; return
    fi
    while IFS= read -r code; do
        case "$code" in
            127.0.0.2) labels+=(SBL) ;;
            127.0.0.3) labels+=(CSS) ;;
            127.0.0.4) labels+=(XBL) ;;
            127.0.0.9) labels+=(DROP) ;;
            127.0.0.10|127.0.0.11|127.0.0.12) labels+=(PBL) ;;
            *) labels+=("OTHER:$code") ;;
        esac
    done <<< "$codes"
    joined=$(IFS=+; echo "${labels[*]}")
    printf '%s|YES\n' "$joined"
}

jq -rn '["IP Address","CIDR","ASN","Provider","IP2 Proxy","PC Anonymous","PC VPN","PC Proxy","PC Tor","PC Hosting","PC Network Type","PC Risk","PC Confidence","Spamhaus Lists","Spamhaus Status","Anonymisation","Hosting","Threat Listing","Review"] | @csv' > "$OUTPUT" || { echo "Cannot write output: $OUTPUT" >&2; exit 1; }

printf '\nLoaded %d unique public IPv4 addresses.\n\n' "${#IPS[@]}"
printf '%-18s %-21s %-10s %-20s %-6s %-6s %-6s %-8s %-14s %s\n' IP CIDR ASN PROVIDER IP2 VPN TOR HOSTING SPAMHAUS REVIEW
printf '%s\n' '---------------------------------------------------------------------------------------------------------------------------------'

VPN_COUNT=0; PROXY_COUNT=0; HOST_COUNT=0; THREAT_COUNT=0; UNKNOWN_COUNT=0
for IP in "${IPS[@]}"; do
    INFO=$(api_get -H "Authorization: Bearer $IPINFO_KEY" "https://ipinfo.io/$IP/json")
    ORG=$(jq -r '.org // "UNKNOWN"' <<< "$INFO")
    ASN=$(grep -oE '^AS[0-9]+' <<< "$ORG" || true)
    ASN=${ASN:-UNKNOWN}
    PROVIDER="$ORG"
    [[ "$ASN" == UNKNOWN ]] || PROVIDER=${ORG#"$ASN "}

    CIDR=$(get_cidr "$IP")
    IP2=$(api_get -G --data-urlencode "key=$IP2_KEY" --data-urlencode "ip=$IP" 'https://api.ip2location.io/')
    IP2_PROXY=$(json_flag "$IP2" is_proxy)
    if jq -e '.error != null' >/dev/null 2>&1 <<< "$IP2"; then IP2_PROXY=UNKNOWN; fi

    PC=$(api_get -G --data-urlencode "key=$PROXY_KEY" "https://proxycheck.io/v3/$IP")
    PC_STATUS=$(jq -r '.status // "UNKNOWN"' <<< "$PC")
    PC_ENTRY=$(jq -c --arg ip "$IP" '.[$ip] // {}' <<< "$PC")
    if [[ "${PC_STATUS,,}" != ok && "${PC_STATUS,,}" != warning ]]; then
        PC_ENTRY='{}'
        echo "proxycheck.io status for $IP: $PC_STATUS" >&2
    fi
    PC_ANON=$(json_flag "$PC_ENTRY" detections.anonymous)
    PC_VPN=$(json_flag "$PC_ENTRY" detections.vpn)
    PC_PROXY=$(json_flag "$PC_ENTRY" detections.proxy)
    PC_TOR=$(json_flag "$PC_ENTRY" detections.tor)
    PC_NETWORK=$(jq -r '.network.type // "UNKNOWN"' <<< "$PC_ENTRY")
    case "${PC_NETWORK,,}" in
        hosting|datacenter|data_center|data-centre|data-center) PC_HOSTING=YES ;;
        unknown|null|'') PC_HOSTING=UNKNOWN ;;
        *) PC_HOSTING=NO ;;
    esac
    PC_RISK=$(jq -r '.detections.risk // .risk // "UNKNOWN"' <<< "$PC_ENTRY")
    PC_CONFIDENCE=$(jq -r '.detections.confidence // "UNKNOWN"' <<< "$PC_ENTRY")

    SH=$(spamhaus_lookup "$IP")
    SH_LISTS=${SH%%|*}
    SH_STATUS=${SH##*|}
    THREAT=NO
    if [[ "$SH_LISTS" == *SBL* || "$SH_LISTS" == *XBL* || "$SH_LISTS" == *CSS* || "$SH_LISTS" == *DROP* ]]; then
        THREAT=YES
        ((THREAT_COUNT+=1))
    elif [[ "$SH_STATUS" == UNKNOWN ]]; then
        THREAT=UNKNOWN
    fi

    ANON=NO
    if [[ "$PC_VPN" == YES || "$PC_PROXY" == YES || "$PC_TOR" == YES || "$PC_ANON" == YES || "$IP2_PROXY" == YES ]]; then
        ANON=YES
    elif [[ "$PC_VPN" == UNKNOWN || "$PC_PROXY" == UNKNOWN || "$PC_TOR" == UNKNOWN || "$PC_ANON" == UNKNOWN || "$IP2_PROXY" == UNKNOWN ]]; then
        ANON=UNKNOWN
    fi
    [[ "$PC_VPN" != YES ]] || ((VPN_COUNT+=1))
    if [[ "$ANON" == YES && "$PC_VPN" != YES ]]; then ((PROXY_COUNT+=1)); fi
    [[ "$PC_HOSTING" != YES ]] || ((HOST_COUNT+=1))

    FLAGS=()
    [[ "$PC_VPN" != YES ]] || FLAGS+=(VPN)
    [[ "$PC_TOR" != YES ]] || FLAGS+=(TOR)
    if [[ "$IP2_PROXY" == YES || "$PC_PROXY" == YES || "$PC_ANON" == YES ]]; then FLAGS+=(PROXY); fi
    [[ "$PC_HOSTING" != YES ]] || FLAGS+=(HOSTING)
    [[ "$THREAT" != YES ]] || FLAGS+=(SPAMHAUS_THREAT)
    if ((${#FLAGS[@]})); then
        REVIEW=$(IFS=+; echo "${FLAGS[*]}")
    elif [[ "$ANON" == UNKNOWN || "$PC_HOSTING" == UNKNOWN || "$THREAT" == UNKNOWN ]]; then
        REVIEW=INCOMPLETE
        ((UNKNOWN_COUNT+=1))
    else
        REVIEW=NO_POSITIVE_DETECTION
    fi

    printf '%-18s %-21s %-10s %-20.20s %-6s %-6s %-6s %-8s %-14.14s %s\n' \
        "$IP" "$CIDR" "$ASN" "$PROVIDER" "$IP2_PROXY" "$PC_VPN" "$PC_TOR" "$PC_HOSTING" "$SH_LISTS" "$REVIEW"

    jq -rn --arg ip "$IP" --arg cidr "$CIDR" --arg asn "$ASN" --arg provider "$PROVIDER" \
        --arg ip2 "$IP2_PROXY" --arg anon "$PC_ANON" --arg vpn "$PC_VPN" --arg proxy "$PC_PROXY" \
        --arg tor "$PC_TOR" --arg hosting "$PC_HOSTING" --arg network "$PC_NETWORK" \
        --arg risk "$PC_RISK" --arg confidence "$PC_CONFIDENCE" --arg sh "$SH_LISTS" \
        --arg shstatus "$SH_STATUS" --arg anonymisation "$ANON" --arg threat "$THREAT" \
        --arg review "$REVIEW" \
        '[$ip,$cidr,$asn,$provider,$ip2,$anon,$vpn,$proxy,$tor,$hosting,$network,$risk,$confidence,$sh,$shstatus,$anonymisation,$hosting,$threat,$review] | @csv' >> "$OUTPUT" || { echo "Cannot append output: $OUTPUT" >&2; exit 1; }
    sleep 0.2
done
printf '\nTotal: %d | VPN: %d | Other proxy/anonymous: %d | Hosting: %d | Spamhaus threat: %d | Incomplete: %d\n' \
    "${#IPS[@]}" "$VPN_COUNT" "$PROXY_COUNT" "$HOST_COUNT" "$THREAT_COUNT" "$UNKNOWN_COUNT"
printf 'CSV: %s\n' "$OUTPUT"
unset IPINFO_KEY IP2_KEY PROXY_KEY SPAMHAUS_KEY
