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
# IPQS is optional so existing four-provider installations keep working.
IPQS_KEY=${IPQS_KEY:-}
IPQS_ENABLED=0
[[ -z "$IPQS_KEY" ]] || IPQS_ENABLED=1
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

# Preserve safe transport metadata, including bodies returned with HTTP errors.
api_get() {
    local response code exit_code=0
    response=$(curl -sSL --connect-timeout 5 --max-time 18 --write-out '\n%{http_code}' "$@" 2>/dev/null) || exit_code=$?
    if ((exit_code)); then
        if ((exit_code == 28)); then echo '{"_lookup_error":"TIMEOUT"}'; else echo '{"_lookup_error":"NETWORK_ERROR"}'; fi
        return
    fi
    code=${response##*$'\n'}
    response=${response%$'\n'*}
    [[ "$code" =~ ^[0-9]{3}$ ]] || { echo '{"_lookup_error":"NETWORK_ERROR"}'; return; }
    if jq -e . >/dev/null 2>&1 <<< "$response"; then
        jq -c --argjson code "$((10#$code))" 'if type == "object" then . + {_http_status:$code} else {_lookup_error:"INVALID_RESPONSE",_http_status:$code} end' <<< "$response"
    else
        jq -cn --argjson code "$((10#$code))" '{_lookup_error:"INVALID_JSON",_http_status:$code}'
    fi
}

# Read a dotted JSON field. Missing and null values are UNKNOWN.
json_flag() {
    local data="$1" path="$2"
    local result
    result=$(jq -r --arg path "$path" '
        def normalize:
          if . == true or . == 1 or . == "1" or . == "yes" or . == "YES" or . == "Y" then "YES"
          elif . == false or . == 0 or . == "0" or . == "no" or . == "NO" or . == "N" then "NO"
          else "UNKNOWN" end;
        getpath($path | split("."))? | normalize
    ' <<< "$data" 2>/dev/null) || result=UNKNOWN
    printf '%s\n' "${result:-UNKNOWN}"
}

# Fetch registered allocation data once; reuse it for CIDR and WHOIS-style fields.
get_rdap() {
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
        cidr=$(printf '%s' "$response" | python3 "$BASE/provider_data.py" --rdap-cidr "$ip")
        if [[ -n "$cidr" && "$cidr" != UNKNOWN ]]; then
            jq -c --arg source "$url" '. + {_rdap_source:$source}' <<< "$response"
            return
        fi
    done
    echo '{"_lookup_error":"RDAP_UNAVAILABLE"}'
}

# Return LISTS|STATE. Query status must be checked, not just empty answer.
spamhaus_lookup() {
    local ip="$1" reversed q response status codes code labels=() joined
    reversed=$(awk -F. '{print $4"."$3"."$2"."$1}' <<< "$ip")
    q="${reversed}.${SPAMHAUS_KEY}.zen.dq.spamhaus.net"
    response=$(dig +time=3 +tries=1 +noall +comments +answer "$q" A 2>/dev/null) || { echo 'UNKNOWN|UNKNOWN'; return; }
    status=$(sed -n 's/.*status: \([A-Z]*\),.*/\1/p' <<< "$response" | head -n 1)
    case "$status" in
        NXDOMAIN) if awk '$4 == "A" {found=1} END {exit !found}' <<< "$response"; then echo 'INVALID_RESPONSE|UNKNOWN'; else echo 'NONE|NO'; fi; return ;;
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
            127.0.0.10|127.0.0.11) labels+=(PBL) ;;
            127.0.0.30) labels+=(BCL) ;;
            *) labels+=("OTHER:$code") ;;
        esac
    done <<< "$codes"
    joined=$(IFS=+; echo "${labels[*]}")
    if [[ "$joined" == *OTHER:* ]]; then printf '%s|UNKNOWN\n' "$joined"; else printf '%s|YES\n' "$joined"; fi
}

python3 "$BASE/provider_data.py" --csv-header > "$OUTPUT" || { echo "Cannot write output: $OUTPUT" >&2; exit 1; }

printf '\nLoaded %d unique public IPv4 addresses.\n\n' "${#IPS[@]}"
printf '%-18s %-21s %-10s %-20s %-6s %-6s %-6s %-8s %-14s %s\n' IP CIDR ASN PROVIDER IP2 VPN TOR HOSTING SPAMHAUS REVIEW
printf '%s\n' '---------------------------------------------------------------------------------------------------------------------------------'

VPN_COUNT=0; PROXY_COUNT=0; HOST_COUNT=0; THREAT_COUNT=0; UNKNOWN_COUNT=0
for IP in "${IPS[@]}"; do
    INFO=$(api_get -H "Authorization: Bearer $IPINFO_KEY" "https://ipinfo.io/$IP/json")
    LITE='{}'
    if ! jq -e '(.org | type) == "string" and (.org | length) > 0' >/dev/null 2>&1 <<< "$INFO"; then
        LITE=$(api_get -H "Authorization: Bearer $IPINFO_KEY" "https://api.ipinfo.io/lite/$IP")
    fi

    RDAP=$(get_rdap "$IP")
    IP2=$(api_get -G --data-urlencode "key=$IP2_KEY" --data-urlencode "ip=$IP" 'https://api.ip2location.io/')
    IP2_PROXY=$(json_flag "$IP2" is_proxy)
    if jq -e '.error != null or ._lookup_error != null or (._http_status // 200) >= 400' >/dev/null 2>&1 <<< "$IP2"; then IP2_PROXY=UNKNOWN; fi

    PC=$(api_get -G --data-urlencode "key=$PROXY_KEY" "https://proxycheck.io/v3/$IP")
    PC_STATUS=$(jq -r '.status // "UNKNOWN"' <<< "$PC")
    PC_ENTRY=$(jq -c --arg ip "$IP" '.[$ip] // {}' <<< "$PC")
    if [[ "${PC_STATUS,,}" != ok && "${PC_STATUS,,}" != warning ]] || jq -e '._lookup_error != null or (._http_status // 200) >= 400' >/dev/null 2>&1 <<< "$PC"; then
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
        residential|business|wireless) PC_HOSTING=NO ;;
        *) PC_HOSTING=UNKNOWN ;;
    esac
    PC_RISK=$(jq -r '.detections.risk // .risk // "UNKNOWN"' <<< "$PC_ENTRY")
    PC_CONFIDENCE=$(jq -r '.detections.confidence // "UNKNOWN"' <<< "$PC_ENTRY")

    IPQS_STATUS=NOT_CONFIGURED
    IPQS='{}'
    IPQS_RAW='{}'
    if ((IPQS_ENABLED)); then
        IPQS=$(api_get -H "ipqs-key: $IPQS_KEY" -G --data-urlencode "ip=$IP" 'https://www.ipqualityscore.com/api/json/ip')
        IPQS_RAW=$IPQS
        if jq -e '.success == true and ._lookup_error == null and (._http_status // 200) < 400' >/dev/null 2>&1 <<< "$IPQS"; then
            IPQS_STATUS=OK
        else
            IPQS_STATUS=ERROR
            IPQS='{}'
        fi
    fi
    IPQS_PROXY=$(json_flag "$IPQS" proxy)
    IPQS_VPN=$(json_flag "$IPQS" vpn)
    IPQS_TOR=$(json_flag "$IPQS" tor)
    IPQS_ABUSE=$(json_flag "$IPQS" recent_abuse)
    IPQS_BOT=$(json_flag "$IPQS" bot_status)
    IPQS_SCORE=$(jq -r 'if (.fraud_score | type) == "number" then if .fraud_score >= 0 and .fraud_score <= 100 then .fraud_score else "UNKNOWN" end else "UNKNOWN" end' <<< "$IPQS")
    IPQS_ACTIVE_VPN=$(json_flag "$IPQS" active_vpn)
    IPQS_ACTIVE_TOR=$(json_flag "$IPQS" active_tor)
    IPQS_CRAWLER=$(json_flag "$IPQS" is_crawler)
    IPQS_CONNECTION=$(jq -r 'if (.connection_type | type) == "string" and (.connection_type | length) > 0 then .connection_type else "UNKNOWN" end' <<< "$IPQS")
    IPQS_VELOCITY=$(jq -r 'if (.abuse_velocity | type) == "string" and (.abuse_velocity | length) > 0 then .abuse_velocity else "UNKNOWN" end' <<< "$IPQS")
    IPQS_HOST=$(jq -r 'if (.host | type) == "string" and (.host | length) > 0 then .host else "UNKNOWN" end' <<< "$IPQS")
    IPQS_COUNTRY=$(jq -r 'if (.country_code | type) == "string" and (.country_code | length) > 0 then .country_code else "UNKNOWN" end' <<< "$IPQS")


    META=$(jq -n --argjson info "$INFO" --argjson lite "$LITE" --argjson ip2 "$IP2" \
        --argjson pc "$PC" --argjson ipqs "$IPQS_RAW" --argjson rdap "$RDAP" --arg ip "$IP" \
        '{info:$info,lite:$lite,ip2:$ip2,pc:$pc,ipqs:$ipqs,ip:$ip,rdap:$rdap}' | python3 "$BASE/provider_data.py") || exit 1
    CIDR=$(jq -r ' .CIDR ' <<< "$META")
    PC_RISK=$(jq -r ' ."PC Risk" ' <<< "$META")
    PC_CONFIDENCE=$(jq -r ' ."PC Confidence" ' <<< "$META")
    ASN=$(jq -r '.ASN' <<< "$META")
    PROVIDER=$(jq -r '.Provider' <<< "$META")
    HEALTH=$(jq -r '."Lookup Health"' <<< "$META")
    if [[ "$PC_RISK" == UNKNOWN || "$IP2_PROXY" == UNKNOWN || "$PC_VPN" == UNKNOWN || "$PC_PROXY" == UNKNOWN || "$PC_TOR" == UNKNOWN || "$PC_ANON" == UNKNOWN || "$PC_HOSTING" == UNKNOWN ]] || { ((IPQS_ENABLED)) && [[ "$IPQS_BOT" == UNKNOWN || "$IPQS_ABUSE" == UNKNOWN || "$IPQS_SCORE" == UNKNOWN || "$IPQS_PROXY" == UNKNOWN || "$IPQS_VPN" == UNKNOWN || "$IPQS_TOR" == UNKNOWN ]]; }; then
        HEALTH=PARTIAL
    fi

    SH=$(spamhaus_lookup "$IP")
    SH_LISTS=${SH%%|*}
    SH_STATUS=${SH##*|}
    [[ "$SH_STATUS" != UNKNOWN ]] || HEALTH=PARTIAL
    THREAT=NO
    if [[ "$SH_LISTS" == *SBL* || "$SH_LISTS" == *XBL* || "$SH_LISTS" == *CSS* || "$SH_LISTS" == *DROP* || "$SH_LISTS" == *BCL* ]]; then
        THREAT=YES
        ((THREAT_COUNT+=1))
    elif [[ "$SH_STATUS" == UNKNOWN ]]; then
        THREAT=UNKNOWN
    fi

    ANON=NO
    if [[ "$PC_VPN" == YES || "$PC_PROXY" == YES || "$PC_TOR" == YES || "$PC_ANON" == YES || "$IP2_PROXY" == YES || "$IPQS_PROXY" == YES || "$IPQS_VPN" == YES || "$IPQS_TOR" == YES || "$IPQS_ACTIVE_VPN" == YES || "$IPQS_ACTIVE_TOR" == YES ]]; then
        ANON=YES
    elif [[ "$PC_VPN" == UNKNOWN || "$PC_PROXY" == UNKNOWN || "$PC_TOR" == UNKNOWN || "$PC_ANON" == UNKNOWN || "$IP2_PROXY" == UNKNOWN ]] || { ((IPQS_ENABLED)) && [[ "$IPQS_PROXY" == UNKNOWN || "$IPQS_VPN" == UNKNOWN || "$IPQS_TOR" == UNKNOWN ]]; }; then
        ANON=UNKNOWN
    fi
    if [[ "$PC_VPN" == YES || "$IPQS_VPN" == YES || "$IPQS_ACTIVE_VPN" == YES ]]; then ((VPN_COUNT+=1)); fi
    if [[ "$ANON" == YES && "$PC_VPN" != YES && "$IPQS_VPN" != YES && "$IPQS_ACTIVE_VPN" != YES ]]; then ((PROXY_COUNT+=1)); fi
    [[ "$PC_HOSTING" != YES ]] || ((HOST_COUNT+=1))

    FLAGS=()
    SCORE_FLAGS=$(jq -r '."Score Review"' <<< "$META")
    if [[ -n "$SCORE_FLAGS" && "$SCORE_FLAGS" != null ]]; then
        IFS='+' read -r -a SCORE_FLAGS_ARRAY <<< "$SCORE_FLAGS"
        FLAGS+=("${SCORE_FLAGS_ARRAY[@]}")
    fi
    if [[ "$PC_VPN" == YES || "$IPQS_VPN" == YES || "$IPQS_ACTIVE_VPN" == YES ]]; then FLAGS+=(VPN); fi
    if [[ "$PC_TOR" == YES || "$IPQS_TOR" == YES || "$IPQS_ACTIVE_TOR" == YES ]]; then FLAGS+=(TOR); fi
    if [[ "$IP2_PROXY" == YES || "$PC_PROXY" == YES || "$PC_ANON" == YES || "$IPQS_PROXY" == YES ]]; then FLAGS+=(PROXY); fi
    [[ "$IPQS_ABUSE" != YES ]] || FLAGS+=(IPQS_RECENT_ABUSE)
    [[ "$IPQS_BOT" != YES ]] || FLAGS+=(IPQS_BOT)
    [[ "$PC_HOSTING" != YES ]] || FLAGS+=(HOSTING)
    [[ "$THREAT" != YES ]] || FLAGS+=(SPAMHAUS_THREAT)
    if ((${#FLAGS[@]})); then
        REVIEW=$(IFS=+; echo "${FLAGS[*]}")
    elif [[ "$ANON" == UNKNOWN || "$PC_HOSTING" == UNKNOWN || "$THREAT" == UNKNOWN || "$HEALTH" == PARTIAL ]] || { ((IPQS_ENABLED)) && [[ "$IPQS_SCORE" == UNKNOWN || "$IPQS_ABUSE" == UNKNOWN || "$IPQS_BOT" == UNKNOWN ]]; }; then
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
        --arg review "$REVIEW" --arg qsstatus "$IPQS_STATUS" --arg qsscore "$IPQS_SCORE" \
        --arg qsproxy "$IPQS_PROXY" --arg qsvpn "$IPQS_VPN" --arg qstor "$IPQS_TOR" \
        --arg qsabuse "$IPQS_ABUSE" --arg qsbot "$IPQS_BOT" --argjson meta "$META" --arg health "$HEALTH" \
        --arg qactivevpn "$IPQS_ACTIVE_VPN" --arg qactivetor "$IPQS_ACTIVE_TOR" --arg qconnection "$IPQS_CONNECTION" \
        --arg qvelocity "$IPQS_VELOCITY" --arg qcrawler "$IPQS_CRAWLER" --arg qhost "$IPQS_HOST" --arg qcountry "$IPQS_COUNTRY" \
        '[$ip,$cidr,$asn,$provider,$ip2,$anon,$vpn,$proxy,$tor,$hosting,$network,$risk,$confidence,$sh,$shstatus,$anonymisation,$hosting,$threat,$review,$qsstatus,$qsscore,$qsproxy,$qsvpn,$qstor,$qsabuse,$qsbot,$meta["IPinfo Status"],$meta["IP2Location Status"],$meta["Proxycheck Status"],$meta["IPQS Detail"],$meta["ASN Source"],$meta["Provider Source"],$health,$qactivevpn,$qactivetor,$qconnection,$qvelocity,$qcrawler,$qhost,$qcountry] + [$meta["Country Code"], $meta["Country"], $meta["Region"], $meta["City"], $meta["Timezone"], $meta["Latitude"], $meta["Longitude"], $meta["Geolocation Source"], $meta["RDAP Status"], $meta["Network Name"], $meta["Network Handle"], $meta["Network Start"], $meta["Network End"], $meta["Network Country"], $meta["Network Registered"], $meta["Network Updated"], $meta["Network Status"], $meta["RDAP Source"]] | @csv' >> "$OUTPUT" || { echo "Cannot append output: $OUTPUT" >&2; exit 1; }
    sleep 0.2
done
printf '\nTotal: %d | VPN: %d | Other proxy/anonymous: %d | Hosting: %d | Spamhaus threat: %d | Incomplete: %d\n' \
    "${#IPS[@]}" "$VPN_COUNT" "$PROXY_COUNT" "$HOST_COUNT" "$THREAT_COUNT" "$UNKNOWN_COUNT"
printf 'CSV: %s\n' "$OUTPUT"
unset IPINFO_KEY IP2_KEY PROXY_KEY SPAMHAUS_KEY IPQS_KEY
