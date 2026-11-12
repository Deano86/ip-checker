"""Normalise provider metadata and expose safe diagnostics, never raw errors."""
import json
import re
import sys
import csv
import ipaddress
import math
import maxmind_geo

LEGACY_COLUMNS = ['IP Address','CIDR','ASN','Provider','IP2 Proxy','PC Anonymous','PC VPN','PC Proxy','PC Tor','PC Hosting','PC Network Type','PC Risk','PC Confidence','Spamhaus Lists','Spamhaus Status','Anonymisation','Hosting','Threat Listing','Review','IPQS Status','IPQS Fraud Score','IPQS Proxy','IPQS VPN','IPQS Tor','IPQS Recent Abuse','IPQS Bot','IPinfo Status','IP2Location Status','Proxycheck Status','IPQS Detail','ASN Source','Provider Source','Lookup Health','IPQS Active VPN','IPQS Active Tor','IPQS Connection Type','IPQS Abuse Frequency','IPQS Verified Crawler','IPQS Hostname','IPQS Country']
EXTRA_COLUMNS = ['Country Code','Country','Region','City','Timezone','Latitude','Longitude','Geolocation Source','RDAP Status','Network Name','Network Handle','Network Start','Network End','Network Country','Network Registered','Network Updated','Network Status','RDAP Source']
LEGACY_REPORT_COLUMNS = LEGACY_COLUMNS + EXTRA_COLUMNS
MAXMIND_COLUMNS = ['MaxMind Status', 'MaxMind Database Date', 'Accuracy Radius km']
REPORT_COLUMNS = LEGACY_REPORT_COLUMNS + MAXMIND_COLUMNS


def text(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    value = str(value).strip()
    return value if value.lower() not in ('', 'unknown', 'null', 'none', 'n/a', '-') else None


def status(data, provider):
    if not isinstance(data, dict):
        return 'INVALID_RESPONSE'
    code = data.get('_http_status', 200)
    if type(code) is not int:
        return 'INVALID_RESPONSE'
    if code == 401:
        return 'AUTH_ERROR'
    if code == 403:
        return 'ACCESS_DENIED'
    if code == 429:
        return 'RATE_LIMIT_OR_QUOTA'
    if code >= 400:
        return f'HTTP_{int(code)}'
    if data.get('_lookup_error'):
        return data['_lookup_error'] if data['_lookup_error'] in ('TIMEOUT', 'NETWORK_ERROR', 'INVALID_JSON', 'INVALID_RESPONSE') else 'REQUEST_ERROR'
    error = data.get('error')
    if provider == 'IP2Location' and isinstance(error, dict):
        codes = {10000: 'AUTH_OR_QUOTA_ERROR', 10001: 'INVALID_IP',
                 10002: 'PROVIDER_ERROR', 10003: 'INVALID_LANGUAGE', 10004: 'PLAN_RESTRICTED'}
        return codes.get(error.get('error_code'), 'PROVIDER_ERROR')
    failed = bool(error) or (provider == 'IPQS' and data.get('success') is not True)
    failed |= provider == 'Proxycheck' and data.get('status') not in ('ok', 'warning')
    if failed:
        # Classify internally; do not expose messages which can echo API keys.
        message = str(error or data.get('message') or data.get('status') or '').lower()
        if any(word in message for word in ('quota', 'credit', 'limit', 'exhaust')):
            return 'RATE_LIMIT_OR_QUOTA'
        if any(word in message for word in ('key', 'token', 'auth')):
            return 'AUTH_ERROR'
        return 'PROVIDER_ERROR'
    if provider == 'IPinfo' and not any(text(data.get(key)) for key in ('org', 'asn', 'as_name')):
        return 'MISSING_NETWORK_FIELDS'
    return 'OK'


def number(value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 'UNKNOWN'
    try:
        result = float(value)
        return str(value).strip() if math.isfinite(result) and minimum <= result <= maximum else 'UNKNOWN'
    except ValueError:
        return 'UNKNOWN'


def geolocation(info, ip2, ipqs, maxmind=None):
    # Keep the location bundle from one source; do not combine one provider's
    # city with another provider's coordinates.
    result = {key: 'UNKNOWN' for key in EXTRA_COLUMNS[:8]}
    for data, name, fields in (
        (maxmind if isinstance(maxmind, dict) and maxmind.get('status') == 'OK' else None, 'MaxMind GeoLite2', ('country_code','country_name','region_name','city_name','time_zone','latitude','longitude')),
        (ip2, 'IP2Location', ('country_code','country_name','region_name','city_name','time_zone','latitude','longitude')),
        (info, 'IPinfo', ('country',None,'region','city','timezone',None,None)),
        (ipqs, 'IPQS', ('country_code',None,'region','city','timezone','latitude','longitude')),
    ):
        if not isinstance(data, dict) or status(data, name) not in (('OK', 'MISSING_NETWORK_FIELDS') if name == 'IPinfo' else ('OK',)):
            continue
        if not any(text(data.get(key)) for key in fields[:4] if key):
            continue
        for label, key in zip(EXTRA_COLUMNS[:7], fields):
            value = data.get(key) if key else None
            result[label] = number(value, -90 if label == 'Latitude' else -180, 90 if label == 'Latitude' else 180) if label in ('Latitude','Longitude') else text(value) or 'UNKNOWN'
        if name == 'IPinfo' and isinstance(data.get('loc'), str):
            coords = data['loc'].split(',')
            if len(coords) == 2:
                result['Latitude'] = number(coords[0], -90, 90)
                result['Longitude'] = number(coords[1], -180, 180)
        result['Geolocation Source'] = name
        return result
    return result


def rdap_fields(data, ip):
    result = {key: 'UNKNOWN' for key in EXTRA_COLUMNS[8:]}
    result['CIDR'] = 'UNKNOWN'
    if not isinstance(data, dict) or data.get('errorCode') or status(data, 'RDAP') != 'OK':
        result['RDAP Status'] = 'UNAVAILABLE'
        return result
    try:
        address = ipaddress.ip_address(ip)
        matches = []
        for item in data.get('cidr0_cidrs', []) if isinstance(data.get('cidr0_cidrs'), list) else []:
            if not isinstance(item, dict) or 'v4prefix' not in item or type(item.get('length')) is not int:
                continue
            try:
                net = ipaddress.ip_network(str(item['v4prefix'])+'/'+str(item['length']), strict=False)
                if address in net:
                    matches.append(net)
            except (ValueError, TypeError):
                continue
        start = end = None
        if data.get('startAddress') or data.get('endAddress'):
            start = ipaddress.ip_address(data.get('startAddress'))
            end = ipaddress.ip_address(data.get('endAddress'))
            if not start <= address <= end:
                raise ValueError()
            matches = [net for net in matches if start <= net.network_address and net.broadcast_address <= end]
            if not matches:
                matches = [net for net in ipaddress.summarize_address_range(start, end) if address in net]
        if not matches:
            raise ValueError()
        result['CIDR'] = str(max(matches, key=lambda net: net.prefixlen))
        result['Network Start'] = str(start) if start else 'UNKNOWN'
        result['Network End'] = str(end) if end else 'UNKNOWN'
    except (ValueError, TypeError):
        result['RDAP Status'] = 'INVALID_NETWORK_RESPONSE'
        return result
    for label, key in [('Network Name','name'),('Network Handle','handle'),('Network Country','country')]:
        result[label] = text(data.get(key)) or 'UNKNOWN'
    events = data.get('events', [])
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict):
            label = {'registration':'Network Registered','last changed':'Network Updated','last update of RDAP database':'Network Updated'}.get(event.get('eventAction'))
            if label and result[label] == 'UNKNOWN':
                result[label] = text(event.get('eventDate')) or 'UNKNOWN'
    states = data.get('status')
    result['Network Status'] = ', '.join(value for value in states if isinstance(value, str)) if isinstance(states, list) and states else 'UNKNOWN'
    result['RDAP Status'] = 'OK'
    result['RDAP Source'] = text(data.get('_rdap_source')) or 'RDAP registry'
    return result


def enrich(info, lite, ip2, pc, ipqs, ip, rdap=None, maxmind=None):
    sources = [(info, 'IPinfo'), (lite, 'IPinfo Lite'), (ip2, 'IP2Location')]
    entry = pc.get(ip, {}) if isinstance(pc, dict) else {}
    network = entry.get('network', {}) if isinstance(entry, dict) else {}
    if not isinstance(network, dict):
        network = {}
    sources += [(network, 'Proxycheck'), (ipqs, 'IPQS')]
    asn = provider = 'UNKNOWN'
    asn_source = provider_source = 'UNKNOWN'
    for data, name in sources:
        if not isinstance(data, dict):
            continue
        check_data = pc if name == 'Proxycheck' else data
        if status(check_data, 'IPinfo' if name == 'IPinfo Lite' else name) != 'OK':
            continue
        org = text(data.get('org'))
        org_match = re.match(r'^(AS\d+)\s+(.+)$', org or '')
        candidate_asn = data.get('asn') or data.get('ASN')
        if isinstance(candidate_asn, dict):
            candidate_asn = candidate_asn.get('asn')
        as_info = data.get('as_info') if isinstance(data.get('as_info'), dict) else {}
        candidate_asn = text(candidate_asn) or text(as_info.get('as_number')) or (org_match[1] if org_match else None)
        if candidate_asn and re.fullmatch(r'(?:AS)?\d+', candidate_asn, re.I):
            candidate_asn = 'AS' + re.sub(r'^AS', '', candidate_asn, flags=re.I)
            if asn == 'UNKNOWN':
                asn, asn_source = candidate_asn, name
        candidates = (data.get('as_name'), as_info.get('as_name'), data.get('as'),
                      org_match[2] if org_match else None, data.get('organisation'),
                      data.get('organization'), data.get('Organization'), data.get('ISP'), data.get('isp'), data.get('provider'))
        candidate_provider = next((text(value) for value in candidates if text(value)), None)
        if provider == 'UNKNOWN' and candidate_provider:
            provider, provider_source = candidate_provider, name
    result = {'ASN': asn, 'Provider': provider, 'ASN Source': asn_source, 'Provider Source': provider_source}
    info_status = status(info, 'IPinfo')
    if lite:
        info_status = f'Legacy: {info_status}; Lite: {status(lite, "IPinfo")}'
    elif info_status == 'OK' and (asn_source != 'IPinfo' or provider_source != 'IPinfo'):
        info_status = 'MISSING_NETWORK_FIELDS'
    ip2_status = status(ip2, 'IP2Location')
    if ip2_status == 'OK' and not isinstance(ip2.get('is_proxy'), (bool, int, str)):
        ip2_status = 'MISSING_PROXY_FIELD'
    result.update({'IPinfo Status': info_status, 'IP2Location Status': ip2_status,
                   'Proxycheck Status': status(pc, 'Proxycheck'),
                   'IPQS Detail': status(ipqs, 'IPQS') if ipqs else 'NOT_CONFIGURED'})
    missing = any(value in ('UNKNOWN', 'MISSING_NETWORK_FIELDS', 'MISSING_PROXY_FIELD') for value in result.values())
    failed = any(status(data, name) != 'OK' for data, name in ((info, 'IPinfo'), (ip2, 'IP2Location'), (pc, 'Proxycheck')))
    if lite and status(lite, 'IPinfo') == 'OK':
        failed = any(status(data, name) != 'OK' for data, name in ((ip2, 'IP2Location'), (pc, 'Proxycheck')))
    failed |= bool(ipqs) and status(ipqs, 'IPQS') != 'OK'
    result['Lookup Health'] = 'PARTIAL' if failed or missing else 'OK'
    detections = entry.get('detections', {}) if isinstance(entry, dict) else {}
    detections = detections if isinstance(detections, dict) else {}
    pc_ok = status(pc, 'Proxycheck') == 'OK'
    result['PC Risk'] = number(detections.get('risk', entry.get('risk')), 0, 100) if pc_ok else 'UNKNOWN'
    result['PC Confidence'] = number(detections.get('confidence'), 0, 100) if pc_ok else 'UNKNOWN'
    review = []
    qs_score = number(ipqs.get('fraud_score'), 0, 100) if isinstance(ipqs, dict) and type(ipqs.get('fraud_score')) in (int, float) and status(ipqs, 'IPQS') == 'OK' else 'UNKNOWN'
    if qs_score != 'UNKNOWN' and float(qs_score) >= 75:
        review.append('IPQS_HIGH_RISK' if float(qs_score) >= 90 else 'IPQS_ELEVATED_RISK')
    if result['PC Risk'] != 'UNKNOWN' and float(result['PC Risk']) > 25:
        review.append('PC_HIGH_RISK' if float(result['PC Risk']) > 75 else 'PC_ELEVATED_RISK')
    result['Score Review'] = '+'.join(review)
    result.update(geolocation(info, ip2, ipqs, maxmind))
    maxmind = maxmind if isinstance(maxmind, dict) else {}
    result['MaxMind Status'] = maxmind.get('status', 'NOT_INSTALLED')
    result['MaxMind Database Date'] = maxmind.get('database_date', 'UNKNOWN')
    result['Accuracy Radius km'] = number(maxmind.get('accuracy_radius'), 0, 10000) if result['Geolocation Source'] == 'MaxMind GeoLite2' else 'UNKNOWN'
    if rdap is not None:
        result.update(rdap_fields(rdap, ip))
        if result['RDAP Status'] != 'OK':
            result['Lookup Health'] = 'PARTIAL'
    return result


if __name__ == '__main__':
    if sys.argv[1:] == ['--csv-header']:
        csv.writer(sys.stdout, lineterminator='\n').writerow(REPORT_COLUMNS)
    elif len(sys.argv) == 3 and sys.argv[1] == '--rdap-cidr':
        try:
            print(rdap_fields(json.load(sys.stdin), sys.argv[2])['CIDR'])
        except (ValueError, TypeError):
            print('UNKNOWN')
    else:
        data = json.load(sys.stdin)
        data['maxmind'] = maxmind_geo.lookup(data['ip'])
        print(json.dumps(enrich(**data)))
