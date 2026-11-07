"""Normalise provider metadata and expose safe diagnostics, never raw errors."""
import json
import re
import sys


def text(value):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    value = str(value).strip()
    return value if value.lower() not in ('', 'unknown', 'null', 'none', 'n/a', '-') else None


def status(data, provider):
    if not isinstance(data, dict):
        return 'INVALID_RESPONSE'
    code = data.get('_http_status', 200)
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


def enrich(info, lite, ip2, pc, ipqs, ip):
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
                      data.get('organization'), data.get('Organization'), data.get('ISP'), data.get('isp'))
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
    return result


if __name__ == '__main__':
    data = json.load(sys.stdin)
    print(json.dumps(enrich(**data)))
