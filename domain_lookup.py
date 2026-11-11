"""Public registration and DNS lookups, with optional Spamhaus DQS checks."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import spamhaus_domain
import tldextract
from datetime import datetime, timezone

TYPES = {'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2, 'TXT': 16, 'CNAME': 5, 'SOA': 6}
SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)


def registration_target(domain):
    """Use the bundled PSL offline; never guess a parent by removing two labels."""
    extracted = SUFFIXES(domain)
    return extracted.top_domain_under_public_suffix, extracted.suffix


def registration_query(domain):
    data, state = get_json('https://rdap.org/domain/' + domain, 'application/rdap+json')
    if state == 'OK':
        try:
            name = validate_domain(data.get('ldhName') or data.get('unicodeName'))
        except ValueError:
            name = ''
        if name != domain:
            return {}, 'INVALID_REGISTRATION_RESPONSE'
    return data, state


def validate_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Enter a domain name.')
    value = value.strip()
    if '://' in value:
        parts = urlsplit(value)
        if parts.scheme not in ('http', 'https') or parts.username or parts.password or not parts.hostname:
            raise ValueError('Enter a domain name or an HTTP(S) website URL.')
        value = parts.hostname
    value = value.rstrip('.')
    try:
        value = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Enter a valid domain name.') from None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Enter a domain name, rather than an IP address.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or not re.search('[a-z]', labels[-1]) or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in labels):
        raise ValueError('Enter a valid domain, such as example.com.')
    return value


class PublicHTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
            raise URLError('Unsupported RDAP redirect')
        addresses = socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise URLError('Non-public RDAP redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def get_json(url, accept):
    request = Request(url, headers={'Accept': accept, 'User-Agent': 'IPChecker-DomainLookup/1.0'})
    try:
        with build_opener(PublicHTTPSRedirects()).open(request, timeout=12) as response:
            body = response.read(2_000_001)
        if len(body) > 2_000_000:
            return {}, 'RESPONSE_TOO_LARGE'
        data = json.loads(body)
        if isinstance(data, dict) and isinstance(data.get('errorCode'), int):
            return {}, {404: 'NOT_FOUND_OR_UNSUPPORTED', 403: 'ACCESS_DENIED', 429: 'RATE_LIMITED'}.get(data['errorCode'], 'RDAP_ERROR')
        return (data, 'OK') if isinstance(data, dict) else ({}, 'INVALID_RESPONSE')
    except HTTPError as error:
        return {}, {404: 'NOT_FOUND_OR_UNSUPPORTED', 403: 'ACCESS_DENIED', 429: 'RATE_LIMITED'}.get(error.code, f'HTTP_{error.code}')
    except (TimeoutError, socket.timeout):
        return {}, 'TIMEOUT'
    except (URLError, OSError):
        return {}, 'NETWORK_ERROR'
    except (ValueError, UnicodeError):
        return {}, 'INVALID_RESPONSE'


def clean(value, fallback='UNKNOWN'):
    return str(value).strip()[:1000] if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip() else fallback


def entity_field(data, role, field):
    for entity in data.get('entities', []) if isinstance(data.get('entities'), list) else []:
        if not isinstance(entity, dict) or not isinstance(entity.get('roles'), list) or role not in entity['roles']:
            continue
        vcard = entity.get('vcardArray', [])
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == field:
                    value = item[3]
                    if isinstance(value, list):
                        value = ', '.join(str(part) for part in value if isinstance(part, str))
                    return clean(value, 'NOT_PUBLISHED')
    return 'NOT_PUBLISHED'


def registration(domain, data, status):
    def event(*actions):
        for item in data.get('events', []) if isinstance(data.get('events'), list) else []:
            if isinstance(item, dict) and item.get('eventAction') in actions:
                return clean(item.get('eventDate'))
        return 'UNKNOWN'
    servers = data.get('nameservers', [])
    names = [clean(item.get('ldhName') or item.get('unicodeName')) for item in servers if isinstance(item, dict)] if isinstance(servers, list) else []
    statuses = data.get('status', [])
    signed = data.get('secureDNS', {})
    signed = signed.get('delegationSigned') if isinstance(signed, dict) else None
    return {'Domain': domain, 'Registration Lookup': status,
            'Registered Domain': clean(data.get('ldhName') or data.get('unicodeName')),
            'Registrar': entity_field(data, 'registrar', 'fn'),
            'Registry Handle': clean(data.get('handle')),
            'Created': event('registration'), 'Expires': event('expiration', 'registrar expiration'),
            'Updated': event('last changed', 'last update of RDAP database'),
            'Domain Status': ', '.join(clean(value) for value in statuses) if isinstance(statuses, list) and statuses else 'UNKNOWN',
            'Nameservers': ', '.join(names) if names else 'UNKNOWN',
            'DNSSEC Delegation Signed': 'YES' if signed is True else 'NO' if signed is False else 'UNKNOWN',
            'Registrant Organisation': entity_field(data, 'registrant', 'org'),
            'WHOIS Server': clean(data.get('port43'))}


def dns_query(domain, record_type):
    data, state = get_json('https://cloudflare-dns.com/dns-query?' + urlencode({'name': domain, 'type': record_type}), 'application/dns-json')
    if state != 'OK':
        return {'type': record_type, 'status': state, 'records': []}
    code = data.get('Status')
    if code != 0:
        return {'type': record_type, 'status': {3: 'NXDOMAIN', 2: 'SERVFAIL', 5: 'REFUSED'}.get(code, 'DNS_ERROR'), 'records': []}
    records = []
    for answer in data.get('Answer', []) if isinstance(data.get('Answer'), list) else []:
        if not isinstance(answer, dict):
            continue
        records.append({'Name': clean(answer.get('name')), 'Type': next((name for name, number in TYPES.items() if number == answer.get('type')), str(answer.get('type', 'UNKNOWN'))),
                        'Value': clean(answer.get('data')), 'TTL': clean(answer.get('TTL'))})
    return {'type': record_type, 'status': 'OK' if records else 'NO_RECORDS', 'records': records}


def lookup(domain, spamhaus_key=None):
    registered, suffix = registration_target(domain)
    target = registered or domain
    with ThreadPoolExecutor(max_workers=10) as pool:
        rdap = pool.submit(registration_query, target) if registered or not suffix else None
        dns_futures = [pool.submit(dns_query, domain, record_type) for record_type in TYPES]
        spamhaus_futures = [pool.submit(spamhaus_domain.lookup, domain, spamhaus_key, zone) for zone in ('dbl', 'zrd')]
        data, state = rdap.result() if rdap else ({}, 'PUBLIC_SUFFIX_ONLY')
        queries = [future.result() for future in dns_futures]
        reputation = [future.result() for future in spamhaus_futures]
    report = registration(domain, data, state)
    report.update({'RDAP Query Domain': target if rdap else 'NOT_APPLICABLE',
                   'Public Suffix': suffix or 'UNKNOWN',
                   'Registration Scope': 'Registered parent domain' if registered and target != domain else 'Submitted domain',
                   'Checked At': datetime.now(timezone.utc).isoformat()})
    records, seen = [], set()
    for query in queries:
        for record in query['records']:
            key = (record['Name'], record['Type'], record['Value'])
            if key not in seen:
                seen.add(key)
                records.append(record)
    healthy = state == 'OK' and all(query['status'] in ('OK', 'NO_RECORDS') for query in queries)
    healthy = healthy and all(check['status'] == 'OK' for check in reputation)
    notes = []
    if target != domain:
        notes.append('Registration describes '+target+'; DNS and Spamhaus checks describe '+domain+'.')
    if state != 'OK':
        notes.append('Registration lookup: '+state+'. This is missing registration data, not a threat detection or an availability verdict.')
    for query in queries:
        if query['status'] not in ('OK', 'NO_RECORDS'):
            notes.append('DNS '+query['type']+': '+query['status']+'.')
    for check in reputation:
        if check['status'] != 'OK':
            notes.append('Spamhaus '+check['list']+': '+check['status']+'. No reputation verdict is available from this check.')
    return {'report': report, 'records': records,
            'queries': [{'type': query['type'], 'status': query['status']} for query in queries],
            'health': 'OK' if healthy else 'PARTIAL', 'reputation': reputation, 'notes': notes}
