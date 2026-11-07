"""Spamhaus domain DNS checks; never expose the keyed DNS query or raw output."""
import re
import subprocess

DBL = {2: 'Low-reputation domain', 4: 'Phishing-related domain', 5: 'Malware-related domain',
       6: 'Botnet command-and-control domain', 102: 'Abused legitimate domain',
       103: 'Abused redirector', 104: 'Abused domain used in phishing',
       105: 'Abused domain used by malware', 106: 'Abused domain hosting command-and-control'}
ERRORS = {'127.255.255.250': 'KEY_DISABLED', '127.255.255.251': 'KEY_OR_ACCESS_ERROR',
          '127.255.255.252': 'INVALID_ZONE', '127.255.255.254': 'RESOLVER_OR_ACCESS_BLOCKED'}


def result(zone, status, listed='UNKNOWN', labels=None, codes=None):
    return {'list': zone.upper(), 'status': status, 'listed': listed,
            'categories': labels or [], 'codes': codes or []}


def parse_dns(zone, output):
    match = re.search(r'\bstatus:\s*([A-Z]+)', output)
    status = match[1] if match else 'UNKNOWN'
    codes = sorted(set(re.findall(r'^\S+\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$', output, re.M)))
    if status == 'NXDOMAIN':
        return result(zone, 'OK', 'NO') if not codes else result(zone, 'INVALID_RESPONSE')
    if status != 'NOERROR':
        return result(zone, status if status in ('SERVFAIL', 'REFUSED', 'FORMERR') else 'DNS_ERROR')
    if not codes:
        return result(zone, 'EMPTY_RESPONSE')
    # Any error or unexpected reply invalidates a purported negative/listing.
    for code in codes:
        if code.startswith('127.255.255.'):
            return result(zone, ERRORS.get(code, 'DQS_QUERY_ERROR'), codes=[code])
        if code in ('127.0.1.255', '127.0.2.255'):
            return result(zone, 'UNSUPPORTED_QUERY', codes=[code])
    labels = []
    for code in codes:
        parts = list(map(int, code.split('.')))
        if len(parts) != 4 or any(part > 255 for part in parts):
            return result(zone, 'INVALID_RESPONSE')
        if zone == 'dbl' and parts[:3] == [127, 0, 1] and (2 <= parts[3] <= 99 or 102 <= parts[3] <= 199):
            labels.append(DBL.get(parts[3], 'Abused legitimate domain' if parts[3] >= 102 else 'Low-reputation domain (uncategorised)'))
        elif zone == 'zrd' and parts[:3] == [127, 0, 2] and 2 <= parts[3] <= 24:
            age = '0–2' if parts[3] == 2 else f'{parts[3]-1}–{parts[3]}'
            labels.append(f'First observed {age} hours ago')
        else:
            return result(zone, 'INVALID_RESPONSE')
    return result(zone, 'OK', 'YES', list(dict.fromkeys(labels)), codes)


def lookup(domain, key, zone='dbl'):
    if zone not in ('dbl', 'zrd'):
        return result(zone, 'INVALID_ZONE')
    if not key:
        return result(zone, 'NOT_CONFIGURED')
    if not re.fullmatch(r'[A-Za-z0-9-]{1,63}', key):
        return result(zone, 'INVALID_KEY_FORMAT')
    query = f'{domain}.{key}.{zone}.dq.spamhaus.net'
    if len(query) > 253:
        return result(zone, 'QUERY_NAME_TOO_LONG')
    try:
        response = subprocess.run(['dig', '+time=3', '+tries=1', '+noall', '+comments', '+answer', query, 'A'],
                                  capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        return result(zone, 'DEPENDENCY_MISSING')
    except subprocess.TimeoutExpired:
        return result(zone, 'TIMEOUT')
    except OSError:
        return result(zone, 'DNS_ERROR')
    if response.returncode:
        return result(zone, 'DNS_ERROR')
    return parse_dns(zone, response.stdout)
