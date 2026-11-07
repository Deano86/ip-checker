"""IPQS email reputation lookups. Only selected report fields leave the server."""
import json
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class LookupError(Exception):
    pass


def validate_email(value):
    if not isinstance(value, str):
        raise ValueError('Enter one email address.')
    value = value.strip()
    if len(value) > 254 or value.count('@') != 1:
        raise ValueError('Enter a valid email address.')
    local, domain = value.rsplit('@', 1)
    try:
        domain = domain.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Enter a valid email domain.') from None
    if not 1 <= len(local) <= 64 or local.startswith('.') or local.endswith('.') or '..' in local:
        raise ValueError('Enter a valid email address.')
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        raise ValueError('Use an ordinary email address without display names or spaces.')
    labels = domain.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise ValueError('Enter a valid email domain.')
    result = local + '@' + domain
    if len(result) > 254:
        raise ValueError('Email address is too long.')
    return result


def flag(value):
    return 'YES' if value is True else 'NO' if value is False else 'UNKNOWN'


def normalise(email, data):
    if not isinstance(data, dict) or data.get('success') is False or data.get('error'):
        raise LookupError('IPQS rejected the email lookup. Check email API access, key and available credits in your account.')
    if not any(field in data for field in ('valid', 'disposable', 'fraud_score', 'deliverability')):
        raise LookupError('IPQS returned no usable email verification fields.')
    score = data.get('fraud_score')
    score = str(score) if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 100 else 'UNKNOWN'
    report = {'Email Address': email, 'Provider': 'IPQS', 'Valid': flag(data.get('valid')),
              'Disposable': flag(data.get('disposable')), 'Fraud Score': score,
              'Recent Abuse': flag(data.get('recent_abuse')), 'Verification Timed Out': flag(data.get('timed_out'))}
    # A timed-out mailbox check must not be reported as a confirmed invalid mailbox.
    if data.get('timed_out') is True and data.get('valid') is False:
        report['Valid'] = 'UNKNOWN'
    for label, key in {'DNS Valid': 'dns_valid', 'Catch All': 'catch_all', 'Honeypot': 'honeypot',
                       'Suspect': 'suspect', 'Frequent Complainer': 'frequent_complainer', 'Leaked': 'leaked'}.items():
        report[label] = flag(data.get(key))
    for label, key in {'Deliverability': 'deliverability', 'Spam Trap Score': 'spam_trap_score',
                       'Suggested Domain': 'suggested_domain'}.items():
        value = data.get(key)
        report[label] = str(value)[:200] if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value).strip() else 'UNKNOWN'
    return report


def lookup(email, key):
    request = Request('https://www.ipqualityscore.com/api/json/email/',
                      data=json.dumps({'email': email, 'timeout': 10}).encode(),
                      headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'ipqs-key': key}, method='POST')
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read(1_000_001)
            if len(body) > 1_000_000:
                raise LookupError('IPQS returned an oversized response.')
        data = json.loads(body)
        return normalise(email, data)
    except HTTPError as error:
        messages = {401: 'IPQS authentication failed. Check IPQS_KEY in .secrets.',
                    403: 'IPQS denied email API access. Check account permissions and restrictions.',
                    429: 'IPQS email quota or rate limit reached. Check your account credits.'}
        raise LookupError(messages.get(error.code, f'IPQS email request failed (HTTP {error.code}).')) from None
    except (TimeoutError, socket.timeout):
        raise LookupError('IPQS email lookup timed out. Try again later.') from None
    except URLError:
        raise LookupError('Could not reach IPQS. Check server DNS and outbound HTTPS access.') from None
    except (ValueError, UnicodeError):
        raise LookupError('IPQS returned an unreadable email response.') from None
