"""IPQS reputation and Kickbox verification. Only selected report fields leave the server."""
import json
import re
import socket
import math
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.parse import urlencode


class LookupError(Exception):
    pass


def selected_providers(selection, keys):
    choices = {'ipqs': ['IPQS'], 'kickbox': ['Kickbox'], 'both': ['IPQS', 'Kickbox']}
    if selection == 'configured':
        names = [name for name in ('IPQS', 'Kickbox') if keys.get('IPQS_KEY' if name == 'IPQS' else 'KICKBOX_KEY')]
    elif isinstance(selection, str) and selection in choices:
        names = choices[selection]
    else:
        raise ValueError('Choose configured providers, IPQS, Kickbox or both.')
    if not names:
        raise LookupError('Add IPQS_KEY or KICKBOX_KEY to the server .secrets file to enable email lookups.')
    for name in names:
        key_name = 'IPQS_KEY' if name == 'IPQS' else 'KICKBOX_KEY'
        if not keys.get(key_name):
            raise LookupError('Add '+key_name+' to the server .secrets file for the selected provider.')
    return names


def normalise_kickbox(email, data):
    if not isinstance(data, dict) or data.get('success') is not True:
        raise LookupError('Kickbox rejected the lookup. Check API access, key and available credits.')
    result = data.get('result')
    if not isinstance(result, str) or result not in ('deliverable', 'undeliverable', 'risky', 'unknown'):
        raise LookupError('Kickbox returned an invalid verification result.')
    reasons = {'invalid_email', 'invalid_domain', 'rejected_email', 'accepted_email', 'low_quality',
               'low_deliverability', 'no_connect', 'timeout', 'invalid_smtp', 'unavailable_smtp', 'unexpected_error', 'accept_all', 'disposable'}
    reason = data.get('reason') if isinstance(data.get('reason'), str) and data['reason'] in reasons else 'UNKNOWN'
    score = data.get('sendex')
    score = str(score) if type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1 else 'UNKNOWN'
    suggestion = data.get('did_you_mean')
    try:
        suggestion = validate_email(suggestion) if suggestion else 'NONE'
    except ValueError:
        suggestion = 'UNKNOWN'
    report = {'Kickbox Status': 'OK', 'Kickbox Result': result, 'Kickbox Reason': reason,
              'Kickbox Sendex': score, 'Kickbox Disposable': flag(data.get('disposable')),
              'Kickbox Accept All': flag(data.get('accept_all')), 'Kickbox Role': flag(data.get('role')),
              'Kickbox Free': flag(data.get('free')), 'Kickbox Suggested Email': suggestion}
    partial = result == 'unknown' or reason == 'UNKNOWN' or score == 'UNKNOWN' or any(report[k] == 'UNKNOWN' for k in ('Kickbox Disposable', 'Kickbox Accept All', 'Kickbox Role', 'Kickbox Free'))
    report['Kickbox Lookup Health'] = 'PARTIAL' if partial else 'OK'
    report['Kickbox Notes'] = 'Sendex is email quality from 0 to 1; higher is better. It is not a fraud score or delivery probability.'
    if data.get('accept_all') is True:
        report['Kickbox Notes'] += ' Accept-all server: an individual mailbox cannot be confirmed.'
    if result == 'unknown':
        report['Kickbox Notes'] += ' Verification was inconclusive; do not treat this as an invalid mailbox.'
    return report


class NoKickboxRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise URLError('Redirect refused')


def lookup_kickbox(email, key):
    # Match Kickbox's official SDK header authentication; never put keys in URLs.
    request = Request('https://api.kickbox.com/v2/verify?' + urlencode({'email': email, 'timeout': 10000}),
                      headers={'Accept': 'application/json', 'Authorization': 'token '+key, 'User-Agent': 'IPChecker-EmailLookup/1.0'})
    try:
        with build_opener(NoKickboxRedirects()).open(request, timeout=15) as response:
            body = response.read(1_000_001)
        if len(body) > 1_000_000:
            raise LookupError('Kickbox returned an oversized response.')
        return normalise_kickbox(email, json.loads(body))
    except HTTPError as error:
        messages = {401: 'Kickbox authentication failed. Check KICKBOX_KEY in .secrets.',
                    403: 'Kickbox denied access. Check API permissions and credits.',
                    429: 'Kickbox quota or rate limit reached. Check credits and try later.'}
        raise LookupError(messages.get(error.code, 'Kickbox request failed (HTTP '+str(error.code)+').')) from None
    except (TimeoutError, socket.timeout):
        raise LookupError('Kickbox lookup timed out. Try again later.') from None
    except (URLError, OSError):
        raise LookupError('Could not reach Kickbox. Check server DNS and outbound HTTPS access.') from None
    except (ValueError, UnicodeError):
        raise LookupError('Kickbox returned an unreadable response.') from None


def lookup_selected(email, keys, names):
    report = {'Email Address': email, 'Provider': ' + '.join(names)}
    errors = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {name: pool.submit(lookup if name == 'IPQS' else lookup_kickbox, email,
                                    keys['IPQS_KEY' if name == 'IPQS' else 'KICKBOX_KEY']) for name in names}
        for name, future in futures.items():
            try:
                fields = future.result()
                report.update(fields)
                report[name+' Status'] = 'OK'
            except LookupError as error:
                report[name+' Status'] = 'ERROR'
                report[name+' Error'] = str(error)
                errors.append(str(error))
    if len(errors) == len(names):
        raise LookupError(' '.join(errors))
    report['Provider'] = ' + '.join(names)
    partial = bool(errors) or report.get('Lookup Health') == 'PARTIAL' or report.get('Kickbox Lookup Health') == 'PARTIAL'
    report['Lookup Health'] = 'PARTIAL' if partial else 'OK'
    notes = [report.get('Lookup Notes', ''), report.get('Kickbox Notes', ''), *errors]
    report['Lookup Notes'] = ' '.join(note for note in notes if note)
    report['Checked At'] = datetime.now(timezone.utc).isoformat()
    return report


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
    if not isinstance(data, dict) or data.get('success') is not True or data.get('error'):
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
    if report['Deliverability'].lower() not in ('high', 'medium', 'low'):
        report['Deliverability'] = 'UNKNOWN'
    missing = [key for key in ('Valid', 'Disposable', 'Fraud Score', 'Deliverability') if report[key] == 'UNKNOWN']
    report['Lookup Health'] = 'PARTIAL' if missing or data.get('timed_out') is True else 'OK'
    report['Lookup Notes'] = ('Unavailable fields: '+', '.join(missing)+'. ' if missing else '') + ('Mailbox verification timed out. ' if data.get('timed_out') is True else '')
    report['Lookup Notes'] = report['Lookup Notes'].strip() or 'Core email checks returned usable data.'
    if report['Catch All'] == 'YES':
        report['Lookup Notes'] += ' Catch-all server: an individual mailbox cannot be confirmed.'
    findings = []
    for key, label in [('Disposable','Disposable email indicator'),('Recent Abuse','Recent abuse reported'),('Honeypot','Honeypot indicator'),('Frequent Complainer','Frequent complainer indicator')]:
        if report[key] == 'YES':
            findings.append(label)
    if report['Valid'] == 'NO':
        findings.append('Provider reports an invalid email')
    if score != 'UNKNOWN' and float(score) >= 75:
        findings.append('High IPQS email fraud score' if float(score) >= 90 else 'Elevated IPQS email fraud score')
    if report['Spam Trap Score'].lower() in ('medium', 'high'):
        findings.append(report['Spam Trap Score'].title()+' spam-trap indicator')
    report['Review'] = '; '.join(findings) if findings else 'No positive email-risk indicators among returned fields'
    report['Score Source'] = 'IPQS email fraud model (0–100); not a delivery probability'
    report['Checked At'] = datetime.now(timezone.utc).isoformat()
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
