"""Optional local GeoLite2 City lookups and explicit, atomic database updates."""
import base64
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / 'data' / 'GeoLite2-City.mmdb'
MAX_AGE = 30 * 86400
DOWNLOAD = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz'
STORAGE_HOST = 'mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com'


class UpdateError(Exception):
    pass


def metadata(reader):
    info = reader.metadata()
    if info.database_type != 'GeoLite2-City':
        return {'status': 'WRONG_DATABASE', 'database_date': 'UNKNOWN'}
    stamp = info.build_epoch
    if type(stamp) is not int or stamp <= 0 or stamp > time.time() + 86400:
        return {'status': 'INVALID_DATABASE_DATE', 'database_date': 'UNKNOWN'}
    return {'status': 'STALE' if time.time() - stamp > MAX_AGE else 'OK',
            'database_date': datetime.fromtimestamp(stamp, timezone.utc).date().isoformat()}


def database_state(path=None):
    path = Path(path or DATABASE)
    try:
        if not path.exists():
            return {'status': 'NOT_INSTALLED', 'database_date': 'UNKNOWN'}
    except OSError:
        return {'status': 'DATABASE_ERROR', 'database_date': 'UNKNOWN'}
    try:
        import maxminddb
    except ImportError:
        return {'status': 'MISSING_DEPENDENCY', 'database_date': 'UNKNOWN'}
    try:
        with maxminddb.open_database(str(path)) as reader:
            return metadata(reader)
    except (OSError, ValueError, RuntimeError, OverflowError):
        return {'status': 'DATABASE_ERROR', 'database_date': 'UNKNOWN'}


def clean(value):
    return value.strip()[:200] if isinstance(value, str) and value.strip() else None


def finite(value, minimum, maximum):
    return value if type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum else None


def normalise(record):
    def section(name):
        return record.get(name) if isinstance(record.get(name), dict) else {}
    def name(item):
        names = item.get('names')
        return clean(names.get('en')) if isinstance(names, dict) else None
    country, city, location = section('country'), section('city'), section('location')
    subdivisions = record.get('subdivisions')
    region = next((item for item in reversed(subdivisions) if isinstance(item, dict)), {}) if isinstance(subdivisions, list) else {}
    return {'country_code': clean(country.get('iso_code')), 'country_name': name(country),
            'region_name': name(region), 'city_name': name(city), 'time_zone': clean(location.get('time_zone')),
            'latitude': finite(location.get('latitude'), -90, 90), 'longitude': finite(location.get('longitude'), -180, 180),
            'accuracy_radius': finite(location.get('accuracy_radius'), 0, 10000)}


def lookup(ip, path=None):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'status': 'INVALID_IP', 'database_date': 'UNKNOWN'}
    path = Path(path or DATABASE)
    try:
        if not path.exists():
            return {'status': 'NOT_INSTALLED', 'database_date': 'UNKNOWN'}
    except OSError:
        return {'status': 'DATABASE_ERROR', 'database_date': 'UNKNOWN'}
    try:
        import maxminddb
    except ImportError:
        return {'status': 'MISSING_DEPENDENCY', 'database_date': 'UNKNOWN'}
    try:
        with maxminddb.open_database(str(path)) as reader:
            state = metadata(reader)
            if state['status'] != 'OK':
                return state
            record = reader.get(ip)
        if not isinstance(record, dict):
            return {**state, 'status': 'NO_RECORD'}
        result = normalise(record)
        if not any(result.get(key) is not None for key in ('country_code', 'country_name', 'city_name', 'latitude', 'longitude')):
            return {**state, 'status': 'NO_LOCATION'}
        return {**state, **result}
    except (OSError, ValueError, RuntimeError, OverflowError):
        return {'status': 'DATABASE_ERROR', 'database_date': 'UNKNOWN'}


class DownloadRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        if parts.scheme != 'https' or parts.hostname not in ('download.maxmind.com', STORAGE_HOST) or parts.username or parts.password or parts.port not in (None, 443):
            raise URLError('Unsupported database redirect')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and parts.hostname != 'download.maxmind.com':
            redirected.remove_header('Authorization')
        return redirected


def read_credentials():
    path = Path(os.environ.get('IP_CHECKER_SECRETS', str(ROOT / '.secrets')))
    result = {}
    try:
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            match = re.match(r'^\s*(?:export\s+)?(MAXMIND_ACCOUNT_ID|MAXMIND_LICENSE_KEY)=(.*)$', line)
            if match:
                result[match[1]] = ' '.join(shlex.split(match[2], comments=True))
    except (OSError, UnicodeError, ValueError):
        raise UpdateError('Could not read MaxMind credentials from .secrets.') from None
    return result


def update(account_id, license_key, path=None):
    if not isinstance(account_id, str) or not re.fullmatch(r'\d+', account_id) or not isinstance(license_key, str) or not license_key.strip():
        raise UpdateError('Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .secrets.')
    path = Path(path or DATABASE)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        auth = base64.b64encode((account_id + ':' + license_key).encode()).decode()
        request = Request(DOWNLOAD, headers={'Authorization': 'Basic ' + auth, 'User-Agent': 'IPChecker-GeoLite2/1.0'})
        with tempfile.TemporaryDirectory(prefix='.maxmind-', dir=path.parent) as directory:
            archive_path, candidate = Path(directory) / 'city.tar.gz', Path(directory) / 'city.mmdb'
            with build_opener(DownloadRedirects()).open(request, timeout=120) as response, archive_path.open('wb') as archive:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise UpdateError('MaxMind download exceeds the supported size.')
                    archive.write(chunk)
            # Never extract paths or links supplied by an archive.
            with tarfile.open(archive_path, 'r:gz') as archive:
                count = 0
                for member in archive:
                    count += 1
                    if count > 100:
                        raise UpdateError('MaxMind archive has too many entries.')
                    if Path(member.name).name != 'GeoLite2-City.mmdb':
                        continue
                    if not member.isfile() or member.size > 512 * 1024 * 1024 or member.size <= 0:
                        raise UpdateError('Invalid MaxMind database archive.')
                    with archive.extractfile(member) as source, candidate.open('wb') as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                    break
            if not candidate.exists() or database_state(candidate)['status'] != 'OK':
                raise UpdateError('Downloaded GeoLite2 City database failed validation; existing data was kept.')
            candidate.chmod(0o600)
            os.replace(candidate, path)
        return database_state(path)
    except HTTPError as error:
        message = {401: 'MaxMind authentication failed.', 403: 'MaxMind denied database access.', 429: 'MaxMind download limit reached.'}.get(error.code, 'MaxMind download failed.')
        raise UpdateError(message + ' Check account access and credentials; existing data was kept.') from None
    except (OSError, ValueError, tarfile.TarError, URLError):
        raise UpdateError('MaxMind update failed. Check network, file permissions and archive format; existing data was kept.') from None


if __name__ == '__main__':
    if sys.argv[1:] == ['status']:
        print(json.dumps(database_state()))
    elif sys.argv[1:] == ['update']:
        try:
            values = read_credentials()
            result = update(values.get('MAXMIND_ACCOUNT_ID'), values.get('MAXMIND_LICENSE_KEY'))
            print('GeoLite2 City updated: ' + result['database_date'])
        except UpdateError as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
    else:
        sys.exit('Usage: python3 maxmind_geo.py update|status')
