import base64
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request
import maxmind_geo as geo
from provider_data import enrich


class MaxMindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'GeoLite2-City.mmdb'
        self.path.write_bytes(b'old database')

    def reader(self, **changes):
        reader = Mock()
        reader.__enter__ = Mock(return_value=reader)
        reader.__exit__ = Mock(return_value=False)
        reader.metadata.return_value = types.SimpleNamespace(database_type='GeoLite2-City', build_epoch=int(time.time()), **changes)
        reader.get.return_value = {'country':{'iso_code':'GB','names':{'en':'United Kingdom'}},
                                   'registered_country':{'iso_code':'US'},'city':{'names':{'en':'Example City'}},
                                   'subdivisions':[{'names':{'en':'Example Region'}}],
                                   'location':{'latitude':0,'longitude':0,'time_zone':'Europe/London','accuracy_radius':25}}
        return reader

    def test_local_lookup_preserves_zero_and_does_not_use_registered_country(self):
        reader=self.reader()
        module=types.SimpleNamespace(open_database=Mock(return_value=reader))
        with patch.dict('sys.modules',maxminddb=module), patch.object(geo,'build_opener') as network:
            report=geo.lookup('1.1.1.1',self.path)
        self.assertEqual(report['status'],'OK')
        self.assertEqual(report['country_code'],'GB')
        self.assertEqual(report['latitude'],0)
        self.assertEqual(report['accuracy_radius'],25)
        network.assert_not_called()

    def test_stale_and_wrong_database_are_not_queried(self):
        for kind,stamp,status in [('GeoLite2-ASN',int(time.time()),'WRONG_DATABASE'),('GeoLite2-City',int(time.time())-31*86400,'STALE'),('GeoLite2-City',int(time.time())+7*86400,'INVALID_DATABASE_DATE')]:
            reader=self.reader();reader.metadata.return_value=types.SimpleNamespace(database_type=kind,build_epoch=stamp)
            with patch.dict('sys.modules',maxminddb=types.SimpleNamespace(open_database=lambda path:reader)):
                self.assertEqual(geo.lookup('1.1.1.1',self.path)['status'],status)
            reader.get.assert_not_called()

    def test_missing_file_missing_library_and_no_record_are_distinct(self):
        self.assertEqual(geo.lookup('1.1.1.1',self.path.parent/'missing.mmdb')['status'],'NOT_INSTALLED')
        with patch.dict('sys.modules',maxminddb=None):
            self.assertEqual(geo.lookup('1.1.1.1',self.path)['status'],'MISSING_DEPENDENCY')
        reader=self.reader();reader.get.return_value=None
        with patch.dict('sys.modules',maxminddb=types.SimpleNamespace(open_database=lambda path:reader)):
            self.assertEqual(geo.lookup('1.1.1.1',self.path)['status'],'NO_RECORD')

    def test_corrupt_database_falls_back_with_safe_status(self):
        module=types.SimpleNamespace(open_database=Mock(side_effect=RuntimeError('private-path-sentinel')))
        with patch.dict('sys.modules',maxminddb=module):
            for result in (geo.lookup('1.1.1.1',self.path),geo.database_state(self.path)):
                self.assertEqual(result['status'],'DATABASE_ERROR')
                self.assertNotIn('private-path-sentinel',json.dumps(result))

    def test_real_reader_rejects_corrupt_database(self):
        try:
            import maxminddb
        except ImportError:
            self.skipTest('maxminddb is installed in the Docker/CI environment')
        self.assertEqual(geo.database_state(self.path)['status'],'DATABASE_ERROR')

    def test_invalid_coordinates_and_wrong_shapes_remain_absent(self):
        report=geo.normalise({'country':None,'city':[],'subdivisions':[None],'location':{'latitude':True,'longitude':200,'accuracy_radius':float('nan')}})
        self.assertIsNone(report['latitude'])
        self.assertIsNone(report['longitude'])
        self.assertIsNone(report['accuracy_radius'])
        self.assertIsNone(report['country_code'])

    def test_maxmind_bundle_is_preferred_without_changing_risk(self):
        mm={'status':'OK','database_date':'2026-01-01','country_code':'GB','city_name':'Example City','latitude':0,'longitude':0,'accuracy_radius':25}
        result=enrich({}, {}, {'is_proxy':False,'country_code':'US','city_name':'Other City'}, {}, {}, '1.1.1.1', maxmind=mm)
        self.assertEqual(result['Geolocation Source'],'MaxMind GeoLite2')
        self.assertEqual(result['City'],'Example City')
        self.assertEqual(result['Latitude'],'0')
        self.assertEqual(result['Accuracy Radius km'],'25')
        self.assertEqual(result['PC Risk'],'UNKNOWN')
        mm['status']='STALE'
        result=enrich({}, {}, {'is_proxy':False,'country_code':'US','city_name':'Other City'}, {}, {}, '1.1.1.1', maxmind=mm)
        self.assertEqual(result['Geolocation Source'],'IP2Location')
        self.assertEqual(result['MaxMind Status'],'STALE')
        self.assertEqual(result['Accuracy Radius km'],'UNKNOWN')

    def test_redirect_removes_credentials_and_blocks_other_destinations(self):
        request=Request(geo.DOWNLOAD,headers={'Authorization':'Basic private-sentinel'})
        handler=geo.DownloadRedirects()
        redirected=handler.redirect_request(request,None,302,'',{},'https://'+geo.STORAGE_HOST+'/file?signature=example')
        self.assertIsNone(redirected.get_header('Authorization'))
        for url in ('http://'+geo.STORAGE_HOST+'/file','https://evil.example/file','https://download.maxmind.com@evil.example/file'):
            with self.assertRaises(URLError):handler.redirect_request(request,None,302,'',{},url)

    def archive(self,kind=tarfile.REGTYPE):
        result=io.BytesIO()
        with tarfile.open(fileobj=result,mode='w:gz') as archive:
            member=tarfile.TarInfo('GeoLite2-City_Test/GeoLite2-City.mmdb');member.size=9;member.type=kind
            archive.addfile(member,io.BytesIO(b'new valid'))
        result.seek(0)
        return result

    def test_update_uses_header_auth_and_atomic_validated_replacement(self):
        opener=Mock();opener.open.return_value=self.archive()
        with patch.object(geo,'build_opener',return_value=opener),patch.object(geo,'database_state',return_value={'status':'OK','database_date':'2026-01-01'}):
            geo.update('123','private-sentinel',self.path)
        request=opener.open.call_args.args[0]
        self.assertNotIn('private-sentinel',request.full_url)
        self.assertEqual(request.get_header('Authorization'),'Basic '+base64.b64encode(b'123:private-sentinel').decode())
        self.assertEqual(self.path.read_bytes(),b'new valid')
        self.assertEqual(list(self.path.parent.glob('.maxmind-*')),[])

    def test_failed_validation_and_links_keep_old_database(self):
        for archive in (self.archive(),self.archive(tarfile.SYMTYPE)):
            opener=Mock();opener.open.return_value=archive
            with patch.object(geo,'build_opener',return_value=opener),patch.object(geo,'database_state',return_value={'status':'DATABASE_ERROR'}):
                with self.assertRaises(geo.UpdateError):geo.update('123','private-sentinel',self.path)
            self.assertEqual(self.path.read_bytes(),b'old database')

    def test_download_failures_never_echo_credentials_or_remove_old_data(self):
        for error in (HTTPError('https://example.test',401,'private-sentinel',{},None),URLError('private-sentinel'),TimeoutError('private-sentinel')):
            opener=Mock();opener.open.side_effect=error
            with patch.object(geo,'build_opener',return_value=opener),self.assertRaises(geo.UpdateError) as result:
                geo.update('123','private-sentinel',self.path)
            self.assertNotIn('private-sentinel',str(result.exception))
            self.assertEqual(self.path.read_bytes(),b'old database')

    def test_credentials_are_read_without_executing_shell(self):
        secrets=self.path.parent/'.secrets'; marker=self.path.parent/'not-created'
        secrets.write_text("MAXMIND_ACCOUNT_ID='123'\nMAXMIND_LICENSE_KEY='test'\ntouch "+str(marker)+'\n')
        with patch.dict('os.environ',IP_CHECKER_SECRETS=str(secrets)):
            self.assertEqual(geo.read_credentials()['MAXMIND_ACCOUNT_ID'],'123')
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
