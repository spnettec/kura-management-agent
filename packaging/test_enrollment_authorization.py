"""Root filesystem/command fixtures, not a native systemd or business enrollment."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PACKAGING = Path(__file__).resolve().parent
setup = module('reader_authorization_setup', PACKAGING / 'setup.py')
build = module('reader_authorization_build', PACKAGING / 'build.py')


@unittest.skipUnless(os.geteuid() == 0, 'requires an isolated Root filesystem fixture')
class EnrollmentAuthorizationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.setup = setup.Setup(self.root)
        self.calls = []
        self.uid = patch.object(setup.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=997, pw_gid=997))
        self.uid.start()
        self.addCleanup(self.uid.stop)
        for path in [setup.CONFIG, setup.STATE]:
            self.setup.path(path).mkdir(mode=0o700, parents=True)
        self.write(setup.CONFIG + '/agent.env', self.setup.serialize(self.setup.local_settings()), 0o600)
        self.write('/usr/lib/systemd/system/kura.service', '[Service]\nUser=kurad\n')
        self.setup.authorize('kurad')
        self.pair()

    def write(self, name, value, mode=0o644):
        path = self.setup.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        path.chmod(mode)

    def pair(self):
        for destination, source in setup.READER_FILES.items():
            self.write(destination, (PACKAGING / source).read_bytes())
        metadata = build.enrollment_reader()
        self.write(setup.READER_META, json.dumps(metadata))
        self.write('/usr/share/kura-management-agent/source-manifest.json', json.dumps({
            'schemaVersion': 2, 'sourceFiles': [{'path': 'packaging/' + source,
                'sha256': metadata['files'][destination]} for destination, source in setup.READER_FILES.items()]}))

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_ino,
                path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode),
                path.stat().st_mtime_ns, path.stat().st_ctime_ns)
                for path in self.root.rglob('*') if path.is_file()}

    def grant(self, ident=None):
        return self.setup.grant_enrollment(ident or str(uuid.uuid4()), 'root-fixture')

    def test_default_is_off_and_explicit_grant_never_starts_units_or_enables_remote(self):
        before = self.setup.settings()
        self.assertNotIn('AGENT_KURA_ENROLLMENT_READER_SOCKET', before)
        self.assertFalse(self.setup.path(setup.READER_GRANT).exists())
        with patch.object(self.setup, 'systemctl', side_effect=lambda *args: self.calls.append(args)):
            result = self.grant()
        self.assertEqual(result['phase'], 'APPLIED')
        self.assertFalse(result['receipt']['unitStarted'])
        self.assertFalse(result['receipt']['remoteEnabled'])
        self.assertFalse(any(call[0] in ['start', 'stop', 'enable', 'disable'] for call in self.calls))
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_KURA_UID'], '997')
        self.assertEqual(settings['AGENT_KURA_ENROLLMENT_READER_SOCKET'], setup.READER_SOCKET)
        self.assertEqual(settings['AGENT_KURA_ENROLLMENT_DIR'], setup.READER_SOURCE)
        for key in ['AGENT_REMOTE_ENABLED', 'AGENT_KURA_REMOTE_MANAGEMENT', 'AGENT_FIREWALL_WRITE']:
            self.assertEqual(settings[key], '0')
        self.assertFalse(self.setup.path(setup.READER_SOURCE).exists(), 'never create or chmod Core data')
        self.assertEqual(stat.S_IMODE(self.setup.path(setup.READER_GRANT).stat().st_mode), 0o600)
        again = self.snapshot()
        self.assertEqual(self.setup.authorization_status(result['requestId']), result)
        self.assertEqual(self.snapshot(), again)

    def test_original_uuid_observation_does_not_reexecute_or_replace_a_grant(self):
        result = self.grant()
        before = self.snapshot()
        with patch.object(self.setup, 'put_durable', side_effect=AssertionError('must not write')):
            self.assertEqual(self.grant(result['requestId']), result)
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(RuntimeError, 'already granted'):
            self.grant()
        self.assertEqual(self.snapshot(), before)

    def test_each_durable_interruption_retains_original_unknown_and_blocks_new_ids(self):
        for stop in range(1, 8):
            with self.subTest(stop=stop):
                other = type(self)('runTest')
                other.setUp()
                try:
                    ident = str(uuid.uuid4())
                    put = other.setup.put_durable
                    count = 0
                    def fail(*args, **kwargs):
                        nonlocal count
                        put(*args, **kwargs)
                        count += 1
                        if count == stop:
                            raise OSError('injected after durable boundary')
                    with patch.object(other.setup, 'put_durable', side_effect=fail):
                        with self.assertRaisesRegex(OSError, 'durable boundary'):
                            other.grant(ident)
                    before = other.snapshot()
                    self.assertEqual(other.setup.authorization_status(ident)['phase'], 'UNKNOWN')
                    with patch.object(other.setup, 'put_durable', side_effect=AssertionError('no replay')):
                        self.assertEqual(other.grant(ident)['phase'], 'UNKNOWN')
                        with self.assertRaises(RuntimeError):
                            other.grant()
                    with self.assertRaises(RuntimeError):
                        other.setup.check()
                    with self.assertRaises(RuntimeError):
                        other.setup.guard_writer()
                    self.assertEqual(other.snapshot(), before)
                finally:
                    other.doCleanups()

    def test_environment_switch_failure_keeps_intent_grant_and_previous_bytes(self):
        ident = str(uuid.uuid4())
        previous = self.setup.path(setup.CONFIG + '/agent.env').read_bytes()
        with patch.object(self.setup, 'replace', side_effect=OSError('injected environment failure')):
            with self.assertRaises(OSError):
                self.grant(ident)
        self.assertEqual(self.setup.path(setup.CONFIG + '/agent.env').read_bytes(), previous)
        self.assertTrue(self.setup.path(setup.READER_GRANT).exists())
        self.assertEqual(self.setup.authorization_status(ident)['phase'], 'UNKNOWN')
        self.assertEqual(self.setup.path(setup.AUTHORIZATIONS + '/' + ident + '.previous.env').read_bytes(), previous)

    def test_unpaired_environment_grant_uid_and_configuration_cannot_start(self):
        self.grant()
        baseline = self.setup.path(setup.READER_GRANT).read_bytes()
        for change in [{'sourceUid': 998}, {'socket': '/run/other.sock'}, {'sourceRoot': '/tmp/other'},
                       {'pairSha256': '0' * 64}, {'requestId': str(uuid.uuid4())}]:
            value = json.loads(baseline)
            value.update(change)
            self.write(setup.READER_GRANT, json.dumps(value), 0o600)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                self.setup.check()
        self.write(setup.READER_GRANT, baseline, 0o600)
        settings = self.setup.settings()
        settings['AGENT_KURA_ENROLLMENT_DIR'] = '/tmp/other'
        self.write(setup.CONFIG + '/agent.env', self.setup.serialize(settings), 0o600)
        with self.assertRaisesRegex(RuntimeError, 'Exact explicit'):
            self.setup.check()

    def test_script_unit_source_manifest_and_protected_metadata_are_independently_checked(self):
        self.grant()
        for name in [*setup.READER_FILES, setup.READER_META,
                     '/usr/share/kura-management-agent/source-manifest.json']:
            path = self.setup.path(name)
            before = path.read_bytes()
            path.write_bytes(before + b'\nchanged')
            with self.assertRaises((RuntimeError, ValueError)):
                self.setup.check()
            path.write_bytes(before)
            path.chmod(0o664)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe native'):
                self.setup.check()
            path.chmod(0o644)
        self.setup.check()

    def test_symlinks_hardlinks_and_duplicate_metadata_are_refused(self):
        path = self.setup.path(setup.READER_META)
        before = path.read_bytes()
        linked = path.with_name('other.json')
        os.link(path, linked)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe native'):
            self.setup.reader_pair()
        linked.unlink()
        path.rename(linked)
        path.symlink_to(linked)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            self.setup.reader_pair()
        path.unlink()
        linked.rename(path)
        path.write_bytes(b'{"schemaVersion":1,' + before[1:])
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            self.setup.reader_pair()

    def test_effective_units_and_active_agent_are_rejected_without_configuration_changes(self):
        def live(*args):
            unit = args[1]
            vendor = setup.READER_SERVICE_UNIT if '@' in unit else setup.READER_SOCKET_UNIT
            return subprocess.CompletedProcess(args, 0,
                f'LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/{vendor}\nDropInPaths=/etc/unreviewed.conf\n')
        before = self.snapshot()
        with patch.object(self.setup, 'systemctl', side_effect=live):
            with self.assertRaisesRegex(RuntimeError, 'Effective native'):
                self.setup.reader_pair()
        def active(*args):
            return subprocess.CompletedProcess(args, 0, 'MainPID=123\nActiveState=active\n')
        with patch.object(self.setup, 'systemctl', side_effect=active):
            with self.assertRaisesRegex(RuntimeError, 'Stop the packaged agent'):
                self.grant()
        self.assertEqual(self.snapshot(), before)

    def test_instance_specific_override_and_invalid_operator_never_write_a_grant(self):
        before = self.snapshot()
        for operator in ['', 'x\x1b', 'x\n', '汉' * 43]:
            with self.assertRaisesRegex(RuntimeError, 'operator'):
                self.setup.grant_enrollment(str(uuid.uuid4()), operator)
        self.assertEqual(self.snapshot(), before)
        name = '/etc/systemd/system/kura-management-enrollment-reader@0-1.service.d/override.conf'
        self.write(name, '[Service]\nAmbientCapabilities=CAP_DAC_READ_SEARCH\n')
        with self.assertRaisesRegex(RuntimeError, 'instance override'):
            self.setup.reader_pair()

    def test_missing_intent_and_pending_temporary_files_are_unknown_and_never_replaced(self):
        ident = str(uuid.uuid4())
        self.write(setup.AUTHORIZATIONS + '/' + ident + '.grant.json', b'{}', 0o600)
        self.setup.path(setup.AUTHORIZATIONS).chmod(0o700)
        self.assertEqual(self.setup.authorization_status(ident)['phase'], 'UNKNOWN')
        before = self.snapshot()
        self.assertEqual(self.grant(ident)['phase'], 'UNKNOWN')
        with self.assertRaises(RuntimeError):
            self.grant()
        self.assertEqual(self.snapshot(), before)
        self.write(setup.AUTHORIZATIONS + '/.' + ident + '.intent.json.record-new', b'{}', 0o600)
        with self.assertRaisesRegex(RuntimeError, 'Incomplete local'):
            self.setup.guard_local_authorizations()

    def test_missing_receipt_or_changed_original_proof_cannot_certify_application(self):
        result = self.grant()
        base = setup.AUTHORIZATIONS + '/' + result['requestId']
        receipt = self.setup.path(base + '.result.json')
        raw = receipt.read_bytes()
        receipt.unlink()
        self.assertEqual(self.setup.authorization_status(result['requestId'])['phase'], 'UNKNOWN')
        with self.assertRaises(RuntimeError):
            self.setup.check()
        self.write(base + '.result.json', raw, 0o600)
        self.write(base + '.grant.json', b'{}', 0o600)
        with self.assertRaisesRegex(RuntimeError, 'evidence changed'):
            self.setup.authorization_status(result['requestId'])

    def test_purge_retains_applied_local_grants_and_original_receipts(self):
        self.grant()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'explicit verified archive'):
            self.setup.purge()
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
