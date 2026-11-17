"""Native profile filesystem/command fixtures; not an installed systemd result."""
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PACKAGING = Path(__file__).resolve().parent
legacy = load('native_profile_legacy_setup', PACKAGING / 'setup.py')
native = load('native_profile_setup', PACKAGING / 'runtime_setup.py')


@unittest.skipUnless(os.geteuid() == 0, 'disposable Root filesystem fixture required')
class NativeProfileTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.setup = legacy.Setup(self.root)
        self.native = native.RuntimeSetup(self.setup)
        self.operation = str(uuid.uuid4())
        self.account = SimpleNamespace(pw_name=native.V2_USER, pw_uid=995, pw_gid=994, pw_dir='/nonexistent', pw_shell='/usr/sbin/nologin')
        account = patch.object(native.pwd, 'getpwnam', side_effect=lambda name: self.account)
        group = patch.object(native.grp, 'getgrnam', side_effect=lambda name: SimpleNamespace(gr_gid=993 if name == 'kura-management' else 994))
        groups = patch.object(native.grp, 'getgrall', return_value=[])
        users = patch.object(native.pwd, 'getpwall', side_effect=lambda: [self.account])
        for context in [account, group, groups, users]: context.start(); self.addCleanup(context.stop)
        for name in ['/etc', '/var/lib']:
            self.setup.path(name).mkdir(parents=True, exist_ok=True)
        self.write('/usr/bin/yofc-management-agent', b'isolated fake ELF input', 0o755)
        self.write('/usr/share/kura-management-agent/source-manifest.json', json.dumps({'schemaVersion': 2, 'sourceFiles': []}))
        self.write(native.V2_VENDOR, (PACKAGING / native.V2_UNIT).read_bytes())

    def write(self, name, value, mode=0o644):
        path = self.setup.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode() if isinstance(value, str) else value); path.chmod(mode)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_uid, path.stat().st_gid,
            stat.S_IMODE(path.stat().st_mode), path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
            for path in self.root.rglob('*') if path.is_file()}

    def test_new_runtime_and_root_administration_are_separate_without_start_or_data_adoption(self):
        self.assertTrue(self.native.initialize(self.operation))
        state = self.setup.path(native.V2_STATE).stat()
        self.assertEqual((state.st_uid, state.st_gid, stat.S_IMODE(state.st_mode)), (995, 993, 0o700))
        for path, mode in [(native.V2_CONFIG + '/agent.env', 0o600), (native.V2_IDENTITY, 0o644),
                           (native.V2_ADMIN + '/initialization.json', 0o600)]:
            m = self.setup.path(path).stat()
            self.assertEqual((m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)), (0, 0, mode))
        identity = self.native.check()
        self.assertEqual(identity['uid'], 995)
        self.assertEqual(identity['socket'], native.V2_SOCKET)
        self.assertNotIn('User=root', self.setup.path(native.V2_VENDOR).read_text())
        self.assertNotIn('StateDirectory=', self.setup.path(native.V2_VENDOR).read_text())
        self.assertFalse(self.setup.path('/etc/kura-management-agent').exists())
        self.assertFalse(self.setup.path('/var/lib/kura-management-agent').exists())
        self.assertFalse(self.setup.path('/opt/eclipse/kura').exists())

    def test_repeated_original_initialization_is_readonly_and_new_ids_cannot_replace_it(self):
        self.native.initialize(self.operation)
        before = self.snapshot()
        self.assertFalse(self.native.initialize(self.operation))
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(RuntimeError, 'original native initialization'):
            self.native.initialize(str(uuid.uuid4()))
        self.assertEqual(self.snapshot(), before)

    def test_legacy_data_and_running_legacy_unit_are_rejected_before_any_profile_write(self):
        before = self.snapshot()
        with patch.object(self.setup, 'systemctl', return_value=subprocess.CompletedProcess([], 0, 'MainPID=12\nActiveState=active\n')):
            with self.assertRaisesRegex(RuntimeError, 'Explicitly stop'):
                self.native.initialize(self.operation)
        self.assertEqual(self.snapshot(), before)
        self.write('/var/lib/kura-management-agent/original-journal', b'public retained sentinel', 0o600)
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Retained legacy'):
            self.native.initialize(self.operation)
        self.assertEqual(self.snapshot(), before)

    def test_interactive_or_root_account_is_not_adopted(self):
        before = self.snapshot()
        for changes in [{'pw_uid': 0}, {'pw_shell': '/bin/bash'}, {'pw_dir': '/home/personal'}, {'pw_gid': 0}]:
            account = SimpleNamespace(**{**vars(self.account), **changes})
            with patch.object(native.pwd, 'getpwnam', return_value=account):
                with self.assertRaisesRegex(RuntimeError, 'separate non-login'):
                    self.native.initialize(self.operation)
        self.assertEqual(self.snapshot(), before)

    def test_uid_aliases_and_empty_retained_state_are_not_fresh_profiles(self):
        before = self.snapshot()
        other = SimpleNamespace(pw_uid=995, pw_name='kurad')
        with patch.object(native.pwd, 'getpwall', return_value=[self.account, other]):
            with self.assertRaisesRegex(RuntimeError, 'separate non-login'):
                self.native.initialize(self.operation)
        self.assertEqual(self.snapshot(), before)
        state = self.setup.path(native.V2_STATE); state.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, 'Retained native profile'):
            self.native.initialize(self.operation)
        self.assertFalse(self.setup.path(native.V2_CONFIG).exists())

    def test_every_publication_interruption_retains_pending_and_never_reinitializes(self):
        for stop in range(1, 6):
            with self.subTest(stop=stop):
                other = type(self)('runTest'); other.setUp()
                try:
                    publish = other.native.publish
                    count = 0
                    def fail(*args, **kwargs):
                        nonlocal count
                        publish(*args, **kwargs); count += 1
                        if count == stop: raise OSError('injected after publication')
                    with patch.object(other.native, 'publish', side_effect=fail):
                        with self.assertRaises(OSError): other.native.initialize(other.operation)
                    before = other.snapshot()
                    with self.assertRaisesRegex(RuntimeError, 'uncertain original'):
                        other.native.check()
                    with self.assertRaises(RuntimeError): other.native.initialize(other.operation)
                    with self.assertRaises(RuntimeError): other.native.initialize(str(uuid.uuid4()))
                    self.assertEqual(other.snapshot(), before)
                finally:
                    other.doCleanups()

    def test_source_unit_public_identity_and_ownership_drift_are_not_repaired(self):
        self.native.initialize(self.operation)
        unit = self.setup.path(native.V2_VENDOR); original = unit.read_bytes()
        unit.write_bytes(original + b'\n# changed\n')
        with self.assertRaisesRegex(RuntimeError, 'pair changed'): self.native.check()
        unit.write_bytes(original); self.native.check()
        state = self.setup.path(native.V2_STATE); os.chown(state, 0, 0)
        with self.assertRaisesRegex(RuntimeError, 'directory requires explicit recovery'): self.native.check()
        self.assertEqual(state.stat().st_uid, 0, 'must not recursively chown retained data')

    def test_missing_runtime_marker_does_not_become_a_clean_initialization(self):
        self.native.initialize(self.operation)
        self.setup.path(native.V2_STATE + '/.native-profile-v1').unlink()
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError): self.native.check()
        with self.assertRaises(FileNotFoundError): self.native.initialize(self.operation)
        self.assertEqual(self.snapshot(), before)

    def test_changed_capability_configuration_and_effective_unit_do_not_start(self):
        self.native.initialize(self.operation)
        def live(*args):
            if args[1] == 'kura-management-agent.service':
                return subprocess.CompletedProcess(args, 0, 'MainPID=0\nActiveState=inactive\n')
            return subprocess.CompletedProcess(args, 0, 'LoadState=loaded\nFragmentPath=' + native.V2_VENDOR +
                '\nDropInPaths=/etc/unreviewed.conf\nUser=root\nGroup=root\n')
        with patch.object(self.setup, 'systemctl', side_effect=live):
            with self.assertRaisesRegex(RuntimeError, 'Effective non-Root'): self.native.check()
        path = self.setup.path(native.V2_CONFIG + '/agent.env')
        path.write_bytes(path.read_bytes() + b'AGENT_NM_CONFIG=/etc/unreviewed.json\n')
        with self.assertRaisesRegex(RuntimeError, 'authorization/migration is not installed'): self.native.check()


if __name__ == '__main__':
    unittest.main()
