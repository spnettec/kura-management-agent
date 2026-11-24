"""Native profile filesystem/command fixtures; not an installed systemd result."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
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
        pairs = {}
        rows = []
        for path, name in native.NATIVE_FILES.items():
            raw = (PACKAGING / name).read_bytes()
            self.write(path, raw); digest = hashlib.sha256(raw).hexdigest()
            pairs[path] = digest; rows.append({'path': 'packaging/' + name, 'sha256': digest})
        self.write('/usr/share/kura-management-agent/source-manifest.json', json.dumps({'schemaVersion': 2, 'sourceFiles': rows}))
        self.write('/usr/share/kura-management-agent/native-profile.json', json.dumps({'schemaVersion': 1, 'profile':'native-nonroot-v1', 'files':pairs}))
        self.write('/usr/share/kura-management-agent/package-v2', b'kura-management-agent-v2\n')
        bootstrap = patch.object(self.native, 'bootstrap', side_effect=self.bootstrap_fixture)
        bootstrap.start(); self.addCleanup(bootstrap.stop)

    def bootstrap_fixture(self, operation, descriptor):
        # Filesystem/command fixture only; actual Rust/bootstrap interop is
        # separately selected in a disposable Linux native profile.
        db = self.setup.path(native.V2_STATE + '/results.sqlite')
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE native_profile_generation(singleton INTEGER,operation_id TEXT)')
            connection.execute('INSERT INTO native_profile_generation VALUES(1,?)', (operation,))
        key = db.with_name(db.name + '.plan-key'); key.write_bytes(os.urandom(32))
        for path in [db, key]:
            os.chown(path, descriptor['uid'], descriptor['gid']); path.chmod(0o600)

    def write(self, name, value, mode=0o644):
        path = self.setup.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode() if isinstance(value, str) else value); path.chmod(mode)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_uid, path.stat().st_gid,
            stat.S_IMODE(path.stat().st_mode), path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
            for path in self.root.rglob('*') if path.is_file()}

    def test_snapshot_peer_attestation_is_current_root_prestart_only(self):
        self.assertTrue(self.native.initialize(self.operation))
        descriptor = self.native.descriptor()
        boot = str(uuid.uuid4())
        self.write('/proc/sys/kernel/random/boot_id', boot + '\n')
        self.setup.path('/run').mkdir(exist_ok=True)
        target = self.setup.path(native.SNAPSHOT_VALIDATION_PEER)

        def publish(invocation, control_pid):
            state = SimpleNamespace(stdout=f'ActiveState=activating\nControlPID={control_pid}\nInvocationID={invocation}\n')
            with patch.dict(os.environ, {'INVOCATION_ID': invocation}), patch.object(
                    self.setup, 'systemctl', return_value=state):
                self.native.attest_snapshot_validation_peer(descriptor)

        with self.assertRaisesRegex(RuntimeError, 'exact packaged pre-start controller'):
            publish('1' * 32, os.getpid() + 1)
        self.assertFalse(target.exists())
        publish('1' * 32, os.getpid())
        root = self.root.stat()
        expected = dict(schema=1, purpose=native.SNAPSHOT_VALIDATION_PURPOSE, invocationId='1' * 32,
                        bootId=boot, rootDevice=root.st_dev, rootInode=root.st_ino,
                        identitySha256=hashlib.sha256(self.setup.path(native.V2_IDENTITY).read_bytes()).hexdigest())
        self.assertEqual(expected, json.loads(target.read_bytes()))
        self.assertEqual((0, 0, 0o600), (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode)))
        publish('2' * 32, os.getpid())
        self.assertEqual(expected | {'invocationId': '2' * 32}, json.loads(target.read_bytes()))

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

    def test_initialization_keeps_its_original_overlay_proof_across_device_reattachment(self):
        backing = {'device': self.root.stat().st_dev, 'overlaySha256': 'a' * 64}
        with patch.object(native.RetainedRemoval, 'overlay_mount', return_value=backing):
            self.assertTrue(self.native.initialize(self.operation))
        descriptor = self.native.descriptor()
        receipt = json.loads(self.setup.path(native.V2_ADMIN + '/initialization.json').read_bytes())
        path = self.setup.path(native.V2_CONTINUITY)
        raw = path.read_bytes()
        observed = json.loads(raw)
        moved_device = backing['device'] + 1
        observed['rootOverlay']['device'] = moved_device
        for name in ('database', 'planKey'):
            observed[name]['device'] = moved_device
        with patch.object(self.native, 'continuity', return_value=observed):
            self.assertEqual(self.native.initialization_state(receipt, descriptor), receipt)
            self.assertEqual(path.read_bytes(), raw)
            observed['rootOverlay']['overlaySha256'] = 'b' * 64
            with self.assertRaisesRegex(RuntimeError, 'overlay backing differs'):
                self.native.initialization_state(receipt, descriptor)

    def test_repeated_original_initialization_is_readonly_and_new_ids_cannot_replace_it(self):
        self.native.initialize(self.operation)
        before = self.snapshot()
        self.assertFalse(self.native.initialize(self.operation))
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(RuntimeError, 'original native initialization'):
            self.native.initialize(str(uuid.uuid4()))
        self.assertEqual(self.snapshot(), before)

    def test_configuration_write_is_explicit_and_preserves_the_original_environment(self):
        self.native.initialize(self.operation)
        status = self.native.configuration_write_action(self.operation)
        self.assertFalse(status['enabled'])
        with self.assertRaisesRegex(RuntimeError, 'original paired Kura peer'):
            self.native.configuration_write_action(self.operation, True)
        self.assertFalse(self.setup.path(native.CONFIGURATION_WRITE).exists())

        env_path = self.setup.path(native.V2_CONFIG + '/agent.env')
        env = env_path.read_bytes().replace(b'AGENT_KURA_UID=4294967295\n', b'AGENT_KURA_UID=997\n')
        env_path.write_bytes(env)
        with patch.object(native.KuraPeer, 'check', return_value={'kuraUid': 997}):
            self.assertTrue(self.native.configuration_write_action(self.operation, True)['enabled'])
            policy = self.setup.path(native.CONFIGURATION_WRITE)
            self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o644)
            before = self.snapshot()
            self.assertTrue(self.native.configuration_write_action(self.operation)['enabled'])
            with self.assertRaisesRegex(RuntimeError, 'Different native installation'):
                self.native.configuration_write_action(str(uuid.uuid4()), False)
            self.assertEqual(self.snapshot(), before)
            self.assertFalse(self.native.configuration_write_action(self.operation, False)['enabled'])
            self.assertEqual(env_path.read_bytes(), env)

    def test_configuration_write_refuses_unsafe_or_foreign_policy(self):
        self.native.initialize(self.operation)
        content = self.native.configuration_write_content(str(uuid.uuid4()), False)
        self.write(native.CONFIGURATION_WRITE, content, 0o644)
        with self.assertRaisesRegex(RuntimeError, 'original installation'):
            self.native.check()
        content = self.native.configuration_write_content(self.operation, False)
        self.write(native.CONFIGURATION_WRITE, content, 0o666)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe native'):
            self.native.check()
        policy = self.setup.path(native.CONFIGURATION_WRITE)
        foreign = policy.with_name('unrelated')
        policy.rename(foreign)
        policy.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError, 'Refusing symlink'):
            self.native.check()

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
        for stop in range(1, 7):
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
                    self.assertEqual(other.native.status(other.operation)['state'], 'UNKNOWN')
                    with self.assertRaisesRegex(RuntimeError, 'original native initialization'):
                        other.native.status(str(uuid.uuid4()))
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

    def test_kura_peer_reviews_effective_networking_dropin_after_filtering_the_adapter(self):
        peer = native.KuraPeer(self.native)
        core_home = self.setup.path('/opt/eclipse/kura')
        descriptor = {'uid': 995, 'gid': 993, 'readerGid': 992}
        bridge = {'coreLoaderSha256': '1' * 64, 'metadataSha256': '2' * 64}
        self.account = SimpleNamespace(pw_name='kurad', pw_uid=997, pw_gid=994, pw_shell='/usr/sbin/nologin')
        self.write(peer.NETWORKING_DROP_IN, 'fixture networking unit')
        systemd = ('LoadState=loaded\nFragmentPath=' + peer.CORE_UNIT + '\nUser=kurad\nGroup=kurad\n')
        installed = subprocess.CompletedProcess([], 0, 'installed')
        with patch.object(self.setup, 'run', return_value=installed), patch.object(
                self.setup, 'guard_core_loader', return_value=core_home), patch.object(
                self.native, 'asset', return_value='3' * 64), patch.object(
                peer, 'networking_drop_in', return_value='4' * 64) as review:
            mixed = systemd + 'DropInPaths=' + peer.NETWORKING_DROP_IN + ' ' + native.CONTAINER_ADAPTER_DROPIN + '\n'
            with patch.object(self.setup, 'systemctl', return_value=SimpleNamespace(stdout=mixed)):
                self.assertEqual(peer.core(descriptor, bridge)['coreNetworkingDropInSha256'], '4' * 64)
            review.assert_called_once_with('3' * 64, core_home)
            self.setup.path(peer.NETWORKING_DROP_IN).unlink()
            unreviewed = systemd + 'DropInPaths=/etc/systemd/system/kura.service.d/unreviewed.conf\n'
            with patch.object(self.setup, 'systemctl', return_value=SimpleNamespace(stdout=unreviewed)):
                with self.assertRaisesRegex(RuntimeError, 'Unreviewed effective Core unit'):
                    peer.core(descriptor, bridge)

    def test_lost_database_or_key_cannot_become_a_fresh_profile(self):
        for name in ['results.sqlite', 'results.sqlite.plan-key']:
            with self.subTest(name=name):
                other = type(self)('runTest'); other.setUp()
                try:
                    other.native.initialize(other.operation)
                    path = other.setup.path(native.V2_STATE + '/' + name); path.unlink()
                    before = other.snapshot()
                    with self.assertRaises(FileNotFoundError): other.native.check()
                    with self.assertRaises(FileNotFoundError): other.native.initialize(other.operation)
                    with self.assertRaises(RuntimeError): other.native.initialize(str(uuid.uuid4()))
                    self.assertEqual(other.snapshot(), before)
                    self.assertFalse(path.exists())
                finally: other.doCleanups()

    def test_replaced_database_changed_generation_and_changed_key_are_not_repaired(self):
        self.native.initialize(self.operation)
        key = self.setup.path(native.V2_STATE + '/results.sqlite.plan-key')
        raw = key.read_bytes(); key.write_bytes(b'0' * 32)
        with self.assertRaisesRegex(RuntimeError, 'continuity changed'): self.native.check()
        key.write_bytes(raw); self.native.check()
        db = self.setup.path(native.V2_STATE + '/results.sqlite')
        original = db.read_bytes(); retained = db.with_name('retained.sqlite'); db.rename(retained)
        self.write(native.V2_STATE + '/results.sqlite', original, 0o600); os.chown(db, 995, 993)
        with self.assertRaisesRegex(RuntimeError, 'continuity changed'): self.native.check()
        db.unlink(); retained.rename(db)
        with sqlite3.connect(db) as connection:
            connection.execute('DELETE FROM native_profile_generation')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'generation requires original recovery'): self.native.check()
        self.assertEqual(self.snapshot(), before)

    def test_original_applied_receipt_and_current_readiness_are_independent_readonly_observations(self):
        self.native.initialize(self.operation)
        before = self.snapshot()
        self.assertEqual(self.native.status(self.operation), {'schemaVersion':1, 'requestId':self.operation,
            'state':'APPLIED','currentReadiness':'READY','replayed':False})
        self.assertEqual(self.snapshot(), before)
        self.setup.path(native.V2_STATE + '/results.sqlite').unlink()
        before = self.snapshot()
        self.assertEqual(self.native.status(self.operation)['state'], 'APPLIED')
        self.assertEqual(self.native.status(self.operation)['currentReadiness'], 'REFUSED')
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
