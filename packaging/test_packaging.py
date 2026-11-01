import hashlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location('agent_package_' + name, Path(__file__).parent / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup_module = load('setup')
build = load('build')


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory()
        cls.certificates = Path(cls.shared.name)
        commands = [
            ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=package-test-ca',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', 'ca.key', '-out', 'ca.pem'],
            ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=package-test-agent', '-keyout', 'agent.key', '-out', 'agent.csr'],
            ['x509', '-req', '-in', 'agent.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
             '-days', '1', '-extfile', 'client.ext', '-out', 'agent.pem'],
        ]
        (cls.certificates / 'client.ext').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n')
        for command in commands:
            subprocess.run(['openssl', *command], cwd=cls.certificates, check=True, capture_output=True)
        for path in cls.certificates.glob('*.key'):
            path.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.setup = setup_module.Setup(self.root)

    def install(self, endpoint='https://console.example.invalid:8443', key='agent.key'):
        self.setup.import_identity(endpoint, 'registered-gateway', self.certificates / 'ca.pem',
                                   self.certificates / 'agent.pem', self.certificates / key)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}

    def test_import_is_private_idempotent_and_observation_only(self):
        self.install()
        before = self.snapshot()
        self.install()
        self.assertEqual(before, self.snapshot())
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_NETWORK_INTERFACES'], '')
        self.assertNotIn('AGENT_KURA_NETWORK_INTERFACES', settings)
        self.assertEqual(settings['AGENT_KURA_UID'], '4294967295')
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '1')
        for path in self.setup.path(setup_module.CONFIG).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_same_center_binding_generation_migration_is_explicit(self):
        self.install()
        env = self.setup.path(setup_module.CONFIG) / 'agent.env'
        lines = [line for line in env.read_text().splitlines() if not line.startswith('AGENT_BINDING_GENERATION=')]
        env.write_text('\n'.join(lines) + '\n')
        with self.assertRaisesRegex(RuntimeError, 'Binding generation missing'):
            self.setup.check()
        self.setup.migrate_binding_generation()
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '1')

    def test_local_rebind_is_explicit_backed_up_and_increments_generation(self):
        self.install()
        before = self.snapshot()
        self.setup.transfer_identity('https://new-console.example.invalid:8443', 'registered-gateway',
                                     self.certificates / 'ca.pem', self.certificates / 'agent.pem',
                                     self.certificates / 'agent.key', 1, 'local-admin')
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_CONSOLE_ENDPOINT'], 'https://new-console.example.invalid:8443')
        self.assertEqual(settings['AGENT_GATEWAY_ID'], 'registered-gateway')
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '2')
        backup = self.setup.path(setup_module.STATE + '/transfers/2')
        receipt = json.loads((backup / 'receipt.json').read_text())
        self.assertEqual(receipt['fromBindingGeneration'], 1)
        self.assertEqual(receipt['toBindingGeneration'], 2)
        self.assertEqual(receipt['authorization'], 'gateway-local-operator')
        self.assertTrue((backup / 'agent.env').is_file())
        self.assertTrue((backup / 'agent.key').is_file())
        marker = self.setup.path(setup_module.CONFIG + '/.identity-transferring')
        self.assertFalse(marker.exists())

    def test_local_rebind_requires_exact_generation_and_is_atomic_on_refusal(self):
        self.install()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Binding generation changed'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443', 'registered-gateway',
                                         self.certificates / 'ca.pem', self.certificates / 'agent.pem',
                                         self.certificates / 'agent.key', 99, 'local-admin')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE + '/transfers/100').exists())

    def test_local_rebind_blocks_unsettled_side_effects(self):
        self.install()
        database = self.setup.path(setup_module.STATE + '/results.sqlite')
        database.parent.mkdir(parents=True, exist_ok=True)
        with __import__('contextlib').closing(__import__('sqlite3').connect(database)) as connection:
            connection.execute('CREATE TABLE executions(state TEXT, operation INTEGER)')
            connection.execute("INSERT INTO executions VALUES('UNKNOWN',5)")
            connection.commit()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'uncertain executions'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443', 'registered-gateway',
                                         self.certificates / 'ca.pem', self.certificates / 'agent.pem',
                                         self.certificates / 'agent.key', 1, 'local-admin')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE + '/transfers/2').exists())

    def test_second_console_is_rejected_without_changing_identity(self):
        self.install()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'explicit transfer'):
            self.install('https://another-console.example.invalid')
        self.assertEqual(before, self.snapshot())

    def test_activate_releases_lock_before_systemd_start_pre_check(self):
        self.install()
        lock = self.setup.path('/run/lock/kura-management-agent-setup.lock')
        lock.parent.mkdir(parents=True)
        calls = []

        def systemctl(*args):
            with lock.open('r+') as child:
                # A fresh ExecStartPre process must be able to acquire the lock.
                fcntl.flock(child, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.setup.check()
            calls.append(args)

        with patch.object(setup_module, 'Setup', return_value=self.setup), \
                patch.object(setup_module.os, 'geteuid', return_value=0), \
                patch.object(setup_module.sys, 'argv', ['setup.py', 'activate']), \
                patch.object(self.setup, 'systemctl', side_effect=systemctl):
            setup_module.main()
        self.assertEqual(calls, [('enable', '--now', setup_module.UNIT)])

    def test_starting_agent_cannot_change_identity_even_before_main_pid_exists(self):
        result = types.SimpleNamespace(stdout='MainPID=0\nActiveState=activating\n')
        with patch.object(self.setup, 'systemctl', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'Stop the packaged agent'):
                self.install()
        self.assertFalse(self.setup.path(setup_module.CONFIG).exists())

    def test_mismatched_private_key_does_not_begin_install(self):
        with self.assertRaisesRegex(RuntimeError, 'do not match'):
            self.install(key='ca.key')
        self.assertFalse(self.setup.path(setup_module.CONFIG).exists())

    def test_interrupted_import_and_symlink_are_not_repaired_implicitly(self):
        config = self.setup.path(setup_module.CONFIG)
        config.mkdir(parents=True, mode=0o700)
        (config / '.identity-installing').write_text('v1\n')
        with self.assertRaisesRegex(RuntimeError, 'interrupted identity'):
            self.install()
        (config / '.identity-installing').unlink()
        (config / 'agent.key').symlink_to(self.certificates / 'agent.key')
        with self.assertRaises(RuntimeError):
            self.install()

    def test_endpoint_and_gateway_cannot_inject_environment(self):
        for value in ['http://console', 'https://user:pass@console', 'https://console/route',
                      'https://console\nAGENT_ADMIN_UID=1', 'https://console"', 'https://console:0']:
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                self.setup.identity_settings(value, 'gateway')
        with self.assertRaises(RuntimeError):
            self.setup.identity_settings('https://console', 'gateway\nUID=0')

    def test_authorization_is_uid_bound_read_only_and_preserved_on_reimport(self):
        self.install()
        account = types.SimpleNamespace(pw_uid=997, pw_gid=997)
        with patch.object(setup_module.pwd, 'getpwnam', return_value=account):
            self.setup.authorize('kura-netplan')
            self.assertEqual(self.setup.check()['AGENT_KURA_UID'], '997')
            self.assertEqual(self.setup.check()['AGENT_KURA_NETWORK_INTERFACES'], '')
            self.install()
            with patch.object(setup_module.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=998, pw_gid=998)):
                with self.assertRaisesRegex(RuntimeError, 'UID changed'):
                    self.setup.check()

    def test_writer_and_unsettled_journal_block_lifecycle(self):
        self.install()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        env.write_text(env.read_text().replace('AGENT_NETWORK_INTERFACES=\n', 'AGENT_NETWORK_INTERFACES=eth0\n'))
        with self.assertRaisesRegex(RuntimeError, 'handover'):
            self.setup.guard_writer()
        env.write_text(env.read_text().replace('AGENT_NETWORK_INTERFACES=eth0\n', 'AGENT_NETWORK_INTERFACES=\n'))
        journal = self.setup.path(setup_module.STATE + '/network/transaction.json')
        journal.parent.mkdir(parents=True)
        for state in ['WAIT_CONFIRM', 'RECOVERY_REQUIRED', 'FAILED']:
            journal.write_text(json.dumps({'state': state}))
            with self.assertRaises(RuntimeError):
                self.setup.guard_writer()
        journal.write_text(json.dumps({'state': 'ROLLED_BACK'}))
        self.setup.guard_writer()

    def test_purge_refuses_confirmed_network_and_foreign_authorization(self):
        self.install()
        confirmed = self.setup.path(setup_module.STATE + '/network/confirmed.json')
        confirmed.parent.mkdir(parents=True)
        confirmed.write_text(json.dumps({'revision': 2, 'yaml': 'network: {}\n'}))
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'handover'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())
        confirmed.write_text(json.dumps({'yaml': None}))
        dropin = self.setup.path(setup_module.DROPIN)
        dropin.parent.mkdir(parents=True)
        dropin.write_text('[Service]\n# administrator change\n')
        with self.assertRaisesRegex(RuntimeError, 'externally modified'):
            self.setup.purge()

    def test_uncertain_execution_blocks_purge_without_deleting_identity_or_key(self):
        from contextlib import closing
        self.install()
        database = self.setup.path(setup_module.STATE + '/results.sqlite')
        database.parent.mkdir(parents=True, exist_ok=True)
        key = database.with_name(database.name + '.plan-key')
        key.write_bytes(b'private execution key fixture')
        with closing(sqlite3.connect(database)) as connection:
            connection.execute('CREATE TABLE executions(state TEXT, operation INTEGER)')
            for state, operation in [('RUNNING', 5), ('UNKNOWN', 6), ('UNKNOWN', 99)]:
                connection.execute('DELETE FROM executions')
                connection.execute('INSERT INTO executions VALUES(?,?)', (state, operation))
                connection.commit()
                before = self.snapshot()
                with self.assertRaisesRegex(RuntimeError, 'uncertain executions'):
                    self.setup.purge()
                self.assertEqual(self.snapshot(), before)
            connection.execute('DELETE FROM executions')
            connection.executemany('INSERT INTO executions VALUES(?,?)', [('RUNNING', 1), ('SUCCEEDED', 5)])
            connection.commit()
        self.setup.guard_writer()

    def test_corrupt_execution_database_blocks_lifecycle(self):
        self.install()
        database = self.setup.path(setup_module.STATE + '/results.sqlite')
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_bytes(b'not a SQLite database')
        with self.assertRaisesRegex(RuntimeError, 'recovery required'):
            self.setup.guard_writer()

    def test_purge_scope_excludes_kura_and_os_network(self):
        self.install()
        foreign = []
        for name in ['/etc/netplan/10-existing.yaml', '/var/lib/kura-netplan/user/snapshot.xml',
                     '/etc/systemd/system/kura-netplan.service.d/local.conf', '/home/operator/keep']:
            path = self.setup.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('keep\n')
            foreign.append(path)
        self.setup.purge()
        self.assertTrue(all(path.read_text() == 'keep\n' for path in foreign))
        self.assertFalse(self.setup.path(setup_module.CONFIG).exists())

    def test_preflight_accepts_retained_package_but_rejects_legacy(self):
        self.install()
        with self.assertRaisesRegex(RuntimeError, 'unpackaged'):
            self.setup.preflight()
        marker = self.setup.path(setup_module.STATE + '/.package-v1')
        marker.parent.mkdir(parents=True)
        marker.write_text('kura-management-agent-v1\n')
        self.setup.preflight()


class SourceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def artifact(self, unsafe=False):
        path = self.root / 'protocol.crate'
        with tarfile.open(path, 'w:gz') as archive:
            content = b'[package]\nname="yofc-management-protocol"\nversion="0.1.0"\n'
            item = tarfile.TarInfo('yofc-management-protocol-0.1.0/Cargo.toml')
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
            if unsafe:
                item = tarfile.TarInfo('yofc-management-protocol-0.1.0/../../escape')
                archive.addfile(item, io.BytesIO())
        return path

    def test_artifact_stage_is_self_contained_and_checksum_bound(self):
        artifact = self.artifact()
        destination = self.root / 'source'
        result = build.stage(artifact, build.sha(artifact), destination)
        self.assertFalse(result['siblingSourceRequired'])
        cargo = (destination / 'Cargo.toml').read_text()
        self.assertNotIn('path = "../', cargo)
        self.assertIn('path = "vendor/yofc-management-protocol-0.1.0"', cargo)
        with self.assertRaises(RuntimeError):
            build.stage(artifact, '0' * 64, self.root / 'other')

    def test_protocol_archive_cannot_escape_or_replace_staging(self):
        artifact = self.artifact(unsafe=True)
        with self.assertRaises(RuntimeError):
            build.stage(artifact, build.sha(artifact), self.root / 'source')
        self.assertFalse((self.root / 'source').exists())

    def test_non_linux_binary_is_rejected_before_packaging(self):
        binary = self.root / 'agent'
        binary.write_bytes(b'not a Linux ELF64')
        with self.assertRaisesRegex(RuntimeError, 'ELF64'):
            build.deb(binary, build.sha(binary), 'arm64', '0.1.0~test1', self.root / 'deb', self.root / 'manifest.json')


if __name__ == '__main__':
    unittest.main()
