import base64
import hashlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sqlite3
import tarfile
import tempfile
import time
import types
import unittest
import uuid
import zipfile
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location('agent_package_' + name, Path(__file__).parent / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OPENSSL = '/opt/homebrew/bin/openssl' if Path('/opt/homebrew/bin/openssl').is_file() else shutil.which('openssl')

setup_module = load('setup')
build = load('build')


class CommandLineTests(unittest.TestCase):
    def test_both_fixed_profiles_reach_the_public_parser_and_other_users_are_rejected(self):
        script = Path(__file__).with_name('setup.py')
        for user in ('kurad', 'kura-netplan'):
            result = subprocess.run([sys.executable, str(script), 'authorize-kura', '--user', user, '--help'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
        result = subprocess.run([sys.executable, str(script), 'authorize-kura', '--user', 'root', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertIn('invalid choice', result.stderr)


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
        subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'ED25519', '-out', 'transfer-signer.private.pem'],
                       cwd=cls.certificates, check=True, capture_output=True)
        subprocess.run([OPENSSL, 'pkey', '-in', 'transfer-signer.private.pem', '-pubout', '-out', 'transfer-signer.pem'],
                       cwd=cls.certificates, check=True, capture_output=True)
        subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'ED25519', '-out', 'transfer-signer-2.private.pem'],
                       cwd=cls.certificates, check=True, capture_output=True)
        subprocess.run([OPENSSL, 'pkey', '-in', 'transfer-signer-2.private.pem', '-pubout', '-out', 'transfer-signer-2.pem'],
                       cwd=cls.certificates, check=True, capture_output=True)
        for path in cls.certificates.glob('*.key'):
            path.chmod(0o600)
        (cls.certificates / 'transfer-signer.pem').chmod(0o644)

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.setup = setup_module.Setup(self.root)
        self.agent_binary_stub(0)

    def test_remote_control_intent_blocks_maintenance_and_is_preserved(self):
        pending = self.setup.path(setup_module.STATE + '/remote-management-pending.json')
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text('{"evidence":"retained"}')
        with self.assertRaisesRegex(RuntimeError, 'remote management control recovery'):
            self.setup.guard_transactions()
        with self.assertRaisesRegex(RuntimeError, 'remote management control recovery'):
            self.setup.guard_writer()
        self.assertEqual(pending.read_text(), '{"evidence":"retained"}')

    def test_firewall_boot_restore_preserves_uncertain_intent_and_settled_receipt(self):
        folder = self.setup.path(setup_module.STATE + '/firewall/boot-restore')
        folder.mkdir(parents=True, mode=0o700)
        pending = folder / 'pending.json'
        pending.write_bytes(b'{"retained":"original intent"}')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'original confirmed firewall boot restore'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())
        pending.rename(folder / 'boot.receipt.json')
        self.setup.guard_writer()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'boot restore records require an explicit verified archive'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())

    def test_firewall_boot_unit_requires_exact_identity_and_an_inactive_actor(self):
        vendor = self.setup.path(setup_module.FIREWALL_BOOT_VENDOR)
        vendor.parent.mkdir(parents=True)
        content = (Path(__file__).parent / setup_module.FIREWALL_BOOT_UNIT).read_bytes()
        vendor.write_bytes(content)
        meta = self.setup.path(setup_module.FIREWALL_BOOT_META)
        meta.parent.mkdir(parents=True)
        pair = {'schemaVersion': 1, 'runtimeProfile': 'legacy-root-v1',
                'unitPath': setup_module.FIREWALL_BOOT_VENDOR,
                'unitSha256': hashlib.sha256(content).hexdigest()}
        meta.write_text(json.dumps(pair))

        with patch.object(self.setup, 'reader_file', side_effect=lambda name, **_kw: self.setup.path(name).read_bytes()), \
                patch.object(self.setup, 'systemctl') as manager:
            base = ('LoadState=loaded\nFragmentPath=' + setup_module.FIREWALL_BOOT_VENDOR + '\n'
                    'DropInPaths=\nUnitFileState=enabled\n')
            manager.return_value = types.SimpleNamespace(stdout=base + 'MainPID=0\nActiveState=inactive\n')
            self.assertEqual('enabled', self.setup.guard_firewall_boot_unit())
            manager.return_value.stdout = base + 'MainPID=8\nActiveState=activating\n'
            with self.assertRaisesRegex(RuntimeError, 'actor is still executing'):
                self.setup.guard_firewall_boot_unit()
            meta.write_text(json.dumps({**pair, 'unitSha256': '0' * 64}))
            with self.assertRaisesRegex(RuntimeError, 'manifest differ'):
                self.setup.guard_firewall_boot_unit()

    def test_external_firewall_boot_unit_is_never_disabled_by_the_package(self):
        custom = self.root / 'etc/systemd/system' / setup_module.FIREWALL_BOOT_UNIT
        custom.parent.mkdir(parents=True)
        custom.write_text('site-owned configuration')
        with patch.object(self.setup, 'systemctl') as manager:
            with self.assertRaisesRegex(RuntimeError, 'Externally supplied'):
                self.setup.guard_firewall_boot_unit()
            manager.assert_not_called()
        self.assertEqual('site-owned configuration', custom.read_text())

    def test_root_fence_publisher_requires_exact_package_bytes_and_current_unit(self):
        operation = str(uuid.uuid4())
        supplied = b'packaged fixture'
        digest = hashlib.sha256(supplied).hexdigest()
        vendor = setup_module.ROOT_FENCE_VENDOR
        meta = {'schemaVersion': 1, 'unitPath': vendor, 'coreLoaderSha256': digest}
        meta.update({key: digest for key in ('unitSha256', 'sourceManifestSha256', 'setupSha256',
                                            'binarySha256', 'bridgeSha256')})
        effective = {'LoadState': 'loaded', 'FragmentPath': vendor, 'DropInPaths': '', 'ActiveState': 'activating',
                     'User': 'root', 'Group': 'kura-management', 'NoNewPrivileges': 'yes',
                     'ProtectSystem': 'strict', 'CapabilityBoundingSet': ''}
        agent = {'ActiveState': 'active', 'FragmentPath': '/usr/lib/systemd/system/' + setup_module.UNIT,
                 'MainPID': '329', 'ExecStart': '{ path=/usr/bin/yofc-management-agent ; argv[]=/usr/bin/yofc-management-agent ; }'}

        def file(name, **_limits):
            if name == setup_module.ROOT_FENCE_META:
                return json.dumps(meta).encode()
            if name.endswith('/package-v1'):
                return b'kura-management-agent-v1\n'
            return supplied

        def systemd(_verb, name, _fields):
            values = agent if name == setup_module.UNIT else effective
            return types.SimpleNamespace(stdout=''.join(f'{k}={v}\n' for k, v in values.items()))

        with patch.object(self.setup, 'reader_file', side_effect=file), \
                patch.object(self.setup, 'guard_core_loader') as loader, \
                patch.object(self.setup, 'systemctl', side_effect=systemd), patch.object(self.setup, 'run') as run:
            self.setup.publish_nm_fence(operation)
            loader.assert_called_once_with(digest)
            run.assert_called_once_with(['/usr/bin/yofc-management-agent', 'publish-original-nm-fence',
                                         operation, '329'], check=True, timeout=85)
            run.reset_mock()
            effective['DropInPaths'] = '/etc/systemd/system/replacement.conf'
            with self.assertRaisesRegex(RuntimeError, 'unit differs'):
                self.setup.publish_nm_fence(operation)
            meta['binarySha256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'package file changed'):
                self.setup.publish_nm_fence(operation)
            run.assert_not_called()

    def test_handoff_evidence_without_main_recovery_journal_blocks_package_changes(self):
        commands = self.setup.path(setup_module.STATE + '/recovery/commands')
        commands.mkdir(parents=True, mode=0o700)
        self.setup.guard_transactions()
        path = commands / 'retained.json'
        path.write_bytes(b'{"unlinked":true}')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'handoff command evidence'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def nm_handover_record(self, directory, name, value):
        folder = self.setup.path(setup_module.STATE + '/' + directory)
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = folder / name
        data = json.dumps(value, separators=(',', ':')).encode()
        path.write_bytes(data)
        path.chmod(0o600)
        return hashlib.sha256(data).hexdigest()

    def test_nm_prepared_fence_intent_and_orphan_export_block_maintenance_without_changes(self):
        operation = str(uuid.uuid4())
        for phase in ('PREPARED', 'FENCE_INTENT', 'FENCED', 'LEASE_INTENT'):
            self.nm_handover_record('nm-ownership', 'transaction.json', {
                'schemaVersion': 1, 'operationId': operation, 'state': phase,
            })
            before = self.snapshot()
            with self.assertRaisesRegex(RuntimeError, 'Settle the original NM handover'):
                self.setup.guard_writer()
            with self.assertRaisesRegex(RuntimeError, 'Settle the original NM handover'):
                self.setup.purge()
            self.assertEqual(before, self.snapshot())
        self.setup.path(setup_module.STATE + '/nm-ownership/transaction.json').unlink()
        self.nm_handover_record('nm-template', operation + '.intent.json', {'operationId': operation})
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Missing or unreadable original NM handover evidence'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def test_nm_cancelled_original_receipt_allows_maintenance_and_blocks_purge(self):
        operation = str(uuid.uuid4())
        intent_sha = self.nm_handover_record('nm-template', operation + '.intent.json', {'operationId': operation})
        self.nm_handover_record('nm-template', 'transaction.json', {
            'schemaVersion': 1, 'operationId': operation, 'phase': 'CANCELLED',
            'intentSha256': intent_sha, 'receiptSha256': None,
        })
        cancellation = {'schemaVersion': 1, 'operationId': operation, 'intentSha256': intent_sha,
                        'state': 'CANCELLED', 'readyReceiptSha256': None}
        self.nm_handover_record('nm-template', operation + '.cancel.json', cancellation)
        before = self.snapshot()
        self.setup.guard_writer()
        with self.assertRaisesRegex(RuntimeError, 'explicit verified archive'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())
        self.nm_handover_record('nm-template', operation + '.cancel.json',
                                {**cancellation, 'operationId': str(uuid.uuid4())})
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'cancellation does not match'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def test_nm_ready_template_requires_the_same_committed_original_plan_and_receipt(self):
        operation = str(uuid.uuid4())
        intent_sha = self.nm_handover_record('nm-template', operation + '.intent.json', {'operationId': operation})
        binding = {'operationId': operation, 'intentSha256': intent_sha,
                   'manifestSha256': 'a' * 64, 'templateSha256': 'b' * 64, 'chunkCount': 1}
        ready_sha = self.nm_handover_record('nm-template', operation + '.receipt.json',
                                            {'schemaVersion': 1, **binding})
        self.nm_handover_record('nm-template', 'transaction.json', {
            'schemaVersion': 1, 'operationId': operation, 'phase': 'READY',
            'intentSha256': intent_sha, 'receiptSha256': ready_sha, 'manifestSha256': binding['manifestSha256'],
        })
        with self.assertRaisesRegex(RuntimeError, 'Settle the original NM handover'):
            self.setup.guard_writer()
        plan_sha = self.nm_handover_record('nm-ownership', operation + '.intent.json', {
            'operationId': operation, 'template': {**binding, 'receiptSha256': ready_sha},
        })
        lease = {'operationId': operation, 'planSha256': plan_sha}
        lease_sha = self.nm_handover_record('nm-ownership', operation + '.lease.json', lease)
        receipt_sha = self.nm_handover_record('nm-ownership', operation + '.receipt.json', {
            'schemaVersion': 1, 'operationId': operation, 'planSha256': plan_sha, 'state': 'COMMITTED',
            'leaseSha256': lease_sha,
        })
        self.nm_handover_record('nm-ownership', 'transaction.json', {
            'schemaVersion': 1, 'operationId': operation, 'state': 'COMMITTED',
            'planSha256': plan_sha, 'receiptSha256': receipt_sha,
        })
        self.setup.guard_writer()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'explicit verified archive'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())
        self.nm_handover_record('nm-ownership', operation + '.lease.json', {**lease, 'future': True})
        with self.assertRaisesRegex(RuntimeError, 'evidence changed'):
            self.setup.guard_writer()

    def test_interrupted_remote_resolution_alone_still_blocks_maintenance(self):
        pending = self.setup.path(setup_module.STATE + '/remote-management-resolution.json')
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text('{"evidence":"original intent already archived"}')
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'remote management control recovery'):
            self.setup.guard_writer()
        self.assertEqual(before,self.snapshot())

    def test_identity_enrollment_intent_blocks_package_changes(self):
        pending = self.setup.path(setup_module.STATE + '/identity-enrollment-pending.json')
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text('preserve uncertain identity')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'remote management control recovery'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def test_managed_candidates_cannot_be_purged_or_imported_over(self):
        self.setup.init_local()
        candidate = self.setup.path(setup_module.STATE + '/enrollment/candidates/rejected')
        candidate.mkdir(parents=True)
        (candidate / 'retained').write_text('evidence')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'explicit verified archive'):
            self.setup.purge()
        with patch.object(self.setup, 'inactive'):
            with self.assertRaisesRegex(RuntimeError, 'import cannot replace'):
                self.setup.import_identity('https://example.invalid', 'gateway', 'ca', 'cert', 'key')
        self.assertEqual(before, self.snapshot())

    def test_managed_identity_allows_start_with_enabled_durable_decision(self):
        self.setup.init_local()
        pointer = self.setup.path(setup_module.STATE + '/enrollment/identity.json')
        pointer.parent.mkdir(parents=True)
        pointer.write_text('Rust startup must validate this, not package check')
        decision = self.setup.path(setup_module.STATE + '/remote-management.json')
        decision.write_text(json.dumps(dict(version=1, revision=str(__import__('uuid').uuid4()), enabled=True, actor='explicit-admin')))
        decision.chmod(0o600)
        before = self.snapshot()
        self.setup.check()
        self.assertEqual(before, self.snapshot())

    def test_clean_local_install_is_keyless_disabled_and_repeat_is_read_only(self):
        self.assertTrue(self.setup.init_local())
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_REMOTE_ENABLED'], '0')
        self.assertEqual(settings['AGENT_KURA_REMOTE_MANAGEMENT'], '0')
        self.assertFalse(any(k in settings for k in ['AGENT_CA', 'AGENT_KEY', 'AGENT_GATEWAY_ID']))
        before = self.snapshot()
        self.assertFalse(self.setup.init_local())
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.setup.path(setup_module.CONFIG + '/agent.env').stat().st_mode & 0o777, 0o600)

    def test_absent_settings_with_retained_state_is_not_a_new_install(self):
        p = self.setup.path(setup_module.STATE + '/results.sqlite')
        p.parent.mkdir(parents=True)
        p.write_bytes(b'retained')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'explicit recovery'):
            self.setup.init_local()
        self.assertEqual(before, self.snapshot())

    def test_first_identity_binds_local_install_without_losing_local_choices(self):
        self.setup.init_local()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        local = self.setup.settings()
        local['AGENT_KURA_REMOTE_MANAGEMENT'] = '1'
        self.setup.replace(env, self.setup.serialize(local))
        before = env.read_bytes()
        self.install()
        current = self.setup.check()
        self.assertEqual(current['AGENT_GATEWAY_ID'], 'registered-gateway')
        self.assertEqual(current['AGENT_REMOTE_ENABLED'], '0')
        self.assertEqual(current['AGENT_KURA_REMOTE_MANAGEMENT'], '1')
        self.assertEqual(self.setup.path(setup_module.CONFIG + '/local-enrollment-before.env').read_bytes(), before)
        after = self.snapshot()
        self.install()
        self.assertEqual(after, self.snapshot())

    def test_failed_first_binding_keeps_intent_local_backup_and_blocks_retry(self):
        self.setup.init_local()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        before = env.read_bytes()
        with patch.object(self.setup, 'replace_bytes', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(env.read_bytes(), before)
        self.assertTrue(self.setup.path(setup_module.CONFIG + '/.identity-installing').exists())
        retained = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.setup.check()
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertEqual(retained, self.snapshot())

    def test_legacy_remote_decision_is_explicit_and_cannot_be_overwritten(self):
        self.install()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        legacy = self.setup.settings()
        legacy.pop('AGENT_REMOTE_ENABLED')
        self.setup.replace(env, self.setup.serialize(legacy))
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'migrate-remote-control'):
            self.setup.check()
        self.assertEqual(before, self.snapshot())
        self.setup.migrate_remote_control(True, 'local-admin')
        self.setup.check()
        record = json.loads(self.setup.path(setup_module.STATE + '/remote-management.json').read_bytes())
        self.assertIs(record['enabled'], True)
        self.assertEqual(record['actor'], 'migration:local-admin')
        self.assertEqual(env.read_bytes(), before[str(env.relative_to(self.root))])
        after = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.setup.migrate_remote_control(False, 'local-admin')
        self.assertEqual(after, self.snapshot())

    def test_partial_identity_and_unbound_remote_enable_are_rejected(self):
        self.setup.init_local()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        settings = self.setup.settings()
        settings['AGENT_REMOTE_ENABLED'] = '1'
        self.setup.replace(env, self.setup.serialize(settings))
        with self.assertRaisesRegex(RuntimeError, 'Unbound agent'):
            self.setup.check()
        settings['AGENT_REMOTE_ENABLED'] = '0'
        settings['AGENT_CERT'] = setup_module.CONFIG + '/agent.pem'
        self.setup.replace(env, self.setup.serialize(settings))
        with self.assertRaisesRegex(RuntimeError, 'Binding generation'):
            self.setup.check()

    def test_old_binding_generation_and_remote_decision_migrate_separately(self):
        self.install()
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        settings = self.setup.settings()
        settings.pop('AGENT_BINDING_GENERATION')
        settings.pop('AGENT_REMOTE_ENABLED')
        self.setup.replace(env, self.setup.serialize(settings))
        self.setup.migrate_binding_generation()
        self.assertEqual(self.setup.settings()['AGENT_BINDING_GENERATION'], '1')
        with self.assertRaisesRegex(RuntimeError, 'migrate-remote-control'):
            self.setup.check()
        self.setup.migrate_remote_control(False, 'migration-admin')
        self.setup.check()
        self.assertIs(json.loads(self.setup.path(setup_module.STATE + '/remote-management.json').read_bytes())['enabled'], False)

    def agent_binary_stub(self, code):
        """Stand-in installed agent binary; exit 0 models an ACTIVE revocation check."""
        binary = self.root / 'usr/bin/yofc-management-agent'
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text('#!/bin/sh\nexit %d\n' % code)
        binary.chmod(0o755)

    def install(self, endpoint='https://console.example.invalid:8443', key='agent.key', signer=False):
        self.setup.import_identity(endpoint, 'registered-gateway', self.certificates / 'ca.pem',
                                   self.certificates / 'agent.pem', self.certificates / key,
                                   self.certificates / 'transfer-signer.pem' if signer else None)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}

    def transfer_token(self, endpoint='https://new-console.example.invalid:8443', generation=1,
                       gateway='registered-gateway', ca_hash=None, cert_hash=None, expires=600,
                       signer='transfer-signer.private.pem', payload_override=None):
        from contextlib import closing
        if payload_override is not None:
            payload=payload_override
        else:
            payload=json.dumps({
                'schema':'yofc.agent.transfer.v1','transferId':'token-test',
                'gatewayId':gateway,'fromBindingGeneration':generation,
                'toBindingGeneration':generation+1,'newEndpoint':endpoint,
                'newGatewayId':gateway,
                'newClientCertificateSha256':cert_hash or ('c'*64),
                'newClientCaSha256':ca_hash or ('a'*64),
                'expiresAtUnixMs':int((time.time() + expires) * 1000)
            },separators=(',',':')).encode()
        openssl_bin=OPENSSL
        payload_path=self.certificates/'transfer-payload'
        payload_path.write_bytes(payload)
        signature=subprocess.check_output([openssl_bin,'pkeyutl','-sign','-rawin','-inkey',
                                           str(self.certificates/signer),'-in',str(payload_path)])
        encoded=__import__('base64').urlsafe_b64encode(payload).decode()
        encoded += '=' * (-len(encoded) % 4)
        token='YOFC-AGENT-TRANSFER-v1\n' + encoded + '\n' + signature.hex() + '\n'
        path=self.certificates/'transfer-token'
        path.write_text(token)
        return path

    def rotation_token(self, generation=1, gateway='registered-gateway', expires=600,
                       from_signer='transfer-signer.pem', signing_private='transfer-signer.private.pem',
                       to_signer='transfer-signer-2.pem', operator='local-admin',
                       payload_override=None, rotation_id='rotation-test'):
        if payload_override is not None:
            payload=payload_override
        else:
            from_spki = self.setup.public_spki_sha256(self.certificates / from_signer)
            to_spki = self.setup.public_spki_sha256(self.certificates / to_signer)
            payload = json.dumps({
                'schema': 'yofc.agent.transfer-signer-rotation.v1', 'rotationId': rotation_id,
                'gatewayId': gateway, 'bindingGeneration': generation,
                'fromSignerSpkiSha256': from_spki, 'toSignerSpkiSha256': to_spki,
                'operator': operator, 'expiresAtUnixMs': int((time.time() + expires) * 1000)
            }, separators=(',', ':')).encode()
        openssl_bin = OPENSSL
        payload_path = self.certificates / 'rotation-payload'
        payload_path.write_bytes(payload)
        signature=subprocess.check_output([openssl_bin,'pkeyutl','-sign','-rawin','-inkey',
                                           str(self.certificates/signing_private),'-in',str(payload_path)])
        encoded=__import__('base64').urlsafe_b64encode(payload).decode()
        encoded += '=' * (-len(encoded) % 4)
        token='YOFC-AGENT-SIGNER-ROTATION-v1\n' + encoded + '\n' + signature.hex() + '\n'
        try:
            rotation_id=json.loads(payload)['rotationId']
        except Exception:
            rotation_id='unknown'
        path=self.certificates/('rotation-token-'+str(rotation_id))
        path.write_text(token)
        return path

    def make_bundle(self, gateway='registered-gateway', endpoint='https://console.example.invalid:8443',
                    ca='ca.pem', cert='agent.pem', key='agent.key', manifest_override=None, members=None,
                    purpose='identity', previous=None):
        import hashlib as hashlib_module
        ca_pem = (self.certificates / ca).read_bytes()
        cert_pem = (self.certificates / cert).read_bytes()
        key_pem = (self.certificates / key).read_bytes()

        def fingerprint(value):
            lines = [line.strip() for line in value.decode().splitlines() if line.strip()]
            return hashlib_module.sha256(base64.b64decode(''.join(lines[1:-1]), validate=True)).hexdigest()

        manifest = {
            'schemaVersion': 1, 'gatewayId': gateway, 'purpose': purpose,
            'caFingerprint': fingerprint(ca_pem), 'certificateFingerprint': fingerprint(cert_pem),
        }
        if purpose == 'identity':
            manifest['endpoint'] = endpoint
        if purpose == 'rotation':
            manifest['previousCertificateSha256'] = previous or fingerprint((self.certificates / 'agent.pem').read_bytes())
        if manifest_override is not None:
            manifest.update(manifest_override)
        payloads = members if members is not None else {
            'manifest.json': (json.dumps(manifest) + '\n').encode(),
            'ca.pem': ca_pem, 'agent.pem': cert_pem, 'agent.key': key_pem,
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name in ('manifest.json', 'ca.pem', 'agent.pem', 'agent.key'):
                info = tarfile.TarInfo(name)
                info.size = len(payloads[name])
                archive.addfile(info, io.BytesIO(payloads[name]))
        target = self.root / 'bundle.tar'
        target.write_bytes(buffer.getvalue())
        return target

    def test_bundle_import_binds_identity_and_is_idempotent(self):
        target = self.make_bundle()
        self.setup.import_bundle(target)
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_GATEWAY_ID'], 'registered-gateway')
        self.assertEqual(settings['AGENT_CONSOLE_ENDPOINT'], 'https://console.example.invalid:8443')
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '1')
        for name in ('ca.pem', 'agent.pem', 'agent.key', 'agent.env'):
            self.assertEqual((self.setup.path(setup_module.CONFIG) / name).stat().st_mode & 0o777, 0o600)
        self.setup.inactive()
        before = self.snapshot()
        self.setup.import_bundle(target)
        self.assertEqual(before, self.snapshot())

    def test_bundle_manifest_fingerprint_mismatch_is_refused(self):
        target = self.make_bundle(manifest_override={'certificateFingerprint': '0' * 64})
        with self.assertRaisesRegex(RuntimeError, 'fingerprints do not match'):
            self.setup.import_bundle(target)

    def test_bundle_rejects_extra_members_and_compressed_archive(self):
        payloads = {
            'manifest.json': b'{"schemaVersion":1}', 'ca.pem': b'x', 'agent.pem': b'y',
            'agent.key': b'z', 'extra.sh': b'echo pwned',
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, value in payloads.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        target = self.root / 'extra.tar'
        target.write_bytes(buffer.getvalue())
        with self.assertRaisesRegex(RuntimeError, 'exactly the four identity files'):
            self.setup.import_bundle(target)
        compressed = self.root / 'compressed.tar.gz'
        gz = io.BytesIO()
        with tarfile.open(fileobj=gz, mode='w:gz') as archive:
            info = tarfile.TarInfo('manifest.json')
            archive.addfile(info, io.BytesIO(b'{}'))
        compressed.write_bytes(gz.getvalue())
        with self.assertRaisesRegex(RuntimeError, 'uncompressed ustar'):
            self.setup.import_bundle(compressed)

    def test_bundle_symlink_member_is_refused(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            info = tarfile.TarInfo('agent.key')
            info.type = tarfile.SYMTYPE
            info.linkname = '/etc/shadow'
            archive.addfile(info)
        target = self.root / 'symlink.tar'
        target.write_bytes(buffer.getvalue())
        with self.assertRaisesRegex(RuntimeError, 'four identity files'):
            self.setup.import_bundle(target)

    def test_rotate_bundle_replaces_identity_and_keeps_binding(self):
        self.install()
        settings_before = self.setup.check()
        rotated_cert = self.certificates / 'rotated.pem'
        rotated_key = self.certificates / 'rotated.key'
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=package-test-agent-2',
                        '-keyout', str(rotated_key), '-out', str(self.certificates / 'rotated.csr')],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-req', '-in', str(self.certificates / 'rotated.csr'),
                        '-CA', str(self.certificates / 'ca.pem'), '-CAkey', str(self.certificates / 'ca.key'),
                        '-CAcreateserial', '-days', '1', '-extfile', str(self.certificates / 'client.ext'),
                        '-out', str(rotated_cert)], check=True, capture_output=True)
        rotated_key.chmod(0o600)
        import hashlib as hashlib_module
        def fingerprint(value):
            lines = [line.strip() for line in value.decode().splitlines() if line.strip()]
            return hashlib_module.sha256(base64.b64decode(''.join(lines[1:-1]), validate=True)).hexdigest()
        previous = fingerprint((self.certificates / 'agent.pem').read_bytes())
        target = self.make_bundle(cert='rotated.pem', key='rotated.key', purpose='rotation', previous=previous)
        self.setup.inactive()
        self.setup.rotate_bundle(target, 'rotation-operator')
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_GATEWAY_ID'], settings_before['AGENT_GATEWAY_ID'])
        self.assertEqual(settings['AGENT_CONSOLE_ENDPOINT'], settings_before['AGENT_CONSOLE_ENDPOINT'])
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], settings_before['AGENT_BINDING_GENERATION'])
        installed = fingerprint(self.setup.path(setup_module.CONFIG).joinpath('agent.pem').read_bytes())
        self.assertEqual(installed, fingerprint(rotated_cert.read_bytes()))
        rotations = sorted((self.setup.path(setup_module.STATE) / 'certificate-rotations').iterdir())
        self.assertEqual(len(rotations), 1)
        receipt = json.loads((rotations[0] / 'receipt.json').read_text())
        self.assertEqual(receipt['operator'], 'rotation-operator')

    def test_rotate_bundle_refuses_wrong_previous_fingerprint_and_identity_purpose(self):
        self.install()
        wrong_previous = self.make_bundle(purpose='rotation', previous='0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'different installed certificate'):
            self.setup.rotate_bundle(wrong_previous, 'operator')
        identity_bundle = self.make_bundle()
        with self.assertRaisesRegex(RuntimeError, 'Rotation requires a rotation-purpose bundle'):
            self.setup.rotate_bundle(identity_bundle, 'operator')
        rotation_for_import = self.make_bundle(purpose='rotation')
        with self.assertRaisesRegex(RuntimeError, 'Identity import requires an identity-purpose bundle'):
            self.setup.import_bundle(rotation_for_import)

    def test_csr_mode_never_exports_the_private_key(self):
        csr_out = self.root / 'gw-csr-1.csr'
        self.setup.create_certificate_request('gw-csr-1', csr_out)
        self.assertTrue(csr_out.is_file())
        csr_text = csr_out.read_text()
        self.assertIn('BEGIN CERTIFICATE REQUEST', csr_text)
        pending = self.setup.path(setup_module.STATE + '/certificate-requests/pending.json')
        record = json.loads(pending.read_text())
        self.assertEqual(record['schema'], 'yofc.agent.certificate-request.v1')
        self.assertEqual(record['gatewayId'], 'gw-csr-1')
        # the locally generated key stays on the box; only the CSR was handed out
        pending_key = self.setup.path(setup_module.STATE + '/certificate-requests/agent.key')
        self.assertEqual(pending_key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.setup.path(setup_module.STATE + '/certificate-requests')).stat().st_mode & 0o777, 0o700)
        # second request is refused while one is pending
        with self.assertRaisesRegex(RuntimeError, 'pending certificate request already exists'):
            self.setup.create_certificate_request('gw-csr-1', self.root / 'second.csr')
        # issue the certificate externally and activate: identity binds the local key
        pending_key_bytes = pending_key.read_bytes()
        issued_cert = self.certificates / 'csr-issued.pem'
        subprocess.run(['openssl', 'x509', '-req', '-sha256', '-in', str(csr_out),
                        '-CA', str(self.certificates / 'ca.pem'), '-CAkey', str(self.certificates / 'ca.key'),
                        '-CAcreateserial', '-days', '1', '-extfile', str(self.certificates / 'client.ext'),
                        '-out', str(issued_cert)], check=True, capture_output=True)
        self.setup.activate_pending_certificate('https://console.example.invalid:8443',
                                                self.certificates / 'ca.pem', issued_cert)
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_GATEWAY_ID'], 'gw-csr-1')
        self.assertEqual(settings['AGENT_CONSOLE_ENDPOINT'], 'https://console.example.invalid:8443')
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '1')
        installed_key = self.setup.path(setup_module.CONFIG + '/agent.key').read_bytes()
        self.assertEqual(installed_key, pending_key_bytes)
        self.assertFalse(self.setup.path(setup_module.STATE + '/certificate-requests').exists())

    def csr_publication_race(self, kind):
        output = self.root / 'race.csr'
        protected = self.root / 'protected'
        protected.write_bytes(b'protected before CSR generation')
        protected.chmod(0o600)
        original_run = self.setup.run
        injected = False

        def racing_run(arguments, **kwargs):
            nonlocal injected
            if len(arguments) > 1 and arguments[1] == 'genpkey' and not injected:
                injected = True
                if kind == 'symlink':
                    output.symlink_to(protected)
                elif kind == 'hardlink':
                    os.link(protected, output)
                else:
                    output.write_bytes(b'concurrent operator file')
                    output.chmod(0o600)
            return original_run(arguments, **kwargs)

        self.setup.run = racing_run
        rejected = False
        try:
            self.setup.create_certificate_request('race-agent', output)
        except FileExistsError:
            rejected = True
        self.assertTrue(injected)
        self.assertEqual(protected.read_bytes(), b'protected before CSR generation')
        self.assertEqual(protected.stat().st_mode & 0o777, 0o600)
        if kind == 'regular':
            self.assertEqual(output.read_bytes(), b'concurrent operator file')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertTrue(rejected, 'a path created during key generation must be refused')
        pending = self.setup.path(setup_module.STATE + '/certificate-requests')
        self.assertIn('BEGIN CERTIFICATE REQUEST', (pending / 'request.csr').read_text())
        self.assertEqual((pending / 'agent.key').stat().st_mode & 0o777, 0o600)

    def test_csr_publication_race_symlink_never_overwrites_or_chmods_target(self):
        self.csr_publication_race('symlink')

    def test_csr_publication_race_hardlink_never_overwrites_or_chmods_target(self):
        self.csr_publication_race('hardlink')

    def test_csr_publication_race_regular_file_is_preserved(self):
        self.csr_publication_race('regular')

    def test_csr_publication_race_replaced_parent_is_refused(self):
        parent = self.root / 'output'
        parent.mkdir()
        protected = self.root / 'protected-output'
        protected.mkdir()
        saved = self.root / 'original-output'
        original_run = self.setup.run
        def racing_run(arguments, **kwargs):
            if len(arguments) > 1 and arguments[1] == 'genpkey' and parent.is_dir() and not parent.is_symlink():
                parent.rename(saved)
                parent.symlink_to(protected, target_is_directory=True)
            return original_run(arguments, **kwargs)
        self.setup.run = racing_run
        rejected = False
        try:
            self.setup.create_certificate_request('race-agent', parent / 'race.csr')
        except RuntimeError as error:
            self.assertIn('CSR output directory changed', str(error))
            rejected = True
        self.assertEqual(list(protected.iterdir()), [])
        self.assertEqual(list(saved.iterdir()), [])
        self.assertTrue(rejected)

    def test_csr_activation_rejects_mismatched_certificate(self):
        self.setup.create_certificate_request('gw-csr-2', self.root / 'gw-csr-2.csr')
        other_key = self.certificates / 'agent.key'
        # the issued cert corresponds to a different key than the pending one
        with self.assertRaisesRegex(RuntimeError, 'does not match the locally generated key'):
            self.setup.activate_pending_certificate('https://console.example.invalid:8443',
                                                    self.certificates / 'ca.pem',
                                                    self.certificates / 'agent.pem')
        # identity was not installed by the failed activation
        env = self.setup.path(setup_module.CONFIG + '/agent.env')
        self.assertFalse(env.exists())

    def test_csr_request_refuses_when_identity_installed(self):
        self.install()
        with self.assertRaisesRegex(RuntimeError, 'use rotate-client-certificate'):
            self.setup.create_certificate_request('registered-gateway', self.root / 'x.csr')

    def test_bundle_import_requires_stopped_agent(self):
        target = self.make_bundle()
        self.install()
        self.agent_binary_stub(0)
        # import_identity refuses while the (stubbed) service is running.
        with patch.object(setup_module.Setup, 'systemctl') as systemctl:
            systemctl.return_value = types.SimpleNamespace(stdout='MainPID=42\nActiveState=active\n')
            with self.assertRaisesRegex(RuntimeError, 'Stop the packaged agent'):
                self.setup.import_bundle(target)

    def test_import_is_private_idempotent_and_observation_only(self):
        self.install()
        before = self.snapshot()
        self.install()
        self.assertEqual(before, self.snapshot())
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_NETWORK_INTERFACES'], '')
        self.assertEqual(settings['AGENT_KURA_NETWORK_INTERFACES'], '')
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

    def test_signed_transfer_requires_registered_signer_and_exact_claims(self):
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        token=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        self.install(signer=False)
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'Signed transfer requires'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',token)
        self.assertEqual(before,self.snapshot())
        # Install into a distinct temporary root to prove signer registration is explicit.
        replacement_dir=tempfile.TemporaryDirectory()
        self.addCleanup(replacement_dir.cleanup)
        replacement=setup_module.Setup(Path(replacement_dir.name))
        replacement.setup=setup_module.Setup(Path(replacement_dir.name))
        stub=replacement.setup.path('/usr/bin/yofc-management-agent')
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text('#!/bin/sh\nexit 0\n')
        stub.chmod(0o755)
        replacement.setup.import_identity('https://console.example.invalid:8443','registered-gateway',
                                          self.certificates/'ca.pem',self.certificates/'agent.pem',
                                          self.certificates/'agent.key',
                                          self.certificates/'transfer-signer.pem')
        replacement.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                            self.certificates/'ca.pem',self.certificates/'agent.pem',
                                            self.certificates/'agent.key',1,'local-admin',token)
        settings=replacement.setup.check()
        self.assertEqual(settings['AGENT_BINDING_GENERATION'],'2')
        receipt=json.loads((replacement.setup.path(setup_module.STATE+'/transfers/2/receipt.json')).read_text())
        self.assertEqual(receipt['authorization'],'original-center-signed-transfer')
        self.assertEqual(receipt['transferId'],'token-test')

    def test_transfer_signer_registration_is_explicit_private_and_generation_bound(self):
        self.install(signer=False)
        before=self.snapshot()
        public=self.certificates/'transfer-signer.pem'
        with self.assertRaisesRegex(RuntimeError,'Binding generation changed'):
            self.setup.register_transfer_signer(public,99,'local-admin')
        self.assertEqual(before,self.snapshot())
        self.setup.register_transfer_signer(public,1,'local-admin')
        settings=self.setup.check()
        signer=self.setup.path(setup_module.TRANSFER_SIGNER)
        self.assertTrue(signer.is_file())
        self.assertEqual(signer.stat().st_mode & 0o777,0o644)
        receipt_path=self.setup.path(setup_module.STATE+'/transfer-signer-registrations/generation-1.json')
        receipt=json.loads(receipt_path.read_text())
        self.assertEqual(receipt['bindingGeneration'],1)
        self.assertEqual(receipt['operator'],'local-admin')
        # Same signer is idempotent.
        before=self.snapshot()
        self.setup.register_transfer_signer(public,1,'local-admin')
        self.assertEqual(before,self.snapshot())
        # A different signer cannot silently replace the registered authority.
        other=self.certificates/'transfer-signer-2.pem'
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'different transfer signer'):
            self.setup.register_transfer_signer(other,1,'local-admin')
        self.assertEqual(before,self.snapshot())

    def test_public_authority_never_accepts_private_key_or_certificate_pem(self):
        self.install(signer=False)
        before = self.snapshot()
        for name in ['ca.key', 'transfer-signer.private.pem', 'ca.pem']:
            with self.assertRaisesRegex(RuntimeError, 'Ed25519 public key'):
                self.setup.register_transfer_signer(self.certificates / name, 1, 'local-admin')
            self.assertEqual(before, self.snapshot())

    def test_registered_signer_allows_signed_transfer(self):
        self.install(signer=False)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        token=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        self.setup.register_transfer_signer(self.certificates/'transfer-signer.pem',1,'local-admin')
        self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                     self.certificates/'ca.pem',self.certificates/'agent.pem',
                                     self.certificates/'agent.key',1,'local-admin',token)
        settings=self.setup.check()
        self.assertEqual(settings['AGENT_BINDING_GENERATION'],'2')
        receipt=json.loads((self.setup.path(setup_module.STATE+'/transfers/2/receipt.json')).read_text())
        self.assertEqual(receipt['authorization'],'original-center-signed-transfer')

    def test_signed_transfer_accepts_unpadded_console_payload(self):
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        padded=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        lines=padded.read_text().splitlines()
        lines[1]=lines[1].rstrip('=')
        unpadded=self.certificates/'unpadded-token'; unpadded.write_text('\n'.join(lines)+'\n')
        self.install(signer=True)
        self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                     self.certificates/'ca.pem',self.certificates/'agent.pem',
                                     self.certificates/'agent.key',1,'local-admin',unpadded)
        self.assertEqual(self.setup.check()['AGENT_BINDING_GENERATION'],'2')

    def test_signed_transfer_rejects_tampering_expiry_and_mismatch(self):
        self.install(signer=True)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        good=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        lines=good.read_text().splitlines()
        lines[2]=('0'*128)
        bad=self.certificates/'bad-token'; bad.write_text('\n'.join(lines)+'\n')
        with self.assertRaisesRegex(RuntimeError,'signature rejected'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',bad)
        expired_payload=json.dumps({'schema':'yofc.agent.transfer.v1','transferId':'expired','gatewayId':'registered-gateway',
            'fromBindingGeneration':1,'toBindingGeneration':2,'newEndpoint':'https://new-console.example.invalid:8443',
            'newGatewayId':'registered-gateway','newClientCertificateSha256':cert_hash,
            'newClientCaSha256':ca_hash,'expiresAtUnixMs':0},separators=(',',':')).encode()
        expired=self.transfer_token(payload_override=expired_payload)
        with self.assertRaisesRegex(RuntimeError,'expired'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',expired)

    def test_current_signer_can_rotate_once_with_exact_claims(self):
        self.install(signer=True)
        current=self.setup.path(setup_module.TRANSFER_SIGNER)
        old=current.read_bytes()
        new=self.certificates/'transfer-signer-2.pem'
        before=self.snapshot()
        token=self.rotation_token()
        self.setup.rotate_transfer_signer(new,1,'local-admin',token)
        self.assertEqual(current.read_bytes(),new.read_bytes())
        self.setup.check()
        self.assertNotEqual(before,self.snapshot())
        rotation_dir=self.setup.path(setup_module.STATE+'/transfer-signer-rotations/generation-1')
        receipt=json.loads((rotation_dir/'receipt.json').read_text())
        self.assertEqual(receipt['rotationId'],'rotation-test')
        self.assertEqual(receipt['bindingGeneration'],1)
        uses=list(self.setup.path(setup_module.STATE+'/transfer-signer-rotations/uses').glob('*.json'))
        self.assertEqual(len(uses),1)
        record=json.loads(uses[0].read_text())
        self.assertEqual(record['rotationId'],'rotation-test')
        with self.assertRaisesRegex(RuntimeError,'already been used'):
            self.setup.consume_rotation_token(token,record,self.setup.check(),1,
                                              self.setup.public_spki_sha256(current),
                                              self.setup.public_spki_sha256(new),'local-admin')

    def test_rotation_rejects_mismatch_expired_and_foreign_authority_without_mutation(self):
        self.install(signer=True)
        new=self.certificates/'transfer-signer-2.pem'
        mismatch_payload=json.dumps({
            'schema':'yofc.agent.transfer-signer-rotation.v1','rotationId':'mismatch',
            'gatewayId':'registered-gateway','bindingGeneration':1,
            'fromSignerSpkiSha256':'0'*64,'toSignerSpkiSha256':'1'*64,
            'operator':'local-admin','expiresAtUnixMs':int((time.time()+600)*1000)
        },separators=(',',':')).encode()
        mismatch=self.rotation_token(payload_override=mismatch_payload)
        cases=[
            ('does not match', mismatch),
            ('expired', self.rotation_token(expires=0,rotation_id='rotation-test-expired')),
            ('signature rejected', self.rotation_token(signing_private='transfer-signer-2.private.pem',rotation_id='rotation-test-foreign')),
        ]
        for message,token in cases:
            before=self.snapshot()
            with self.assertRaisesRegex(RuntimeError,message):
                self.setup.rotate_transfer_signer(new,1,'local-admin',token)
            self.assertEqual(before,self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE+'/transfer-signer-rotations/generation-1').exists())
        self.assertFalse(self.setup.path(setup_module.STATE+'/transfer-signer-rotations/uses').exists())

    def test_transfer_token_use_is_durable_and_blocks_replay(self):
        self.install(signer=True)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        token=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        claims=json.loads(__import__('base64').urlsafe_b64decode(
            token.read_text().splitlines()[1] + '=' * (-len(token.read_text().splitlines()[1]) % 4)))
        current=self.setup.check()
        record=self.setup.consume_transfer_token(
            token,claims,current,1,'https://new-console.example.invalid:8443','registered-gateway',
            ca_hash,cert_hash,'local-admin')
        self.assertEqual(record.stat().st_mode & 0o777,0o600)
        persisted=json.loads(record.read_text())
        self.assertEqual(persisted['schema'],'yofc.agent.transfer-token-use.v1')
        self.assertEqual(persisted['transferId'],'token-test')
        self.assertIn('tokenSha256',persisted)
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'already been used'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',token)
        self.assertEqual(before,self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE+'/transfers/2').exists())

    def test_revoked_transfer_token_is_refused_before_any_change(self):
        self.install(signer=True)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        token=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        self.agent_binary_stub(1)
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'not ACTIVE'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',token)
        self.assertEqual(before,self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE+'/transfer-token-uses').exists())
        self.assertFalse(self.setup.path(setup_module.STATE+'/transfers/2').exists())

    def test_missing_agent_binary_fails_transfer_revocation_closed(self):
        self.install(signer=True)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        token=self.transfer_token(ca_hash=ca_hash,cert_hash=cert_hash)
        shutil.rmtree(self.root/'usr')
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'cannot verify transfer revocation'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',token)
        self.assertEqual(before,self.snapshot())

    def second_client_identity(self):
        """A second client certificate under the SAME package-test CA."""
        directory = self.certificates
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                        '-subj', '/CN=package-test-agent-2', '-keyout', 'agent-2.key',
                        '-out', 'agent-2.csr'], cwd=directory, check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-req', '-in', 'agent-2.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                        '-CAcreateserial', '-days', '1', '-extfile', 'client.ext', '-out', 'agent-2.pem'],
                       cwd=directory, check=True, capture_output=True)
        (directory / 'agent-2.key').chmod(0o600)
        return directory / 'agent-2.pem', directory / 'agent-2.key'

    def test_client_certificate_rotation_backs_up_and_keeps_binding(self):
        self.install()
        new_cert, new_key = self.second_client_identity()
        old_cert_sha = self.setup.certificate_sha256(self.certificates / 'agent.pem')
        receipt = self.setup.rotate_client_certificate(new_cert, new_key, 'local-admin')
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_BINDING_GENERATION'], '1')
        self.assertEqual(settings['AGENT_GATEWAY_ID'], 'registered-gateway')
        self.assertEqual(self.setup.certificate_sha256(self.certificates / 'agent-2.pem'),
                         self.setup.certificate_sha256(self.setup.path(settings['AGENT_CERT'])))
        backup = self.setup.path(setup_module.STATE + '/certificate-rotations/1')
        persisted = json.loads((backup / 'receipt.json').read_text())
        self.assertEqual(persisted['schema'], 'yofc.agent.client-certificate-rotation.v1')
        self.assertEqual(persisted['oldClientCertificateSha256'], old_cert_sha)
        self.assertEqual(persisted['newClientCertificateSha256'], receipt['newClientCertificateSha256'])
        self.assertEqual(self.setup.certificate_sha256(backup / 'agent.pem'), old_cert_sha)
        second = self.setup.rotate_client_certificate(self.certificates / 'agent.pem',
                                                      self.certificates / 'agent.key', 'local-admin')
        self.assertTrue((self.setup.path(setup_module.STATE + '/certificate-rotations/2/receipt.json')).is_file())
        self.assertNotEqual(second['newClientCertificateSha256'], receipt['newClientCertificateSha256'])

    def test_client_certificate_rotation_rejects_mismatch_foreign_ca_and_same_cert(self):
        self.install()
        new_cert, new_key = self.second_client_identity()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'do not match'):
            self.setup.rotate_client_certificate(new_cert, self.certificates / 'agent.key', 'local-admin')
        self.assertEqual(before, self.snapshot())
        foreign = tempfile.TemporaryDirectory()
        self.addCleanup(foreign.cleanup)
        foreign = Path(foreign.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=foreign-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-keyout', 'foreign.key', '-out', 'foreign-ca.pem'], cwd=foreign, check=True, capture_output=True)
        (foreign / 'client.ext').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n')
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=foreign-client',
                        '-keyout', 'foreign-client.key', '-out', 'foreign-client.csr'], cwd=foreign, check=True, capture_output=True)
        (foreign / 'foreign-client.key').chmod(0o600)
        subprocess.run(['openssl', 'x509', '-req', '-in', 'foreign-client.csr', '-CA', 'foreign-ca.pem',
                        '-CAkey', 'foreign.key', '-CAcreateserial', '-days', '1',
                        '-extfile', 'client.ext', '-out', 'foreign-client.pem'],
                       cwd=foreign, check=True, capture_output=True)
        with self.assertRaisesRegex(RuntimeError, 'trust chain'):
            self.setup.rotate_client_certificate(foreign / 'foreign-client.pem',
                                                 foreign / 'foreign-client.key', 'local-admin')
        self.assertEqual(before, self.snapshot())
        with self.assertRaisesRegex(RuntimeError, 'identical'):
            self.setup.rotate_client_certificate(self.certificates / 'agent.pem',
                                                 self.certificates / 'agent.key', 'local-admin')
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.setup.path(setup_module.STATE + '/certificate-rotations').exists())

    def confirmed_writer_state(self, interfaces='eth0,ens5', yaml_text='network:\n  version: 2\n'):
        """Install, grant the writer, and place a settled confirmed state plus managed file."""
        self.install()
        self.setup.grant_network_writer(interfaces, 'local-admin')
        network = self.setup.path(setup_module.STATE + '/network')
        network.mkdir(parents=True, exist_ok=True, mode=0o700)
        confirmed = {'revision': 3, 'yaml': yaml_text}
        (network / 'confirmed.json').write_text(json.dumps(confirmed) + '\n')
        managed = self.setup.path('/etc/netplan/90-yofc-managed.yaml')
        managed.parent.mkdir(parents=True, exist_ok=True)
        managed.write_text(yaml_text)
        return confirmed, managed

    def test_grant_network_writer_requires_clean_state_and_valid_names(self):
        self.install()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'empty entries'):
            self.setup.grant_network_writer('eth0,,dup', 'local-admin')
        with self.assertRaisesRegex(RuntimeError, 'Invalid interface name'):
            self.setup.grant_network_writer('bad name', 'local-admin')
        with self.assertRaisesRegex(RuntimeError, 'unique'):
            self.setup.grant_network_writer('eth0,eth0', 'local-admin')
        self.assertEqual(before, self.snapshot())
        self.setup.grant_network_writer('eth0,ens5', 'local-admin')
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_NETWORK_INTERFACES'], 'eth0,ens5')
        with self.assertRaisesRegex(RuntimeError, 'Hand the current network writer over'):
            self.setup.grant_network_writer('eth9', 'local-admin')
        with self.assertRaisesRegex(RuntimeError, 'writer handover required'):
            self.setup.purge()

    def test_handover_keeps_config_archives_state_and_releases_purge(self):
        confirmed, managed = self.confirmed_writer_state()
        self.setup.handover_network_writer('local-admin')
        settings = self.setup.check()
        self.assertEqual(settings['AGENT_NETWORK_INTERFACES'], '')
        self.assertTrue(managed.exists(), 'default handover keeps the system config file')
        archive = self.setup.path(setup_module.STATE + '/network/handovers/1')
        receipt = json.loads((archive / 'receipt.json').read_text())
        self.assertEqual(receipt['schema'], 'yofc.agent.network-writer-handover.v1')
        self.assertEqual(receipt['interfaces'], 'eth0,ens5')
        self.assertEqual(receipt['revision'], 3)
        self.assertEqual(receipt['keptManagedConfigFile'], True)
        self.assertEqual(json.loads((archive / 'confirmed.json').read_text()), confirmed)
        self.assertFalse(self.setup.path(setup_module.STATE + '/network/confirmed.json').exists())
        self.setup.purge()
        self.assertFalse(self.setup.path(setup_module.CONFIG).exists())

    def test_handover_discard_requires_exact_file_and_refuses_drift(self):
        confirmed, managed = self.confirmed_writer_state()
        managed.write_text('network:\n  version: 2\n  renderer: networkd\n')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'drifted'):
            self.setup.handover_network_writer('local-admin', discard_config=True)
        self.assertEqual(before, self.snapshot())
        managed.write_text(confirmed['yaml'])
        self.setup.handover_network_writer('local-admin', discard_config=True)
        self.assertFalse(managed.exists())
        receipt = json.loads(self.setup.path(setup_module.STATE + '/network/handovers/1/receipt.json').read_text())
        self.assertEqual(receipt['keptManagedConfigFile'], False)

    def test_handover_refuses_unsettled_transaction_and_empty_state(self):
        self.install()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'No network writer or confirmed state'):
            self.setup.handover_network_writer('local-admin')
        self.assertEqual(before, self.snapshot())
        self.setup.grant_network_writer('eth0', 'local-admin')
        network = self.setup.path(setup_module.STATE + '/network')
        network.mkdir(parents=True, exist_ok=True, mode=0o700)
        (network / 'transaction.json').write_text(json.dumps({'state': 'WAIT_CONFIRM'}) + '\n')
        granted = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Settle the network transaction'):
            self.setup.handover_network_writer('local-admin')
        self.assertEqual(granted, self.snapshot())
        (network / 'transaction.json').write_text(json.dumps({'state': 'COMMITTED'}) + '\n')
        self.setup.handover_network_writer('local-admin')
        self.assertEqual(self.setup.check()['AGENT_NETWORK_INTERFACES'], '')

    def test_transfer_token_id_cannot_escape_the_use_ledger(self):
        self.install(signer=True)
        ca_hash=self.setup.certificate_sha256(self.certificates/'ca.pem')
        cert_hash=self.setup.certificate_sha256(self.certificates/'agent.pem')
        payload=json.dumps({'schema':'yofc.agent.transfer.v1','transferId':'../escaped',
            'gatewayId':'registered-gateway','fromBindingGeneration':1,'toBindingGeneration':2,
            'newEndpoint':'https://new-console.example.invalid:8443','newGatewayId':'registered-gateway',
            'newClientCertificateSha256':cert_hash,'newClientCaSha256':ca_hash,
            'expiresAtUnixMs':int((time.time()+600)*1000)},separators=(',',':')).encode()
        token=self.transfer_token(payload_override=payload)
        before=self.snapshot()
        with self.assertRaisesRegex(RuntimeError,'Invalid transfer authorization id'):
            self.setup.transfer_identity('https://new-console.example.invalid:8443','registered-gateway',
                                         self.certificates/'ca.pem',self.certificates/'agent.pem',
                                         self.certificates/'agent.key',1,'local-admin',token)
        self.assertEqual(before,self.snapshot())

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
        unit = self.setup.path('/usr/lib/systemd/system/kura-netplan.service')
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nUser=kura-netplan\n')
        account = types.SimpleNamespace(pw_uid=997, pw_gid=997)
        with patch.object(setup_module.pwd, 'getpwnam', return_value=account):
            self.setup.authorize('kura-netplan')
            self.assertEqual(self.setup.check()['AGENT_KURA_UID'], '997')
            self.assertEqual(self.setup.check()['AGENT_KURA_NETWORK_INTERFACES'], '')
            self.install()
            with patch.object(setup_module.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=998, pw_gid=998)):
                with self.assertRaisesRegex(RuntimeError, 'UID changed'):
                    self.setup.check()

    def test_default_core_profile_is_authorized_without_a_core_start_dependency(self):
        self.install()
        unit = self.setup.path('/usr/lib/systemd/system/kura.service')
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nUser=kurad\n')
        account = types.SimpleNamespace(pw_uid=997, pw_gid=997)
        with patch.object(setup_module.pwd, 'getpwnam', return_value=account):
            self.setup.authorize('kurad')
            dropin = self.setup.path(setup_module.KURA_PROFILES['kurad'][1])
            self.assertEqual(setup_module.DROPIN_CONTENT, dropin.read_text())
            self.assertFalse(self.setup.path(setup_module.DROPIN).exists())
            self.assertEqual('997', self.setup.check()['AGENT_KURA_UID'])
            self.assertEqual('', self.setup.check()['AGENT_KURA_NETWORK_INTERFACES'])
            unit.unlink()  # Agent remains independent of a missing/broken Core unit.
            self.assertEqual('997', self.setup.check()['AGENT_KURA_UID'])

    def test_installed_core_loader_requires_the_exact_reviewed_pair(self):
        self.setup.root = self.setup.root.resolve()
        loader = self.setup.path('/opt/eclipse/kura/bin/gen_config_ini.sh')
        loader.parent.mkdir(parents=True)
        loader.write_text('# reviewed Core loader\n')
        digest = hashlib.sha256(loader.read_bytes()).hexdigest()
        installed = types.SimpleNamespace(returncode=0, stdout='installed')
        with patch.object(self.setup, 'run', return_value=installed):
            self.setup.guard_core_loader(digest)
            with self.assertRaisesRegex(RuntimeError, 'paired Core'):
                self.setup.guard_core_loader('0' * 64)
            loader.chmod(0o666)
            with self.assertRaises(RuntimeError):
                self.setup.guard_core_loader(digest)

    def test_unconfigured_or_absent_core_does_not_block_standalone_agent(self):
        for state in (types.SimpleNamespace(returncode=1, stdout=''),
                      types.SimpleNamespace(returncode=0, stdout='half-installed')):
            with patch.object(self.setup, 'run', return_value=state):
                self.setup.guard_core_loader('1' * 64)
        with self.assertRaisesRegex(RuntimeError, 'loader binding'):
            self.setup.guard_core_loader(None)
        with patch.object(self.setup, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='unexpected-state')):
            with self.assertRaises(RuntimeError):
                self.setup.guard_core_loader('1' * 64)

    def test_authorization_refuses_other_profiles_root_uid_and_effective_user_override(self):
        self.install()
        before = self.snapshot()
        for name in ('root', 'personal', 'kurad.service'):
            with self.assertRaises(RuntimeError):
                self.setup.authorize(name)
        self.assertEqual(before, self.snapshot())
        unit = self.setup.path('/usr/lib/systemd/system/kura.service')
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nUser=kurad\n')
        before = self.snapshot()
        with patch.object(setup_module.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=0, pw_gid=997)):
            with self.assertRaises(RuntimeError):
                self.setup.authorize('kurad')
        with patch.object(setup_module.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=997, pw_gid=997)), \
                patch.object(self.setup, 'systemctl', side_effect=lambda *args:
                    types.SimpleNamespace(stdout='LoadState=loaded\nUser=root\n') if args[1] == 'kura.service' else None):
            with self.assertRaisesRegex(RuntimeError, 'Effective Kura service User'):
                self.setup.authorize('kurad')
        self.assertEqual(before, self.snapshot())

    def test_foreign_or_ambiguous_profile_dropins_are_not_overwritten(self):
        self.install()
        unit = self.setup.path('/usr/lib/systemd/system/kura.service')
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nUser=kurad\n')
        account = types.SimpleNamespace(pw_uid=997, pw_gid=997)
        legacy = self.setup.path(setup_module.DROPIN)
        legacy.parent.mkdir(parents=True)
        legacy.write_text(setup_module.DROPIN_CONTENT)
        with patch.object(setup_module.pwd, 'getpwnam', return_value=account):
            with self.assertRaisesRegex(RuntimeError, 'Another Kura service profile'):
                self.setup.authorize('kurad')
        self.assertEqual(setup_module.DROPIN_CONTENT, legacy.read_text())
        legacy.unlink()
        with patch.object(setup_module.pwd, 'getpwnam', return_value=account):
            self.setup.authorize('kurad')
            legacy.write_text(setup_module.DROPIN_CONTENT)
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                self.setup.check()
        legacy.write_text('administrator configuration\n')
        with self.assertRaisesRegex(RuntimeError, 'externally modified'):
            self.setup.authorization_dropins()

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

    def test_firewall_and_recovery_unsettled_states_preserve_every_file(self):
        self.install()
        for subsystem, states in [('firewall', ['PREPARED', 'WAIT_CONFIRM', 'CONFIRMING', 'ROLLING_BACK', 'RECOVERY_REQUIRED']),
                                  ('recovery', ['VALIDATED', 'COMMITTING', 'COMPENSATING', 'RECOVERY_REQUIRED', 'ORDINARY_PREPARED', 'STOPPING_ORDINARY', 'STARTING_ORDINARY', 'VERIFYING_ORDINARY']),
                                  ('ordinary-boot', ['BOOT_POLICY_PREPARED', 'APPLYING_BOOT_POLICY', 'RECOVERY_REQUIRED'])]:
            journal = self.setup.path(setup_module.STATE + '/' + subsystem + '/transaction.json')
            journal.parent.mkdir(parents=True, exist_ok=True)
            for state in states:
                journal.write_text(json.dumps({'state': state}))
                journal.chmod(0o600)
                before = self.snapshot()
                with self.assertRaisesRegex(RuntimeError, 'Settle the ' + subsystem):
                    self.setup.purge()
                self.assertEqual(before, self.snapshot())
            journal.unlink()

    def test_ordinary_approved_terminal_allows_lifecycle_guard_without_changing_evidence(self):
        self.install()
        journal = self.setup.path(setup_module.STATE + '/recovery/transaction.json')
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text(json.dumps({'state': 'ORDINARY_ACTIVE_APPROVED_CHECKS'}))
        before = self.snapshot()
        self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def test_boot_policy_terminal_requires_matching_private_receipt_for_maintenance(self):
        self.install()
        journal = self.setup.path(setup_module.STATE + '/ordinary-boot/transaction.json')
        journal.parent.mkdir(parents=True, exist_ok=True)
        ident = 'boot-11111111-1111-1111-1111-111111111111'
        proof = {'id': ident, 'request': {}, 'targetBefore': {'unit': 'kura.service'},
                 'retiredBefore': [], 'actionIntents': ['enable kura.service'],
                 'status': 'BOOT_POLICY_COMMITTED', 'bootVerified': False, 'kuraRecoveryVerified': False}
        receipt = journal.parent / 'receipts' / (ident + '.json')
        receipt.parent.mkdir()
        raw = json.dumps(proof).encode()
        receipt.write_bytes(raw)
        receipt.chmod(0o600)
        journal.write_text(json.dumps({'schema': 1, 'id': ident, 'token': '22222222-2222-2222-2222-222222222222', 'expiresAt': 123, 'previousConfirmedSha256': None, 'state': 'BOOT_POLICY_COMMITTED',
            'request': {}, 'target': proof['targetBefore'], 'retired': [],
            'actionIntents': proof['actionIntents'], 'receiptSha256': hashlib.sha256(raw).hexdigest()}))
        journal.chmod(0o600)
        confirmed = journal.parent / 'confirmed.json'
        confirmed.write_bytes(journal.read_bytes())
        confirmed.chmod(0o600)
        before = self.snapshot()
        self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())
        with self.assertRaisesRegex(RuntimeError, 'boot policy receipts'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())
        command = '33333333-3333-4333-8333-333333333333'
        decision = {'schema': 1, 'transactionId': ident, 'binding': {'commandId': command, 'requestSha256': 'a' * 64, 'operation': 19}, 'result': {}}
        path = journal.parent / 'commands' / (command + '.json')
        path.parent.mkdir()
        path.write_bytes(json.dumps(decision).encode())
        path.chmod(0o600)
        value = json.loads(journal.read_bytes())
        value['commandDecisions'] = {command: hashlib.sha256(path.read_bytes()).hexdigest()}
        journal.write_text(json.dumps(value))
        self.setup.guard_writer()
        evidence = path.read_bytes()
        path.write_bytes(evidence + b' ')
        with self.assertRaisesRegex(RuntimeError, 'command decision changed'):
            self.setup.guard_writer()
        path.write_bytes(evidence)
        receipt.write_bytes(raw + b' ')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'boot receipt changed'):
            self.setup.guard_writer()
        self.assertEqual(before, self.snapshot())

    def test_confirmed_firewall_and_recovery_backups_refuse_destructive_purge(self):
        self.install()
        confirmed = self.setup.path(setup_module.STATE + '/firewall/confirmed.json')
        confirmed.parent.mkdir(parents=True)
        confirmed.write_text(json.dumps({'revision': 1, 'text': 'owned firewall rules'}))
        with self.assertRaisesRegex(RuntimeError, 'firewall.*handover'):
            self.setup.purge()
        confirmed.unlink()
        backup = self.setup.path(setup_module.STATE + '/recovery/backups/keep/manifest.json')
        backup.parent.mkdir(parents=True)
        backup.write_text('{}')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'verified archive'):
            self.setup.purge()
        self.assertEqual(before, self.snapshot())

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

    def artifact(self, unsafe=False, marker=''):
        path = self.root / 'protocol.crate'
        with tarfile.open(path, 'w:gz') as archive:
            content = ('[package]\nname="yofc-management-protocol"\nversion="0.1.0"\n# ' + marker + '\n').encode()
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
        self.assertIn('path = "' + result['protocol']['sourcePath'] + '"', cargo)
        self.assertTrue((destination / result['protocol']['sourcePath'] / 'Cargo.toml').is_file())
        with self.assertRaises(RuntimeError):
            build.stage(artifact, '0' * 64, self.root / 'other')

    def test_same_version_different_protocol_content_has_a_distinct_cargo_identity(self):
        artifact = self.artifact(marker='old wire contract')
        old = build.stage(artifact, build.sha(artifact), self.root / 'old')
        old_bytes = (self.root / 'old/Cargo.toml').read_bytes()
        artifact = self.artifact(marker='new wire contract')
        new = build.stage(artifact, build.sha(artifact), self.root / 'new')
        self.assertEqual(old['protocol']['version'], new['protocol']['version'])
        self.assertNotEqual(old['protocol']['sourcePath'], new['protocol']['sourcePath'])
        self.assertEqual(old_bytes, (self.root / 'old/Cargo.toml').read_bytes())

    def test_package_code_and_service_are_exported_and_verified_with_rust(self):
        artifact = self.artifact()
        destination = self.root / 'source'
        result = build.stage(artifact, build.sha(artifact), destination)
        records = {row['path']: row['sha256'] for row in result['sourceFiles']}
        for name in ('build.py', 'setup.py', 'lifecycle.py', 'kura-management-agent.service', build.FIREWALL_BOOT_UNIT):
            relative = 'packaging/' + name
            self.assertEqual(build.sha(build.ROOT / relative), records[relative])
            self.assertEqual(records[relative], build.sha(destination / relative))
        with patch.object(build, 'ROOT', destination):
            build.verify_source_manifest(result)
            for relative in ('packaging/lifecycle.py', 'src/main.rs', 'packaging/kura-management-agent.service'):
                path = destination / relative
                original = path.read_bytes()
                path.write_bytes(original + b'\n# source cohort drift\n')
                with self.assertRaisesRegex(RuntimeError, 'differs from staged'):
                    build.verify_source_manifest(result)
                path.write_bytes(original)

    def test_vendored_protocol_and_complete_source_set_are_rechecked(self):
        artifact = self.artifact()
        destination = self.root / 'source'
        result = build.stage(artifact, build.sha(artifact), destination)
        with patch.object(build, 'ROOT', destination):
            build.verify_source_manifest(result)
            protocol = destination / result['protocol']['sourcePath'] / 'Cargo.toml'
            protocol.write_text(protocol.read_text() + '\n# changed vendor\n')
            with self.assertRaisesRegex(RuntimeError, 'Vendored protocol differs'):
                build.verify_source_manifest(result)
        incomplete = {**result, 'sourceFiles': result['sourceFiles'][1:]}
        with self.assertRaisesRegex(RuntimeError, 'exact source set'):
            build.verify_source_manifest(incomplete)

    def test_unsafe_protocol_source_path_and_old_manifest_are_rejected(self):
        artifact = self.artifact()
        result = build.stage(artifact, build.sha(artifact), self.root / 'source')
        with self.assertRaises(RuntimeError):
            build.verify_source_manifest({**result, 'schemaVersion': 1})
        with self.assertRaisesRegex(RuntimeError, 'protocol source path'):
            build.verify_source_manifest({**result, 'protocol': {**result['protocol'], 'sourcePath': '../../outside'}})

    def test_compile_time_firewall_templates_are_exported_and_checksum_bound(self):
        artifact = self.artifact()
        destination = self.root / 'source'
        result = build.stage(artifact, build.sha(artifact), destination)
        records = {row['path']: row['sha256'] for row in result['sourceFiles']}
        for name in ['ip-icmp-on.save', 'ip-icmp-off.save', 'ip6-icmp-on.save', 'ip6-icmp-off.save']:
            relative = Path('src/firewall/original/templates') / name
            self.assertEqual((build.ROOT / relative).read_bytes(), (destination / relative).read_bytes())
            self.assertEqual(records[str(relative)], build.sha(destination / relative))

    def test_non_rust_resource_symlinks_cannot_enter_the_source_artifact(self):
        artifact = self.artifact()
        source = self.root / 'crate'
        (source / 'src').mkdir(parents=True)
        for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']:
            (source / name).write_bytes((build.ROOT / name).read_bytes())
        outside = self.root / 'outside.save'
        outside.write_text('not a source input')
        (source / 'src/template.save').symlink_to(outside)
        with patch.object(build, 'ROOT', source), self.assertRaisesRegex(RuntimeError, 'Source symlinks'):
            build.stage(artifact, build.sha(artifact), self.root / 'source')

    def test_protocol_archive_cannot_escape_or_replace_staging(self):
        artifact = self.artifact(unsafe=True)
        with self.assertRaises(RuntimeError):
            build.stage(artifact, build.sha(artifact), self.root / 'source')
        self.assertFalse((self.root / 'source').exists())

    def test_non_linux_binary_is_rejected_before_packaging(self):
        binary = self.root / 'agent'
        binary.write_bytes(b'not a Linux ELF64')
        with self.assertRaisesRegex(RuntimeError, 'ELF64'):
            build.deb(binary, build.sha(binary), 'arm64', '0.1.0~test1', self.root / 'deb', self.root / 'manifest.json',
                      self.root / 'bridge.jar', '0' * 64)


class JavaBridgeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def bundle(self, name='org.eclipse.kura.management.bridge', implementation=True):
        """Metadata-only test JAR; actual runtime acceptance uses a compiled bundle."""
        path = self.root / 'bridge.jar'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('META-INF/MANIFEST.MF',
                             'Manifest-Version: 1.0\r\nBundle-SymbolicName: ' + name +
                             ';singleton:=true\r\nBundle-Version: 1.0.0.test\r\n'
                             'Service-Component: OSGI-INF/other.xml,\r\n OSGI-INF/management-bridge.xml\r\n\r\n')
            archive.writestr('OSGI-INF/management-bridge.xml',
                             '<component><implementation class="org.eclipse.kura.management.bridge.Bridge"/></component>')
            if implementation:
                archive.writestr('org/eclipse/kura/management/bridge/Bridge.class', b'metadata-only-fixture')
        return path

    def test_reviewed_adapter_metadata_is_bound_to_actual_archive_bytes(self):
        path = self.bundle()
        metadata = build.java_bridge(path, build.sha(path))
        self.assertEqual(metadata['sha256'], build.sha(path))
        self.assertEqual(metadata['symbolicName'], 'org.eclipse.kura.management.bridge')
        with self.assertRaisesRegex(RuntimeError, 'digest mismatch'):
            build.java_bridge(path, '0' * 64)

    def test_matching_digest_cannot_substitute_an_unrelated_bundle(self):
        path = self.bundle(name='unrelated.bundle')
        with self.assertRaisesRegex(RuntimeError, 'Invalid Java bridge'):
            build.java_bridge(path, build.sha(path))

    def test_missing_adapter_implementation_is_rejected(self):
        path = self.bundle(implementation=False)
        with self.assertRaisesRegex(RuntimeError, 'Invalid Java bridge'):
            build.java_bridge(path, build.sha(path))


if __name__ == '__main__':
    unittest.main()
