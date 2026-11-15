"""Maintenance must preserve unresolved actions and immutable original receipts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('system_control_setup', Path(__file__).with_name('setup.py'))
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


class SystemControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.install = setup.Setup(self.root)
        self.state = self.install.path(setup.STATE + '/system-control')

    def put(self, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value, separators=(',', ':')).encode())
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def journal(self, completed=False):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.chmod(0o700)
        ident = 'system-11111111-1111-4111-8111-111111111111'
        unit = {'unit': 'kura.service', 'activeState': 'active', 'pid': 123,
                'invocationId': 'a' * 32, 'controlGroup': '/system.slice/kura.service',
                'unitFileState': 'enabled'}
        config = {'schema': 1, 'unit': 'kura.service', 'unitDefinitionSha256': 'a' * 64}
        sha = self.put(self.state / 'receipts' / (ident + '.config.json'), config)
        j = {'schema': 1, 'id': ident, 'token': '22222222-2222-4222-8222-222222222222',
             'state': 'CANCELLED', 'action': 'restart', 'configSha256': sha,
             'definitionSha256': 'a' * 64, 'unit': 'kura.service', 'before': unit,
             'beforeBootId': '33333333-3333-4333-8333-333333333333',
             'expiresAt': 123, 'profile': None, 'snapshots': [], 'probe': None,
             'issuedCommand': None, 'issued': False, 'issuedAt': None,
             'requestAccepted': False, 'scheduledUnit': None, 'after': None,
             'afterBootId': None, 'observation': None, 'outcome': None,
             'receiptSha256': None, 'error': None, 'commandDecisions': {}}
        receipt = self.state / 'receipts' / (ident + '.completed.json')
        if completed:
            after = dict(unit, pid=234, invocationId='b' * 32)
            observed = {'configured': False, 'verified': False, 'error': None, 'report': None}
            j.update(state='COMPLETED', issued=True, issuedAt=1, requestAccepted=True,
                     after=after, afterBootId=j['beforeBootId'], observation=observed)
            value = {'id': ident, 'state': 'COMPLETED', 'action': 'service.restart',
                     'unit': j['unit'], 'before': unit, 'beforeBootId': j['beforeBootId'],
                     'after': after, 'afterBootId': j['afterBootId'], 'issued': True,
                     'requestAccepted': True, 'application': observed,
                     'processRestartVerified': True, 'hostRebootVerified': False,
                     'kuraRecoveryVerified': False, 'normalBootVerified': False}
            j['outcome'] = {'state': 4, 'error': 0, 'value': value}
            j['receiptSha256'] = self.put(receipt, j['outcome'])
        self.put(self.state / 'transaction.json', j)
        return j, receipt

    def snapshot(self):
        return {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_default_absence_and_valid_settlement_allow_read_only_maintenance(self):
        self.install.guard_transactions()
        for completed in (False, True):
            self.journal(completed)
            before = self.snapshot()
            self.install.guard_transactions()
            self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(RuntimeError, 'verified archive'):
            self.install.purge()

    def test_every_unsettled_state_blocks_maintenance_and_keeps_all_evidence(self):
        j, _ = self.journal()
        for state in ('PREPARED', 'ISSUING', 'AWAITING_BOOT', 'VERIFYING_APPLICATION', 'RECOVERY_REQUIRED'):
            j['state'] = state
            self.put(self.state / 'transaction.json', j)
            before = self.snapshot()
            with self.assertRaisesRegex(RuntimeError, 'unresolved transaction'):
                self.install.guard_writer()
            self.assertEqual(self.snapshot(), before)

    def test_unlinked_grant_history_or_command_blocks_even_when_feature_is_unconfigured(self):
        for name in ('commands', 'receipts', 'history'):
            p = self.state / name / 'retained.json'
            self.put(p, {'retained': True})
            before = self.snapshot()
            with self.assertRaisesRegex(RuntimeError, 'journal missing'):
                self.install.guard_transactions()
            self.assertEqual(self.snapshot(), before)
            p.unlink()  # This test's disposable fixture only.

    def test_changed_receipt_config_and_exposed_file_deny_maintenance(self):
        j, receipt = self.journal(True)
        for p in (receipt, self.state / 'receipts' / (j['id'] + '.config.json')):
            original = p.read_bytes()
            p.write_bytes(original + b' ')
            before = self.snapshot()
            with self.assertRaises(RuntimeError):
                self.install.guard_transactions()
            self.assertEqual(self.snapshot(), before)
            p.write_bytes(original)
            p.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'unsafe private record'):
                self.install.guard_transactions()
            p.chmod(0o600)
        j['state'] = 'CANCELLED'
        self.put(self.state / 'transaction.json', j)
        with self.assertRaisesRegex(RuntimeError, 'issued intent'):
            self.install.guard_transactions()

    def test_original_command_digest_and_issued_binding_are_required(self):
        j, _ = self.journal(True)
        ident = '44444444-4444-4444-8444-444444444444'
        bound = {'commandId': ident, 'operation': 25, 'requestSha256': 'e' * 64}
        decision = {'schema': 1, 'binding': bound, 'planId': j['id'], 'result': j['outcome']}
        p = self.state / 'commands' / (ident + '.json')
        j['commandDecisions'] = {ident: self.put(p, decision)}
        j['issuedCommand'] = bound
        self.put(self.state / 'transaction.json', j)
        self.install.guard_transactions()
        p.write_bytes(p.read_bytes() + b' ')
        with self.assertRaisesRegex(RuntimeError, 'original command changed'):
            self.install.guard_transactions()

    def test_interrupted_install_blocks_start_and_maintenance_without_deleting_marker(self):
        self.install.init_local()
        p = self.install.path(setup.CONFIG + '/.system-control-installing')
        self.put(p, {'retain': 'old env and new grant'})
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.install.check()
        with self.assertRaisesRegex(RuntimeError, 'Interrupted system control installation'):
            self.install.guard_writer()
        self.assertEqual(self.snapshot(), before)

    def test_configure_preserves_old_settings_and_grant_without_enabling_a_channel_or_unit(self):
        self.install.init_local()
        request = self.root / 'request.json'
        self.put(request, {'test': 'only a sealer stub in this test'})
        calls = []

        def seal(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[1:3], ['seal-system-control', '--request'])
            out = Path(argv[-1])
            sha = self.put(out, {'schema': 1, 'unit': 'kura.service'})
            return subprocess.CompletedProcess(argv, 0, json.dumps({
                'grantSha256': sha, 'unitStarted': False, 'unitEnabled': False, 'remoteEnabled': False}))

        self.install.run = seal
        env = self.install.path(setup.CONFIG + '/agent.env')
        old = env.read_bytes()
        first = self.install.configure_system_control(request, False, 'test-operator')
        first_grant = self.install.path(first['grant']).read_bytes()
        self.assertEqual(self.install.settings()['AGENT_REMOTE_ENABLED'], '0')
        self.assertEqual(self.install.settings()['AGENT_SYSTEM_CONTROL_REMOTE'], '0')
        self.install.configure_system_control(request, True, 'test-operator')
        self.assertEqual(self.install.settings()['AGENT_REMOTE_ENABLED'], '0')
        self.assertEqual(self.install.settings()['AGENT_SYSTEM_CONTROL_REMOTE'], '1')
        self.assertEqual(self.install.path(first['grant']).read_bytes(), first_grant)
        backup = self.install.path(setup.STATE + '/system-control-installations/' + first['id'] + '.previous.env')
        self.assertEqual(backup.read_bytes(), old)
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.install.path(setup.CONFIG + '/.system-control-installing').exists())

    def test_failed_environment_switch_preserves_install_intent_and_both_env_versions(self):
        self.install.init_local()
        request = self.root / 'request.json'
        self.put(request, {})

        def seal(argv, **kwargs):
            sha = self.put(Path(argv[-1]), {'schema': 1})
            return subprocess.CompletedProcess(argv, 0, json.dumps({'grantSha256': sha,
                'unitStarted': False, 'unitEnabled': False, 'remoteEnabled': False}))

        self.install.run = seal
        old = self.install.path(setup.CONFIG + '/agent.env').read_bytes()
        with patch.object(self.install, 'replace', side_effect=OSError('test-only power loss')):
            with self.assertRaises(OSError):
                self.install.configure_system_control(request, False, 'test')
        self.assertEqual(self.install.path(setup.CONFIG + '/agent.env').read_bytes(), old)
        with self.assertRaises(RuntimeError):
            self.install.guard_writer()
        self.assertTrue(self.install.path(setup.CONFIG + '/.system-control-installing').exists())

if __name__ == '__main__':
    unittest.main()
