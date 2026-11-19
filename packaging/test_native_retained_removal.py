"""Original native removal decisions against a disposable Root profile."""
import json
import os
import subprocess
import unittest
from unittest.mock import patch
import uuid

import test_native_source_update as fixture

native = fixture.native


@unittest.skipUnless(os.geteuid() == 0, 'disposable Root Linux fixture required')
class RetainedRemovalTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.SourceUpdateTests('runTest')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.setup, self.profile = self.case.setup, self.case.profile
        self.initialization = self.case.case.operation
        self.operation = str(uuid.uuid4())
        self.removal = native.RetainedRemoval(self.profile)
        self.identity = self.profile.descriptor()
        self.pair = {key: self.identity[key] for key in native.SourceUpdate.PINS}
        self.loader = 'b' * 64
        self.version = '0.1.0~fixture'
        self.removal.source.incoming_version = self.version
        self.assets = {}
        self.present = True

        def unit(*args):
            if args[0] == 'show' and '--property=UnitFileState' in args:
                phase = 'disabled' if self.present else ''
                return subprocess.CompletedProcess(args, 0, f'ActiveState=inactive\nDropInPaths=\nUnitFileState={phase}\n')
            if args[0] == 'show' and '--property=MainPID' in args:
                return subprocess.CompletedProcess(args, 0, 'MainPID=0\nActiveState=inactive\n')
            return None

        self.setup.systemctl = unit
        self.setup.guard_core_loader = lambda expected: self.assertEqual(expected, self.loader)
        self.case.case.write('/reviewed-fixture.deb', b'fixture', 0o600)
        package = self.setup.path('/reviewed-fixture.deb')
        self.package_sha = self.removal.source.digest(package.read_bytes())
        self.enterContext(patch.object(self.removal, 'version', return_value=self.version))
        self.enterContext(patch.object(native.KuraPeer, 'members', return_value=[]))
        for name in native.SourceUpdate.PAYLOAD:
            path = self.setup.path(name)
            if path.is_file():
                self.assets[name] = (path.read_bytes(), path.stat().st_mode & 0o777)

    def prepare(self, operation=None):
        package = '/reviewed-fixture.deb'
        with patch.object(self.removal.source, 'candidate', return_value=(self.pair, self.case.old_prerm)), \
                patch.object(self.removal, 'package_assets', return_value={}):
            return self.removal.prepare(self.initialization, operation or self.operation, package, self.package_sha)

    def status(self):
        return self.removal.status(self.initialization, self.operation)['phase']

    def remove_payload(self):
        for name in self.assets:
            self.setup.path(name).unlink()
        self.present = False

    def reinstall_payload(self):
        for name, (data, mode) in self.assets.items():
            self.case.case.write(name, data, mode)
        self.present = True

    def test_remove_purge_and_exact_reinstall_preserve_the_original_profile(self):
        self.assertEqual(self.prepare()['phase'], 'PREPARED')
        self.assertEqual(self.prepare()['phase'], 'PREPARED')
        with self.assertRaisesRegex(RuntimeError, 'original native removal UUID'):
            self.prepare(str(uuid.uuid4()))
        with self.assertRaisesRegex(RuntimeError, 'removal remains active'):
            self.profile.check()
        with self.assertRaisesRegex(RuntimeError, 'Different native installation'):
            self.removal.status(str(uuid.uuid4()), self.operation)
        self.removal.admit_removal(self.pair, self.loader)
        self.assertEqual(self.status(), 'REMOVE_ADMITTED')
        with self.assertRaisesRegex(RuntimeError, 'already admitted'):
            self.removal.admit_removal(self.pair, self.loader)
        self.remove_payload()
        self.removal.finish_removal(self.pair, self.loader, purge=False)
        self.assertEqual(self.status(), 'REMOVED')
        self.removal.finish_removal(self.pair, self.loader, purge=True)
        self.assertEqual(self.status(), 'PURGED')
        with self.assertRaisesRegex(RuntimeError, 'Incoming Agent version differs'):
            self.removal.admit_install(self.pair, self.loader, '0.1.0~different')
        self.removal.admit_install(self.pair, self.loader, self.version)
        self.assertEqual(self.status(), 'INSTALL_ADMITTED')
        self.reinstall_payload()
        self.removal.finish_install(self.pair, self.loader)
        self.assertEqual(self.status(), 'REINSTALLED')
        self.assertFalse(self.removal.pending())
        self.assertEqual(self.profile.check(), self.identity)
        self.assertEqual(self.case.update.snapshot(), self.case.before)

    def test_cloned_ticket_or_mutated_original_does_not_admit_removal(self):
        self.prepare()
        candidate = self.setup.path(self.removal.PENDING)
        original = candidate.read_bytes()
        record = json.loads(original)
        record['requestId'] = str(uuid.uuid4())
        candidate.write_text(self.profile.encode(record))
        with self.assertRaises(FileNotFoundError):
            self.removal.admit_removal(self.pair, self.loader)
        candidate.write_bytes(original)
        plan = self.setup.path(native.V2_STATE + '/results.sqlite.plan-key')
        plan.write_bytes(b'9' * 32)
        with self.assertRaises((RuntimeError, ValueError)):
            self.removal.admit_removal(self.pair, self.loader)
        with self.assertRaisesRegex(RuntimeError, 'state continuity changed'):
            self.status()
        self.assertFalse(self.setup.path(self.removal.record(self.operation, 'remove-admitted')).exists())

    def test_lost_pending_marker_does_not_admit_a_new_original_or_start(self):
        self.prepare()
        self.setup.path(self.removal.PENDING).unlink()
        with self.assertRaisesRegex(RuntimeError, 'Lost native removal marker'):
            self.prepare(str(uuid.uuid4()))
        with self.assertRaisesRegex(RuntimeError, 'Lost native removal marker'):
            self.profile.check()


if __name__ == '__main__':
    unittest.main()
