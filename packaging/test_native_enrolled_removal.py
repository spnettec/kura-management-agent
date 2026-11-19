"""Package lifecycle checks over the existing enrolled Root state fixture."""
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import test_retained_business_source as fixture

native = fixture.native


@unittest.skipUnless(os.geteuid() == 0, 'disposable Root Linux fixture required')
class EnrolledRemovalTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.RetainedBusinessSourceTests('runTest')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.setup = self.case.setup
        self.profile = self.case.profile
        self.removal = native.RetainedRemoval(self.profile)
        self.initialization = self.case.initialization
        self.operation = str(uuid.uuid4())
        self.identity = self.profile.descriptor()
        self.pair = {key: self.identity[key] for key in self.removal.source.PINS}
        self.loader = self.removal.source.bridge()['coreLoaderSha256']
        self.package = '/reviewed-enrolled-agent.deb'
        self.archive = b'reviewed installed native pair fixture'
        self.case.f.case.write(self.package, self.archive, 0o600)
        self.expected = self.removal.source.digest(self.archive)
        self.version = self.case.f.update.incoming_version
        self.removal.source.incoming_version = self.version
        self.enterContext(patch.object(self.removal, 'version', return_value=self.version))
        self.present = True
        original_systemctl = self.setup.systemctl

        def unit(*args):
            if args[0] == 'show' and '--property=UnitFileState' in args:
                state = 'disabled' if self.present else ''
                return SimpleNamespace(stdout=f'ActiveState=inactive\nUnitFileState={state}\nDropInPaths=\n')
            return original_systemctl(*args)

        self.setup.systemctl = unit

    def prepare(self, enrolled=True):
        prerm = self.removal.source.raw(self.removal.source.PRERM, 0o755)
        with patch.object(self.removal.source, 'candidate', return_value=(self.pair, prerm)), \
                patch.object(self.removal, 'package_assets', return_value={}):
            return self.removal.prepare(self.initialization, self.operation, self.package, self.expected,
                                        enrolled=enrolled)

    def terminal_inspection(self, *args):
        report = self.case.inspection(*args)
        count = report['inventory']['tableCounts']['executions']
        report['inventory']['executionStates'] = {'SUCCEEDED': count}
        report['inventory']['unresolvedExecutions'] = 0
        return report

    def test_unresolved_business_blocks_intent_and_leaves_original_wal_exact(self):
        with self.assertRaisesRegex(RuntimeError, 'Unresolved enrolled business'):
            self.prepare()
        self.assertFalse(self.removal.pending())
        self.case.assert_preserved()

    def test_bound_same_pair_remove_and_reinstall_keep_business_and_authority(self):
        with self.assertRaisesRegex(RuntimeError, 'unbound native removal'):
            self.prepare(enrolled=False)
        with patch.object(native.RetainedBusiness, 'execute', side_effect=self.terminal_inspection):
            self.assertEqual(self.prepare()['phase'], 'PREPARED')
        ticket = self.removal.ticket()
        self.assertEqual(ticket['binding']['business']['inventory']['executionStates'], {'SUCCEEDED': 3})
        self.assertIn(native.KuraPeer.CURRENT, ticket['state'])
        self.assertIn(native.KuraMaterial.RELAY, ticket['state'])
        self.assertIn(native.V2_STATE + '/results.sqlite-wal', ticket['state'])
        self.removal.admit_removal(self.pair, self.loader)
        assets = {}
        for name in self.removal.source.PAYLOAD:
            path = self.setup.path(name)
            if path.is_file():
                assets[name] = path.read_bytes(), path.stat().st_mode & 0o777
                path.unlink()
        self.present = False
        with patch.object(self.profile, 'descriptor', side_effect=AssertionError('removed Agent payload accessed')):
            self.removal.finish_removal(self.pair, self.loader, purge=False)
            self.removal.finish_removal(self.pair, self.loader, purge=True)
            self.removal.admit_install(self.pair, self.loader, self.version)
        for name, (data, mode) in assets.items():
            self.case.f.case.write(name, data, mode)
        self.present = True
        self.removal.finish_install(self.pair, self.loader)
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'REINSTALLED')
        self.assertEqual(self.profile.check(), self.identity)
        self.case.assert_preserved()


if __name__ == '__main__':
    unittest.main()
