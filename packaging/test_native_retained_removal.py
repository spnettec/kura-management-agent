"""Original native removal decisions against a disposable Root profile."""
import json
import os
import subprocess
from types import SimpleNamespace
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
        self.original_postrm = b'#!/bin/sh\nexit 1\n'
        self.case.case.write(self.removal.POSTRM, self.original_postrm, 0o755)
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
        self.enterContext(patch.object(native.grp, 'getgrnam', side_effect=lambda name:
            SimpleNamespace(gr_gid=993 if name == 'kura-management' else 994, gr_mem=[])))
        for name in native.SourceUpdate.PAYLOAD:
            path = self.setup.path(name)
            if path.is_file():
                self.assets[name] = (path.read_bytes(), path.stat().st_mode & 0o777)

    def prepare(self, operation=None):
        package = '/reviewed-fixture.deb'
        script = {self.removal.POSTRM: [0o755, self.removal.source.digest(self.original_postrm)]}
        with patch.object(self.removal.source, 'candidate', return_value=(self.pair, self.case.old_prerm)), \
                patch.object(self.removal, 'package_assets', return_value=script):
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

    def test_documentation_exclusion_does_not_allow_missing_runtime_code(self):
        example = '/usr/share/doc/kura-management-agent/agent.env.example'
        self.setup.path(example).unlink()
        self.removal.installed_assets({example: (0o644, '0' * 64)})
        self.setup.path(native.V2_VENDOR).unlink()
        with self.assertRaises(FileNotFoundError):
            self.removal.installed_assets({native.V2_VENDOR: (0o644, '0' * 64)})

    def test_failed_postrm_reuses_the_original_admission_and_archives_exact_old_code(self):
        self.prepare()
        self.removal.admit_removal(self.pair, self.loader)
        self.remove_payload()
        fixed = b'#!/bin/sh\nexit 0\n'
        self.removal.source.incoming_postrm = fixed
        reviewed_pair = {**self.pair, 'sourceManifestSha256': 'd' * 64}
        with patch.object(self.removal.source, 'candidate', return_value=(reviewed_pair, b'fixture')):
            for _ in range(2):
                self.assertEqual(self.removal.recover_postrm(self.initialization, self.operation,
                    '/reviewed-fixture.deb', self.package_sha)['phase'], 'POSTRM_READY')
        self.assertEqual(self.status(), 'REMOVE_ADMITTED')
        old_path = self.removal.record(self.operation, 'postrm-recovery').removesuffix('.json') + '.previous'
        self.assertEqual(self.setup.path(old_path).read_bytes(), self.original_postrm)
        self.assertEqual(self.setup.path(self.removal.POSTRM).read_bytes(), fixed)
        with self.assertRaisesRegex(RuntimeError, 'postrm recovery proof differs'):
            self.removal.finish_removal(self.pair, self.loader, purge=False)
        self.removal.finish_removal(reviewed_pair, self.loader, purge=False)
        self.assertEqual(self.status(), 'REMOVED')

    def test_postrm_recovery_refuses_a_different_device_before_reviewing_new_code(self):
        self.prepare()
        self.removal.admit_removal(self.pair, self.loader)
        self.remove_payload()
        ticket = self.removal.ticket()
        remounted = {name: [values[0] + 1, *values[1:]] for name, values in ticket['state'].items()}
        with patch.object(self.removal, 'inventory', return_value=remounted), \
                patch.object(self.removal.source, 'candidate', side_effect=AssertionError('archive opened')):
            with self.assertRaisesRegex(RuntimeError, 'Original native removal data changed'):
                self.removal.recover_postrm(self.initialization, self.operation, '/reviewed-fixture.deb', self.package_sha)
        self.assertEqual(self.setup.path(self.removal.POSTRM).read_bytes(), self.original_postrm)
        self.assertFalse(self.setup.path(self.removal.record(self.operation, 'postrm-recovery')).exists())

    def test_overlay_reattachment_requires_the_same_backing_and_every_other_fingerprint(self):
        self.prepare()
        ticket = self.removal.ticket()
        original_device = next(iter(ticket['state'].values()))[0]
        ticket['rootOverlay'] = {'device': original_device, 'overlaySha256': '1' * 64}
        current = {path: [original_device + 1, *data[1:]] for path, data in ticket['state'].items()}
        backing = {'device': original_device + 1, 'overlaySha256': '1' * 64}
        with patch.object(self.removal, 'overlay_mount', return_value=backing):
            self.removal.verify_inventory(ticket, current)
            leaf = next(iter(current))
            current[leaf][1] += 1
            with self.assertRaisesRegex(RuntimeError, 'Original native removal data changed'):
                self.removal.verify_inventory(ticket, current)
            current[leaf][1] -= 1
            backing['overlaySha256'] = '2' * 64
            with self.assertRaisesRegex(RuntimeError, 'overlay backing differs'):
                self.removal.verify_inventory(ticket, current)


if __name__ == '__main__':
    unittest.main()
