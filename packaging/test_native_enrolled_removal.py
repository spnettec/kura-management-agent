"""Package lifecycle checks over the existing enrolled Root state fixture."""
import json
import os
from pathlib import Path
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

    def remove_bound(self):
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
        return assets

    def reinstall_assets(self, assets):
        for name, (data, mode) in assets.items():
            self.case.f.case.write(name, data, mode)
        self.present = True

    def test_bound_same_pair_remove_and_reinstall_keep_business_and_authority(self):
        with self.assertRaisesRegex(RuntimeError, 'unbound native removal'):
            self.prepare(enrolled=False)
        assets = self.remove_bound()
        with patch.object(self.profile, 'descriptor', side_effect=AssertionError('removed Agent payload accessed')):
            self.removal.finish_removal(self.pair, self.loader, purge=True)
            self.removal.admit_install(self.pair, self.loader, self.version)
        self.reinstall_assets(assets)
        self.removal.finish_install(self.pair, self.loader)
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'REINSTALLED')
        self.assertEqual(self.profile.check(), self.identity)
        self.case.assert_preserved()

    def test_interruption_after_reinstalled_receipt_resumes_original_removal(self):
        assets = self.remove_bound()
        self.removal.admit_install(self.pair, self.loader, self.version)
        self.reinstall_assets(assets)
        pending = self.setup.path(self.removal.PENDING)
        intent = pending.read_bytes()
        unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == pending:
                raise OSError('pending marker is busy')
            return unlink(path, *args, **kwargs)

        with patch.object(Path, 'unlink', interrupt):
            with self.assertRaisesRegex(OSError, 'pending marker is busy'):
                self.removal.finish_install(self.pair, self.loader)

        receipt = self.setup.path(self.removal.record(self.operation, 'reinstalled'))
        original, stat = receipt.read_bytes(), receipt.stat()
        self.assertEqual(pending.read_bytes(), intent)
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'INSTALL_ADMITTED')
        with self.assertRaisesRegex(RuntimeError, 'removal remains active'):
            self.profile.check()

        self.removal.finish_install(self.pair, self.loader)
        self.assertFalse(pending.exists())
        self.assertEqual(receipt.read_bytes(), original)
        self.assertEqual((receipt.stat().st_ino, receipt.stat().st_ctime_ns), (stat.st_ino, stat.st_ctime_ns))
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'REINSTALLED')
        self.case.assert_preserved()

    def interrupt_receipt_link(self, linked):
        assets = self.remove_bound()
        self.removal.admit_install(self.pair, self.loader, self.version)
        self.reinstall_assets(assets)
        receipt = self.setup.path(self.removal.record(self.operation, 'reinstalled'))
        staging = receipt.with_name('.reinstalled.json.native-new')
        link = os.link

        def interrupt(src, dst, **kwargs):
            if dst != receipt:
                return link(src, dst, **kwargs)
            if linked:
                link(src, dst, **kwargs)
            raise InterruptedError('receipt publication interrupted')

        with patch.object(os, 'link', side_effect=interrupt):
            with self.assertRaisesRegex(InterruptedError, 'receipt publication interrupted'):
                self.removal.finish_install(self.pair, self.loader)
        self.assertEqual(receipt.exists(), linked)
        self.assertEqual(staging.stat().st_nlink, 2 if linked else 1)
        return receipt, staging

    def check_receipt_link_recovery(self, linked):
        receipt, staging = self.interrupt_receipt_link(linked)
        inode, raw = staging.stat().st_ino, staging.read_bytes()
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'INSTALL_ADMITTED')
        self.assertEqual(receipt.exists(), linked)
        self.assertTrue(staging.exists())
        self.removal.finish_install(self.pair, self.loader)
        self.assertFalse(staging.exists())
        self.assertEqual((receipt.stat().st_ino, receipt.stat().st_nlink, receipt.read_bytes()), (inode, 1, raw))
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'REINSTALLED')
        self.case.assert_preserved()

    def test_recover_synced_receipt_before_link(self):
        self.check_receipt_link_recovery(False)

    def test_recover_linked_receipt_before_staging_unlink(self):
        self.check_receipt_link_recovery(True)

    def test_preserve_incomplete_staged_receipt(self):
        receipt, staging = self.interrupt_receipt_link(False)
        raw = staging.read_bytes()[:-1]
        staging.write_bytes(raw)
        with self.assertRaises(RuntimeError):
            self.removal.finish_install(self.pair, self.loader)
        self.assertFalse(receipt.exists())
        self.assertEqual(staging.read_bytes(), raw)
        self.assertTrue(self.removal.pending())
        self.case.assert_preserved()

    def test_pending_survives_until_receipt_directory_sync_succeeds(self):
        assets = self.remove_bound()
        self.removal.admit_install(self.pair, self.loader, self.version)
        self.reinstall_assets(assets)
        receipt = self.setup.path(self.removal.record(self.operation, 'reinstalled'))
        parent = receipt.parent.stat()
        sync = os.fsync

        def interrupt(fd):
            if receipt.exists() and os.path.samestat(os.fstat(fd), parent):
                raise OSError('receipt directory sync interrupted')
            sync(fd)

        with patch.object(os, 'fsync', side_effect=interrupt):
            for _ in range(2):
                with self.assertRaisesRegex(OSError, 'receipt directory sync interrupted'):
                    self.removal.finish_install(self.pair, self.loader)
                self.assertTrue(self.removal.pending())
        self.removal.finish_install(self.pair, self.loader)
        self.assertFalse(self.removal.pending())
        self.case.assert_preserved()

    def test_identical_bytes_in_separate_receipts_do_not_complete_publication(self):
        receipt, staging = self.interrupt_receipt_link(False)
        receipt.write_bytes(staging.read_bytes())
        receipt.chmod(0o600)
        original = (receipt.stat().st_ino, staging.stat().st_ino)
        self.assertNotEqual(*original)
        with self.assertRaisesRegex(RuntimeError, 'differs from the original removal proof'):
            self.removal.finish_install(self.pair, self.loader)
        self.assertEqual((receipt.stat().st_ino, staging.stat().st_ino), original)
        self.assertTrue(self.removal.pending())
        self.case.assert_preserved()

    def prepare_next(self, assets, inspect):
        path = '/reviewed-enrolled-successor.deb'
        archive = b'reviewed successor fixture'
        self.case.f.case.write(path, archive, 0o600)
        source = self.removal.source
        self.next_version = '1:0.1.0~enrolled-next'
        source.incoming_version = self.next_version
        meta = json.loads(assets['/usr/share/kura-management-agent/native-profile.json'][0])
        meta['files'][native.V2_VENDOR] = self.case.f.pair['unitSha256']
        source.incoming_material_pair = {
            'publisherPairSha256': source.digest(assets['/usr/share/kura-management-agent/enrollment-reader.json'][0]),
            'relayPairSha256': source.digest(json.dumps(meta).encode()),
        }
        source.incoming_inspector = b'explicit filesystem fixture; no ELF proof'
        with patch.object(source, 'candidate', return_value=(self.case.f.pair, b'fixture')) as candidate, \
                patch.object(self.removal, 'package_assets', return_value={}), \
                patch.object(native.RetainedBusiness, 'execute', side_effect=inspect), \
                patch.object(self.profile, 'descriptor', side_effect=AssertionError('removed Agent payload accessed')):
            result = self.removal.prepare_successor(self.initialization, self.operation, path, source.digest(archive))
            self.assertTrue(candidate.call_args.kwargs['inspection'])
            return result

    def test_successor_refuses_a_different_authenticated_wal_inventory(self):
        assets = self.remove_bound()
        with self.assertRaisesRegex(RuntimeError, 'original authenticated business inventory'):
            self.prepare_next(assets, self.case.inspection)
        self.assertIsNone(self.removal.successor(self.removal.ticket()))
        self.case.assert_preserved()

    def test_bound_successor_recovers_after_private_relay_publication(self):
        assets = self.remove_bound()
        self.assertEqual(self.prepare_next(assets, self.terminal_inspection)['phase'], 'SUCCESSOR_READY')
        ticket = self.removal.ticket()
        plan = self.removal.successor(ticket)
        self.removal.admit_install(self.case.f.pair, self.loader, self.next_version)
        self.reinstall_assets(assets)
        self.case.f.install_payload_fixture()
        source = self.removal.source
        replace = source.replace

        def interrupt(name, data, mode):
            if name == native.KuraMaterial.PUBLIC:
                raise OSError('interruption after private relay publication')
            replace(name, data, mode)

        with patch.object(self.removal, 'version', return_value=self.next_version):
            with patch.object(source, 'replace', side_effect=interrupt):
                with self.assertRaisesRegex(OSError, 'interruption after private relay publication'):
                    self.removal.finish_install(self.case.f.pair, self.loader)
            self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'INSTALL_ADMITTED')
            with self.assertRaisesRegex(RuntimeError, 'removal remains active'):
                self.profile.check()
            self.removal.finish_install(self.case.f.pair, self.loader)
        self.assertEqual(self.removal.status(self.initialization, self.operation)['phase'], 'REINSTALLED')
        self.assertEqual(self.profile.check(), plan['identity'])
        self.assertEqual(native.KuraMaterial(self.profile).check(), plan['materialTransition']['incoming'])
        self.assertEqual(native.KuraPeer(self.profile).check(), plan['peerTransition']['incoming'])
        self.case.assert_preserved()


if __name__ == '__main__':
    unittest.main()
