"""Joint code/authority continuity using disposable Root policy fixtures."""
import hashlib
import json
import os
import unittest
from unittest.mock import patch
import uuid

import test_native_kura_peer as fixture

native=fixture.native


@unittest.skipUnless(os.geteuid()==0, 'disposable Root Linux fixture required')
class LocalPeerSourceTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.KuraPeerTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.peer,self.setup,self.profile=self.case.peer,self.case.setup,self.case.profile
        self.peer.authorize(self.case.operation)
        self.source=native.SourceUpdate(self.profile);self.source.local_kura_peer=True
        self.f=self.case.case;self.operation=str(uuid.uuid4())
        self.source.incoming_version=self.f.update.incoming_version
        loader=self.source.bridge()['coreLoaderSha256']
        self.prerm=self.f.prerm.replace(repr('b'*64).encode(),repr(loader).encode(),1)
        self.setup.path(self.source.PRERM).write_bytes(
            self.f.old_prerm.replace(repr('b'*64).encode(),repr(loader).encode(),1))
        self.before=self.source.initial_snapshot();self.grant_before=self.grant_files()

    def grant_files(self):
        paths=[p for p in self.setup.path(self.peer.RECORDS).rglob('*') if p.is_file()]
        paths.append(self.setup.path(self.peer.CURRENT));result={}
        for path in paths:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME)
            with os.fdopen(fd,'rb') as stream:
                m=os.fstat(stream.fileno());result[str(path)]=[
                    m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,
                    m.st_mtime_ns,m.st_ctime_ns,hashlib.file_digest(stream,'sha256').hexdigest()]
        return result

    def prepare(self):
        with patch.object(self.source,'candidate',return_value=(self.f.pair,self.prerm)):
            return self.source.prepare(self.operation,'/reviewed-local-source.deb','a'*64)

    def install_and_finish(self):
        self.source.admit(self.f.pair);self.f.install_payload_fixture()
        return self.source.finish(self.f.pair)

    def test_joint_update_preserves_original_grant_data_and_exact_permission_scope(self):
        original=self.peer.check();self.assertEqual(self.prepare()['state'],'UNKNOWN')
        self.assertEqual(self.install_and_finish()['state'],'APPLIED')
        self.profile.check();current=self.peer.check()
        self.assertNotEqual(original['nativeIdentitySha256'],current['nativeIdentitySha256'])
        self.assertEqual({k:v for k,v in original.items() if k!='nativeIdentitySha256'},
                         {k:v for k,v in current.items() if k!='nativeIdentitySha256'})
        self.assertEqual(self.source.initial_snapshot(),self.before)
        self.assertEqual(self.grant_files(),self.grant_before);self.assertEqual(self.case.dispatches,1)
        self.assertEqual(self.peer.status(self.case.operation)['state'],'APPLIED')
        with self.assertRaisesRegex(RuntimeError,'joint native maintenance'):self.source.snapshot()

    def test_normal_source_action_and_running_core_cannot_enter_joint_authority(self):
        self.source.local_kura_peer=False
        with self.assertRaisesRegex(RuntimeError,'joint native maintenance'):self.prepare()
        self.source.local_kura_peer=True;self.case.running=True
        with self.assertRaisesRegex(RuntimeError,'Explicitly stop'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assertEqual(self.grant_files(),self.grant_before)

    def test_permission_widening_in_pending_ticket_is_refused_before_admission(self):
        self.prepare();ticket=self.source.json(self.source.PENDING)
        ticket['peerTransition']['incoming']['kuraUid']=0
        self.setup.path(self.source.PENDING).write_text(self.profile.encode(ticket))
        with self.assertRaisesRegex(RuntimeError,'permission scope'):self.source.admit(self.f.pair)
        self.assertEqual(self.grant_files(),self.grant_before);self.assertEqual(self.case.dispatches,1)

    def test_changed_core_pair_or_membership_is_never_repaired_to_obtain_admission(self):
        self.prepare();path=self.setup.path(self.peer.CORE_UNIT);path.write_bytes(path.read_bytes()+b'\nchanged')
        with self.assertRaisesRegex(RuntimeError,'authority changed'):self.source.admit(self.f.pair)
        self.assertTrue(path.read_bytes().endswith(b'changed'))
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.grant_files(),self.grant_before)

    def test_changed_environment_cannot_enable_a_remote_capability_inside_code_maintenance(self):
        self.prepare();path=self.setup.path(self.peer.ENV)
        path.write_bytes(path.read_bytes().replace(b'AGENT_REMOTE_ENABLED=0',b'AGENT_REMOTE_ENABLED=1'))
        with self.assertRaisesRegex(RuntimeError,'authority changed'):self.source.admit(self.f.pair)
        self.assertIn(b'AGENT_REMOTE_ENABLED=1',path.read_bytes());self.assertEqual(self.case.dispatches,1)

    def test_missing_source_history_keeps_grant_fate_but_refuses_current_binding(self):
        self.prepare();self.install_and_finish();self.setup.path(self.source.CURRENT).unlink()
        with self.assertRaisesRegex(RuntimeError,'without original maintenance proof'):self.profile.check()
        status=self.peer.status(self.case.operation)
        self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        self.assertEqual(self.grant_files(),self.grant_before)

    def test_interruption_after_peer_publication_completes_without_reinstall_or_regrant(self):
        self.prepare();self.source.admit(self.f.pair);self.f.install_payload_fixture()
        real=self.source.replace
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.peer.PUBLIC:raise OSError('after original current peer publication')
        with patch.object(self.source,'replace',side_effect=fault):
            with self.assertRaises(OSError):self.source.finish(self.f.pair)
        before=self.setup.path(self.peer.PUBLIC).stat()
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.peer.status(self.case.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.source.finish(self.f.pair)['state'],'APPLIED')
        after=self.setup.path(self.peer.PUBLIC).stat()
        self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),
                         (after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(self.grant_files(),self.grant_before);self.assertEqual(self.case.dispatches,1)

    def test_two_source_evolutions_anchor_back_to_the_same_original_grant(self):
        self.prepare();self.install_and_finish()
        self.operation=str(uuid.uuid4());self.f.new_unit+=b'\n# second reviewed source fixture\n'
        source=json.loads(self.f.source_raw)
        unit_sha=hashlib.sha256(self.f.new_unit).hexdigest()
        for row in source['sourceFiles']:
            if row['path']=='packaging/'+native.V2_UNIT:row['sha256']=unit_sha
        self.f.source_raw=json.dumps(source).encode();self.f.pair={
            **self.f.pair,'unitSha256':unit_sha,'sourceManifestSha256':hashlib.sha256(self.f.source_raw).hexdigest()}
        loader=self.source.bridge()['coreLoaderSha256']
        self.prerm=("#!/usr/bin/python3 -I\nSCRIPT_NAME = 'prerm'\nPACKAGE_CORE_LOADER_SHA256 = "+repr(loader)
            +'\nPACKAGE_NATIVE_PAIR = '+repr(self.f.pair)+'\n').encode()+self.f.control_body
        self.assertEqual(self.prepare()['state'],'UNKNOWN');self.install_and_finish();self.profile.check()
        self.assertEqual(self.peer.status(self.case.operation)['currentReadiness'],'READY')
        self.assertEqual(self.grant_files(),self.grant_before);self.assertEqual(self.case.dispatches,1)


if __name__=='__main__':unittest.main(verbosity=2)
