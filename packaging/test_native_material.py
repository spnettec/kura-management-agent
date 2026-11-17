"""Independent material capability with sealed local grant and no env mutation."""
import hashlib
import json
import os
import unittest
from unittest.mock import patch
import uuid

import test_native_kura_peer as fixture

native=fixture.native


@unittest.skipUnless(os.geteuid()==0, 'disposable Root Linux fixture required')
class NativeMaterialTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.KuraPeerTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup=self.case.profile,self.case.setup
        self.peer=self.case.peer;self.peer.authorize(self.case.operation)
        self.material=native.KuraMaterial(self.profile);self.operation=str(uuid.uuid4())
        meta=json.loads(self.setup.path('/usr/share/kura-management-agent/native-profile.json').read_bytes())
        paths=['/usr/lib/kura-management-agent/enrollment_reader.py',
            '/usr/lib/systemd/system/kura-management-enrollment-reader.socket',
            '/usr/lib/systemd/system/kura-management-enrollment-reader@.service']
        value={'schemaVersion':1,'protocolVersion':1,'user':'kurad','socket':self.material.UPSTREAM,
            'sourceRoot':self.material.SOURCE,'files':{p:meta['files'][p] for p in paths}}
        self.case.case.case.write('/usr/share/kura-management-agent/enrollment-reader.json',json.dumps(value))
        self.env=self.material.source.raw(self.peer.ENV);self.before=self.material.state()
        self.original=self.peer.original();self.calls=[]
        real=self.setup.systemctl
        def systemctl(*args):self.calls.append(args);return real(*args)
        self.setup.systemctl=systemctl

    def test_material_authority_keeps_original_env_peer_state_and_remote_disabled(self):
        result=self.material.authorize(self.operation)
        self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        self.profile.check();public=self.material.check();private=json.loads(self.material.source.raw(self.material.RELAY))
        self.assertEqual(public['peerAuthorizationId'],self.case.operation)
        self.assertEqual((private['agentUid'],private['sourceUid']),(995,991))
        self.assertEqual(self.env,self.material.source.raw(self.peer.ENV))
        self.assertEqual(self.before,self.material.state());self.assertEqual(self.original,self.peer.original())
        self.assertFalse(self.setup.path(self.material.SOURCE).exists())
        self.assertFalse(any(c[0] in ['start','enable','stop'] for c in self.calls))
        self.assertEqual(self.case.dispatches,1)
        self.assertEqual(self.material.authorize(self.operation)['state'],'APPLIED')
        with self.assertRaisesRegex(RuntimeError,'original maintenance'):self.material.authorize(str(uuid.uuid4()))

    def test_interruption_after_private_grant_completes_without_repairing_env_or_source(self):
        real=self.material.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.material.RELAY:raise OSError('after original private material grant')
        with patch.object(self.material.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.material.authorize(self.operation)
        before=self.setup.path(self.material.RELAY).stat()
        self.assertEqual(self.material.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.material.authorize(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.material.complete(self.operation)['state'],'APPLIED')
        after=self.setup.path(self.material.RELAY).stat()
        self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),
                         (after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(self.env,self.material.source.raw(self.peer.ENV));self.assertEqual(self.before,self.material.state())

    def test_missing_original_marker_blocks_new_ids_and_does_not_assume_publication(self):
        real=self.material.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name.endswith('/intent.json'):raise OSError('after original material intent')
        with patch.object(self.material.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.material.authorize(self.operation)
        self.setup.path(self.material.PENDING).unlink()
        self.assertEqual(self.material.status(self.operation)['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.material.authorize(str(uuid.uuid4()))
        self.assertFalse(self.setup.path(self.material.PUBLIC).exists())

    def test_pub_or_private_grant_drift_keeps_fate_but_refuses_readiness(self):
        self.material.authorize(self.operation);path=self.setup.path(self.material.PUBLIC)
        original=path.read_bytes();value=json.loads(original);value['sourceUid']=0;path.write_text(json.dumps(value))
        self.assertEqual(self.material.status(self.operation)['currentReadiness'],'REFUSED')
        path.write_bytes(original);private=self.setup.path(self.material.RELAY);private.write_bytes(private.read_bytes()+b' ')
        status=self.material.status(self.operation)
        self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        self.assertTrue(private.read_bytes().endswith(b' '))

    def test_material_pair_changes_are_refused_without_republishing_the_grant(self):
        self.material.authorize(self.operation)
        path=self.setup.path('/usr/lib/systemd/system/kura-management-enrollment-reader@.service')
        path.write_bytes(path.read_bytes()+b'\nchanged')
        with self.assertRaisesRegex(RuntimeError,'pair|payload'):self.profile.check()
        self.assertEqual(self.material.status(self.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.original,self.peer.original())

    def test_local_only_joint_source_cannot_implicitly_carry_material_authority(self):
        self.material.authorize(self.operation);source=native.SourceUpdate(self.profile);source.local_kura_peer=True
        with self.assertRaisesRegex(RuntimeError,'separate joint maintenance'):
            source.prepare(str(uuid.uuid4()),'/never-read.deb','a'*64)
        self.assertFalse(self.setup.path(source.PENDING).exists())
        self.assertEqual(self.material.status(self.operation)['currentReadiness'],'READY')

    def test_core_can_remain_active_while_only_native_material_consumer_is_stopped(self):
        self.case.running=True
        self.assertEqual(self.material.authorize(self.operation)['state'],'APPLIED')
        self.assertTrue(self.case.running);self.assertFalse(any(c[0] in ['stop','start','enable'] for c in self.calls))

    def test_existing_wrong_source_is_preserved_without_adoption_or_grant(self):
        path=self.setup.path(self.material.SOURCE);path.mkdir(parents=True);path.chmod(0o755)
        before=path.stat()
        with self.assertRaisesRegex(RuntimeError,'Preserve unreviewed'):self.material.authorize(self.operation)
        after=path.stat();self.assertEqual((before.st_ino,before.st_mode,before.st_uid,before.st_gid),
                                         (after.st_ino,after.st_mode,after.st_uid,after.st_gid))
        self.assertFalse(self.setup.path(self.material.PENDING).exists())


if __name__=='__main__':unittest.main(verbosity=2)
