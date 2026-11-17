"""Original material capability continuity across explicit source maintenance."""
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import test_native_material as fixture

native=fixture.native


@unittest.skipUnless(os.geteuid()==0, 'disposable Root Linux fixture required')
class MaterialSourceTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.NativeMaterialTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup,self.material=self.case.profile,self.case.setup,self.case.material
        self.material.authorize(self.case.operation)
        self.local=self.case.case;self.f=self.local.case;self.peer=self.local.peer
        self.source=native.SourceUpdate(self.profile);self.source.material_kura_peer=True
        self.operation=str(uuid.uuid4());self.source.incoming_version=self.f.update.incoming_version
        loader=self.source.bridge()['coreLoaderSha256']
        self.setup.path(self.source.PRERM).write_bytes(self.f.old_prerm.replace(repr('b'*64).encode(),repr(loader).encode(),1))
        self.before=self.source.initial_snapshot(extra_config=['enrollment-relay-grant.json'])
        self.original_public=self.material.check();self.original=self.material.original()
        self.sealed_before=self.sealed_files()

    def sealed_files(self):
        paths=[p for name in [self.peer.RECORDS,self.material.RECORDS] for p in self.setup.path(name).rglob('*') if p.is_file()]
        paths.extend(self.setup.path(n) for n in [self.peer.CURRENT,self.material.CURRENT])
        result={}
        for path in paths:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME)
            with os.fdopen(fd,'rb') as stream:
                m=os.fstat(stream.fileno());result[str(path)]=[m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,
                    m.st_size,m.st_mtime_ns,m.st_ctime_ns,hashlib.file_digest(stream,'sha256').hexdigest()]
        return result

    def prepare(self):
        meta=json.loads(self.setup.path('/usr/share/kura-management-agent/native-profile.json').read_bytes())
        meta['files'][native.V2_VENDOR]=self.f.pair['unitSha256']
        self.source.incoming_material_pair={'publisherPairSha256':self.source.digest(self.setup.path(
            '/usr/share/kura-management-agent/enrollment-reader.json').read_bytes()),
            'relayPairSha256':self.source.digest(json.dumps(meta).encode())}
        loader=self.source.bridge()['coreLoaderSha256']
        prerm=("#!/usr/bin/python3 -I\nSCRIPT_NAME = 'prerm'\nPACKAGE_CORE_LOADER_SHA256 = "+repr(loader)
            +'\nPACKAGE_NATIVE_PAIR = '+repr(self.f.pair)+'\n').encode()+self.f.control_body
        with patch.object(self.source,'candidate',return_value=(self.f.pair,prerm)):
            return self.source.prepare(self.operation,'/reviewed-material-source.deb','a'*64)

    def install(self):
        self.source.admit(self.f.pair);self.f.install_payload_fixture()

    def assert_preserved(self):
        self.assertEqual(self.before,self.source.initial_snapshot(extra_config=['enrollment-relay-grant.json']))
        self.assertEqual(self.sealed_before,self.sealed_files());self.assertEqual(self.original,self.material.original())
        self.assertEqual(self.local.dispatches,1)

    def test_joint_source_advances_only_code_bindings_and_keeps_original_material_proof(self):
        self.assertEqual(self.prepare()['state'],'UNKNOWN');self.install()
        self.assertEqual(self.source.finish(self.f.pair)['state'],'APPLIED');self.profile.check()
        current=self.material.check();mutable={'nativeIdentitySha256','publisherPairSha256','relayPairSha256','relayGrantSha256'}
        self.assertEqual({k:v for k,v in current.items() if k not in mutable},
                         {k:v for k,v in self.original_public.items() if k not in mutable})
        self.assertNotEqual(current['nativeIdentitySha256'],self.original_public['nativeIdentitySha256'])
        self.assertNotEqual(current['relayPairSha256'],self.original_public['relayPairSha256'])
        self.assertEqual(self.material.source.raw(self.material.RELAY),self.material.private_bytes(current))
        self.assertEqual(self.material.status(self.case.operation)['currentReadiness'],'READY');self.assert_preserved()

    def test_local_only_action_cannot_carry_the_material_grant(self):
        self.source.material_kura_peer=False;self.source.local_kura_peer=True
        with self.assertRaisesRegex(RuntimeError,'separate joint maintenance'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_active_core_or_undrained_material_socket_refuses_before_any_source_intent(self):
        self.local.running=True
        with self.assertRaisesRegex(RuntimeError,'Explicitly stop'):self.prepare()
        self.local.running=False;real=self.setup.systemctl
        def active(*args):
            if args[0]=='show' and args[1].endswith('.socket') and '--property=ActiveState,NConnections' in args:
                return SimpleNamespace(stdout='ActiveState=active\nNConnections=1\n')
            return real(*args)
        with patch.object(self.setup,'systemctl',side_effect=active):
            with self.assertRaisesRegex(RuntimeError,'stop and drain'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_existing_core_material_is_not_reinterpreted_as_initial_state(self):
        root=self.setup.path(self.material.SOURCE);root.mkdir(parents=True,mode=0o700)
        for p in [root.parent,root]:p.chmod(0o700);os.chown(p,991,992)
        before=root.stat()
        with self.assertRaisesRegex(RuntimeError,'Real retained enrollment'):self.prepare()
        self.assertEqual((before.st_ino,before.st_mode,before.st_ctime_ns),(root.stat().st_ino,root.stat().st_mode,root.stat().st_ctime_ns))
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assertEqual(self.sealed_before,self.sealed_files())

    def test_changed_material_permission_is_refused_before_admission(self):
        self.prepare();original=self.source.json(self.source.PENDING)
        for key,value in [('sourceUid',0),('sourceRoot','/etc/kura/credentials'),('remoteEnabled',True),('readerGid',0),('schemaVersion',True)]:
            with self.subTest(key=key):
                ticket=json.loads(json.dumps(original));ticket['materialTransition']['incoming'][key]=value
                self.setup.path(self.source.PENDING).write_text(self.profile.encode(ticket))
                with self.assertRaisesRegex(RuntimeError,'permission scope'):self.source.admit(self.f.pair)
        self.assertEqual(self.sealed_before,self.sealed_files())

    def test_changed_private_relay_grant_is_preserved_and_not_admitted(self):
        self.prepare();path=self.setup.path(self.material.RELAY);path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(RuntimeError,'material authority changed'):self.source.admit(self.f.pair)
        self.assertTrue(path.read_bytes().endswith(b' '));self.assertEqual(self.sealed_before,self.sealed_files())

    def test_original_authorization_hash_mismatch_cannot_obtain_admission(self):
        self.prepare();ticket=self.source.json(self.source.PENDING)
        ticket['materialTransition']['authorizationResultSha256']='f'*64
        self.setup.path(self.source.PENDING).write_text(self.profile.encode(ticket))
        with self.assertRaisesRegex(RuntimeError,'material authority changed'):self.source.admit(self.f.pair)
        self.assertEqual(self.sealed_before,self.sealed_files())

    def test_complete_cannot_admit_an_unadmitted_payload_or_publish_a_new_identity(self):
        self.prepare();before=self.source.raw(native.V2_IDENTITY,0o644);self.f.install_payload_fixture()
        with self.assertRaisesRegex(RuntimeError,'cannot publish'):self.source.complete(self.operation)
        self.assertEqual(before,self.source.raw(native.V2_IDENTITY,0o644))
        self.assertTrue(self.setup.path(self.source.PENDING).exists());self.assertEqual(self.sealed_before,self.sealed_files())

    def interrupted_publication(self, target):
        self.prepare();self.install();real=self.source.replace
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==target:raise OSError('after original material source publication')
        with patch.object(self.source,'replace',side_effect=fault):
            with self.assertRaises(OSError):self.source.finish(self.f.pair)
        before=self.setup.path(target).stat()
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.material.status(self.case.operation)['state'],'APPLIED')
        self.assertEqual(self.material.status(self.case.operation)['currentReadiness'],'REFUSED')
        with self.assertRaisesRegex(RuntimeError,'original native source'):self.source.complete(str(uuid.uuid4()))
        self.assertEqual(self.source.complete(self.operation)['state'],'APPLIED')
        after=self.setup.path(target).stat()
        self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),(after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.profile.check();self.assert_preserved()

    def test_private_publication_interruption_completes_original_without_reinstall(self):
        self.interrupted_publication(self.material.RELAY)

    def test_public_publication_interruption_does_not_rewrite_already_published_assets(self):
        self.interrupted_publication(self.material.PUBLIC)

    def test_missing_source_history_keeps_applied_fate_but_refuses_current_material_binding(self):
        self.prepare();self.install();self.source.finish(self.f.pair);self.setup.path(self.source.CURRENT).unlink()
        status=self.material.status(self.case.operation)
        self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        self.assertEqual(self.sealed_before,self.sealed_files())

    def test_material_history_cannot_be_dropped_while_native_and_local_peer_history_remain_valid(self):
        self.prepare();self.install();self.source.finish(self.f.pair)
        result=self.source.json(self.source.record(self.operation,'result.json'));del result['materialTransition']
        raw=self.profile.encode(result).encode();self.setup.path(self.source.record(self.operation,'result.json')).write_bytes(raw)
        pointer=self.source.json(self.source.CURRENT);pointer['sha256']=self.source.digest(raw)
        self.setup.path(self.source.CURRENT).write_text(self.profile.encode(pointer))
        self.source.verify_chain(self.source.json(native.V2_ADMIN+'/initialization.json'),self.profile.descriptor())
        self.assertIsNotNone(self.peer.check())
        with self.assertRaisesRegex(RuntimeError,'without original authority history'):self.material.check()
        self.assertEqual(self.material.status(self.case.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.sealed_before,self.sealed_files())

    def test_two_evolutions_anchor_to_the_same_original_material_and_local_authorization(self):
        self.prepare();self.install();self.source.finish(self.f.pair)
        self.operation=str(uuid.uuid4());self.f.new_unit+=b'\n# next material source fixture\n'
        source=json.loads(self.f.source_raw);unit_sha=hashlib.sha256(self.f.new_unit).hexdigest()
        for row in source['sourceFiles']:
            if row['path']=='packaging/'+native.V2_UNIT:row['sha256']=unit_sha
        self.f.source_raw=json.dumps(source).encode();self.f.pair={**self.f.pair,'unitSha256':unit_sha,
            'sourceManifestSha256':hashlib.sha256(self.f.source_raw).hexdigest()}
        self.assertEqual(self.prepare()['state'],'UNKNOWN');self.install();self.source.finish(self.f.pair)
        self.profile.check();self.assert_preserved()
        self.assertEqual(self.material.status(self.case.operation)['currentReadiness'],'READY')


if __name__=='__main__':unittest.main(verbosity=2)
