"""Disposable Root filesystem/crypto fixtures; no live Kura or source admission."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import test_native_material_source as fixture
native=fixture.native


@unittest.skipUnless(os.geteuid()==0,'disposable Root Linux fixture required')
class RetainedEnrollmentSourceTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.MaterialSourceTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup,self.source=self.case.profile,self.case.setup,self.case.source
        self.source.enrolled_material_kura_peer=True
        self.local=self.case.peer.check();descriptor=self.profile.descriptor()
        self.uid,self.gid=descriptor['uid'],descriptor['gid'];self.core_uid,self.core_gid=self.local['kuraUid'],self.local['kuraGid']
        self.request=str(uuid.uuid4());self.candidate=str(uuid.uuid4());self.context=str(uuid.uuid4())
        temporary=tempfile.TemporaryDirectory(prefix='retained-enrollment-crypto-');self.addCleanup(temporary.cleanup);tmp=Path(temporary.name)
        def openssl(*args):
            return subprocess.run(['/usr/bin/openssl',*map(str,args)],capture_output=True,check=True).stdout
        openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=source-fixture',
                '-keyout',tmp/'client-key.pem','-out',tmp/'request.pem')
        openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=source-fixture-ca',
                '-days','14','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
                '-keyout',tmp/'ca-key.pem','-out',tmp/'ca.pem')
        ext=tmp/'client.ext';ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        openssl('x509','-req','-in',tmp/'request.pem','-CA',tmp/'ca.pem','-CAkey',tmp/'ca-key.pem','-set_serial','1',
                '-days','7','-extfile',ext,'-out',tmp/'client.pem')
        private=openssl('pkcs8','-topk8','-nocrypt','-in',tmp/'client-key.pem','-outform','DER')
        public=openssl('pkey','-in',tmp/'client-key.pem','-pubout','-outform','DER')
        leaf=(tmp/'client.pem').read_bytes();ca=(tmp/'ca.pem').read_bytes()
        end=openssl('x509','-in',tmp/'client.pem','-noout','-enddate').decode().strip().partition('=')[2]
        not_after=datetime.datetime.strptime(end,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00','Z')
        self.material={'schema':'yofc.kura.remote.certificates.v1','requestId':self.request,'gatewayId':'source-fixture',
            'endpoint':'https://center.example.invalid:18443','publicKeySha256':hashlib.sha256(public).hexdigest(),
            'clientCertificateSha256':hashlib.sha256(openssl('x509','-in',tmp/'client.pem','-outform','DER')).hexdigest(),
            'issuerCaSha256':hashlib.sha256(ca).hexdigest(),'consoleCaSha256':hashlib.sha256(ca).hexdigest(),'notAfter':not_after}
        manifest=json.dumps(self.material,separators=(',',':')).encode();self.stage=hashlib.sha256(manifest).hexdigest()
        values={'private.pk8':private,'public.der':public,'request.pem':(tmp/'request.pem').read_bytes(),
            'gateway.id':b'source-fixture','complete':b'kura.remote.identity.v1\n','certificates/client-chain.pem':leaf,
            'certificates/issuer-ca.pem':ca,'certificates/console-ca.pem':ca,'certificates/manifest.json':manifest,
            'certificates/complete':(self.stage+'\n').encode()}
        self.core=self.setup.path(native.KuraMaterial.SOURCE);self.slot=self.core/self.request
        for path in [self.core.parent,self.core,self.slot,self.slot/'certificates']:self.directory(path,core=True)
        self.write(self.core.parent/'management-enrollment-context-v1',('yofc.kura.remote-request-context.v1\n'+self.context+'\n').encode(),core=True)
        self.write(self.core/'.enrollment.lock',b'',core=True)
        for name,value in values.items():self.write(self.slot/name,value,core=True)
        self.base=self.setup.path(native.V2_STATE+'/enrollment');self.owned=self.base/'candidates'/self.candidate
        for path in [self.base,self.base/'candidates',self.owned,self.owned/'certificates']:self.directory(path)
        for name,value in values.items():self.write(self.owned/name,value)
        self.write(self.owned/'agent-key.pem',(tmp/'client-key.pem').read_bytes())
        for name,pem in [('client-chain.pem',leaf),('issuer-ca.pem',ca),('console-ca.pem',ca)]:
            self.write(self.owned/(name+'-0.certificate.pem'),pem)
            if name!='client-chain.pem':self.write(self.owned/(name+'-0.anchor.pem'),pem)
        receipt={'schema':'yofc.agent.enrollment.v1','candidateId':self.candidate,'requestId':self.request,
            'stageSha256':self.stage,'material':self.material,'bindingGeneration':1,'sourceUid':self.core_uid,
            'actor':'kura-uid:'+str(self.core_uid),'operator':'admin','acceptedAtUnixMs':1}
        raw=json.dumps(receipt,separators=(',',':')).encode()
        for path in [self.base/'identity.json',self.owned/'receipt.json',self.owned/'completed-intent.json']:self.write(path,raw)
        self.write(self.owned/'identity-complete',(hashlib.sha256(raw).hexdigest()+'\n').encode())
        remote={'version':1,'revision':str(uuid.uuid4()),'enabled':False,'actor':receipt['actor']}
        self.remote=self.setup.path(native.V2_STATE+'/remote-management.json');self.write(self.remote,json.dumps(remote).encode())
        self.before,self.summary=self.source.enrolled_snapshot(self.local)
        self.sealed=self.case.sealed_files()

    def directory(self,path,core=False):
        path.mkdir(mode=0o700,parents=True,exist_ok=True);path.chmod(0o700)
        os.chown(path,self.core_uid if core else self.uid,self.core_gid if core else self.gid)

    def write(self,path,raw,core=False):
        path.write_bytes(raw);path.chmod(0o600);os.chown(path,self.core_uid if core else self.uid,self.core_gid if core else self.gid)

    def prepare(self):return self.case.prepare()

    def assert_preserved(self):
        state,summary=self.source.enrolled_snapshot(self.local)
        self.assertEqual(state,self.before);self.assertEqual(summary,self.summary)
        self.assertEqual(self.case.sealed_files(),self.sealed);self.assertEqual(self.case.local.dispatches,1)

    def test_explicit_enrolled_source_preserves_all_original_identity_and_material_metadata(self):
        self.assertEqual(self.prepare()['state'],'UNKNOWN');self.case.install()
        self.assertEqual(self.source.finish(self.case.f.pair)['state'],'APPLIED');self.profile.check();self.assert_preserved()
        result=self.source.json(self.source.record(self.case.operation,'result.json'))
        self.assertEqual(result['retainedEnrollment'],self.summary)

    def test_initial_material_action_still_refuses_real_enrollment_before_intent(self):
        self.source.enrolled_material_kura_peer=False
        with self.assertRaisesRegex(RuntimeError,'Real retained enrollment'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_pending_original_identity_is_preserved_and_never_completed_by_source_maintenance(self):
        marker=self.setup.path(native.V2_STATE+'/identity-enrollment-pending.json');self.write(marker,b'original unfinished intent')
        with self.assertRaisesRegex(RuntimeError,'Pending original identity'):self.prepare()
        self.assertEqual(marker.read_bytes(),b'original unfinished intent');self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_partial_completion_and_additional_candidate_are_not_adopted(self):
        path=self.owned/'completed-intent.json';before=path.read_bytes();path.unlink()
        with self.assertRaisesRegex(RuntimeError,'Incomplete, multiple or pending'):self.prepare()
        self.write(path,before);extra=self.base/'candidates'/str(uuid.uuid4());self.directory(extra)
        with self.assertRaisesRegex(RuntimeError,'Incomplete, multiple or pending'):self.prepare()
        self.assertTrue(extra.is_dir());self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_changed_core_context_after_prepare_refuses_admission_under_original_source_id(self):
        self.prepare();path=self.core.parent/'management-enrollment-context-v1'
        self.write(path,('yofc.kura.remote-request-context.v1\n'+str(uuid.uuid4())+'\n').encode(),core=True)
        with self.assertRaisesRegex(RuntimeError,'Original retained enrollment binding'):self.source.admit(self.case.f.pair)
        self.assertEqual(self.source.status(self.case.operation)['state'],'UNKNOWN')
        self.assertEqual(self.case.sealed_files(),self.sealed)

    def test_changed_core_key_and_copied_key_cannot_bypass_public_key_verification(self):
        for path,core in [(self.slot/'private.pk8',True),(self.owned/'private.pk8',False)]:self.write(path,b'not a private key',core)
        with self.assertRaisesRegex(RuntimeError,'crypto verification'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_original_source_or_native_copy_permission_and_link_drift_is_refused(self):
        path=self.owned/'public.der';path.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError,'Unsafe retained enrollment'):self.prepare()
        path.chmod(0o600);alias=self.owned/'unreviewed-link';alias.symlink_to(self.slot/'private.pk8')
        with self.assertRaisesRegex(RuntimeError,'Incomplete, multiple or pending'):self.prepare()
        self.assertTrue(alias.is_symlink());self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_remote_enabled_or_nonempty_wal_is_not_empty_retained_identity_state(self):
        raw=self.remote.read_bytes();value=json.loads(raw);value['enabled']=True;self.write(self.remote,json.dumps(value).encode())
        with self.assertRaisesRegex(RuntimeError,'remote decision'):self.prepare()
        self.write(self.remote,raw);wal=self.setup.path(native.V2_STATE+'/results.sqlite-wal');self.write(wal,b'nonempty wal')
        with self.assertRaisesRegex(RuntimeError,'Nonempty native journal'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assertEqual(wal.read_bytes(),b'nonempty wal')

    def test_retained_summary_cannot_be_dropped_from_published_source_history(self):
        self.prepare();self.case.install();self.source.finish(self.case.f.pair)
        name=self.source.record(self.case.operation,'result.json');result=self.source.json(name);del result['retainedEnrollment']
        raw=self.profile.encode(result).encode();self.setup.path(name).write_bytes(raw)
        pointer=self.source.json(self.source.CURRENT);pointer['sha256']=hashlib.sha256(raw).hexdigest();self.setup.path(self.source.CURRENT).write_text(self.profile.encode(pointer))
        with self.assertRaisesRegex(RuntimeError,'retained enrollment source proof'):self.profile.check()
        self.assertEqual(self.case.sealed_files(),self.sealed)

    def test_pending_ticket_cannot_change_the_original_package_intent_before_admission(self):
        self.prepare();ticket=self.source.json(self.source.PENDING);ticket['packageSha256']='c'*64
        self.setup.path(self.source.PENDING).write_text(self.profile.encode(ticket))
        with self.assertRaisesRegex(RuntimeError,'original native source intent|Original native source intent'):
            self.source.admit(self.case.f.pair)
        self.assertFalse(self.setup.path(self.source.record(self.case.operation,'admitted.json')).exists())
        self.assertEqual(self.case.sealed_files(),self.sealed)

    def test_receipt_unknown_fields_boolean_generation_and_control_operator_are_refused(self):
        original=json.loads((self.base/'identity.json').read_bytes())
        for change in [{'extra':True},{'bindingGeneration':True},{'sourceUid':True},{'operator':'admin\u0085injected'}]:
            with self.subTest(change=list(change)):
                value={**original,**change};self.write(self.base/'identity.json',json.dumps(value).encode())
                with self.assertRaisesRegex(RuntimeError,'Unreviewed retained identity receipt'):self.prepare()
                self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_invalid_endpoint_and_expiry_are_not_promoted_as_a_complete_retained_identity(self):
        original=json.loads((self.base/'identity.json').read_bytes())
        for change in [{'endpoint':'http://center.example.invalid'},{'endpoint':'https://user@center.example.invalid'},
                       {'endpoint':{'untrusted':'object'}},{'notAfter':'not a timestamp'}]:
            with self.subTest(change=list(change)):
                value={**original,'material':{**original['material'],**change}}
                self.write(self.base/'identity.json',json.dumps(value).encode())
                with self.assertRaisesRegex(RuntimeError,'Invalid retained endpoint or certificate expiry'):self.prepare()
                self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_well_formed_but_wrong_expiry_is_refused_even_when_manifest_and_receipts_agree(self):
        receipt=json.loads((self.base/'identity.json').read_bytes());material={**receipt['material'],'notAfter':'2099-01-01T00:00:00Z'}
        manifest=json.dumps(material,separators=(',',':')).encode();digest=hashlib.sha256(manifest).hexdigest()
        for folder,core in [(self.slot,True),(self.owned,False)]:
            self.write(folder/'certificates/manifest.json',manifest,core)
            self.write(folder/'certificates/complete',(digest+'\n').encode(),core)
        receipt={**receipt,'material':material,'stageSha256':digest};raw=json.dumps(receipt,separators=(',',':')).encode()
        for path in [self.base/'identity.json',self.owned/'receipt.json',self.owned/'completed-intent.json']:self.write(path,raw)
        self.write(self.owned/'identity-complete',(hashlib.sha256(raw).hexdigest()+'\n').encode())
        with self.assertRaisesRegex(RuntimeError,'Retained certificate expiry differs'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_inherited_openssl_configuration_does_not_enter_the_root_crypto_probe(self):
        with patch.dict(os.environ,{'OPENSSL_CONF':'/definitely/missing/retained-source-openssl.cnf',
                                    'OPENSSL_MODULES':'/untrusted/provider/directory','LANG':'untrusted'}):
            self.assert_preserved()

    def test_held_identity_change_lock_and_live_core_refuse_before_any_source_intent(self):
        import fcntl
        lock=self.setup.path(native.V2_STATE+'/system-change.lock');self.write(lock,b'')
        with lock.open('r') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError,'writer remains active'):self.prepare()
        self.case.local.running=True
        with self.assertRaisesRegex(RuntimeError,'Explicitly stop'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_actual_controller_lock_contention_returns_busy_without_entering_profile_checks(self):
        import fcntl
        import sys
        path=Path('/run/lock/kura-management-agent-setup.lock')
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=subprocess.run([sys.executable,'-I','-B',str(Path(native.__file__).resolve()),'check'],
                capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,1);self.assertIn('BUSY: preserve the original native setup operation',result.stderr)
            self.assertNotIn('Traceback',result.stderr);self.assertEqual(result.stdout,'')
        finally:os.close(fd)

    def test_interrupted_private_publication_completes_original_without_reinstall_or_identity_replay(self):
        self.prepare();self.case.install();real=self.source.replace
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.case.material.RELAY:raise OSError('after original retained source publication')
        with patch.object(self.source,'replace',side_effect=fault):
            with self.assertRaises(OSError):self.source.finish(self.case.f.pair)
        self.assertEqual(self.source.status(self.case.operation)['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'original native source'):self.source.complete(str(uuid.uuid4()))
        self.assertEqual(self.source.complete(self.case.operation)['state'],'APPLIED');self.assert_preserved()


if __name__=='__main__':unittest.main()
