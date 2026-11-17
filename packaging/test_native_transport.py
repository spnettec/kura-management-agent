"""Explicit same-host transport configuration, without changing identity evidence."""
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid
import test_retained_enrollment_source as fixture
native=fixture.native


@unittest.skipUnless(os.geteuid()==0,'disposable Root Linux fixture required')
class NativeTransportTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.RetainedEnrollmentSourceTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup,self.source=self.case.profile,self.case.setup,self.case.source
        self.switch=native.KuraRemoteSwitch(self.profile);self.switch.authorize(str(uuid.uuid4()))
        self.control=native.NativeTransport(self.profile);self.operation=str(uuid.uuid4())
        receipt,_=self.control.receipt(self.case.local);self.original=receipt['material']['endpoint']
        parsed=urlsplit(self.original);host='['+parsed.hostname+']' if ':' in parsed.hostname else parsed.hostname
        self.endpoint='https://'+host+':'+str(19444 if parsed.port!=19444 else 29444)
        self.before,self.summary=self.source.enrolled_snapshot(self.case.local)
        self.env=self.source.raw(native.V2_CONFIG+'/agent.env');self.sealed=self.case.case.sealed_files()

    def assert_retained(self):
        state,summary=self.source.enrolled_snapshot(self.case.local,include_transport=False)
        self.assertEqual(state,self.before);self.assertEqual(summary,self.summary)
        self.assertEqual(self.source.raw(native.V2_CONFIG+'/agent.env'),self.env)
        self.assertEqual(self.case.case.sealed_files(),self.sealed);self.assertEqual(self.case.case.local.dispatches,1)

    def configure(self):return self.control.configure(self.operation,self.endpoint)

    def test_one_root_configuration_changes_no_identity_grant_environment_or_remote_decision(self):
        result=self.configure();self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        config=self.control.check();self.assertEqual((config['originalEndpoint'],config['endpoint']),(self.original,self.endpoint))
        self.assertEqual(config['identityReceiptSha256'],self.summary['identityReceiptSha256']);self.assertFalse(config['remoteEnabled'])
        self.assertEqual(len(self.control.proof_assets()),7);self.profile.check();self.assert_retained()

    def test_duplicate_id_is_readonly_and_different_payload_or_new_id_cannot_replace_configuration(self):
        self.configure();path=self.setup.path(self.control.PUBLIC);before=path.stat()
        self.assertEqual(self.configure()['state'],'APPLIED')
        with self.assertRaisesRegex(RuntimeError,'parameters changed'):self.control.configure(self.operation,self.endpoint+'/')
        with self.assertRaisesRegex(RuntimeError,'already exists'):self.control.configure(str(uuid.uuid4()),self.endpoint)
        self.assertEqual(before,path.stat());self.assert_retained()

    def interrupted(self,target,method):
        real=getattr(self.source,method)
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==target:raise OSError('after original transport boundary')
        with patch.object(self.control.source,method,side_effect=fault):
            with self.assertRaises(OSError):self.configure()
        self.assertEqual(self.control.status(self.operation)['state'],'UNKNOWN')
        with self.assertRaises(RuntimeError):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'original transport'):self.control.complete(str(uuid.uuid4()))
        before=self.setup.path(target).stat()
        self.assertEqual(self.control.complete(self.operation)['state'],'APPLIED')
        if target!=self.control.PENDING:self.assertEqual(before,self.setup.path(target).stat())
        self.profile.check();self.assert_retained()

    def test_original_global_intent_completes_before_private_index_exists(self):self.interrupted(self.control.PENDING,'immutable')
    def test_lost_private_intent_reply_completes_same_operation(self):self.interrupted(self.control.record(self.operation,'intent.json'),'immutable')
    def test_lost_publication_reply_never_replaces_the_original_config(self):self.interrupted(self.control.PUBLIC,'replace')
    def test_lost_current_pointer_reply_never_replaces_the_pointer(self):self.interrupted(self.control.CURRENT,'replace')
    def test_lost_result_reply_completes_only_original_publication(self):self.interrupted(self.control.record(self.operation,'result.json'),'immutable')

    def test_pending_state_or_code_epoch_change_is_preserved_and_refused(self):
        real=self.control.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.control.PENDING:raise OSError('after original intent')
        with patch.object(self.control.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.configure()
        before=self.setup.path(native.V2_CONFIG+'/agent.env').read_bytes()
        self.setup.path(native.V2_CONFIG+'/agent.env').write_bytes(before+b'UNKNOWN_OPTION=1\n')
        with self.assertRaises(RuntimeError):self.control.complete(self.operation)
        self.assertFalse(self.setup.path(self.control.PUBLIC).exists());self.assertTrue(self.setup.path(self.control.PENDING).exists())

    def test_missing_current_proof_keeps_original_fate_but_refuses_startup_or_new_config(self):
        self.configure();self.setup.path(self.control.CURRENT).unlink()
        result=self.control.status(self.operation);self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','REFUSED'))
        with self.assertRaisesRegex(RuntimeError,'proof is missing'):self.profile.check()
        with self.assertRaises(RuntimeError):self.control.configure(str(uuid.uuid4()),self.endpoint)

    def test_mutated_current_receipt_or_foreign_gateway_is_not_a_configuration_target(self):
        self.configure();path=self.setup.path(native.V2_STATE+'/enrollment/identity.json');value=json.loads(path.read_text())
        value['material']['gatewayId']='another-gateway';path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError,'identity scope changed'):self.control.check()

    def test_foreign_installation_is_checked_before_any_saved_transport_request_path(self):
        for action,method in [('configure-native-transport-endpoint','configure'),('complete-native-transport-endpoint','complete'),('native-transport-endpoint-status','status')]:
            with self.subTest(action=action),patch.object(native.NativeTransport,method) as invoked:
                with self.assertRaisesRegex(RuntimeError,'Different native installation'):
                    self.profile.transport_action(action,self.operation,str(uuid.uuid4()),self.endpoint if method=='configure' else None)
                invoked.assert_not_called()

    def test_address_cannot_change_host_scheme_credentials_path_or_query(self):
        host=urlsplit(self.original).hostname
        for address in ['http://'+host+':19444','https://elsewhere.invalid:19444','https://user@'+host+':19444',
                        'https://'+host+':19444/path','https://'+host+':19444?q=1','https://'+host+':19444#fragment',
                        'https://'+host+':0','https://'+host+':','https://'+host+':65536',self.original]:
            with self.subTest(address=address),self.assertRaises(RuntimeError):self.control.configure(self.operation,address)
        self.assertFalse(self.setup.path(self.control.PENDING).exists());self.assert_retained()

    def test_schema_extra_fields_booleans_and_unsealed_flags_are_refused(self):
        self.configure();config=self.control.check()
        for key,value in [('schemaVersion',True),('nativeUid',True),('minimumBindingGeneration',True),('remoteEnabled',True),('unitStarted',True),('arbitraryPath','/tmp/other')]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):self.control.validate_config({**config,key:value})

    def test_changed_result_bytes_cannot_report_original_applied_fate(self):
        self.configure();p=self.setup.path(self.control.record(self.operation,'result.json'));p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaisesRegex(RuntimeError,'completion receipt changed'):self.control.status(self.operation)

    def test_source_evolution_preserves_original_transport_and_switch_proofs(self):
        self.configure();paths=self.control.proof_assets()+self.switch.proof_assets()
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
        self.assertEqual(self.case.prepare()['state'],'UNKNOWN');self.case.case.install()
        self.assertEqual(self.source.finish(self.case.case.f.pair)['state'],'APPLIED');self.profile.check()
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()})
        self.assertEqual(self.control.status(self.operation)['currentReadiness'],'READY');self.assert_retained()


if __name__=='__main__':unittest.main()
