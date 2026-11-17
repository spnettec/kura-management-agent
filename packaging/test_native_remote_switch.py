"""Root switch-delegation/filesystem fixtures; no channel or live service actions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_retained_enrollment_source as fixture
native=fixture.native


@unittest.skipUnless(os.geteuid()==0,'disposable Root Linux fixture required')
class NativeRemoteSwitchTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.RetainedEnrollmentSourceTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup,self.source=self.case.profile,self.case.setup,self.case.source
        self.switch=native.KuraRemoteSwitch(self.profile);self.operation=str(uuid.uuid4())
        self.env=self.source.raw(self.switch.ENV);self.before=self.case.before;self.sealed=self.case.sealed

    def assert_retained(self):
        state,summary=self.source.enrolled_snapshot(self.case.local,include_switch=False)
        self.assertEqual({k:v for k,v in state.items() if k!=self.switch.ENV},
                         {k:v for k,v in self.before.items() if k!=self.switch.ENV})
        self.assertEqual(summary,self.case.summary);self.assertEqual(self.case.case.sealed_files(),self.sealed)
        self.assertEqual(self.case.case.local.dispatches,1)

    def test_one_root_grant_changes_only_local_switch_permission_and_keeps_original_authorities(self):
        result=self.switch.authorize(self.operation);self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        new=self.source.raw(self.switch.ENV)
        self.assertEqual(new,self.env.replace(b'AGENT_KURA_REMOTE_MANAGEMENT=0\n',b'AGENT_KURA_REMOTE_MANAGEMENT=1\n'))
        self.assertIn(b'AGENT_REMOTE_ENABLED=0\n',new);self.assert_retained();self.profile.check()
        grant=self.switch.check();self.assertTrue(grant['canControl']);self.assertFalse(grant['unitStarted']);self.assertFalse(grant['remoteEnabled'])

    def test_environment_flag_without_its_original_root_grant_never_becomes_authority(self):
        self.setup.path(self.switch.ENV).write_bytes(self.env.replace(b'AGENT_KURA_REMOTE_MANAGEMENT=0\n',b'AGENT_KURA_REMOTE_MANAGEMENT=1\n'))
        with self.assertRaises(RuntimeError):self.profile.check()
        with self.assertRaises(RuntimeError):self.switch.authorize(self.operation)
        self.assertFalse(self.setup.path(self.switch.PENDING).exists())

    def test_same_completed_id_is_readonly_and_another_id_cannot_regrant(self):
        self.switch.authorize(self.operation);path=self.setup.path(self.switch.ENV);before=path.stat()
        self.assertEqual(self.switch.authorize(self.operation)['state'],'APPLIED')
        with self.assertRaisesRegex(RuntimeError,'already exists'):self.switch.authorize(str(uuid.uuid4()))
        after=path.stat();self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),(after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.assert_retained()

    def interrupted(self,target):
        real=self.switch.source.replace
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==target:raise OSError('after original switch publication')
        with patch.object(self.switch.source,'replace',side_effect=fault):
            with self.assertRaises(OSError):self.switch.authorize(self.operation)
        self.assertEqual(self.switch.status(self.operation)['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'uncertain original outcome'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'original remote-switch'):self.switch.complete(str(uuid.uuid4()))
        before=self.setup.path(target).stat();self.assertEqual(self.switch.complete(self.operation)['state'],'APPLIED')
        after=self.setup.path(target).stat();self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),(after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.profile.check();self.assert_retained()

    def test_lost_environment_publication_reply_finishes_original_without_rewriting_environment(self):
        self.interrupted(self.switch.ENV)

    def test_lost_public_grant_reply_finishes_original_without_republishing_it(self):
        self.interrupted(self.switch.PUBLIC)

    def test_lost_current_pointer_reply_finishes_original_without_replacing_it(self):
        self.interrupted(self.switch.CURRENT)

    def test_mutated_pending_scope_or_environment_is_preserved_and_refused(self):
        real=self.switch.source.replace
        with patch.object(self.switch.source,'replace',side_effect=OSError('before environment publication')):
            with self.assertRaises(OSError):self.switch.authorize(self.operation)
        ticket=self.source.json(self.switch.PENDING);ticket['grant']['remoteEnabled']=True
        self.setup.path(self.switch.PENDING).write_text(self.profile.encode(ticket))
        with self.assertRaisesRegex(RuntimeError,'intent differs'):self.switch.complete(self.operation)
        self.assertEqual(self.source.raw(self.switch.ENV),self.env);self.assertTrue(self.setup.path(self.switch.PENDING).exists())

    def test_missing_original_pointer_keeps_applied_fate_but_blocks_new_grants_and_startup(self):
        self.switch.authorize(self.operation);self.setup.path(self.switch.CURRENT).unlink()
        status=self.switch.status(self.operation);self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        with self.assertRaisesRegex(RuntimeError,'proof is missing'):self.profile.check()
        with self.assertRaises(RuntimeError):self.switch.authorize(str(uuid.uuid4()))

    def test_retained_source_upgrade_preserves_the_stable_permission_and_every_original_grant(self):
        self.switch.authorize(self.operation);assets=self.switch.proof_assets()
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in assets if p.is_file()}
        self.assertEqual(self.case.prepare()['state'],'UNKNOWN');self.case.case.install()
        self.assertEqual(self.source.finish(self.case.case.f.pair)['state'],'APPLIED');self.profile.check()
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in assets if p.is_file()})
        self.assertEqual(self.switch.status(self.operation)['currentReadiness'],'READY');self.assert_retained()

    def interrupted_intent_index(self,target):
        real=self.switch.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==target:raise OSError('after original switch intent boundary')
        with patch.object(self.switch.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.switch.authorize(self.operation)
        self.assertEqual(self.source.raw(self.switch.ENV),self.env)
        self.assertEqual(self.switch.status(self.operation)['state'],'UNKNOWN')
        with self.assertRaises(RuntimeError):self.switch.authorize(str(uuid.uuid4()))
        self.assertEqual(self.switch.complete(self.operation)['state'],'APPLIED');self.profile.check();self.assert_retained()

    def test_original_global_intent_survives_interruption_before_any_index_file(self):
        self.interrupted_intent_index(self.switch.PENDING)

    def test_original_index_survives_interruption_before_private_env_copies(self):
        self.interrupted_intent_index(self.switch.record(self.operation,'intent.json'))

    def test_original_before_env_survives_interruption_before_incoming_env(self):
        self.interrupted_intent_index(self.switch.record(self.operation,'previous.env'))

    def test_missing_global_marker_with_even_empty_authority_directory_cannot_start_new_id(self):
        self.profile.directory(self.switch.RECORDS,0,0,0o700,True)
        with self.assertRaisesRegex(RuntimeError,'proof is missing'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'proof is missing'):self.switch.authorize(self.operation)

    def test_published_completion_bytes_must_match_original_ack_before_reporting_applied(self):
        self.switch.authorize(self.operation)
        path=self.setup.path(self.switch.record(self.operation,'result.json'));path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(RuntimeError,'completion receipt changed'):self.switch.status(self.operation)

    def test_grant_schema_rejects_boolean_versions_or_roles_and_unknown_permissions(self):
        grant,_,_=self.switch.context(self.operation)
        for key,value in [('schemaVersion',True),('nativeUid',True),('canControl',1),('remoteEnabled',0),('arbitraryPermission',True)]:
            with self.subTest(key=key):
                bad={**grant,key:value}
                with self.assertRaisesRegex(RuntimeError,'grant schema'):self.switch.validate_grant(bad)

    def test_local_inspection_discovers_only_the_current_public_namespace(self):
        initial=self.source.json(native.V2_ADMIN+'/initialization.json')['operationId']
        before=self.case.case.sealed_files();env_info=self.setup.path(self.switch.ENV).stat()
        value=self.profile.inspect()
        self.assertEqual(set(value),{'schemaVersion','profile','initializationId','sourceManifestSha256',
                                    'nativeUid','controlGid','permission','requestId','readiness'})
        self.assertEqual((value['initializationId'],value['permission'],value['requestId'],value['readiness']),
                         (initial,'NONE',None,'READY'))
        self.assertEqual(before,self.case.case.sealed_files())
        self.assertEqual(env_info,self.setup.path(self.switch.ENV).stat())
        self.assertFalse(self.setup.path(self.switch.PENDING).exists());self.assert_retained()

    def test_each_saved_request_action_checks_root_namespace_before_request_access(self):
        actions={'authorize-kura-remote-switch':'authorize','complete-kura-remote-switch':'complete',
                 'kura-remote-switch-status':'status'}
        for action,method in actions.items():
            with self.subTest(action=action),patch.object(native.KuraRemoteSwitch,method) as called:
                with self.assertRaisesRegex(RuntimeError,'Different native installation'):
                    self.profile.remote_switch_action(action,self.operation,str(uuid.uuid4()))
                called.assert_not_called()
        self.assertFalse(self.setup.path(self.switch.PENDING).exists());self.assert_retained()

    def test_current_namespace_routes_the_original_request_without_another_grant(self):
        initial=self.profile.inspect()['initializationId']
        value=self.profile.remote_switch_action('authorize-kura-remote-switch',self.operation,initial)
        self.assertEqual(value['state'],'APPLIED');env=self.setup.path(self.switch.ENV).stat()
        value=self.profile.remote_switch_action('kura-remote-switch-status',self.operation,initial)
        self.assertEqual(value['state'],'APPLIED');self.assertEqual(env,self.setup.path(self.switch.ENV).stat())
        current=self.profile.inspect()
        self.assertEqual((current['permission'],current['requestId'],current['readiness']),('GRANTED',self.operation,'READY'))
        self.assert_retained()

    def test_inspection_can_discover_original_pending_id_before_private_index_exists(self):
        real=self.switch.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.switch.PENDING:raise OSError('after durable original namespace intent')
        with patch.object(self.switch.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.switch.authorize(self.operation)
        value=self.profile.inspect()
        self.assertEqual((value['permission'],value['requestId'],value['readiness']),('PENDING',self.operation,'REFUSED'))
        self.assertEqual(self.source.raw(self.switch.ENV),self.env)
        result=self.profile.remote_switch_action('complete-kura-remote-switch',self.operation,value['initializationId'])
        self.assertEqual(result['state'],'APPLIED');self.assert_retained()

    def test_pending_identity_mismatch_never_exposes_an_old_request_as_local(self):
        real=self.switch.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.switch.PENDING:raise OSError('after durable intent')
        with patch.object(self.switch.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.switch.authorize(self.operation)
        pending=self.source.json(self.switch.PENDING);pending['grant']['initializationId']=str(uuid.uuid4())
        self.setup.path(self.switch.PENDING).write_text(self.profile.encode(pending))
        with self.assertRaisesRegex(RuntimeError,'different installation'):self.profile.inspect()
        self.assertEqual(self.source.raw(self.switch.ENV),self.env)

    def test_damaged_installed_source_pair_refuses_before_any_saved_request_lookup(self):
        initial=self.profile.inspect()['initializationId']
        self.setup.path(native.V2_IDENTITY).write_text('{}\n')
        with patch.object(native.KuraRemoteSwitch,'status') as called:
            with self.assertRaisesRegex(RuntimeError,'identity/source pair changed'):
                self.profile.remote_switch_action('kura-remote-switch-status',self.operation,initial)
            called.assert_not_called()
        with self.assertRaises(RuntimeError):self.profile.inspect()

    def test_invalid_environment_can_be_inspected_but_is_never_reported_ready(self):
        self.setup.path(self.switch.ENV).write_bytes(self.env.replace(b'AGENT_REMOTE_ENABLED=0\n',b'AGENT_REMOTE_ENABLED=1\n'))
        value=self.profile.inspect()
        self.assertEqual((value['permission'],value['readiness']),('NONE','REFUSED'))
        self.assertNotIn('AGENT_REMOTE_ENABLED',json.dumps(value))

    def test_remote_switch_cli_requires_current_initialization_before_root_access(self):
        for action in ['authorize-kura-remote-switch','complete-kura-remote-switch','kura-remote-switch-status']:
            result=subprocess.run([sys.executable,'-B',str(Path(native.__file__)),action,'--request-id',self.operation],
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2);self.assertIn('--initialization-id',result.stderr)
        self.assertFalse(self.setup.path(self.switch.PENDING).exists())


if __name__=='__main__':unittest.main()
