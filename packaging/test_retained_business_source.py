"""Root transaction fixtures; crypto/UID execution is tested by the Rust inspector.

Only image/execute are replaced here. Copies, WAL bytes, namespace/history,
admission, publication and interruptions exercise the actual Python controller.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_retained_enrollment_source as fixture
import test_native_source_update as source_fixture
native=fixture.native


@unittest.skipUnless(os.geteuid()==0,'disposable Root Linux fixture required')
class RetainedBusinessSourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.RetainedEnrollmentSourceTests('runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.material=self.fixture.case;self.f=self.material.f
        self.profile,self.setup,self.source=self.fixture.profile,self.fixture.setup,self.fixture.source
        self.initialization=self.f.case.operation
        self.source.retained_business=True
        self.source.namespace(self.initialization)
        self.identity=self.profile.descriptor()
        self.setup.path('/run').mkdir(mode=0o755,exist_ok=True)
        self.root=self.setup.path(native.V2_STATE)
        self.writer=sqlite3.connect(self.root/'results.sqlite')
        self.addCleanup(self.writer.close)
        self.writer.execute('PRAGMA journal_mode=WAL');self.writer.execute('PRAGMA wal_autocheckpoint=0')
        self.writer.executemany('INSERT INTO executions(command_id) VALUES(?)',[(str(uuid.uuid4()),) for _ in range(3)])
        self.writer.commit()
        for name in ['results.sqlite-wal','results.sqlite-shm']:
            p=self.root/name;p.chmod(0o600);os.chown(p,self.identity['uid'],self.identity['gid'])
        self.assertGreater((self.root/'results.sqlite-wal').stat().st_size,0)
        self.inspections=[]
        self.addCleanup(patch.stopall)
        patch.object(native.RetainedBusiness,'image',return_value=b'explicit filesystem fixture; no ELF proof').start()
        patch.object(native.RetainedBusiness,'execute',side_effect=self.inspection).start()
        self.before=self.fingerprints()
        self.sealed=self.material.sealed_files()

    def fingerprints(self):
        inspector=native.RetainedBusiness(self.source)
        return {p.name:inspector.fingerprint(p,self.identity,p==self.root) for p in [self.root,*[
            self.root/name for name in ['results.sqlite','results.sqlite.plan-key','.native-profile-v1',
                                        'results.sqlite-wal','results.sqlite-shm']]]}

    def inspection(self,image,directory,identity,initialization):
        self.assertEqual(image,b'explicit filesystem fixture; no ELF proof')
        self.assertEqual(initialization,self.initialization)
        self.assertEqual(set(p.name for p in directory.iterdir()),{'results.sqlite','results.sqlite-wal'})
        self.assertEqual(directory.stat().st_uid,identity['uid'])
        self.assertEqual(directory.stat().st_gid,identity['gid'])
        self.assertEqual(directory.stat().st_mode&0o777,0o700)
        self.assertEqual(directory.parent.stat().st_uid,0)
        self.assertEqual(directory.parent.stat().st_mode&0o777,0o711)
        inputs={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in directory.iterdir()}
        with sqlite3.connect('file:'+str(directory/'results.sqlite')+'?mode=ro',uri=True) as db:
            counts={t:db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in self.source.TABLES}
        self.assertEqual(counts['executions'],3)
        self.inspections.append(str(directory))
        # This report is explicitly mocked. Real envelope authentication,
        # generation/schema validation and role rejection belong to Rust tests.
        return {'schemaVersion':1,'profile':'native-retained-state-inspection-v1',
            'nativeUid':identity['uid'],'nativeGid':identity['gid'],'noNewPrivileges':True,'inputFiles':inputs,
            'inventory':{'schemaVersion':1,'profile':'native-execution-inventory-v1','initializationId':initialization,
                'tableCounts':counts,'executionStates':{'SUCCEEDED':1,'UNKNOWN':1,'RUNNING':1},'unresolvedExecutions':2,
                'schemaSha256':'e'*64,'logicalSha256':'f'*64,'recordsChanged':False,'replayPerformed':False}}

    def prepare(self):
        return self.material.prepare()

    def assert_preserved(self):
        self.assertEqual(self.before,self.fingerprints())
        self.assertEqual(self.sealed,self.material.sealed_files())
        self.assertTrue(all(not Path(p).exists() for p in self.inspections))
        self.assertEqual(self.writer.execute('SELECT count(*) FROM executions').fetchone()[0],3)

    def test_explicit_business_action_carries_wal_and_unknown_without_repair_or_replay(self):
        self.assertEqual(self.prepare()['state'],'UNKNOWN')
        ticket=self.source.json(self.source.PENDING)
        self.assertEqual(ticket['retainedBusiness']['report']['inventory']['unresolvedExecutions'],2)
        self.material.install()
        self.assertEqual(self.source.finish(self.f.pair)['state'],'APPLIED')
        self.source.namespace(self.initialization);self.profile.check()
        self.assertEqual(self.source.status(self.material.operation)['state'],'APPLIED')
        self.assertGreaterEqual(len(self.inspections),4)
        self.assert_preserved()

    def test_old_empty_enrollment_action_still_refuses_nonempty_business_and_wal(self):
        self.source.retained_business=False
        with self.assertRaisesRegex(RuntimeError,'Nonempty native journal/WAL|Retained business'):
            self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_new_action_requires_original_namespace_and_explicit_material_scope(self):
        for key,value in [('business_initialization',None),('enrolled_material_kura_peer',False),
                          ('material_kura_peer',False),('uninstalled_core_loader',True)]:
            with self.subTest(key=key),patch.object(self.source,key,value):
                with self.assertRaisesRegex(RuntimeError,'explicit original-namespace'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_foreign_initialization_refuses_before_any_saved_uuid_lookup(self):
        with patch.object(self.source,'record',side_effect=AssertionError('saved request was accessed')):
            with self.assertRaisesRegex(RuntimeError,'Different native installation'):
                self.source.namespace(str(uuid.uuid4()))
        self.assert_preserved()

    def test_pending_does_not_allow_another_source_id_for_the_same_package(self):
        self.prepare();number=len(self.inspections)
        with self.assertRaisesRegex(RuntimeError,'original native maintenance UUID'):
            self.source.prepare(str(uuid.uuid4()),'/reviewed-material-source.deb','a'*64)
        self.assertEqual(number,len(self.inspections));self.assert_preserved()

    def test_bad_inspection_authority_counts_or_replay_flags_refuse_before_intent(self):
        original=self.inspection
        def changed(field,value):
            def execute(*args):
                report=original(*args)
                target=report if field in report else report['inventory'];target[field]=value
                return report
            return execute
        for field,value in [('nativeUid',0),('noNewPrivileges',False),('recordsChanged',True),
                ('replayPerformed',True),('initializationId',str(uuid.uuid4())),('unresolvedExecutions',0),
                ('tableCounts',{}),('schemaVersion',True)]:
            with self.subTest(field=field),patch.object(native.RetainedBusiness,'execute',side_effect=changed(field,value)):
                with self.assertRaises(RuntimeError):self.prepare()
            self.assertFalse(self.setup.path(self.source.PENDING).exists())
        self.assert_preserved()

    def test_claiming_different_input_bytes_cannot_admit_even_a_well_formed_report(self):
        def changed(*args):
            report=self.inspection(*args);report['inputFiles']['results.sqlite-wal']['sha256']='0'*64;return report
        with patch.object(native.RetainedBusiness,'execute',side_effect=changed):
            with self.assertRaisesRegex(RuntimeError,'different database/WAL bytes'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists());self.assert_preserved()

    def test_inspection_failure_preserves_original_files_and_leaves_no_new_intent(self):
        with patch.object(native.RetainedBusiness,'execute',side_effect=RuntimeError('fixture authentication refused')):
            with self.assertRaisesRegex(RuntimeError,'authentication refused'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())
        self.assertFalse(list(self.setup.path('/run').glob('kura-source-inspection-*')));self.assert_preserved()

    def test_wal_change_after_prepare_is_refused_under_its_original_operation(self):
        self.prepare();p=self.root/'results.sqlite-wal'
        with p.open('ab') as stream:stream.write(b'explicit changed bytes')
        with self.assertRaisesRegex(RuntimeError,'inventory changed'):self.source.admit(self.f.pair)
        self.assertFalse(self.setup.path(self.source.record(self.material.operation,'admitted.json')).exists())
        self.assertTrue(self.setup.path(self.source.PENDING).exists())

    def test_additional_native_provider_state_is_preserved_and_refused(self):
        p=self.root/'network'/'unreviewed-provider.json';p.parent.mkdir(mode=0o700,exist_ok=True)
        os.chown(p.parent,self.identity['uid'],self.identity['gid'])
        p.write_bytes(b'preserve');p.chmod(0o600);os.chown(p,self.identity['uid'],self.identity['gid'])
        with self.assertRaisesRegex(RuntimeError,'unreviewed owned state'):self.prepare()
        self.assertEqual(p.read_bytes(),b'preserve');self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_remote_on_or_running_core_cannot_enter_the_business_path(self):
        remote=self.fixture.remote;value=json.loads(remote.read_bytes());value['enabled']=True
        remote.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError,'remote decision'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())
        value['enabled']=False;remote.write_text(json.dumps(value));self.material.local.running=True
        with self.assertRaisesRegex(RuntimeError,'Explicitly stop'):self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_original_global_pending_survives_interruption_before_per_operation_records(self):
        real=self.source.immutable
        def fault(name,*args):
            real(name,*args)
            if name==self.source.PENDING:raise OSError('after original global intent')
        with patch.object(self.source,'immutable',side_effect=fault):
            with self.assertRaisesRegex(OSError,'original global intent'):self.prepare()
        self.source.namespace(self.initialization)
        self.assertEqual(self.source.status(self.material.operation)['state'],'UNKNOWN')
        self.assertFalse(self.setup.path(self.source.record(self.material.operation,'intent.json')).exists())
        with self.assertRaisesRegex(RuntimeError,'original native maintenance UUID'):
            self.source.prepare(str(uuid.uuid4()),'/reviewed-material-source.deb','a'*64)
        self.assert_preserved()

    def test_namespace_accepts_only_its_original_pending_pair_during_publication(self):
        self.prepare();self.material.install();real=self.source.replace
        def fault(name,*args):
            real(name,*args)
            if name==self.source.CURRENT:raise OSError('after current pointer')
        with patch.object(self.source,'replace',side_effect=fault):
            with self.assertRaisesRegex(OSError,'current pointer'):self.source.finish(self.f.pair)
        self.source.namespace(self.initialization)
        self.assertEqual(self.source.status(self.material.operation)['state'],'UNKNOWN')
        self.assertEqual(self.source.complete(self.material.operation)['state'],'APPLIED')
        self.assert_preserved()

    def test_published_history_cannot_drop_the_original_retained_business_proof(self):
        self.prepare();self.material.install();self.source.finish(self.f.pair)
        result=self.source.json(self.source.record(self.material.operation,'result.json'));del result['retainedBusiness']
        raw=self.profile.encode(result).encode()
        self.setup.path(self.source.record(self.material.operation,'result.json')).write_bytes(raw)
        pointer=self.source.json(self.source.CURRENT);pointer['sha256']=self.source.digest(raw)
        self.setup.path(self.source.CURRENT).write_text(self.profile.encode(pointer))
        with self.assertRaisesRegex(RuntimeError,'retained business source proof changed'):
            self.source.namespace(self.initialization)

    def test_inventory_bundle_must_match_original_input_fingerprints_and_program(self):
        self.prepare();ticket=self.source.json(self.source.PENDING)
        for mutation in ['program','wal','generation','loader','material']:
            value=copy.deepcopy(ticket)
            if mutation=='program':value['retainedBusiness']['programSha256']='0'*64
            elif mutation=='wal':value['retainedBusiness']['report']['inputFiles'].pop('results.sqlite-wal')
            elif mutation=='generation':value['retainedBusiness']['report']['inventory']['tableCounts']['native_profile_generation']=0
            elif mutation=='loader':value['loaderTransition']={}
            else:value.pop('materialTransition')
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):
                native.RetainedBusiness.bundle(value['retainedBusiness'],value)


@unittest.skipUnless(os.geteuid()==0,'disposable Root Linux fixture required')
class RetainedInspectorPairTests(unittest.TestCase):
    def setUp(self):
        self.case=source_fixture.SourceUpdateTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)

    def test_candidate_retains_only_its_fully_paired_elf_without_metadata_size_bypass(self):
        image=b'\x7fELF'+b'explicit archive fixture\n'+b'\x00'*(2*1024*1024)
        previous=repr(self.case.pair).encode();self.case.pair={**self.case.pair,'binarySha256':hashlib.sha256(image).hexdigest()}
        self.case.prerm=self.case.prerm.replace(previous,repr(self.case.pair).encode(),1)
        package,_,_,_=self.case.candidate_archive();root=self.case.setup.path('/candidate-root')
        (root/'usr/bin/yofc-management-agent').write_bytes(image)
        subprocess.run(['dpkg-deb','--root-owner-group','--build',str(root),str(package)],check=True,stdout=subprocess.DEVNULL)
        digest=hashlib.sha256(package.read_bytes()).hexdigest()
        self.assertEqual(self.case.update.candidate('/candidate.deb',digest,inspection=True)[0],self.case.pair)
        self.assertEqual(self.case.update.incoming_inspector,image)
        identity={**self.case.old_identity,**self.case.pair}
        self.assertEqual(native.RetainedBusiness(self.case.update).image('/candidate.deb',digest,identity),image)
        with self.assertRaisesRegex(RuntimeError,'checksum differs'):
            native.RetainedBusiness(self.case.update).image('/candidate.deb','0'*64,identity)

    def test_paired_non_elf_payload_cannot_become_a_retained_inspector(self):
        _,digest,_,_=self.case.candidate_archive()
        with self.assertRaisesRegex(RuntimeError,'Root-paired native program'):
            self.case.update.candidate('/candidate.deb',digest,inspection=True)
        self.assertFalse(hasattr(self.case.update,'incoming_inspector'))


class SourceNamespaceCliTests(unittest.TestCase):
    def test_every_public_source_action_requires_initialization_before_controller_entry(self):
        actions=['prepare-source-update','prepare-uninstalled-core-loader-update','prepare-local-kura-source-update',
            'prepare-material-kura-source-update','prepare-enrolled-material-kura-source-update',
            'prepare-retained-business-material-kura-source-update','complete-source-update','source-update-status',
            'complete-retained-business-source-update','retained-business-source-status']
        for action in actions:
            args=[sys.executable,'-B',str(Path(native.__file__)),action,'--request-id',str(uuid.uuid4())]
            if action.startswith('prepare-'):args+=['--package','/unused-fixture.deb','--sha256','a'*64]
            with self.subTest(action=action):
                result=subprocess.run(args,capture_output=True,text=True)
                self.assertEqual(result.returncode,2);self.assertIn('--initialization-id',result.stderr)
                self.assertIn('required',result.stderr);self.assertEqual(result.stdout,'')


if __name__=='__main__':unittest.main()
