"""Original source maintenance in disposable Root filesystem/command fixtures."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import unittest
from unittest.mock import patch
import uuid

import test_runtime_setup as fixture

native = fixture.native


@unittest.skipUnless(os.geteuid() == 0, 'disposable Root Linux fixture required')
class SourceUpdateTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.NativeProfileTests('runTest'); self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.profile, self.setup = self.case.native, self.case.setup
        self.lifecycle=(fixture.PACKAGING/'native_lifecycle.py').read_bytes()
        source=json.loads(self.setup.path('/usr/share/kura-management-agent/source-manifest.json').read_text())
        source['sourceFiles'].append({'path':'packaging/native_lifecycle.py','sha256':hashlib.sha256(self.lifecycle).hexdigest()})
        for path,filename in native.SourceUpdate.SOURCE_PAYLOAD.items():
            raw=(fixture.PACKAGING/filename).read_bytes();self.case.write(path,raw)
            source['sourceFiles'].append({'path':'packaging/'+filename,'sha256':hashlib.sha256(raw).hexdigest()})
        source['siblingSourceRequired']=False
        self.case.write('/usr/share/kura-management-agent/source-manifest.json',json.dumps(source))
        jar=b'filesystem fixture, not a compiled adapter'
        self.case.write('/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar',jar)
        self.case.write('/usr/share/kura-management-agent/java-bridge.json',json.dumps({
            'symbolicName':'org.eclipse.kura.management.bridge','version':'1.0.0.fixture',
            'path':'/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar',
            'sha256':hashlib.sha256(jar).hexdigest(),'coreLoaderProtocol':1,'coreLoaderSha256':'b'*64}))
        self.profile.initialize(self.case.operation)
        self.calls = []; self.setup.systemctl = lambda *args: self.calls.append(args)
        db = self.setup.path(native.V2_STATE+'/results.sqlite')
        with sqlite3.connect(db) as connection:
            for name in native.SourceUpdate.TABLES-{'native_profile_generation'}:
                connection.execute('CREATE TABLE '+name+'(command_id TEXT PRIMARY KEY)')
        body=native.SourceUpdate.embedded(self.setup.path('/usr/lib/kura-management-agent/setup.py').read_bytes())+b'\n'
        body+=native.SourceUpdate.embedded(self.setup.path('/usr/lib/kura-management-agent/runtime_setup.py').read_bytes())+b'\n'
        self.control_body=body+self.lifecycle
        self.old_prerm=("#!/usr/bin/python3 -I\nSCRIPT_NAME = 'prerm'\nPACKAGE_CORE_LOADER_SHA256 = "+repr('b'*64)+'\n').encode()+self.control_body
        self.case.write(native.SourceUpdate.PRERM,self.old_prerm,0o755)
        self.update = native.SourceUpdate(self.profile); self.operation=str(uuid.uuid4())
        self.update.incoming_version='0.1.0~fixture'
        self.before=self.update.snapshot(); self.initial=self.update.raw(native.V2_ADMIN+'/initialization.json')
        self.old_identity=self.profile.descriptor()
        self.new_unit=self.setup.path(native.V2_VENDOR).read_bytes()+b'\n# reviewed new source fixture\n'
        self.source=json.loads(self.setup.path('/usr/share/kura-management-agent/source-manifest.json').read_text())
        self.source['siblingSourceRequired']=False
        digest=hashlib.sha256(self.new_unit).hexdigest()
        for row in self.source['sourceFiles']:
            if row['path']=='packaging/'+native.V2_UNIT:row['sha256']=digest
        self.source_raw=json.dumps(self.source).encode()
        self.pair={key:self.old_identity[key] for key in self.update.PINS}
        self.pair.update(unitSha256=digest,sourceManifestSha256=hashlib.sha256(self.source_raw).hexdigest())
        self.prerm=("#!/usr/bin/python3 -I\nSCRIPT_NAME = 'prerm'\nPACKAGE_CORE_LOADER_SHA256 = "+repr('b'*64)+'\nPACKAGE_NATIVE_PAIR = '+repr(self.pair)+'\n').encode()+self.control_body

    def prepare(self):
        with patch.object(self.update,'candidate',return_value=(self.pair,self.prerm)):
            return self.update.prepare(self.operation,'/reviewed-fixture.deb','a'*64)

    def runtime_assets(self):
        for leaf in ['network','firewall','recovery','recovery/backups','recovery/receipts','recovery/staging']:
            path=self.setup.path(native.V2_STATE+'/'+leaf);path.mkdir(parents=True,exist_ok=True)
            os.chown(path,995,993);path.chmod(0o700)
        data={'remote-management.json':json.dumps({'version':1,'revision':str(uuid.uuid4()),'enabled':False,'actor':'installation'}).encode(),
            'network/coordinator.lock':b'','system-change.lock':b'','results.sqlite-wal':b'','results.sqlite-shm':b'\0'*32768}
        for leaf,raw in data.items():
            path=self.setup.path(native.V2_STATE+'/'+leaf);path.write_bytes(raw);os.chown(path,995,993);path.chmod(0o600)

    def install_payload_fixture(self):
        self.case.write(native.V2_VENDOR,self.new_unit)
        self.case.write('/usr/share/kura-management-agent/source-manifest.json',self.source_raw)
        meta=json.loads(self.setup.path('/usr/share/kura-management-agent/native-profile.json').read_text())
        meta['files'][native.V2_VENDOR]=self.pair['unitSha256']
        self.case.write('/usr/share/kura-management-agent/native-profile.json',json.dumps(meta))

    def test_original_preparation_masks_start_preserves_prerm_and_never_changes_state(self):
        self.assertEqual(self.prepare()['state'],'UNKNOWN')
        self.update.verify_mask()
        self.assertEqual(self.update.raw(self.update.record(self.operation,'previous.prerm')),
            self.old_prerm)
        self.assertEqual(self.update.raw(self.update.PRERM,0o755),self.prerm)
        self.assertEqual(self.update.snapshot(),self.before)
        before=self.case.snapshot()
        with patch.object(self.update,'candidate',side_effect=AssertionError('must not re-read/reprepare')):
            self.assertEqual(self.update.prepare(self.operation,'/reviewed-fixture.deb','a'*64)['state'],'UNKNOWN')
            with self.assertRaisesRegex(RuntimeError,'original native maintenance'):
                self.update.prepare(str(uuid.uuid4()),'/reviewed-fixture.deb','a'*64)
        self.assertEqual(self.case.snapshot(),before)
        with self.assertRaisesRegex(RuntimeError,'uncertain original'):self.profile.check()
        self.assertFalse(any(row[0] in ['start','stop','enable'] for row in self.calls))

    def test_original_admission_and_publication_preserve_initialization_and_data(self):
        self.prepare();self.update.admit(self.pair);self.install_payload_fixture()
        self.assertEqual(self.update.finish(self.pair)['state'],'APPLIED')
        self.profile.check()
        self.assertEqual(self.update.snapshot(),self.before)
        self.assertEqual(self.update.raw(native.V2_ADMIN+'/initialization.json'),self.initial)
        self.assertFalse(os.path.lexists(self.update.mask_path()))
        self.assertNotEqual(self.profile.descriptor(),self.old_identity)
        before=self.case.snapshot()
        with patch.object(self.update,'candidate',side_effect=AssertionError('closed original cannot prepare again')):
            self.assertEqual(self.update.prepare(self.operation,'/reviewed-fixture.deb','a'*64)['state'],'APPLIED')
        self.assertEqual(before,self.case.snapshot())

    def test_different_pair_state_or_mask_is_refused_before_payload_mutation(self):
        self.prepare()
        with self.assertRaisesRegex(RuntimeError,'pair differs'):self.update.admit({**self.pair,'unitSha256':'f'*64})
        with self.assertRaisesRegex(RuntimeError,'version differs'):self.update.admit(self.pair,'0.1.0~other')
        key=self.setup.path(native.V2_STATE+'/results.sqlite.plan-key');key.write_bytes(b'0'*32)
        with self.assertRaisesRegex(RuntimeError,'input changed'):self.update.admit(self.pair)
        self.assertTrue(os.path.lexists(self.update.mask_path()))
        self.update.mask_path().unlink();os.symlink('/dev/zero',self.update.mask_path())
        with self.assertRaisesRegex(RuntimeError,'maintenance mask changed'):self.update.admit(self.pair)

    def test_unknown_business_or_legacy_data_is_not_a_source_only_update(self):
        db=self.setup.path(native.V2_STATE+'/results.sqlite')
        with sqlite3.connect(db) as connection:connection.execute("INSERT INTO executions VALUES('original-unknown')")
        before=self.case.snapshot()
        with self.assertRaisesRegex(RuntimeError,'business or unknown'):self.prepare()
        self.assertEqual(before,self.case.snapshot())
        self.assertFalse(os.path.lexists(self.setup.path(self.update.PENDING)))

    def test_publication_interruption_keeps_the_same_pending_and_resumes_only_missing_files(self):
        self.prepare();self.update.admit(self.pair);self.install_payload_fixture()
        real=self.update.immutable
        def fail(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name.endswith('/result.json'):raise OSError('after original result publication')
        with patch.object(self.update,'immutable',side_effect=fail):
            with self.assertRaises(OSError):self.update.finish(self.pair)
        self.assertEqual(self.update.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.update.raw(native.V2_ADMIN+'/initialization.json'),self.initial)
        self.assertEqual(self.update.snapshot(),self.before)
        result=self.setup.path(self.update.record(self.operation,'result.json')).stat()
        self.assertEqual(self.update.finish(self.pair)['state'],'APPLIED')
        after=self.setup.path(self.update.record(self.operation,'result.json')).stat()
        self.assertEqual((result.st_ino,result.st_mtime_ns,result.st_ctime_ns),
                         (after.st_ino,after.st_mtime_ns,after.st_ctime_ns))

    def test_lost_pending_marker_does_not_allow_another_id_or_start(self):
        self.prepare();self.setup.path(self.update.PENDING).unlink()
        before=self.case.snapshot()
        with self.assertRaisesRegex(RuntimeError,'Lost native maintenance marker'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'Lost native maintenance marker'):
            self.update.prepare(str(uuid.uuid4()),'/reviewed-fixture.deb','a'*64)
        self.assertEqual(before,self.case.snapshot());self.update.verify_mask()

    def test_pinned_source_history_cannot_change_authority_or_erase_the_old_link(self):
        self.prepare();self.update.admit(self.pair);self.install_payload_fixture();self.update.finish(self.pair)
        result=self.setup.path(self.update.record(self.operation,'result.json'));raw=result.read_bytes()
        value=json.loads(raw);value['previousIdentity']['uid']=0;result.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError,'source-pair proof'):self.profile.check()
        result.write_bytes(raw);self.profile.check()
        self.setup.path(self.update.CURRENT).unlink()
        with self.assertRaisesRegex(RuntimeError,'without original maintenance proof'):self.profile.check()

    def test_incoming_archive_role_source_code_and_original_package_hash_are_checked(self):
        root=self.setup.path('/candidate-root');root.mkdir()
        for path in native.NATIVE_FILES:
            target=root/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(self.new_unit if path==native.V2_VENDOR else self.setup.path(path).read_bytes());target.chmod(0o644)
        for path in native.SourceUpdate.SOURCE_PAYLOAD:
            target=root/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(self.setup.path(path).read_bytes());target.chmod(0o644)
        meta=json.loads(self.setup.path('/usr/share/kura-management-agent/native-profile.json').read_text())
        meta['files'][native.V2_VENDOR]=self.pair['unitSha256']
        reader_paths=['/usr/lib/kura-management-agent/enrollment_reader.py',
            '/usr/lib/systemd/system/kura-management-enrollment-reader.socket',
            '/usr/lib/systemd/system/kura-management-enrollment-reader@.service']
        reader={'schemaVersion':1,'protocolVersion':1,'user':'kurad','socket':'/run/kura-management-enrollment-reader.sock',
            'sourceRoot':'/opt/eclipse/kura/data/management-enrollment','files':{path:meta['files'][path] for path in reader_paths}}
        for name,raw,mode in [('/usr/bin/yofc-management-agent',self.setup.path('/usr/bin/yofc-management-agent').read_bytes(),0o755),
                ('/usr/share/kura-management-agent/source-manifest.json',self.source_raw,0o644),
                ('/usr/share/kura-management-agent/native-profile.json',json.dumps(meta).encode(),0o644),
                ('/usr/share/kura-management-agent/java-bridge.json',self.setup.path('/usr/share/kura-management-agent/java-bridge.json').read_bytes(),0o644),
                ('/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar',self.setup.path('/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar').read_bytes(),0o644),
                ('/usr/share/kura-management-agent/enrollment-reader.json',json.dumps(reader).encode(),0o644),
                ('/usr/sbin/kura-agent-setup',b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/kura-management-agent/runtime_setup.py "$@"\n',0o755),
                ('/usr/share/kura-management-agent/package-v2',b'kura-management-agent-v2\n',0o644)]:
            path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
        control=root/'DEBIAN';control.mkdir()
        architecture=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
        (control/'control').write_text('Package: kura-management-agent\nVersion: 0.1.0~fixture\nArchitecture: '+architecture+'\nMaintainer: fixture\nDescription: metadata-only filesystem fixture\n')
        (control/'prerm').write_bytes(self.prerm);(control/'prerm').chmod(0o755)
        for name in ['preinst','postinst','postrm']:
            raw=self.prerm.replace(b"SCRIPT_NAME = 'prerm'",('SCRIPT_NAME = '+repr(name)).encode(),1)
            (control/name).write_bytes(raw);(control/name).chmod(0o755)
        package=self.setup.path('/candidate.deb')
        subprocess.run(['dpkg-deb','--root-owner-group','--build',str(root),str(package)],check=True,stdout=subprocess.DEVNULL)
        package.chmod(0o600);digest=hashlib.sha256(package.read_bytes()).hexdigest()
        self.assertEqual(self.update.candidate('/candidate.deb',digest),(self.pair,self.prerm))
        with self.assertRaisesRegex(RuntimeError,'checksum differs'):self.update.candidate('/candidate.deb','0'*64)

    def test_unpaired_previous_maintainer_cannot_be_replaced_by_a_new_intent(self):
        self.setup.path(self.update.PRERM).write_bytes(self.old_prerm+b'\n# unpaired guard change\n')
        before=self.case.snapshot()
        with self.assertRaisesRegex(RuntimeError,'paired source'):self.prepare()
        self.assertEqual(before,self.case.snapshot())
        self.assertFalse(os.path.lexists(self.setup.path(self.update.PENDING)))

    def test_ast_boundary_keeps_main_guard_text_inside_source_literals(self):
        raw=b"value = \"if __name__ == '__main__':\"\ndef fixed(): return value\nif __name__ == '__main__':\n fixed()\n"
        code=native.SourceUpdate.embedded(raw)
        compile(code,'paired source fixture','exec')
        self.assertIn(b'def fixed()',code)
        self.assertNotIn(b'\n fixed()',code)
        import test_packaging
        path=fixture.PACKAGING/'runtime_setup.py'
        self.assertEqual(test_packaging.build.embedded(path).encode(),native.SourceUpdate.embedded(path.read_bytes()))
        compile(self.prerm,'reviewed native maintainer fixture','exec')

    def test_busy_package_manager_refuses_before_intent_or_control_script_mutation(self):
        import sys
        path=self.setup.path('/var/lib/dpkg/lock-frontend')
        script="import fcntl,os,sys,time;f=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);fcntl.lockf(f,fcntl.LOCK_EX);print('ready',flush=True);time.sleep(20)"
        child=subprocess.Popen([sys.executable,'-I','-c',script,str(path)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'ready')
            before=self.case.snapshot()
            with self.assertRaisesRegex(RuntimeError,'Package manager is busy'):self.prepare()
            self.assertEqual(before,self.case.snapshot())
            self.assertFalse(os.path.lexists(self.setup.path(self.update.PENDING)))
        finally:
            child.terminate();child.wait(timeout=5);child.stdout.close()

    def test_known_initial_runtime_assets_are_preserved_by_the_original_source_update(self):
        self.runtime_assets();before=self.update.snapshot()
        self.prepare();self.update.admit(self.pair);self.install_payload_fixture();self.update.finish(self.pair)
        self.assertEqual(self.update.snapshot(),before)
        self.assertEqual(self.update.raw(native.V2_ADMIN+'/initialization.json'),self.initial)

    def test_nonempty_wal_is_not_ignored_when_main_database_has_zero_business_rows(self):
        self.runtime_assets();self.setup.path(native.V2_STATE+'/results.sqlite-wal').write_bytes(b'original retained WAL')
        before=self.case.snapshot()
        with self.assertRaisesRegex(RuntimeError,'Nonempty native journal/WAL'):self.prepare()
        self.assertEqual(self.case.snapshot(),before)
        self.assertFalse(os.path.lexists(self.setup.path(self.update.PENDING)))

    def test_missing_original_remote_decision_is_not_recreated_from_empty_runtime_directories(self):
        self.runtime_assets();path=self.setup.path(native.V2_STATE+'/remote-management.json');path.unlink()
        before=self.case.snapshot()
        with self.assertRaisesRegex(RuntimeError,'lost its original remote decision'):self.prepare()
        self.assertFalse(path.exists());self.assertEqual(self.case.snapshot(),before)

    def test_real_recovery_or_changed_remote_state_requires_its_original_authorization(self):
        self.runtime_assets();path=self.setup.path(native.V2_STATE+'/recovery/receipts/original.json')
        path.write_bytes(b'public original receipt sentinel');path.chmod(0o600);os.chown(path,995,993)
        with self.assertRaisesRegex(RuntimeError,'business, pending or unreviewed'):self.prepare()
        self.assertEqual(path.read_bytes(),b'public original receipt sentinel')
        path.unlink();remote=self.setup.path(native.V2_STATE+'/remote-management.json');value=json.loads(remote.read_bytes());value['enabled']=True;remote.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError,'original authorized maintenance'):self.prepare()
        self.assertTrue(json.loads(remote.read_bytes())['enabled'])

    def test_orphan_runtime_writer_lock_blocks_source_admission_without_any_repair(self):
        import sys
        self.runtime_assets();path=self.setup.path(native.V2_STATE+'/network/coordinator.lock')
        script="import fcntl,os,sys,time;f=os.open(sys.argv[1],os.O_RDONLY);fcntl.flock(f,fcntl.LOCK_EX);print('ready',flush=True);time.sleep(20)"
        child=subprocess.Popen([sys.executable,'-I','-c',script,str(path)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'ready');before=self.case.snapshot()
            with self.assertRaisesRegex(RuntimeError,'runtime writer remains active'):self.prepare()
            self.assertEqual(before,self.case.snapshot())
            self.assertFalse(os.path.lexists(self.setup.path(self.update.PENDING)))
        finally:child.terminate();child.wait(timeout=5);child.stdout.close()


if __name__=='__main__':unittest.main()
