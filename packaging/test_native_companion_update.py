"""Original local peer continuity for an explicitly reviewed Core/Networking pair."""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4
import unittest
from unittest.mock import patch

import test_native_kura_peer as fixture
import test_retained_enrollment_source as enrolled_fixture

native=fixture.native


@unittest.skipUnless(native.os.geteuid()==0, 'disposable Root Linux fixture required')
class CompanionUpdateTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.KuraPeerTests('runTest')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.prepare_reviewed_networking()
        self.peer=self.case.peer
        self.profile=self.case.profile
        self.setup=self.case.setup
        self.source=native.SourceUpdate(self.profile)
        self.flow=native.KuraCompanionUpdate(self.source)
        self.old_caps='cap_net_admin cap_net_bind_service cap_net_raw'
        self.new_caps='cap_net_admin cap_net_bind_service'
        self.case.case.case.write(self.peer.CORE_UNIT,self.unit(self.old_caps))
        self.case.case.case.write(self.flow.KEY,b'k'*32)
        self.setup.path(self.flow.KEY).chmod(0o400)
        self.peer.authorize(self.case.operation)
        result=self.peer.original()[0]
        self.initialization=result['initializationId']
        self.authorization=self.case.operation
        self.original=result['peer']
        self.original_result=self.source.raw(self.peer.record(self.authorization,'result.json'))
        self.original_public=self.source.raw(native.V2_IDENTITY,0o644)
        self.operation=str(uuid4())
        self.controls={name:(name+'\n').encode() for name in self.flow.CONTROLS}
        self.versions={name:'6.0.0~g1' for name in self.flow.PACKAGES}
        self.incoming_version='6.0.0~g2'
        self.preserves_data=True
        self.networking=(b'[Unit]\nWants=NetworkManager.service ModemManager.service\n'
                         b'After=NetworkManager.service ModemManager.service\n')
        self.inputs=(('/core.deb','a'*64),('/networking.deb','b'*64))

    @staticmethod
    def unit(caps):
        return ('[Service]\nUser=kurad\nGroup=kurad\nNoNewPrivileges=yes\n'
                'ExecStart=/bin/sh /opt/eclipse/kura/bin/start_kura_background.sh\n'
                f'AmbientCapabilities={caps}\nCapabilityBoundingSet={caps}\n').encode()

    def candidate(self, package, path, digest):
        home=(self.setup.root/'opt/eclipse/kura').resolve()
        data={'unit':self.unit(self.new_caps),'loader':
              (home/'bin/gen_config_ini.sh').read_bytes(),'home':home.name,
              'preservesData':self.preserves_data} if package=='kura-core' else {
              'unit':self.networking}
        return dict(sha256=digest,previousVersion=self.versions[package],version=self.incoming_version,
                    controls={name:self.source.digest(raw) for name,raw in self.controls.items()}),data

    def prepare(self, material_authorization=None, enrollment_id=None, *, remote_switch_authorization=None):
        with patch.object(self.flow,'candidate',side_effect=self.candidate):
            return self.flow.prepare(self.initialization,self.operation,*self.inputs,material_authorization,enrollment_id,
                                     remote_switch_authorization=remote_switch_authorization)

    def configured(self):
        self.setup.path(self.peer.CORE_UNIT).write_bytes(self.unit(self.new_caps))
        self.case.capability_fields={'NeedDaemonReload':'no','AmbientCapabilities':self.new_caps,
                                     'CapabilityBoundingSet':self.new_caps}
        for name in (self.peer.NETWORKING_DROP_IN,self.peer.NETWORKING_TEMPLATE):
            (self.setup.root/name.lstrip('/')).write_bytes(self.networking)
        for package in self.flow.PACKAGES:
            self.versions[package]=self.incoming_version
            for name,raw in self.controls.items():
                path=Path('/var/lib/dpkg/info')/(package+'.'+name)
                self.case.case.case.write(str(path),raw)
                self.setup.path(str(path)).chmod(0o755)

    def complete(self, operation=None):
        with patch.object(native.KuraCompanionUpdate,'installed_version',
                          side_effect=lambda name:self.versions[name]):
            return self.source.complete(operation or self.operation)

    def test_requires_both_releases_and_keeps_the_original_grant(self):
        self.assertEqual(self.prepare()['state'],'UNKNOWN')
        self.assertEqual(self.prepare()['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'both finish configuration'):
            self.complete()
        with self.assertRaisesRegex(RuntimeError,'does not authorize'):
            self.source.admit({key:None for key in self.source.PINS})
        self.configured()
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.profile.check()
        current=self.peer.check()
        changed={'coreUnitSha256','coreNetworkingDropInSha256'}
        self.assertEqual({k for k,v in current.items() if v!=self.original[k]},changed)
        self.assertEqual(self.peer.status(self.authorization)['currentReadiness'],'READY')
        self.assertEqual(self.source.raw(self.peer.record(self.authorization,'result.json')),self.original_result)
        self.assertEqual(self.source.raw(native.V2_IDENTITY,0o644),self.original_public)
        self.assertEqual(self.case.dispatches,1)

    def test_upgrades_both_releases_with_the_current_drop_in_and_unchanged_unit(self):
        self.prepare()
        self.configured()
        self.assertEqual(self.complete()['state'],'APPLIED')
        previous_operation=self.operation
        previous_receipt=self.source.raw(self.source.record(previous_operation,'result.json'))
        paired=self.peer.check()
        self.operation=str(uuid4())
        self.incoming_version='6.0.0~g3'
        self.inputs=(('/core-next.deb','c'*64),('/networking-next.deb','d'*64))
        self.assertEqual(self.prepare()['state'],'UNKNOWN')
        ticket=self.source.json(self.source.PENDING)
        self.assertEqual(ticket['peerTransition']['previous'],paired)
        self.assertEqual(ticket['peerTransition']['incoming'],paired)
        self.assertEqual(ticket['previousPair']['requestId'],previous_operation)
        with self.assertRaisesRegex(RuntimeError,'both finish configuration'):
            self.complete()
        self.configured()
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.profile.check()
        self.assertEqual(self.peer.check(),paired)
        self.assertEqual(self.source.status(previous_operation)['state'],'APPLIED')
        self.assertEqual(self.source.raw(self.source.record(previous_operation,'result.json')),previous_receipt)
        self.assertEqual(self.source.raw(self.peer.record(self.authorization,'result.json')),self.original_result)
        self.assertEqual(self.case.dispatches,1)

    def test_extra_main_capability_is_refused_before_preparing(self):
        self.new_caps+=' cap_sys_admin'
        with self.assertRaisesRegex(RuntimeError,'cannot expand Main scope'):
            self.prepare()
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_changed_maintainer_and_wrong_identifier_cannot_publish(self):
        self.prepare()
        self.configured()
        with self.assertRaisesRegex(RuntimeError,'Preserve original'):
            self.complete(str(uuid4()))
        self.setup.path('/var/lib/dpkg/info/kura-networking.postinst').write_bytes(b'drift')
        with self.assertRaisesRegex(RuntimeError,'maintainer differs'):
            self.complete()
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')

    def test_same_pending_intent_can_finish_after_partial_publication(self):
        self.prepare()
        self.configured()
        def fault(name,raw,mode,**kwargs):
            if name==self.peer.PUBLIC:
                target=self.setup.path(name)
                temporary=target.with_name('.'+target.name+'.source-update-new')
                temporary.write_bytes(raw[:31])
                temporary.chmod(0o600)
                raise OSError('publication interrupted')
            return original_replace(name,raw,mode,**kwargs)
        original_replace=self.source.replace
        with patch.object(self.source,'replace',side_effect=fault):
            with self.assertRaisesRegex(OSError,'publication interrupted'):
                self.complete()
        self.source.namespace(self.initialization)
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.profile.check()
        self.assertEqual(self.case.dispatches,1)

    def material_grant(self):
        material=native.KuraMaterial(self.profile)
        meta=json.loads(self.setup.path('/usr/share/kura-management-agent/native-profile.json').read_bytes())
        files=('/usr/lib/kura-management-agent/enrollment_reader.py',
               '/usr/lib/systemd/system/kura-management-enrollment-reader.socket',
               '/usr/lib/systemd/system/kura-management-enrollment-reader@.service')
        publisher=dict(schemaVersion=1,protocolVersion=1,user='kurad',socket=material.UPSTREAM,
                       sourceRoot=material.SOURCE,files={name:meta['files'][name] for name in files})
        self.case.case.case.write('/usr/share/kura-management-agent/enrollment-reader.json',json.dumps(publisher))
        operation=str(uuid4())
        self.assertEqual(material.authorize(operation)['currentReadiness'],'READY')
        return material,operation

    def test_named_material_grant_and_its_original_receipts_are_preserved(self):
        material,operation=self.material_grant()
        with self.assertRaisesRegex(RuntimeError,'Name the existing material authorization'):
            self.prepare()
        with self.assertRaisesRegex(RuntimeError,'Preserve the original material authorization UUID'):
            self.prepare(str(uuid4()))
        self.assertFalse(self.setup.path(self.source.PENDING).exists())
        self.assertEqual(self.prepare(operation)['state'],'UNKNOWN')
        ticket=self.source.json(self.source.PENDING)
        self.assertEqual(ticket['companionTransition']['material']['requestId'],operation)
        paths=[material.PUBLIC,material.RELAY,material.CURRENT,
               *(material.record(operation,name) for name in
                 ('intent.json','result.json','published.json','relay-grant.json'))]
        self.assertTrue(set(paths)<=set(ticket['state']))
        self.configured()
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.assertEqual(material.status(operation)['currentReadiness'],'READY')
        self.assertEqual(self.flow.snapshot(ticket['companionTransition'],self.peer.check(),
                                            ticket['previousPair']),ticket['state'])
        self.assertEqual(self.case.dispatches,1)

    def test_changed_material_bytes_keep_the_original_companion_pending(self):
        material,operation=self.material_grant()
        self.prepare(operation)
        self.configured()
        relay=self.setup.path(material.RELAY)
        modified=relay.read_bytes()+b' '
        relay.write_bytes(modified)
        with self.assertRaisesRegex(RuntimeError,'Original companion material authority changed'):
            self.complete()
        self.assertEqual(relay.read_bytes(),modified)
        self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')

    def test_existing_enrollment_source_still_requires_separate_maintenance(self):
        material,operation=self.material_grant()
        root=self.setup.path(material.SOURCE)
        root.mkdir(parents=True,mode=0o700)
        for path in (root.parent,root):
            path.chmod(0o700)
            os.chown(path,self.original['kuraUid'],self.original['kuraGid'])
        with self.assertRaisesRegex(RuntimeError,'Real retained enrollment'):
            self.prepare(operation)
        self.assertFalse(self.setup.path(self.source.PENDING).exists())

    def test_unbound_companion_preserves_the_original_remote_switch_authorization(self):
        material,material_id=self.material_grant()
        switch=native.KuraRemoteSwitch(self.profile)
        switch_id=str(uuid4())
        self.assertEqual(switch.authorize(switch_id)['currentReadiness'],'READY')
        with self.assertRaisesRegex(RuntimeError,'Name the original remote-switch authorization'):
            self.prepare(material_id)
        self.assertFalse(self.setup.path(self.source.PENDING).exists())
        original=switch.original()
        result=self.prepare(material_id,remote_switch_authorization=switch_id)
        self.assertEqual(result['state'],'UNKNOWN')
        ticket=self.source.json(self.source.PENDING)
        self.assertEqual(ticket['companionTransition']['remoteSwitchAuthorizationId'],switch_id)
        self.assertIn(switch.record(switch_id,'result.json'),ticket['state'])
        with self.assertRaisesRegex(RuntimeError,'Retain the original companion maintenance'):
            self.prepare(material_id,remote_switch_authorization=str(uuid4()))
        self.configured()
        self.assertEqual(self.complete()['state'],'APPLIED')
        self.assertEqual(switch.original(),original)
        self.assertEqual(material.status(material_id)['currentReadiness'],'READY')
        self.assertFalse(switch.status(switch_id)['remoteEnabled'])
        self.assertEqual(switch.status(switch_id)['currentReadiness'],'READY')

    def test_enrolled_companion_update_resumes_with_original_journal_and_delegations(self):
        alias=self.setup.path('/opt/eclipse/kura')
        home=alias.with_name('kura_fixture_linux')
        alias.rename(home)
        alias.symlink_to(home.name)
        material,material_id=self.material_grant()
        enrollment=enrolled_fixture.RetainedEnrollmentSourceTests('runTest')
        self.addCleanup(enrollment.doCleanups)
        enrollment.profile,enrollment.setup,enrollment.local=self.profile,self.setup,self.peer.check()
        enrollment.stage_enrollment()
        switch=native.KuraRemoteSwitch(self.profile)
        transport=native.NativeTransport(self.profile)
        switch_id,transport_id=str(uuid4()),str(uuid4())
        self.assertEqual(switch.authorize(switch_id)['state'],'APPLIED')
        self.assertEqual(transport.configure(transport_id,'https://center.example.invalid:19444')['state'],'APPLIED')
        self.setup.path('/run').mkdir(mode=0o755,exist_ok=True)
        database=self.setup.path(native.V2_STATE+'/results.sqlite')
        with closing(sqlite3.connect(database)) as db:
            db.execute('INSERT INTO executions(command_id) VALUES(?)',(str(uuid4()),))
            db.commit()

        def inspect_copy(image,directory,identity,initialization):
            self.assertEqual(initialization,self.initialization)
            copied=directory/'results.sqlite'
            with closing(sqlite3.connect(copied)) as db:
                counts={name:db.execute('SELECT count(*) FROM '+name).fetchone()[0] for name in self.source.TABLES}
            self.assertEqual(counts['executions'],1)
            raw=copied.read_bytes()
            return {'schemaVersion':1,'profile':'native-retained-state-inspection-v1','nativeUid':identity['uid'],
                'nativeGid':identity['gid'],'noNewPrivileges':True,
                'inputFiles':{'results.sqlite':{'bytes':len(raw),'sha256':self.source.digest(raw)}},
                'inventory':{'schemaVersion':1,'profile':'native-execution-inventory-v1','initializationId':initialization,
                    'tableCounts':counts,'executionStates':{'UNKNOWN':1},'unresolvedExecutions':1,
                    'schemaSha256':'e'*64,'logicalSha256':'f'*64,'recordsChanged':False,'replayPerformed':False}}

        with patch.object(native.RetainedBusiness,'image',return_value=b'reviewed test image') as read_image, \
                patch.object(native.RetainedBusiness,'execute',side_effect=inspect_copy):
            self.preserves_data=False
            with self.assertRaisesRegex(RuntimeError,'same-home data handoff'):
                self.prepare(material_id,enrollment.request)
            self.preserves_data=True
            with self.assertRaisesRegex(RuntimeError,'original enrollment UUID'):
                self.prepare(material_id,str(uuid4()))
            self.assertFalse(self.setup.path(self.source.PENDING).exists())
            read_image.assert_not_called()
            self.assertEqual(self.prepare(material_id,enrollment.request)['state'],'UNKNOWN')
            ticket=self.source.json(self.source.PENDING)
            self.assertEqual(ticket['companionTransition']['enrollment']['journal']['inventory']['unresolvedExecutions'],1)
            self.assertEqual(read_image.call_args.args[:2],(None,None))
            self.configured()
            proof=ticket['companionTransition']
            path=proof['enrollment']['coreData']
            data=self.setup.path(path)
            stamp=ticket['state'][path]
            displaced=data.with_name('.exchange')
            data.rename(displaced)
            displaced.rename(data)
            new_ctime=data.stat().st_ctime_ns
            self.assertNotEqual(new_ctime,stamp[8])
            key_path=self.setup.path('/var/lib/kura-key-service/journal.key')
            key_path.parent.mkdir(mode=0o700)
            key=b'c'*32
            key_path.write_bytes(key)
            key_path.chmod(0o600)
            core_id=str(uuid4())
            record=self.setup.path('/var/lib/kura-package-configure/'+core_id+'/runtime-data-handoff.json')
            record.parent.mkdir(parents=True,mode=0o700)
            record.parent.parent.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError,'Missing unique original Core runtime data handoff'):
                self.complete()
            receipt={'schema':1,'maintenanceId':core_id,'phase':'runtime-data-handoff','manifestSha256':'e'*64,
                'packageVersion':self.incoming_version,'postinstSha256':proof['packages']['kura-core']['controls']['postinst'],
                'recovery':{'root':{k:proof['root'][k] for k in ('device','inode')},'bootId':proof['root']['boot'],
                    'home':home.name,'originalDirectory':{'device':stamp[0],'inode':stamp[1],'ctimeNs':stamp[8]},
                    'installedCtimeNs':new_ctime,'factoryDirectory':{'device':stamp[0],'inode':stamp[1]+1},
                    'captureTag':'a'*64}}
            serialized=json.dumps(receipt,sort_keys=True,separators=(',',':')).encode('ascii')
            valid_tag=hmac.new(key,b'kura-core-postinst-v1\0'+serialized,hashlib.sha256).hexdigest()
            record.write_text(self.profile.encode({**receipt,'tag':'0'*64}))
            record.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,'Invalid Core data handoff signature'):
                self.complete()
            record.write_text(self.profile.encode({**receipt,'tag':valid_tag}))
            original_replace=self.source.replace

            def interrupt_peer_publication(name,*args,**kwargs):
                if name==self.peer.PUBLIC:
                    raise OSError('after companion source pointer')
                return original_replace(name,*args,**kwargs)

            with patch.object(self.source,'replace',side_effect=interrupt_peer_publication):
                with self.assertRaisesRegex(OSError,'after companion source pointer'):
                    self.complete()
            self.source.namespace(self.initialization)
            self.assertEqual(self.source.status(self.operation)['state'],'UNKNOWN')
            self.assertEqual(self.complete()['state'],'APPLIED')
            self.profile.check()
            retained={**ticket['state'],path:stamp[:8]+[new_ctime,stamp[9]]}
            self.assertEqual(self.flow.snapshot(proof,self.peer.check(),ticket['previousPair'],self.initialization),
                             retained)
        self.assertEqual(material.status(material_id)['currentReadiness'],'READY')
        self.assertEqual(switch.status(switch_id)['currentReadiness'],'READY')
        self.assertEqual(transport.status(transport_id)['currentReadiness'],'READY')
        self.assertEqual(self.case.dispatches,1)
