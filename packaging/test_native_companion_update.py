"""Original local peer continuity for an explicitly reviewed Core/Networking pair."""
import json
import os
from pathlib import Path
from uuid import uuid4
import unittest
from unittest.mock import patch

import test_native_kura_peer as fixture

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
        self.networking=(b'[Unit]\nWants=NetworkManager.service ModemManager.service\n'
                         b'After=NetworkManager.service ModemManager.service\n')
        self.inputs=(('/core.deb','a'*64),('/networking.deb','b'*64))

    @staticmethod
    def unit(caps):
        return ('[Service]\nUser=kurad\nGroup=kurad\nNoNewPrivileges=yes\n'
                'ExecStart=/bin/sh /opt/eclipse/kura/bin/start_kura_background.sh\n'
                f'AmbientCapabilities={caps}\nCapabilityBoundingSet={caps}\n').encode()

    def candidate(self, package, path, digest):
        data={'unit':self.unit(self.new_caps),'loader':
              self.setup.path('/opt/eclipse/kura/bin/gen_config_ini.sh').read_bytes()} if package=='kura-core' else {
              'unit':self.networking}
        return dict(sha256=digest,previousVersion='6.0.0~g1',version='6.0.0~g2',
                    controls={name:self.source.digest(raw) for name,raw in self.controls.items()}),data

    def prepare(self, material_authorization=None):
        with patch.object(self.flow,'candidate',side_effect=self.candidate):
            return self.flow.prepare(self.initialization,self.operation,*self.inputs,material_authorization)

    def configured(self):
        self.setup.path(self.peer.CORE_UNIT).write_bytes(self.unit(self.new_caps))
        self.case.capability_fields={'NeedDaemonReload':'no','AmbientCapabilities':self.new_caps,
                                     'CapabilityBoundingSet':self.new_caps}
        for name in (self.peer.NETWORKING_DROP_IN,self.peer.NETWORKING_TEMPLATE):
            self.setup.path(name).write_bytes(self.networking)
        for package in self.flow.PACKAGES:
            self.versions[package]='6.0.0~g2'
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
