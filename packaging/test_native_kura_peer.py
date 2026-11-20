"""Original local peer grant in disposable Root filesystem/OS boundary fixtures."""
import hashlib
import json
import os
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import test_native_source_update as fixture

native=fixture.native


@unittest.skipUnless(os.geteuid()==0, 'disposable Root Linux fixture required')
class KuraPeerTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.SourceUpdateTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.profile,self.setup=self.case.profile,self.case.setup
        self.peer=native.KuraPeer(self.profile);self.operation=str(uuid.uuid4())
        self.members=[];self.dispatches=0;self.group_fault=None;self.running=False
        self.kura=SimpleNamespace(pw_name='kurad',pw_uid=991,pw_gid=992,pw_shell='/sbin/nologin')
        agent=self.case.case.account
        contexts=[patch.object(native.pwd,'getpwnam',side_effect=lambda n: self.kura if n=='kurad' else agent),
            patch.object(native.pwd,'getpwall',side_effect=lambda: [agent,self.kura]),
            patch.object(native.grp,'getgrnam',side_effect=lambda n: SimpleNamespace(
                gr_gid=993 if n=='kura-management' else 992 if n=='kurad' else 994,
                gr_mem=list(self.members) if n=='kura-management' else []))]
        for context in contexts:context.start();self.addCleanup(context.stop)
        self.core_fields={'LoadState':'loaded','FragmentPath':native.KuraPeer.CORE_UNIT,
                          'DropInPaths':'','User':'kurad','Group':'kurad'}
        self.capability_fields={}
        self.networking_owner='kura-networking'
        self.setup.systemctl=self.systemctl
        self.real_run=self.setup.run;self.setup.run=self.run_boundary
        self.case.case.write(native.KuraPeer.CORE_UNIT,b'Root filesystem unit fixture; not systemd acceptance')
        loader=b'Root filesystem Core loader fixture; not execution'
        self.case.case.write('/opt/eclipse/kura/bin/gen_config_ini.sh',loader)
        path=self.setup.path('/usr/share/kura-management-agent/java-bridge.json')
        value=json.loads(path.read_bytes());value['coreLoaderSha256']=hashlib.sha256(loader).hexdigest()
        path.write_text(json.dumps(value))
        self.before=self.peer.source.initial_snapshot()
        self.initial=self.peer.source.raw(native.V2_ADMIN+'/initialization.json')

    def systemctl(self,*args):
        if args[:2]==('show','kura.service'):
            if 'LoadState' in args[-1]:
                fields=self.core_fields
            elif 'NeedDaemonReload' in args[-1]:
                fields=self.capability_fields
            else:
                fields={'MainPID':'17' if self.running else '0','ActiveState':'active' if self.running else 'inactive'}
            return subprocess.CompletedProcess(args,0,stdout='\n'.join(k+'='+v for k,v in fields.items())+'\n')
        return None

    def run_boundary(self,argv,**kwargs):
        if argv[0]=='/usr/bin/dpkg-query':
            output=self.networking_owner+': '+argv[2] if argv[1]=='-S' else 'installed'
            return subprocess.CompletedProcess(argv,0,stdout=output,stderr='')
        if argv[0]=='/usr/bin/gpasswd':
            self.assertEqual(argv,['/usr/bin/gpasswd','--add','kurad','kura-management'])
            self.dispatches+=1
            if self.group_fault!='before':self.members[:]=['kurad']
            if self.group_fault:raise OSError('original group dispatch reply lost '+self.group_fault)
            return subprocess.CompletedProcess(argv,0,stdout='',stderr='')
        return self.real_run(argv,**kwargs)

    def assert_state_preserved(self):
        state=self.peer.source.initial_snapshot()
        without=lambda v:{k:x for k,x in v.items() if k!=native.KuraPeer.ENV}
        self.assertEqual(without(state),without(self.before))
        self.assertEqual(self.peer.source.raw(native.V2_ADMIN+'/initialization.json'),self.initial)

    def test_original_local_grant_changes_only_uid_and_group_without_remote_or_start(self):
        result=self.peer.authorize(self.operation)
        self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        self.assertEqual(self.dispatches,1);self.assertEqual(self.members,['kurad'])
        self.profile.check();self.assert_state_preserved()
        env=self.peer.source.raw(native.KuraPeer.ENV)
        self.assertIn(b'AGENT_KURA_UID=991\n',env);self.assertIn(b'AGENT_REMOTE_ENABLED=0\n',env)
        self.assertEqual(self.peer.authorize(self.operation)['state'],'APPLIED');self.assertEqual(self.dispatches,1)
        with self.assertRaisesRegex(RuntimeError,'original migration'):self.peer.authorize(str(uuid.uuid4()))
        with self.assertRaisesRegex(RuntimeError,'joint native maintenance'):self.peer.source.snapshot()

    def prepare_reviewed_networking(self, legacy=True):
        template=(b'[Unit]\nWants=NetworkManager.service ModemManager.service\n'
                  b'After=NetworkManager.service ModemManager.service\n')
        scope='cap_net_admin cap_net_bind_service'
        expected=native.KuraPeer.NETWORKING_DROP_IN_SHA256
        if legacy:
            template+=b'\n[Service]\nAmbientCapabilities=cap_net_admin cap_net_raw\n'
            scope+=' cap_net_raw'
            expected=native.KuraPeer.LEGACY_NETWORKING_DROP_IN_SHA256
        self.assertEqual(hashlib.sha256(template).hexdigest(),expected)
        for name in (native.KuraPeer.NETWORKING_TEMPLATE,native.KuraPeer.NETWORKING_DROP_IN):
            self.case.case.write(name,template)
        core='[Service]\nAmbientCapabilities='+scope+'\nCapabilityBoundingSet='+scope+'\n'
        self.case.case.write(native.KuraPeer.CORE_UNIT,core.encode())
        self.core_fields['DropInPaths']=native.KuraPeer.NETWORKING_DROP_IN
        self.capability_fields={'NeedDaemonReload':'no','AmbientCapabilities':scope,'CapabilityBoundingSet':scope}

    def test_networking_grant_pins_the_exact_already_effective_capability_scope(self):
        self.prepare_reviewed_networking()
        home=self.setup.path('/opt/eclipse/kura')
        versioned=home.with_name('kura_6.0.0-linux')
        home.rename(versioned)
        home.symlink_to(versioned.name)
        result=self.peer.authorize(self.operation)
        self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        grant=self.peer.check()
        self.assertEqual((grant['schemaVersion'],grant['profile']),(2,'local-kura-v2'))
        self.assertEqual(grant['coreNetworkingDropInSha256'],native.KuraPeer.LEGACY_NETWORKING_DROP_IN_SHA256)
        self.assertEqual(self.dispatches,1)
        self.assert_state_preserved()
        self.core_fields['DropInPaths']+=' /etc/systemd/system/kura.service.d/local.conf'
        self.assertEqual(self.peer.status(self.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.dispatches,1)

    def test_networking_dependency_unit_pairs_without_raw_capability(self):
        self.prepare_reviewed_networking(legacy=False)
        result=self.peer.authorize(self.operation)
        self.assertEqual((result['state'],result['currentReadiness']),('APPLIED','READY'))
        self.assertEqual(self.peer.check()['coreNetworkingDropInSha256'],native.KuraPeer.NETWORKING_DROP_IN_SHA256)
        self.capability_fields['AmbientCapabilities']+=' cap_net_raw'
        self.assertEqual(self.peer.status(self.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.dispatches,1)

    def test_legacy_networking_unit_cannot_expand_the_core_scope(self):
        self.prepare_reviewed_networking()
        unit=self.setup.path(native.KuraPeer.CORE_UNIT)
        unit.write_bytes(unit.read_bytes().replace(b' cap_net_raw',b''))
        with self.assertRaisesRegex(RuntimeError,'capability scope changed'):
            self.peer.authorize(self.operation)
        self.assertEqual(self.dispatches,0)

    def test_networking_changed_owner_bytes_or_live_scope_never_dispatches(self):
        self.prepare_reviewed_networking()
        self.networking_owner='unreviewed-package'
        with self.assertRaisesRegex(RuntimeError,'does not own'):
            self.peer.authorize(self.operation)
        self.networking_owner='kura-networking'
        self.capability_fields['AmbientCapabilities']+=' cap_sys_admin'
        with self.assertRaisesRegex(RuntimeError,'capability scope changed'):
            self.peer.authorize(self.operation)
        self.case.case.write(native.KuraPeer.NETWORKING_DROP_IN,b'[Service]\nUser=root\n')
        with self.assertRaisesRegex(RuntimeError,'differs from its reviewed package template'):
            self.peer.authorize(self.operation)
        self.assertEqual(self.dispatches,0)
        self.assertEqual(self.peer.status(self.operation)['state'],'NOT_FOUND')

    def test_packaged_networking_template_requires_exact_core_group_and_mode(self):
        self.prepare_reviewed_networking()
        template = self.setup.path(native.KuraPeer.NETWORKING_TEMPLATE)
        live = self.setup.path(native.KuraPeer.NETWORKING_DROP_IN)
        code_gid = native.grp.getgrnam('kura-key-control').gr_gid
        for group, mode in ((code_gid, 0o644), (code_gid + 1, 0o640), (0, 0o640), (code_gid, 0o660)):
            with self.subTest(group=group, mode=mode):
                os.chown(template, 0, group)
                template.chmod(mode)
                with self.assertRaisesRegex(RuntimeError, 'Unsafe native runtime program/source file'):
                    self.peer.authorize(self.operation)
        os.chown(template, 0, code_gid)
        template.chmod(0o640)
        os.chown(live, 0, code_gid)
        live.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe native runtime program/source file'):
            self.peer.authorize(self.operation)
        self.assertEqual(self.dispatches, 0)
        self.assertEqual(self.peer.status(self.operation)['state'], 'NOT_FOUND')
        os.chown(live, 0, 0)
        live.chmod(0o644)
        result = self.peer.authorize(self.operation)
        self.assertEqual((result['state'], result['currentReadiness']), ('APPLIED', 'READY'))
        self.assertEqual(self.dispatches, 1)

    def test_lost_group_reply_is_observed_and_completed_without_redispatch(self):
        self.group_fault='after'
        with self.assertRaises(OSError):self.peer.authorize(self.operation)
        self.assertEqual(self.peer.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.peer.authorize(self.operation)['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'uncertain original'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'original Kura peer authorization UUID'):self.peer.authorize(str(uuid.uuid4()))
        self.assertEqual(self.peer.complete(self.operation)['state'],'APPLIED')
        self.assertEqual(self.dispatches,1);self.assert_state_preserved()

    def test_unapplied_unknown_group_is_not_sent_again_by_complete(self):
        self.group_fault='before'
        with self.assertRaises(OSError):self.peer.authorize(self.operation)
        with self.assertRaisesRegex(RuntimeError,'do not redispatch'):self.peer.complete(self.operation)
        self.assertEqual(self.peer.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.dispatches,1);self.assertEqual(self.members,[])
        self.assertEqual(self.peer.source.initial_snapshot(),self.before)

    def test_publication_fault_resumes_only_missing_files_with_the_original_id(self):
        real=self.peer.source.immutable
        def fault(name,*args,**kwargs):
            real(name,*args,**kwargs)
            if name==self.peer.PUBLIC:raise OSError('after original public publication')
        with patch.object(self.peer.source,'immutable',side_effect=fault):
            with self.assertRaises(OSError):self.peer.authorize(self.operation)
        before=self.setup.path(self.peer.ENV).lstat()
        self.assertEqual(self.peer.status(self.operation)['state'],'UNKNOWN')
        self.assertEqual(self.peer.complete(self.operation)['state'],'APPLIED')
        after=self.setup.path(self.peer.ENV).lstat()
        self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_ctime_ns),
                         (after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(self.dispatches,1);self.assert_state_preserved()

    def test_lost_pending_marker_never_allows_another_grant_or_assumes_publication(self):
        self.group_fault='after'
        with self.assertRaises(OSError):self.peer.authorize(self.operation)
        self.setup.path(self.peer.PENDING).unlink()
        self.assertEqual(self.peer.status(self.operation)['state'],'UNKNOWN')
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.peer.authorize(str(uuid.uuid4()))
        self.assertEqual(self.dispatches,1)

    def test_historical_grant_fate_survives_current_code_or_membership_refusal(self):
        self.peer.authorize(self.operation)
        path=self.setup.path(native.KuraPeer.CORE_UNIT);original=path.read_bytes();path.write_bytes(original+b'\nchanged')
        status=self.peer.status(self.operation)
        self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        with self.assertRaisesRegex(RuntimeError,'original Root proof'):self.profile.check()
        path.write_bytes(original);self.members.append('unexpected-user')
        self.assertEqual(self.peer.status(self.operation)['currentReadiness'],'REFUSED')
        self.assertEqual(self.members,['kurad','unexpected-user'])
        self.members[:]=['kurad']
        with patch.object(self.setup,'systemctl',side_effect=subprocess.CalledProcessError(1,['systemctl','show'])):
            status=self.peer.status(self.operation)
            self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))

    def test_root_alias_native_uid_override_or_running_core_refuse_before_dispatch(self):
        for uid in [0,995]:
            self.kura.pw_uid=uid
            with self.assertRaisesRegex(RuntimeError,'separate'):self.peer.authorize(self.operation)
        self.kura.pw_uid=991;self.core_fields['DropInPaths']='/etc/systemd/system/kura.service.d/personal.conf'
        with self.assertRaisesRegex(RuntimeError,'Unreviewed effective Core'):self.peer.authorize(self.operation)
        self.core_fields['DropInPaths']='';self.running=True
        with self.assertRaisesRegex(RuntimeError,'Explicitly stop'):self.peer.authorize(self.operation)
        self.assertEqual(self.dispatches,0);self.assertFalse(self.setup.path(self.peer.PENDING).exists())

    def test_pending_state_change_is_preserved_and_cannot_publish_authority(self):
        self.group_fault='after'
        with self.assertRaises(OSError):self.peer.authorize(self.operation)
        key=self.setup.path(native.V2_STATE+'/results.sqlite.plan-key');key.write_bytes(b'changed original plan key sentinel')
        with self.assertRaisesRegex(RuntimeError,'state changed'):self.peer.complete(self.operation)
        self.assertEqual(key.read_bytes(),b'changed original plan key sentinel')
        self.assertFalse(self.setup.path(self.peer.PUBLIC).exists());self.assertEqual(self.dispatches,1)

    def test_closed_publication_receipt_keeps_historical_fate_when_current_pointer_is_lost(self):
        self.peer.authorize(self.operation);self.setup.path(self.peer.CURRENT).unlink()
        status=self.peer.status(self.operation)
        self.assertEqual((status['state'],status['currentReadiness']),('APPLIED','REFUSED'))
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.profile.check()
        with self.assertRaisesRegex(RuntimeError,'Lost original'):self.peer.authorize(str(uuid.uuid4()))
        self.assertEqual(self.dispatches,1)


if __name__=='__main__':unittest.main(verbosity=2)
