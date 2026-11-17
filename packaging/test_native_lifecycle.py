"""Native package admission uses original retained state; it never adopts it."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location('native_lifecycle_' + name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


legacy = load('setup')
native = load('runtime_setup')
scope = {**vars(legacy), **vars(native), 'Setup': legacy.Setup, 'PACKAGE_CORE_LOADER_SHA256': 'a' * 64}
exec(Path(__file__).with_name('native_lifecycle.py').read_text().split("if __name__ == '__main__':")[0], scope)


class NativeLifecycleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.setup = legacy.Setup(Path(directory.name))
        self.calls = []
        self.setup.systemctl = lambda *args: self.calls.append(args)
        self.setup.guard_core_loader = lambda expected: self.calls.append(('loader', expected))
        self.factory = patch.dict(scope, {'Setup': lambda: self.setup}); self.factory.start(); self.addCleanup(self.factory.stop)

    def retained(self, name):
        path = self.setup.path(name); path.mkdir(parents=True)
        (path / 'original').write_bytes(b'public retained sentinel')
        return path / 'original'

    def test_clean_install_only_checks_the_original_loader_and_stopped_profiles(self):
        scope['lifecycle']('preinst', 'install')
        self.assertEqual(self.calls[-1], ('loader', 'a' * 64))
        self.assertFalse(any(row[0] in ['start', 'stop', 'enable', 'disable'] for row in self.calls))
        self.assertFalse(self.setup.path(native.V2_STATE).exists())

    def test_legacy_data_refuses_before_payload_replacement_or_service_mutation(self):
        original = self.retained(legacy.STATE); before = original.stat()
        with self.assertRaisesRegex(RuntimeError, 'original migration'): scope['lifecycle']('preinst', 'upgrade')
        self.assertEqual(original.read_bytes(), b'public retained sentinel')
        self.assertEqual(original.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertFalse(any(row[0] in ['start', 'stop', 'enable', 'disable', 'loader'] for row in self.calls))

    def test_each_native_root_even_empty_requires_original_maintenance(self):
        for name in [native.V2_CONFIG, native.V2_ADMIN, native.V2_PUBLIC, native.V2_STATE]:
            with self.subTest(name=name):
                path = self.setup.path(name); path.mkdir(parents=True)
                try:
                    for script, action in [('preinst','upgrade'), ('prerm','remove'), ('postrm','purge')]:
                        with self.assertRaisesRegex(RuntimeError, 'original|Preserve native'):
                            scope['lifecycle'](script,action)
                    self.assertTrue(path.is_dir())
                finally: path.rmdir()
        self.assertFalse(any(row[0] in ['stop','disable'] for row in self.calls))

    def test_effective_running_profile_is_not_implicitly_stopped(self):
        def running(*args):
            self.calls.append(args)
            return subprocess.CompletedProcess(args,0,'MainPID=42\nActiveState=active\n')
        self.setup.systemctl = running
        with self.assertRaisesRegex(RuntimeError, 'Explicitly stop'): scope['lifecycle']('preinst','install')
        self.assertEqual(len(self.calls),1)

    def test_configure_checks_payload_and_creates_no_state_or_automatic_start(self):
        with patch.dict(scope, {'native_accounts': lambda setup: self.calls.append(('accounts',))}), \
                patch.object(native.RuntimeSetup,'profile_pair',return_value={'fixture':True}):
            scope['lifecycle']('postinst','configure')
        self.assertEqual(self.calls,[('accounts',),('daemon-reload',)])
        self.assertFalse(self.setup.path(native.V2_ADMIN).exists())
        self.assertFalse(self.setup.path(legacy.STATE).exists())

    def test_payload_pair_or_account_command_failure_propagates_before_reload(self):
        with patch.dict(scope, {'native_accounts': lambda setup: None}), \
                patch.object(native.RuntimeSetup,'profile_pair',side_effect=RuntimeError('injected pair')):
            with self.assertRaisesRegex(RuntimeError,'injected pair'): scope['lifecycle']('postinst','configure')
        self.assertEqual(self.calls,[])
        with patch.dict(scope, {'native_accounts': lambda setup: (_ for _ in ()).throw(subprocess.CalledProcessError(17,['groupadd']))}):
            with self.assertRaises(subprocess.CalledProcessError): scope['lifecycle']('postinst','configure')
        self.assertEqual(self.calls,[])

    def test_fixed_account_creation_never_adopts_an_interactive_root_or_alias(self):
        account = SimpleNamespace(pw_name=native.V2_USER,pw_uid=0,pw_gid=994,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        with patch.object(native.pwd,'getpwnam',return_value=account), \
                patch.object(native.grp,'getgrnam',side_effect=lambda name: SimpleNamespace(gr_gid=993 if name=='kura-management' else 994)):
            with self.assertRaisesRegex(RuntimeError,'separate non-login'): scope['native_accounts'](self.setup)
        self.assertEqual(self.calls,[])

    def test_uninitialized_removal_touches_only_its_own_units_and_reload_failure_propagates(self):
        scope['lifecycle']('prerm','remove')
        mutations = [row for row in self.calls if row[0] in ['stop','disable']]
        self.assertEqual(len(mutations),2)
        self.assertTrue(all('kura.service' not in row and legacy.UNIT not in row for row in mutations))
        self.setup.systemctl = lambda *args: (_ for _ in ()).throw(subprocess.CalledProcessError(23,args))
        with self.assertRaises(subprocess.CalledProcessError): scope['lifecycle']('postrm','remove')


if __name__ == '__main__': unittest.main()
