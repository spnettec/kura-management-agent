#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Native non-Root profile primitives. No legacy adoption or implicit repair.

The package/UI controller supplies the original initialization UUID. This module
does not create users, stop services, start a unit or reinterpret retained data.
Native enrollment authorization and legacy migration are separate work.
"""
import fcntl
import base64
import datetime
from contextlib import closing, contextmanager
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import sys
import subprocess
import tarfile
import tempfile
import threading
import unicodedata
from urllib.parse import urlsplit
import uuid

V2_USER = 'kura-management-agent'
V2_CONFIG = '/etc/kura-management-agent-runtime'
V2_ADMIN = '/var/lib/kura-management-agent-admin'
V2_STATE = '/var/lib/kura-management-agent-runtime'
V2_PUBLIC = '/etc/kura-management-runtime'
V2_IDENTITY = V2_PUBLIC + '/agent.json'
V2_UNIT = 'kura-management-agent-v2.service'
V2_SOCKET = '/run/kura-management-agent-runtime/control.sock'
V2_VENDOR = '/usr/lib/systemd/system/' + V2_UNIT
V2_CONTINUITY = V2_PUBLIC + '/continuity.json'
CONFIGURATION_WRITE = V2_PUBLIC + '/configuration-write.json'
NATIVE_FILES = {
    '/usr/lib/kura-management-agent/runtime_setup.py': 'runtime_setup.py',
    '/usr/lib/kura-management-agent/setup.py': 'setup.py',
    '/usr/lib/kura-management-agent/enrollment_relay.py': 'enrollment_relay.py',
    V2_VENDOR: V2_UNIT,
    '/usr/lib/systemd/system/kura-management-agent-enrollment.socket': 'kura-management-agent-enrollment.socket',
    '/usr/lib/systemd/system/kura-management-agent-enrollment@.service': 'kura-management-agent-enrollment@.service',
    '/usr/lib/kura-management-agent/enrollment_reader.py': 'enrollment_reader.py',
    '/usr/lib/systemd/system/kura-management-enrollment-reader.socket': 'kura-management-enrollment-reader.socket',
    '/usr/lib/systemd/system/kura-management-enrollment-reader@.service': 'kura-management-enrollment-reader@.service',
}


class RuntimeSetup:
    def __init__(self, legacy):
        self.legacy = legacy

    def account(self):
        account = pwd.getpwnam(V2_USER)
        control = grp.getgrnam('kura-management')
        reader = grp.getgrnam(V2_USER)
        if (account.pw_name != V2_USER or not 0 < account.pw_uid < 4294967295 or not 0 < control.gr_gid < 4294967295
                or not 0 < reader.gr_gid < 4294967295 or control.gr_gid == reader.gr_gid
                or account.pw_gid != reader.gr_gid or account.pw_dir != '/nonexistent'
                or account.pw_shell not in ['/usr/sbin/nologin', '/sbin/nologin']
                or any(other.pw_uid == account.pw_uid and other.pw_name != V2_USER for other in pwd.getpwall())
                or any(group.gr_gid not in [control.gr_gid, reader.gr_gid]
                       for group in grp.getgrall() if V2_USER in group.gr_mem)):
            raise RuntimeError('A separate non-login packaged agent identity is required')
        return account.pw_uid, control.gr_gid, reader.gr_gid

    def directory(self, name, uid, gid, mode, create=False):
        path = self.legacy.path(name)
        self.legacy.authorization_parents(path)
        if not path.exists() and create:
            path.mkdir(mode=mode)
            os.chown(path, uid, gid)
            path.chmod(mode)
            for entry in [path, path.parent]:
                fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
        m = path.lstat()
        if (not stat.S_ISDIR(m.st_mode) or m.st_uid != uid or m.st_gid != gid or stat.S_IMODE(m.st_mode) != mode):
            raise RuntimeError('Retained native runtime directory requires explicit recovery')
        return path

    def asset(self, name, mode=0o644, maximum=2 * 1024 * 1024, alternate_layout=None):
        path = self.legacy.path(name)
        self.legacy.authorization_parents(path)
        layouts = {(0, mode)}
        if alternate_layout is not None:
            layouts.add(alternate_layout)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME)
        with os.fdopen(fd, 'rb') as source:
            m = os.fstat(source.fileno())
            if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0
                    or (m.st_gid, stat.S_IMODE(m.st_mode)) not in layouts or m.st_nlink != 1 or m.st_size > maximum):
                raise RuntimeError('Unsafe native runtime program/source file')
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
            after = os.fstat(source.fileno())
            stable = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink,
                                v.st_size, v.st_mtime_ns, v.st_ctime_ns)
            if stable(after) != stable(m):
                raise RuntimeError('Native runtime program/source changed')
        return digest

    def descriptor(self):
        self.profile_pair()
        uid, gid, reader = self.account()
        return {'schemaVersion': 1, 'profile': 'native-nonroot-v1', 'user': V2_USER,
                'uid': uid, 'gid': gid, 'readerGid': reader, 'stateDirectory': V2_STATE, 'socket': V2_SOCKET,
                'unitSha256': self.asset(V2_VENDOR),
                'binarySha256': self.asset('/usr/bin/yofc-management-agent', 0o755, 512 * 1024 * 1024),
                'sourceManifestSha256': self.asset('/usr/share/kura-management-agent/source-manifest.json')}

    def profile_pair(self):
        marker = self.legacy.reader_file('/usr/share/kura-management-agent/package-v2', limit=128)
        if marker != b'kura-management-agent-v2\n':
            raise RuntimeError('Exact packaged native profile selection required')
        meta = self.legacy.reader_json(self.legacy.reader_file('/usr/share/kura-management-agent/native-profile.json'))
        if (set(meta) != {'schemaVersion', 'profile', 'files'} or type(meta['schemaVersion']) is not int
                or meta['schemaVersion'] != 1 or meta['profile'] != 'native-nonroot-v1'
                or not isinstance(meta['files'], dict) or set(meta['files']) != set(NATIVE_FILES)):
            raise RuntimeError('Exact Root native payload pair required')
        source = self.legacy.reader_json(self.legacy.reader_file('/usr/share/kura-management-agent/source-manifest.json',
                                                               limit=2 * 1024 * 1024))
        rows = source.get('sourceFiles', [])
        records = {row['path']: row['sha256'] for row in rows}
        if source.get('schemaVersion') != 2 or len(records) != len(rows):
            raise RuntimeError('Native Root code source pair required')
        for path, name in NATIVE_FILES.items():
            actual = self.asset(path)
            if actual != meta['files'][path] or actual != records.get('packaging/' + name):
                raise RuntimeError('Native Root program/unit/source pair changed')
        return meta

    def stopped(self, unit):
        result = self.legacy.systemctl('show', unit, '--property=MainPID', '--property=ActiveState')
        if result is not None:
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if fields.get('MainPID') != '0' or fields.get('ActiveState') not in ['inactive', 'failed']:
                raise RuntimeError('Explicitly stop the selected original agent before changing its runtime profile')

    @staticmethod
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'

    def publish(self, name, value, uid=0, gid=0, mode=0o600):
        path = self.legacy.path(name)
        temporary = path.with_name('.' + path.name + '.native-new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as output:
            output.write(value.encode() if isinstance(value, str) else value)
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), uid, gid)
            output.flush(); os.fsync(output.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def settings():
        return {'AGENT_RUNTIME_IDENTITY': V2_IDENTITY, 'AGENT_STATE_DB': V2_STATE + '/results.sqlite',
                'AGENT_SOCKET': V2_SOCKET, 'AGENT_KURA_UID': '4294967295', 'AGENT_ADMIN_UID': '0',
                'AGENT_REMOTE_ENABLED': '0', 'AGENT_KURA_REMOTE_MANAGEMENT': '0',
                'AGENT_NETWORK_INTERFACES': '', 'AGENT_KURA_NETWORK_INTERFACES': '',
                'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE': '0', 'AGENT_FIREWALL_WRITE': '0',
                'AGENT_SYSTEM_CONTROL_REMOTE': '0', 'RUST_LOG': 'info'}

    def bootstrap(self, operation, descriptor):
        # The reviewed binary creates its own schema as the dedicated identity.
        # The Root controller never opens a business listener or creates TLS.
        if self.legacy.root != Path('/'):
            raise RuntimeError('Native state bootstrap requires its installed Root controller')
        result = self.legacy.run(['/usr/bin/setpriv', '--reuid=' + str(descriptor['uid']),
            '--regid=' + str(descriptor['gid']), '--groups=' + str(descriptor['readerGid']),
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
            '/usr/bin/yofc-management-agent', 'initialize-native-state', '--operation-id', operation],
            env={**self.settings(), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
            capture_output=True, text=True, check=True, timeout=30)
        if self.legacy.reader_json(result.stdout) != {'schemaVersion': 1, 'operationId': operation, 'stateCreated': True}:
            raise RuntimeError('Native state bootstrap outcome is uncertain; preserve its original UUID')

    def continuity(self, operation, descriptor, *, include_overlay=False):
        """Read only the new profile's generation and key, never adopt/recreate it."""
        result = {'schemaVersion': 1, 'operationId': operation, 'stateDirectory': V2_STATE}
        for name, maximum in [('results.sqlite', 8 * 1024 * 1024 * 1024), ('results.sqlite.plan-key', 32)]:
            path = self.legacy.path(V2_STATE + '/' + name)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME)
            with os.fdopen(fd, 'rb') as source:
                m = os.fstat(source.fileno())
                if (not stat.S_ISREG(m.st_mode) or m.st_uid != descriptor['uid'] or m.st_gid != descriptor['gid']
                        or stat.S_IMODE(m.st_mode) != 0o600 or m.st_nlink != 1 or m.st_size > maximum):
                    raise RuntimeError('Native state continuity requires original recovery')
                item = {'device': m.st_dev, 'inode': m.st_ino}
                if name.endswith('plan-key'):
                    if m.st_size != 32:
                        raise RuntimeError('Native plan key requires original recovery')
                    item['sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
                    result['planKey'] = item
                else:
                    if m.st_size < 4096:
                        raise RuntimeError('Native database requires original recovery')
                    # The fixed generation was checkpointed before sealing. An
                    # immutable read never creates WAL/SHM or initializes a DB.
                    with closing(sqlite3.connect('file:/proc/self/fd/' + str(source.fileno()) + '?mode=ro&immutable=1',
                                         uri=True, timeout=0)) as connection:
                        connection.execute('PRAGMA trusted_schema=OFF')
                        remaining = 100
                        def bounded():
                            nonlocal remaining
                            remaining -= 1
                            return int(remaining <= 0)
                        connection.set_progress_handler(bounded, 1000)
                        rows = connection.execute('SELECT singleton,operation_id FROM native_profile_generation LIMIT 2').fetchall()
                    if rows != [(1, operation)]:
                        raise RuntimeError('Native database generation requires original recovery')
                    result['database'] = item
                after = os.fstat(source.fileno())
                stable = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink,
                                    v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                if stable(m) != stable(after) or stable(m) != stable(path.lstat()):
                    raise RuntimeError('Native state changed during continuity inspection')
        if include_overlay:
            mount = RetainedRemoval(self).overlay_mount({
                V2_STATE + '/results.sqlite': [result['database']['device']],
                V2_STATE + '/results.sqlite.plan-key': [result['planKey']['device']],
            })
            if mount is not None:
                result['rootOverlay'] = mount
        return result

    def initialize(self, operation):
        if os.geteuid() != 0:
            raise RuntimeError('Native profile provisioning requires the fixed Root controller')
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise RuntimeError('Original native initialization UUID required')
        self.stopped('kura-management-agent.service')
        self.stopped(V2_UNIT)
        # Never infer a fresh native profile from missing settings on an old
        # installation; migration must preserve that installation separately.
        for name in ['/etc/kura-management-agent', '/var/lib/kura-management-agent']:
            path = self.legacy.path(name)
            if path.exists() and any(path.iterdir()):
                raise RuntimeError('Retained legacy agent data requires explicit migration')
        receipt = self.legacy.path(V2_ADMIN + '/initialization.json')
        if receipt.exists():
            original = self.legacy.reader_json(self.legacy.reader_file(str(receipt.relative_to(self.legacy.root)), mode=0o600))
            if original.get('operationId') != operation:
                raise RuntimeError('Retain the original native initialization UUID')
            self.check()
            return False
        for name in [V2_CONFIG, V2_ADMIN, V2_PUBLIC, V2_STATE]:
            path = self.legacy.path(name)
            if os.path.lexists(path):
                raise RuntimeError('Retained native profile requires original recovery; never initialize again')
        descriptor = self.descriptor()
        # Parent /etc and /var/lib already belong to the OS. Only known new,
        # empty profile directories may be assigned an owner here.
        self.directory(V2_ADMIN, 0, 0, 0o700, create=True)
        pending = {'schemaVersion': 1, 'operationId': operation, 'identity': descriptor,
                   'remoteEnabled': False, 'unitStarted': False}
        self.publish(V2_ADMIN + '/.initialization-pending', self.encode(pending))
        self.directory(V2_CONFIG, 0, 0, 0o700, create=True)
        self.directory(V2_PUBLIC, 0, 0, 0o755, create=True)
        self.directory(V2_STATE, descriptor['uid'], descriptor['gid'], 0o700, create=True)
        self.publish(V2_CONFIG + '/agent.env', self.legacy.serialize(self.settings()))
        self.publish(V2_IDENTITY, self.encode(descriptor), mode=0o644)
        self.publish(V2_STATE + '/.native-profile-v1', self.encode({'schemaVersion': 1, 'operationId': operation}),
                     descriptor['uid'], descriptor['gid'])
        self.bootstrap(operation, descriptor)
        continuity = self.encode(self.continuity(operation, descriptor, include_overlay=True))
        self.publish(V2_CONTINUITY, continuity, mode=0o644)
        pending['continuitySha256'] = hashlib.sha256(continuity.encode()).hexdigest()
        self.publish(V2_ADMIN + '/initialization.json', self.encode(pending))
        self.legacy.path(V2_ADMIN + '/.initialization-pending').unlink()
        directory = os.open(self.legacy.path(V2_ADMIN), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.check()
        return True

    def check(self):
        RetainedRemoval(self).require_inactive()
        if os.path.lexists(self.legacy.path(V2_ADMIN + '/.initialization-pending')):
            raise RuntimeError('Native initialization has an uncertain original outcome; preserve all files')
        if os.path.lexists(self.legacy.path(V2_ADMIN + '/.source-update-pending.json')):
            raise RuntimeError('Native source update has an uncertain original outcome; preserve its original UUID')
        if os.path.lexists(self.legacy.path(KuraPeer.PENDING)):
            raise RuntimeError('Native Kura peer authorization has an uncertain original outcome; preserve its UUID')
        if os.path.lexists(self.legacy.path(KuraMaterial.PENDING)):
            raise RuntimeError('Native material authorization has an uncertain original outcome; preserve its UUID')
        if os.path.lexists(self.legacy.path(KuraRemoteSwitch.PENDING)):
            raise RuntimeError('Native remote-switch authority has an uncertain original outcome; preserve its UUID')
        if os.path.lexists(self.legacy.path(NativeTransport.PENDING)):
            raise RuntimeError('Native transport configuration has an uncertain original outcome; preserve its UUID')
        NativeTransport(self).no_orphan()
        KuraRemoteSwitch(self).no_orphan()
        KuraMaterial(self).no_orphan()
        KuraPeer(self).no_orphan()
        SourceUpdate(self).no_orphan()
        self.stopped('kura-management-agent.service')
        descriptor = self.descriptor()
        for name, uid, gid, mode in [(V2_ADMIN, 0, 0, 0o700), (V2_CONFIG, 0, 0, 0o700),
                (V2_PUBLIC, 0, 0, 0o755), (V2_STATE, descriptor['uid'], descriptor['gid'], 0o700)]:
            self.directory(name, uid, gid, mode)
        original = self.initialization(descriptor)
        raw = self.legacy.reader_file(V2_CONFIG + '/agent.env', mode=0o600)
        settings = {}
        for line in raw.decode().splitlines():
            key, sep, value = line.partition('=')
            if not sep or key in settings:
                raise RuntimeError('Invalid native environment')
            settings[key] = value
        # Only the initial, unbound capability set is provisioned by this
        # primitive. Separate reviewed authorization methods must add choices.
        expected=self.settings()
        authorized=KuraPeer(self).check()
        if authorized is not None: expected['AGENT_KURA_UID']=str(authorized['kuraUid'])
        if self.configuration_write(original['operationId']) and authorized is None:
            raise RuntimeError('Native configuration writes require the original paired Kura peer')
        if KuraRemoteSwitch(self).check() is not None:expected['AGENT_KURA_REMOTE_MANAGEMENT']='1'
        if settings != expected:
            raise RuntimeError('Native authorization/migration is not installed for this configuration')
        KuraMaterial(self).check()
        NativeTransport(self).check()
        result = self.legacy.systemctl('show', V2_UNIT, '--property=LoadState', '--property=FragmentPath',
                                       '--property=DropInPaths', '--property=User', '--property=Group')
        if result is not None:
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if fields != {'LoadState': 'loaded', 'FragmentPath': V2_VENDOR, 'DropInPaths': '',
                           'User': V2_USER, 'Group': 'kura-management'}:
                raise RuntimeError('Effective non-Root agent profile differs from its reviewed unit')
        return descriptor

    def initialization(self, descriptor):
        """Authenticate this installed namespace without using a browser's old ID."""
        if os.path.lexists(self.legacy.path(V2_ADMIN + '/.initialization-pending')):
            raise RuntimeError('Native initialization has an uncertain original outcome; preserve all files')
        actual = self.legacy.reader_json(self.legacy.reader_file(V2_IDENTITY))
        original = self.legacy.reader_json(self.legacy.reader_file(V2_ADMIN + '/initialization.json', mode=0o600))
        if (actual != descriptor or set(original) != {'schemaVersion', 'operationId', 'identity', 'remoteEnabled', 'unitStarted', 'continuitySha256'}
                or type(original.get('schemaVersion')) is not int or original.get('schemaVersion') != 1
                or original.get('remoteEnabled') is not False or original.get('unitStarted') is not False):
            raise RuntimeError('Native runtime identity/source pair changed')
        SourceUpdate(self).verify_chain(original, descriptor)
        self.initialization_state(original, descriptor)
        return original

    def initialization_state(self, original, descriptor):
        """Check original private continuity even during paired code publication."""
        operation = original['operationId']
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise RuntimeError('Original native initialization UUID changed')
        marker = self.legacy.path(V2_STATE + '/.native-profile-v1')
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME)
        with os.fdopen(fd, 'rb') as source:
            m = os.fstat(source.fileno())
            if (not stat.S_ISREG(m.st_mode) or m.st_uid != descriptor['uid'] or m.st_gid != descriptor['gid']
                    or stat.S_IMODE(m.st_mode) != 0o600 or m.st_nlink != 1 or m.st_size > 4096):
                raise RuntimeError('Retained native runtime marker requires recovery')
            marker_value = self.legacy.reader_json(source.read(4097))
        if marker_value != {'schemaVersion': 1, 'operationId': operation}:
            raise RuntimeError('Retained native runtime marker differs from its original initialization')
        continuity_raw = self.legacy.reader_file(V2_CONTINUITY, limit=4096)
        if hashlib.sha256(continuity_raw).hexdigest() != original['continuitySha256']:
            raise RuntimeError('Native state continuity changed; retain the original recovery intent')
        expected = self.legacy.reader_json(continuity_raw)
        mount = expected.get('rootOverlay')
        actual = self.continuity(operation, descriptor, include_overlay=mount is not None)
        if mount is not None:
            current = actual.get('rootOverlay')
            if (current is None or set(mount) != {'device', 'overlaySha256'}
                    or mount['overlaySha256'] != current['overlaySha256']
                    or any(expected[name]['device'] != mount['device'] for name in ('database', 'planKey'))):
                raise RuntimeError('Native state continuity overlay backing differs')
            expected['rootOverlay'] = current
            for name in ('database', 'planKey'):
                expected[name]['device'] = current['device']
        if expected != actual:
            raise RuntimeError('Native state continuity changed; retain the original recovery intent')
        return original

    def namespace(self, expected=None):
        descriptor=self.descriptor()
        for name,uid,gid,mode in [(V2_ADMIN,0,0,0o700),(V2_CONFIG,0,0,0o700),
                (V2_PUBLIC,0,0,0o755),(V2_STATE,descriptor['uid'],descriptor['gid'],0o700)]:
            self.directory(name,uid,gid,mode)
        original=self.initialization(descriptor)
        if expected is not None and SourceUpdate.uuid(expected)!=original['operationId']:
            raise RuntimeError('Different native installation; do not query or complete the saved request here')
        return descriptor,original

    def inspect(self):
        """Public local context only; it never accepts or dispatches an old request."""
        descriptor,initial=self.namespace()
        switch=KuraRemoteSwitch(self);pending=switch.source.optional(switch.PENDING)
        result={'schemaVersion':1,'profile':descriptor['profile'],'initializationId':initial['operationId'],
                'sourceManifestSha256':descriptor['sourceManifestSha256'],
                'nativeUid':descriptor['uid'],'controlGid':descriptor['gid'],
                'permission':'NONE','requestId':None,'readiness':'REFUSED'}
        if pending is not None:
            grant=pending.get('grant');switch.validate_grant(grant)
            if grant['initializationId']!=initial['operationId'] or pending.get('requestId')!=grant['requestId']:
                raise RuntimeError('Original remote-switch intent belongs to a different installation')
            result.update(permission='PENDING',requestId=grant['requestId'])
        else:
            grant=switch.check()
            if grant is not None:
                if grant['initializationId']!=initial['operationId']:
                    raise RuntimeError('Remote-switch grant belongs to a different installation')
                result.update(permission='GRANTED',requestId=grant['requestId'])
            try:
                self.check();result['readiness']='READY'
            except (RuntimeError,OSError,ValueError,KeyError):pass
        return result

    def remote_switch_action(self,action,operation,initialization):
        # Authenticate the current Root before opening any saved request path.
        self.namespace(initialization)
        control=KuraRemoteSwitch(self)
        methods={'authorize-kura-remote-switch':control.authorize,
                 'complete-kura-remote-switch':control.complete,'kura-remote-switch-status':control.status}
        if action not in methods:raise RuntimeError('Fixed native remote-switch action required')
        return methods[action](operation)

    def transport_action(self,action,operation,initialization,endpoint=None):
        self.namespace(initialization)
        control=NativeTransport(self)
        if action=='configure-native-transport-endpoint':return control.configure(operation,endpoint)
        if endpoint is not None:raise RuntimeError('Unexpected transport endpoint selection')
        methods={'complete-native-transport-endpoint':control.complete,'native-transport-endpoint-status':control.status}
        if action not in methods:raise RuntimeError('Fixed native transport action required')
        return methods[action](operation)

    def configuration_write_content(self, initialization, enabled):
        return self.encode({'schemaVersion': 1, 'initializationId': initialization, 'enabled': enabled})

    def configuration_write(self, initialization):
        SourceUpdate.uuid(initialization)
        if not os.path.lexists(self.legacy.path(CONFIGURATION_WRITE)):
            return False
        raw = self.legacy.reader_file(CONFIGURATION_WRITE, limit=256)
        for enabled in (False, True):
            if raw == self.configuration_write_content(initialization, enabled).encode():
                return enabled
        raise RuntimeError('Native configuration-write policy differs from its original installation')

    def configuration_write_action(self, initialization, enabled=None):
        self.namespace(initialization)
        if enabled is not None:
            self.stopped(V2_UNIT)
        self.check()
        current = self.configuration_write(initialization)
        if enabled is not None and current != enabled:
            if enabled and KuraPeer(self).check() is None:
                raise RuntimeError('Native configuration writes require the original paired Kura peer')
            content = self.configuration_write_content(initialization, enabled)
            SourceUpdate(self).replace(CONFIGURATION_WRITE, content.encode(), 0o644)
            current = self.configuration_write(initialization)
            if current != enabled:
                raise RuntimeError('Native configuration-write policy publication could not be verified')
        return {'schemaVersion': 1, 'initializationId': initialization, 'enabled': current, 'unitStarted': False}

    def status(self, operation):
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise RuntimeError('Original native initialization UUID required')
        pending = self.legacy.path(V2_ADMIN + '/.initialization-pending')
        receipt = self.legacy.path(V2_ADMIN + '/initialization.json')
        record = pending if os.path.lexists(pending) else receipt
        value = self.legacy.reader_json(self.legacy.reader_file('/' + str(record.relative_to(self.legacy.root)), mode=0o600))
        if value.get('operationId') != operation:
            raise RuntimeError('Retain the original native initialization UUID')
        if os.path.lexists(pending):
            return {'schemaVersion': 1, 'requestId': operation, 'state': 'UNKNOWN', 'replayed': False}
        try:
            self.check()
            ready = True
        except Exception:
            ready = False
        return {'schemaVersion': 1, 'requestId': operation, 'state': 'APPLIED',
                'currentReadiness': 'READY' if ready else 'REFUSED', 'replayed': False}


class SourceUpdate:
    """Paired code-only maintenance for a stopped, proven empty native profile.

    No credential migration, state reset, unit start or authority change. The
    incoming reviewed controller can bootstrap the first candidate's otherwise
    unconditional prerm refusal, retaining that exact script before replacement.
    """
    PENDING = V2_ADMIN + '/.source-update-pending.json'
    CURRENT = V2_ADMIN + '/source-pair-current.json'
    RECORDS = V2_ADMIN + '/source-pairs'
    PRERM = '/var/lib/dpkg/info/kura-management-agent.prerm'
    MASK = '/run/systemd/system/' + V2_UNIT
    PINS = {'unitSha256', 'binarySha256', 'sourceManifestSha256'}
    TABLES = {'results', 'imported_remote_originals', 'imported_remote_connection_barriers',
              'imported_remote_connection_confirmations', 'firewall_execution_authorities',
              'executions', 'execution_resolutions', 'native_profile_generation'}
    SOURCE_PAYLOAD = {'/usr/lib/systemd/system/kura-management-agent.service':'kura-management-agent.service',
        **{'/usr/share/doc/kura-management-agent/'+name:name for name in [
            'agent.env.example','system-control.json.example','recovery.conf.example',
            'core-snapshot-validator.json.example','network.conf.example']}}
    PAYLOAD = set(NATIVE_FILES) | set(SOURCE_PAYLOAD) | {
        '/usr/bin/yofc-management-agent','/usr/sbin/kura-agent-setup',
        '/usr/share/kura-management-agent/source-manifest.json',
        '/usr/share/kura-management-agent/native-profile.json','/usr/share/kura-management-agent/package-v2',
        '/usr/share/kura-management-agent/java-bridge.json','/usr/share/kura-management-agent/enrollment-reader.json',
        '/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'}

    def __init__(self, profile):
        self.profile, self.legacy = profile, profile.legacy
        self.uninstalled_core_loader = False
        self.unbound_java_bridge = False
        self.local_kura_peer = False
        self.material_kura_peer = False
        self.enrolled_material_kura_peer = False
        self.retained_business = False

    @staticmethod
    def uuid(value):
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise RuntimeError('Original native source maintenance UUID required')
        return value

    @staticmethod
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def raw(self, name, mode=0o600):
        return self.legacy.reader_file(name, mode=mode, limit=1024 * 1024)

    def json(self, name):
        return self.legacy.reader_json(self.raw(name))

    def optional(self, name, mode=0o600):
        return self.legacy.reader_json(self.raw(name,mode)) if os.path.lexists(self.legacy.path(name)) else None

    def no_orphan(self):
        root = self.legacy.path(self.RECORDS)
        if os.path.lexists(root):
            self.profile.directory(self.RECORDS,0,0,0o700)
            for folder in root.iterdir():
                self.uuid(folder.name)
                self.profile.directory(self.RECORDS+'/'+folder.name,0,0,0o700)
                if not os.path.lexists(folder/'result.json'):
                    raise RuntimeError('Lost native maintenance marker; preserve the original source records')

    def mask_path(self):
        # Setup.path intentionally refuses symlinks. Inspect only this fixed
        # runtime mask, with separate strict parent/owner/target checks.
        return self.legacy.root / self.MASK.lstrip('/')

    def verify_mask(self):
        path = self.mask_path(); self.legacy.authorization_parents(path)
        m = path.lstat()
        if not stat.S_ISLNK(m.st_mode) or m.st_uid != 0 or m.st_gid != 0 or os.readlink(path) != '/dev/null':
            raise RuntimeError('Original native maintenance mask changed')

    def install_mask(self):
        path = self.mask_path(); self.legacy.authorization_parents(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        os.symlink('/dev/null',path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.legacy.systemctl('daemon-reload')

    def remove_mask(self):
        path=self.mask_path()
        if os.path.lexists(path):
            self.verify_mask(); path.unlink()
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.legacy.systemctl('daemon-reload')

    def record(self, operation, name):
        return self.RECORDS + '/' + self.uuid(operation) + '/' + name

    @contextmanager
    def package_locks(self):
        descriptors=[]
        try:
            for name in ['/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock']:
                path=self.legacy.path(name);self.legacy.authorization_parents(path)
                fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                descriptors.append(fd);m=os.fstat(fd)
                if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or m.st_nlink!=1 or m.st_mode&0o022:
                    raise RuntimeError('Unsafe native package-manager lock')
                try:fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise RuntimeError('Package manager is busy; no native source intent was published')
            yield
        finally:
            for fd in reversed(descriptors):os.close(fd)

    def immutable(self, name, value, mode=0o600):
        raw = value.encode() if isinstance(value, str) else value
        if os.path.lexists(self.legacy.path(name)):
            if self.raw(name, mode) != raw:
                raise RuntimeError('Original native maintenance record changed')
        else:
            self.profile.publish(name, raw, mode=mode)

    def replace(self, name, raw, mode, *, resume_companion=False):
        path = self.legacy.path(name)
        if os.path.lexists(path) and self.raw(name, mode) == raw:
            return
        self.legacy.authorization_parents(path)
        temporary = path.with_name('.' + path.name + '.source-update-new')
        if resume_companion and os.path.lexists(temporary):
            fd=os.open(temporary,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            with os.fdopen(fd,'rb') as stream:
                m=os.fstat(stream.fileno())
                if (not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or m.st_nlink!=1
                        or stat.S_IMODE(m.st_mode) not in (0o600,mode) or m.st_size>len(raw)
                        or not raw.startswith(stream.read(len(raw)+1))):
                    raise RuntimeError('Unpaired companion publication staging file')
            temporary.unlink()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); os.fchmod(stream.fileno(), mode); os.fchown(stream.fileno(), 0, 0)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)

    def verify_chain(self, original, descriptor, current_bridge=None):
        pointer = self.optional(self.CURRENT)
        expected = descriptor
        initial_hash = self.digest(self.raw(V2_ADMIN + '/initialization.json'))
        seen = set(); expected_bridge = current_bridge
        while pointer is not None:
            if (not isinstance(pointer, dict) or set(pointer) != {'schemaVersion', 'requestId', 'sha256'}
                    or type(pointer['schemaVersion']) is not int or pointer['schemaVersion'] != 1):
                raise RuntimeError('Invalid original native source-pair pointer')
            operation = self.uuid(pointer['requestId'])
            if operation in seen or len(seen) >= 256:
                raise RuntimeError('Invalid native source-pair history')
            seen.add(operation)
            raw = self.raw(self.record(operation, 'result.json'))
            value = self.legacy.reader_json(raw)
            required = {'schemaVersion', 'requestId',
                    'initializationId', 'initializationReceiptSha256', 'previousPair', 'previousIdentity',
                    'identity', 'packageSha256', 'stateFingerprintSha256', 'unitStarted'}
            if (self.digest(raw) != pointer['sha256'] or set(value) not in
                    [required, required | {'retainedRemoval'},
                     required | {'retainedRemoval','peerTransition','materialTransition'},
                     required | {'loaderTransition'}, required | {'javaBridgeTransition'}, required | {'peerTransition'},
                     required | {'peerTransition','companionTransition'},
                     required | {'peerTransition','materialTransition'},
                     required | {'peerTransition','materialTransition','retainedEnrollment'},
                     required | {'peerTransition','materialTransition','retainedEnrollment','retainedBusiness'}]
                    or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                    or value['requestId'] != operation or value['identity'] != expected
                    or value['initializationId'] != original['operationId']
                    or value['initializationReceiptSha256'] != initial_hash or value['unitStarted'] is not False
                    or set(value['previousIdentity']) != set(expected)
                    or any(value['previousIdentity'][key] != expected[key] for key in set(expected) - self.PINS)):
                raise RuntimeError('Native source-pair proof differs from its original initialization')
            if 'loaderTransition' in value:
                previous, incoming = self.loader_transition(value)
                if expected_bridge is None: expected_bridge = self.bridge()
                if incoming != expected_bridge:
                    raise RuntimeError('Native Core loader transition differs from its original source history')
                expected_bridge = previous
            if 'javaBridgeTransition' in value:
                previous, incoming = self.java_bridge_transition(value)
                if expected_bridge is None: expected_bridge = self.bridge()
                if incoming != expected_bridge:
                    raise RuntimeError('Native Java bridge transition differs from its original source history')
                expected_bridge = previous
            if 'peerTransition' in value: self.peer_transition(value)
            if 'materialTransition' in value: self.material_transition(value)
            if 'retainedRemoval' in value:
                removal = RetainedRemoval(self.profile)
                ticket = self.json(removal.record(operation, 'intent'))
                plan = removal.successor(ticket)
                if plan is None or removal.successor_source_receipt(ticket, plan) != value:
                    raise RuntimeError('Original retained removal source publication differs')
            intent=self.optional(self.record(operation,'intent.json'))
            if 'javaBridgeTransition' in value or (isinstance(intent,dict) and 'javaBridgeTransition' in intent):
                if (not isinstance(intent,dict) or 'javaBridgeTransition' not in intent
                        or self.source_result(intent, intent['identity'])!=value):
                    raise RuntimeError('Original Java bridge maintenance proof changed')
            if 'companionTransition' in value or (isinstance(intent,dict) and 'companionTransition' in intent):
                if (not isinstance(intent,dict) or 'companionTransition' not in intent
                        or self.source_result(intent, intent['identity'])!=value):
                    raise RuntimeError('Original Core and Networking maintenance proof changed')
            if 'retainedEnrollment' in value or (isinstance(intent,dict) and 'retainedEnrollment' in intent):
                if (not isinstance(intent,dict) or value.get('retainedEnrollment')!=intent.get('retainedEnrollment')
                        or value['stateFingerprintSha256']!=self.digest(self.profile.encode(intent['state']).encode())):
                    raise RuntimeError('Original retained enrollment source proof changed')
                RetainedEnrollment.summary(value['retainedEnrollment'])
            if 'retainedBusiness' in value or (isinstance(intent,dict) and 'retainedBusiness' in intent):
                if (not isinstance(intent,dict) or value.get('retainedBusiness')!=intent.get('retainedBusiness')
                        or value['stateFingerprintSha256']!=self.digest(self.profile.encode(intent['state']).encode())):
                    raise RuntimeError('Original retained business source proof changed')
                RetainedBusiness.bundle(value['retainedBusiness'],intent)
            expected = value['previousIdentity']; pointer = value['previousPair']
        if expected != original['identity']:
            raise RuntimeError('Native runtime identity/source pair changed without original maintenance proof')
        return seen

    def namespace(self, initialization):
        """Authenticate the local Root before looking up a caller's saved UUID.

        Publication can legitimately contain either old or incoming code/public
        pins. Only the one original pending ticket authorizes that interval.
        """
        self.uuid(initialization)
        descriptor=self.profile.descriptor()
        for name,uid,gid,mode in [(V2_ADMIN,0,0,0o700),(V2_CONFIG,0,0,0o700),
                (V2_PUBLIC,0,0,0o755),(V2_STATE,descriptor['uid'],descriptor['gid'],0o700)]:
            self.profile.directory(name,uid,gid,mode)
        if os.path.lexists(self.legacy.path(V2_ADMIN+'/.initialization-pending')):
            raise RuntimeError('Original native initialization remains uncertain')
        raw=self.raw(V2_ADMIN+'/initialization.json');original=self.legacy.reader_json(raw)
        if (not isinstance(original,dict) or set(original)!={'schemaVersion','operationId','identity',
                'remoteEnabled','unitStarted','continuitySha256'} or type(original['schemaVersion']) is not int
                or original['schemaVersion']!=1 or original['remoteEnabled'] is not False or original['unitStarted'] is not False):
            raise RuntimeError('Original native initialization proof differs')
        if original['operationId']!=initialization:
            raise RuntimeError('Different native installation; do not query or complete the saved request here')
        self.profile.initialization_state(original,descriptor)
        pending=self.optional(self.PENDING);public=self.legacy.reader_json(self.raw(V2_IDENTITY,0o644))
        if pending is None:
            if public!=descriptor:raise RuntimeError('Native public source identity differs')
            self.verify_chain(original,descriptor)
        else:
            if (not isinstance(pending,dict) or type(pending.get('schemaVersion')) is not int
                    or pending['schemaVersion']!=1 or pending.get('initializationId')!=initialization
                    or pending.get('initializationReceiptSha256')!=self.digest(raw)):
                raise RuntimeError('Pending native source belongs to a different original installation')
            self.uuid(pending['requestId'])
            previous,incoming=pending['previousIdentity'],pending['identity']
            for identity in [previous,incoming]:
                if (not isinstance(identity,dict) or set(identity)!=set(descriptor)
                        or any(identity[k]!=descriptor[k] for k in set(descriptor)-self.PINS)):
                    raise RuntimeError('Pending native source cannot change original runtime roles')
            if descriptor not in [previous,incoming] or public not in [previous,incoming]:
                raise RuntimeError('Native code/public identity is outside its original pending pair')
            if 'retainedBusiness' in pending:RetainedBusiness.bundle(pending['retainedBusiness'],pending)
            pointer=self.optional(self.CURRENT)
            if pointer==pending['previousPair']:
                self.verify_chain(original,previous,pending['bridge'])
            elif isinstance(pointer,dict) and pointer.get('requestId')==pending['requestId']:
                self.verify_chain(original,incoming)
            else:raise RuntimeError('Pending native source lost its original published pair')
        self.business_initialization=initialization
        return descriptor,original

    def initial_runtime_assets(self, descriptor):
        """Typed assets created by the unbound/default-off native constructors.

        Unknown recovery/network/enrollment state is not empty housekeeping.
        In particular, never ignore a nonempty WAL while inspecting main DB.
        """
        return self.runtime_assets(descriptor)

    def runtime_assets(self, descriptor, extra_directories=(), extra_files=(), actor='installation', business=False):
        root=self.legacy.path(V2_STATE)
        directories={'network','firewall','recovery','recovery/backups','recovery/receipts','recovery/staging'}
        directories.update(extra_directories)
        required={'.native-profile-v1','results.sqlite','results.sqlite.plan-key'}
        files=required|{'remote-management.json','system-change.lock','network/coordinator.lock',
                        'results.sqlite-wal','results.sqlite-shm'}
        files.update(extra_files)
        observed={str(path.relative_to(root)):path for path in root.rglob('*')}
        if not required<=set(observed) or set(observed)-files-directories:
            raise RuntimeError('Native runtime has business, pending or unreviewed owned state; preserve it')
        for name,path in observed.items():
            m=path.lstat();directory=name in directories
            if (m.st_uid!=descriptor['uid'] or m.st_gid!=descriptor['gid']
                    or stat.S_IMODE(m.st_mode)!=(0o700 if directory else 0o600)
                    or (not directory and m.st_size>(RetainedBusiness.LIMIT if business and name in
                        ['results.sqlite','results.sqlite-wal'] else 16*1024*1024 if business and name=='results.sqlite-shm' else 8*1024*1024))
                    or (not stat.S_ISDIR(m.st_mode) if directory else not stat.S_ISREG(m.st_mode) or m.st_nlink!=1)):
                raise RuntimeError('Unsafe native runtime asset ownership/type; never repair by adoption')
        runtime=set(observed)-required-{'results.sqlite-wal','results.sqlite-shm'}
        if runtime and 'remote-management.json' not in observed:
            raise RuntimeError('Retained runtime lost its original remote decision; recovery required')
        if 'remote-management.json' in observed:
            path=observed['remote-management.json']
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME)
            with os.fdopen(fd,'rb') as stream:
                if os.fstat(stream.fileno()).st_size>4096:raise RuntimeError('Oversized native remote decision')
                value=self.legacy.reader_json(stream.read(4097))
            if (set(value)!={'version','revision','enabled','actor'} or type(value['version']) is not int
                    or value['version']!=1 or value['enabled'] is not False or value['actor']!=actor
                    or not isinstance(value['revision'],str) or str(uuid.UUID(value['revision']))!=value['revision']):
                raise RuntimeError('Native remote decision needs its original authorized maintenance')
        for name in ['system-change.lock','network/coordinator.lock']+([] if business else ['results.sqlite-wal']):
            if name in observed and observed[name].lstat().st_size!=0:
                raise RuntimeError('Nonempty native journal/WAL or lock requires original state maintenance')
        if (not business and 'results.sqlite-shm' in observed and observed['results.sqlite-shm'].lstat().st_size not in [0,32768]):
            raise RuntimeError('Unreviewed native shared-memory state requires original maintenance')
        self.profile.directory(V2_STATE,descriptor['uid'],descriptor['gid'],0o700)
        return [root,*observed.values()]

    @contextmanager
    def runtime_locks(self, descriptor):
        descriptors=[]
        try:
            for leaf in ['system-change.lock','network/coordinator.lock']:
                path=self.legacy.path(V2_STATE+'/'+leaf)
                if not os.path.lexists(path):continue
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(fd);m=os.fstat(fd)
                if (not stat.S_ISREG(m.st_mode) or m.st_uid!=descriptor['uid'] or m.st_gid!=descriptor['gid']
                        or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o600 or m.st_size!=0):
                    raise RuntimeError('Unsafe original native runtime lock')
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise RuntimeError('Original native runtime writer remains active')
            yield
        finally:
            for fd in reversed(descriptors):os.close(fd)

    def snapshot(self):
        if any(os.path.lexists(self.legacy.path(name)) for name in [KuraPeer.PUBLIC,KuraPeer.CURRENT]):
            raise RuntimeError('Authorized Kura peer requires its joint native maintenance flow')
        return self.initial_snapshot()

    def initial_snapshot(self, extra_config=(), include_switch=True, include_transport=True, extra_assets=()):
        descriptor = self.profile.descriptor()
        self.profile.stopped('kura-management-agent.service'); self.profile.stopped(V2_UNIT)
        assets=self.initial_runtime_assets(descriptor) + list(extra_assets)
        if include_switch:assets+=KuraRemoteSwitch(self.profile).proof_assets()
        if include_transport:assets+=NativeTransport(self.profile).proof_assets()
        with self.runtime_locks(descriptor):
            return self.snapshot_assets(descriptor,assets,extra_config=extra_config)

    def snapshot_assets(self, descriptor, assets, extra_config=(), asset_owners=None, business=None):
        config = self.legacy.path(CONFIGURATION_WRITE)
        if os.path.lexists(config):
            original = self.json(V2_ADMIN + '/initialization.json')
            self.profile.configuration_write(original['operationId'])
            if config not in assets:
                assets = [*assets, config]
        if set(p.name for p in self.legacy.path(V2_CONFIG).iterdir()) != {'agent.env',*extra_config}:
            raise RuntimeError('Native credentials or grants require their separate maintenance flow')
        for name in ['/etc/kura-management-agent', '/var/lib/kura-management-agent']:
            path = self.legacy.path(name)
            if os.path.lexists(path):
                m = path.lstat()
                if (not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_gid != 0
                        or stat.S_IMODE(m.st_mode) != 0o755 or any(path.iterdir())):
                    raise RuntimeError('Real legacy data must not be adopted by native code maintenance')
        if business is None:
            database = self.legacy.path(V2_STATE + '/results.sqlite')
            with closing(sqlite3.connect('file:' + str(database) + '?mode=ro&immutable=1', uri=True)) as connection:
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
                tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables != self.TABLES or any(connection.execute('SELECT count(*) FROM ' + name).fetchone()[0]
                        for name in self.TABLES - {'native_profile_generation'}):
                    raise RuntimeError('Retained business or unknown records require full native maintenance')
        result = {}
        names=['/'+str(path.relative_to(self.legacy.root)) for path in assets]+[
                V2_CONFIG+'/agent.env',V2_ADMIN+'/initialization.json',V2_CONTINUITY]
        for name in names:
            path=self.legacy.path(name);directory=path.is_dir()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME
                         | (os.O_DIRECTORY if directory else 0))
            try:
                m = os.fstat(fd); own = name.startswith(V2_STATE + '/')
                own=own or name==V2_STATE
                uid,gid=(asset_owners or {}).get(name,(descriptor['uid'],descriptor['gid']) if own else (0,0))
                if ((not stat.S_ISDIR(m.st_mode) if directory else not stat.S_ISREG(m.st_mode) or m.st_nlink!=1)
                        or m.st_size>(RetainedBusiness.LIMIT if business is not None and name in
                            [V2_STATE+'/results.sqlite',V2_STATE+'/results.sqlite-wal'] else
                            16*1024*1024 if business is not None and name==V2_STATE+'/results.sqlite-shm' else 8*1024*1024) or m.st_uid!=uid
                        or m.st_gid!=gid
                        or stat.S_IMODE(m.st_mode)!=(0o700 if directory else 0o644 if name in [
                            V2_IDENTITY,V2_CONTINUITY,CONFIGURATION_WRITE,KuraPeer.PUBLIC,KuraMaterial.PUBLIC,
                            KuraRemoteSwitch.PUBLIC,NativeTransport.PUBLIC] else 0o600)):
                    raise RuntimeError('Unsafe retained native maintenance input')
                digest=None
                if not directory:
                    with os.fdopen(os.dup(fd),'rb') as stream:
                        digest=hashlib.file_digest(stream,'sha256').hexdigest()
                after = os.fstat(fd)
                stable = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,
                                    v.st_size,v.st_mtime_ns,v.st_ctime_ns)
                if stable(m) != stable(after) or stable(m)!=stable(path.lstat()):
                    raise RuntimeError('Native state changed during source maintenance')
                result[name] = [*stable(m),digest]
            finally:
                os.close(fd)
        if business is not None:
            RetainedBusiness.report(business,descriptor,business['inventory']['initializationId'],result)
        return result

    def enrolled_snapshot(self, local, expected=None, include_switch=True, include_transport=True, business=None):
        self.profile.stopped('kura-management-agent.service');self.profile.stopped(V2_UNIT)
        KuraMaterial(self.profile).maintenance_stopped(local,retained=True)
        descriptor=self.profile.descriptor()
        with self.runtime_locks(descriptor):
            enrollment=RetainedEnrollment(self.profile,local)
            summary=enrollment.inspect()
            if expected is not None and summary!=RetainedEnrollment.summary(expected):
                raise RuntimeError('Original retained enrollment binding changed')
            assets=self.runtime_assets(descriptor,enrollment.directories,enrollment.files,actor=enrollment.actor,business=business is not None)
            report=None
            if business is not None:
                report=RetainedBusiness(self).inspect(business['packagePath'],business['packageSha256'],
                    business['identity'],business['initializationId'])
                if business.get('report') is not None and report!=business['report']:
                    raise RuntimeError('Original authenticated retained business inventory changed')
                business['report']=report
            if include_switch:assets+=KuraRemoteSwitch(self.profile).proof_assets()
            if include_transport:assets+=NativeTransport(self.profile).proof_assets()
            result=self.snapshot_assets(descriptor,assets+enrollment.core_assets,
                extra_config=['enrollment-relay-grant.json'],asset_owners=enrollment.core_owners,business=report)
            for name,want in enrollment.read_fingerprints.items():
                if result.get(name)!=want:raise RuntimeError('Retained enrollment changed during source inspection')
            return result,summary

    def bridge(self):
        raw=self.legacy.reader_file('/usr/share/kura-management-agent/java-bridge.json')
        path='/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'
        return self.bridge_data(raw,self.profile.asset(path,maximum=16*1024*1024))

    def peer_transition(self, value):
        transition=value.get('peerTransition')
        companion='companionTransition' in value
        fields={'schemaVersion','profile','requestId','initializationId','nativeIdentitySha256',
                'controlGid','kuraUid','kuraGid','coreUnitSha256','coreLoaderSha256','javaBridgeMetadataSha256'}
        if (not isinstance(transition,dict) or set(transition)!=
                {'authorizationId','authorizationResultSha256','previous','incoming'}
                or 'loaderTransition' in value
                or not isinstance(transition['authorizationResultSha256'],str)
                or not re.fullmatch('[0-9a-f]{64}',transition['authorizationResultSha256'])):
            raise RuntimeError('Invalid original local Kura source transition')
        operation=self.uuid(transition['authorizationId'])
        previous,incoming=transition['previous'],transition['incoming']
        if isinstance(previous,dict) and previous.get('schemaVersion')==2:
            fields.add('coreNetworkingDropInSha256')
        mutable=({'coreUnitSha256','coreNetworkingDropInSha256'} if companion else {'nativeIdentitySha256'})
        if (not isinstance(previous,dict) or not isinstance(incoming,dict)
                or set(previous)!=fields or set(incoming)!=fields
                or any(previous[k]!=incoming[k] for k in fields-mutable)
                or previous['requestId']!=operation
                or previous['initializationId']!=value['initializationId']
                or previous['nativeIdentitySha256']!=self.digest(self.profile.encode(value['previousIdentity']).encode())
                or incoming['nativeIdentitySha256']!=self.digest(self.profile.encode(value['identity']).encode())
                or not companion and previous['nativeIdentitySha256']==incoming['nativeIdentitySha256']):
            raise RuntimeError('Local Kura source transition changed original permission scope')
        if companion:
            KuraCompanionUpdate(self).transition(value, previous, incoming)
        return transition

    def current_peer(self, original, authorization_sha):
        public=self.optional(KuraPeer.PUBLIC,0o644);expected=public
        pointer=self.optional(self.CURRENT);seen=set()
        while pointer is not None:
            if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                    or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
                raise RuntimeError('Invalid local Kura source history pointer')
            operation=self.uuid(pointer['requestId'])
            if operation in seen or len(seen)>=256: raise RuntimeError('Invalid local Kura source history')
            seen.add(operation);raw=self.raw(self.record(operation,'result.json'));value=self.legacy.reader_json(raw)
            if self.digest(raw)!=pointer['sha256']: raise RuntimeError('Local Kura source history checksum differs')
            if 'peerTransition' in value:
                transition=self.peer_transition(value)
                if (transition['authorizationId']!=original['requestId']
                        or transition['authorizationResultSha256']!=authorization_sha
                        or transition['incoming']!=expected):
                    raise RuntimeError('Local Kura source history differs from original authority')
                expected=transition['previous']
            pointer=value['previousPair']
        if expected!=original:
            raise RuntimeError('Local Kura source binding changed without original authority history')
        return public

    def material_transition(self, value):
        transition=value.get('materialTransition')
        if (not isinstance(transition,dict) or set(transition)!=
                {'authorizationId','authorizationResultSha256','previous','incoming'}
                or 'loaderTransition' in value or 'peerTransition' not in value
                or not isinstance(transition['authorizationResultSha256'],str)
                or not re.fullmatch('[0-9a-f]{64}',transition['authorizationResultSha256'])):
            raise RuntimeError('Invalid original material source transition')
        operation=self.uuid(transition['authorizationId']);peer=self.peer_transition(value)
        previous,incoming=transition['previous'],transition['incoming']
        mutable={'nativeIdentitySha256','publisherPairSha256','relayPairSha256','relayGrantSha256'}
        for public,identity in [(previous,value['previousIdentity']),(incoming,value['identity'])]:
            raw=KuraMaterial.private_bytes(public)
            if (public['requestId']!=operation or public['peerAuthorizationId']!=peer['authorizationId']
                    or public['nativeIdentitySha256']!=self.digest(self.profile.encode(identity).encode())
                    or [public[k] for k in ['agentUid','agentGid','readerGid']]!=
                       [identity[k] for k in ['uid','gid','readerGid']]
                    or public['sourceUid']!=peer['previous']['kuraUid']
                    or public['relayGrantSha256']!=self.digest(raw)):
                raise RuntimeError('Material source transition changed original permission scope')
        if (any(previous[k]!=incoming[k] for k in set(previous)-mutable)
                or previous['nativeIdentitySha256']==incoming['nativeIdentitySha256']):
            raise RuntimeError('Material source transition changed original permission scope')
        return transition

    def material_history(self, original, authorization_sha, expected, pointer):
        seen=set()
        while pointer is not None:
            if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                    or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
                raise RuntimeError('Invalid material source history pointer')
            operation=self.uuid(pointer['requestId'])
            if operation in seen or len(seen)>=256: raise RuntimeError('Invalid material source history')
            seen.add(operation);raw=self.raw(self.record(operation,'result.json'));value=self.legacy.reader_json(raw)
            if self.digest(raw)!=pointer['sha256']: raise RuntimeError('Material source history checksum differs')
            if 'materialTransition' in value:
                transition=self.material_transition(value)
                if (transition['authorizationId']!=original['requestId']
                        or transition['authorizationResultSha256']!=authorization_sha
                        or transition['incoming']!=expected):
                    raise RuntimeError('Material source history differs from original authority')
                expected=transition['previous']
            pointer=value['previousPair']
        if expected!=original:
            raise RuntimeError('Material source binding changed without original authority history')

    def current_material(self, original, authorization_sha):
        public=self.optional(KuraMaterial.PUBLIC,0o644)
        self.material_history(original,authorization_sha,public,self.optional(self.CURRENT))
        if (self.raw(KuraMaterial.PUBLIC,0o644)!=self.profile.encode(public).encode()
                or self.raw(KuraMaterial.RELAY)!=KuraMaterial.private_bytes(public)):
            raise RuntimeError('Material current publication differs from original source proof')
        return public

    def bind_authorities(self, ticket, local_peer, local_material):
        _, authorization_sha = KuraPeer(self.profile).original()
        identity_sha = self.digest(self.profile.encode(ticket['identity']).encode())
        ticket['peerTransition'] = {
            'authorizationId': local_peer['requestId'], 'authorizationResultSha256': authorization_sha,
            'previous': local_peer, 'incoming': {**local_peer, 'nativeIdentitySha256': identity_sha}}
        self.peer_transition(ticket)
        if local_material is not None:
            material = KuraMaterial(self.profile)
            _, material_sha = material.original()
            incoming = {**local_material, **self.incoming_material_pair, 'nativeIdentitySha256': identity_sha}
            incoming['relayGrantSha256'] = self.digest(material.private_bytes(incoming))
            ticket['materialTransition'] = {
                'authorizationId': local_material['requestId'], 'authorizationResultSha256': material_sha,
                'previous': local_material, 'incoming': incoming}
            self.material_transition(ticket)

    def ticket_snapshot(self, ticket, publishing=False):
        business=None
        if 'retainedBusiness' in ticket:
            retained=RetainedBusiness.bundle(ticket['retainedBusiness'],ticket)
            business={**retained,'packageSha256':ticket['packageSha256'],'identity':ticket['identity'],
                      'initializationId':ticket['initializationId']}
        if 'retainedEnrollment' in ticket and not {'peerTransition','materialTransition'}<=set(ticket):
            raise RuntimeError('Retained enrollment requires original material source authority')
        if 'peerTransition' not in ticket: return self.snapshot()
        material=KuraMaterial(self.profile)
        companion='companionTransition' in ticket
        if material.present() and 'materialTransition' not in ticket and not companion:
            raise RuntimeError('Material authority requires its separate joint maintenance flow')
        transition=self.peer_transition(ticket)
        peer=KuraPeer(self.profile);original,authorization_sha=peer.original()
        self.profile.stopped('kura.service')
        context=peer.peer(transition['authorizationId'],ticket['initializationId'])
        allowed=[transition['previous'],transition['incoming']] if publishing else [transition['previous']]
        if (authorization_sha!=transition['authorizationResultSha256']
                or original['requestId']!=transition['authorizationId']
                or self.optional(KuraPeer.PUBLIC,0o644) not in allowed
                or context not in allowed or peer.members()!=['kurad']
                  or self.digest(self.raw(peer.ENV))!=KuraRemoteSwitch(self.profile).expected_env_sha(original)):
            raise RuntimeError('Original local Kura authority changed during source maintenance')
        if companion:
            return KuraCompanionUpdate(self).snapshot(ticket['companionTransition'],context,ticket['previousPair'])
        if 'materialTransition' in ticket:
            update=self.material_transition(ticket)
            old_public,material_sha=material.original()
            self.material_history(old_public,material_sha,update['previous'],ticket['previousPair'])
            permitted=[update['previous'],update['incoming']] if publishing else [update['previous']]
            current=self.raw(material.PUBLIC,0o644);private=self.raw(material.RELAY)
            material.maintenance_stopped(context,retained='retainedEnrollment' in ticket)
            actual,_=material.context(update['authorizationId'],context)
            if (material_sha!=update['authorizationResultSha256']
                    or old_public['requestId']!=update['authorizationId']
                    or current not in [self.profile.encode(v).encode() for v in permitted]
                    or private not in [material.private_bytes(v) for v in permitted]
                    or actual not in permitted):
                raise RuntimeError('Original material authority changed during source maintenance')
            if 'retainedEnrollment' in ticket:
                return self.enrolled_snapshot(context,ticket['retainedEnrollment'],business=business)[0]
            return self.initial_snapshot(extra_config=['enrollment-relay-grant.json'])
        if 'retainedEnrollment' in ticket:
            raise RuntimeError('Retained enrollment requires original material source authority')
        return self.initial_snapshot()

    def bridge_data(self, raw, jar_sha):
        value=self.legacy.reader_json(raw)
        path='/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'
        if (set(value)!={'symbolicName','version','path','sha256','coreLoaderProtocol','coreLoaderSha256'}
                or value.get('path') != path or value.get('symbolicName') != 'org.eclipse.kura.management.bridge'
                or type(value.get('coreLoaderProtocol')) is not int or value.get('coreLoaderProtocol') != 1
                or not re.fullmatch('[0-9a-f]{64}',value.get('coreLoaderSha256',''))
                or jar_sha != value.get('sha256')):
            raise RuntimeError('Existing native Java/Core loader pair differs')
        return {'metadataSha256':self.digest(raw),'jarSha256':value['sha256'],
                'coreLoaderSha256':value['coreLoaderSha256']}

    @staticmethod
    def loader_transition(value):
        transition=value.get('loaderTransition')
        keys={'metadataSha256','jarSha256','coreLoaderSha256'}
        if (not isinstance(transition,dict) or set(transition)!={'previous','incoming'}
                or any(not isinstance(transition[k],dict) or set(transition[k])!=keys
                       or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v)
                              for v in transition[k].values()) for k in ['previous','incoming'])):
            raise RuntimeError('Invalid native Core loader transition proof')
        previous,incoming=transition['previous'],transition['incoming']
        if (previous['jarSha256']!=incoming['jarSha256']
                or previous['coreLoaderSha256']==incoming['coreLoaderSha256']
                or previous['metadataSha256']==incoming['metadataSha256']):
            raise RuntimeError('Native Core loader transition must retain the exact Java adapter')
        if 'bridge' in value and value['bridge']!=previous:
            raise RuntimeError('Original native Core loader transition changed')
        return previous,incoming

    @staticmethod
    def java_bridge_transition(value):
        transition = value.get('javaBridgeTransition')
        keys = {'metadataSha256', 'jarSha256', 'coreLoaderSha256'}
        if (not isinstance(transition, dict) or transition.keys() != {'previous', 'incoming', 'core'}
                or any(not isinstance(transition[key], dict) or transition[key].keys() != keys
                       or any(not KuraCompanionUpdate.hash(digest) for digest in transition[key].values())
                       for key in ('previous', 'incoming'))):
            raise RuntimeError('Invalid native Java bridge transition proof')
        previous, incoming = transition['previous'], transition['incoming']
        core = transition['core']
        if (previous['coreLoaderSha256'] != incoming['coreLoaderSha256']
                or previous['jarSha256'] == incoming['jarSha256']
                or previous['metadataSha256'] == incoming['metadataSha256']
                or ('bridge' in value and value['bridge'] != previous)
                or not isinstance(core, dict) or core.keys() != {'root', 'version', 'home', 'unitSha256', 'lastStarted'}
                or not KuraCompanionUpdate.hash(core['unitSha256'])
                or type(core['lastStarted']) is not int or core['lastStarted'] < 0
                or not isinstance(core['home'], str) or not re.fullmatch(r'/opt/eclipse/kura_[A-Za-z0-9.+~_-]+_linux', core['home'])
                or not isinstance(core['version'], str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', core['version'])
                or not isinstance(core['root'], dict) or core['root'].keys() != {'device', 'inode', 'boot'}
                or any(type(core['root'][key]) is not int or core['root'][key] < 1 for key in ('device', 'inode'))):
            raise RuntimeError('Java bridge update must retain the original paired Core')
        SourceUpdate.uuid(core['root']['boot'])
        return previous, incoming

    def stopped_bridge_core(self, loader):
        companion = KuraCompanionUpdate(self)
        version = companion.installed_version('kura-core')
        home = self.legacy.guard_core_loader(loader)
        unit = '/usr/lib/systemd/system/kura.service'
        result = self.legacy.systemctl('show', 'kura.service', '--property=ActiveState',
                                      '--property=MainPID', '--property=Job', '--property=FragmentPath',
                                      '--property=ExecMainStartTimestampMonotonic')
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines()) if result is not None else {}
        last_start = fields.get('ExecMainStartTimestampMonotonic', '')
        if (home is None or fields.get('ActiveState') != 'inactive' or fields.get('MainPID') != '0'
                or fields.get('Job') != '' or fields.get('FragmentPath') not in (unit, '/lib/systemd/system/kura.service')
                or not re.fullmatch(r'[0-9]+', last_start)):
            raise RuntimeError('Stop the original packaged Kura Main for Java bridge maintenance')
        return dict(root=companion.root(), version=version, home=str(home),
                    unitSha256=self.digest(self.raw(unit, 0o644)), lastStarted=int(last_start))

    def verify_bridge_core(self, ticket):
        previous, incoming = self.java_bridge_transition(ticket)
        if self.stopped_bridge_core(previous['coreLoaderSha256']) != ticket['javaBridgeTransition']['core']:
            raise RuntimeError('Original stopped Core changed during native Java bridge maintenance')
        return incoming

    def core_absent(self):
        parent=self.legacy.path('/opt/eclipse')
        if ((os.path.lexists(parent) and (parent.is_symlink() or not parent.is_dir()
                or any(p.name.startswith('kura') for p in parent.iterdir())))
                or any(os.path.lexists(self.legacy.path(n)) for n in
                       ['/var/lib/kura-key-service','/var/lib/kura-key-recovery'])):
            raise RuntimeError('Core loader change requires an uninstalled Core with no retained data')
        configuration=self.legacy.path('/etc/kura')
        if os.path.lexists(configuration):
            m=configuration.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_gid!=0
                    or stat.S_IMODE(m.st_mode)!=0o755 or any(configuration.iterdir())):
                raise RuntimeError('Core loader change must not adopt real Core configuration')
        self.legacy.reader_file('/var/lib/dpkg/status',limit=16*1024*1024)
        result=self.legacy.run(['dpkg-query','--admindir='+str(self.legacy.path('/var/lib/dpkg')),
                               '--show','--showformat=${db:Status-Status}','kura-core'],
                              check=False,capture_output=True,text=True)
        if result.returncode!=1 or result.stdout:
            raise RuntimeError('Core package or retained package state requires joint cohort maintenance')
        if self.legacy.path('/run/systemd/system').is_dir():
            for unit in ['kura.service','kura-key-service.socket','kura-key-service.service','kura-key-recovery.service']:
                result=self.legacy.run(['/bin/systemctl','show',unit,'--property=LoadState'],
                                      check=False,capture_output=True,text=True)
                if result.returncode not in [0,1] or result.stdout.strip()!='LoadState=not-found':
                    raise RuntimeError('Installed Core units require their joint cohort maintenance')

    @staticmethod
    def embedded(raw):
        import ast
        node=ast.parse(raw).body[-1]
        if (not isinstance(node,ast.If) or not isinstance(node.test,ast.Compare)
                or not isinstance(node.test.left,ast.Name) or node.test.left.id!='__name__'
                or len(node.test.ops)!=1 or not isinstance(node.test.ops[0],ast.Eq)
                or len(node.test.comparators)!=1 or not isinstance(node.test.comparators[0],ast.Constant)
                or node.test.comparators[0].value!='__main__'):
            raise RuntimeError('Exact native source main guard required')
        return b''.join(raw.splitlines(keepends=True)[:node.lineno-1])

    @staticmethod
    def authenticate_prerm(raw, setup, runtime, source, pair, loader, script='prerm', historical_legacy_pair=None):
        import ast
        body=SourceUpdate.embedded(setup)+b'\n'+SourceUpdate.embedded(runtime)+b'\n'
        if raw.count(body) != 1 or not raw.startswith(b'#!/usr/bin/python3 -I\n'):
            raise RuntimeError('Native maintainer body is not its paired Root source')
        prefix,tail=raw.split(body)
        fields={}
        for statement in ast.parse(prefix).body:
            if (not isinstance(statement,ast.Assign) or len(statement.targets)!=1
                    or not isinstance(statement.targets[0],ast.Name)):
                raise RuntimeError('Unexpected native maintainer prefix')
            key=statement.targets[0].id
            if key in fields:raise RuntimeError('Duplicate native maintainer prefix')
            fields[key]=ast.literal_eval(statement.value)
        if 'PACKAGE_LEGACY_NM_PAIR' in fields:
            if (historical_legacy_pair is None or 'PACKAGE_NATIVE_PAIR' not in fields
                    or fields.pop('PACKAGE_LEGACY_NM_PAIR') != historical_legacy_pair()):
                raise RuntimeError('Historical native maintainer metadata differs from the installed package')
        rows={r['path']:r['sha256'] for r in source['sourceFiles']}
        if (set(fields) not in [{'SCRIPT_NAME','PACKAGE_CORE_LOADER_SHA256'},
                               {'SCRIPT_NAME','PACKAGE_CORE_LOADER_SHA256','PACKAGE_NATIVE_PAIR'}]
                or fields.get('SCRIPT_NAME')!=script or fields.get('PACKAGE_CORE_LOADER_SHA256')!=loader
                or ('PACKAGE_NATIVE_PAIR' in fields and fields['PACKAGE_NATIVE_PAIR']!=pair)
                or hashlib.sha256(tail).hexdigest()!=rows.get('packaging/native_lifecycle.py')):
            raise RuntimeError('Native maintainer lifecycle is not its paired source')

    def archive(self, package, control=False, inspection=False):
        process = subprocess.Popen(['dpkg-deb', '--ctrl-tarfile' if control else '--fsys-tarfile', str(package)],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        timer = threading.Timer(30, process.kill); timer.daemon = True; timer.start()
        result = {}; total = 0
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    parts = Path(member.name).parts
                    if member.name.startswith('/') or '..' in parts or member.issym() or member.islnk():
                        raise RuntimeError('Unsafe native package member')
                    if member.uid != 0 or member.gid != 0 or member.mode & 0o7022:
                        raise RuntimeError('Unsafe native package ancestor or code ownership')
                    if member.isdir():
                        allowed_dirs={'.'} if control else {'.',*{
                            str(parent).lstrip('/') for path in self.PAYLOAD for parent in Path(path).parents
                            if str(parent)!='/'}}
                        directory='/'.join(part for part in parts if part!='.') or '.'
                        if directory not in allowed_dirs:raise RuntimeError('Unexpected native package data directory')
                        continue
                    total += member.size
                    if (not member.isfile() or member.uid != 0 or member.gid != 0
                            or member.mode & 0o7022 or member.size > 512 * 1024 * 1024
                            or total > 512 * 1024 * 1024):
                        raise RuntimeError('Unsafe native package code ownership or size')
                    name = '/'.join(part for part in parts if part != '.')
                    allowed={'control','preinst','postinst','prerm','postrm'} if control else {path.lstrip('/') for path in self.PAYLOAD}
                    if name not in allowed:raise RuntimeError('Unexpected native package data or control payload')
                    if name in result: raise RuntimeError('Duplicate native package member')
                    keep = control or name in ['usr/share/kura-management-agent/source-manifest.json',
                        'usr/share/kura-management-agent/native-profile.json','usr/share/kura-management-agent/package-v2',
                        'usr/lib/kura-management-agent/setup.py','usr/lib/kura-management-agent/runtime_setup.py']
                    keep |= name in ['usr/sbin/kura-agent-setup','usr/share/kura-management-agent/enrollment-reader.json',
                                     'usr/share/kura-management-agent/java-bridge.json']
                    program=inspection and not control and name=='usr/bin/yofc-management-agent'
                    if keep and member.size > 2 * 1024 * 1024: raise RuntimeError('Oversized native metadata')
                    keep |= program
                    source = archive.extractfile(member); digest = hashlib.sha256(); data = bytearray()
                    for chunk in iter(lambda: source.read(65536), b''):
                        digest.update(chunk)
                        if keep: data.extend(chunk)
                    result[name] = {'sha256':digest.hexdigest(),'mode':member.mode & 0o7777,'data':bytes(data) if keep else None}
                # The tar reader stops at the end marker. Consume bounded zero
                # padding before waiting for dpkg-deb to finish writing.
                padding = 0
                for chunk in iter(lambda: archive.fileobj.read(8192), b''):
                    padding += len(chunk)
                    if padding > 64 * 1024 or chunk.strip(b'\0'):
                        raise RuntimeError('Unexpected data after native package tar end marker')
            if process.wait(timeout=5) != 0: raise RuntimeError('Native package inspection failed')
        finally:
            timer.cancel(); process.stdout.close()
            if process.poll() is None: process.kill(); process.wait()
        return result

    def candidate(self, name, expected, inspection=False, *, original_bridge=None):
        if self.profile.asset(name, 0o600, 64 * 1024 * 1024) != expected:
            raise RuntimeError('Reviewed native package checksum differs')
        package = self.legacy.path(name)
        payload = self.archive(package,inspection=True) if inspection else self.archive(package)
        control = self.archive(package, True)
        if set(payload)!={path.lstrip('/') for path in self.PAYLOAD} or set(control)!={'control','preinst','postinst','prerm','postrm'}:
            raise RuntimeError('Complete native code-only payload and controls required')
        for path,row in payload.items():
            expected_mode=0o755 if path in ['usr/bin/yofc-management-agent','usr/sbin/kura-agent-setup'] else 0o644
            if row['mode']!=expected_mode:raise RuntimeError('Exact native payload mode required')
        if payload['usr/sbin/kura-agent-setup']['data']!=b'#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/kura-management-agent/runtime_setup.py "$@"\n':
            raise RuntimeError('Exact isolated native setup launcher required')
        fields = {}
        for line in control['control']['data'].decode().splitlines():
            if line and not line[0].isspace():
                key, separator, value = line.partition(': ')
                if not separator or key in fields: raise RuntimeError('Invalid native package control fields')
                fields[key] = value
        architecture = subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
        if (fields.get('Package') != 'kura-management-agent' or fields.get('Architecture') != architecture
                or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*',fields.get('Version',''))
                or payload['usr/bin/yofc-management-agent']['mode'] != 0o755):
            raise RuntimeError('Incoming native package identity or architecture differs')
        self.incoming_version=fields['Version']
        source_name = 'usr/share/kura-management-agent/source-manifest.json'
        for path in [source_name,'usr/share/kura-management-agent/native-profile.json',
                'usr/share/kura-management-agent/package-v2','usr/share/kura-management-agent/java-bridge.json',
                'usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar']:
            if payload[path]['mode'] != 0o644:
                raise RuntimeError('Exact Root native metadata/code mode required')
        source = self.legacy.reader_json(payload[source_name]['data'])
        meta = self.legacy.reader_json(payload['usr/share/kura-management-agent/native-profile.json']['data'])
        if (payload['usr/share/kura-management-agent/package-v2']['data'] != b'kura-management-agent-v2\n'
                or source.get('schemaVersion') != 2 or source.get('siblingSourceRequired') is not False
                or set(meta) != {'schemaVersion','profile','files'} or type(meta['schemaVersion']) is not int or meta['schemaVersion'] != 1
                or meta['profile'] != 'native-nonroot-v1' or set(meta['files']) != set(NATIVE_FILES)):
            raise RuntimeError('Exact incoming native source and profile required')
        records = {r['path']:r['sha256'] for r in source['sourceFiles']}
        if len(records) != len(source['sourceFiles']): raise RuntimeError('Duplicate incoming native source')
        for path, filename in {**NATIVE_FILES,**self.SOURCE_PAYLOAD}.items():
            row = payload[path.lstrip('/')]
            if (row['mode'] != 0o644 or (path in NATIVE_FILES and row['sha256'] != meta['files'][path])
                    or row['sha256'] != records.get('packaging/'+filename)):
                raise RuntimeError('Incoming native code/unit/source pair differs')
        reader=self.legacy.reader_json(payload['usr/share/kura-management-agent/enrollment-reader.json']['data'])
        reader_paths=['/usr/lib/kura-management-agent/enrollment_reader.py',
            '/usr/lib/systemd/system/kura-management-enrollment-reader.socket',
            '/usr/lib/systemd/system/kura-management-enrollment-reader@.service']
        expected_reader={'schemaVersion':1,'protocolVersion':1,'user':'kurad',
            'socket':'/run/kura-management-enrollment-reader.sock',
            'sourceRoot':'/opt/eclipse/kura/data/management-enrollment',
            'files':{path:meta['files'][path] for path in reader_paths}}
        if (reader!=expected_reader or type(reader.get('schemaVersion')) is not int
                or type(reader.get('protocolVersion')) is not int):
            raise RuntimeError('Incoming Root publisher metadata differs from its code')
        self.incoming_material_pair={
            'publisherPairSha256':self.digest(payload['usr/share/kura-management-agent/enrollment-reader.json']['data']),
            'relayPairSha256':self.digest(payload['usr/share/kura-management-agent/native-profile.json']['data'])}
        pair = {'binarySha256':payload['usr/bin/yofc-management-agent']['sha256'],
                'unitSha256':payload[V2_VENDOR.lstrip('/')]['sha256'], 'sourceManifestSha256':payload[source_name]['sha256']}
        bridge=self.bridge() if original_bridge is None else original_bridge
        incoming_raw=payload['usr/share/kura-management-agent/java-bridge.json']['data']
        self.incoming_bridge=self.bridge_data(incoming_raw,
            payload['usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar']['sha256'])
        if self.incoming_bridge!=bridge:
            if original_bridge is not None:
                raise RuntimeError('Reviewed removal recovery must retain the original Java/Core bridge')
            old=self.legacy.reader_json(self.legacy.reader_file('/usr/share/kura-management-agent/java-bridge.json'))
            new=self.legacy.reader_json(incoming_raw)
            if self.unbound_java_bridge:
                if (old['sha256'] == new['sha256']
                        or not isinstance(new['version'], str)
                        or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\.[A-Za-z0-9_-]+)?', new['version'])
                        or any(old[key] != new[key] for key in old.keys() - {'sha256', 'version'})):
                    raise RuntimeError('Unbound Java bridge update requires the same Core loader and bridge contract')
            else:
                if (not self.uninstalled_core_loader or old==new or
                        {k:v for k,v in old.items() if k!='coreLoaderSha256'}!=
                        {k:v for k,v in new.items() if k!='coreLoaderSha256'}):
                    raise RuntimeError('A Java/Core cohort change requires its separate native maintenance flow')
                self.core_absent()
        elif self.uninstalled_core_loader:
            raise RuntimeError('The uninstalled Core loader action requires an actual loader transition')
        elif self.unbound_java_bridge:
            raise RuntimeError('The unbound Java bridge action requires an actual adapter transition')
        for script in ['preinst','postinst','prerm','postrm']:
            self.authenticate_prerm(control[script]['data'],payload['usr/lib/kura-management-agent/setup.py']['data'],
                payload['usr/lib/kura-management-agent/runtime_setup.py']['data'],source,pair,self.incoming_bridge['coreLoaderSha256'],script)
        self.incoming_postrm = control['postrm']['data']
        import ast
        module = ast.parse(control['prerm']['data'])
        values = [ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id=='PACKAGE_NATIVE_PAIR' for t in n.targets)]
        if values != [pair] or control['prerm']['mode'] != 0o755:
            raise RuntimeError('Incoming native maintainer source pair differs')
        if inspection:
            image=payload['usr/bin/yofc-management-agent']['data']
            if not isinstance(image,bytes) or image[:4]!=b'\x7fELF' or self.digest(image)!=pair['binarySha256']:
                raise RuntimeError('Incoming retained inspector is not its Root-paired native program')
            self.incoming_inspector=image
        return pair, control['prerm']['data']

    def installed_legacy_maintainer_pair(self, binary_sha256, bridge_sha256):
        installed = self.legacy.run(
            ['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\n${Version}\n', 'kura-management-agent'],
            capture_output=True, text=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        fields = installed.stdout.splitlines()
        if (installed.returncode != 0 or len(fields) != 2 or fields[0] != 'installed'
                or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', fields[1])):
            raise RuntimeError('Configured native package version required to authenticate its maintainer')
        return {'version': fields[1], 'binarySha256': binary_sha256, 'bridgeSha256': bridge_sha256}

    def prepare(self, operation, package, expected):
        self.uuid(operation)
        if os.path.lexists(self.legacy.path(self.PENDING)):
            pending=self.json(self.PENDING)
            if pending.get('requestId')!=operation:
                raise RuntimeError('Retain the original native maintenance UUID')
            if pending.get('packageSha256') != expected:
                raise RuntimeError('Original native maintenance package differs')
            return self.status(operation)
        if os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
            if self.json(self.record(operation,'intent.json')).get('packageSha256') != expected:
                raise RuntimeError('Original native maintenance package differs')
            return self.status(operation)
        self.profile.check()
        previous = self.profile.descriptor()
        business=None;reviewed=None
        if self.retained_business:
            if (not self.enrolled_material_kura_peer or not self.material_kura_peer or self.uninstalled_core_loader
                    or getattr(self,'business_initialization',None) is None):
                raise RuntimeError('Retained business requires its explicit original-namespace material source action')
            reviewed=self.candidate(package,expected,inspection=True)
            business={'packagePath':package,'packageSha256':expected,'identity':{**previous,**reviewed[0]},
                      'initializationId':self.business_initialization}
        local_peer=None;local_material=None;retained=None
        if self.enrolled_material_kura_peer and not self.material_kura_peer:
            raise RuntimeError('Retained enrollment requires its explicit material source action')
        if self.local_kura_peer or self.material_kura_peer:
            material=KuraMaterial(self.profile)
            if material.present() and not self.material_kura_peer:
                raise RuntimeError('Material authority requires its separate joint maintenance flow')
            local_peer=KuraPeer(self.profile).check()
            if local_peer is None or self.uninstalled_core_loader:
                raise RuntimeError('An original local Kura grant is required for this joint source action')
            self.profile.stopped('kura.service')
            if self.material_kura_peer:
                local_material=material.check()
                if local_material is None:raise RuntimeError('Original material grant required for material source maintenance')
                material.maintenance_stopped(local_peer,retained=self.enrolled_material_kura_peer)
                if self.enrolled_material_kura_peer:
                    snapshot,retained=self.enrolled_snapshot(local_peer,business=business)
                else:snapshot=self.initial_snapshot(extra_config=['enrollment-relay-grant.json'])
            else:snapshot=self.initial_snapshot()
        else: snapshot=self.snapshot()
        bridge=self.bridge()
        previous_prerm=self.raw(self.PRERM,0o755)
        self.authenticate_prerm(previous_prerm,
            self.legacy.reader_file('/usr/lib/kura-management-agent/setup.py',limit=2*1024*1024),
            self.legacy.reader_file('/usr/lib/kura-management-agent/runtime_setup.py',limit=2*1024*1024),
            self.legacy.reader_json(self.legacy.reader_file('/usr/share/kura-management-agent/source-manifest.json',limit=2*1024*1024)),
            {key:previous[key] for key in self.PINS},bridge['coreLoaderSha256'],
            historical_legacy_pair=lambda: self.installed_legacy_maintainer_pair(
                previous['binarySha256'], bridge['jarSha256']))
        pair, prerm = reviewed if reviewed is not None else self.candidate(package, expected)
        incoming_bridge=getattr(self,'incoming_bridge',bridge)
        if all(previous[key] == pair[key] for key in self.PINS):
            raise RuntimeError('The same native source cohort is not a new update')
        folder = self.record(operation,'intent.json').rsplit('/',1)[0]
        if os.path.lexists(self.legacy.path(folder)):
            return self.status(operation)
        original = self.json(V2_ADMIN + '/initialization.json')
        ticket = {'schemaVersion':1,'requestId':operation,'initializationId':original['operationId'],
            'initializationReceiptSha256':self.digest(self.raw(V2_ADMIN+'/initialization.json')),
            'previousIdentity':previous,'identity':{**previous,**pair},'previousPair':self.optional(self.CURRENT),
            'packageSha256':expected,'packageVersion':self.incoming_version,'state':snapshot,'bridge':bridge,
            'previousPrermSha256':self.digest(previous_prerm),
            'prermSha256':self.digest(prerm)}
        if retained is not None:ticket['retainedEnrollment']=retained
        if incoming_bridge!=bridge:
            if self.unbound_java_bridge:
                if local_peer is not None or business is not None or self.uninstalled_core_loader:
                    raise RuntimeError('Java bridge maintenance requires the unbound native profile')
                ticket['javaBridgeTransition'] = {'previous': bridge, 'incoming': incoming_bridge,
                                                  'core': self.stopped_bridge_core(bridge['coreLoaderSha256'])}
                self.java_bridge_transition(ticket)
            else:
                ticket['loaderTransition']={'previous':bridge,'incoming':incoming_bridge}
                self.loader_transition(ticket)
        if local_peer is not None:
            self.bind_authorities(ticket,local_peer,local_material)
        if business is not None:
            ticket['retainedBusiness']={'schemaVersion':1,'profile':RetainedBusiness.PROFILE,
                'packagePath':package,'programSha256':pair['binarySha256'],'report':business['report']}
            RetainedBusiness.bundle(ticket['retainedBusiness'],ticket)
        # Publish the global original intent before creating any per-operation
        # record. Every interruption blocks a new ID as well as startup.
        with self.package_locks():
            self.profile.check()
            if 'loaderTransition' in ticket: self.core_absent()
            if 'javaBridgeTransition' in ticket: self.verify_bridge_core(ticket)
            if (self.profile.descriptor()!=previous or self.ticket_snapshot(ticket)!=snapshot
                    or self.optional(self.CURRENT)!=ticket['previousPair']
                    or self.raw(self.PRERM,0o755)!=previous_prerm or self.bridge()!=bridge):
                raise RuntimeError('Native source changed before package-manager admission')
            self.immutable(self.PENDING,self.profile.encode(ticket))
            self.profile.directory(self.RECORDS,0,0,0o700,True)
            self.profile.directory(folder,0,0,0o700,True)
            self.immutable(self.record(operation,'previous.prerm'),previous_prerm)
            self.immutable(self.record(operation,'incoming.prerm'),prerm)
            self.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
            self.install_mask()
            # Exact previous code is retained. This reviewed bootstrap is necessary
            # for the first candidate whose old prerm refused every retained profile.
            self.replace(self.PRERM,prerm,0o755)
        return self.status(operation)

    def admit(self, expected, target_version=None):
        ticket = self.json(self.PENDING); self.uuid(ticket['requestId'])
        if 'companionTransition' in ticket:
            raise RuntimeError('Original companion maintenance does not authorize changes to the Native Agent package')
        if 'retainedBusiness' in ticket:self.namespace(ticket['initializationId'])
        if 'loaderTransition' in ticket:
            self.loader_transition(ticket); self.core_absent()
        if 'javaBridgeTransition' in ticket:
            self.verify_bridge_core(ticket)
        if ticket['schemaVersion'] != 1 or {key:ticket['identity'][key] for key in self.PINS} != expected:
            raise RuntimeError('Incoming native source maintenance pair differs')
        if target_version is not None and ticket['packageVersion']!=target_version:
            raise RuntimeError('Incoming native package version differs from original maintenance')
        actual = self.legacy.reader_json(self.raw(V2_IDENTITY,0o644))
        self.verify_mask()
        if (actual != ticket['previousIdentity'] or self.profile.descriptor() != actual
                  or self.ticket_snapshot(ticket) != ticket['state'] or self.optional(self.CURRENT) != ticket['previousPair']
                or self.bridge()!=ticket['bridge']
                or self.digest(self.raw(self.PRERM,0o755)) != ticket['prermSha256']):
            raise RuntimeError('Original native source maintenance input changed')
        if ticket!=self.json(self.record(ticket['requestId'],'intent.json')):
            raise RuntimeError('Original native source intent differs before package admission')
        self.immutable(self.record(ticket['requestId'],'admitted.json'),self.profile.encode({
            'schemaVersion':1,'requestId':ticket['requestId'],'incomingPair':expected}))
        return ticket

    def finish(self, expected):
        ticket = self.json(self.PENDING); operation = self.uuid(ticket['requestId'])
        if 'companionTransition' in ticket:
            raise RuntimeError('Complete the original companion maintenance through the Root setup command')
        if 'retainedBusiness' in ticket:self.namespace(ticket['initializationId'])
        if ticket!=self.json(self.record(operation,'intent.json')):
            raise RuntimeError('Original native source intent differs from its pending publication')
        descriptor = self.profile.descriptor()
        incoming_bridge=ticket['bridge']
        if 'loaderTransition' in ticket:
            _,incoming_bridge=self.loader_transition(ticket); self.core_absent()
        if 'javaBridgeTransition' in ticket:
            incoming_bridge = self.verify_bridge_core(ticket)
        if ({key:descriptor[key] for key in self.PINS} != expected or descriptor != ticket['identity']
                or self.ticket_snapshot(ticket,publishing=True) != ticket['state'] or self.bridge()!=incoming_bridge
                or self.optional(self.record(operation,'admitted.json'))!=
                   {'schemaVersion':1,'requestId':operation,'incomingPair':expected}):
            raise RuntimeError('Native source update cannot publish changed authority or state')
        return self.publish_source_result(ticket, descriptor)

    def source_result(self, ticket, descriptor):
        result = {'schemaVersion':1,'requestId':ticket['requestId'],'initializationId':ticket['initializationId'],
            'initializationReceiptSha256':ticket['initializationReceiptSha256'],'previousPair':ticket['previousPair'],
            'previousIdentity':ticket['previousIdentity'],'identity':descriptor,'packageSha256':ticket['packageSha256'],
            'stateFingerprintSha256':self.digest(self.profile.encode(ticket['state']).encode()),'unitStarted':False}
        for key in ('loaderTransition','javaBridgeTransition','peerTransition','materialTransition','retainedEnrollment',
                    'retainedBusiness','companionTransition'):
            if key in ticket:
                result[key]=ticket[key]
        return result

    def publish_source_result(self, ticket, descriptor):
        operation=ticket['requestId']
        result=self.source_result(ticket,descriptor)
        current = self.legacy.reader_json(self.raw(V2_IDENTITY,0o644))
        if current not in [ticket['previousIdentity'],descriptor]: raise RuntimeError('Native public identity drift')
        if current!=descriptor: self.replace(V2_IDENTITY,self.profile.encode(descriptor).encode(),0o644)
        raw = self.profile.encode(result).encode(); self.immutable(self.record(operation,'result.json'),raw)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.digest(raw)}
        if self.optional(self.CURRENT) not in [ticket['previousPair'],pointer]:
            raise RuntimeError('Original native source-pair pointer changed')
        if self.optional(self.CURRENT)!=pointer:
            self.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600,
                         resume_companion='companionTransition' in ticket)
        if 'peerTransition' in ticket:
            incoming=ticket['peerTransition']['incoming']
            if self.optional(KuraPeer.PUBLIC,0o644)!=incoming:
                self.replace(KuraPeer.PUBLIC,self.profile.encode(incoming).encode(),0o644,
                             resume_companion='companionTransition' in ticket)
        if 'materialTransition' in ticket:
            incoming=ticket['materialTransition']['incoming'];material=KuraMaterial(self.profile)
            private=material.private_bytes(incoming)
            if self.raw(material.RELAY)!=private:self.replace(material.RELAY,private,0o600)
            if self.optional(material.PUBLIC,0o644)!=incoming:
                self.replace(material.PUBLIC,self.profile.encode(incoming).encode(),0o644)
        if 'companionTransition' not in ticket:
            self.remove_mask()
        self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check()
        return self.status(operation)

    def complete(self, operation):
        self.uuid(operation)
        if not os.path.lexists(self.legacy.path(self.PENDING)):return self.status(operation)
        ticket=self.json(self.PENDING)
        if ticket.get('requestId')!=operation:raise RuntimeError('Preserve original native source maintenance UUID')
        with self.package_locks():
            if 'companionTransition' in ticket:
                return KuraCompanionUpdate(self).complete(ticket)
            return self.finish({key:ticket['identity'][key] for key in self.PINS})

    def status(self, operation):
        self.uuid(operation)
        pending = self.optional(self.PENDING)
        if pending is not None:
            if pending['requestId'] != operation: raise RuntimeError('Retain the original native maintenance UUID')
            return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
        value = self.json(self.record(operation,'result.json'))
        if value['requestId'] != operation: raise RuntimeError('Original native source result differs')
        pointer=self.json(self.CURRENT)
        current=self.json(self.record(self.uuid(pointer['requestId']),'result.json'))
        seen=self.verify_chain(self.json(V2_ADMIN+'/initialization.json'),current['identity'])
        if operation not in seen:
            raise RuntimeError('Original native source result lacks its published chain proof')
        return {'schemaVersion':1,'requestId':operation,'state':'APPLIED','unitStarted':False,'replayed':False}


class KuraPeer:
    """Original local bridge authorization; no credentials or remote capability."""
    PUBLIC=V2_PUBLIC+'/kura-peer.json'
    CURRENT=V2_ADMIN+'/kura-peer-current.json'
    PENDING=V2_ADMIN+'/.kura-peer-pending.json'
    RECORDS=V2_ADMIN+'/kura-peers'
    ENV=V2_CONFIG+'/agent.env'
    CORE_UNIT='/usr/lib/systemd/system/kura.service'
    NETWORKING_DROP_IN='/usr/lib/systemd/system/kura.service.d/kura-networking.conf'
    NETWORKING_TEMPLATE='/opt/eclipse/kura/libexec/addons/networking/kura-networking.conf'
    LEGACY_NETWORKING_DROP_IN_SHA256='eb1079ba9bc662b196ef873cfc860cc1b53ab3b50813c2ee4437352c4cd65b18'
    NETWORKING_DROP_IN_SHA256='06589b8dede5926f63d760ec0a94a51aa6ef6ce6ddffee1c78dfcf978ec30473'

    def __init__(self, profile):
        self.profile,self.legacy=profile,profile.legacy
        self.source=SourceUpdate(profile)

    def record(self, operation, name):
        return self.RECORDS+'/'+self.source.uuid(operation)+'/'+name

    def no_orphan(self):
        root=self.legacy.path(self.RECORDS)
        if not os.path.lexists(root): return
        self.profile.directory(self.RECORDS,0,0,0o700)
        pending=self.source.optional(self.PENDING)
        for folder in root.iterdir():
            operation=self.source.uuid(folder.name)
            self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700)
            if (not os.path.lexists(folder/'published.json')
                    and (pending is None or pending.get('requestId')!=operation)):
                raise RuntimeError('Lost original Kura peer authorization marker')
        if pending is None and not os.path.lexists(self.legacy.path(self.CURRENT)):
            raise RuntimeError('Lost original Kura peer authorization pointer')

    def members(self, expected_gid=None):
        group=grp.getgrnam('kura-management')
        if expected_gid is None:
            expected_gid = self.profile.descriptor()['gid']
        if group.gr_gid != expected_gid:
            raise RuntimeError('Native Kura control group changed')
        return sorted(group.gr_mem)

    def networking_drop_in(self, core_sha, core_home):
        # The installed networking package copies this reviewed template into
        # systemd's vendor hierarchy. The copy may preserve existing caps.
        named='kura-networking: '+self.NETWORKING_TEMPLATE
        for query,expected in [
                (['-W','-f=${db:Status-Status}','kura-networking'],'installed'),
                (['-S',self.NETWORKING_TEMPLATE],named)]:
            result=self.legacy.run(['/usr/bin/dpkg-query',*query],capture_output=True,text=True,
                                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            if result.returncode!=0 or result.stdout.strip()!=expected:
                raise RuntimeError('Configured Networking package does not own the reviewed Core drop-in template')
        if core_home is None:
            raise RuntimeError('Installed Core loader required for Networking package pairing')
        template='/'+str((core_home/'libexec/addons/networking/kura-networking.conf').relative_to(self.legacy.root))
        # The installed source template can use the protected Core code group.
        # The systemd vendor copy continues to require exactly Root:Root 0644.
        try:
            code_group = grp.getgrnam('kura-key-control').gr_gid
        except KeyError:
            code_group = 0
        template_layout = (code_group, 0o640) if code_group > 0 else None
        template_sha = self.profile.asset(template, maximum=4096, alternate_layout=template_layout)
        if (template_sha not in (self.LEGACY_NETWORKING_DROP_IN_SHA256, self.NETWORKING_DROP_IN_SHA256)
                or self.profile.asset(self.NETWORKING_DROP_IN, maximum=4096) != template_sha):
            raise RuntimeError('Core Networking drop-in differs from its reviewed package template')
        core=self.legacy.reader_file(self.CORE_UNIT)
        if self.source.digest(core)!=core_sha:
            raise RuntimeError('Core unit changed during Networking drop-in review')
        names=('AmbientCapabilities','CapabilityBoundingSet')
        declared={}
        for name in names:
            values=re.findall(r'^'+name+r'=([a-z0-9_ ]+)$',core.decode(),re.MULTILINE)
            if len(values)!=1:
                raise RuntimeError('Core capability scope cannot be paired with Networking')
            declared[name]=set(values[0].split())
        result=self.legacy.systemctl('show','kura.service','--property=NeedDaemonReload,AmbientCapabilities,CapabilityBoundingSet')
        fields={} if result is None else dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        legacy_caps={'cap_net_admin','cap_net_raw'} if template_sha == self.LEGACY_NETWORKING_DROP_IN_SHA256 else set()
        if (set(fields)!={'NeedDaemonReload',*names} or fields['NeedDaemonReload']!='no'
                or not legacy_caps<=declared['AmbientCapabilities']
                or any(set(fields[name].split())!=declared[name] for name in names)):
            raise RuntimeError('Effective Core capability scope changed with Networking')
        return template_sha

    def core(self, descriptor=None, bridge=None):
        if descriptor is None:
            descriptor = self.profile.descriptor()
        account=pwd.getpwnam('kurad');group=grp.getgrnam('kurad')
        if (account.pw_name!='kurad' or not 0<account.pw_uid<4294967295
                or account.pw_uid==descriptor['uid']
                or account.pw_gid!=group.gr_gid or not 0<group.gr_gid<4294967295
                or group.gr_gid in [descriptor['gid'],descriptor['readerGid']]
                or account.pw_shell not in ['/sbin/nologin','/usr/sbin/nologin']
                or any(p.pw_uid==account.pw_uid and p.pw_name!='kurad' for p in pwd.getpwall())):
            raise RuntimeError('Exact separate packaged Kura identity required')
        result=self.legacy.run(['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}','kura-core'],
                               capture_output=True,text=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if result.returncode!=0 or result.stdout.strip()!='installed':
            raise RuntimeError('Configured Core required for local peer authorization')
        result=self.legacy.systemctl('show','kura.service','--property=LoadState,FragmentPath,DropInPaths,User,Group')
        fields={} if result is None else dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        drop_in=fields.pop('DropInPaths',None)
        if (fields!={'LoadState':'loaded','FragmentPath':self.CORE_UNIT,'User':'kurad','Group':'kurad'}
                or drop_in not in ('',self.NETWORKING_DROP_IN)
                or bool(drop_in)!=os.path.lexists(self.legacy.path(self.NETWORKING_DROP_IN))):
            raise RuntimeError('Unreviewed effective Core unit; preserve its configuration')
        core_sha=self.profile.asset(self.CORE_UNIT,maximum=65536)
        if bridge is None:
            bridge = self.source.bridge()
        core_home=self.legacy.guard_core_loader(bridge['coreLoaderSha256'])
        networking=({'coreNetworkingDropInSha256':self.networking_drop_in(core_sha,core_home)} if drop_in else {})
        return {'kuraUid':account.pw_uid,'kuraGid':group.gr_gid,
                'coreUnitSha256':core_sha,**networking,
                'coreLoaderSha256':bridge['coreLoaderSha256'],
                'javaBridgeMetadataSha256':bridge['metadataSha256']}

    def peer(self, operation, initialization):
        core=self.core()
        paired='coreNetworkingDropInSha256' in core
        return {'schemaVersion':2 if paired else 1,'profile':'local-kura-v2' if paired else 'local-kura-v1','requestId':operation,
                'initializationId':initialization,'nativeIdentitySha256':self.source.digest(self.source.raw(V2_IDENTITY,0o644)),
                'controlGid':self.profile.descriptor()['gid'],**core}

    def original(self):
        pointer=self.source.optional(self.CURRENT)
        if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
            raise RuntimeError('Original Kura peer authorization proof is missing')
        operation=self.source.uuid(pointer['requestId'])
        raw=self.source.raw(self.record(operation,'result.json'))
        result=self.legacy.reader_json(raw)
        published=self.source.json(self.record(operation,'published.json'))
        initial=self.source.json(V2_ADMIN+'/initialization.json')
        if (self.source.digest(raw)!=pointer['sha256'] or set(result)!={'schemaVersion','requestId',
                'initializationId','initializationReceiptSha256','peer','stateFingerprintSha256','envSha256','unitStarted'}
                or type(result['schemaVersion']) is not int or result['schemaVersion']!=1
                or result['requestId']!=operation or result['initializationId']!=initial['operationId']
                or result['initializationReceiptSha256']!=self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json'))
                or published!={'schemaVersion':1,'requestId':operation,'resultSha256':self.source.digest(raw),
                              'publicSha256':self.source.digest(self.profile.encode(result['peer']).encode())}
                or result['unitStarted'] is not False):
            raise RuntimeError('Kura peer authority differs from its original Root proof')
        return result,self.source.digest(raw)

    def check(self):
        public=self.source.optional(self.PUBLIC,0o644)
        if public is None and self.source.optional(self.CURRENT) is None: return None
        original,authorization_sha=self.original()
        expected=self.peer(original['requestId'],original['initializationId'])
        effective=self.source.current_peer(original['peer'],authorization_sha)
        if (not isinstance(public,dict)
                or any(type(public.get(k)) is not int for k in ['schemaVersion','controlGid','kuraUid','kuraGid'])
                or public!=expected or effective!=expected or self.members()!=['kurad']
                or KuraRemoteSwitch(self.profile).expected_env_sha(original)!=self.source.digest(self.source.raw(self.ENV))):
            raise RuntimeError('Kura peer authority differs from its original Root proof')
        return expected

    def status(self, operation):
        self.source.uuid(operation)
        pending=self.source.optional(self.PENDING)
        if pending is not None:
            if pending.get('requestId')!=operation:
                raise RuntimeError('Preserve the original Kura peer authorization UUID')
            return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
        result=self.legacy.path(self.record(operation,'published.json'))
        if not os.path.lexists(result):
            if os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
                return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
            self.no_orphan()
            return {'schemaVersion':1,'requestId':operation,'state':'NOT_FOUND','replayed':False}
        raw=self.source.raw(self.record(operation,'result.json'))
        published=self.source.json(self.record(operation,'published.json'))
        value=self.legacy.reader_json(raw)
        if (set(published)!={'schemaVersion','requestId','resultSha256','publicSha256'}
                or type(published['schemaVersion']) is not int or published['schemaVersion']!=1
                or published['requestId']!=operation or published['resultSha256']!=self.source.digest(raw)
                or not isinstance(published['publicSha256'],str)
                or not re.fullmatch('[0-9a-f]{64}',published['publicSha256'])
                or value.get('requestId')!=operation or value.get('unitStarted') is not False):
            raise RuntimeError('Original Kura peer authorization is not published')
        try:
            self.no_orphan()
            self.profile.check()
            peer=self.check();ready='READY' if peer is not None else 'REFUSED'
        except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError): ready='REFUSED'
        return {'schemaVersion':1,'requestId':operation,'state':'APPLIED','unitStarted':False,
                'kuraUid':value['peer']['kuraUid'],'currentReadiness':ready,'remoteEnabled':False,'replayed':False}

    def stopped(self):
        self.profile.stopped('kura.service')
        self.profile.stopped(V2_UNIT)

    def authorize(self, operation):
        self.source.uuid(operation)
        if (os.path.lexists(self.legacy.path(self.PENDING))
                or os.path.lexists(self.legacy.path(self.record(operation,'intent.json')))):
            return self.status(operation)
        self.profile.check();self.stopped()
        if self.check() is not None or self.members()!=[]:
            raise RuntimeError('Existing control-group authority requires its original migration')
        with self.source.package_locks():
            self.profile.check();self.stopped()
            initial=self.source.json(V2_ADMIN+'/initialization.json')
            peer=self.peer(operation,initial['operationId']);state=self.source.initial_snapshot()
            old=self.source.raw(self.ENV)
            needle=b'AGENT_KURA_UID=4294967295\n'
            if old.count(needle)!=1: raise RuntimeError('Original unbound native environment required')
            incoming=old.replace(needle,('AGENT_KURA_UID='+str(peer['kuraUid'])+'\n').encode(),1)
            ticket={'schemaVersion':1,'requestId':operation,'peer':peer,'state':state,
                    'initializationReceiptSha256':self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json')),
                    'previousEnvSha256':self.source.digest(old),'incomingEnvSha256':self.source.digest(incoming)}
            self.source.immutable(self.PENDING,self.profile.encode(ticket))
            self.profile.directory(self.RECORDS,0,0,0o700,True)
            self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
            self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
            self.source.immutable(self.record(operation,'previous.env'),old)
            self.source.immutable(self.record(operation,'incoming.env'),incoming)
            if self.members()!=[]: raise RuntimeError('Original native control group changed before dispatch')
            self.source.immutable(self.record(operation,'group-dispatch.json'),self.profile.encode({
                'schemaVersion':1,'requestId':operation,'user':'kurad','group':'kura-management'}))
            # Exactly one dispatch. A lost reply is reconciled by observing the
            # fixed group; complete() never invokes this command again.
            self.legacy.run(['/usr/bin/gpasswd','--add','kurad','kura-management'],check=True,capture_output=True,text=True)
            return self.finish(ticket)

    def complete(self, operation):
        self.source.uuid(operation)
        if not os.path.lexists(self.legacy.path(self.PENDING)): return self.status(operation)
        ticket=self.source.json(self.PENDING)
        if ticket.get('requestId')!=operation: raise RuntimeError('Preserve the original Kura peer authorization UUID')
        with self.source.package_locks(): return self.finish(ticket)

    def finish(self, ticket):
        operation=self.source.uuid(ticket['requestId']);self.stopped()
        initial=self.source.json(V2_ADMIN+'/initialization.json')
        if (ticket!=self.source.json(self.record(operation,'intent.json'))
                or ticket['peer']!=self.peer(operation,initial['operationId'])
                or ticket['initializationReceiptSha256']!=self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json'))
                or self.members()!=['kurad']
                or self.source.json(self.record(operation,'group-dispatch.json'))!=
                    {'schemaVersion':1,'requestId':operation,'user':'kurad','group':'kura-management'}):
            raise RuntimeError('Original Kura authorization outcome is unresolved; do not redispatch')
        old=self.source.raw(self.record(operation,'previous.env'));incoming=self.source.raw(self.record(operation,'incoming.env'))
        if (self.source.digest(old)!=ticket['previousEnvSha256']
                or self.source.digest(incoming)!=ticket['incomingEnvSha256']
                or self.source.raw(self.ENV) not in [old,incoming]):
            raise RuntimeError('Original Kura authorization environment differs')
        state=self.source.initial_snapshot();without_env=lambda v:{k:x for k,x in v.items() if k!=self.ENV}
        if without_env(state)!=without_env(ticket['state']):
            raise RuntimeError('Original native state changed during Kura authorization')
        if self.source.raw(self.ENV)!=incoming: self.source.replace(self.ENV,incoming,0o600)
        result={'schemaVersion':1,'requestId':operation,'initializationId':initial['operationId'],
                'initializationReceiptSha256':ticket['initializationReceiptSha256'],'peer':ticket['peer'],
                'stateFingerprintSha256':self.source.digest(self.profile.encode(without_env(ticket['state'])).encode()),
                'envSha256':ticket['incomingEnvSha256'],'unitStarted':False}
        raw=self.profile.encode(result).encode();self.source.immutable(self.record(operation,'result.json'),raw)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.source.digest(raw)}
        if self.source.optional(self.CURRENT) not in [None,pointer]: raise RuntimeError('Kura peer pointer changed')
        if self.source.optional(self.CURRENT) is None:
            self.source.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600)
        self.source.immutable(self.PUBLIC,self.profile.encode(ticket['peer']),0o644)
        self.source.immutable(self.record(operation,'published.json'),self.profile.encode({
            'schemaVersion':1,'requestId':operation,'resultSha256':self.source.digest(raw),
            'publicSha256':self.source.digest(self.source.raw(self.PUBLIC,0o644))}))
        self.check()
        self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check()
        return self.status(operation)


class KuraCompanionUpdate:
    """Move an existing local peer to the explicitly reviewed companion releases."""

    PACKAGES = ('kura-core', 'kura-networking')
    MAIN = r'opt/eclipse/kura_[A-Za-z0-9.+~_-]+_linux/install/kura\.service'
    LOADER = r'opt/eclipse/kura_[A-Za-z0-9.+~_-]+_linux/bin/gen_config_ini\.sh'
    CONTROLS = ('preinst', 'postinst', 'prerm', 'postrm')
    KEY = '/etc/kura/credentials/kura_encryption_key'
    ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}

    def __init__(self, source):
        self.source, self.profile, self.legacy = source, source.profile, source.legacy

    def root(self):
        system = self.legacy.root.stat()
        boot = SourceUpdate.uuid(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        return dict(device=system.st_dev, inode=system.st_ino, boot=boot)

    @staticmethod
    def hash(value):
        return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None

    def transition(self, value, previous, incoming):
        proof=value['companionTransition']
        required={'packages','root','keySha256'}
        if (not isinstance(proof,dict) or proof.keys() not in (required,required | {'material'})
                or value['identity']!=value['previousIdentity']
                or 'materialTransition' in value or previous['schemaVersion']!=2
                or previous.get('coreNetworkingDropInSha256')!=KuraPeer.LEGACY_NETWORKING_DROP_IN_SHA256
                or incoming.get('coreNetworkingDropInSha256')!=KuraPeer.NETWORKING_DROP_IN_SHA256
                or not self.hash(previous.get('coreUnitSha256')) or not self.hash(incoming.get('coreUnitSha256'))
                or previous['coreUnitSha256']==incoming['coreUnitSha256']
                or not self.hash(proof['keySha256'])):
            raise RuntimeError('Invalid original Core and Networking peer transition')
        if 'material' in proof:
            material=proof['material']
            digests={'authorizationResultSha256','publicSha256','relayGrantSha256'}
            if (not isinstance(material,dict) or material.keys()!=digests | {'requestId'}
                    or any(not self.hash(material[key]) for key in digests)):
                raise RuntimeError('Invalid retained companion material proof')
            SourceUpdate.uuid(material['requestId'])
        root=proof['root']
        if (not isinstance(root,dict) or root.keys()!={'device','inode','boot'}
                or any(type(root[k]) is not int or root[k]<=0 for k in ('device','inode'))):
            raise RuntimeError('Invalid original companion maintenance Root')
        SourceUpdate.uuid(root['boot'])
        packages=proof['packages']
        if not isinstance(packages,dict) or packages.keys()!=set(self.PACKAGES):
            raise RuntimeError('Both original companion package pins are required')
        for pin in packages.values():
            if (not isinstance(pin,dict) or pin.keys()!={'sha256','previousVersion','version','controls'}
                    or not self.hash(pin['sha256'])
                    or any(not isinstance(pin[k],str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*',pin[k])
                           for k in ('previousVersion','version'))
                    or pin['previousVersion']==pin['version']
                    or not isinstance(pin['controls'],dict) or pin['controls'].keys()!=set(self.CONTROLS)
                    or any(not self.hash(digest) for digest in pin['controls'].values())):
                raise RuntimeError('Invalid original companion package pins')
        if value['packageSha256']!=self.source.digest(self.profile.encode(packages).encode()):
            raise RuntimeError('Original companion package set digest differs')
        return proof

    def command(self, *args):
        result=self.legacy.run(list(args),capture_output=True,text=True,env=self.ENV,timeout=15,check=True)
        return result.stdout.strip()

    def installed_version(self, package):
        version,state,error=self.command('/usr/bin/dpkg-query','-W',
            '-f=${Version} ${db:Status-Status} ${db:Status-Eflag}',package).split()
        if (state,error)!=('installed','ok'):
            raise RuntimeError('Configured companion package required: '+package)
        return version

    def members(self, path, patterns, *, control=False):
        process=subprocess.Popen(['/usr/bin/dpkg-deb','--ctrl-tarfile' if control else '--fsys-tarfile',str(path)],
                                 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=self.ENV)
        timer=threading.Timer(45,process.kill)
        timer.daemon=True
        timer.start()
        found={}
        try:
            total=0
            with tarfile.open(fileobj=process.stdout,mode='r|') as archive:
                for member in archive:
                    total+=member.size
                    if total>512*1024*1024:
                        raise RuntimeError('Oversized companion package')
                    name=member.name.removeprefix('./')
                    for key,pattern in patterns.items():
                        if re.fullmatch(pattern,name):
                            if (key in found or not member.isfile() or member.uid!=0 or member.gid!=0
                                    or member.mode & 0o7022 or not 0<member.size<=2*1024*1024):
                                raise RuntimeError('Unsafe or duplicate companion package member')
                            found[key]=archive.extractfile(member).read()
                for chunk in iter(lambda: archive.fileobj.read(8192),b''):
                    if chunk.strip(b'\0'):
                        raise RuntimeError('Unexpected data after the companion archive')
            if process.wait(timeout=4) or found.keys()!=patterns.keys():
                raise RuntimeError('Incomplete companion package input')
        finally:
            timer.cancel()
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
        return found

    def candidate(self, package, path, expected):
        if not self.hash(expected) or self.profile.asset(path,0o600,320*1024*1024)!=expected:
            raise RuntimeError('Reviewed companion package checksum differs')
        archive=self.legacy.path(path)
        name,version,architecture=self.command('/usr/bin/dpkg-deb','-W',
            '--showformat=${Package} ${Version} ${Architecture}',str(archive)).split()
        arch=self.command('/usr/bin/dpkg','--print-architecture') if package=='kura-core' else 'all'
        previous=self.installed_version(package)
        if name!=package or architecture!=arch:
            raise RuntimeError('Wrong companion package identity or architecture')
        self.command('/usr/bin/dpkg','--compare-versions',version,'gt',previous)
        controls=self.members(archive,{key:key for key in self.CONTROLS},control=True)
        patterns={'unit':self.MAIN,'loader':self.LOADER} if package=='kura-core' else {
            'unit':re.escape(KuraPeer.NETWORKING_TEMPLATE.removeprefix('/'))}
        files=self.members(archive,patterns)
        if self.profile.asset(path,0o600,320*1024*1024)!=expected:
            raise RuntimeError('Reviewed companion package changed during inspection')
        return dict(sha256=expected,previousVersion=previous,version=version,
                    controls={key:self.source.digest(raw) for key,raw in controls.items()}),files

    @staticmethod
    def capabilities(raw):
        section=''
        values={}
        for line in raw.decode('utf-8').splitlines():
            line=line.strip()
            if line.startswith('['):
                section=line
            elif section=='[Service]' and line and not line.startswith(('#',';')):
                key,separator,value=line.partition('=')
                if separator:
                    values.setdefault(key,[]).append(value)
        for key,value in {'User':'kurad','Group':'kurad','NoNewPrivileges':'yes',
                'ExecStart':'/bin/sh /opt/eclipse/kura/bin/start_kura_background.sh'}.items():
            if values.get(key)!=[value]:
                raise RuntimeError('Reviewed companion Core requires its exact non-Root Main contract')
        caps=[]
        for key in ('AmbientCapabilities','CapabilityBoundingSet'):
            assignment=values.get(key,[])
            if len(assignment)!=1:
                raise RuntimeError('Reviewed companion capability declaration is ambiguous')
            names=set(assignment[0].split())
            if not all(re.fullmatch('cap_[a-z0-9_]+',name) for name in names):
                raise RuntimeError('Reviewed companion has an invalid capability declaration')
            caps.append(names)
        if not caps[0]<=caps[1]:
            raise RuntimeError('Reviewed companion ambient scope exceeds its bounding set')
        return caps

    def pin_material(self, material, local, operation):
        if operation is None:
            if material.present():
                raise RuntimeError('Name the existing material authorization for companion maintenance')
            return None
        source=self.source
        source.uuid(operation)
        original,result_sha=material.original()
        if original['requestId']!=operation:
            raise RuntimeError('Preserve the original material authorization UUID')
        material.maintenance_stopped(local)
        public=source.raw(material.PUBLIC,0o644)
        private=source.raw(material.RELAY)
        return dict(requestId=operation,authorizationResultSha256=result_sha,
                    publicSha256=source.digest(public),relayGrantSha256=source.digest(private))

    def snapshot(self, proof, local, previous_pair):
        source=self.source
        material=KuraMaterial(self.profile)
        if 'material' not in proof:
            self.pin_material(material,local,None)
            return source.initial_snapshot()
        bound=proof['material']
        operation=bound['requestId']
        if self.pin_material(material,local,operation)!=bound:
            raise RuntimeError('Original companion material authority changed')
        original,result_sha=material.original()
        context,private=material.context(operation,local)
        source.material_history(original,result_sha,context,previous_pair)
        if (source.raw(material.PUBLIC,0o644)!=self.profile.encode(context).encode()
                or source.raw(material.RELAY)!=private):
            raise RuntimeError('Installed companion context differs from retained material authority')
        records=[material.record(operation,name) for name in ('intent.json','result.json','published.json','relay-grant.json')]
        paths=[material.PUBLIC,material.RELAY,material.CURRENT,*records]
        return source.initial_snapshot(extra_config=['enrollment-relay-grant.json'],
                                       extra_assets=[self.legacy.path(path) for path in paths])

    def prepare(self, initialization, operation, core, networking, material_authorization=None):
        source=self.source
        source.uuid(operation)
        with source.package_locks():
            pending=source.optional(source.PENDING)
            if pending is not None:
                companion=pending.get('companionTransition',{})
                pins=companion.get('packages',{})
                if (pending.get('requestId')!=operation or not pins
                        or companion.get('material',{}).get('requestId')!=material_authorization
                        or [pins.get(name,{}).get('sha256') for name in self.PACKAGES]!=[core[1],networking[1]]):
                    raise RuntimeError('Retain the original companion maintenance UUID and archives')
                source.peer_transition(pending)
                if self.root()!=pending['companionTransition']['root']:
                    raise RuntimeError('Companion maintenance belongs to a different Root or boot')
                if source.optional(source.record(operation,'intent.json')) is None:
                    if source.ticket_snapshot(pending)!=pending['state']:
                        raise RuntimeError('Original companion maintenance input changed')
                    self.persist_intent(pending)
                return source.status(operation)
            original=source.optional(source.record(operation,'intent.json'))
            if original is not None:
                companion=original.get('companionTransition',{})
                pins=companion.get('packages',{})
                if (companion.get('material',{}).get('requestId')!=material_authorization
                        or [pins.get(name,{}).get('sha256') for name in self.PACKAGES]!=[core[1],networking[1]]):
                    raise RuntimeError('Original companion maintenance archives differ')
                return source.status(operation)
            identity=self.profile.check()
            if any(auth is not None for auth in (KuraRemoteSwitch(self.profile).check(),
                    NativeTransport(self.profile).check())) or self.profile.configuration_write(initialization):
                raise RuntimeError('Existing optional authority needs its separate joint maintenance')
            peer=KuraPeer(self.profile)
            peer.stopped()
            for name in (source.CURRENT,peer.PUBLIC):
                path=self.legacy.path(name)
                if os.path.lexists(path.with_name('.'+path.name+'.source-update-new')):
                    raise RuntimeError('Resolve existing source publication staging before companion maintenance')
            local=peer.check()
            if local is None or local.get('coreNetworkingDropInSha256')!=peer.LEGACY_NETWORKING_DROP_IN_SHA256:
                raise RuntimeError('Original reviewed Networking Kura peer is required')
            material=self.pin_material(KuraMaterial(self.profile),local,material_authorization)
            packages={}
            packages['kura-core'],files=self.candidate('kura-core',*core)
            packages['kura-networking'],network=self.candidate('kura-networking',*networking)
            unit=files['unit']
            caps=self.capabilities(unit)
            prior_caps=self.capabilities(source.raw(peer.CORE_UNIT,0o644))
            if (not all(candidate<=old for candidate,old in zip(caps,prior_caps))
                    or any('cap_net_raw' in scope for scope in caps)
                    or source.digest(files['loader'])!=local['coreLoaderSha256']
                    or source.digest(network['unit'])!=peer.NETWORKING_DROP_IN_SHA256):
                raise RuntimeError('Companion transition cannot expand Main scope or change the original adapter')
            proof=dict(packages=packages,root=self.root(),keySha256=self.profile.asset(self.KEY,0o400,32))
            if material is not None:
                proof['material']=material
            raw=source.raw(V2_ADMIN+'/initialization.json')
            _,original_sha=peer.original()
            ticket=dict(schemaVersion=1,requestId=operation,initializationId=initialization,
                initializationReceiptSha256=source.digest(raw),previousIdentity=identity,identity=identity,
                previousPair=source.optional(source.CURRENT),bridge=source.bridge(),
                packageSha256=source.digest(self.profile.encode(packages).encode()),
                companionTransition=proof,
                peerTransition=dict(authorizationId=local['requestId'],authorizationResultSha256=original_sha,
                   previous=local,incoming={**local,'coreUnitSha256':source.digest(unit),
                                           'coreNetworkingDropInSha256':peer.NETWORKING_DROP_IN_SHA256}))
            ticket['state']=source.ticket_snapshot(ticket)
            source.immutable(source.PENDING,self.profile.encode(ticket))
            self.persist_intent(ticket)
            return source.status(operation)

    def persist_intent(self, ticket):
        source=self.source
        name=source.record(ticket['requestId'],'intent.json')
        self.profile.directory(source.RECORDS,0,0,0o700,True)
        self.profile.directory(name.rsplit('/',1)[0],0,0,0o700,True)
        source.immutable(name,self.profile.encode(ticket))

    def complete(self, ticket):
        source=self.source
        if source.json(source.record(ticket['requestId'],'intent.json'))!=ticket:
            raise RuntimeError('Original companion intent differs from its pending publication')
        transition=source.peer_transition(ticket)
        proof=ticket['companionTransition']
        KuraPeer(self.profile).stopped()
        if (self.root()!=proof['root'] or self.profile.asset(self.KEY,0o400,32)!=proof['keySha256']
                or self.profile.descriptor()!=ticket['identity'] or source.bridge()!=ticket['bridge']):
            raise RuntimeError('Original companion Root, key or native identity changed')
        for package,pin in proof['packages'].items():
            if self.installed_version(package)!=pin['version']:
                raise RuntimeError('Original reviewed companion packages must both finish configuration')
            for script,digest in pin['controls'].items():
                if self.profile.asset('/var/lib/dpkg/info/'+package+'.'+script,0o755,2*1024*1024)!=digest:
                    raise RuntimeError('Installed companion maintainer differs from the original archive')
        current=KuraPeer(self.profile).peer(transition['authorizationId'],ticket['initializationId'])
        if current!=transition['incoming'] or source.ticket_snapshot(ticket,publishing=True)!=ticket['state']:
            raise RuntimeError('Installed companions or retained state differ from the original approved pair')
        return source.publish_source_result(ticket,ticket['identity'])


class KuraMaterial:
    """One fixed staged-material FD capability, independent of remote enable."""
    PUBLIC=V2_PUBLIC+'/enrollment-reader.json'
    RELAY=V2_CONFIG+'/enrollment-relay-grant.json'
    CURRENT=V2_ADMIN+'/material-current.json'
    PENDING=V2_ADMIN+'/.material-pending.json'
    RECORDS=V2_ADMIN+'/material-grants'
    SOURCE='/opt/eclipse/kura/data/management-enrollment'
    SOCKET='/run/kura-management-agent-enrollment.sock'
    UPSTREAM='/run/kura-management-enrollment-reader.sock'

    def __init__(self, profile):
        self.profile,self.legacy=profile,profile.legacy
        self.source=SourceUpdate(profile);self.peer=KuraPeer(profile)

    def record(self, operation, name):
        return self.RECORDS+'/'+self.source.uuid(operation)+'/'+name

    def present(self):
        return any(os.path.lexists(self.legacy.path(n)) for n in [self.PUBLIC,self.RELAY,self.CURRENT,self.PENDING,self.RECORDS])

    def no_orphan(self):
        root=self.legacy.path(self.RECORDS)
        if not os.path.lexists(root): return
        self.profile.directory(self.RECORDS,0,0,0o700)
        pending=self.source.optional(self.PENDING)
        for folder in root.iterdir():
            operation=self.source.uuid(folder.name);self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700)
            if (not os.path.lexists(folder/'published.json')
                    and (pending is None or pending.get('requestId')!=operation)):
                raise RuntimeError('Lost original native material authorization marker')
        if pending is None and not os.path.lexists(self.legacy.path(self.CURRENT)):
            raise RuntimeError('Lost original native material authorization pointer')

    def pair(self):
        publisher=self.legacy.reader_pair()
        allowed={'kura-management-agent-enrollment.socket','kura-management-agent-enrollment@.service'}
        for directory in ['/etc/systemd/system','/etc/systemd/system.control','/run/systemd/system',
                '/run/systemd/system.control','/run/systemd/transient','/run/systemd/generator.early',
                '/run/systemd/generator','/run/systemd/generator.late','/usr/local/lib/systemd/system',
                '/usr/lib/systemd/system']:
            parent=self.legacy.path(directory)
            if parent.exists():
                self.legacy.authorization_parents(parent/'.relay-admission')
                for path in parent.glob('kura-management-agent-enrollment*'):
                    if directory!='/usr/lib/systemd/system' or path.name not in allowed:
                        raise RuntimeError('Unreviewed enrollment relay unit or instance override')
        for unit in ['kura-management-agent-enrollment.socket','kura-management-agent-enrollment@admission.service']:
            live=self.legacy.systemctl('show',unit,'--property=LoadState,FragmentPath,DropInPaths')
            fields=None if live is None else dict(line.split('=',1) for line in live.stdout.splitlines() if '=' in line)
            vendor='kura-management-agent-enrollment@.service' if '@' in unit else unit
            if fields is not None and fields!={'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/'+vendor,'DropInPaths':''}:
                raise RuntimeError('Effective relay units differ from their reviewed source pair')
        # The complete native metadata is Root/source checked by descriptor();
        # its hash covers relay code/socket/unit without cross-language encoding.
        self.profile.descriptor()
        relay=self.source.digest(self.legacy.reader_file('/usr/share/kura-management-agent/native-profile.json'))
        return publisher,relay

    def descriptor(self, operation):
        local=self.peer.check()
        if local is None: raise RuntimeError('Original local Kura peer grant required before material authority')
        return self.context(operation,local)

    def context(self, operation, local):
        path=self.source_root(local)
        if os.path.lexists(path):
            m=path.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid!=local['kuraUid'] or m.st_gid!=local['kuraGid']
                    or stat.S_IMODE(m.st_mode)!=0o700):
                raise RuntimeError('Preserve unreviewed Kura enrollment source ownership or mode')
        identity=self.profile.descriptor();publisher,relay=self.pair()
        private={'schemaVersion':1,'requestId':operation,'agentUid':identity['uid'],'agentGid':identity['gid'],
            'readerGid':identity['readerGid'],'sourceUid':local['kuraUid'],'sourceRoot':self.SOURCE,
            'upstreamSocket':self.UPSTREAM,'socket':self.SOCKET,'publisherPairSha256':publisher,
            'relayPairSha256':relay,'operator':'local-root'}
        private_raw=self.profile.encode(private).encode()
        public={'schemaVersion':1,'profile':'staged-enrollment-reader-v1','requestId':operation,
            'peerAuthorizationId':local['requestId'],
            'nativeIdentitySha256':self.source.digest(self.profile.encode(identity).encode()),
            'agentUid':identity['uid'],'agentGid':identity['gid'],'readerGid':identity['readerGid'],
            'sourceUid':local['kuraUid'],'sourceRoot':self.SOURCE,'upstreamSocket':self.UPSTREAM,
            'socket':self.SOCKET,'publisherPairSha256':publisher,'relayPairSha256':relay,
            'relayGrantSha256':self.source.digest(private_raw),'remoteEnabled':False}
        return public,private_raw

    @classmethod
    def private_bytes(cls, public):
        fields={'schemaVersion','profile','requestId','peerAuthorizationId','nativeIdentitySha256',
                'agentUid','agentGid','readerGid','sourceUid','sourceRoot','upstreamSocket','socket',
                'publisherPairSha256','relayPairSha256','relayGrantSha256','remoteEnabled'}
        if (not isinstance(public,dict) or set(public)!=fields or type(public['schemaVersion']) is not int
                or public['schemaVersion']!=1 or public['profile']!='staged-enrollment-reader-v1'
                or public['remoteEnabled'] is not False or public['sourceRoot']!=cls.SOURCE
                or public['upstreamSocket']!=cls.UPSTREAM or public['socket']!=cls.SOCKET
                or any(type(public[k]) is not int or not 0<public[k]<4294967295
                       for k in ['agentUid','agentGid','readerGid','sourceUid'])
                or public['sourceUid']==public['agentUid'] or public['agentGid']==public['readerGid']
                or any(not isinstance(public[k],str) or not re.fullmatch('[0-9a-f]{64}',public[k])
                       for k in ['nativeIdentitySha256','publisherPairSha256','relayPairSha256','relayGrantSha256'])):
            raise RuntimeError('Invalid original material permission scope')
        SourceUpdate.uuid(public['requestId']);SourceUpdate.uuid(public['peerAuthorizationId'])
        keys=['schemaVersion','requestId','agentUid','agentGid','readerGid','sourceUid','sourceRoot',
              'upstreamSocket','socket','publisherPairSha256','relayPairSha256']
        return RuntimeSetup.encode({**{k:public[k] for k in keys},'operator':'local-root'}).encode()

    def maintenance_stopped(self, local, retained=False):
        self.profile.stopped(V2_UNIT);self.profile.stopped('kura.service')
        for unit in ['kura-management-enrollment-reader.socket','kura-management-agent-enrollment.socket']:
            live=self.legacy.systemctl('show',unit,'--property=ActiveState,NConnections')
            fields=None if live is None else dict(line.split('=',1) for line in live.stdout.splitlines() if '=' in line)
            if fields is not None and fields!={'ActiveState':'inactive','NConnections':'0'}:
                raise RuntimeError('Explicitly stop and drain the original material sockets before source maintenance')
        if not retained and os.path.lexists(self.source_root(local)):
            raise RuntimeError('Real retained enrollment material requires its separate joint maintenance flow')

    def source_root(self, local):
        # Core packages use one Root-owned link to a direct versioned sibling.
        # Keep agent-owned path() strict; never follow a data or stage link.
        parent=self.legacy.path('/opt/eclipse')
        self.legacy.authorization_parents(parent/'.material-source')
        home=parent/'kura'
        if home.is_symlink():
            info=home.lstat();raw=os.readlink(home)
            name=raw.removeprefix('/opt/eclipse/') if raw.startswith('/opt/eclipse/') else raw
            if (info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1
                    or not re.fullmatch(r'kura_[A-Za-z0-9._+~:-]+',name)):
                raise RuntimeError('Unsafe packaged Core home for material source')
            home=parent/name
        self.legacy.authorization_parents(home/'data')
        for name in ['data','data/management-enrollment']:
            path=home/name
            if os.path.lexists(path):
                info=path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=local['kuraUid']
                        or info.st_gid!=local['kuraGid'] or stat.S_IMODE(info.st_mode)!=0o700):
                    raise RuntimeError('Preserve unreviewed Kura enrollment source ownership or mode')
        return home/'data/management-enrollment'

    def state(self):
        self.profile.stopped(V2_UNIT)
        descriptor=self.profile.descriptor();assets=self.source.initial_runtime_assets(descriptor)
        extra=['enrollment-relay-grant.json'] if os.path.lexists(self.legacy.path(self.RELAY)) else []
        with self.source.runtime_locks(descriptor):
            return self.source.snapshot_assets(descriptor,assets,extra_config=extra)

    def original(self):
        pointer=self.source.optional(self.CURRENT)
        if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
            raise RuntimeError('Original native material publication proof missing')
        operation=self.source.uuid(pointer['requestId']);raw=self.source.raw(self.record(operation,'result.json'))
        result=self.legacy.reader_json(raw);ticket=self.source.json(self.record(operation,'intent.json'))
        if (not isinstance(ticket,dict) or set(ticket)!=
                {'schemaVersion','requestId','public','relayGrantSha256','peerResultSha256','state'}
                or type(ticket['schemaVersion']) is not int or ticket['schemaVersion']!=1
                or ticket['requestId']!=operation):
            raise RuntimeError('Original native material intent differs')
        public=ticket['public'];private=self.private_bytes(public)
        published=self.source.json(self.record(operation,'published.json'))
        peer,peer_sha=self.peer.original()
        if (self.source.digest(raw)!=pointer['sha256']
                or set(result)!={'schemaVersion','requestId','peerAuthorizationId','peerResultSha256',
                    'publicSha256','relayGrantSha256','stateFingerprintSha256','unitStarted','remoteEnabled'}
                or type(result['schemaVersion']) is not int or result['schemaVersion']!=1
                or result['requestId']!=operation or result['peerAuthorizationId']!=public['peerAuthorizationId']
                or public['requestId']!=operation or public['peerAuthorizationId']!=peer['requestId']
                or ticket['peerResultSha256']!=peer_sha or ticket['relayGrantSha256']!=self.source.digest(private)
                or result['peerResultSha256']!=peer_sha or result['unitStarted'] is not False or result['remoteEnabled'] is not False
                or result['publicSha256']!=self.source.digest(self.profile.encode(public).encode())
                or result['relayGrantSha256']!=self.source.digest(private)
                or result['stateFingerprintSha256']!=self.source.digest(self.profile.encode(ticket['state']).encode())
                or self.source.raw(self.record(operation,'relay-grant.json'))!=private
                or published!={'schemaVersion':1,'requestId':operation,'resultSha256':self.source.digest(raw),
                              'publicSha256':result['publicSha256']}):
            raise RuntimeError('Native material authority differs from original Root proof')
        return public,self.source.digest(raw)

    def check(self):
        if not self.present(): return None
        original,authorization_sha=self.original()
        public,private=self.descriptor(original['requestId'])
        if (self.source.current_material(original,authorization_sha)!=public
                or self.source.raw(self.RELAY)!=private):
            raise RuntimeError('Native material current source binding differs from original authority')
        return public

    def status(self, operation):
        self.source.uuid(operation);pending=self.source.optional(self.PENDING)
        if pending is not None:
            if pending.get('requestId')!=operation: raise RuntimeError('Preserve original material authorization UUID')
            return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
        if not os.path.lexists(self.legacy.path(self.record(operation,'published.json'))):
            if os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
                return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
            self.no_orphan();return {'schemaVersion':1,'requestId':operation,'state':'NOT_FOUND','replayed':False}
        raw=self.source.raw(self.record(operation,'result.json'));ack=self.source.json(self.record(operation,'published.json'))
        if ack!={'schemaVersion':1,'requestId':operation,'resultSha256':self.source.digest(raw),
                 'publicSha256':self.legacy.reader_json(raw)['publicSha256']}:
            raise RuntimeError('Original material result publication differs')
        try:self.profile.check();ready='READY'
        except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):ready='REFUSED'
        return {'schemaVersion':1,'requestId':operation,'state':'APPLIED','currentReadiness':ready,
                'remoteEnabled':False,'unitStarted':False,'replayed':False}

    def authorize(self, operation):
        self.source.uuid(operation)
        if os.path.lexists(self.legacy.path(self.PENDING)) or os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
            return self.status(operation)
        self.profile.check();self.profile.stopped(V2_UNIT)
        if self.present(): raise RuntimeError('Existing material authority requires its original maintenance')
        with self.source.package_locks():
            self.profile.check();public,private=self.descriptor(operation);state=self.state();_,peer_sha=self.peer.original()
            ticket={'schemaVersion':1,'requestId':operation,'public':public,'relayGrantSha256':self.source.digest(private),
                    'peerResultSha256':peer_sha,'state':state}
            self.source.immutable(self.PENDING,self.profile.encode(ticket))
            self.profile.directory(self.RECORDS,0,0,0o700,True)
            self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
            self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
            self.source.immutable(self.record(operation,'relay-grant.json'),private)
            return self.finish(ticket)

    def complete(self, operation):
        self.source.uuid(operation)
        if not os.path.lexists(self.legacy.path(self.PENDING)): return self.status(operation)
        ticket=self.source.json(self.PENDING)
        if ticket.get('requestId')!=operation: raise RuntimeError('Preserve original material authorization UUID')
        with self.source.package_locks():return self.finish(ticket)

    def finish(self, ticket):
        operation=self.source.uuid(ticket['requestId']);self.profile.stopped(V2_UNIT)
        public,private=self.descriptor(operation);_,peer_sha=self.peer.original()
        if (ticket!=self.source.json(self.record(operation,'intent.json')) or public!=ticket['public']
                or peer_sha!=ticket['peerResultSha256'] or self.source.digest(private)!=ticket['relayGrantSha256']
                or self.source.raw(self.record(operation,'relay-grant.json'))!=private or self.state()!=ticket['state']):
            raise RuntimeError('Original material authorization context/state changed')
        self.source.immutable(self.RELAY,private)
        result={'schemaVersion':1,'requestId':operation,'peerAuthorizationId':public['peerAuthorizationId'],
                'peerResultSha256':peer_sha,'publicSha256':self.source.digest(self.profile.encode(public).encode()),
                'relayGrantSha256':ticket['relayGrantSha256'],
                'stateFingerprintSha256':self.source.digest(self.profile.encode(ticket['state']).encode()),
                'unitStarted':False,'remoteEnabled':False}
        raw=self.profile.encode(result).encode();self.source.immutable(self.record(operation,'result.json'),raw)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.source.digest(raw)}
        if self.source.optional(self.CURRENT) not in [None,pointer]: raise RuntimeError('Material pointer changed')
        if self.source.optional(self.CURRENT) is None:self.source.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600)
        self.source.immutable(self.PUBLIC,self.profile.encode(public),0o644)
        self.source.immutable(self.record(operation,'published.json'),self.profile.encode({
            'schemaVersion':1,'requestId':operation,'resultSha256':self.source.digest(raw),'publicSha256':result['publicSha256']}))
        self.check();self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check();return self.status(operation)


class KuraRemoteSwitch:
    """Root delegation to the original Kura peer, never a remote ON decision."""
    PUBLIC=V2_PUBLIC+'/kura-remote-switch.json'
    RECORDS=V2_ADMIN+'/kura-remote-switch'
    CURRENT=V2_ADMIN+'/kura-remote-switch-current.json'
    PENDING=V2_ADMIN+'/.kura-remote-switch-pending.json'
    ENV=V2_CONFIG+'/agent.env'

    def __init__(self,profile):
        self.profile,self.legacy=profile,profile.legacy;self.source=SourceUpdate(profile)

    def record(self,operation,leaf):return self.RECORDS+'/'+self.source.uuid(operation)+'/'+leaf

    def present(self):
        return any(os.path.lexists(self.legacy.path(n)) for n in [self.PUBLIC,self.CURRENT,self.PENDING,self.RECORDS])

    def no_orphan(self):
        if os.path.lexists(self.legacy.path(self.PENDING)):return
        if self.source.optional(self.CURRENT) is None:
            folder=self.legacy.path(self.RECORDS)
            if os.path.lexists(self.legacy.path(self.PUBLIC)) or os.path.lexists(folder):
                raise RuntimeError('Original remote-switch proof is missing; preserve its authority records')

    @staticmethod
    def validate_grant(grant):
        keys={'schemaVersion','profile','requestId','initializationId','peerAuthorizationId',
              'peerAuthorizationResultSha256','nativeUid','controlGid','kuraUid','kuraGid',
              'canControl','unitStarted','remoteEnabled'}
        if (not isinstance(grant,dict) or set(grant)!=keys
                or any(type(grant[k]) is not int for k in ['schemaVersion','nativeUid','controlGid','kuraUid','kuraGid'])
                or grant['schemaVersion']!=1 or grant['profile']!='local-kura-remote-switch-v1'
                or any(not 0<grant[k]<4294967295 for k in ['nativeUid','controlGid','kuraUid','kuraGid'])
                or grant['canControl'] is not True or grant['unitStarted'] is not False or grant['remoteEnabled'] is not False
                or not isinstance(grant['peerAuthorizationResultSha256'],str)
                or not re.fullmatch('[0-9a-f]{64}',grant['peerAuthorizationResultSha256'])):
            raise RuntimeError('Invalid original remote-switch grant schema')
        for key in ['requestId','initializationId','peerAuthorizationId']:SourceUpdate.uuid(grant[key])
        return grant

    def context(self,operation):
        peer=KuraPeer(self.profile);original,peer_sha=peer.original()
        initial=self.source.json(V2_ADMIN+'/initialization.json');descriptor=self.profile.descriptor()
        # This delegation has stable peer scope. Current code pairing remains
        # enforced by RuntimeSetup/KuraPeer/SourceUpdate, including the permitted
        # old/new publication interval; do not demand an already-published code
        # pointer while that original source transaction is completing.
        current=peer.core()
        if (any(current[k]!=original['peer'][k] for k in current) or peer.members()!=['kurad']):
            raise RuntimeError('Original remote-switch Kura peer changed')
        grant={'schemaVersion':1,'profile':'local-kura-remote-switch-v1','requestId':self.source.uuid(operation),
            'initializationId':initial['operationId'],'peerAuthorizationId':original['requestId'],
            'peerAuthorizationResultSha256':peer_sha,'nativeUid':descriptor['uid'],'controlGid':descriptor['gid'],
            'kuraUid':current['kuraUid'],'kuraGid':current['kuraGid'],'canControl':True,'unitStarted':False,'remoteEnabled':False}
        return grant,original,current

    def expected_result(self,ticket):
        return {**{k:v for k,v in ticket.items() if k!='state'},
                'stateFingerprintSha256':self.source.digest(self.profile.encode(ticket['state']).encode()),
                'unitStarted':False,'remoteEnabled':False}

    def original(self):
        pointer=self.source.optional(self.CURRENT)
        if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
            raise RuntimeError('Original remote-switch publication proof is missing')
        operation=self.source.uuid(pointer['requestId']);ticket=self.source.json(self.record(operation,'intent.json'))
        self.validate_ticket(ticket)
        raw=self.source.raw(self.record(operation,'result.json'));result=self.legacy.reader_json(raw)
        expected=self.expected_result(ticket)
        if (result!=expected or self.source.digest(raw)!=pointer['sha256']
                or self.source.json(self.record(operation,'published.json'))!={'schemaVersion':1,'requestId':operation,
                    'resultSha256':pointer['sha256'],'publicSha256':self.source.digest(self.profile.encode(ticket['grant']).encode())}):
            raise RuntimeError('Original remote-switch authority proof changed')
        return result,pointer['sha256']

    def validate_ticket(self,ticket):
        keys={'schemaVersion','requestId','grant','initializationReceiptSha256','previousEnvSha256',
              'incomingEnvSha256','state','retainedEnrollment','identityAtGrant','sourcePairAtGrant'}
        if (not isinstance(ticket,dict) or set(ticket)!=keys
                or type(ticket['schemaVersion']) is not int or ticket['schemaVersion']!=1):
            raise RuntimeError('Invalid original remote-switch intent')
        operation=self.source.uuid(ticket['requestId']);grant,original,_=self.context(operation)
        self.validate_grant(ticket['grant'])
        old=self.source.raw(self.record(operation,'previous.env'));new=self.source.raw(self.record(operation,'incoming.env'))
        needle=b'AGENT_KURA_REMOTE_MANAGEMENT=0\n'
        if (ticket['grant']!=grant or old.count(needle)!=1 or new!=old.replace(needle,b'AGENT_KURA_REMOTE_MANAGEMENT=1\n',1)
                or self.source.digest(old)!=ticket['previousEnvSha256'] or self.source.digest(new)!=ticket['incomingEnvSha256']
                or ticket['previousEnvSha256']!=original['envSha256']
                or ticket['initializationReceiptSha256']!=self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json'))):
            raise RuntimeError('Original remote-switch scope or environment changed')
        if ticket['retainedEnrollment'] is not None:RetainedEnrollment.summary(ticket['retainedEnrollment'])
        return grant,old,new

    def check(self):
        self.no_orphan()
        if self.source.optional(self.CURRENT) is None:return None
        result,_=self.original();expected,_,_=self.context(result['requestId'])
        if (self.source.optional(self.PUBLIC,0o644)!=expected
                or self.source.digest(self.source.raw(self.ENV))!=result['incomingEnvSha256']):
            raise RuntimeError('Current remote-switch authority differs from its original Root proof')
        return expected

    def expected_env_sha(self,peer_original):
        if os.path.lexists(self.legacy.path(self.PENDING)):
            ticket=self.source.json(self.PENDING)
            if ticket!=self.source.json(self.record(ticket['requestId'],'intent.json')):
                raise RuntimeError('Original remote-switch intent differs from pending publication')
            _,old,incoming=self.validate_ticket(ticket);current=self.source.raw(self.ENV)
            if current not in [old,incoming] or ticket['previousEnvSha256']!=peer_original['envSha256']:
                raise RuntimeError('Pending remote-switch environment changed')
            return self.source.digest(current)
        grant=self.check()
        if grant is None:return peer_original['envSha256']
        result,_=self.original()
        if result['previousEnvSha256']!=peer_original['envSha256']:
            raise RuntimeError('Remote-switch environment does not continue the original peer authority')
        return result['incomingEnvSha256']

    def proof_assets(self):
        if os.path.lexists(self.legacy.path(self.PENDING)):
            raise RuntimeError('Original remote-switch publication remains pending')
        grant=self.check()
        if grant is None:return []
        operation=grant['requestId'];folder=self.RECORDS+'/'+operation
        names=[self.RECORDS,folder,self.PUBLIC,self.CURRENT]+[folder+'/'+n for n in
                ['intent.json','previous.env','incoming.env','result.json','published.json']]
        if {p.name for p in self.legacy.path(folder).iterdir()}!={'intent.json','previous.env','incoming.env','result.json','published.json'}:
            raise RuntimeError('Unreviewed original remote-switch proof assets')
        return [self.legacy.path(n) for n in names]

    def stopped(self,local):
        self.profile.stopped('kura-management-agent.service');self.profile.stopped(V2_UNIT);self.profile.stopped('kura.service')
        if KuraMaterial(self.profile).present():KuraMaterial(self.profile).maintenance_stopped(local,retained=True)
        for name in [V2_ADMIN+'/.initialization-pending',SourceUpdate.PENDING,KuraPeer.PENDING,KuraMaterial.PENDING]:
            if os.path.lexists(self.legacy.path(name)):
                raise RuntimeError('Other original native maintenance remains pending')

    def snapshot(self,local,summary=None):
        if os.path.lexists(self.legacy.path(V2_STATE+'/enrollment')):
            if KuraMaterial(self.profile).check() is None:
                raise RuntimeError('Retained identity needs its original material authority')
            return self.source.enrolled_snapshot(local,summary,include_switch=False)
        if summary is not None:raise RuntimeError('Original retained identity disappeared')
        extra=['enrollment-relay-grant.json'] if KuraMaterial(self.profile).present() else []
        return self.source.initial_snapshot(extra_config=extra,include_switch=False),None

    def status(self,operation):
        self.source.uuid(operation);pending=self.source.optional(self.PENDING)
        if pending is not None and pending.get('requestId')!=operation:
            raise RuntimeError('Preserve the original remote-switch authorization UUID')
        result=self.source.optional(self.record(operation,'result.json'));published=self.source.optional(self.record(operation,'published.json'))
        if result is None or published is None:
            if pending is not None or self.source.optional(self.record(operation,'intent.json')) is not None:
                return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','unitStarted':False,'remoteEnabled':False,'replayed':False}
            raise RuntimeError('Original remote-switch authorization not found')
        if result.get('requestId')!=operation or published.get('requestId')!=operation:
            raise RuntimeError('Original remote-switch receipt differs')
        self.validate_grant(result.get('grant'))
        intent=self.source.json(self.record(operation,'intent.json'));raw=self.source.raw(self.record(operation,'result.json'))
        if (result!=self.expected_result(intent) or published!={'schemaVersion':1,'requestId':operation,
                'resultSha256':self.source.digest(raw),'publicSha256':self.source.digest(self.profile.encode(result['grant']).encode())}):
            raise RuntimeError('Original remote-switch completion receipt changed')
        ready='REFUSED'
        try:
            self.profile.check()
            grant=self.check()
            if grant is not None and grant['requestId']==operation:ready='READY'
        except (RuntimeError,OSError,ValueError,KeyError):pass
        return {'schemaVersion':1,'requestId':operation,'state':'APPLIED','currentReadiness':ready,
                'canControl':ready=='READY','unitStarted':False,'remoteEnabled':False,'replayed':False}

    def authorize(self,operation):
        self.source.uuid(operation)
        if os.path.lexists(self.legacy.path(self.PENDING)) or os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
            return self.status(operation)
        self.profile.check();local=KuraPeer(self.profile).check()
        if local is None:raise RuntimeError('Original local Kura authority is required before remote-switch delegation')
        self.stopped(local)
        if self.check() is not None:raise RuntimeError('Original remote-switch authority already exists')
        with self.source.package_locks():
            self.profile.check();self.stopped(local)
            grant,original,_=self.context(operation);state,summary=self.snapshot(local)
            old=self.source.raw(self.ENV);needle=b'AGENT_KURA_REMOTE_MANAGEMENT=0\n'
            if old.count(needle)!=1 or self.source.digest(old)!=original['envSha256']:
                raise RuntimeError('Original remote-switch environment required')
            incoming=old.replace(needle,b'AGENT_KURA_REMOTE_MANAGEMENT=1\n',1)
            ticket={'schemaVersion':1,'requestId':operation,'grant':grant,'state':state,'retainedEnrollment':summary,
                'identityAtGrant':self.profile.descriptor(),'sourcePairAtGrant':self.source.optional(SourceUpdate.CURRENT),
                'initializationReceiptSha256':self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json')),
                'previousEnvSha256':self.source.digest(old),'incomingEnvSha256':self.source.digest(incoming)}
            self.source.immutable(self.PENDING,self.profile.encode(ticket))
            self.profile.directory(self.RECORDS,0,0,0o700,True);self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
            self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
            self.source.immutable(self.record(operation,'previous.env'),old)
            self.source.immutable(self.record(operation,'incoming.env'),incoming)
            return self.finish(ticket)

    def complete(self,operation):
        self.source.uuid(operation)
        if not os.path.lexists(self.legacy.path(self.PENDING)):return self.status(operation)
        ticket=self.source.json(self.PENDING)
        if ticket.get('requestId')!=operation:raise RuntimeError('Preserve the original remote-switch authorization UUID')
        with self.source.package_locks():
            self.complete_original_index(ticket)
            return self.finish(ticket)

    def complete_original_index(self,ticket):
        """Fill an interrupted intent index only while original env is untouched.

        The global Root intent was durable first. No permission publication has
        happened at these boundaries; missing files after an env change are a
        recovery condition, not an invitation to reconstruct prior evidence.
        """
        operation=self.source.uuid(ticket['requestId'])
        required=['intent.json','previous.env','incoming.env']
        if all(os.path.lexists(self.legacy.path(self.record(operation,n))) for n in required):return
        self.validate_grant(ticket.get('grant'));grant,original,local=self.context(operation);self.stopped(local)
        old=self.source.raw(self.ENV);needle=b'AGENT_KURA_REMOTE_MANAGEMENT=0\n'
        extra=['enrollment-relay-grant.json'] if KuraMaterial(self.profile).present() else []
        current=self.source.snapshot_assets(self.profile.descriptor(),[],extra_config=extra)
        if (ticket['grant']!=grant or old.count(needle)!=1 or self.source.digest(old)!=original['envSha256']
                or self.source.digest(old)!=ticket['previousEnvSha256'] or current[self.ENV]!=ticket['state'][self.ENV]
                or self.profile.descriptor()!=ticket['identityAtGrant']
                or self.source.optional(SourceUpdate.CURRENT)!=ticket['sourcePairAtGrant']
                or self.source.json(self.PENDING)!=ticket):
            raise RuntimeError('Interrupted original remote-switch index requires its original recovery')
        incoming=old.replace(needle,b'AGENT_KURA_REMOTE_MANAGEMENT=1\n',1)
        if self.source.digest(incoming)!=ticket['incomingEnvSha256']:
            raise RuntimeError('Interrupted remote-switch intent changed its requested environment')
        self.source.verify_chain(self.source.json(V2_ADMIN+'/initialization.json'),ticket['identityAtGrant'])
        self.profile.directory(self.RECORDS,0,0,0o700,True);self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
        self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
        self.source.immutable(self.record(operation,'previous.env'),old)
        self.source.immutable(self.record(operation,'incoming.env'),incoming)

    def finish(self,ticket):
        operation=self.source.uuid(ticket['requestId'])
        if ticket!=self.source.json(self.record(operation,'intent.json')):
            raise RuntimeError('Original remote-switch intent differs from pending publication')
        grant,old,incoming=self.validate_ticket(ticket);_,_,local=self.context(operation);self.stopped(local)
        if (self.profile.descriptor()!=ticket['identityAtGrant']
                or self.source.optional(SourceUpdate.CURRENT)!=ticket['sourcePairAtGrant']
                or self.source.optional(V2_IDENTITY,0o644)!=ticket['identityAtGrant']):
            raise RuntimeError('Original remote-switch approval code pair changed')
        self.source.verify_chain(self.source.json(V2_ADMIN+'/initialization.json'),ticket['identityAtGrant'])
        current=self.source.raw(self.ENV)
        if current not in [old,incoming]:raise RuntimeError('Changed remote-switch environment must be preserved')
        state,summary=self.snapshot(local,ticket['retainedEnrollment'])
        if summary!=ticket['retainedEnrollment'] or {k:v for k,v in state.items() if k!=self.ENV}!={k:v for k,v in ticket['state'].items() if k!=self.ENV}:
            raise RuntimeError('Original remote-switch retained state changed')
        if current==old:
            if state[self.ENV]!=ticket['state'][self.ENV]:raise RuntimeError('Original remote-switch environment metadata changed')
            self.source.replace(self.ENV,incoming,0o600)
        result=self.expected_result(ticket);raw=self.profile.encode(result).encode();self.source.immutable(self.record(operation,'result.json'),raw)
        if self.source.optional(self.PUBLIC,0o644) not in [None,grant]:raise RuntimeError('Remote-switch public authority changed')
        if self.source.optional(self.PUBLIC,0o644)!=grant:self.source.replace(self.PUBLIC,self.profile.encode(grant).encode(),0o644)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.source.digest(raw)}
        if self.source.optional(self.CURRENT) not in [None,pointer]:raise RuntimeError('Remote-switch original pointer changed')
        if self.source.optional(self.CURRENT)!=pointer:self.source.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600)
        self.source.immutable(self.record(operation,'published.json'),self.profile.encode({'schemaVersion':1,'requestId':operation,
            'resultSha256':self.source.digest(raw),'publicSha256':self.source.digest(self.profile.encode(grant).encode())}))
        self.check();self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check();return self.status(operation)


class NativeTransport:
    """Root host/port configuration; no identity rewrite or additional delegation."""
    PUBLIC=V2_PUBLIC+'/transport-endpoint.json'
    RECORDS=V2_ADMIN+'/transport-endpoint'
    CURRENT=V2_ADMIN+'/transport-endpoint-current.json'
    PENDING=V2_ADMIN+'/.transport-endpoint-pending.json'

    def __init__(self,profile):
        self.profile,self.legacy=profile,profile.legacy;self.source=SourceUpdate(profile)

    def record(self,operation,leaf):return self.RECORDS+'/'+self.source.uuid(operation)+'/'+leaf

    def no_orphan(self):
        if os.path.lexists(self.legacy.path(self.PENDING)):return
        if self.source.optional(self.CURRENT) is None and any(os.path.lexists(self.legacy.path(n)) for n in [self.PUBLIC,self.RECORDS]):
            raise RuntimeError('Original transport configuration proof is missing')

    @staticmethod
    def address(value):
        try:
            if not isinstance(value,str) or not 1<=len(value)<=512 or any(not 33<=ord(c)<=126 for c in value):raise ValueError()
            parsed=urlsplit(value)
            if (parsed.scheme!='https' or not parsed.hostname or parsed.netloc.endswith(':') or parsed.username is not None or parsed.password is not None
                    or parsed.path not in ['','/'] or parsed.query or parsed.fragment
                    or parsed.port is not None and not 0<parsed.port<=65535):raise ValueError()
            return parsed.hostname.lower()
        except ValueError:raise RuntimeError('Fixed HTTPS transport host and port required') from None

    @staticmethod
    def validate_config(config):
        keys={'schemaVersion','profile','requestId','initializationId','peerAuthorizationId','peerAuthorizationResultSha256',
              'nativeUid','controlGid','gatewayId','originalEndpoint','endpoint','identityReceiptSha256',
              'minimumBindingGeneration','unitStarted','remoteEnabled'}
        if (not isinstance(config,dict) or set(config)!=keys or type(config['schemaVersion']) is not int
                or config['schemaVersion']!=1 or config['profile']!='native-transport-endpoint-v1'
                or any(type(config[k]) is not int or not 0<config[k]<4294967295 for k in ['nativeUid','controlGid'])
                or type(config['minimumBindingGeneration']) is not int or not 0<config['minimumBindingGeneration']<9223372036854775808
                or config['unitStarted'] is not False or config['remoteEnabled'] is not False
                or not isinstance(config['gatewayId'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',config['gatewayId'])
                or any(not isinstance(config[k],str) or not re.fullmatch('[a-f0-9]{64}',config[k]) for k in ['peerAuthorizationResultSha256','identityReceiptSha256'])):
            raise RuntimeError('Invalid original transport configuration schema')
        for key in ['requestId','initializationId','peerAuthorizationId']:SourceUpdate.uuid(config[key])
        if (NativeTransport.address(config['originalEndpoint'])!=NativeTransport.address(config['endpoint'])
                or config['originalEndpoint'].rstrip('/')==config['endpoint'].rstrip('/')):
            raise RuntimeError('Transport configuration must retain its original HTTPS host')
        return config

    def anchors(self):
        original,sha=KuraPeer(self.profile).original();descriptor=self.profile.descriptor()
        local=KuraPeer(self.profile).core()
        if any(local[k]!=original['peer'][k] for k in local) or KuraPeer(self.profile).members()!=['kurad']:
            raise RuntimeError('Original transport Kura peer changed')
        return {'initializationId':self.source.json(V2_ADMIN+'/initialization.json')['operationId'],
                'peerAuthorizationId':original['requestId'],'peerAuthorizationResultSha256':sha,
                'nativeUid':descriptor['uid'],'controlGid':descriptor['gid']},local

    def receipt(self,local):
        inventory=RetainedEnrollment(self.profile,local)
        raw=inventory.read(inventory.root/'enrollment/identity.json',limit=16384)
        value=self.legacy.reader_json(raw);material=value.get('material')
        if (value.get('schema')!='yofc.agent.enrollment.v1' or not isinstance(material,dict)
                or type(value.get('bindingGeneration')) is not int or value['bindingGeneration']<1
                or not isinstance(material.get('gatewayId'),str)):
            raise RuntimeError('Original native identity required for transport configuration')
        self.address(material.get('endpoint'))
        return value,raw

    def validate_ticket(self,ticket):
        keys={'schemaVersion','requestId','config','state','retainedEnrollment','identityAtConfiguration',
              'sourcePairAtConfiguration','initializationReceiptSha256'}
        if (not isinstance(ticket,dict) or set(ticket)!=keys or type(ticket['schemaVersion']) is not int
                or ticket['schemaVersion']!=1 or not isinstance(ticket['config'],dict)
                or ticket['requestId']!=ticket['config'].get('requestId')):
            raise RuntimeError('Invalid original transport intent')
        config=self.validate_config(ticket['config']);anchors,_=self.anchors()
        if (any(config[k]!=v for k,v in anchors.items())
                or ticket['initializationReceiptSha256']!=self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json'))):
            raise RuntimeError('Original transport installation or peer scope changed')
        summary=RetainedEnrollment.summary(ticket['retainedEnrollment'])
        if (config['identityReceiptSha256']!=summary['identityReceiptSha256']
                or config['minimumBindingGeneration']!=summary['bindingGeneration']):
            raise RuntimeError('Original transport identity summary changed')
        return config

    def expected_result(self,ticket):
        return {**{k:v for k,v in ticket.items() if k!='state'},
                'stateFingerprintSha256':self.source.digest(self.profile.encode(ticket['state']).encode()),
                'unitStarted':False,'remoteEnabled':False}

    def original(self):
        pointer=self.source.optional(self.CURRENT)
        if (not isinstance(pointer,dict) or set(pointer)!={'schemaVersion','requestId','sha256'}
                or type(pointer['schemaVersion']) is not int or pointer['schemaVersion']!=1):
            raise RuntimeError('Original transport publication proof is missing')
        operation=self.source.uuid(pointer['requestId']);ticket=self.source.json(self.record(operation,'intent.json'))
        self.validate_ticket(ticket);raw=self.source.raw(self.record(operation,'result.json'));result=self.legacy.reader_json(raw)
        if (result!=self.expected_result(ticket) or pointer['sha256']!=self.source.digest(raw)
                or self.source.json(self.record(operation,'published.json'))!={'schemaVersion':1,'requestId':operation,
                    'resultSha256':pointer['sha256'],'publicSha256':self.source.digest(self.profile.encode(ticket['config']).encode())}):
            raise RuntimeError('Original transport result or publication proof changed')
        return result

    def check(self):
        self.no_orphan()
        if self.source.optional(self.CURRENT) is None:return None
        result=self.original();config=result['config'];anchors,local=self.anchors()
        value,raw=self.receipt(local);generation=value['bindingGeneration'];material=value['material']
        if (self.source.optional(self.PUBLIC,0o644)!=config or material['gatewayId']!=config['gatewayId']
                or generation<config['minimumBindingGeneration']
                or generation==config['minimumBindingGeneration'] and self.source.digest(raw)!=config['identityReceiptSha256']
                or material['endpoint'].rstrip('/') not in [config['originalEndpoint'].rstrip('/'),config['endpoint'].rstrip('/')]):
            raise RuntimeError('Current transport configuration or identity scope changed')
        return config

    def proof_assets(self):
        if os.path.lexists(self.legacy.path(self.PENDING)):raise RuntimeError('Original transport publication remains pending')
        config=self.check()
        if config is None:return []
        folder=self.RECORDS+'/'+config['requestId'];names={'intent.json','result.json','published.json'}
        if {p.name for p in self.legacy.path(folder).iterdir()}!=names:
            raise RuntimeError('Unreviewed original transport proof assets')
        return [self.legacy.path(n) for n in [self.RECORDS,folder,self.PUBLIC,self.CURRENT]+[folder+'/'+n for n in sorted(names)]]

    def stopped(self,local):
        KuraRemoteSwitch(self.profile).stopped(local)
        if os.path.lexists(self.legacy.path(KuraRemoteSwitch.PENDING)):
            raise RuntimeError('Original switch delegation remains pending')

    def snapshot(self,local,summary=None):
        return self.source.enrolled_snapshot(local,summary,include_transport=False)

    def status(self,operation):
        self.source.uuid(operation);pending=self.source.optional(self.PENDING)
        if pending is not None and pending.get('requestId')!=operation:raise RuntimeError('Preserve the original transport UUID')
        result=self.source.optional(self.record(operation,'result.json'));ack=self.source.optional(self.record(operation,'published.json'))
        if result is None or ack is None:
            if pending is not None or self.source.optional(self.record(operation,'intent.json')) is not None:
                return {'schemaVersion':1,'requestId':operation,'state':'UNKNOWN','replayed':False}
            raise RuntimeError('Original transport configuration not found')
        ticket=self.source.json(self.record(operation,'intent.json'));self.validate_ticket(ticket)
        if (result!=self.expected_result(ticket) or ack!={'schemaVersion':1,'requestId':operation,
                'resultSha256':self.source.digest(self.source.raw(self.record(operation,'result.json'))),
                'publicSha256':self.source.digest(self.profile.encode(ticket['config']).encode())}):
            raise RuntimeError('Original transport completion receipt changed')
        ready='REFUSED'
        try:
            self.profile.check();current=self.check()
            if current is not None and current['requestId']==operation:ready='READY'
        except (RuntimeError,OSError,ValueError,KeyError):pass
        return {'schemaVersion':1,'requestId':operation,'state':'APPLIED','currentReadiness':ready,
                'unitStarted':False,'remoteEnabled':False,'replayed':False}

    def configure(self,operation,endpoint):
        self.source.uuid(operation);self.address(endpoint)
        if os.path.lexists(self.legacy.path(self.PENDING)) or os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
            original=self.source.optional(self.PENDING) or self.source.json(self.record(operation,'intent.json'))
            if original.get('requestId')!=operation or original.get('config',{}).get('endpoint')!=endpoint:
                raise RuntimeError('Original transport request parameters changed')
            return self.status(operation)
        self.profile.check()
        if self.check() is not None:raise RuntimeError('Original transport configuration already exists')
        anchors,local=self.anchors();self.stopped(local)
        with self.source.package_locks():
            self.profile.check();self.stopped(local);state,summary=self.snapshot(local);receipt,raw=self.receipt(local)
            config={'schemaVersion':1,'profile':'native-transport-endpoint-v1','requestId':operation,**anchors,
                    'gatewayId':receipt['material']['gatewayId'],'originalEndpoint':receipt['material']['endpoint'],
                    'endpoint':endpoint,'identityReceiptSha256':summary['identityReceiptSha256'],
                    'minimumBindingGeneration':summary['bindingGeneration'],'unitStarted':False,'remoteEnabled':False}
            self.validate_config(config)
            ticket={'schemaVersion':1,'requestId':operation,'config':config,'state':state,'retainedEnrollment':summary,
                    'identityAtConfiguration':self.profile.descriptor(),'sourcePairAtConfiguration':self.source.optional(SourceUpdate.CURRENT),
                    'initializationReceiptSha256':self.source.digest(self.source.raw(V2_ADMIN+'/initialization.json'))}
            self.source.immutable(self.PENDING,self.profile.encode(ticket))
            self.profile.directory(self.RECORDS,0,0,0o700,True);self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
            self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
            return self.finish(ticket)

    def complete(self,operation):
        self.source.uuid(operation)
        if not os.path.lexists(self.legacy.path(self.PENDING)):return self.status(operation)
        ticket=self.source.json(self.PENDING)
        if ticket.get('requestId')!=operation:raise RuntimeError('Preserve the original transport UUID')
        with self.source.package_locks():return self.finish(ticket)

    def finish(self,ticket):
        config=self.validate_ticket(ticket);operation=self.source.uuid(ticket['requestId']);_,local=self.anchors();self.stopped(local)
        if (self.profile.descriptor()!=ticket['identityAtConfiguration']
                or self.source.optional(SourceUpdate.CURRENT)!=ticket['sourcePairAtConfiguration']
                or self.source.optional(V2_IDENTITY,0o644)!=ticket['identityAtConfiguration']):
            raise RuntimeError('Original transport configuration code epoch changed')
        self.source.verify_chain(self.source.json(V2_ADMIN+'/initialization.json'),ticket['identityAtConfiguration'])
        state,summary=self.snapshot(local,ticket['retainedEnrollment'])
        if state!=ticket['state'] or summary!=ticket['retainedEnrollment']:
            raise RuntimeError('Original transport retained state changed')
        receipt,receipt_raw=self.receipt(local)
        if (config['gatewayId']!=receipt['material']['gatewayId'] or config['originalEndpoint']!=receipt['material']['endpoint']
                or config['minimumBindingGeneration']!=receipt['bindingGeneration']
                or config['identityReceiptSha256']!=self.source.digest(receipt_raw)):
            raise RuntimeError('Original transport configuration does not match its retained identity')
        # The global intent precedes the private index. Filling a missing index
        # is permitted only with that exact original intent and untouched state.
        self.profile.directory(self.RECORDS,0,0,0o700,True);self.profile.directory(self.RECORDS+'/'+operation,0,0,0o700,True)
        self.source.immutable(self.record(operation,'intent.json'),self.profile.encode(ticket))
        if self.source.json(self.record(operation,'intent.json'))!=ticket:raise RuntimeError('Original transport intent differs')
        raw=self.profile.encode(self.expected_result(ticket)).encode();self.source.immutable(self.record(operation,'result.json'),raw)
        if self.source.optional(self.PUBLIC,0o644) not in [None,config]:raise RuntimeError('Current transport public configuration changed')
        if self.source.optional(self.PUBLIC,0o644)!=config:self.source.replace(self.PUBLIC,self.profile.encode(config).encode(),0o644)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.source.digest(raw)}
        if self.source.optional(self.CURRENT) not in [None,pointer]:raise RuntimeError('Current transport pointer changed')
        if self.source.optional(self.CURRENT)!=pointer:self.source.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600)
        self.source.immutable(self.record(operation,'published.json'),self.profile.encode({'schemaVersion':1,'requestId':operation,
            'resultSha256':pointer['sha256'],'publicSha256':self.source.digest(self.profile.encode(config).encode())}))
        self.check();self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check();return self.status(operation)


class RetainedEnrollment:
    """Read-only inventory of one complete first identity and its original Core source.

    This does not adopt legacy data, complete pending work, renew an identity,
    change permissions, repair files or prove a full business-state migration.
    """
    SOURCE_FILES={'private.pk8','public.der','request.pem','gateway.id','complete'}
    CERT_FILES={'client-chain.pem','issuer-ca.pem','console-ca.pem','manifest.json','complete'}
    RECEIPT_KEYS={'schema','candidateId','requestId','stageSha256','material','bindingGeneration',
                  'sourceUid','actor','operator','acceptedAtUnixMs'}
    MATERIAL_KEYS={'schema','requestId','gatewayId','endpoint','publicKeySha256','clientCertificateSha256',
                   'issuerCaSha256','consoleCaSha256','notAfter'}
    SUMMARY_KEYS={'schemaVersion','requestId','candidateId','identityReceiptSha256','stageSha256',
                  'coreContextSha256','bindingGeneration'}

    def __init__(self,profile,local):
        self.profile,self.local=profile,local
        self.source=SourceUpdate(profile);self.root=profile.legacy.path(V2_STATE)
        descriptor=profile.descriptor();self.uid,self.gid=descriptor['uid'],descriptor['gid']
        self.core_uid,self.core_gid=local['kuraUid'],local['kuraGid']
        self.directories=set();self.files=set();self.core_assets=[];self.core_owners={};self.read_fingerprints={}
        self.actor='kura-uid:'+str(self.core_uid)

    @classmethod
    def summary(cls,value):
        if (not isinstance(value,dict) or set(value)!=cls.SUMMARY_KEYS
                or type(value['schemaVersion']) is not int or value['schemaVersion']!=1
                or type(value['bindingGeneration']) is not int or value['bindingGeneration']!=1):
            raise RuntimeError('Invalid original retained enrollment summary')
        for key in ['requestId','candidateId']:SourceUpdate.uuid(value[key])
        for key in ['identityReceiptSha256','stageSha256','coreContextSha256']:
            if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):
                raise RuntimeError('Invalid original retained enrollment digest')
        return value

    def name(self,path):
        return '/'+str(path.relative_to(self.profile.legacy.root))

    def directory(self,path,core=False,children=None):
        uid,gid=(self.core_uid,self.core_gid) if core else (self.uid,self.gid)
        m=path.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=uid or m.st_gid!=gid or stat.S_IMODE(m.st_mode)!=0o700:
            raise RuntimeError('Unsafe retained enrollment directory; preserve it')
        if children is not None and {p.name for p in path.iterdir()}!=set(children):
            raise RuntimeError('Incomplete, multiple or pending retained enrollment requires separate maintenance')
        if core:self.core_assets.append(path);self.core_owners[self.name(path)]=(uid,gid)
        else:self.directories.add(str(path.relative_to(self.root)))

    def read(self,path,core=False,limit=65536):
        uid,gid=(self.core_uid,self.core_gid) if core else (self.uid,self.gid)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME|os.O_NONBLOCK)
        try:
            m=os.fstat(fd)
            if (not stat.S_ISREG(m.st_mode) or m.st_uid!=uid or m.st_gid!=gid
                    or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o600 or m.st_size>limit):
                raise RuntimeError('Unsafe retained enrollment file; never repair by adoption')
            with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(limit+1)
            stable=lambda x:[x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
            if len(raw)>limit or stable(m)!=stable(os.fstat(fd)) or stable(m)!=stable(path.lstat()):
                raise RuntimeError('Retained enrollment changed during read')
            self.read_fingerprints[self.name(path)]=[*stable(m),self.source.digest(raw)]
        finally:os.close(fd)
        if core:self.core_assets.append(path);self.core_owners[self.name(path)]=(uid,gid)
        else:self.files.add(str(path.relative_to(self.root)))
        return raw

    @staticmethod
    def openssl(arguments,raw):
        try:
            result=subprocess.run(['/usr/bin/openssl',*arguments],input=raw,capture_output=True,timeout=5,check=True,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        except (subprocess.SubprocessError,OSError):
            raise RuntimeError('Retained identity crypto verification refused') from None
        if len(result.stdout)>65536:raise RuntimeError('Oversized retained identity crypto observation')
        return result.stdout

    @staticmethod
    def certificate_blocks(raw):
        blocks=re.findall(b'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n',raw)
        if not 1<=len(blocks)<=8 or b''.join(blocks)!=raw:
            raise RuntimeError('Invalid canonical retained public certificates')
        for block in blocks:
            try:base64.b64decode(b''.join(block.splitlines()[1:-1]),validate=True)
            except ValueError:raise RuntimeError('Invalid retained public certificate encoding') from None
        return blocks

    def inspect(self):
        if os.path.lexists(self.root/'identity-enrollment-pending.json'):
            raise RuntimeError('Pending original identity requires recovery, not source maintenance')
        base=self.root/'enrollment';self.directory(base,children={'identity.json','candidates'})
        raw=self.read(base/'identity.json',limit=16384);receipt=self.profile.legacy.reader_json(raw)
        if (not isinstance(receipt,dict) or set(receipt)!=self.RECEIPT_KEYS
                or receipt['schema']!='yofc.agent.enrollment.v1'
                or type(receipt['sourceUid']) is not int or receipt['sourceUid']!=self.core_uid
                or type(receipt['bindingGeneration']) is not int or receipt['bindingGeneration']!=1
                or receipt['actor']!=self.actor or not isinstance(receipt['operator'],str)
                or not 1<=len(receipt['operator'].encode())<=128 or any(unicodedata.category(c)=='Cc' for c in receipt['operator'])
                or type(receipt['acceptedAtUnixMs']) is not int or receipt['acceptedAtUnixMs']<=0):
            raise RuntimeError('Unreviewed retained identity receipt')
        request=self.source.uuid(receipt['requestId']);candidate=self.source.uuid(receipt['candidateId'])
        material=receipt['material']
        if (not isinstance(material,dict) or set(material)!=self.MATERIAL_KEYS
                or material['schema']!='yofc.kura.remote.certificates.v1' or material['requestId']!=request
                or not isinstance(material['gatewayId'],str)
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',material['gatewayId'])):
            raise RuntimeError('Unreviewed retained material manifest')
        for key in ['publicKeySha256','clientCertificateSha256','issuerCaSha256','consoleCaSha256']:
            if not isinstance(material[key],str) or not re.fullmatch('[0-9a-f]{64}',material[key]):
                raise RuntimeError('Invalid retained material fingerprint')
        try:
            endpoint=material['endpoint']
            if not isinstance(endpoint,str) or any(not 33<=ord(c)<=126 for c in endpoint):raise ValueError()
            address=urlsplit(endpoint)
            if (address.scheme!='https' or not address.hostname or address.username is not None or address.password is not None
                    or address.path not in ['','/'] or address.query or address.fragment
                    or address.port is not None and not 1<=address.port<=65535):raise ValueError()
            if not isinstance(material['notAfter'],str):raise ValueError()
            declared_expiry=datetime.datetime.strptime(material['notAfter'],'%Y-%m-%dT%H:%M:%SZ')
        except (ValueError,TypeError):raise RuntimeError('Invalid retained endpoint or certificate expiry') from None
        candidates=base/'candidates';self.directory(candidates,children={candidate});owned=candidates/candidate
        core=KuraMaterial(self.profile).source_root(self.local);context=core.parent/'management-enrollment-context-v1'
        self.directory(core.parent,core=True);context_raw=self.read(context,core=True,limit=128)
        parts=context_raw.decode('ascii').splitlines()
        if (len(parts)!=2 or parts[0]!='yofc.kura.remote-request-context.v1'
                or context_raw!=('yofc.kura.remote-request-context.v1\n'+self.source.uuid(parts[1])+'\n').encode()):
            raise RuntimeError('Original Core enrollment context is incomplete')
        self.directory(core,core=True,children={'.enrollment.lock',request})
        if self.read(core/'.enrollment.lock',core=True,limit=0):raise RuntimeError('Invalid original enrollment lock')
        slot=core/request;self.directory(slot,core=True,children=self.SOURCE_FILES|{'certificates'})
        self.directory(slot/'certificates',core=True,children=self.CERT_FILES)
        values={name:self.read(slot/name,core=True) for name in sorted(self.SOURCE_FILES)}
        values.update({'certificates/'+name:self.read(slot/'certificates'/name,core=True) for name in sorted(self.CERT_FILES)})
        manifest=values['certificates/manifest.json'];stage=self.source.digest(manifest)
        if (self.profile.legacy.reader_json(manifest)!=material or receipt['stageSha256']!=stage
                or values['certificates/complete']!=(stage+'\n').encode()
                or values['gateway.id']!=material['gatewayId'].encode() or values['complete']!=b'kura.remote.identity.v1\n'
                or self.source.digest(values['public.der'])!=material['publicKeySha256']):
            raise RuntimeError('Retained identity differs from its original Core stage')
        extra={'agent-key.pem'}
        expected_public={}
        for name in ['client-chain.pem','issuer-ca.pem','console-ca.pem']:
            pem=values['certificates/'+name];blocks=self.certificate_blocks(pem)
            if name!='client-chain.pem' and self.source.digest(pem)!=material['issuerCaSha256' if name=='issuer-ca.pem' else 'consoleCaSha256']:
                raise RuntimeError('Retained trust material fingerprint differs')
            for i,block in enumerate(blocks):
                expected_public[name+'-'+str(i)+'.certificate.pem']=block
                if name!='client-chain.pem':expected_public[name+'-'+str(i)+'.anchor.pem']=block
        leaf=self.certificate_blocks(values['certificates/client-chain.pem'])[0]
        leaf_der=base64.b64decode(b''.join(leaf.splitlines()[1:-1]),validate=True)
        if self.source.digest(leaf_der)!=material['clientCertificateSha256']:
            raise RuntimeError('Retained client certificate fingerprint differs')
        extra.update(expected_public)
        self.directory(owned,children=self.SOURCE_FILES|{'certificates','receipt.json','identity-complete','completed-intent.json'}|extra)
        self.directory(owned/'certificates',children=self.CERT_FILES)
        for name,value in values.items():
            copied=self.read(owned/name)
            if copied!=value or (owned/name).stat().st_ino==(slot/name).stat().st_ino and (owned/name).stat().st_dev==(slot/name).stat().st_dev:
                raise RuntimeError('Retained material is not an independent unchanged copy')
        for name,value in expected_public.items():
            if self.read(owned/name)!=value:raise RuntimeError('Retained derived certificate differs')
        for name in ['receipt.json','completed-intent.json']:
            if self.read(owned/name,limit=16384)!=raw:raise RuntimeError('Original identity completion receipt differs')
        if self.read(owned/'identity-complete',limit=65)!=(self.source.digest(raw)+'\n').encode():
            raise RuntimeError('Original identity completion marker differs')
        pub=lambda pem:self.openssl(['pkey','-pubin','-outform','DER'],pem)
        expected=values['public.der']
        if (self.openssl(['pkey','-inform','DER','-pubout','-outform','DER'],values['private.pk8'])!=expected
                or self.openssl(['pkey','-pubout','-outform','DER'],self.read(owned/'agent-key.pem'))!=expected
                or pub(self.openssl(['req','-pubkey','-noout'],values['request.pem']))!=expected
                or pub(self.openssl(['x509','-pubkey','-noout'],leaf))!=expected):
            raise RuntimeError('Retained key, CSR or certificate no longer matches')
        subject=self.openssl(['req','-verify','-noout','-subject','-nameopt','RFC2253'],values['request.pem'])
        if [x for x in subject.splitlines() if x.startswith(b'subject=')]!=[('subject=CN='+material['gatewayId']).encode()]:
            raise RuntimeError('Retained CSR subject differs')
        subject=self.openssl(['x509','-noout','-subject','-nameopt','RFC2253'],leaf)
        if subject.strip()!=('subject=CN='+material['gatewayId']).encode():
            raise RuntimeError('Retained client certificate subject differs')
        expiry=self.openssl(['x509','-noout','-enddate'],leaf).decode('ascii').strip()
        try:actual_expiry=datetime.datetime.strptime(expiry.removeprefix('notAfter='),'%b %d %H:%M:%S %Y %Z')
        except ValueError:raise RuntimeError('Invalid retained certificate expiry') from None
        if actual_expiry!=declared_expiry:raise RuntimeError('Retained certificate expiry differs')
        summary={'schemaVersion':1,'requestId':request,'candidateId':candidate,
                 'identityReceiptSha256':self.source.digest(raw),'stageSha256':stage,
                 'coreContextSha256':self.source.digest(context_raw),'bindingGeneration':1}
        return self.summary(summary)


class RetainedBusiness:
    """Authenticate an encrypted copy as the native UID; never migrate/repair it."""
    PROFILE='native-retained-business-source-v1'
    REPORT={'schemaVersion','profile','nativeUid','nativeGid','noNewPrivileges','inputFiles','inventory'}
    INVENTORY={'schemaVersion','profile','initializationId','tableCounts','executionStates',
               'unresolvedExecutions','schemaSha256','logicalSha256','recordsChanged','replayPerformed'}
    LIMIT=8*1024*1024*1024

    def __init__(self,source):
        self.source=source;self.profile=source.profile;self.legacy=source.legacy

    @staticmethod
    def sha(value):
        if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:
            raise RuntimeError('Invalid retained business digest')
        return value

    @staticmethod
    def number(value,maximum=1_000_000):
        if type(value) is not int or not 0<=value<=maximum:
            raise RuntimeError('Invalid retained business count or size')
        return value

    @classmethod
    def report(cls,value,identity,initialization,state=None):
        if (not isinstance(value,dict) or set(value)!=cls.REPORT or type(value['schemaVersion']) is not int
                or value['schemaVersion']!=1 or value['profile']!='native-retained-state-inspection-v1'
                or type(value['nativeUid']) is not int or value['nativeUid']!=identity['uid']
                or type(value['nativeGid']) is not int or value['nativeGid']!=identity['gid']
                or identity['uid']<=0 or identity['gid']<=0 or value['noNewPrivileges'] is not True):
            raise RuntimeError('Retained inspection is not its dedicated native identity')
        inventory=value['inventory'];SourceUpdate.uuid(initialization)
        if (not isinstance(inventory,dict) or set(inventory)!=cls.INVENTORY
                or type(inventory['schemaVersion']) is not int or inventory['schemaVersion']!=1
                or inventory['profile']!='native-execution-inventory-v1'
                or inventory['initializationId']!=initialization or inventory['recordsChanged'] is not False
                or inventory['replayPerformed'] is not False):
            raise RuntimeError('Retained inspection cannot change or replay original records')
        counts=inventory['tableCounts'];states=inventory['executionStates']
        if not isinstance(counts,dict) or set(counts)!=SourceUpdate.TABLES or not isinstance(states,dict):
            raise RuntimeError('Unreviewed retained business table or state inventory')
        for name,count in counts.items():
            cls.number(count,1024 if name.startswith('imported_remote_') else 1_000_000)
        if counts['native_profile_generation']!=1:
            raise RuntimeError('Retained business generation differs')
        for name,count in states.items():
            if not isinstance(name,str) or re.fullmatch('[A-Z][A-Z0-9_]{0,40}',name) is None:
                raise RuntimeError('Unreviewed retained execution state')
            cls.number(count)
        if (sum(states.values())!=counts['executions'] or cls.number(inventory['unresolvedExecutions'])
                !=states.get('RUNNING',0)+states.get('UNKNOWN',0)):
            raise RuntimeError('Retained unresolved execution inventory differs')
        cls.sha(inventory['schemaSha256']);cls.sha(inventory['logicalSha256'])
        inputs=value['inputFiles']
        if not isinstance(inputs,dict) or set(inputs) not in [{'results.sqlite'},{'results.sqlite','results.sqlite-wal'}]:
            raise RuntimeError('Retained inspection inputs differ')
        for name,item in inputs.items():
            if not isinstance(item,dict) or set(item)!={'bytes','sha256'}:
                raise RuntimeError('Unreviewed retained input proof')
            cls.number(item['bytes'],cls.LIMIT);cls.sha(item['sha256'])
            if name=='results.sqlite' and item['bytes']<4096:
                raise RuntimeError('Retained database input is incomplete')
            if state is not None:
                original=state.get(V2_STATE+'/'+name)
                if not isinstance(original,list) or len(original)!=10 or original[6]!=item['bytes'] or original[-1]!=item['sha256']:
                    raise RuntimeError('Retained inspection did not read its original byte-for-byte copy')
        if state is not None and ((V2_STATE+'/results.sqlite-wal' in state)!=('results.sqlite-wal' in inputs)):
            raise RuntimeError('Retained original WAL proof differs')
        return value

    @classmethod
    def bundle(cls,value,ticket):
        if (not isinstance(value,dict) or set(value)!={'schemaVersion','profile','packagePath','programSha256','report'}
                or type(value['schemaVersion']) is not int or value['schemaVersion']!=1 or value['profile']!=cls.PROFILE
                or not isinstance(value['packagePath'],str) or not value['packagePath'].startswith('/')
                or str(Path(value['packagePath']))!=value['packagePath'] or '..' in Path(value['packagePath']).parts
                or '\n' in value['packagePath'] or '\x00' in value['packagePath']
                or cls.sha(value['programSha256'])!=ticket['identity']['binarySha256']
                or not {'peerTransition','materialTransition','retainedEnrollment'}<=set(ticket)
                or 'loaderTransition' in ticket):
            raise RuntimeError('Original retained business source scope differs')
        cls.report(value['report'],ticket['identity'],ticket['initializationId'],ticket['state'])
        return value

    def image(self,package,package_sha,identity):
        # An already installed incoming program is still authenticated by all
        # three incoming pins. Otherwise retain the original reviewed package.
        if self.profile.descriptor()==identity:
            image=self.legacy.reader_file('/usr/bin/yofc-management-agent',mode=0o755,limit=512*1024*1024)
        else:
            pair,_=self.source.candidate(package,package_sha,inspection=True)
            if pair!={name:identity[name] for name in self.source.PINS}:
                raise RuntimeError('Original retained inspector package/source pair changed')
            image=self.source.incoming_inspector
        if image[:4]!=b'\x7fELF' or self.source.digest(image)!=identity['binarySha256']:
            raise RuntimeError('Original Root-paired retained inspector program differs')
        return image

    def fingerprint(self,path,identity,directory=False):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME|(os.O_DIRECTORY if directory else os.O_NONBLOCK))
        try:
            m=os.fstat(fd);maximum=16*1024*1024 if path.name=='results.sqlite-shm' else self.LIMIT
            if ((not stat.S_ISDIR(m.st_mode) if directory else not stat.S_ISREG(m.st_mode) or m.st_nlink!=1)
                    or m.st_uid!=identity['uid'] or m.st_gid!=identity['gid']
                    or stat.S_IMODE(m.st_mode)!=(0o700 if directory else 0o600) or m.st_size>maximum):
                raise RuntimeError('Unsafe original retained business input; never adopt it')
            stable=lambda a:[a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns]
            digest=None
            if not directory:
                with os.fdopen(os.dup(fd),'rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            if stable(m)!=stable(os.fstat(fd)) or stable(m)!=stable(path.lstat()):
                raise RuntimeError('Original retained business input changed during inspection')
            return stable(m)+[digest]
        finally:os.close(fd)

    def execute(self,image,directory,identity,initialization):
        self.profile.asset('/usr/bin/setpriv',0o755,2*1024*1024)
        if not hasattr(os,'memfd_create'):
            raise RuntimeError('Retained source inspection requires the explicit Linux native profile')
        fd=os.memfd_create('paired-native-retained-inspector',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(fd),'wb') as stream:stream.write(image);stream.flush()
            os.fchmod(fd,0o755)
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SEAL)
            groups=','.join(str(n) for n in sorted({identity['gid'],identity['readerGid']}))
            command=['/usr/bin/setpriv','--reuid='+str(identity['uid']),'--regid='+str(identity['gid']),
                '--groups='+groups,'--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',
                '/proc/self/fd/'+str(fd),'inspect-retained-state','--initialization-id',initialization,'--directory',str(directory)]
            result=subprocess.run(command,pass_fds=[fd],cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},
                                  capture_output=True,timeout=40)
            if result.returncode or len(result.stdout)>16384 or len(result.stderr)>8192:
                raise RuntimeError('Original retained native inspection refused; no records were repaired or replayed')
            return self.legacy.reader_json(result.stdout)
        finally:os.close(fd)

    def inspect(self,package,package_sha,identity,initialization):
        image=self.image(package,package_sha,identity)
        return self.inspect_image(image,identity,initialization)

    def inspect_image(self,image,identity,initialization):
        self.profile.directory('/run',0,0,0o755)
        root=self.legacy.path(V2_STATE)
        paths=[root]+[root/name for name in ['results.sqlite','results.sqlite.plan-key','.native-profile-v1',
            'results.sqlite-wal','results.sqlite-shm'] if os.path.lexists(root/name)]
        before={str(p):self.fingerprint(p,identity,p==root) for p in paths}
        if not all(str(root/name) in before for name in ['results.sqlite','results.sqlite.plan-key','.native-profile-v1']):
            raise RuntimeError('Original retained native state is incomplete')
        with tempfile.TemporaryDirectory(prefix='kura-source-inspection-',dir=self.legacy.path('/run')) as name:
            outer=Path(name);os.chmod(outer,0o711);copy=outer/'copy';copy.mkdir(mode=0o700);os.chown(copy,identity['uid'],identity['gid'])
            expected={}
            for name in ['results.sqlite','results.sqlite-wal']:
                original=root/name
                if str(original) not in before:continue
                src=os.open(original,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NOATIME)
                try:
                    dst=os.open(copy/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                    with os.fdopen(dst,'wb') as target,os.fdopen(os.dup(src),'rb') as source:
                        digest=hashlib.sha256();total=0
                        for chunk in iter(lambda:source.read(1024*1024),b''):
                            total+=len(chunk)
                            if total>self.LIMIT:raise RuntimeError('Retained native input exceeds its original bounded profile')
                            target.write(chunk);digest.update(chunk)
                        target.flush();os.fsync(target.fileno());os.fchown(target.fileno(),identity['uid'],identity['gid'])
                    expected[name]={'bytes':total,'sha256':digest.hexdigest()}
                finally:os.close(src)
                if expected[name]!={'bytes':before[str(original)][6],'sha256':before[str(original)][-1]}:
                    raise RuntimeError('Original retained copy changed while reading')
            report=self.report(self.execute(image,copy,identity,initialization),identity,initialization)
            if report['inputFiles']!=expected:
                raise RuntimeError('Retained inspection read different database/WAL bytes')
        after={str(p):self.fingerprint(p,identity,p==root) for p in paths}
        if before!=after or any(os.path.lexists(root/name)!=(str(root/name) in before) for name in ['results.sqlite-wal','results.sqlite-shm']):
            raise RuntimeError('Original native retained state changed; preserve its original maintenance')
        return report



class RetainedRemoval:
    """Package-only removal and reinstall of the original quiescent native pair."""

    PENDING = V2_ADMIN + '/.retained-removal-pending.json'
    RECORDS = V2_ADMIN + '/retained-removals'
    INITIALIZATION = V2_ADMIN + '/initialization.json'
    POSTRM = '/var/lib/dpkg/info/kura-management-agent.postrm'
    SOCKETS = ('kura-management-agent-enrollment.socket', 'kura-management-enrollment-reader.socket')
    PREVIOUS = {'removed': 'remove-admitted', 'purged': 'removed',
                'install-admitted': 'removed', 'reinstalled': 'install-admitted'}

    def __init__(self, profile):
        self.profile = profile
        self.legacy = profile.legacy
        self.source = SourceUpdate(profile)

    def record(self, operation, phase):
        return self.RECORDS + '/' + self.source.uuid(operation) + '/' + phase + '.json'

    def pending(self):
        return os.path.lexists(self.legacy.path(self.PENDING))

    def require_inactive(self):
        if self.pending():
            raise RuntimeError('Original native removal remains active; preserve its original UUID')
        records = self.legacy.path(self.RECORDS)
        if records.exists():
            self.profile.directory(self.RECORDS, 0, 0, 0o700)
            for entry in records.iterdir():
                operation = self.source.uuid(entry.name)
                self.profile.directory(self.RECORDS + '/' + operation, 0, 0, 0o700)
                ticket = self.source.optional(self.record(operation, 'intent'))
                if ticket is None or ticket.get('requestId') != operation or not self.phase(ticket, 'reinstalled'):
                    raise RuntimeError('Lost native removal marker; preserve the original removal records')

    def local_initialization(self, initialization=None):
        self.profile.directory(V2_ADMIN, 0, 0, 0o700)
        raw = self.source.raw(self.INITIALIZATION)
        original = self.legacy.reader_json(raw)
        if (set(original) != {'schemaVersion', 'operationId', 'identity', 'remoteEnabled',
                              'unitStarted', 'continuitySha256'}
                or type(original['schemaVersion']) is not int or original['schemaVersion'] != 1
                or original['remoteEnabled'] is not False or original['unitStarted'] is not False):
            raise RuntimeError('Original native removal requires its initialization receipt')
        current = self.source.uuid(original['operationId'])
        if initialization is not None and self.source.uuid(initialization) != current:
            raise RuntimeError('Different native installation; do not query the removal UUID here')
        self.profile.initialization_state(original, original['identity'])
        return current, self.source.digest(raw), original

    def ticket(self):
        current, digest, _ = self.local_initialization()
        ticket = self.source.json(self.PENDING)
        operation = self.source.uuid(ticket['requestId'])
        if (ticket.get('schemaVersion') != 1
                or (ticket['initializationId'], ticket['initializationReceiptSha256']) != (current, digest)):
            raise RuntimeError('Original native removal belongs to a different installation')
        if ticket != self.source.json(self.record(operation, 'intent')):
            raise RuntimeError('Original native removal intent changed')
        return ticket

    def stopped(self, payload_present):
        for unit in ('kura.service', 'kura-management-agent.service', V2_UNIT):
            self.profile.stopped(unit)
        for unit in (V2_UNIT, *self.SOCKETS):
            result = self.legacy.systemctl('show', unit, '--property=ActiveState',
                                           '--property=UnitFileState', '--property=DropInPaths')
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines()) if result is not None else {}
            if (fields.get('ActiveState') != 'inactive' or fields.get('DropInPaths') != ''
                    or fields.get('UnitFileState') not in ({'disabled'} if payload_present else {'', 'disabled'})):
                raise RuntimeError('Explicitly stop and disable the original Agent and both socket units')

    def inventory(self, identity, bridge, *, public_identity=None):
        _, _, original = self.local_initialization()
        uid, gid, reader = self.profile.account()
        if (identity['uid'], identity['gid'], identity['readerGid']) != (uid, gid, reader):
            raise RuntimeError('Original native removal account differs')
        self.profile.directory(V2_CONFIG, 0, 0, 0o700)
        public = self.profile.directory(V2_PUBLIC, 0, 0, 0o755)
        if {file.name for file in public.iterdir()} != {'agent.json', 'continuity.json'}:
            raise RuntimeError('Original unbound native removal requires its own public profile')
        self.profile.initialization_state(original, identity)
        if self.source.optional(V2_IDENTITY, 0o644) != (identity if public_identity is None else public_identity):
            raise RuntimeError('Original native removal public identity differs')
        self.source.verify_chain(original, identity, bridge)
        if self.source.optional(SourceUpdate.PENDING) is not None or KuraPeer(self.profile).members(gid):
            raise RuntimeError('Other native maintenance or control-group authority remains')
        raw = self.source.raw(V2_CONFIG + '/agent.env')
        if raw != self.legacy.serialize(self.profile.settings()).encode():
            raise RuntimeError('Original native removal requires the unbound configuration')
        with self.source.runtime_locks(identity):
            assets = self.source.initial_runtime_assets(identity)
            return self.source.snapshot_assets(identity, assets + [self.legacy.path(V2_IDENTITY)])

    def enrolled_inventory(self, identity, bridge, binding, *, public_identity=None, source_publication=None):
        """Recheck the captured bound profile, including when its Agent code is absent."""
        if set(binding) != {'peer', 'enrollment', 'business'}:
            raise RuntimeError('Original retained enrollment proof differs')
        peer = binding['peer']
        RetainedEnrollment.summary(binding['enrollment'])
        _, _, original = self.local_initialization()
        if self.profile.account() != (identity['uid'], identity['gid'], identity['readerGid']):
            raise RuntimeError('Original enrolled removal account differs')
        for name, mode in ((V2_ADMIN, 0o700), (V2_CONFIG, 0o700), (V2_PUBLIC, 0o755)):
            self.profile.directory(name, 0, 0, mode)
        kura = KuraPeer(self.profile)
        core = kura.core(identity, bridge)
        peer_core = {k: peer[k] for k in peer if k not in (
            'schemaVersion', 'profile', 'requestId', 'initializationId', 'nativeIdentitySha256', 'controlGid')}
        if (core != peer_core or self.source.optional(KuraPeer.PUBLIC, 0o644) != peer
                or kura.members(identity['gid']) != ['kurad'] or peer['controlGid'] != identity['gid']
                or peer['initializationId'] != original['operationId']
                or self.source.optional(V2_IDENTITY, 0o644) != (public_identity or identity)):
            raise RuntimeError('Original enrolled removal Kura authority differs')
        self.source.verify_chain(original, identity, bridge)
        self.profile.directory(V2_STATE, identity['uid'], identity['gid'], 0o700)
        core_source = KuraMaterial(self.profile).source_root(peer)
        core_context = core_source.parent / 'management-enrollment-context-v1'
        core_assets = [core_source.parent, core_context, core_source, *core_source.rglob('*')]
        owners = {'/' + str(p.relative_to(self.legacy.root)): (peer['kuraUid'], peer['kuraGid'])
                  for p in core_assets}
        admin = self.legacy.path(V2_ADMIN)
        assets = list(core_assets)
        for child in admin.iterdir():
            if '/' + str(child.relative_to(self.legacy.root)) in {self.PENDING, self.RECORDS}:
                continue
            assets.append(child)
            if child.is_dir() and not child.is_symlink():
                assets.extend(p for p in child.rglob('*')
                              if source_publication is None or
                              (p != source_publication and source_publication not in p.parents))
        assets += list(self.legacy.path(V2_CONFIG).rglob('*'))
        assets += list(self.legacy.path(V2_PUBLIC).rglob('*'))
        runtime = self.legacy.path(V2_STATE)
        assets += [runtime, *runtime.rglob('*')]
        report = binding['business']
        RetainedBusiness.report(report, identity, original['operationId'])
        if report['inventory']['unresolvedExecutions']:
            raise RuntimeError('Unresolved enrolled business must retain its original execution context')
        with self.source.runtime_locks(identity):
            return self.source.snapshot_assets(identity, assets, extra_config=['enrollment-relay-grant.json'],
                                               asset_owners=owners, business=report)

    def prepare_enrollment_inventory(self, identity, bridge, package, expected, initialization):
        peer = KuraPeer(self.profile).check()
        if peer is None or KuraMaterial(self.profile).check() is None:
            raise RuntimeError('Original enrolled removal requires its paired Kura and material authority')
        business = {'packagePath': package, 'packageSha256': expected,
                    'identity': identity, 'initializationId': initialization}
        baseline, summary = self.source.enrolled_snapshot(peer, business=business)
        binding = {'peer': peer, 'enrollment': summary, 'business': business['report']}
        state = self.enrolled_inventory(identity, bridge, binding)
        if any(state.get(name) != stamp for name, stamp in baseline.items()):
            raise RuntimeError('Original enrolled data changed during removal preparation')
        return binding, state

    def overlay_mount(self, state):
        """Identify a reusable root overlay without accepting bind-mounted state."""
        if self.legacy.root != Path('/'):
            return None
        with Path('/proc/self/mountinfo').open('rb') as mounts:
            raw = mounts.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            return None
        root_mount = None
        protected = (*state, V2_CONFIG, V2_ADMIN, V2_PUBLIC, V2_STATE, '/var/lib/dpkg')
        for entry in raw.splitlines():
            left, sep, right = entry.partition(b' - ')
            fields = left.split()
            if not sep or len(fields) < 6:
                return None
            point = re.sub(rb'\\([0-7]{3})', lambda m: bytes([int(m[1], 8)]), fields[4])
            if point == b'/':
                if root_mount is not None:
                    return None
                root_mount = (fields[2], fields[3], right.split())
            elif any(os.fsencode(path) == point or os.fsencode(path).startswith(point + b'/') for path in protected):
                return None
        if root_mount is None:
            return None
        dev, mount_root, filesystem = root_mount
        if mount_root != b'/' or len(filesystem) != 3 or filesystem[:2] != [b'overlay', b'overlay']:
            return None
        options = filesystem[2].split(b',')
        for name in (b'upperdir', b'workdir', b'lowerdir'):
            values = [entry.removeprefix(name + b'=') for entry in options if entry.startswith(name + b'=')]
            if len(values) != 1 or not values[0].startswith(b'/'):
                return None
        device = os.stat('/').st_dev
        if (dev != ('%d:%d' % (os.major(device), os.minor(device))).encode()
                or any(values[0] != device for values in state.values())):
            return None
        return {'device': device, 'overlaySha256': self.source.digest(b'\0'.join(filesystem))}

    def verify_inventory(self, ticket, state, *, updated_paths=(), added_source_record=False):
        original = ticket['state']
        mount = ticket.get('rootOverlay')
        if mount is not None:
            current = self.overlay_mount(state)
            if current is None or current['overlaySha256'] != mount['overlaySha256']:
                raise RuntimeError('Original native removal overlay backing differs')
            device = mount['device']
            if any(values[0] != device for values in original.values()):
                raise RuntimeError('Original native removal overlay inventory differs')
            original = {path: [current['device'], *values[1:]] for path, values in original.items()}
        original, state = original.copy(), state.copy()
        for name in updated_paths:
            # Caller has validated an exact replacement in the admitted publication.
            del state[name]
            original.pop(name, None)
        if added_source_record:
            name = self.source.RECORDS
            stamp = state.pop(name)
            before = original.pop(name, None)
            # The single admitted child changes the directory entries and times.
            # If it was already present, keep the original backing inode and mode.
            if before is not None and (stamp[:5] != before[:5] or stamp[5] not in (before[5], before[5] + 1)):
                raise RuntimeError('Original native source history directory changed')
        if original != state:
            raise RuntimeError('Original native removal data changed')

    def package_assets(self, package):
        path = self.legacy.path(package)
        payload = self.source.archive(path)
        controls = self.source.archive(path, control=True)
        return {**{'/' + name: [item['mode'], item['sha256']] for name, item in payload.items()},
                **{'/var/lib/dpkg/info/kura-management-agent.' + name: [controls[name]['mode'], controls[name]['sha256']]
                   for name in ('preinst', 'postinst', 'prerm', 'postrm')}}

    def installed_assets(self, assets):
        for path, (mode, digest) in assets.items():
            # Debian images may exclude reference examples via dpkg path
            # filters. These files never participate in runtime authority.
            if (path in self.source.SOURCE_PAYLOAD and path.startswith('/usr/share/doc/')
                    and not os.path.lexists(self.legacy.path(path))):
                continue
            maximum = 64 * 1024 * 1024 if path == '/usr/bin/yofc-management-agent' else 16 * 1024 * 1024
            if self.profile.asset(path, mode, maximum) != digest:
                raise RuntimeError('Installed Agent code or maintainer differs from the reviewed release')

    def version(self, states, *, removal_selection=False):
        status = '${Status}' if removal_selection else '${db:Status-Status}'
        result = self.legacy.run(['/usr/bin/dpkg-query', '-W', '-f=' + status + '\n${Version}\n',
                                  'kura-management-agent'], capture_output=True, text=True,
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        fields = result.stdout.splitlines()
        if result.returncode or len(fields) != 2 or fields[0] not in states:
            raise RuntimeError('Original native removal requires a known dpkg phase')
        return fields[1]

    def original_pair(self, ticket):
        return {key: ticket['identity'][key] for key in self.source.PINS}

    def recover_postrm(self, initialization, operation, package, expected):
        current, _, _ = self.local_initialization(initialization)
        self.source.uuid(operation)
        with self.source.package_locks():
            ticket = self.ticket()
            if ticket['requestId'] != operation or ticket['initializationId'] != current:
                raise RuntimeError('Only the original retained removal can recover its postrm')
            loader = ticket['bridge']['coreLoaderSha256']
            self.verify(self.original_pair(ticket), loader, payload_present=False)
            if self.version({'deinstall ok half-installed'}, removal_selection=True) != ticket['packageVersion']:
                raise RuntimeError('Original half-installed Agent package version differs')
            if not self.phase(ticket, 'remove-admitted') or self.phase(ticket, 'removed'):
                raise RuntimeError('Only an admitted, unfinished Agent postrm can be recovered')

            pair, _ = self.source.candidate(package, expected, original_bridge=ticket['bridge'])
            old_mode, old_sha = ticket['assets'][self.POSTRM]
            incoming = self.source.incoming_postrm
            incoming_sha = self.source.digest(incoming)
            if (old_mode != 0o755 or incoming_sha == old_sha
                    or self.profile.asset(package, 0o600, 64 * 1024 * 1024) != expected):
                raise RuntimeError('A different reviewed native postrm is required for recovery')
            record = {'schemaVersion': 1, 'requestId': operation,
                      'intentSha256': self.source.digest(self.profile.encode(ticket).encode()),
                      'reviewedPackageSha256': expected, 'reviewedPair': pair,
                      'originalPostrmSha256': old_sha, 'postrmSha256': incoming_sha}
            path = self.record(operation, 'postrm-recovery')
            old_path = path.removesuffix('.json') + '.previous'
            saved = self.source.optional(path)
            present = self.source.raw(self.POSTRM, 0o755)
            digest = self.source.digest(present)
            if digest == old_sha:
                if saved is not None and saved != record:
                    raise RuntimeError('Retain the original postrm recovery decision')
                self.source.immutable(old_path, present)
                self.source.immutable(path, self.profile.encode(record))
                self.source.replace(self.POSTRM, incoming, 0o755)
            elif saved != record or digest != incoming_sha:
                raise RuntimeError('Installed Agent postrm differs from its original or reviewed recovery script')
            self.recovered_postrm_pair(ticket, pair)
        return {'schemaVersion': 1, 'requestId': operation, 'phase': 'POSTRM_READY', 'unitStarted': False}

    def recovered_postrm_pair(self, ticket, pair):
        path = self.record(ticket['requestId'], 'postrm-recovery')
        record = self.source.optional(path)
        if record is None:
            return pair
        mode, original = ticket['assets'][self.POSTRM]
        archived = self.source.raw(path.removesuffix('.json') + '.previous')
        if (mode != 0o755 or self.source.digest(archived) != original
                or type(record.get('schemaVersion')) is not int or record['schemaVersion'] != 1
                or not re.fullmatch('[0-9a-f]{64}', str(record.get('reviewedPackageSha256')))
                or record.get('originalPostrmSha256') != original
                or record.get('requestId') != ticket['requestId']
                or record.get('intentSha256') != self.source.digest(self.profile.encode(ticket).encode())
                or record.get('reviewedPair') != pair
                or record.get('postrmSha256') != self.source.digest(self.source.raw(self.POSTRM, 0o755))):
            raise RuntimeError('Original postrm recovery proof differs')
        return self.original_pair(ticket)

    def prepare(self, initialization, operation, package, expected, *, enrolled=False):
        current, initialization_sha, _ = self.local_initialization(initialization)
        self.source.uuid(operation)
        if self.pending():
            ticket = self.ticket()
            if (ticket['requestId'] != operation or ticket['packageSha256'] != expected
                    or ('binding' in ticket) != enrolled):
                raise RuntimeError('Retain the original native removal UUID and reviewed package')
            return self.status(current, operation)
        self.require_inactive()
        if self.source.optional(self.record(operation, 'reinstalled')) is not None:
            return self.status(current, operation)
        with self.source.package_locks():
            identity = self.profile.check()
            self.stopped(payload_present=True)
            bridge = self.source.bridge()
            core = self.legacy.guard_core_loader(bridge['coreLoaderSha256'])
            paired, prerm = self.source.candidate(package, expected)
            assets = self.package_assets(package)
            version = self.version({'installed'})
            if (paired != {key: identity[key] for key in self.source.PINS}
                    or self.source.incoming_version != version
                    or prerm != self.source.raw(self.source.PRERM, 0o755)
                    or self.profile.asset(package, 0o600, 64 * 1024 * 1024) != expected):
                raise RuntimeError('Reviewed native removal package differs from the configured pair')
            self.installed_assets(assets)
            ticket = {'requestId': operation, 'schemaVersion': 1, 'initializationId': current,
                      'initializationReceiptSha256': initialization_sha, 'identity': identity, 'bridge': bridge,
                      'packageSha256': expected, 'packageVersion': version, 'coreHome': str(core) if core else None,
                      'assets': assets}
            if enrolled:
                ticket['binding'], ticket['state'] = self.prepare_enrollment_inventory(
                    identity, bridge, package, expected, current)
            else:
                ticket['state'] = self.inventory(identity, bridge)
            mount = self.overlay_mount(ticket['state'])
            if mount is not None:
                ticket['rootOverlay'] = mount
            self.profile.directory(self.RECORDS, 0, 0, 0o700, True)
            self.profile.directory(self.RECORDS + '/' + operation, 0, 0, 0o700, True)
            raw = self.profile.encode(ticket)
            self.source.immutable(self.record(operation, 'intent'), raw)
            self.source.immutable(self.PENDING, raw)
        return self.status(current, operation)

    def verify_root(self, ticket, loader, payload_present):
        if loader != ticket['bridge']['coreLoaderSha256']:
            raise RuntimeError('Core loader differs from the original retained removal pair')
        core = self.legacy.guard_core_loader(loader)
        if (str(core) if core else None) != ticket['coreHome']:
            raise RuntimeError('Core installation changed during original Agent removal')
        self.stopped(payload_present)

    def verify(self, pair, loader, payload_present):
        ticket = self.ticket()
        identity = ticket['identity']
        if pair != self.original_pair(ticket):
            raise RuntimeError('Native package differs from the original retained removal pair')
        self.verify_root(ticket, loader, payload_present)
        if payload_present:
            if self.profile.descriptor() != identity or self.source.bridge() != ticket['bridge']:
                raise RuntimeError('Installed native payload differs from the original removal pair')
            self.installed_assets(ticket['assets'])
        elif any(os.path.lexists(self.legacy.path(path)) for path in self.source.PAYLOAD):
            raise RuntimeError('Original Agent payload removal remains incomplete')
        if 'binding' in ticket:
            binding = ticket['binding']
            if payload_present:
                KuraMaterial(self.profile).maintenance_stopped(binding['peer'], retained=True)
            state = self.enrolled_inventory(identity, ticket['bridge'], binding)
        else:
            state = self.inventory(identity, ticket['bridge'])
        self.verify_inventory(ticket, state)
        return ticket

    def phase(self, ticket, name, *, publish=False):
        operation = ticket['requestId']
        record = {'schemaVersion': 1, 'requestId': operation, 'phase': name,
                  'intentSha256': self.source.digest(self.profile.encode(ticket).encode())}
        path = self.record(operation, name)
        saved = self.source.optional(path)
        if saved is None and not publish:
            return False
        previous = self.PREVIOUS.get(name)
        if previous is not None and not self.phase(ticket, previous):
            raise RuntimeError('Original native removal is missing its previous phase')
        if saved is None:
            self.source.immutable(path, self.profile.encode(record))
        elif saved != record:
            raise RuntimeError('Original native removal phase receipt changed')
        return True

    def admit_removal(self, pair, loader):
        ticket = self.verify(pair, loader, payload_present=True)
        if self.version({'half-configured'}) != ticket['packageVersion']:
            raise RuntimeError('Configured Agent version changed before original removal')
        if self.phase(ticket, 'remove-admitted'):
            raise RuntimeError('Original native removal already admitted; observe its phase before proceeding')
        self.phase(ticket, 'remove-admitted', publish=True)

    def finish_removal(self, pair, loader, purge):
        pair = self.recovered_postrm_pair(self.ticket(), pair)
        ticket = self.verify(pair, loader, payload_present=False)
        states = {'config-files'} if purge else {'half-installed'}
        if self.version(states) != ticket['packageVersion']:
            raise RuntimeError('Agent version changed during original removal or purge')
        self.phase(ticket, 'purged' if purge else 'removed', publish=True)

    def encoded_sha(self, value):
        return self.source.digest(self.profile.encode(value).encode())

    def successor(self, ticket):
        plan = self.source.optional(self.record(ticket['requestId'], 'successor'))
        if plan is not None:
            identity = ticket['identity']
            incoming = plan['identity']
            fields = {'schemaVersion', 'requestId', 'intentSha256', 'previousPair',
                      'identity', 'assets', 'packageVersion', 'packageSha256'}
            if 'binding' in ticket:
                fields |= {'peerTransition', 'materialTransition'}
            if (set(plan) != fields
                    or type(plan['schemaVersion']) is not int or plan['schemaVersion'] != 1
                    or plan['requestId'] != ticket['requestId'] or plan['intentSha256'] != self.encoded_sha(ticket)
                    or set(incoming) != set(identity) or incoming == identity
                    or any(identity[k] != incoming[k] for k in identity.keys() - self.source.PINS)
                    or not re.fullmatch('[0-9a-f]{64}', str(plan['packageSha256']))):
                raise RuntimeError('Reviewed successor differs from the original retained removal')
            if 'binding' in ticket:
                self.verify_authority_plan(ticket, plan)
        return plan

    def verify_authority_plan(self, ticket, plan):
        value = {**plan, 'previousIdentity': ticket['identity'], 'initializationId': ticket['initializationId']}
        peer_update = self.source.peer_transition(value)
        material_update = self.source.material_transition(value)
        peer, peer_sha = KuraPeer(self.profile).original()
        material, material_sha = KuraMaterial(self.profile).original()
        if (peer_update['previous'] != ticket['binding']['peer']
                or (peer_update['authorizationId'], peer_update['authorizationResultSha256']) != (peer['requestId'], peer_sha)
                or (material_update['authorizationId'], material_update['authorizationResultSha256']) !=
                   (material['requestId'], material_sha)):
            raise RuntimeError('Enrolled successor differs from the original Kura and material proof')
        if self.encoded_sha(material_update['previous']) != ticket['state'][KuraMaterial.PUBLIC][-1]:
            raise RuntimeError('Enrolled successor differs from the captured material authority')
        self.source.material_history(material, material_sha, material_update['previous'], plan['previousPair'])

    def prepare_successor(self, initialization, operation, package, expected):
        current, _, _ = self.local_initialization(initialization)
        self.source.uuid(operation)
        with self.source.package_locks():
            ticket = self.ticket()
            if ticket['requestId'] != operation or ticket['initializationId'] != current:
                raise RuntimeError('Only the original retained removal can prepare its successor')
            self.verify(self.original_pair(ticket), ticket['bridge']['coreLoaderSha256'], payload_present=False)
            if not self.phase(ticket, 'removed') or self.phase(ticket, 'install-admitted'):
                raise RuntimeError('Original removal must be complete before reviewing a successor')
            if self.phase(ticket, 'purged'):
                status = self.legacy.run(['/usr/bin/dpkg-query', '-W', '-f=${Status}', 'kura-management-agent'],
                                         capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                if status.returncode != 1 or status.stdout:
                    raise RuntimeError('Original Agent purge is not complete in dpkg')
            elif self.version({'deinstall ok config-files'}, removal_selection=True) != ticket['packageVersion']:
                raise RuntimeError('Original removed Agent package version differs')
            binding = ticket.get('binding')
            pair, _ = self.source.candidate(package, expected, inspection=binding is not None,
                                            original_bridge=ticket['bridge'])
            version = self.source.incoming_version
            order = self.legacy.run(['/usr/bin/dpkg', '--compare-versions', version, 'gt', ticket['packageVersion']])
            if order.returncode != 0 or pair == self.original_pair(ticket):
                raise RuntimeError('Reviewed successor must be a newer native source pair')
            assets = self.package_assets(package)
            if self.profile.asset(package, 0o600, 64 * 1024 * 1024) != expected:
                raise RuntimeError('Reviewed native successor archive changed')
            if os.path.lexists(self.legacy.path(self.source.record(operation, 'result.json').rsplit('/', 1)[0])):
                raise RuntimeError('Original removal UUID already belongs to a source publication')
            plan = {'schemaVersion': 1, 'requestId': operation, 'intentSha256': self.encoded_sha(ticket),
                    'previousPair': self.source.optional(self.source.CURRENT), 'identity': {**ticket['identity'], **pair},
                    'packageVersion': version, 'packageSha256': expected, 'assets': assets}
            if binding is not None:
                material = KuraMaterial(self.profile)
                old, authorization_sha = material.original()
                previous = self.source.current_material(old, authorization_sha)
                authority = {**plan, 'previousIdentity': ticket['identity'], 'initializationId': current}
                self.source.bind_authorities(authority, binding['peer'], previous)
                plan.update({name: authority[name] for name in ('peerTransition', 'materialTransition')})
                self.verify_authority_plan(ticket, plan)
                with self.source.runtime_locks(plan['identity']):
                    report = RetainedBusiness(self.source).inspect_image(
                        self.source.incoming_inspector, plan['identity'], current)
                if report != binding['business']:
                    raise RuntimeError('Reviewed successor does not retain the original authenticated business inventory')
                self.verify(self.original_pair(ticket), ticket['bridge']['coreLoaderSha256'], payload_present=False)
                if self.profile.asset(package, 0o600, 64 * 1024 * 1024) != expected:
                    raise RuntimeError('Reviewed native successor archive changed')
            self.source.immutable(self.record(operation, 'successor'), self.profile.encode(plan))
        return {'schemaVersion': 1, 'requestId': operation, 'phase': 'SUCCESSOR_READY', 'unitStarted': False}

    def successor_source_receipt(self, ticket, plan):
        result = {'schemaVersion': 1, 'requestId': ticket['requestId'], 'initializationId': ticket['initializationId'],
                'initializationReceiptSha256': ticket['initializationReceiptSha256'], 'previousPair': plan['previousPair'],
                'previousIdentity': ticket['identity'], 'identity': plan['identity'], 'packageSha256': plan['packageSha256'],
                'stateFingerprintSha256': self.encoded_sha(ticket['state']), 'unitStarted': False,
                'retainedRemoval': {'intentSha256': self.encoded_sha(ticket), 'successorSha256': self.encoded_sha(plan)}}
        if 'binding' in ticket:
            result.update({name: plan[name] for name in ('peerTransition', 'materialTransition')})
        return result

    def finish_enrolled_successor(self, ticket, plan, result, pointer, path):
        peer_update, material_update = plan['peerTransition'], plan['materialTransition']
        material = KuraMaterial(self.profile)
        material.maintenance_stopped(peer_update['incoming'], retained=True)
        public, _ = material.context(material_update['authorizationId'], peer_update['incoming'])
        if public != material_update['incoming']:
            raise RuntimeError('Installed successor material pair differs from the reviewed source')

        def encode(value):
            return self.profile.encode(value).encode()

        publications = {
            V2_IDENTITY: (0o644, encode(ticket['identity']), encode(plan['identity'])),
            KuraPeer.PUBLIC: (0o644, encode(peer_update['previous']), encode(peer_update['incoming'])),
            material.RELAY: (0o600, material.private_bytes(material_update['previous']),
                             material.private_bytes(material_update['incoming'])),
            material.PUBLIC: (0o644, encode(material_update['previous']), encode(material_update['incoming'])),
            self.source.CURRENT: (0o600, None if plan['previousPair'] is None else encode(plan['previousPair']),
                                  encode(pointer)),
        }
        updated = []
        incomplete = False
        for name, (mode, previous, incoming) in publications.items():
            actual = self.source.raw(name, mode) if os.path.lexists(self.legacy.path(name)) else None
            if actual == previous:
                incomplete |= previous != incoming
            elif actual == incoming and not incomplete:
                updated.append(name)
            else:
                raise RuntimeError('Enrolled successor is outside its admitted publication sequence')
        folder = self.legacy.path(path).parent
        added = os.path.lexists(folder)
        source_root_added = self.source.RECORDS not in ticket['state'] and os.path.lexists(folder.parent)
        if source_root_added:
            self.profile.directory(self.source.RECORDS, 0, 0, 0o700)
            if any(entry != folder for entry in folder.parent.iterdir()):
                raise RuntimeError('Enrolled successor contains an unreviewed source history')
        saved = self.source.optional(path)
        if added:
            self.profile.directory('/' + str(folder.relative_to(self.legacy.root)), 0, 0, 0o700)
            expected_files = {'result.json'} if saved is not None else set()
            if {entry.name for entry in folder.iterdir()} != expected_files:
                raise RuntimeError('Enrolled successor contains an unreviewed source publication')
        if (saved is not None and saved != result) or (updated and saved is None):
            raise RuntimeError('Enrolled successor publication differs from its original proof')
        chain = plan['identity'] if self.source.CURRENT in updated else ticket['identity']
        native = plan['identity'] if V2_IDENTITY in updated else ticket['identity']
        peer = peer_update['incoming'] if KuraPeer.PUBLIC in updated else peer_update['previous']
        state = self.enrolled_inventory(chain, ticket['bridge'], {**ticket['binding'], 'peer': peer},
                                        public_identity=native, source_publication=folder if added else None)
        self.verify_inventory(ticket, state, updated_paths=updated, added_source_record=added or source_root_added)
        self.profile.directory(self.source.RECORDS, 0, 0, 0o700, True)
        self.profile.directory('/' + str(folder.relative_to(self.legacy.root)), 0, 0, 0o700, True)
        self.source.immutable(path, encode(result))
        for name, (mode, _, incoming) in publications.items():
            self.source.replace(name, incoming, mode)
        self.profile.initialization(plan['identity'])
        KuraPeer(self.profile).check()
        material.check()
        KuraRemoteSwitch(self.profile).check()
        NativeTransport(self.profile).check()

    def finish_successor(self, ticket, plan, pair, loader):
        identity = plan['identity']
        if not self.phase(ticket, 'install-admitted') or pair != {k: identity[k] for k in self.source.PINS}:
            raise RuntimeError('Incoming Agent source pair lacks its original successor admission')
        self.verify_root(ticket, loader, payload_present=True)
        if self.profile.descriptor() != identity or self.source.bridge() != ticket['bridge']:
            raise RuntimeError('Installed native successor differs from the reviewed source pair')
        self.installed_assets(plan['assets'])
        if self.version({'unpacked', 'half-configured'}) != plan['packageVersion']:
            raise RuntimeError('Installed Agent version differs from the approved successor')

        operation = ticket['requestId']
        result = self.successor_source_receipt(ticket, plan)
        pointer = {'schemaVersion': 1, 'requestId': operation, 'sha256': self.encoded_sha(result)}
        path = self.source.record(operation, 'result.json')
        if 'binding' in ticket:
            self.finish_enrolled_successor(ticket, plan, result, pointer, path)
            return
        public = self.source.optional(V2_IDENTITY, 0o644)
        current = self.source.optional(self.source.CURRENT)
        published = public == identity
        if (public not in [ticket['identity'], identity] or current not in [plan['previousPair'], pointer]
                or (current == pointer and not published)
                or (published and self.source.optional(path) != result)):
            raise RuntimeError('Native successor publication is outside its original retained proof')
        chain = identity if current == pointer else ticket['identity']
        state = self.inventory(chain, ticket['bridge'], public_identity=public)
        self.verify_inventory(ticket, state, updated_paths=[V2_IDENTITY] if published else [])
        self.profile.directory(self.source.RECORDS, 0, 0, 0o700, True)
        self.profile.directory(self.source.RECORDS + '/' + operation, 0, 0, 0o700, True)
        self.source.immutable(path, self.profile.encode(result))
        self.source.replace(V2_IDENTITY, self.profile.encode(identity).encode(), 0o644)
        self.source.replace(self.source.CURRENT, self.profile.encode(pointer).encode(), 0o600)
        self.profile.initialization(identity)

    def admit_install(self, pair, loader, version):
        ticket = self.ticket()
        plan = self.successor(ticket)
        expected = plan or ticket
        if pair != {k: expected['identity'][k] for k in self.source.PINS}:
            raise RuntimeError('Incoming native package differs from the original approved pair')
        self.verify(self.original_pair(ticket), loader, payload_present=False)
        incoming = version or self.version({'half-installed'})
        if incoming != expected['packageVersion']:
            raise RuntimeError('Incoming Agent version differs from the original retained package')
        self.phase(ticket, 'install-admitted', publish=True)

    def finish_install(self, pair, loader):
        ticket = self.ticket()
        plan = self.successor(ticket)
        if plan is None:
            self.verify(pair, loader, payload_present=True)
            if self.version({'unpacked', 'half-configured'}) != ticket['packageVersion']:
                raise RuntimeError('Reinstalled Agent version differs from the original retained package')
        else:
            self.finish_successor(ticket, plan, pair, loader)
        self.phase(ticket, 'reinstalled', publish=True)
        path = self.legacy.path(self.PENDING)
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def status(self, initialization, operation):
        current, digest, _ = self.local_initialization(initialization)
        ticket = self.source.optional(self.record(operation, 'intent'))
        phase = 'NOT_FOUND'
        if ticket is not None:
            if (ticket.get('schemaVersion') != 1 or ticket.get('requestId') != operation
                    or (ticket['initializationId'], ticket['initializationReceiptSha256']) != (current, digest)):
                raise RuntimeError('Original native removal belongs to a different installation')
            phase = 'PREPARED'
            for name, state in [('reinstalled', 'REINSTALLED'), ('install-admitted', 'INSTALL_ADMITTED'),
                                ('purged', 'PURGED'), ('removed', 'REMOVED'), ('remove-admitted', 'REMOVE_ADMITTED')]:
                if self.phase(ticket, name):
                    phase = state
                    break
            if phase == 'REINSTALLED' and self.pending() and self.ticket() == ticket:
                phase = 'INSTALL_ADMITTED'
            if phase != 'REINSTALLED' and (not self.pending() or self.ticket() != ticket):
                raise RuntimeError('Lost native removal marker; preserve the original removal records')
        return {'schemaVersion': 1, 'requestId': operation, 'phase': phase, 'unitStarted': False}


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Fixed non-Root native agent profile controller')
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('check')
    actions.add_parser('inspect')
    initialize = actions.add_parser('initialize')
    initialize.add_argument('--request-id', required=True)
    status = actions.add_parser('status')
    status.add_argument('--request-id', required=True)
    for name in ('prepare-retained-removal', 'prepare-retained-enrolled-removal', 'prepare-retained-postrm-recovery',
                 'prepare-retained-successor', 'retained-removal-status'):
        removal = actions.add_parser(name)
        removal.add_argument('--request-id', required=True)
        removal.add_argument('--initialization-id', required=True)
        if name.startswith('prepare-'):
            removal.add_argument('--package', required=True)
            removal.add_argument('--sha256', required=True)
    update = actions.add_parser('prepare-source-update')
    update.add_argument('--request-id', required=True)
    update.add_argument('--package', required=True)
    update.add_argument('--sha256', required=True)
    loader_update = actions.add_parser('prepare-uninstalled-core-loader-update')
    loader_update.add_argument('--request-id', required=True)
    loader_update.add_argument('--package', required=True)
    loader_update.add_argument('--sha256', required=True)
    bridge_update = actions.add_parser('prepare-unbound-java-bridge-update')
    bridge_update.add_argument('--request-id', required=True)
    bridge_update.add_argument('--package', required=True)
    bridge_update.add_argument('--sha256', required=True)
    local_update = actions.add_parser('prepare-local-kura-source-update')
    local_update.add_argument('--request-id', required=True)
    local_update.add_argument('--package', required=True)
    local_update.add_argument('--sha256', required=True)
    material_update = actions.add_parser('prepare-material-kura-source-update')
    material_update.add_argument('--request-id', required=True)
    material_update.add_argument('--package', required=True)
    material_update.add_argument('--sha256', required=True)
    enrolled_update = actions.add_parser('prepare-enrolled-material-kura-source-update')
    enrolled_update.add_argument('--request-id', required=True)
    enrolled_update.add_argument('--package', required=True)
    enrolled_update.add_argument('--sha256', required=True)
    business_update=actions.add_parser('prepare-retained-business-material-kura-source-update')
    business_update.add_argument('--request-id',required=True)
    business_update.add_argument('--package',required=True)
    business_update.add_argument('--sha256',required=True)
    for command in [update,loader_update,bridge_update,local_update,material_update,enrolled_update,business_update]:
        command.add_argument('--initialization-id',required=True)
    companion_update = actions.add_parser('prepare-kura-companion-update')
    companion_update.add_argument('--request-id',required=True)
    companion_update.add_argument('--initialization-id',required=True)
    companion_update.add_argument('--preserve-material-authorization')
    for component in ('core','networking'):
        companion_update.add_argument('--'+component+'-package',required=True)
        companion_update.add_argument('--'+component+'-sha256',required=True)
    complete_update = actions.add_parser('complete-source-update')
    complete_update.add_argument('--request-id', required=True)
    complete_update.add_argument('--initialization-id', required=True)
    update_status = actions.add_parser('source-update-status')
    update_status.add_argument('--request-id', required=True)
    update_status.add_argument('--initialization-id', required=True)
    for name in ['complete-retained-business-source-update','retained-business-source-status']:
        command=actions.add_parser(name);command.add_argument('--request-id',required=True)
        command.add_argument('--initialization-id',required=True)
    for name in ['authorize-kura-peer','complete-kura-peer','kura-peer-status']:
        peer=actions.add_parser(name);peer.add_argument('--request-id',required=True)
    for name in ['authorize-enrollment-reader','complete-enrollment-reader','enrollment-reader-status']:
        material=actions.add_parser(name);material.add_argument('--request-id',required=True)
    for name in ['authorize-kura-remote-switch','complete-kura-remote-switch','kura-remote-switch-status']:
        control=actions.add_parser(name);control.add_argument('--request-id',required=True)
        control.add_argument('--initialization-id',required=True)
    for name in ['configure-native-transport-endpoint','complete-native-transport-endpoint','native-transport-endpoint-status']:
        transport=actions.add_parser(name);transport.add_argument('--request-id',required=True)
        transport.add_argument('--initialization-id',required=True)
        if name=='configure-native-transport-endpoint':transport.add_argument('--endpoint',required=True)
    for name in ('configure-configuration-write', 'configuration-write-status'):
        config_write = actions.add_parser(name)
        config_write.add_argument('--initialization-id', required=True)
        if name == 'configure-configuration-write':
            config_write.add_argument('--enabled', choices=('yes', 'no'), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Use the fixed Root native profile inspection')
    setup_source = Path(__file__).resolve().with_name('setup.py')
    spec = importlib.util.spec_from_file_location('_kura_agent_setup', setup_source)
    legacy = importlib.util.module_from_spec(spec)
    # Read the paired source directly. Root maintenance must not create or
    # execute an unmanaged bytecode cache in the package's program directory.
    exec(compile(setup_source.read_bytes(), str(setup_source), 'exec'), legacy.__dict__)
    lock = Path('/run/lock/kura-management-agent-setup.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        m = os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1 or m.st_mode & 0o077:
            raise RuntimeError('Unsafe native profile inspection lock')
        try:fcntl.flock(stream, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('BUSY: preserve the original native setup operation; do not redispatch') from None
        setup = RuntimeSetup(legacy.Setup())
        if args.action == 'inspect':
            print(json.dumps(setup.inspect()))
        elif args.action == 'initialize':
            created = setup.initialize(args.request_id)
            print(json.dumps({'schemaVersion': 1, 'requestId': args.request_id, 'initialized': True, 'created': created,
                              'remoteEnabled': False, 'unitStarted': False}))
        elif args.action == 'status':
            print(json.dumps(setup.status(args.request_id)))
        elif args.action in ('prepare-retained-removal', 'prepare-retained-enrolled-removal'):
            print(json.dumps(RetainedRemoval(setup).prepare(
                args.initialization_id, args.request_id, args.package, args.sha256,
                enrolled=args.action == 'prepare-retained-enrolled-removal')))
        elif args.action == 'prepare-retained-postrm-recovery':
            print(json.dumps(RetainedRemoval(setup).recover_postrm(
                args.initialization_id, args.request_id, args.package, args.sha256)))
        elif args.action == 'prepare-retained-successor':
            print(json.dumps(RetainedRemoval(setup).prepare_successor(
                args.initialization_id, args.request_id, args.package, args.sha256)))
        elif args.action == 'retained-removal-status':
            print(json.dumps(RetainedRemoval(setup).status(args.initialization_id, args.request_id)))
        elif args.action == 'prepare-kura-companion-update':
            source=SourceUpdate(setup)
            source.namespace(args.initialization_id)
            print(json.dumps(KuraCompanionUpdate(source).prepare(args.initialization_id,args.request_id,
                (args.core_package,args.core_sha256),(args.networking_package,args.networking_sha256),
                args.preserve_material_authorization)))
        elif args.action in ['prepare-source-update','prepare-uninstalled-core-loader-update','prepare-unbound-java-bridge-update',
                             'prepare-local-kura-source-update','prepare-material-kura-source-update',
                             'prepare-enrolled-material-kura-source-update',
                             'prepare-retained-business-material-kura-source-update']:
            source=SourceUpdate(setup)
            source.namespace(args.initialization_id)
            source.uninstalled_core_loader=args.action=='prepare-uninstalled-core-loader-update'
            source.unbound_java_bridge=args.action=='prepare-unbound-java-bridge-update'
            source.local_kura_peer=args.action=='prepare-local-kura-source-update'
            source.material_kura_peer=args.action in ['prepare-material-kura-source-update',
                'prepare-enrolled-material-kura-source-update','prepare-retained-business-material-kura-source-update']
            source.enrolled_material_kura_peer=args.action in ['prepare-enrolled-material-kura-source-update',
                'prepare-retained-business-material-kura-source-update']
            source.retained_business=args.action=='prepare-retained-business-material-kura-source-update'
            print(json.dumps(source.prepare(args.request_id, args.package, args.sha256)))
        elif args.action in ['complete-source-update','source-update-status',
                            'complete-retained-business-source-update','retained-business-source-status']:
            source=SourceUpdate(setup);source.namespace(args.initialization_id)
            if args.action.startswith('complete-'):
                print(json.dumps(source.complete(args.request_id)))
            else:print(json.dumps(source.status(args.request_id)))
        elif args.action == 'authorize-kura-peer':
            print(json.dumps(KuraPeer(setup).authorize(args.request_id)))
        elif args.action == 'complete-kura-peer':
            print(json.dumps(KuraPeer(setup).complete(args.request_id)))
        elif args.action == 'kura-peer-status':
            print(json.dumps(KuraPeer(setup).status(args.request_id)))
        elif args.action == 'authorize-enrollment-reader':
            print(json.dumps(KuraMaterial(setup).authorize(args.request_id)))
        elif args.action == 'complete-enrollment-reader':
            print(json.dumps(KuraMaterial(setup).complete(args.request_id)))
        elif args.action == 'enrollment-reader-status':
            print(json.dumps(KuraMaterial(setup).status(args.request_id)))
        elif args.action in ['authorize-kura-remote-switch','complete-kura-remote-switch','kura-remote-switch-status']:
            print(json.dumps(setup.remote_switch_action(args.action,args.request_id,args.initialization_id)))
        elif args.action in ['configure-native-transport-endpoint','complete-native-transport-endpoint','native-transport-endpoint-status']:
            print(json.dumps(setup.transport_action(args.action,args.request_id,args.initialization_id,getattr(args,'endpoint',None))))
        elif args.action in ('configure-configuration-write', 'configuration-write-status'):
            enabled = args.enabled == 'yes' if args.action == 'configure-configuration-write' else None
            print(json.dumps(setup.configuration_write_action(args.initialization_id, enabled)))
        else:
            setup.check()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Native agent setup refused: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__),
              file=sys.stderr)
        sys.exit(1)
