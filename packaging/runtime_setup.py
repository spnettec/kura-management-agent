#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Native non-Root profile primitives. No legacy adoption or implicit repair.

The package/UI controller supplies the original initialization UUID. This module
does not create users, stop services, start a unit or reinterpret retained data.
Native enrollment authorization and legacy migration are separate work.
"""
import fcntl
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
import threading
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

    def asset(self, name, mode=0o644, maximum=2 * 1024 * 1024):
        path = self.legacy.path(name)
        self.legacy.authorization_parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME)
        with os.fdopen(fd, 'rb') as source:
            m = os.fstat(source.fileno())
            if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_gid != 0
                    or stat.S_IMODE(m.st_mode) != mode or m.st_nlink != 1 or m.st_size > maximum):
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

    def continuity(self, operation, descriptor):
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
        continuity = self.encode(self.continuity(operation, descriptor))
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
        if os.path.lexists(self.legacy.path(V2_ADMIN + '/.initialization-pending')):
            raise RuntimeError('Native initialization has an uncertain original outcome; preserve all files')
        if os.path.lexists(self.legacy.path(V2_ADMIN + '/.source-update-pending.json')):
            raise RuntimeError('Native source update has an uncertain original outcome; preserve its original UUID')
        SourceUpdate(self).no_orphan()
        self.stopped('kura-management-agent.service')
        descriptor = self.descriptor()
        for name, uid, gid, mode in [(V2_ADMIN, 0, 0, 0o700), (V2_CONFIG, 0, 0, 0o700),
                (V2_PUBLIC, 0, 0, 0o755), (V2_STATE, descriptor['uid'], descriptor['gid'], 0o700)]:
            self.directory(name, uid, gid, mode)
        actual = self.legacy.reader_json(self.legacy.reader_file(V2_IDENTITY))
        original = self.legacy.reader_json(self.legacy.reader_file(V2_ADMIN + '/initialization.json', mode=0o600))
        if (actual != descriptor or set(original) != {'schemaVersion', 'operationId', 'identity', 'remoteEnabled', 'unitStarted', 'continuitySha256'}
                or type(original.get('schemaVersion')) is not int or original.get('schemaVersion') != 1
                or original.get('remoteEnabled') is not False or original.get('unitStarted') is not False):
            raise RuntimeError('Native runtime identity/source pair changed')
        SourceUpdate(self).verify_chain(original, descriptor)
        operation = original['operationId']
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise RuntimeError('Original native initialization UUID changed')
        marker = self.legacy.path(V2_STATE + '/.native-profile-v1')
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            m = os.fstat(source.fileno())
            if (not stat.S_ISREG(m.st_mode) or m.st_uid != descriptor['uid'] or m.st_gid != descriptor['gid']
                    or stat.S_IMODE(m.st_mode) != 0o600 or m.st_nlink != 1 or m.st_size > 4096):
                raise RuntimeError('Retained native runtime marker requires recovery')
            marker_value = self.legacy.reader_json(source.read(4097))
        if marker_value != {'schemaVersion': 1, 'operationId': operation}:
            raise RuntimeError('Retained native runtime marker differs from its original initialization')
        continuity_raw = self.legacy.reader_file(V2_CONTINUITY, limit=4096)
        if (hashlib.sha256(continuity_raw).hexdigest() != original['continuitySha256']
                or self.legacy.reader_json(continuity_raw) != self.continuity(operation, descriptor)):
            raise RuntimeError('Native state continuity changed; retain the original recovery intent')
        raw = self.legacy.reader_file(V2_CONFIG + '/agent.env', mode=0o600)
        settings = {}
        for line in raw.decode().splitlines():
            key, sep, value = line.partition('=')
            if not sep or key in settings:
                raise RuntimeError('Invalid native environment')
            settings[key] = value
        # Only the initial, unbound capability set is provisioned by this
        # primitive. Separate reviewed authorization methods must add choices.
        if settings != self.settings():
            raise RuntimeError('Native authorization/migration is not installed for this configuration')
        result = self.legacy.systemctl('show', V2_UNIT, '--property=LoadState', '--property=FragmentPath',
                                       '--property=DropInPaths', '--property=User', '--property=Group')
        if result is not None:
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if fields != {'LoadState': 'loaded', 'FragmentPath': V2_VENDOR, 'DropInPaths': '',
                           'User': V2_USER, 'Group': 'kura-management'}:
                raise RuntimeError('Effective non-Root agent profile differs from its reviewed unit')
        return descriptor

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

    def optional(self, name):
        return self.json(name) if os.path.lexists(self.legacy.path(name)) else None

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

    def replace(self, name, raw, mode):
        path = self.legacy.path(name)
        if os.path.lexists(path) and self.raw(name, mode) == raw:
            return
        self.legacy.authorization_parents(path)
        temporary = path.with_name('.' + path.name + '.source-update-new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); os.fchmod(stream.fileno(), mode); os.fchown(stream.fileno(), 0, 0)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)

    def verify_chain(self, original, descriptor):
        pointer = self.optional(self.CURRENT)
        expected = descriptor
        initial_hash = self.digest(self.raw(V2_ADMIN + '/initialization.json'))
        seen = set()
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
            if (self.digest(raw) != pointer['sha256'] or set(value) != {'schemaVersion', 'requestId',
                    'initializationId', 'initializationReceiptSha256', 'previousPair', 'previousIdentity',
                    'identity', 'packageSha256', 'stateFingerprintSha256', 'unitStarted'}
                    or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                    or value['requestId'] != operation or value['identity'] != expected
                    or value['initializationId'] != original['operationId']
                    or value['initializationReceiptSha256'] != initial_hash or value['unitStarted'] is not False
                    or set(value['previousIdentity']) != set(expected)
                    or any(value['previousIdentity'][key] != expected[key] for key in set(expected) - self.PINS)):
                raise RuntimeError('Native source-pair proof differs from its original initialization')
            expected = value['previousIdentity']; pointer = value['previousPair']
        if expected != original['identity']:
            raise RuntimeError('Native runtime identity/source pair changed without original maintenance proof')
        return seen

    def snapshot(self):
        descriptor = self.profile.descriptor()
        self.profile.stopped('kura-management-agent.service'); self.profile.stopped(V2_UNIT)
        if set(p.name for p in self.legacy.path(V2_STATE).iterdir()) != {
                '.native-profile-v1', 'results.sqlite', 'results.sqlite.plan-key'}:
            raise RuntimeError('Native source-only maintenance requires the proven original unbound state')
        if set(p.name for p in self.legacy.path(V2_CONFIG).iterdir()) != {'agent.env'}:
            raise RuntimeError('Native credentials or grants require their separate maintenance flow')
        for name in ['/etc/kura-management-agent', '/var/lib/kura-management-agent']:
            path = self.legacy.path(name)
            if os.path.lexists(path):
                m = path.lstat()
                if (not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_gid != 0
                        or stat.S_IMODE(m.st_mode) != 0o755 or any(path.iterdir())):
                    raise RuntimeError('Real legacy data must not be adopted by native code maintenance')
        database = self.legacy.path(V2_STATE + '/results.sqlite')
        with closing(sqlite3.connect('file:' + str(database) + '?mode=ro&immutable=1', uri=True)) as connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
            tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables != self.TABLES or any(connection.execute('SELECT count(*) FROM ' + name).fetchone()[0]
                    for name in self.TABLES - {'native_profile_generation'}):
                raise RuntimeError('Retained business or unknown records require full native maintenance')
        result = {}
        for name in [V2_STATE + '/' + leaf for leaf in ['.native-profile-v1', 'results.sqlite', 'results.sqlite.plan-key']] + [
                V2_CONFIG + '/agent.env', V2_ADMIN + '/initialization.json', V2_CONTINUITY]:
            fd = os.open(self.legacy.path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
            with os.fdopen(fd, 'rb') as stream:
                m = os.fstat(stream.fileno()); own = name.startswith(V2_STATE + '/')
                if (not stat.S_ISREG(m.st_mode) or m.st_nlink != 1 or m.st_size > 8 * 1024 * 1024
                        or m.st_uid != (descriptor['uid'] if own else 0)
                        or m.st_gid != (descriptor['gid'] if own else 0)
                        or stat.S_IMODE(m.st_mode) != (0o644 if name == V2_CONTINUITY else 0o600)):
                    raise RuntimeError('Unsafe retained native maintenance input')
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                after = os.fstat(stream.fileno())
                stable = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,
                                    v.st_size,v.st_mtime_ns,v.st_ctime_ns)
                if stable(m) != stable(after): raise RuntimeError('Native state changed during source maintenance')
                result[name] = [*stable(m),digest]
        return result

    def bridge(self):
        raw=self.legacy.reader_file('/usr/share/kura-management-agent/java-bridge.json')
        value=self.legacy.reader_json(raw)
        path='/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'
        if (set(value)!={'symbolicName','version','path','sha256','coreLoaderProtocol','coreLoaderSha256'}
                or value.get('path') != path or value.get('symbolicName') != 'org.eclipse.kura.management.bridge'
                or type(value.get('coreLoaderProtocol')) is not int or value.get('coreLoaderProtocol') != 1
                or not re.fullmatch('[0-9a-f]{64}',value.get('coreLoaderSha256',''))
                or self.profile.asset(path,maximum=16*1024*1024) != value.get('sha256')):
            raise RuntimeError('Existing native Java/Core loader pair differs')
        return {'metadataSha256':self.digest(raw),'jarSha256':value['sha256'],
                'coreLoaderSha256':value['coreLoaderSha256']}

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
    def authenticate_prerm(raw, setup, runtime, source, pair, loader, script='prerm'):
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
        rows={r['path']:r['sha256'] for r in source['sourceFiles']}
        if (set(fields) not in [{'SCRIPT_NAME','PACKAGE_CORE_LOADER_SHA256'},
                               {'SCRIPT_NAME','PACKAGE_CORE_LOADER_SHA256','PACKAGE_NATIVE_PAIR'}]
                or fields.get('SCRIPT_NAME')!=script or fields.get('PACKAGE_CORE_LOADER_SHA256')!=loader
                or ('PACKAGE_NATIVE_PAIR' in fields and fields['PACKAGE_NATIVE_PAIR']!=pair)
                or hashlib.sha256(tail).hexdigest()!=rows.get('packaging/native_lifecycle.py')):
            raise RuntimeError('Native maintainer lifecycle is not its paired source')

    def archive(self, package, control=False):
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
                    keep |= name in ['usr/sbin/kura-agent-setup','usr/share/kura-management-agent/enrollment-reader.json']
                    if keep and member.size > 2 * 1024 * 1024: raise RuntimeError('Oversized native metadata')
                    source = archive.extractfile(member); digest = hashlib.sha256(); data = bytearray()
                    for chunk in iter(lambda: source.read(65536), b''):
                        digest.update(chunk)
                        if keep: data.extend(chunk)
                    result[name] = {'sha256':digest.hexdigest(),'mode':member.mode & 0o7777,'data':bytes(data) if keep else None}
            if process.wait(timeout=5) != 0: raise RuntimeError('Native package inspection failed')
        finally:
            timer.cancel(); process.stdout.close()
            if process.poll() is None: process.kill(); process.wait()
        return result

    def candidate(self, name, expected):
        if self.profile.asset(name, 0o600, 64 * 1024 * 1024) != expected:
            raise RuntimeError('Reviewed native package checksum differs')
        package = self.legacy.path(name); payload = self.archive(package); control = self.archive(package, True)
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
        pair = {'binarySha256':payload['usr/bin/yofc-management-agent']['sha256'],
                'unitSha256':payload[V2_VENDOR.lstrip('/')]['sha256'], 'sourceManifestSha256':payload[source_name]['sha256']}
        bridge=self.bridge()
        if (payload['usr/share/kura-management-agent/java-bridge.json']['sha256']!=bridge['metadataSha256']
                or payload['usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar']['sha256']!=bridge['jarSha256']):
            raise RuntimeError('A Java/Core cohort change requires its separate native maintenance flow')
        for script in ['preinst','postinst','prerm','postrm']:
            self.authenticate_prerm(control[script]['data'],payload['usr/lib/kura-management-agent/setup.py']['data'],
                payload['usr/lib/kura-management-agent/runtime_setup.py']['data'],source,pair,bridge['coreLoaderSha256'],script)
        import ast
        module = ast.parse(control['prerm']['data'])
        values = [ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id=='PACKAGE_NATIVE_PAIR' for t in n.targets)]
        if values != [pair] or control['prerm']['mode'] != 0o755:
            raise RuntimeError('Incoming native maintainer source pair differs')
        return pair, control['prerm']['data']

    def prepare(self, operation, package, expected):
        self.uuid(operation)
        if os.path.lexists(self.legacy.path(self.PENDING)):
            if self.json(self.PENDING).get('packageSha256') != expected:
                raise RuntimeError('Original native maintenance package differs')
            return self.status(operation)
        if os.path.lexists(self.legacy.path(self.record(operation,'intent.json'))):
            if self.json(self.record(operation,'intent.json')).get('packageSha256') != expected:
                raise RuntimeError('Original native maintenance package differs')
            return self.status(operation)
        self.profile.check()
        previous = self.profile.descriptor(); snapshot = self.snapshot()
        bridge=self.bridge()
        previous_prerm=self.raw(self.PRERM,0o755)
        self.authenticate_prerm(previous_prerm,
            self.legacy.reader_file('/usr/lib/kura-management-agent/setup.py',limit=2*1024*1024),
            self.legacy.reader_file('/usr/lib/kura-management-agent/runtime_setup.py',limit=2*1024*1024),
            self.legacy.reader_json(self.legacy.reader_file('/usr/share/kura-management-agent/source-manifest.json',limit=2*1024*1024)),
            {key:previous[key] for key in self.PINS},bridge['coreLoaderSha256'])
        pair, prerm = self.candidate(package, expected)
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
        # Publish the global original intent before creating any per-operation
        # record. Every interruption blocks a new ID as well as startup.
        with self.package_locks():
            if self.profile.descriptor()!=previous or self.snapshot()!=snapshot or self.raw(self.PRERM,0o755)!=previous_prerm:
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
        if ticket['schemaVersion'] != 1 or {key:ticket['identity'][key] for key in self.PINS} != expected:
            raise RuntimeError('Incoming native source maintenance pair differs')
        if target_version is not None and ticket['packageVersion']!=target_version:
            raise RuntimeError('Incoming native package version differs from original maintenance')
        actual = self.legacy.reader_json(self.raw(V2_IDENTITY,0o644))
        self.verify_mask()
        if (actual != ticket['previousIdentity'] or self.profile.descriptor() != actual
                or self.snapshot() != ticket['state'] or self.optional(self.CURRENT) != ticket['previousPair']
                or self.bridge()!=ticket['bridge']
                or self.digest(self.raw(self.PRERM,0o755)) != ticket['prermSha256']):
            raise RuntimeError('Original native source maintenance input changed')
        self.immutable(self.record(ticket['requestId'],'admitted.json'),self.profile.encode({
            'schemaVersion':1,'requestId':ticket['requestId'],'incomingPair':expected}))
        return ticket

    def finish(self, expected):
        ticket = self.json(self.PENDING); operation = self.uuid(ticket['requestId'])
        descriptor = self.profile.descriptor()
        if ({key:descriptor[key] for key in self.PINS} != expected or descriptor != ticket['identity']
                or self.snapshot() != ticket['state'] or self.bridge()!=ticket['bridge']
                or not os.path.lexists(self.legacy.path(self.record(operation,'admitted.json')))):
            raise RuntimeError('Native source update cannot publish changed authority or state')
        result = {'schemaVersion':1,'requestId':operation,'initializationId':ticket['initializationId'],
            'initializationReceiptSha256':ticket['initializationReceiptSha256'],'previousPair':ticket['previousPair'],
            'previousIdentity':ticket['previousIdentity'],'identity':descriptor,'packageSha256':ticket['packageSha256'],
            'stateFingerprintSha256':self.digest(self.profile.encode(ticket['state']).encode()),'unitStarted':False}
        current = self.legacy.reader_json(self.raw(V2_IDENTITY,0o644))
        if current not in [ticket['previousIdentity'],descriptor]: raise RuntimeError('Native public identity drift')
        self.replace(V2_IDENTITY,self.profile.encode(descriptor).encode(),0o644)
        raw = self.profile.encode(result).encode(); self.immutable(self.record(operation,'result.json'),raw)
        pointer={'schemaVersion':1,'requestId':operation,'sha256':self.digest(raw)}
        if self.optional(self.CURRENT) not in [ticket['previousPair'],pointer]:
            raise RuntimeError('Original native source-pair pointer changed')
        self.replace(self.CURRENT,self.profile.encode(pointer).encode(),0o600)
        self.remove_mask()
        self.legacy.path(self.PENDING).unlink()
        fd=os.open(self.legacy.path(V2_ADMIN),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.profile.check()
        return self.status(operation)

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


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Fixed non-Root native agent profile controller')
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('check')
    initialize = actions.add_parser('initialize')
    initialize.add_argument('--request-id', required=True)
    status = actions.add_parser('status')
    status.add_argument('--request-id', required=True)
    update = actions.add_parser('prepare-source-update')
    update.add_argument('--request-id', required=True)
    update.add_argument('--package', required=True)
    update.add_argument('--sha256', required=True)
    update_status = actions.add_parser('source-update-status')
    update_status.add_argument('--request-id', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Use the fixed Root native profile inspection')
    spec = importlib.util.spec_from_file_location('_kura_agent_setup', Path(__file__).resolve().with_name('setup.py'))
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    lock = Path('/run/lock/kura-management-agent-setup.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        m = os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1 or m.st_mode & 0o077:
            raise RuntimeError('Unsafe native profile inspection lock')
        fcntl.flock(stream, fcntl.LOCK_EX)
        setup = RuntimeSetup(legacy.Setup())
        if args.action == 'initialize':
            created = setup.initialize(args.request_id)
            print(json.dumps({'schemaVersion': 1, 'requestId': args.request_id, 'initialized': True, 'created': created,
                              'remoteEnabled': False, 'unitStarted': False}))
        elif args.action == 'status':
            print(json.dumps(setup.status(args.request_id)))
        elif args.action == 'prepare-source-update':
            print(json.dumps(SourceUpdate(setup).prepare(args.request_id, args.package, args.sha256)))
        elif args.action == 'source-update-status':
            print(json.dumps(SourceUpdate(setup).status(args.request_id)))
        else:
            setup.check()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Native agent setup refused: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__),
              file=sys.stderr)
        sys.exit(1)
