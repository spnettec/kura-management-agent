#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Native non-Root profile primitives. No legacy adoption or implicit repair.

The package/UI controller supplies the original initialization UUID. This module
does not create users, stop services, start a unit or reinterpret retained data.
Native enrollment authorization and legacy migration are separate work.
"""
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys
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
        uid, gid, reader = self.account()
        return {'schemaVersion': 1, 'profile': 'native-nonroot-v1', 'user': V2_USER,
                'uid': uid, 'gid': gid, 'readerGid': reader, 'stateDirectory': V2_STATE, 'socket': V2_SOCKET,
                'unitSha256': self.asset(V2_VENDOR),
                'binarySha256': self.asset('/usr/bin/yofc-management-agent', 0o755, 512 * 1024 * 1024),
                'sourceManifestSha256': self.asset('/usr/share/kura-management-agent/source-manifest.json')}

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
        self.stopped('kura-management-agent.service')
        descriptor = self.descriptor()
        for name, uid, gid, mode in [(V2_ADMIN, 0, 0, 0o700), (V2_CONFIG, 0, 0, 0o700),
                (V2_PUBLIC, 0, 0, 0o755), (V2_STATE, descriptor['uid'], descriptor['gid'], 0o700)]:
            self.directory(name, uid, gid, mode)
        actual = self.legacy.reader_json(self.legacy.reader_file(V2_IDENTITY))
        original = self.legacy.reader_json(self.legacy.reader_file(V2_ADMIN + '/initialization.json', mode=0o600))
        if (actual != descriptor or set(original) != {'schemaVersion', 'operationId', 'identity', 'remoteEnabled', 'unitStarted'}
                or type(original.get('schemaVersion')) is not int or original.get('schemaVersion') != 1 or original.get('identity') != descriptor
                or original.get('remoteEnabled') is not False or original.get('unitStarted') is not False):
            raise RuntimeError('Native runtime identity/source pair changed')
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


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ['check']:
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
        RuntimeSetup(legacy.Setup()).check()


if __name__ == '__main__':
    main()
