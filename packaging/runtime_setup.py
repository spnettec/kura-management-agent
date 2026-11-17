#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Native non-Root profile primitives. No legacy adoption or implicit repair.

The package/UI controller supplies the original initialization UUID. This module
does not create users, stop services, start a unit or reinterpret retained data.
Native enrollment authorization and legacy migration are separate work.
"""
import fcntl
from contextlib import closing
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sqlite3
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
        self.stopped('kura-management-agent.service')
        descriptor = self.descriptor()
        for name, uid, gid, mode in [(V2_ADMIN, 0, 0, 0o700), (V2_CONFIG, 0, 0, 0o700),
                (V2_PUBLIC, 0, 0, 0o755), (V2_STATE, descriptor['uid'], descriptor['gid'], 0o700)]:
            self.directory(name, uid, gid, mode)
        actual = self.legacy.reader_json(self.legacy.reader_file(V2_IDENTITY))
        original = self.legacy.reader_json(self.legacy.reader_file(V2_ADMIN + '/initialization.json', mode=0o600))
        if (actual != descriptor or set(original) != {'schemaVersion', 'operationId', 'identity', 'remoteEnabled', 'unitStarted', 'continuitySha256'}
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


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Fixed non-Root native agent profile controller')
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('check')
    initialize = actions.add_parser('initialize')
    initialize.add_argument('--request-id', required=True)
    status = actions.add_parser('status')
    status.add_argument('--request-id', required=True)
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
        else:
            setup.check()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Native agent setup refused: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__),
              file=sys.stderr)
        sys.exit(1)
