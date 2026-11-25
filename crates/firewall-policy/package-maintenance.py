# SPDX-License-Identifier: EPL-2.0
"""Read the retained boot restore gate from an installed or incoming control script."""
import fcntl
import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys


STATE = Path('/var/lib/kura-legacy-firewall/boot-restore')
ACTIONS = {
    'preinst': {'install', 'upgrade'},
    'prerm': {'remove', 'upgrade', 'failed-upgrade', 'deconfigure'},
    'postinst': {'configure', 'abort-remove', 'abort-upgrade', 'abort-deconfigure'},
    'postrm': {'remove', 'purge'},
}
ABORT = {'abort-remove', 'abort-upgrade', 'abort-deconfigure'}


def pending_restore():
    for path in (*reversed(STATE.parents), STATE):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe firewall boot restore directory')
    fd = os.open(STATE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        before = os.fstat(fd)
        if (before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o700
                or not os.path.samestat(before, STATE.lstat())):
            raise ValueError('Unsafe firewall boot restore directory')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        try:
            os.stat('pending.json', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(fd)


MAX_RECORD = 2 * 1024 * 1024
ROOT_DOMAIN = '.root-domain-v2'


def kernel_object(fd):
    if sys.platform != 'linux' or ctypes.sizeof(ctypes.c_long) != 8:
        raise ValueError('Unsupported persistent Root ABI')
    class Statfs(ctypes.Structure):
        _fields_ = [('kind', ctypes.c_long), ('size', ctypes.c_long),
                    ('blocks', ctypes.c_ulong), ('free', ctypes.c_ulong), ('available', ctypes.c_ulong),
                    ('files', ctypes.c_ulong), ('free_files', ctypes.c_ulong), ('fsid', ctypes.c_int * 2),
                    ('name_length', ctypes.c_long), ('fragment', ctypes.c_long), ('flags', ctypes.c_long),
                    ('spare', ctypes.c_long * 4)]
    class Handle(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint), ('kind', ctypes.c_int), ('value', ctypes.c_ubyte * 128)]
    if ctypes.sizeof(Statfs) != 120 or ctypes.sizeof(Handle) != 136:
        raise ValueError('Unsupported persistent Root ABI layout')
    library = ctypes.CDLL(None, use_errno=True)
    filesystem, handle, mount = Statfs(), Handle(), ctypes.c_int()
    handle.size = 128
    if library.fstatfs(fd, ctypes.byref(filesystem)) != 0:
        raise ValueError('Unsupported persistent Root filesystem')
    if library.name_to_handle_at(fd, ctypes.c_char_p(b''), ctypes.byref(handle), ctypes.byref(mount), 0x1000) != 0:
        raise ValueError('Unsupported persistent Root file handle')
    if not 0 < handle.size <= 128:
        raise ValueError('Unsafe persistent Root file handle')
    fsid = bytes(filesystem.fsid)
    if not any(fsid):
        raise ValueError('Missing persistent Root filesystem identity')
    return {'filesystemType': filesystem.kind % (1 << 64), 'filesystemId': fsid.hex(),
            'handleType': handle.kind, 'handle': bytes(handle.value[:handle.size]).hex()}


def persistent_scope(fd):
    try:
        os.stat(ROOT_DOMAIN, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    directory = os.open(ROOT_DOMAIN, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDONLY, dir_fd=fd)
    try:
        info = os.fstat(directory)
        named = os.stat(ROOT_DOMAIN, dir_fd=fd, follow_symlinks=False)
        if (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or not os.path.samestat(info, named) or os.listdir(directory) != ['binding.json']):
            raise ValueError('Incomplete or unsafe persistent Root directory')
        binding = os.open('binding.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        try:
            meta = os.fstat(binding)
            if (not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o400
                    or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_nlink != 1 or not 0 < meta.st_size <= 8192
                    or not os.path.samestat(meta, os.stat('binding.json', dir_fd=directory, follow_symlinks=False))):
                raise ValueError('Unsafe persistent Root binding')
            raw = os.read(binding, 8193)
            if len(raw) != meta.st_size:
                raise ValueError('Incomplete persistent Root binding')
        finally:
            os.close(binding)
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            machine = Path('/etc/machine-id').read_text().rstrip()
            if re.fullmatch('[0-9a-f]{32}', machine) is None:
                raise ValueError('Unsafe persistent Root machine identity')
            expected = {'schema': 2, 'purpose': 'kura-firewall-persistent-root-v2',
                        'machineSha256': hashlib.sha256(machine.encode()).hexdigest(),
                        'identity': {'root': kernel_object(root), 'journal': kernel_object(fd)}}
        finally:
            os.close(root)
        canonical = json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()
        if raw != canonical:
            raise ValueError('Persistent firewall Root objects differ')
        return hashlib.sha256(b'kura-firewall-publication-v2\0' + canonical).hexdigest()
    finally:
        os.close(directory)


def read_record(fd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=fd), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_RECORD):
            raise ValueError('Unsafe firewall publication record')
        raw = stream.read(MAX_RECORD + 1)
        if len(raw) != info.st_size:
            raise ValueError('Incomplete firewall publication record')
        return raw


def complete_publication(fd, operation_id, scope):
    intent_bytes = read_record(fd, operation_id + '.intent')
    intent = json.loads(intent_bytes)
    receipt_bytes = read_record(fd, operation_id + '.result')
    receipt = json.loads(receipt_bytes)
    if not isinstance(intent, dict) or not isinstance(receipt, dict):
        return False
    outcome = receipt.get('outcome')
    if (not isinstance(outcome, dict) or type(intent.get('schema')) is not int
            or intent['schema'] not in (1, 2) or receipt.get('schema') != 1
            or intent.get('operationId') != operation_id or intent.get('rootScope') != scope
            or receipt.get('intentSha256') != hashlib.sha256(intent_bytes).hexdigest()
            or not isinstance(intent.get('requestSha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', intent['requestSha256'])
            or any(outcome.get(key) != intent.get(key)
                   for key in ('rootScope', 'operationId', 'requestSha256', 'wireSha256'))):
        return False
    transition = intent.get('forwarding')
    state = outcome.get('state')
    if intent['schema'] == 2:
        if (not isinstance(transition, dict) or set(transition) != {'family', 'namespace', 'before'}
                or transition['family'] not in ('ipv4', 'ipv6') or type(transition['before']) is not bool
                or not isinstance(transition['namespace'], list) or len(transition['namespace']) != 2
                or not all(type(n) is int and n > 0 for n in transition['namespace'])
                or 'outcomeSha256' not in receipt):
            return False
        if state == 'REJECTED':
            if 'forwardingEnabled' in outcome:
                return False
        elif outcome.get('forwardingEnabled') is not True:
            return False
    elif 'forwarding' in intent or 'forwardingEnabled' in outcome:
        return False
    if 'outcomeSha256' not in receipt:
        worker = Path('/usr/libexec/kura-firewall-publish/worker')
        for path in (*reversed(worker.parents), worker):
            meta = path.lstat()
            valid = stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 if path == worker else stat.S_ISDIR(meta.st_mode)
            if not valid or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
                return False
        return subprocess.run([worker, '--check-receipt'], input=intent_bytes + b'\n' + receipt_bytes + b'\n',
                              timeout=5, stdout=subprocess.DEVNULL).returncode == 0
    if receipt['outcomeSha256'] != hashlib.sha256(
            json.dumps(outcome, sort_keys=True, separators=(',', ':')).encode()).hexdigest():
        return False
    wire = bytes.fromhex(intent['wire'])
    if hashlib.sha256(wire).hexdigest() != intent.get('wireSha256'):
        return False
    if not wire:
        expected = 'APPLIED' if transition and not transition['before'] else 'UNCHANGED'
        return state == expected and intent.get('commands') == 0 and 'ack' not in outcome
    return (state in ('APPLIED', 'REJECTED') and intent.get('commands', 0) > 0
            and isinstance(outcome.get('ack'), str) and bool(bytes.fromhex(outcome['ack'])))


def publication_scope(info):
    root = os.stat('/')
    machine = Path('/etc/machine-id').read_text().rstrip()
    binding = ['kura-firewall-publication-v1', machine, root.st_dev, root.st_ino, info.st_dev, info.st_ino]
    return hashlib.sha256(json.dumps(binding, separators=(',', ':')).encode()).hexdigest()


def pending_sender(state):
    # lstat each directory before descending into service-owned state.
    path = state / 'rules'
    for directory in (path, path / 'publication-sender'):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            return True
    return os.path.lexists(path / 'publication-sender/pending')


def pending_publication(directory=None):
    directory = directory or STATE.parent / 'publication'
    for path in reversed(directory.parents):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe firewall publication directory')
    if pending_sender(directory.parent):
        return True
    try:
        fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_RDONLY)
    except FileNotFoundError:
        return False
    try:
        before = os.fstat(fd)
        if (before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o700
                or not os.path.samestat(before, directory.lstat())):
            raise ValueError('Unsafe firewall publication directory')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        stable = persistent_scope(fd)
        intents, results = set(), set()
        for name in os.listdir(fd):
            if stable is not None and name == ROOT_DOMAIN:
                continue
            match = re.fullmatch(r'([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.(intent|result|staged)', name)
            if not match or match[2] == 'staged':
                return True
            (intents if match[2] == 'intent' else results).add(match[1])
            if len(intents) > 4096 or len(results) > 4096:
                return True
        if intents != results:
            return True
        if not intents:
            return False
        scope = stable if stable is not None else publication_scope(before)
        try:
            return any(not complete_publication(fd, op, scope) for op in intents)
        except (ValueError, OSError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
            return True
    finally:
        os.close(fd)


def check(hook, action):
    if action not in ACTIONS[hook]:
        return
    if (os.geteuid() != 0 or os.environ.get('DPKG_ROOT', '') not in ('', '/')
            or os.environ.get('DPKG_ADMINDIR', '/var/lib/dpkg') != '/var/lib/dpkg'):
        raise ValueError('Unpaired Debian package Root')
    boot = pending_restore()
    if boot or pending_publication():
        if hook == 'postinst' and action in ABORT:
            print('preserve')
            return
        raise ValueError('Original firewall boot restore is pending' if boot else 'Original firewall publication is pending')


if __name__ == '__main__':
    try:
        check(*sys.argv[1:])
    except (ValueError, OSError) as error:
        print(f'Cannot maintain Networking packages: {error}', file=sys.stderr)
        sys.exit(1)
