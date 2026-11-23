"""Report only the identities of the two physical fences, without write authority."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import socket
import stat
import struct
import subprocess
import sys

DIRECTORY = Path('/etc/kura')
SOCKET_UNIT = 'kura-management-nm-fence-reader.socket'
SERVICE_UNIT = 'kura-management-nm-fence-reader@.service'
SCRIPT = '/usr/lib/kura-management-agent/fence_reader.py'
META = '/usr/share/kura-management-agent/root-fence-reader.json'
VENDOR = '/usr/lib/systemd/system/'


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def observe(directory, gid):
    def marker(parent, name):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME,
                         dir_fd=parent)
        except FileNotFoundError:
            return None, None
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != gid
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= 16384):
                raise RuntimeError('Unsafe original fence file')
            data = source.read(16385)
            if (len(data) != before.st_size
                    or stamp(before) != stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                raise RuntimeError('Original fence changed while reading')
        return {'device': before.st_dev, 'inode': before.st_ino,
                'sha256': hashlib.sha256(data).hexdigest()}, stamp(before)

    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(parent)
        if before.st_uid != 0 or before.st_mode & 0o022:
            raise RuntimeError('Unsafe original fence directory')
        names = ('network-owner-agent', 'firewall-owner-agent')
        first = [marker(parent, name) for name in names]
        second = [marker(parent, name) for name in names]
        if first != second or stamp(before) != stamp(directory.lstat()):
            raise RuntimeError('Original fence pair changed while reading')
        return {'schemaVersion': 1, 'network': first[0][0], 'firewall': first[1][0]}
    finally:
        os.close(parent)


def verify_release(unit):
    if not re.fullmatch(r'kura-management-nm-fence-reader@[A-Za-z0-9_.:\\-]+\.service', unit):
        raise RuntimeError('Invalid fence reader instance')
    setup = runpy.run_path('/usr/lib/kura-management-agent/setup.py')['Setup']()
    if setup.reader_file('/usr/share/kura-management-agent/package-v1') != b'kura-management-agent-v1\n':
        raise RuntimeError('Packaged legacy fence reader required')
    files = {'scriptSha256': SCRIPT, 'socketSha256': VENDOR + SOCKET_UNIT,
             'unitSha256': VENDOR + SERVICE_UNIT}
    meta = setup.reader_json(setup.reader_file(META))
    if (set(meta) != {'schemaVersion', 'coreLoaderSha256', 'bridgeSha256', *files}
            or type(meta['schemaVersion']) is not int or meta['schemaVersion'] != 1):
        raise RuntimeError('Original Root fence reader release pair is invalid')
    setup.guard_core_loader(meta['coreLoaderSha256'])
    bridge = '/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'
    if hashlib.sha256(setup.reader_file(bridge, limit=8 * 1024 * 1024)).hexdigest() != meta['bridgeSha256']:
        raise RuntimeError('Original paired Java bridge changed')
    if any(hashlib.sha256(setup.reader_file(path, limit=1024 * 1024)).hexdigest() != meta[field]
           for field, path in files.items()):
        raise RuntimeError('Original installed Root fence reader bytes changed')
    for active, vendor in ((SOCKET_UNIT, SOCKET_UNIT), (unit, SERVICE_UNIT)):
        result = subprocess.run(
            ['/usr/bin/systemctl', 'show', active, '--property=LoadState,FragmentPath,DropInPaths'],
            check=True, stdout=subprocess.PIPE, timeout=1, text=True,
        )
        props = dict(row.split('=', 1) for row in result.stdout.splitlines())
        drop_ins = [p for p in props.get('DropInPaths', '').split()
                    if p != '/run/systemd/system/service.d/zzz-lxc-service.conf']
        if (props.get('LoadState') != 'loaded' or drop_ins != []
                or props.get('FragmentPath') not in (VENDOR + vendor, '/lib/systemd/system/' + vendor)):
            raise RuntimeError('Root fence reader must use its reviewed systemd units')


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0:
        raise RuntimeError('Installed Root fence reader required')
    with socket.socket(fileno=0) as connection:
        pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 1 or uid != 0 or gid != os.getegid():
            raise RuntimeError('Unpaired fence reader caller')
        connection.settimeout(2)
        with connection.makefile('rb') as request:
            if request.read(9) != b'observe\n':
                raise RuntimeError('Unsupported fence reader request')
        verify_release(sys.argv[1])
        connection.sendall(json.dumps(observe(DIRECTORY, gid), separators=(',', ':')).encode() + b'\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        # A failed observation must never be indistinguishable from absence.
        print('Root fence observation refused: ' + error.__class__.__name__, file=sys.stderr)
        sys.exit(1)
