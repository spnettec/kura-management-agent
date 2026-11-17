#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Socket-activated, unprivileged read-only access to one reviewed CSR stage.

The native unit binds only Kura's enrollment directory at INPUT_ROOT. The agent
receives read-only descriptors; key bytes never enter the JSON protocol. No path,
UID, command, permission change or private-key export is accepted from a peer.
"""
import array
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

INPUT_ROOT = Path('/run/kura-enrollment-stage-input')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
DIGEST = re.compile(r'[0-9a-f]{64}')
FILES = (
    ('private.pk8', 16384), ('public.der', 16384), ('request.pem', 16384),
    ('gateway.id', 128), ('complete', 64),
    ('certificates/client-chain.pem', 65536), ('certificates/issuer-ca.pem', 65536),
    ('certificates/console-ca.pem', 65536), ('certificates/manifest.json', 16384),
    ('certificates/complete', 65),
)


class Refused(Exception):
    pass


def require(value):
    if not value:
        raise Refused()


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def request_from(connection):
    request = bytearray()
    while b'\n' not in request:
        data, ancillary, flags, _ = connection.recvmsg(4097 - len(request), socket.CMSG_SPACE(64))
        # Peers cannot inject descriptors. Close any delivered rights before
        # rejecting, including malformed/oversized ancillary records.
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                for fd in values:
                    os.close(fd)
        require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        require(data)
        request.extend(data)
        require(len(request) <= 4096)
    require(request.endswith(b'\n') and request.count(b'\n') == 1)
    value = json.loads(request, object_pairs_hook=unique_object)
    require(isinstance(value, dict) and set(value) == {'version', 'requestId', 'stageSha256'})
    require(type(value['version']) is int and value['version'] == 1)
    require(isinstance(value['requestId'], str) and UUID.fullmatch(value['requestId']))
    require(isinstance(value['stageSha256'], str) and DIGEST.fullmatch(value['stageSha256']))
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(stack, name, uid, parent=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME
    fd = os.open(name, flags, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
            and stat.S_IMODE(info.st_mode) == 0o700)
    return fd


def private_file(stack, name, parent, uid, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME,
                 dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 <= info.st_size <= limit)
    return fd, info


def bounded_read(fd, before, limit):
    result = os.pread(fd, limit + 1, 0)
    require(len(result) == before.st_size and len(result) <= limit)
    require(identity(os.fstat(fd)) == identity(before))
    return result


def send_record(connection, value, descriptors=()):
    payload = json.dumps(value, separators=(',', ':')).encode('ascii')
    require(len(payload) <= 4096)
    frame = struct.pack('!I', len(payload)) + payload
    rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', descriptors))] if descriptors else []
    sent = connection.sendmsg([frame], rights)
    require(0 < sent <= len(frame))
    connection.sendall(frame[sent:])


def serve(connection, root=INPUT_ROOT):
    connection.settimeout(5)
    require(connection.family == socket.AF_UNIX and connection.type == socket.SOCK_STREAM)
    peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(peer[1] == 0)
    request = request_from(connection)
    uid = os.geteuid()
    with ExitStack() as stack:
        source = directory(stack, root, uid)
        slot = directory(stack, request['requestId'], uid, source)
        require(set(os.listdir(slot)) == {'private.pk8', 'public.der', 'request.pem',
                                         'gateway.id', 'complete', 'certificates'})
        certificates = directory(stack, 'certificates', uid, slot)
        require(set(os.listdir(certificates)) == {'client-chain.pem', 'issuer-ca.pem',
                                                  'console-ca.pem', 'manifest.json', 'complete'})
        opened = []
        for name, limit in FILES:
            parent = certificates if name.startswith('certificates/') else slot
            fd, info = private_file(stack, name.rsplit('/', 1)[-1], parent, uid, limit)
            opened.append((name, fd, info, limit))
        values = {name: (fd, info, limit) for name, fd, info, limit in opened}
        raw = bounded_read(*values['certificates/manifest.json'])
        require(hashlib.sha256(raw).hexdigest() == request['stageSha256'])
        require(bounded_read(*values['certificates/complete']) == (request['stageSha256'] + '\n').encode())
        require(bounded_read(*values['complete']) == b'kura.remote.identity.v1\n')
        for _, fd, info, _ in opened:
            require(identity(os.fstat(fd)) == identity(info))
        send_record(connection, {'version': 1, 'ok': True, 'requestId': request['requestId'],
                                'stageSha256': request['stageSha256'], 'sourceUid': uid,
                                'files': [name for name, _ in FILES]},
                    [fd for _, fd, _, _ in opened])


def main():
    # Native activation runs as the existing Kura account, with zero caps.
    # The main program has no test/root/path options or environment overrides.
    if len(sys.argv) != 1 or os.geteuid() == 0:
        return 1
    with socket.socket(fileno=0) as connection:
        try:
            serve(connection)
            return 0
        except Exception:
            try:
                send_record(connection, {'version': 1, 'ok': False, 'code': 'REFUSED'})
            except Exception:
                pass
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
