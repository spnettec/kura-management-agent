#!/usr/bin/env python3
# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
"""Root-only, fixed staged-identity FD relay for the separately named agent UID.

The worker receives an accepted socket and a readonly Root grant from systemd.
Its namespace contains one upstream socket, no /proc or other host /run sockets.
It never opens Core data or reads private descriptor contents.
"""
import array
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

_spec = importlib.util.spec_from_file_location('_kura_stage_publisher', Path(__file__).resolve().with_name('enrollment_reader.py'))
publisher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(publisher)
require = publisher.require

UPSTREAM = '/run/kura-management-enrollment-reader.sock'
SOCKET = '/run/kura-management-agent-enrollment.sock'
GRANT = '/run/kura-enrollment-relay-grant.json'
SOURCE = '/opt/eclipse/kura/data/management-enrollment'


def grant_from(path=GRANT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and before.st_size <= 4096)
        raw = source.read(4097)
        require(len(raw) == before.st_size and publisher.identity(os.fstat(source.fileno())) == publisher.identity(before))
    value = json.loads(raw, object_pairs_hook=publisher.unique_object)
    require(isinstance(value, dict) and set(value) == {'schemaVersion', 'requestId', 'agentUid', 'agentGid',
            'readerGid', 'sourceUid', 'sourceRoot', 'upstreamSocket', 'socket',
            'publisherPairSha256', 'relayPairSha256', 'operator'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and isinstance(value['requestId'], str) and publisher.UUID.fullmatch(value['requestId']))
    for key in ['agentUid', 'agentGid', 'readerGid', 'sourceUid']:
        require(type(value[key]) is int and 0 < value[key] < 4294967295)
    require(value['agentUid'] != value['sourceUid'] and value['agentGid'] != value['readerGid']
            and value['sourceRoot'] == SOURCE and value['upstreamSocket'] == UPSTREAM and value['socket'] == SOCKET)
    require(isinstance(value['operator'], str) and 1 <= len(value['operator'].encode()) <= 128
            and value['operator'].isprintable())
    for key in ['publisherPairSha256', 'relayPairSha256']:
        require(isinstance(value[key], str) and publisher.DIGEST.fullmatch(value[key]))
    return value


def receive(upstream, request, uid):
    descriptors = []
    deadline = time.monotonic() + 5
    def read(size, eof=False):
        value = bytearray()
        while len(value) < size:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            upstream.settimeout(remaining)
            data, ancillary, flags, _ = upstream.recvmsg(size - len(value), socket.CMSG_SPACE(16 * array.array('i').itemsize),
                                                        socket.MSG_CMSG_CLOEXEC)
            unexpected = False
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                    descriptors.extend(values)
                    unexpected |= len(raw) % values.itemsize != 0
                else:
                    unexpected = True
            # Adopt all rights before checking truncation/error, then close in finally.
            require(not unexpected and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    and len(descriptors) <= len(publisher.FILES))
            if not data:
                require(eof and not value)
                return b''
            value.extend(data)
        return bytes(value)
    try:
        size = struct.unpack('!I', read(4))[0]
        require(1 <= size <= 4096)
        value = json.loads(read(size), object_pairs_hook=publisher.unique_object)
        require(read(1, eof=True) == b'')
        require(isinstance(value, dict) and set(value) == {'version', 'ok', 'requestId', 'stageSha256', 'sourceUid', 'files'})
        require(type(value['version']) is int and value['version'] == 1 and value['ok'] is True
                and value['requestId'] == request['requestId'] and value['stageSha256'] == request['stageSha256']
                and type(value['sourceUid']) is int and value['sourceUid'] == uid
                and value['files'] == [name for name, _ in publisher.FILES]
                and len(descriptors) == len(publisher.FILES))
        identities = set()
        for fd, (_, limit) in zip(descriptors, publisher.FILES):
            m = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            require(stat.S_ISREG(m.st_mode) and m.st_uid == uid and stat.S_IMODE(m.st_mode) == 0o600
                    and m.st_nlink == 1 and m.st_size <= limit and flags & os.O_ACCMODE == os.O_RDONLY
                    and not flags & os.O_PATH and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                    and (m.st_dev, m.st_ino) not in identities)
            identities.add((m.st_dev, m.st_ino))
        result = descriptors
        descriptors = []
        return value, result
    finally:
        for fd in descriptors:
            os.close(fd)


def connect(path=UPSTREAM):
    for parent in Path(path).parents:
        m = parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022)
    m = Path(path).lstat()
    require(stat.S_ISSOCK(m.st_mode) and m.st_uid == m.st_gid == 0
            and stat.S_IMODE(m.st_mode) == 0o600 and m.st_nlink == 1)
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.settimeout(5)
        upstream.connect(path)
        require(struct.unpack('3i', upstream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] == 0)
        return upstream
    except Exception:
        upstream.close()
        raise


def serve(connection, grant, upstream_path=UPSTREAM):
    require(os.geteuid() == 0 and connection.family == socket.AF_UNIX and connection.type == socket.SOCK_STREAM)
    peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(peer[1:3] == (grant['agentUid'], grant['agentGid']))
    connection.settimeout(5)
    request = publisher.request_from(connection)
    with connect(upstream_path) as upstream:
        upstream.sendall(json.dumps(request, separators=(',', ':')).encode() + b'\n')
        upstream.shutdown(socket.SHUT_WR)
        header, descriptors = receive(upstream, request, grant['sourceUid'])
        try:
            publisher.send_record(connection, header, descriptors)
        finally:
            for fd in descriptors:
                os.close(fd)


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 1
    with socket.socket(fileno=0) as connection:
        try:
            serve(connection, grant_from())
            return 0
        except Exception:
            try:
                publisher.send_record(connection, {'version': 1, 'ok': False, 'code': 'REFUSED'})
            except Exception:
                pass
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
