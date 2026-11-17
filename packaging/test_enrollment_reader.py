# Copyright (c) 2026 YOFC. SPDX-License-Identifier: EPL-2.0
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import unittest
import uuid

import enrollment_reader as reader


class EnrollmentReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'staging'
        self.root.mkdir(mode=0o700)
        self.ident = str(uuid.uuid4())
        self.slot = self.root / self.ident
        self.slot.mkdir(mode=0o700)
        self.slot.joinpath('certificates').mkdir(mode=0o700)
        self.synthetic_secret = b'SYNTHETIC_STAGE_PRIVATE_BYTES_NOT_A_REAL_KEY'
        self.payloads = {name: ('public fixture ' + name).encode() for name, _ in reader.FILES}
        self.payloads['private.pk8'] = self.synthetic_secret
        self.payloads['complete'] = b'kura.remote.identity.v1\n'
        self.payloads['certificates/manifest.json'] = b'{"syntheticFixture":true}'
        self.sha = hashlib.sha256(self.payloads['certificates/manifest.json']).hexdigest()
        self.payloads['certificates/complete'] = (self.sha + '\n').encode()
        for name, value in self.payloads.items():
            path = self.slot / name
            path.write_bytes(value)
            path.chmod(0o600)

    def request(self, **changes):
        value = dict(version=1, requestId=self.ident, stageSha256=self.sha)
        value.update(changes)
        return json.dumps(value).encode() + b'\n'

    def exchange(self, payload, extra_rights=()):
        server, client = socket.socketpair()
        self.addCleanup(client.close)

        def publish():
            with server:
                try:
                    reader.serve(server, self.root)
                except Exception:
                    reader.send_record(server, dict(version=1, ok=False, code='REFUSED'))

        thread = threading.Thread(target=publish, daemon=True)
        thread.start()
        rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', extra_rights))] if extra_rights else []
        client.sendmsg([payload], rights)
        header, ancillary, flags, _ = client.recvmsg(4, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC)
        self.assertEqual(len(header), 4)
        self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        length = struct.unpack('!I', header)[0]
        self.assertLessEqual(length, 4096)
        raw = bytearray()
        while len(raw) < length:
            chunk = client.recv(length - len(raw))
            self.assertTrue(chunk)
            raw.extend(chunk)
        fds = []
        for level, kind, data in ancillary:
            self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
            values = array.array('i')
            values.frombytes(data)
            fds.extend(values)
        for fd in fds:
            self.addCleanup(os.close, fd)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        return json.loads(raw), bytes(raw), fds

    def assertRefused(self, payload=None):
        value, raw, fds = self.exchange(self.request() if payload is None else payload)
        self.assertEqual(value, dict(version=1, ok=False, code='REFUSED'))
        self.assertEqual(fds, [])
        self.assertNotIn(self.synthetic_secret, raw)

    def test_transfers_only_readonly_descriptors_and_preserves_source_metadata(self):
        before = {name: reader.identity((self.slot / name).stat()) for name in self.payloads}
        value, raw, fds = self.exchange(self.request())
        self.assertTrue(value['ok'])
        self.assertEqual(value['requestId'], self.ident)
        self.assertEqual(value['stageSha256'], self.sha)
        self.assertEqual(value['files'], list(self.payloads))
        self.assertNotIn(self.synthetic_secret, raw)
        self.assertEqual(len(fds), len(self.payloads))
        for (name, limit), fd in zip(reader.FILES, fds):
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.assertEqual(os.read(fd, limit + 1), self.payloads[name])
            with self.assertRaises(OSError):
                os.write(fd, b'never allowed')
        self.assertEqual(before, {name: reader.identity((self.slot / name).stat()) for name in self.payloads})

    def test_unknown_paths_commands_and_duplicate_fields_are_refused(self):
        for payload in (self.request(path='/etc/kura/credentials/kura_encryption_key'),
                        self.request(command='anything'), self.request(requestId='../outside'),
                        self.request(version=True), self.request(stageSha256='F' * 64),
                        b'{"version":1,"version":1,"requestId":"' + self.ident.encode()
                        + b'","stageSha256":"' + self.sha.encode() + b'"}\n'):
            with self.subTest(payload=payload):
                self.assertRefused(payload)

    def test_socket_peer_cannot_inject_descriptors(self):
        with open('/dev/null', 'rb') as source:
            value, _, fds = self.exchange(self.request(), (source.fileno(),))
        self.assertFalse(value['ok'])
        self.assertEqual(fds, [])

    def test_changed_manifest_or_completion_marker_never_discloses_a_descriptor(self):
        path = self.slot / 'certificates/complete'
        path.write_bytes(b'0' * 64 + b'\n')
        self.assertRefused()
        path.write_bytes(self.payloads['certificates/complete'])
        self.assertRefused(self.request(stageSha256='0' * 64))

    def test_symlink_stage_and_private_file_are_refused(self):
        original = self.slot / 'private.pk8'
        saved = self.root / 'retained'
        original.rename(saved)
        original.symlink_to(saved)
        self.assertRefused()
        original.unlink()
        saved.rename(original)
        renamed = self.root / 'retained-stage'
        self.slot.rename(renamed)
        self.slot.symlink_to(renamed, target_is_directory=True)
        self.assertRefused()

    def test_hardlinks_and_group_readable_private_material_are_refused(self):
        path = self.slot / 'private.pk8'
        linked = self.root / 'retained-link'
        os.link(path, linked)
        self.assertRefused()
        linked.unlink()
        path.chmod(0o640)
        self.assertRefused()

    def test_unknown_files_and_oversized_key_are_refused(self):
        extra = self.slot / 'unexpected'
        extra.write_bytes(b'preserve')
        self.assertRefused()
        extra.unlink()
        self.slot.joinpath('private.pk8').write_bytes(b'x' * 16385)
        self.assertRefused()

    def test_malformed_and_overlong_requests_are_refused(self):
        for payload in (b'{}\n{}\n', b'no json\n', b'x' * 4097 + b'\n'):
            with self.subTest(payloadLength=len(payload)):
                self.assertRefused(payload)

    def test_capability_limited_root_reads_descriptors_from_zero_cap_kura_uid(self):
        # Models the native agent and socket-activated publisher with distinct
        # real UIDs. These bytes are synthetic, not a Kura/CA/agent private key.
        self.assertEqual(os.geteuid(), 0, 'Run this native boundary test in the Linux Root fixture')
        for path in (Path(self.temporary.name), self.root, self.slot,
                     self.slot / 'certificates', *(self.slot / name for name in self.payloads)):
            os.chown(path, 997, 997)
        before = {name: reader.identity((self.slot / name).stat()) for name in self.payloads}
        server, client = socket.socketpair()
        read_end, write_end = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                import ctypes
                client.close()
                os.close(read_end)
                libc = ctypes.CDLL(None, use_errno=True)
                last_cap = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
                for cap in range(last_cap + 1):
                    if libc.prctl(24, cap, 0, 0, 0) != 0:
                        raise OSError(ctypes.get_errno(), 'Drop publisher bounding capability')
                os.setgroups([])
                os.setgid(997)
                os.setuid(997)
                if libc.prctl(38, 1, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), 'Publisher NoNewPrivileges')
                status = dict(x.split(':', 1) for x in Path('/proc/self/status').read_text().splitlines()
                              if x.split(':', 1)[0] in ('CapEff', 'CapBnd', 'NoNewPrivs'))
                os.write(write_end, json.dumps({'uid': os.geteuid(),
                                               'status': {k: v.strip() for k, v in status.items()}}).encode())
                os.close(write_end)
                with server:
                    reader.serve(server, self.root)
                os._exit(0)
            except BaseException:
                os._exit(1)
        server.close()
        os.close(write_end)
        publisher = json.loads(os.read(read_end, 4096))
        os.close(read_end)
        probe = '''import array,fcntl,json,os,pathlib,socket,struct,sys
path=pathlib.Path(sys.argv[1])
try:
 path.read_bytes();raise AssertionError('limited agent unexpectedly read source path')
except PermissionError:pass
connection=socket.socket(fileno=int(sys.argv[2]));connection.settimeout(5)
connection.sendall(sys.argv[3].encode())
header,ancillary,flags,_=connection.recvmsg(4,socket.CMSG_SPACE(64),socket.MSG_CMSG_CLOEXEC)
assert len(header)==4 and not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)
length=struct.unpack('!I',header)[0];assert length<=4096
body=bytearray()
while len(body)<length:
 value=connection.recv(length-len(body));assert value;body.extend(value)
reply=json.loads(body);assert reply['ok'] and reply['sourceUid']==997
assert b'SYNTHETIC_STAGE_PRIVATE_BYTES' not in body
fds=[]
for level,kind,raw in ancillary:
 assert (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
 values=array.array('i');values.frombytes(raw);fds.extend(values)
assert len(fds)==10
for fd in fds:
 assert os.fstat(fd).st_uid==997 and os.fstat(fd).st_mode&0o777==0o600
 assert fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
assert os.read(fds[0],16385)==b'SYNTHETIC_STAGE_PRIVATE_BYTES_NOT_A_REAL_KEY'
for fd in fds:os.close(fd)
status={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.split(':',1)[0] in ('CapEff','CapBnd','NoNewPrivs')}
assert status==dict(CapEff='0000000000001000',CapBnd='0000000000001000',NoNewPrivs='1')
print(json.dumps({'uid':os.geteuid(),'status':status,'directReadDenied':True,'readOnlyDescriptors':len(fds)}))
'''
        try:
            result = subprocess.run(['setpriv', '--bounding-set=-all,+net_admin', '--no-new-privs',
                                     '--reuid=0', '--regid=0', '--clear-groups', 'python3', '-c', probe,
                                     str(self.slot / 'private.pk8'), str(client.fileno()),
                                     self.request().decode()], pass_fds=(client.fileno(),),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            outcome = json.loads(result.stdout)
            self.assertTrue(outcome['directReadDenied'])
            self.assertEqual(outcome['readOnlyDescriptors'], 10)
        finally:
            client.close()
            _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)
        self.assertEqual(publisher, {'uid': 997, 'status': {'CapEff': '0000000000000000',
                                                         'CapBnd': '0000000000000000',
                                                         'NoNewPrivs': '1'}})
        self.assertEqual(before, {name: reader.identity((self.slot / name).stat()) for name in self.payloads})


if __name__ == '__main__':
    unittest.main()
