"""Disposable Linux checks for the separate-UID readonly FD relay."""
import array
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import threading
import unittest
import uuid

spec = importlib.util.spec_from_file_location('relay', Path(__file__).with_name('enrollment_relay.py'))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
publisher = relay.publisher


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Root Linux fixture required')
class RelayTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/run') / ('yofc-enrollment-relay-test-' + str(uuid.uuid4()))
        self.root.mkdir(mode=0o755)
        self.addCleanup(lambda: shutil.rmtree(self.root))
        self.request = {'version': 1, 'requestId': str(uuid.uuid4()), 'stageSha256': 'a' * 64}
        self.fds = []
        for index, _ in enumerate(publisher.FILES):
            path = self.root / str(index)
            path.write_bytes(('public synthetic ' + str(index)).encode())
            path.chmod(0o600)
            os.chown(path, 997, 997)
            self.fds.append(os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOATIME))
        self.addCleanup(lambda: [os.close(fd) for fd in self.fds])
        self.header = {'version': 1, 'ok': True, 'requestId': self.request['requestId'],
                       'stageSha256': 'a' * 64, 'sourceUid': 997, 'files': [name for name, _ in publisher.FILES]}
        self.grant = {'schemaVersion': 1, 'requestId': str(uuid.uuid4()), 'agentUid': 995, 'agentGid': 993,
                      'readerGid': 994, 'sourceUid': 997, 'sourceRoot': relay.SOURCE,
                      'upstreamSocket': relay.UPSTREAM, 'socket': relay.SOCKET,
                      'publisherPairSha256': 'b' * 64, 'relayPairSha256': 'c' * 64, 'operator': 'isolated-root'}

    def count(self):
        total = 0
        for path in Path('/proc/self/fd').iterdir():
            try:
                total += os.readlink(path).startswith(str(self.root) + '/')
            except OSError:
                pass
        return total

    def receive(self, header=None, rights=None, extra=False, raw=None):
        before = self.count()
        consumer, sender = socket.socketpair()
        try:
            if raw is None:
                publisher.send_record(sender, self.header if header is None else header, self.fds if rights is None else rights)
            else:
                sender.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', self.fds))])
            if extra:
                publisher.send_record(sender, self.header, self.fds)
            sender.close()
            value, fds = relay.receive(consumer, self.request, 997)
            try:
                self.assertEqual(value, self.header)
            finally:
                for fd in fds:
                    os.close(fd)
        finally:
            sender.close()
            consumer.close()
            self.assertEqual(self.count(), before, 'all received rights must close')

    def test_relay_never_reads_descriptor_contents(self):
        self.receive()
        self.assertEqual([os.lseek(fd, 0, os.SEEK_CUR) for fd in self.fds], [0] * 10)

    def test_missing_duplicate_extra_and_truncated_rights_close_on_rejection(self):
        for rights in [[], self.fds[:9], [self.fds[0]] * 10, self.fds + self.fds[:1], self.fds * 2]:
            with self.assertRaises(publisher.Refused):
                self.receive(rights=rights)

    def test_source_binding_labels_modes_and_writable_rights_are_rejected(self):
        for key, value in [('requestId', str(uuid.uuid4())), ('stageSha256', 'd' * 64),
                           ('sourceUid', 998), ('files', list(reversed(self.header['files']))), ('path', '/etc/shadow')]:
            with self.assertRaises(publisher.Refused):
                self.receive(header={**self.header, key: value})
        (self.root / '0').chmod(0o640)
        with self.assertRaises(publisher.Refused):
            self.receive()
        (self.root / '0').chmod(0o600)
        fd = os.open(self.root / '0', os.O_RDWR)
        try:
            with self.assertRaises(publisher.Refused):
                self.receive(rights=[fd] + self.fds[1:])
        finally:
            os.close(fd)

    def test_truncated_oversized_and_extra_frames_are_rejected(self):
        for raw in [b'\x00', struct.pack('!I', 0), struct.pack('!I', 4097), struct.pack('!I', 10) + b'{}']:
            with self.assertRaises(publisher.Refused):
                self.receive(raw=raw)
        with self.assertRaises(publisher.Refused):
            self.receive(extra=True)

    def test_root_or_wrong_peer_does_not_gain_the_nonroot_relay_role(self):
        a, b = socket.socketpair()
        try:
            with self.assertRaises(publisher.Refused):
                relay.serve(a, self.grant, str(self.root / 'absent.sock'))
        finally:
            a.close(); b.close()

    def test_grant_is_exact_root_private_and_cannot_authorize_root_or_the_source_uid(self):
        path = self.root / 'grant.json'
        path.write_text(json.dumps(self.grant)); path.chmod(0o600)
        self.assertEqual(relay.grant_from(path), self.grant)
        for changes in [{'agentUid': 0}, {'agentUid': 997}, {'agentGid': 0}, {'schemaVersion': True},
                        {'socket': '/run/other.sock'}, {'path': '/etc/shadow'}]:
            path.write_text(json.dumps({**self.grant, **changes}))
            with self.assertRaises(publisher.Refused): relay.grant_from(path)
        path.write_text(json.dumps(self.grant)); path.chmod(0o640)
        with self.assertRaises(publisher.Refused): relay.grant_from(path)

    def test_actual_dedicated_uid_receives_only_readonly_source_descriptors(self):
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream_path = self.root / 'upstream.sock'
        upstream.bind(str(upstream_path)); upstream_path.chmod(0o600); upstream.listen(1); upstream.settimeout(5)
        public = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        public_path = self.root / 'public.sock'
        public.bind(str(public_path)); os.chown(public_path, 0, 994); public_path.chmod(0o660)
        public.listen(1); public.settimeout(5)
        errors = []
        def source():
            try:
                with upstream.accept()[0] as connection:
                    self.assertEqual(publisher.request_from(connection), self.request)
                    publisher.send_record(connection, self.header, self.fds)
            except Exception as error: errors.append(error)
        def serve():
            try:
                with public.accept()[0] as connection: relay.serve(connection, self.grant, str(upstream_path))
            except Exception as error: errors.append(error)
        workers = [threading.Thread(target=source), threading.Thread(target=serve)]
        for worker in workers: worker.start()
        client = '''import socket,sys,json,array,os,fcntl
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode()+b'\\n')
fds=[];raw=b''
while True:
 data,rights,flags,_=s.recvmsg(4096,socket.CMSG_SPACE(16*4),socket.MSG_CMSG_CLOEXEC)
 for level,kind,value in rights:
  assert (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
  a=array.array('i');a.frombytes(value);fds.extend(a)
 if not data:break
 raw+=data
assert len(fds)==10
for index,fd in enumerate(fds):
 assert fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
 assert os.fstat(fd).st_uid==997
 assert os.read(fd,128)==('public synthetic '+str(index)).encode()
 os.close(fd)
print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'readonlyDescriptors':10,'privateBytesLogged':False}))
'''
        try:
            result = subprocess.run(['setpriv', '--reuid=995', '--regid=993', '--groups=994', '--bounding-set=-all',
                '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs', '/usr/bin/python3', '-I', '-c', client,
                str(public_path), json.dumps(self.request)], capture_output=True, text=True, timeout=10)
            for worker in workers: worker.join(6)
            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertFalse(errors, repr(errors))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['uid'], 995)
        finally:
            upstream.close(); public.close()

    def test_dedicated_uid_cannot_follow_a_zero_capability_root_peers_filesystem(self):
        path = self.root / 'root-only-public-probe'
        path.write_bytes(b'public peer filesystem probe\n'); path.chmod(0o600)
        peer = subprocess.Popen(['setpriv', '--bounding-set=-all', '--no-new-privs', '/usr/bin/python3', '-I', '-c',
            'import os,sys;print(os.getpid(),flush=True);sys.stdin.buffer.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            pid = int(peer.stdout.readline())
            code = '''import os,json,sys,pathlib
try:
 with open(sys.argv[1],'rb') as f:readable=f.read()==b'public peer filesystem probe\\n'
 error=None
except OSError as e:readable=False;error=e.errno
fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
print(json.dumps({'uid':os.geteuid(),'readable':readable,'errno':error,'caps':fields['CapEff'].strip(),'nnp':fields['NoNewPrivs'].strip()}))
'''
            results = []
            for uid, caps in [(0, True), (995, False), (995, True)]:
                args = ['setpriv', '--bounding-set=-all' + (',+net_admin' if caps else ''),
                        '--inh-caps=+net_admin' if caps else '--inh-caps=-all',
                        '--ambient-caps=+net_admin' if caps else '--ambient-caps=-all', '--no-new-privs']
                if uid: args += ['--reuid=995', '--regid=993', '--groups=994']
                output = subprocess.run(args + ['/usr/bin/python3', '-I', '-c', code, f'/proc/{pid}/root{path}'],
                                        capture_output=True, text=True, timeout=5, check=True)
                result = json.loads(output.stdout)
                self.assertEqual(result['uid'], uid)
                self.assertEqual(result['readable'], uid == 0)
                self.assertEqual(result['nnp'], '1')
                self.assertEqual(result['caps'], '0000000000001000' if caps else '0000000000000000')
                if uid: self.assertEqual(result['errno'], 13)
                results.append(result)
            print('public-only namespace controls: ' + json.dumps(results, sort_keys=True))
        finally:
            peer.communicate('', timeout=5)


if __name__ == '__main__':
    unittest.main()
