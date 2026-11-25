#!/usr/bin/env python3
# SPDX-License-Identifier: EPL-2.0
"""Destructive only to NEW synthetic test directories in a no-Kura Linux fixture.

Not a business-receipt test. Run explicitly as Root with --worker and a NEW
--test-parent. Each case runs in its own private mount namespace. No operation
is dispatched and no outcome is synthesized. Artifacts are retained for audit.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

STATE = Path('/var/lib/kura-legacy-firewall')
PUB = STATE / 'publication'
WRITER = Path('/run/kura-key-service/writers/lease.lock')
MARKER = '.root-domain-v2'
SENTINEL = '11111111-1111-4111-8111-111111111111.intent'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--test-parent', type=Path, required=True)
    parser.add_argument('--case')
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
    assert not Path('/opt/eclipse/kura').exists(), 'Use a no-Kura fixture'
    if args.case:
        run_case(args)
        return
    assert args.test_parent.is_absolute()
    args.test_parent.mkdir(mode=0o700)  # Never erase or reuse a previous run.
    assert not STATE.exists() or not list(STATE.iterdir()), 'Retained state must not be mounted over'
    STATE.mkdir(mode=0o700, exist_ok=True)
    # Explicit synthetic coordinator; no Core is installed in this fixture.
    WRITER.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not WRITER.exists():
        WRITER.touch(mode=0o600)
    assert WRITER.stat().st_size == 0 and WRITER.stat().st_mode & 0o7777 == 0o600
    cases = ['fence', 'legacy', 'rules', 'boot', 'fresh', 'pending', 'interrupted',
             'empty-marker', 'partial-staged', 'foreign-binding', 'corrupt-final']
    results = []
    for name in cases:
        directory = args.test_parent / name
        directory.mkdir(mode=0o700)
        (directory / 'publication').mkdir(mode=0o700)
        command = ['unshare', '--mount', '--propagation', 'private', sys.executable, '-B',
                   str(Path(__file__).resolve()), '--worker', str(args.worker.resolve()),
                   '--test-parent', str(directory), '--case', name]
        with (args.test_parent / (name + '.log')).open('xb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        results.append({'case': name, 'exit': result.returncode})
        (args.test_parent / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        assert result.returncode == 0, f'{name} failed; retained log in {args.test_parent}'
    print(json.dumps({'cases': len(results), 'passed': len(results), 'businessDispatches': 0,
                      'syntheticOnly': True, 'artifacts': str(args.test_parent)}))


def run_case(args):
    directory = args.test_parent
    subprocess.run(['mount', '--bind', str(directory), str(STATE)], check=True)
    helper = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'package-maintenance.py'))
    native = ['setpriv', '--bounding-set=-all', '--no-new-privs', str(args.worker)]
    calls = []

    def invoke(mode=None, *, inherited=True, fd_path=WRITER, request=None, trace=None, inject=None):
        command = list(native) + ([mode] if mode else [])
        if trace:
            command = ['strace', '-qq', '-f', '-o', str(directory / trace),
                       '-e', 'trace=%file'] + (['-e', 'inject=renameat2:error=EINTR:when=1'] if inject else []) + command
        fd = os.open(fd_path, os.O_RDONLY | os.O_CLOEXEC) if inherited else None
        try:
            options = {'pass_fds': tuple(sorted({3, fd})),
                       'preexec_fn': lambda: os.dup2(fd, 3)} if fd is not None else {}
            result = subprocess.run(command, input=(json.dumps(request) + '\n').encode() if request else b'',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, **options)
        finally:
            if fd is not None:
                os.close(fd)
        calls.append({'command': command, 'request': request, 'exit': result.returncode,
                      'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
        (directory / 'calls.json').write_text(json.dumps(calls, indent=2) + '\n')
        return result

    def query(**values):
        return invoke(request={'schema': 1, **values})

    def init(**values):
        return invoke('--initialize-persistent-root', **values)

    def response(result):
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def reject(result, text):
        assert result.returncode != 0 and text.encode() in result.stderr, result

    def unknown_sentinel():
        path = PUB / SENTINEL
        path.write_bytes(b'SYNTHETIC pending sentinel; not a task or receipt\n')
        path.chmod(0o600)
        return path, path.read_bytes(), path.stat().st_ino

    def incomplete_gate():
        try:
            helper['pending_publication']()
        except (ValueError, OSError):
            return
        raise AssertionError('Incomplete binding was accepted by workerless maintenance')

    marker = PUB / MARKER
    final = marker / 'binding.json'
    staged = marker / 'binding.staged'
    name = args.case
    if name == 'fence':
        reject(init(inherited=False), 'inherited Core writer fence')
        other = directory / 'wrong-lock'
        other.touch(mode=0o600)
        reject(init(fd_path=other), 'Core writer fence')
        with WRITER.open('rb') as lease:
            fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
            reject(init(), 'BUSY')
        assert not marker.exists()
    elif name in ('legacy', 'rules', 'boot'):
        if name == 'legacy':
            path, raw, inode = unknown_sentinel()
            scope = response(query(action='scope'))['rootScope']
            assert scope == helper['publication_scope'](PUB.stat())
        else:
            path = STATE / ('rules' if name == 'rules' else 'boot-restore')
            path.mkdir(mode=0o700)
            path = path / 'retained-test-state'
            path.write_bytes(b'SYNTHETIC retained state\n')
            raw, inode = path.read_bytes(), path.stat().st_ino
        reject(init(), 'LEGACY_DOMAIN')
        assert path.read_bytes() == raw and path.stat().st_ino == inode and not marker.exists()
    elif name in ('empty-marker', 'partial-staged'):
        marker.mkdir(mode=0o700)
        if name == 'partial-staged':
            staged.write_bytes(b'{"schema":2,')
            staged.chmod(0o600)
            reject(init(), 'UNRESOLVED')
            assert staged.read_bytes() == b'{"schema":2,' and not final.exists()
        reject(query(action='scope'), 'UNRESOLVED')
        incomplete_gate()
    elif name == 'interrupted':
        reject(init(trace='publish-eintr.trace', inject=True), 'UNRESOLVED')
        assert staged.is_file() and not final.exists()
        raw, inode = staged.read_bytes(), staged.stat().st_ino
        assert 'EINTR' in (directory / 'publish-eintr.trace').read_text()
        reject(query(action='scope'), 'UNRESOLVED')
        incomplete_gate()
        result = response(init())
        assert result['state'] == 'INITIALIZED'
        assert final.read_bytes() == raw and final.stat().st_ino == inode and not staged.exists()
    elif name in ('fresh', 'pending', 'foreign-binding', 'corrupt-final'):
        result = response(init())
        assert result['state'] == 'INITIALIZED' and result['rootScopeScheme'] == 'kernel-fh-v2'
        scope = result['rootScope']
        assert scope != helper['publication_scope'](PUB.stat())
        query_result = response(query(action='scope'))
        assert query_result == {'state': 'SCOPE', 'rootScope': scope}, query_result
        fd = os.open(PUB, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert scope == helper['persistent_scope'](fd)
        finally:
            os.close(fd)
        assert not helper['pending_publication']()
        raw, inode = final.read_bytes(), final.stat().st_ino
        assert final.stat().st_mode & 0o7777 == 0o400 and marker.stat().st_mode & 0o7777 == 0o700
        if name == 'fresh':
            assert response(init())['state'] == 'EXISTS'
            assert response(invoke('--boot-model'))['publications'] == 0
            observed = response(invoke('--inspect-root-identity'))
            assert observed['rootScopeScheme'] == 'kernel-fh-v2' and not observed['authorizesMigration']
        elif name == 'pending':
            path, sentinel, sent_inode = unknown_sentinel()
            assert helper['pending_publication']()  # No installed worker exists.
            for hook, action in [('prerm', 'remove'), ('postrm', 'purge')]:
                try:
                    helper['check'](hook, action)
                except ValueError as error:
                    assert 'publication is pending' in str(error)
                else:
                    raise AssertionError('Workerless package gate accepted a pending intent')
            reject(invoke(request={'schema': 1, 'action': 'outcome', 'operationId': SENTINEL[:-7],
                                 'rootScope': helper['publication_scope'](PUB.stat()), 'requestSha256': '0' * 64},
                          trace='wrong-scope.trace'), 'UNPAIRED')
            assert SENTINEL not in (directory / 'wrong-scope.trace').read_text()
            assert path.read_bytes() == sentinel and path.stat().st_ino == sent_inode
            assert response(init())['state'] == 'EXISTS'  # Read-only idempotence; no new domain.
        elif name == 'corrupt-final':
            final.chmod(0o600)
            final.write_bytes(raw + b' ')
            final.chmod(0o400)
            reject(query(action='scope'), 'UNPAIRED')
            reject(init(), 'UNPAIRED')
            incomplete_gate()
            assert final.read_bytes() == raw + b' '
            return
        elif name == 'foreign-binding':
            original = directory / 'original-publication'
            original.mkdir(mode=0o700)
            # Preserve the actual domain then replace ONLY the synthetic bind mount.
            subprocess.run(['umount', str(STATE)], check=True)
            replacement = directory / 'replacement-state'
            replacement.mkdir(mode=0o700)
            other_pub = replacement / 'publication'
            other_pub.mkdir(mode=0o700)
            shutil.copytree(directory / 'publication' / MARKER, other_pub / MARKER)
            subprocess.run(['mount', '--bind', str(replacement), str(STATE)], check=True)
            reject(query(action='scope'), 'UNPAIRED')
            reject(init(), 'UNPAIRED')
            incomplete_gate()
            assert final.read_bytes() == raw
            return
        assert final.read_bytes() == raw and final.stat().st_ino == inode
    print(json.dumps({'case': name, 'passed': True, 'businessDispatches': 0}))


if __name__ == '__main__':
    main()
