#!/usr/bin/python3
"""Explicit, root-only identity import and read-only Kura OS authorization."""
import argparse
import base64
from contextlib import closing
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from urllib.parse import quote, urlsplit

CONFIG = '/etc/kura-management-agent'
STATE = '/var/lib/kura-management-agent'
NM_HANDOVER_DIRECTORIES = ('nm-ownership', 'nm-template')
NM_UPGRADE = CONFIG + '/.nm-continuity-upgrade.json'
NM_UPGRADE_CANDIDATE = CONFIG + '/.nm-continuity-candidate'
NM_UPGRADE_STOP = CONFIG + '/.nm-continuity-stop'
DROPIN = '/etc/systemd/system/kura-netplan.service.d/agent-authorization.conf'
KURA_PROFILES = {
    'kurad': ('kura.service', '/etc/systemd/system/kura.service.d/agent-authorization.conf'),
    'kura-netplan': ('kura-netplan.service', DROPIN),
}
TRANSFER_SIGNER = '/etc/kura-management-agent/transfer-signer.pem'
UNIT = 'kura-management-agent.service'
FIREWALL_BOOT_UNIT = 'kura-management-firewall-boot.service'
FIREWALL_BOOT_VENDOR = '/usr/lib/systemd/system/' + FIREWALL_BOOT_UNIT
FIREWALL_BOOT_META = '/usr/share/kura-management-agent/firewall-boot.json'
ROOT_FENCE_UNIT = 'kura-management-nm-fence@.service'
ROOT_FENCE_VENDOR = '/usr/lib/systemd/system/' + ROOT_FENCE_UNIT
ROOT_FENCE_META = '/usr/share/kura-management-agent/root-fence.json'
FENCE_READER_SOCKET_UNIT = 'kura-management-nm-fence-reader.socket'
DROPIN_CONTENT = '# Managed by kura-management-agent setup; read-only UDS access.\n[Service]\nSupplementaryGroups=kura-management\n'
READER_SOCKET = '/run/kura-management-enrollment-reader.sock'
READER_SOURCE = '/opt/eclipse/kura/data/management-enrollment'
READER_META = '/usr/share/kura-management-agent/enrollment-reader.json'
READER_GRANT = CONFIG + '/enrollment-reader-grant.json'
AUTHORIZATIONS = STATE + '/local-authorizations'
AUTHORIZATION_PENDING = CONFIG + '/.local-authorization-installing'
READER_SOCKET_UNIT = 'kura-management-enrollment-reader.socket'
READER_SERVICE_UNIT = 'kura-management-enrollment-reader@.service'
READER_FILES = {
    '/usr/lib/kura-management-agent/enrollment_reader.py': 'enrollment_reader.py',
    '/usr/lib/systemd/system/' + READER_SOCKET_UNIT: READER_SOCKET_UNIT,
    '/usr/lib/systemd/system/' + READER_SERVICE_UNIT: READER_SERVICE_UNIT,
}


# Shared verbatim with the Core maintainer guard; neither needs a running agent.
def guard_cancelled_handoff(root):
    """Pure validation of an explicitly cancelled unissued ordinary handoff."""
    path = root / 'transaction.json'
    if not os.path.lexists(path):
        return
    def read(p):
        m = p.parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
            raise RuntimeError('Unsafe ordinary cancellation evidence directory')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            m = os.fstat(fd)
            if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or stat.S_IMODE(m.st_mode) != 0o600 or m.st_size > 1024 * 1024:
                raise RuntimeError('Unsafe ordinary cancellation evidence')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                return source.read(1024 * 1024 + 1)
        finally:
            os.close(fd)
    def decode(raw):
        def pairs(values):
            result = {}
            for k, v in values:
                if k in result:
                    raise RuntimeError('Duplicate cancellation evidence field')
                result[k] = v
            return result
        return json.loads(raw, object_pairs_hook=pairs)
    # Existing terminal recovery formats retain their established validation.
    j = json.loads(path.read_text())
    if j.get('state') != 'ORDINARY_CANCELLED':
        return
    j = decode(read(path))
    def require(ok):
        if not ok:
            raise RuntimeError('Unproven ordinary cancellation; preserve state')
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()
    def equal(a, b):
        return json.dumps(a, sort_keys=True, separators=(',', ':')) == json.dumps(b, sort_keys=True, separators=(',', ':'))
    def canonical(s, prefix=''):
        try:
            return isinstance(s, str) and s.startswith(prefix) and str(uuid.UUID(s[len(prefix):])) == s[len(prefix):]
        except (ValueError, AttributeError):
            return False
    def sha(s):
        return isinstance(s, str) and len(s) == 64 and all(c in '0123456789abcdef' for c in s)
    p = j.get('ordinary')
    require(isinstance(p, dict) and canonical(p.get('id'), 'handoff-') and canonical(j.get('id'), 'rec-'))
    require(p.get('cancelled') is True and p.get('issued') is False and p.get('verified') is False and p.get('issued_command') is None and p.get('observation') is None)
    f = lambda suffix: root / 'receipts' / (p['id'] + suffix)
    raw = read(f('.ordinary-source.json')); require(digest(raw) == p['source_sha256']); original = decode(raw)
    strip = lambda v: {k: x for k, x in v.items() if k not in ('state', 'error', 'ordinary')}
    require(original.get('state') == 'COMPLETED_APPROVED_CHECKS' and original.get('ordinary') is None and equal(strip(original), strip(j)))
    raw = read(f('.ordinary-grant.json')); require(digest(raw) == p['grant_sha256']); grant = decode(raw)
    require(grant.get('schema') == 1 and grant.get('unit') == p.get('unit') and grant.get('profileId') == p.get('profile_id'))
    hashes = [digest(raw)] + [v['sha256'] for v in grant['profileFiles']]
    require(all(sha(s) for s in hashes) and digest('\n'.join(hashes).encode()) == p['profile_digest'])
    result = dict(id=p['id'], unit=p['unit'], profileId=p['profile_id'], state='ORDINARY_CANCELLED', cancelled=True, issued=False, ordinaryUnitHandedOff=False, scope='administrator-selected-checks', kuraRecoveryVerified=False, normalBootVerified=False)
    binding = p.get('cancel_command'); commands = p.get('command_decisions', {})
    require(isinstance(commands, dict) and len(commands) <= 2)
    if binding is not None:
        require(binding.get('operation') == 29 and binding.get('commandId') in commands)
    for command_id, h in commands.items():
        require(canonical(command_id) and sha(h)); raw = read(root / 'commands' / (command_id + '.json')); require(digest(raw) == h); d = decode(raw); a = d['binding']
        require(set(d) == {'schema', 'binding', 'recoveryId', 'handoffId', 'result'} and d['schema'] == 1 and d['recoveryId'] == j['id'] and d['handoffId'] == p['id'])
        require(set(a) == {'commandId', 'operation', 'requestSha256'} and a['commandId'] == command_id and sha(a['requestSha256']) and a['operation'] in (21, 29))
        if a['operation'] == 21:
            expected_prepare = dict(transactionId=p['id'], confirmToken=p['confirm_token'], state='ORDINARY_PREPARED', scope='administrator-selected-checks', kuraRecoveryVerified=False, normalBootVerified=False, profileId=p['profile_id'], unit=p['unit'], profileDigest=p['profile_digest'], grantSha256=p['grant_sha256'], sourceJournalSha256=p['source_sha256'], snapshotSha256=p['highest_sha256'], expiresAtUnixMs=p['expires_at'], previousPid=p['old_normal_pid'], componentPids=grant['componentPids'], checkIds=grant['checkIds'])
            require(equal(d['result'], expected_prepare))
        if a['operation'] == 29:
            require(equal(a, binding) and equal(d['result'], result))
    expected = dict(schema='yofc.agent.ordinary-cancel.v1', result=result, sourceJournalSha256=p['source_sha256'], grantSha256=p['grant_sha256'], profileDigest=p['profile_digest'], cancellationCommand=binding)
    raw = read(f('.ordinary-cancel.json')); require(sha(p['receipt_sha256']) and digest(raw) == p['receipt_sha256'] and equal(decode(raw), expected))

def guard_system_control(root):
    def fail(reason):
        raise RuntimeError('System control evidence: ' + reason + '; preserve state')

    def directory(path):
        m = path.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
            fail('unsafe private directory')

    def read(path):
        directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            m = os.fstat(fd)
            if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or stat.S_IMODE(m.st_mode) != 0o600 or m.st_size > 1024 * 1024:
                fail('unsafe private record')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                fail('record exceeds limit')
            return data
        finally:
            os.close(fd)

    def canonical(value):
        return isinstance(value, str) and str(uuid.UUID(value)) == value

    def digest(value):
        return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

    def binding(value):
        return isinstance(value, dict) and set(value) == {'commandId', 'operation', 'requestSha256'} and canonical(value['commandId']) and value['operation'] in (24, 25, 26, 27, 28) and digest(value['requestSha256'])

    journal = root / 'transaction.json'
    if not os.path.lexists(journal):
        for name in ('commands', 'receipts', 'history'):
            path = root / name
            if os.path.lexists(path):
                directory(path)
                if any(path.iterdir()):
                    fail('journal missing with retained records')
        return
    j = json.loads(read(journal))
    expected = {'schema', 'id', 'token', 'state', 'action', 'configSha256', 'definitionSha256', 'unit', 'before', 'beforeBootId', 'expiresAt', 'profile', 'snapshots', 'probe', 'issuedCommand', 'issued', 'issuedAt', 'requestAccepted', 'scheduledUnit', 'after', 'afterBootId', 'observation', 'outcome', 'receiptSha256', 'error', 'commandDecisions'}
    if set(j) != expected or j.get('schema') != 1 or not isinstance(j.get('id'), str) or not j['id'].startswith('system-') or not canonical(j['id'][7:]) or not canonical(j['token']) or not canonical(j['beforeBootId']) or not digest(j['configSha256']) or not digest(j['definitionSha256']) or j['action'] not in ('restart', 'reboot'):
        fail('invalid journal identity')
    if j['state'] not in ('COMPLETED', 'CANCELLED'):
        fail('unresolved transaction')
    raw = read(root / 'receipts' / (j['id'] + '.config.json'))
    config = json.loads(raw)
    if hashlib.sha256(raw).hexdigest() != j['configSha256'] or config.get('schema') != 1 or config.get('unit') != j['unit'] or config.get('unitDefinitionSha256') != j['definitionSha256']:
        fail('archived grant changed')
    commands = j['commandDecisions']
    if not isinstance(commands, dict) or len(commands) > 2:
        fail('invalid command map')
    decisions = {}
    for ident, sha in commands.items():
        if not canonical(ident) or not digest(sha):
            fail('invalid command identity')
        raw = read(root / 'commands' / (ident + '.json'))
        decision = json.loads(raw)
        if hashlib.sha256(raw).hexdigest() != sha or set(decision) != {'schema', 'binding', 'planId', 'result'} or decision['schema'] != 1 or decision['planId'] != j['id'] or not binding(decision['binding']) or decision['binding']['commandId'] != ident:
            fail('original command changed')
        if decision['binding']['operation'] in (25, 27) and decision['binding'] != j['issuedCommand']:
            fail('unbound issued command')
        decisions[ident] = decision
    issued = j['issuedCommand']
    if issued is not None and (not binding(issued) or issued['operation'] != (25 if j['action'] == 'restart' else 27) or decisions.get(issued['commandId'], {}).get('binding') != issued):
        fail('invalid issued command')
    if j['state'] == 'CANCELLED':
        if j['issued'] is not False or j['requestAccepted'] is not False or issued is not None or j['issuedAt'] is not None or j['receiptSha256'] is not None or j['after'] is not None or j['afterBootId'] is not None or j['observation'] is not None or j['scheduledUnit'] is not None:
            fail('cancelled plan contains issued intent')
        return
    raw = read(root / 'receipts' / (j['id'] + '.completed.json'))
    result = json.loads(raw)
    value = result.get('value', {})
    if hashlib.sha256(raw).hexdigest() != j['receiptSha256'] or result != j['outcome'] or result.get('state') not in (4, 5) or j['issued'] is not True or j['requestAccepted'] is not True or type(j['issuedAt']) is not int or not canonical(j['afterBootId']) or not isinstance(j['observation'], dict):
        fail('completion receipt changed')
    if issued is not None and decisions[issued['commandId']]['result'] != result:
        fail('original execution outcome changed')
    for key, expected_value in {'id': j['id'], 'state': 'COMPLETED', 'action': 'service.restart' if j['action'] == 'restart' else 'system.reboot', 'unit': j['unit'], 'before': j['before'], 'beforeBootId': j['beforeBootId'], 'after': j['after'], 'afterBootId': j['afterBootId'], 'issued': True, 'requestAccepted': True, 'application': j['observation'], 'kuraRecoveryVerified': False, 'normalBootVerified': False}.items():
        if value.get(key) != expected_value:
            fail('completion stages changed')
    if j['action'] == 'restart' and (value.get('processRestartVerified') is not True or j['afterBootId'] != j['beforeBootId'] or value.get('hostRebootVerified') is not False):
        fail('process transition unproven')
    if j['action'] == 'reboot' and (value.get('hostRebootVerified') is not True or j['afterBootId'] == j['beforeBootId']):
        fail('host transition unproven')


class Setup:
    def __init__(self, root=Path('/'), run=subprocess.run):
        self.root, self.run = root, run

    def path(self, name):
        path = self.root / name.lstrip('/')
        for entry in [path, *path.parents]:
            if entry.is_symlink():
                raise RuntimeError('Refusing symlink in agent-owned path')
            if entry == self.root:
                break
        return path

    def systemctl(self, *args):
        if self.path('/run/systemd/system').is_dir():
            return self.run(['/bin/systemctl', *args], check=True, capture_output=True, text=True)
        return None

    @staticmethod
    def put(path, value, mode=0o600):
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), 'wb') as out:
            out.write(value.encode() if isinstance(value, str) else value)
            os.fchmod(out.fileno(), mode)

    def put_durable(self, path, value, mode=0o600):
        """Create a file atomically and fsync it plus its directory."""
        path = self.path(path) if isinstance(path, str) else path
        temporary = path.with_name('.' + path.name + '.record-new')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, 'wb') as out:
            out.write(value.encode() if isinstance(value, str) else value)
            out.flush()
            os.fsync(out.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            os.unlink(temporary)
            raise
        os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def private(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('Identity/config must be an owned regular file with mode 0600')

    @staticmethod
    def public_key(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid() \
                or info.st_mode & 0o022:
            raise RuntimeError('Transfer signer must be a root-owned public key not writable by others')
        # Some OpenSSL variants accept private-key PEM even with -pubin. Check
        # the exact public Ed25519 SPKI before storing it as a public authority.
        try:
            if info.st_size > 1024:
                raise ValueError('oversized key')
            lines = [line for line in path.read_text(encoding='ascii').splitlines() if line.strip()]
            if len(lines) < 3 or lines[0] != '-----BEGIN PUBLIC KEY-----' or lines[-1] != '-----END PUBLIC KEY-----':
                raise ValueError('not public PEM')
            der = base64.b64decode(''.join(lines[1:-1]), validate=True)
            if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
                raise ValueError('not Ed25519 SPKI')
        except (ValueError, UnicodeError) as error:
            raise RuntimeError('Transfer signer must be an Ed25519 public key') from error

    def settings(self):
        path = self.path(CONFIG + '/agent.env')
        self.private(path)
        settings = {}
        for line in path.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if not separator or not re.fullmatch(r'[A-Z_]+', key) or key in settings or '\x00' in value:
                raise RuntimeError('Invalid or duplicate agent setting')
            settings[key] = value
        return settings

    def inactive(self):
        result = self.systemctl('show', UNIT, '-p', 'MainPID', '-p', 'ActiveState')
        if result:
            state = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if state.get('MainPID') != '0' or state.get('ActiveState') not in ('inactive', 'failed'):
                raise RuntimeError('Stop the packaged agent before changing its identity or authorization')

    @staticmethod
    def local_settings():
        return {
            'AGENT_STATE_DB': STATE + '/results.sqlite',
            'AGENT_SOCKET': '/run/kura-management-agent/control.sock',
            'AGENT_KURA_UID': '4294967295', 'AGENT_ADMIN_UID': '0',
            'AGENT_KURA_NETWORK_INTERFACES': '',
            'AGENT_NETWORK_INTERFACES': '', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE': '0',
            'AGENT_FIREWALL_WRITE': '0', 'AGENT_REMOTE_ENABLED': '0',
            'AGENT_SYSTEM_CONTROL_REMOTE': '0',
            'AGENT_KURA_REMOTE_MANAGEMENT': '0', 'RUST_LOG': 'info',
        }

    def init_local(self):
        """Initialize only a clean install; never infer identity loss from absent env."""
        self.inactive()
        config = self.path(CONFIG)
        state = self.path(STATE)
        env = config / 'agent.env'
        if env.exists():
            self.check()
            return False
        if (config.exists() and any(config.iterdir())) or (state.exists() and any(
                p.name != '.package-v1' for p in state.iterdir())):
            raise RuntimeError('Retained agent data without settings requires explicit recovery')
        config.mkdir(mode=0o700, parents=True, exist_ok=True)
        if config.stat().st_uid != os.getuid() or config.stat().st_mode & 0o077:
            raise RuntimeError('Identity directory must be owned and private')
        self.put_durable(env, self.serialize(self.local_settings()))
        self.check()
        return True

    def migrate_remote_control(self, enabled, operator):
        """Record an operator decision for a stopped pre-switch bound deployment."""
        if type(enabled) is not bool:
            raise RuntimeError('Explicit boolean remote decision required')
        if not operator or len(operator) > 128 or any(c in operator for c in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        self.guard_writer()
        settings = self.check(require_remote=False)
        if 'AGENT_CONSOLE_ENDPOINT' not in settings:
            raise RuntimeError('Remote migration requires an existing bound identity')
        target = self.path(STATE + '/remote-management.json')
        if target.exists():
            raise RuntimeError('Remote control decision already exists; use the local control API')
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        decision = {'version': 1, 'revision': str(uuid.uuid4()), 'enabled': enabled,
                    'actor': 'migration:' + operator}
        self.put_durable(target, json.dumps(decision, separators=(',', ':')) + '\n')
        self.check()

    @staticmethod
    def identity_settings(endpoint, gateway, generation='1'):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+/?', endpoint)
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise RuntimeError('A plain HTTPS console endpoint is required')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', gateway):
            raise RuntimeError('Invalid gateway identifier')
        if not re.fullmatch(r'[1-9][0-9]{0,17}', str(generation)):
            raise RuntimeError('Invalid binding generation')
        return {**Setup.local_settings(), **{
            'AGENT_CONSOLE_ENDPOINT': endpoint, 'AGENT_GATEWAY_ID': gateway,
            'AGENT_CA': CONFIG + '/ca.pem', 'AGENT_CERT': CONFIG + '/agent.pem',
            'AGENT_KEY': CONFIG + '/agent.key', 'AGENT_STATE_DB': STATE + '/results.sqlite',
            'AGENT_SOCKET': '/run/kura-management-agent/control.sock',
            # Cross-center binding generation is independent of runtime connection epochs.
            'AGENT_BINDING_GENERATION': str(generation),
            # uid_t -1 is not a valid Linux user; nobody is not an authorization placeholder.
            'AGENT_KURA_UID': '4294967295', 'AGENT_ADMIN_UID': '0',
            'AGENT_NETWORK_INTERFACES': '', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE': '0',
            'AGENT_FIREWALL_WRITE': '0',
            'RUST_LOG': 'info',
        }}

    @staticmethod
    def serialize(settings):
        return ''.join(key + '=' + value + '\n' for key, value in settings.items())

    def migrate_binding_generation(self):
        """Explicitly add generation 1 to a proven same-center pre-generation identity."""
        self.inactive()
        current = self.settings()
        generation = current.get('AGENT_BINDING_GENERATION')
        if generation is not None:
            if generation == '1':
                self.check(require_remote=False)
                return
            raise RuntimeError('Binding generation is already present; explicit transfer/recovery required')
        marker = self.path(CONFIG + '/.identity-installing')
        if marker.exists():
            raise RuntimeError('Interrupted identity installation')
        endpoint = current.get('AGENT_CONSOLE_ENDPOINT', '')
        gateway = current.get('AGENT_GATEWAY_ID', '')
        expected = self.identity_settings(endpoint, gateway)
        if endpoint != expected['AGENT_CONSOLE_ENDPOINT'] or gateway != expected['AGENT_GATEWAY_ID']:
            raise RuntimeError('Invalid existing center identity')
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY', 'AGENT_STATE_DB', 'AGENT_SOCKET', 'AGENT_ADMIN_UID']:
            if current.get(key) != expected[key]:
                raise RuntimeError('Packaged identity/state/socket path changed; explicit migration required')
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY']:
            self.private(self.path(current[key]))
        current['AGENT_BINDING_GENERATION'] = '1'
        target = self.path(CONFIG + '/agent.env')
        temporary = target.with_name('.agent.env.binding-generation')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as out:
            out.write(self.serialize(current))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, target)
        self.private(target)
        self.check(require_remote=False)

    def import_identity(self, endpoint, gateway, ca, cert, key, transfer_signer=None):
        self.inactive()
        if self.path(STATE + "/enrollment").exists():
            raise RuntimeError("Managed identity candidates/receipts require explicit recovery or transfer; import cannot replace them")
        settings = self.identity_settings(endpoint, gateway)
        sources = [Path(ca), Path(cert), Path(key)]
        if transfer_signer is not None:
            sources.append(Path(transfer_signer))
        for path in sources:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Identity input must be a bounded regular file')
        self.private(sources[2])
        # Validate exactly the bytes subsequently installed, not mutable caller paths.
        payload = [path.read_bytes() for path in sources]
        with tempfile.TemporaryDirectory(prefix='kura-agent-identity-') as directory:
            staged = [Path(directory) / name for name in ['ca.pem', 'agent.pem', 'agent.key']]
            if transfer_signer is not None:
                staged.append(Path(directory) / 'transfer-signer.pem')
            for path, value in zip(staged, payload):
                self.put(path, value)
            self.run([self.openssl(), 'verify', '-purpose', 'sslclient', '-CAfile', str(staged[0]), str(staged[1])],
                     check=True, capture_output=True)
            public = self.run([self.openssl(), 'x509', '-in', str(staged[1]), '-pubkey', '-noout'], check=True, capture_output=True).stdout
            private_public = self.run([self.openssl(), 'pkey', '-in', str(staged[2]), '-pubout'], check=True, capture_output=True).stdout
            if public != private_public:
                raise RuntimeError('Certificate and private key do not match')
            if transfer_signer is not None:
                self.openssl_for_public_key(staged[3])
                self.run([self.openssl(), 'pkey', '-pubin', '-in', str(staged[3])], check=True,
                         capture_output=True)
        config = self.path(CONFIG)
        config.mkdir(mode=0o700, parents=True, exist_ok=True)
        if config.stat().st_uid != os.getuid() or config.stat().st_mode & 0o077:
            raise RuntimeError('Identity directory must be owned and private')
        files = [config / name for name in ['ca.pem', 'agent.pem', 'agent.key']]
        signer = config / 'transfer-signer.pem'
        if transfer_signer is not None:
            files.append(signer)
        env = config / 'agent.env'
        local = None
        if env.exists():
            current = self.settings()
            if not any(name in current for name in ('AGENT_CONSOLE_ENDPOINT', 'AGENT_GATEWAY_ID',
                    'AGENT_BINDING_GENERATION', 'AGENT_CA', 'AGENT_CERT', 'AGENT_KEY')):
                self.guard_writer()
                local = self.check()
                if any(p.exists() for p in [*files, signer, config / '.identity-installing']):
                    raise RuntimeError('Interrupted identity installation')
                settings = {**local, **{k: v for k, v in settings.items() if k in (
                    'AGENT_CONSOLE_ENDPOINT', 'AGENT_GATEWAY_ID', 'AGENT_BINDING_GENERATION',
                    'AGENT_CA', 'AGENT_CERT', 'AGENT_KEY')}}
        expected = [*payload, self.serialize(settings).encode()]
        if local is None and any(path.exists() for path in [*files, env, config / '.identity-installing']):
            # No force option: another console registration/partial import must be handled explicitly.
            if (all(path.is_file() and not path.is_symlink() and path.read_bytes() == value
                    for path, value in zip(files, payload)) and env.is_file()
                    and not (config / '.identity-installing').exists()):
                current = self.settings()
                if all(current.get(name) == value for name, value in settings.items()
                       if name not in ('AGENT_KURA_UID', 'AGENT_NETWORK_INTERFACES', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE',
                                       'AGENT_REMOTE_ENABLED', 'AGENT_KURA_REMOTE_MANAGEMENT')):
                    for path in files[:3]:
                        self.private(path)
                    if transfer_signer is not None:
                        self.public_key(signer)
                    return
            raise RuntimeError('Existing or interrupted identity; explicit transfer/recovery required')
        marker = config / '.identity-installing'
        if local is not None:
            self.put_durable(config / 'local-enrollment-before.env', env.read_bytes())
        self.put(marker, 'v1\n')
        for path, value in zip([*files, env], expected):
            if local is not None and path == env:
                self.replace_bytes(env, value)
            elif path == signer:
                self.put(path, value, 0o644)
            else:
                self.put(path, value)
        marker.unlink()

    BUNDLE_MEMBERS = ('manifest.json', 'ca.pem', 'agent.pem', 'agent.key')
    BUNDLE_MEMBER_LIMITS = {'manifest.json': 16384, 'ca.pem': 65536, 'agent.pem': 65536, 'agent.key': 65536}
    BUNDLE_MAX = 1024 * 1024

    @staticmethod
    def pem_certificate_der(value):
        lines = [line.strip() for line in value.decode('utf-8').splitlines() if line.strip()]
        if len(lines) < 3 or lines[0] != '-----BEGIN CERTIFICATE-----' or lines[-1] != '-----END CERTIFICATE-----':
            raise RuntimeError('Bundle certificate must be one public PEM certificate')
        try:
            return base64.b64decode(''.join(lines[1:-1]), validate=True)
        except ValueError as error:
            raise RuntimeError('Bundle certificate body is not base64') from error

    def read_bundle(self, bundle_path):
        """Validate and unpack a console-issued bundle (uncompressd ustar).

        Returns (manifest, contents) with the four members; manifest
        fingerprints must match the archive contents. Local file operation with
        no network side effects.
        """
        path = Path(bundle_path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > self.BUNDLE_MAX:
            raise RuntimeError('Identity bundle must be a bounded regular file')
        data = path.read_bytes()
        contents = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                members = archive.getmembers()
                if sorted(member.name for member in members) != sorted(self.BUNDLE_MEMBERS) \
                        or any(not member.isreg() for member in members):
                    raise RuntimeError('Bundle members must be exactly the four identity files')
                for member in members:
                    limit = self.BUNDLE_MEMBER_LIMITS[member.name]
                    if member.size > limit:
                        raise RuntimeError(f'Bundle member {member.name} exceeds its size bound')
                    contents[member.name] = archive.extractfile(member).read()
        except tarfile.TarError as error:
            raise RuntimeError('Identity bundle must be an uncompressed ustar archive') from error
        try:
            manifest = json.loads(contents['manifest.json'].decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError('Bundle manifest must be valid JSON') from error
        if not isinstance(manifest, dict) or manifest.get('schemaVersion') != 1 \
                or manifest.get('purpose') not in ('identity', 'rotation'):
            raise RuntimeError('Unsupported identity bundle manifest')
        required = ['gatewayId', 'caFingerprint', 'certificateFingerprint']
        required.append('endpoint' if manifest['purpose'] == 'identity' else 'previousCertificateSha256')
        for field in required:
            if not isinstance(manifest.get(field), str) or not manifest[field]:
                raise RuntimeError(f'Bundle manifest field {field} is required')
        for field in ('caFingerprint', 'certificateFingerprint', 'previousCertificateSha256'):
            if manifest.get(field) is not None and not re.fullmatch(r'[0-9a-f]{64}', manifest[field]):
                raise RuntimeError(f'Bundle manifest {field} must be a lowercase SHA-256')
        if hashlib.sha256(self.pem_certificate_der(contents['ca.pem'])).hexdigest() != manifest['caFingerprint'] \
                or hashlib.sha256(self.pem_certificate_der(contents['agent.pem'])).hexdigest() != manifest['certificateFingerprint']:
            raise RuntimeError('Bundle manifest fingerprints do not match the archive contents')
        return manifest, contents

    def import_bundle(self, bundle_path):
        """Import a console-issued one-time identity bundle (uncompressd ustar)."""
        manifest, contents = self.read_bundle(bundle_path)
        if manifest['purpose'] != 'identity':
            raise RuntimeError('Identity import requires an identity-purpose bundle; use rotate-bundle')
        with tempfile.TemporaryDirectory(prefix='kura-agent-bundle-') as directory:
            staged = {name: Path(directory) / name for name in ('ca.pem', 'agent.pem', 'agent.key')}
            for name, target in staged.items():
                self.put(target, contents[name])
            self.import_identity(manifest['endpoint'], manifest['gatewayId'],
                                 staged['ca.pem'], staged['agent.pem'], staged['agent.key'])

    def rotate_bundle(self, bundle_path, operator):
        """Rotate the installed client identity from a console-issued bundle.

        The bundle's previousCertificateSha256 must match the installed
        certificate, so a stale or wrong-gateway rotation package is refused
        before anything is touched. Delegates to rotate_client_certificate for
        the stopped-agent, CA-chain, pairing, backup and receipt requirements.
        """
        manifest, contents = self.read_bundle(bundle_path)
        if manifest['purpose'] != 'rotation':
            raise RuntimeError('Rotation requires a rotation-purpose bundle; use import-bundle')
        current = self.check(require_remote=False)
        installed = self.path(current['AGENT_CERT'])
        installed_hash = hashlib.sha256(self.pem_certificate_der(installed.read_bytes())).hexdigest()
        if installed_hash != manifest['previousCertificateSha256']:
            raise RuntimeError('Rotation bundle was issued against a different installed certificate')
        if installed_hash == manifest['certificateFingerprint']:
            raise RuntimeError('Rotation bundle is identical to the installed certificate')
        with tempfile.TemporaryDirectory(prefix='kura-agent-rotation-') as directory:
            staged = {name: Path(directory) / name for name in ('agent.pem', 'agent.key')}
            for name, target in staged.items():
                self.put(target, contents[name])
            self.rotate_client_certificate(staged['agent.pem'], staged['agent.key'], operator)

    CERT_REQUEST_SCHEMA = 'yofc.agent.certificate-request.v1'

    def create_certificate_request(self, gateway, csr_path):
        """Generate a private key plus CSR locally; the key never leaves the box.

        First-provisioning path only: refuse when an identity is already
        installed (rotation has its own flow). The pending key waits in
        STATE/certificate-requests until activate-pending-certificate pairs it
        with an externally issued certificate.
        """
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', gateway):
            raise RuntimeError('Invalid gateway identifier')
        self.inactive()
        settings_path = self.path(CONFIG + '/agent.env')
        if settings_path.exists():
            current = self.settings()
            if 'AGENT_CONSOLE_ENDPOINT' in current:
                raise RuntimeError('Identity already installed; use rotate-client-certificate or rotate-bundle for rotation')
        if self.path(STATE + '/enrollment').exists():
            raise RuntimeError('Managed identity enrollment requires an explicit verified archive; CSR request is unavailable')
        output = Path(csr_path)
        if output.is_symlink() or not output.parent.is_dir():
            raise RuntimeError('CSR output must be a regular path in an existing directory')
        if output.exists():
            raise RuntimeError('CSR output already exists; choose a new file')
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            parent_info = os.fstat(parent_fd)
            base = self.path(STATE + '/certificate-requests')
            if base.exists() and any(base.iterdir()):
                raise RuntimeError('A pending certificate request already exists; activate it or delete STATE/certificate-requests first')
            base.mkdir(parents=True, exist_ok=False, mode=0o700)
            key = base / 'agent.key'
            csr = base / 'request.csr'
            self.run([self.openssl(), 'genpkey', '-algorithm', 'EC',
                      '-pkeyopt', 'ec_paramgen_curve:P-256',
                      '-pkeyopt', 'ec_param_enc:named_curve', '-out', str(key)],
                     check=True, capture_output=True)
            os.chmod(key, 0o600)
            self.run([self.openssl(), 'req', '-new', '-sha256', '-key', str(key),
                      '-subj', f'/CN={gateway}', '-out', str(csr)],
                     check=True, capture_output=True)
            public = self.run([self.openssl(), 'pkey', '-in', str(key), '-pubout'],
                              check=True, capture_output=True).stdout
            pending = {
                'schema': self.CERT_REQUEST_SCHEMA,
                'gatewayId': gateway,
                'publicKeySha256': hashlib.sha256(public).hexdigest(),
                'createdAtUnixMs': int(time.time() * 1000),
            }
            self.put(base / 'pending.json',
                     json.dumps(pending, sort_keys=True, separators=(',', ':')) + '\n')
            current_parent = os.stat(output.parent, follow_symlinks=False)
            if not stat.S_ISDIR(current_parent.st_mode) or (current_parent.st_dev, current_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                raise RuntimeError('CSR output directory changed during key generation')
            descriptor = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=parent_fd)
            # Work only through the exclusively created descriptor. A concurrent
            # path replacement cannot redirect either the write or chmod.
            with os.fdopen(descriptor, 'wb') as exported:
                exported.write(csr.read_bytes())
                exported.flush()
                os.fchmod(exported.fileno(), 0o644)
                os.fsync(exported.fileno())
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        print(f'Certificate request written: {output}')
        print(f'Public key SHA-256: {pending["publicKeySha256"]}')

    def activate_pending_certificate(self, endpoint, ca, cert):
        """Pair the pending locally-generated key with its issued certificate."""
        self.inactive()
        base = self.path(STATE + '/certificate-requests')
        pending_path = base / 'pending.json'
        if not pending_path.is_file() or pending_path.is_symlink():
            raise RuntimeError('No pending certificate request; run create-certificate-request first')
        pending = json.loads(pending_path.read_text())
        if pending.get('schema') != self.CERT_REQUEST_SCHEMA:
            raise RuntimeError('Unrecognized pending certificate request')
        gateway = pending['gatewayId']
        sources = [Path(ca), Path(cert)]
        for path in sources:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Certificate inputs must be bounded regular files')
        pending_key = base / 'agent.key'
        if not pending_key.is_file() or pending_key.is_symlink():
            raise RuntimeError('Pending private key is missing; recreate the certificate request')
        staged_key = base / 'activate.key'
        shutil.copyfile(pending_key, staged_key)
        os.chmod(staged_key, 0o600)
        with tempfile.TemporaryDirectory(prefix='kura-agent-csr-') as directory:
            staged = {name: Path(directory) / name for name in ('ca.pem', 'agent.pem', 'agent.key')}
            self.put(staged['agent.key'], pending_key.read_bytes())
            self.put(staged['ca.pem'], sources[0].read_bytes())
            self.put(staged['agent.pem'], sources[1].read_bytes())
            installed_public = self.run([self.openssl(), 'pkey', '-in', str(staged['agent.key']), '-pubout'],
                                        check=True, capture_output=True).stdout
            if hashlib.sha256(installed_public).hexdigest() != pending['publicKeySha256']:
                raise RuntimeError('Pending key no longer matches the recorded request')
            certificate_public = self.run([self.openssl(), 'x509', '-in', str(staged['agent.pem']), '-pubkey', '-noout'],
                                          check=True, capture_output=True).stdout
            if installed_public != certificate_public:
                raise RuntimeError('Issued certificate does not match the locally generated key')
        # import_identity re-verifies the CA chain, pairing, endpoint and
        # gateway id before anything is installed.
        self.import_identity(endpoint, gateway, sources[0], sources[1], staged_key)
        shutil.rmtree(base)
        print(f'Activated locally-generated identity for {gateway}')

    def guard_core_loader(self, expected):
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise RuntimeError('Missing reviewed Core loader binding')
        status = self.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}', 'kura-core'],
                          capture_output=True, text=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if status.returncode not in (0, 1):
            raise RuntimeError('Cannot verify installed Core package state')
        state = status.stdout.strip()
        if status.returncode or state in {'not-installed', 'config-files', 'half-installed', 'unpacked', 'half-configured'}:
            return  # Standalone agent or an unconfigured Core; no Core dependency.
        if state not in {'installed', 'triggers-awaited', 'triggers-pending'}:
            raise RuntimeError('Unknown Core package state; preserve the component cohort')
        home = self.root / 'opt/eclipse/kura'
        if home.is_symlink():
            target = home.resolve(strict=True)
            if home.lstat().st_uid != os.geteuid() or target.parent != home.parent or not target.name.startswith('kura_'):
                raise RuntimeError('Unsafe Core home for adapter pairing')
        else:
            target = home
        loader = target / 'bin/gen_config_ini.sh'
        self.authorization_parents(loader)
        value = loader.lstat()
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                or value.st_nlink != 1 or value.st_mode & 0o022
                or hashlib.sha256(loader.read_bytes()).hexdigest() != expected):
            raise RuntimeError('Upgrade the paired Core optional-adapter loader before this agent package')
        return target

    def authorization_parents(self, path):
        for parent in path.parents:
            if parent.exists():
                value = parent.lstat()
                if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
                        or value.st_mode & 0o022):
                    raise RuntimeError('Unsafe Kura authorization directory')
            if parent == self.root:
                break

    def authorization_dropins(self):
        result = {}
        for username, (_, filename) in KURA_PROFILES.items():
            path = self.path(filename)
            self.authorization_parents(path)
            if os.path.lexists(path):
                value = path.lstat()
                if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                        or value.st_nlink != 1 or value.st_mode & 0o022
                        or path.read_text() != DROPIN_CONTENT):
                    raise RuntimeError('Refusing externally modified Kura authorization')
                result[username] = path
        return result

    def authorization_account(self, username, require_service=True):
        if username not in KURA_PROFILES:
            raise RuntimeError('Only a packaged kurad or kura-netplan profile can be authorized')
        account = pwd.getpwnam(username)
        if account.pw_uid <= 0 or account.pw_gid <= 0 or account.pw_uid >= 4294967295:
            raise RuntimeError('Kura authorization requires a non-Root package account')
        if not require_service:
            return account
        unit, _ = KURA_PROFILES[username]
        vendor = self.path('/usr/lib/systemd/system/' + unit)
        self.authorization_parents(vendor)
        if not vendor.is_file():
            raise RuntimeError('The selected Kura service package is not installed')
        value = vendor.lstat()
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                or value.st_nlink != 1 or value.st_mode & 0o022 or value.st_size > 65536):
            raise RuntimeError('Unsafe Kura vendor unit')
        service, users = False, []
        for line in vendor.read_text().splitlines():
            line = line.strip()
            if line.startswith('['):
                service = line == '[Service]'
            elif service and line.startswith('User='):
                users.append(line[5:])
        if users != [username]:
            raise RuntimeError('Kura service User does not match the selected profile')
        live = self.systemctl('show', unit, '--property=LoadState', '--property=User')
        if live is not None:
            fields = dict(line.split('=', 1) for line in live.stdout.splitlines() if '=' in line)
            if fields.get('LoadState') != 'loaded' or fields.get('User') != username:
                raise RuntimeError('Effective Kura service User differs from its vendor profile')
        return account

    def authorize(self, username):
        self.inactive()
        settings = self.settings()
        account = self.authorization_account(username)
        if settings.get('AGENT_KURA_UID') not in ('4294967295', str(account.pw_uid)):
            raise RuntimeError('Another Kura UID is already authorized')
        self.guard_writer()
        existing = self.authorization_dropins()
        if any(name != username for name in existing):
            raise RuntimeError('Another Kura service profile is already authorized')
        dropin = self.path(KURA_PROFILES[username][1])
        self.authorization_parents(dropin)
        settings['AGENT_KURA_UID'] = str(account.pw_uid)
        settings['AGENT_KURA_NETWORK_INTERFACES'] = ''
        dropin.parent.mkdir(parents=True, exist_ok=True)
        if not dropin.exists():
            self.put(dropin, DROPIN_CONTENT, 0o644)
        self.replace(self.path(CONFIG + '/agent.env'), self.serialize(settings))
        self.systemctl('daemon-reload')

    def reader_file(self, name, mode=0o644, limit=65536):
        """Bounded, immutable-during-read native Root code or grant bytes."""
        path = self.path(name)
        self.authorization_parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                     | getattr(os, 'O_NOATIME', 0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1 or before.st_size > limit):
                raise RuntimeError('Unsafe native enrollment reader file')
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            identity = lambda m: (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode,
                                  m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
            if len(raw) != before.st_size or identity(before) != identity(after):
                raise RuntimeError('Native enrollment reader file changed')
            return raw

    @staticmethod
    def reader_json(raw):
        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise RuntimeError('Duplicate native enrollment reader field')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=pairs)

    def reader_pair(self):
        raw = self.reader_file(READER_META)
        value = self.reader_json(raw)
        if (set(value) != {'schemaVersion', 'protocolVersion', 'user', 'socket', 'sourceRoot', 'files'}
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                or type(value['protocolVersion']) is not int or value['protocolVersion'] != 1
                or value['user'] != 'kurad' or value['socket'] != READER_SOCKET or value['sourceRoot'] != READER_SOURCE
                or not isinstance(value['files'], dict) or set(value['files']) != set(READER_FILES)):
            raise RuntimeError('Invalid native enrollment reader pair')
        provenance = self.reader_json(self.reader_file('/usr/share/kura-management-agent/source-manifest.json', limit=2 * 1024 * 1024))
        rows = provenance.get('sourceFiles', [])
        records = {row['path']: row['sha256'] for row in rows}
        if provenance.get('schemaVersion') != 2 or len(records) != len(rows):
            raise RuntimeError('Complete native enrollment reader source provenance required')
        for path, name in READER_FILES.items():
            digest = value['files'][path]
            if (not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest)
                    or records.get('packaging/' + name) != digest
                    or hashlib.sha256(self.reader_file(path)).hexdigest() != digest):
                raise RuntimeError('Native enrollment reader source/unit pair changed')
        # Probe effective common overrides and also reject per-instance files.
        # Socket-generated instance names differ from the admission probe.
        for directory in ['/etc/systemd/system', '/etc/systemd/system.control',
                          '/run/systemd/system', '/run/systemd/system.control', '/run/systemd/transient',
                          '/run/systemd/generator.early', '/run/systemd/generator', '/run/systemd/generator.late',
                          '/usr/local/lib/systemd/system', '/usr/lib/systemd/system']:
            parent = self.path(directory)
            if parent.exists():
                self.authorization_parents(parent / '.reader-admission')
                for path in parent.glob('kura-management-enrollment-reader*'):
                    if directory != '/usr/lib/systemd/system' or path.name not in [READER_SOCKET_UNIT, READER_SERVICE_UNIT]:
                        raise RuntimeError('Unreviewed native enrollment reader unit or instance override')
        for unit in [READER_SOCKET_UNIT, 'kura-management-enrollment-reader@admission.service']:
            live = self.systemctl('show', unit, '--property=LoadState', '--property=FragmentPath', '--property=DropInPaths')
            if live is not None:
                fields = dict(line.split('=', 1) for line in live.stdout.splitlines() if '=' in line)
                vendor = READER_SERVICE_UNIT if '@' in unit else READER_SOCKET_UNIT
                if (fields.get('LoadState') != 'loaded' or fields.get('DropInPaths') != ''
                        or fields.get('FragmentPath') != '/usr/lib/systemd/system/' + vendor):
                    raise RuntimeError('Effective native enrollment reader units differ from the reviewed pair')
        return hashlib.sha256(raw).hexdigest()

    def check_reader(self, settings):
        keys = {'AGENT_KURA_ENROLLMENT_READER_SOCKET', 'AGENT_KURA_ENROLLMENT_DIR'}
        enabled = 'AGENT_KURA_ENROLLMENT_READER_SOCKET' in settings
        retained = os.path.lexists(self.path(READER_GRANT))
        if not enabled:
            if retained:
                raise RuntimeError('Retained native enrollment grant requires explicit recovery')
            return
        if (any(key not in settings for key in keys) or settings['AGENT_KURA_ENROLLMENT_READER_SOCKET'] != READER_SOCKET
                or settings['AGENT_KURA_ENROLLMENT_DIR'] != READER_SOURCE):
            raise RuntimeError('Exact explicit native enrollment reader paths required')
        account = self.authorization_account('kurad', require_service=False)
        profiles = self.authorization_dropins()
        if settings.get('AGENT_KURA_UID') != str(account.pw_uid) or set(profiles) != {'kurad'}:
            raise RuntimeError('Native enrollment reader requires the authorized packaged Kura UID')
        grant = self.reader_json(self.reader_file(READER_GRANT, mode=0o600))
        if (set(grant) != {'schemaVersion', 'requestId', 'sourceUid', 'sourceRoot', 'socket', 'pairSha256', 'operator'}
                or type(grant['schemaVersion']) is not int or grant['schemaVersion'] != 1
                or type(grant['sourceUid']) is not int or grant['sourceUid'] != account.pw_uid
                or grant['sourceRoot'] != READER_SOURCE or grant['socket'] != READER_SOCKET
                or not self.authorization_operator(grant['operator'])
                or not isinstance(grant['requestId'], str) or str(uuid.UUID(grant['requestId'])) != grant['requestId']
                or grant['pairSha256'] != self.reader_pair()):
            raise RuntimeError('Native enrollment reader grant differs from the reviewed pair')
        if self.authorization_status(grant['requestId'])['phase'] != 'APPLIED':
            raise RuntimeError('Native enrollment authorization has no original completion proof')

    @staticmethod
    def authorization_id(value):
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise RuntimeError('Use the original local authorization UUID')
        return value

    @staticmethod
    def authorization_operator(value):
        return (isinstance(value, str) and 1 <= len(value.encode('utf-8')) <= 128
                and all(character.isprintable() for character in value))

    def authorization_status(self, request_id):
        """Observe one original local action; never repeat an authorization write."""
        self.authorization_id(request_id)
        base = AUTHORIZATIONS + '/' + request_id
        intent_path = self.path(base + '.intent.json')
        if not os.path.lexists(intent_path):
            partial = self.path(AUTHORIZATIONS).exists() and any(
                request_id in item.name for item in self.path(AUTHORIZATIONS).iterdir())
            return {'requestId': request_id, 'phase': 'UNKNOWN' if partial else 'UNOBSERVED',
                    'transportNonDeliveryCertified': False}
        raw = self.reader_file(base + '.intent.json', mode=0o600)
        intent = self.reader_json(raw)
        expected = {'schemaVersion', 'requestId', 'action', 'operator', 'sourceUid', 'sourceRoot',
                    'socket', 'pairSha256', 'grantSha256', 'previousEnvSha256', 'envSha256'}
        if (set(intent) != expected or type(intent['schemaVersion']) is not int or intent['schemaVersion'] != 1
                or intent['requestId'] != request_id or intent['action'] != 'grant-kura-enrollment'
                or type(intent['sourceUid']) is not int or not 0 < intent['sourceUid'] < 4294967295
                or intent['sourceRoot'] != READER_SOURCE or intent['socket'] != READER_SOCKET
                or not self.authorization_operator(intent['operator'])
                or any(not isinstance(intent[key], str) or not re.fullmatch('[a-f0-9]{64}', intent[key])
                       for key in ['pairSha256', 'grantSha256', 'previousEnvSha256', 'envSha256'])):
            raise RuntimeError('Invalid original local authorization intent')
        result = {'requestId': request_id, 'phase': 'UNKNOWN', 'action': intent['action'],
                  'transportNonDeliveryCertified': False}
        if not os.path.lexists(self.path(base + '.result.json')):
            return result
        expected_grant = {'schemaVersion': 1, 'requestId': request_id, 'sourceUid': intent['sourceUid'],
                          'sourceRoot': READER_SOURCE, 'socket': READER_SOCKET,
                          'pairSha256': intent['pairSha256'], 'operator': intent['operator']}
        for suffix, digest in [('.previous.env', intent['previousEnvSha256']),
                               ('.requested.env', intent['envSha256']), ('.grant.json', intent['grantSha256'])]:
            data = self.reader_file(base + suffix, mode=0o600)
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError('Original local authorization evidence changed')
            if suffix == '.grant.json' and self.reader_json(data) != expected_grant:
                raise RuntimeError('Original local authorization grant changed')
        receipt = self.reader_json(self.reader_file(base + '.result.json', mode=0o600))
        expected_receipt = {'schemaVersion': 1, 'requestId': request_id,
                            'intentSha256': hashlib.sha256(raw).hexdigest(),
                            'settingsSha256': intent['envSha256'], 'grantSha256': intent['grantSha256'],
                            'unitStarted': False, 'remoteEnabled': False}
        if (receipt != expected_receipt or type(receipt.get('schemaVersion')) is not int
                or type(receipt.get('unitStarted')) is not bool or type(receipt.get('remoteEnabled')) is not bool):
            raise RuntimeError('Original local authorization receipt changed')
        if os.path.lexists(self.path(AUTHORIZATION_PENDING)):
            pending = self.reader_json(self.reader_file(AUTHORIZATION_PENDING, mode=0o600))
            if pending.get('requestId') == request_id:
                return result
        return {**result, 'phase': 'APPLIED', 'receipt': receipt}

    def guard_local_authorizations(self):
        if os.path.lexists(self.path(AUTHORIZATION_PENDING)):
            raise RuntimeError('Interrupted local authorization; preserve its original intent and grant')
        directory = self.path(AUTHORIZATIONS)
        if not directory.exists():
            return
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('Unsafe retained local authorization directory')
        names = list(directory.iterdir())
        if len(names) > 512:
            raise RuntimeError('Preserve and explicitly archive retained local authorizations')
        ids = set()
        for path in names:
            match = re.fullmatch(r'([a-f0-9-]{36})\.(intent\.json|previous\.env|requested\.env|grant\.json|result\.json)', path.name)
            if not match:
                raise RuntimeError('Incomplete local authorization evidence; preserve all files')
            ids.add(self.authorization_id(match[1]))
        for request_id in ids:
            if self.authorization_status(request_id)['phase'] != 'APPLIED':
                raise RuntimeError('Observe the original uncertain local authorization before changing it')

    def grant_enrollment(self, request_id, operator):
        self.authorization_id(request_id)
        if not self.authorization_operator(operator):
            raise RuntimeError('Bounded operator identity required')
        base = AUTHORIZATIONS + '/' + request_id
        if self.authorization_status(request_id)['phase'] != 'UNOBSERVED':
            # Returning an original observation is deliberately not a repair or
            # a second execution, even when the caller repeats the same UUID.
            return self.authorization_status(request_id)
        self.guard_writer()
        settings = self.check()
        account = self.authorization_account('kurad')
        if (settings.get('AGENT_KURA_UID') != str(account.pw_uid)
                or set(self.authorization_dropins()) != {'kurad'}):
            raise RuntimeError('Authorize the packaged Kura UID before granting enrollment')
        if settings.get('AGENT_REMOTE_ENABLED', '0') != '0':
            raise RuntimeError('Disable the remote channel before changing local authorization')
        decision = self.path(STATE + '/remote-management.json')
        if decision.exists() and self.reader_json(self.reader_file(STATE + '/remote-management.json', mode=0o600))['enabled'] is not False:
            raise RuntimeError('Disable the remote channel before changing local authorization')
        if os.path.lexists(self.path(READER_GRANT)) or 'AGENT_KURA_ENROLLMENT_READER_SOCKET' in settings:
            raise RuntimeError('Native enrollment is already granted; retain the original authorization')
        pair = self.reader_pair()
        directory = self.path(AUTHORIZATIONS)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.guard_local_authorizations()
        grant = {'schemaVersion': 1, 'requestId': request_id, 'sourceUid': account.pw_uid,
                 'sourceRoot': READER_SOURCE, 'socket': READER_SOCKET, 'pairSha256': pair, 'operator': operator}
        encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'
        grant_raw = encode(grant)
        previous = self.reader_file(CONFIG + '/agent.env', mode=0o600)
        settings['AGENT_KURA_ENROLLMENT_DIR'] = READER_SOURCE
        settings['AGENT_KURA_ENROLLMENT_READER_SOCKET'] = READER_SOCKET
        requested = self.serialize(settings)
        digest = lambda value: hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()
        intent = {'schemaVersion': 1, 'requestId': request_id, 'action': 'grant-kura-enrollment',
                  'operator': operator, 'sourceUid': account.pw_uid, 'sourceRoot': READER_SOURCE,
                  'socket': READER_SOCKET, 'pairSha256': pair, 'grantSha256': digest(grant_raw),
                  'previousEnvSha256': digest(previous), 'envSha256': digest(requested)}
        raw = encode(intent)
        self.put_durable(self.path(base + '.intent.json'), raw)
        self.put_durable(self.path(AUTHORIZATION_PENDING), raw)
        for suffix, value in [('.previous.env', previous), ('.requested.env', requested), ('.grant.json', grant_raw)]:
            self.put_durable(self.path(base + suffix), value)
        self.put_durable(self.path(READER_GRANT), grant_raw)
        self.replace(self.path(CONFIG + '/agent.env'), requested)
        if (self.reader_file(CONFIG + '/agent.env', mode=0o600) != requested.encode()
                or self.reader_file(READER_GRANT, mode=0o600) != grant_raw.encode() or self.reader_pair() != pair):
            raise RuntimeError('Local authorization requires original recovery')
        receipt = {'schemaVersion': 1, 'requestId': request_id, 'intentSha256': digest(raw),
                   'settingsSha256': intent['envSha256'], 'grantSha256': intent['grantSha256'],
                   'unitStarted': False, 'remoteEnabled': False}
        self.put_durable(self.path(base + '.result.json'), encode(receipt))
        self.path(AUTHORIZATION_PENDING).unlink()
        descriptor = os.open(self.path(CONFIG), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.check()
        return self.authorization_status(request_id)

    def configure_system_control(self, request, remote, operator):
        """Install an explicit fixed-unit grant; preserve prior grants/settings."""
        if type(remote) is not bool or not operator or len(operator) > 128 or any(c in operator for c in '\r\n\x00'):
            raise RuntimeError('Explicit remote boolean and bounded operator identity required')
        self.guard_writer()
        settings = self.check()
        request = Path(request)
        if not request.is_absolute() or request.stat().st_size > 512 * 1024:
            raise RuntimeError('Absolute bounded private system control request required')
        self.private(request)
        ident = str(uuid.uuid4())
        relative = CONFIG + '/system-control-' + ident + '.json'
        output = self.path(relative)
        # The installed Rust sealer checks the actual effective systemd mapping,
        # file pins and cgroup stop policy. It never starts/enables a target.
        result = self.run([str(self.path('/usr/bin/yofc-management-agent')),
                           'seal-system-control', '--request', str(request), '--output', str(output)],
                          check=True, capture_output=True, text=True)
        self.private(output)
        sealed = output.read_bytes()
        summary = json.loads(result.stdout)
        if summary.get('grantSha256') != hashlib.sha256(sealed).hexdigest() or any(summary.get(k) is not False for k in ('unitStarted', 'unitEnabled', 'remoteEnabled')):
            raise RuntimeError('System control seal receipt does not match the retained grant')
        env = self.path(CONFIG + '/agent.env')
        old = env.read_bytes()
        audit = self.path(STATE + '/system-control-installations')
        audit.mkdir(mode=0o700, parents=True, exist_ok=True)
        if audit.stat().st_uid != os.geteuid() or audit.stat().st_mode & 0o077:
            raise RuntimeError('Private installation audit directory required')
        self.put_durable(audit / (ident + '.previous.env'), old)
        settings['AGENT_SYSTEM_CONTROL_CONFIG'] = relative
        settings['AGENT_SYSTEM_CONTROL_REMOTE'] = '1' if remote else '0'
        new = self.serialize(settings)
        record = {'schema': 1, 'id': ident, 'operator': operator, 'grant': relative,
                  'grantSha256': hashlib.sha256(sealed).hexdigest(),
                  'previousEnvSha256': hashlib.sha256(old).hexdigest(),
                  'envSha256': hashlib.sha256(new.encode()).hexdigest(), 'remote': remote,
                  'unitStarted': False, 'unitEnabled': False}
        intent = self.path(CONFIG + '/.system-control-installing')
        self.put_durable(intent, json.dumps(record, separators=(',', ':')))
        self.replace(env, new)
        self.put_durable(audit / (ident + '.json'), json.dumps(record, separators=(',', ':')))
        intent.unlink()
        directory = os.open(env.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.check()
        return record

    @staticmethod
    def interface_list(value):
        names = value.split(',')
        if not names or any(not name for name in names):
            raise RuntimeError('Interface list must not contain empty entries')
        if len(names) != len(set(names)):
            raise RuntimeError('Interface list must be unique')
        for name in names:
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,15}', name):
                raise RuntimeError('Invalid interface name: ' + name)
        return names

    def grant_network_writer(self, interfaces, operator):
        """Delegate network writing to this agent for exactly the named interfaces."""
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        names = self.interface_list(interfaces)
        self.inactive()
        self.guard_transactions()
        journal = self.path(STATE + '/network/transaction.json')
        if journal.exists() and json.loads(journal.read_text()).get('state') not in ('COMMITTED', 'ROLLED_BACK'):
            raise RuntimeError('Settle the network transaction before granting a writer')
        settings = self.settings()
        if settings.get('AGENT_NETWORK_INTERFACES'):
            raise RuntimeError('Hand the current network writer over before granting another')
        if self.path(STATE + '/network/confirmed.json').exists():
            raise RuntimeError('Hand the confirmed network state over before granting a writer')
        settings['AGENT_NETWORK_INTERFACES'] = ','.join(names)
        self.replace(self.path(CONFIG + '/agent.env'), self.serialize(settings))
        self.check()

    def handover_network_writer(self, operator, discard_config=False):
        """Return the network writer role and confirmed state to the system.

        By default the persisted managed Netplan file stays in place so the
        system keeps the last confirmed configuration; the agent only drops its
        management markers. Deleting the file requires --discard-config and is
        refused when the file no longer matches the confirmed content.
        """
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        self.inactive()
        self.guard_transactions()
        journal = self.path(STATE + '/network/transaction.json')
        if journal.exists() and json.loads(journal.read_text()).get('state') not in ('COMMITTED', 'ROLLED_BACK'):
            raise RuntimeError('Settle the network transaction before handover')
        settings = self.settings()
        interfaces = settings.get('AGENT_NETWORK_INTERFACES', '')
        confirmed_path = self.path(STATE + '/network/confirmed.json')
        if not interfaces and not confirmed_path.exists():
            raise RuntimeError('No network writer or confirmed state to hand over')
        kept = True
        yaml_sha = None
        revision = None
        if confirmed_path.exists():
            confirmed = json.loads(confirmed_path.read_text())
            yaml_text = confirmed.get('yaml')
            revision = confirmed.get('revision')
            if yaml_text:
                yaml_sha = hashlib.sha256(yaml_text.encode()).hexdigest()
                managed = self.path('/etc/netplan/90-yofc-managed.yaml')
                if managed.exists():
                    if managed.read_text() != yaml_text:
                        raise RuntimeError('Managed Netplan file drifted from confirmed state; resolve before handover')
                    if discard_config:
                        managed.unlink()
                kept = managed.exists()
            base = self.path(STATE + '/network/handovers')
            number = 1
            if base.exists():
                number = max([int(entry.name) for entry in base.iterdir()
                              if re.fullmatch(r'[1-9][0-9]{0,5}', entry.name)], default=0) + 1
            archive = base / str(number)
            archive.mkdir(parents=True, exist_ok=False, mode=0o700)
            self.put(archive / 'confirmed.json', confirmed_path.read_bytes())
            receipt = {
                'schema': 'yofc.agent.network-writer-handover.v1',
                'interfaces': interfaces,
                'revision': revision,
                'confirmedYamlSha256': yaml_sha,
                'keptManagedConfigFile': kept,
                'operator': operator,
                'handedOverAtUnixMs': int(time.time() * 1000),
            }
            self.put(archive / 'receipt.json', json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
            confirmed_path.unlink()
        elif discard_config:
            raise RuntimeError('No confirmed state to discard')
        settings['AGENT_NETWORK_INTERFACES'] = ''
        self.replace(self.path(CONFIG + '/agent.env'), self.serialize(settings))
        self.check()

    @staticmethod
    def openssl(algorithm=None):
        candidates = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl']
        if algorithm == 'ED25519':
            candidates = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl']
        for candidate in candidates:
            if Path(candidate).is_file():
                return candidate
        return 'openssl'

    @staticmethod
    def supports_ed25519(command):
        probe = Path('/tmp') / ('yofc-ed25519-probe-' + secrets.token_hex(8))
        try:
            result = subprocess.run([command, 'genpkey', '-algorithm', 'ED25519', '-out', str(probe)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        finally:
            try:
                probe.unlink()
            except FileNotFoundError:
                pass

    def openssl_for_public_key(self, path):
        command = self.openssl()
        result = self.run([command, 'pkey', '-pubin', '-in', str(path)], capture_output=True)
        if result.returncode == 0:
            return command
        modern = self.openssl('ED25519')
        if modern != command and self.supports_ed25519(modern):
            result = self.run([modern, 'pkey', '-pubin', '-in', str(path)], capture_output=True)
            if result.returncode == 0:
                return modern
        raise RuntimeError('Transfer signer public key cannot be read by installed OpenSSL')

    @staticmethod
    def private_input(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_mode & 0o077:
            raise RuntimeError('Private identity input must be a bounded regular file with mode 0600')

    def certificate_sha256(self, path):
        result = self.run([self.openssl(), 'x509', '-in', str(path), '-outform', 'DER'], check=True,
                          capture_output=True)
        return hashlib.sha256(result.stdout).hexdigest()

    def replace_bytes(self, path, value):
        temporary = path.with_name('.' + path.name + '.transfer-new')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        self.private(path)

    def public_spki_sha256(self, path):
        openssl = self.openssl_for_public_key(Path(path))
        result = self.run([openssl, 'pkey', '-pubin', '-in', str(path), '-outform', 'DER'],
                          check=True, capture_output=True)
        return hashlib.sha256(result.stdout).hexdigest()

    def verify_transfer_token(self, token_path, current_gateway, old_generation, new_generation,
                              endpoint, gateway, ca_hash, cert_hash, signer=TRANSFER_SIGNER):
        token_path = Path(token_path)
        if not token_path.is_file() or token_path.is_symlink() or token_path.stat().st_size > 65536:
            raise RuntimeError('Transfer authorization must be a bounded regular file')
        signer = self.path(signer)
        if not signer.exists():
            raise RuntimeError('Signed transfer requires a registered original-center signer')
        self.public_key(signer)
        openssl = self.openssl_for_public_key(signer)
        raw = token_path.read_text().splitlines()
        if len(raw) != 3 or raw[0] != 'YOFC-AGENT-TRANSFER-v1':
            raise RuntimeError('Invalid transfer authorization format')
        try:
            encoded_payload = raw[1]
            encoded_payload += '=' * (-len(encoded_payload) % 4)
            payload = base64.urlsafe_b64decode(encoded_payload.encode())
            signature = bytes.fromhex(raw[2])
        except (ValueError, BaseException) as error:
            raise RuntimeError('Invalid transfer authorization encoding') from error
        if not payload or len(payload) > 16384 or len(signature) != 64:
            raise RuntimeError('Invalid transfer authorization size')
        with tempfile.TemporaryDirectory(prefix='kura-agent-transfer-token-') as directory:
            payload_path = Path(directory) / 'payload'
            signature_path = Path(directory) / 'signature'
            self.put(payload_path, payload)
            self.put(signature_path, signature)
            result = self.run([openssl, 'pkeyutl', '-verify', '-rawin', '-pubin',
                               '-inkey', str(signer), '-sigfile', str(signature_path),
                               '-in', str(payload_path)], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError('Transfer authorization signature rejected')
        try:
            claims = json.loads(payload)
        except json.JSONDecodeError as error:
            raise RuntimeError('Invalid transfer authorization claims') from error
        now_ms = int(time.time() * 1000)
        required = {
            'schema': 'yofc.agent.transfer.v1', 'gatewayId': current_gateway,
            'fromBindingGeneration': old_generation, 'toBindingGeneration': new_generation,
            'newEndpoint': endpoint, 'newGatewayId': gateway,
            'newClientCertificateSha256': cert_hash, 'newClientCaSha256': ca_hash,
        }
        if not isinstance(claims, dict) or any(claims.get(key) != value for key, value in required.items()):
            raise RuntimeError('Transfer authorization does not match this gateway')
        expires = claims.get('expiresAtUnixMs')
        transfer_id = claims.get('transferId')
        if not isinstance(expires, int) or not (now_ms < expires <= now_ms + 900_000):
            raise RuntimeError('Transfer authorization is expired or unbounded')
        if not isinstance(transfer_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', transfer_id):
            raise RuntimeError('Invalid transfer authorization id')
        return claims

    def consume_transfer_token(self, token_path, claims, current, old_generation, endpoint,
                               gateway, ca_hash, cert_hash, operator, signer=TRANSFER_SIGNER):
        """Persist exact authorization material before any identity byte changes."""
        transfer_id = claims['transferId']
        uses = self.path(STATE + '/transfer-token-uses')
        uses.mkdir(parents=True, exist_ok=True, mode=0o700)
        record_path = uses / (transfer_id + '.json')
        if record_path.exists():
            raise RuntimeError('Transfer authorization has already been used')
        raw = Path(token_path).read_bytes()
        signer_path = self.path(signer)
        receipt = {
            'schema': 'yofc.agent.transfer-token-use.v1',
            'transferId': transfer_id,
            'fromGatewayId': current.get('AGENT_GATEWAY_ID'),
            'fromBindingGeneration': old_generation,
            'toGatewayId': gateway,
            'toBindingGeneration': old_generation + 1,
            'newEndpoint': endpoint,
            'newClientCertificateSha256': cert_hash,
            'newClientCaSha256': ca_hash,
            'tokenSha256': hashlib.sha256(raw).hexdigest(),
            'signerSha256': hashlib.sha256(signer_path.read_bytes()).hexdigest(),
            'operator': operator,
            'consumedAtUnixMs': int(time.time() * 1000),
        }
        self.put_durable(record_path, json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        return record_path

    def verify_rotation_token(self, token_path, gateway, generation, current_spki, new_spki,
                              operator, signer=TRANSFER_SIGNER):
        token_path = Path(token_path)
        if not token_path.is_file() or token_path.is_symlink() or token_path.stat().st_size > 65536:
            raise RuntimeError('Signer rotation authorization must be a bounded regular file')
        signer = self.path(signer)
        if not signer.exists():
            raise RuntimeError('Signer rotation requires the currently registered signer')
        self.public_key(signer)
        openssl = self.openssl_for_public_key(signer)
        raw = token_path.read_text().splitlines()
        if len(raw) != 3 or raw[0] != 'YOFC-AGENT-SIGNER-ROTATION-v1':
            raise RuntimeError('Invalid signer rotation authorization format')
        try:
            encoded_payload = raw[1]
            encoded_payload += '=' * (-len(encoded_payload) % 4)
            payload = base64.urlsafe_b64decode(encoded_payload.encode())
            signature = bytes.fromhex(raw[2])
        except (ValueError, BaseException) as error:
            raise RuntimeError('Invalid signer rotation authorization encoding') from error
        if not payload or len(payload) > 16384 or len(signature) != 64:
            raise RuntimeError('Invalid signer rotation authorization size')
        with tempfile.TemporaryDirectory(prefix='kura-agent-rotation-token-') as directory:
            payload_path = Path(directory) / 'payload'
            signature_path = Path(directory) / 'signature'
            self.put(payload_path, payload)
            self.put(signature_path, signature)
            result = self.run([openssl, 'pkeyutl', '-verify', '-rawin', '-pubin',
                               '-inkey', str(signer), '-sigfile', str(signature_path),
                               '-in', str(payload_path)], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError('Signer rotation authorization signature rejected')
        try:
            claims = json.loads(payload)
        except json.JSONDecodeError as error:
            raise RuntimeError('Invalid signer rotation authorization claims') from error
        now_ms = int(time.time() * 1000)
        required = {
            'schema': 'yofc.agent.transfer-signer-rotation.v1', 'gatewayId': gateway,
            'bindingGeneration': generation, 'fromSignerSpkiSha256': current_spki,
            'toSignerSpkiSha256': new_spki, 'operator': operator,
        }
        if not isinstance(claims, dict):
            raise RuntimeError('Signer rotation authorization does not match this gateway')
        for key, value in required.items():
            if claims.get(key) != value:
                raise RuntimeError('Signer rotation authorization does not match: ' + key)
        if not set(required).issubset(claims):
            raise RuntimeError('Signer rotation authorization has unexpected claims: ' + ','.join(sorted(set(claims) - set(required))))
        expires = claims.get('expiresAtUnixMs')
        rotation_id = claims.get('rotationId')
        if not isinstance(expires, int) or not (now_ms < expires <= now_ms + 900_000):
            raise RuntimeError('Signer rotation authorization is expired or unbounded')
        if not isinstance(rotation_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', rotation_id):
            raise RuntimeError('Invalid signer rotation authorization id')
        return claims

    def consume_rotation_token(self, token_path, claims, current, generation,
                               current_spki, new_spki, operator, signer=TRANSFER_SIGNER):
        """Durably consume the signed rotation before changing the registered key."""
        rotation_id = claims['rotationId']
        uses = self.path(STATE + '/transfer-signer-rotations/uses')
        uses.mkdir(parents=True, exist_ok=True, mode=0o700)
        record_path = uses / (rotation_id + '.json')
        if record_path.exists():
            raise RuntimeError('Signer rotation authorization has already been used')
        raw = Path(token_path).read_bytes()
        signer_path = self.path(signer)
        receipt = {
            'schema': 'yofc.agent.transfer-signer-rotation-use.v1',
            'rotationId': rotation_id,
            'gatewayId': current.get('AGENT_GATEWAY_ID'),
            'bindingGeneration': generation,
            'fromSignerSpkiSha256': current_spki,
            'toSignerSpkiSha256': new_spki,
            'tokenSha256': hashlib.sha256(raw).hexdigest(),
            'signerSha256': hashlib.sha256(signer_path.read_bytes()).hexdigest(),
            'operator': operator,
            'consumedAtUnixMs': int(time.time() * 1000),
        }
        self.put_durable(record_path, json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        return record_path

    def rotate_transfer_signer(self, public_key, expected_generation, operator,
                               authorization_token):
        """Rotate to a different signer only with a one-time authorization signed by the current key."""
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        current = self.settings()
        try:
            generation = int(current['AGENT_BINDING_GENERATION'])
        except (KeyError, ValueError) as error:
            raise RuntimeError('Invalid current binding generation') from error
        if generation < 1 or generation != expected_generation:
            raise RuntimeError('Binding generation changed; inspect the gateway before signer rotation')
        self.inactive()
        self.guard_writer()
        if self.path(CONFIG + '/.identity-installing').exists():
            raise RuntimeError('Interrupted identity installation')
        current_signer = self.path(TRANSFER_SIGNER)
        if not current_signer.exists():
            raise RuntimeError('Signer rotation requires a registered current signer')
        self.public_key(current_signer)
        source = Path(public_key)
        if not source.is_file() or source.is_symlink() or source.stat().st_size > 1024 * 1024:
            raise RuntimeError('Transfer signer must be a bounded regular public key')
        self.public_key(source)
        openssl = self.openssl_for_public_key(source)
        self.run([openssl, 'pkey', '-pubin', '-in', str(source)], check=True,
                 capture_output=True)
        old_bytes = current_signer.read_bytes()
        new_bytes = source.read_bytes()
        if old_bytes == new_bytes:
            raise RuntimeError('The proposed transfer signer is unchanged')
        current_spki = self.public_spki_sha256(current_signer)
        new_spki = self.public_spki_sha256(source)
        if current_spki == new_spki:
            raise RuntimeError('The proposed transfer signer is unchanged')
        claims = self.verify_rotation_token(
            authorization_token, current.get('AGENT_GATEWAY_ID'), generation,
            current_spki, new_spki, operator)
        rotation_dir = self.path(STATE + '/transfer-signer-rotations/generation-' + str(generation))
        if rotation_dir.exists():
            raise RuntimeError('A signer rotation receipt already exists for this generation')
        self.consume_rotation_token(
            authorization_token, claims, current, generation, current_spki, new_spki, operator)
        rotation_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(rotation_dir.iterdir()):
            raise RuntimeError('Signer rotation receipt directory already contains data')
        self.put(rotation_dir / 'old-transfer-signer.pem', old_bytes, 0o644)
        self.put(rotation_dir / 'authorization-token', Path(authorization_token).read_bytes(), 0o600)
        receipt = {
            'schema': 'yofc.agent.transfer-signer-rotation.v1',
            'gatewayId': current.get('AGENT_GATEWAY_ID'),
            'bindingGeneration': generation,
            'fromSignerSpkiSha256': current_spki,
            'toSignerSpkiSha256': new_spki,
            'fromSignerSha256': hashlib.sha256(old_bytes).hexdigest(),
            'toSignerSha256': hashlib.sha256(new_bytes).hexdigest(),
            'rotationId': claims['rotationId'],
            'tokenExpiresAtUnixMs': claims['expiresAtUnixMs'],
            'operator': operator,
        }
        temporary = current_signer.with_name('.transfer-signer.pem.rotating')
        self.put(temporary, new_bytes, 0o644)
        os.replace(temporary, current_signer)
        self.public_key(current_signer)
        self.put(rotation_dir / 'receipt.json', json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        self.check()

    def register_transfer_signer(self, public_key, expected_generation, operator):
        """Explicitly register the original-center signer for the current generation."""
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        current = self.settings()
        try:
            generation = int(current['AGENT_BINDING_GENERATION'])
        except (KeyError, ValueError) as error:
            raise RuntimeError('Invalid current binding generation') from error
        if generation < 1 or generation != expected_generation:
            raise RuntimeError('Binding generation changed; inspect the gateway before signer registration')
        self.inactive()
        self.guard_writer()
        if self.path(CONFIG + '/.identity-installing').exists():
            raise RuntimeError('Interrupted identity installation')
        source = Path(public_key)
        if not source.is_file() or source.is_symlink() or source.stat().st_size > 1024 * 1024:
            raise RuntimeError('Transfer signer must be a bounded regular public key')
        self.public_key(source)
        openssl = self.openssl_for_public_key(source)
        self.run([openssl, 'pkey', '-pubin', '-in', str(source)], check=True,
                 capture_output=True)
        signer = self.path(TRANSFER_SIGNER)
        signer_bytes = source.read_bytes()
        if signer.exists():
            self.public_key(signer)
            if signer.read_bytes() == signer_bytes:
                return
            raise RuntimeError('A different transfer signer is registered; explicit recovery required')
        config = self.path(CONFIG)
        if config.stat().st_uid != os.getuid() or config.stat().st_mode & 0o077:
            raise RuntimeError('Identity directory must be owned and private')
        digest = hashlib.sha256(signer_bytes).hexdigest()
        registrations = self.path(STATE + '/transfer-signer-registrations')
        registrations.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipt_path = registrations / ('generation-' + str(generation) + '.json')
        if receipt_path.exists():
            raise RuntimeError('Transfer signer registration already exists for this generation')
        receipt = {
            'schema': 'yofc.agent.transfer-signer-registration.v1',
            'gatewayId': current.get('AGENT_GATEWAY_ID'),
            'bindingGeneration': generation,
            'signerSha256': digest,
            'operator': operator,
        }
        temporary = signer.with_name('.transfer-signer.pem.registering')
        self.put(temporary, signer_bytes, 0o644)
        os.replace(temporary, signer)
        self.public_key(signer)
        self.put(receipt_path, json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        self.check()

    def rotate_client_certificate(self, cert, key, operator):
        """Replace this gateway's client certificate/key under the same center.

        Binding generation, endpoint and gateway id do not change and no transfer
        token is involved. The center must register the new certificate
        (rotate-gateway-certificate) while the agent is stopped; the old pair is
        backed up first so a failed activation can be rolled back by hand.
        """
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        self.inactive()
        self.guard_writer()
        current = self.settings()
        sources = [Path(cert), Path(key)]
        for path in sources:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Certificate input must be a bounded regular file')
        self.private_input(sources[1])
        payload = [path.read_bytes() for path in sources]
        with tempfile.TemporaryDirectory(prefix='kura-agent-certificate-') as directory:
            staged = [Path(directory) / name for name in ['agent.pem', 'agent.key']]
            for path, value in zip(staged, payload):
                self.put(path, value)
            verify = self.run([self.openssl(), 'verify', '-purpose', 'sslclient',
                               '-CAfile', str(self.path(current['AGENT_CA'])), str(staged[0])],
                              capture_output=True)
            if verify.returncode != 0:
                raise RuntimeError('New client certificate is not issued for the current trust chain')
            public = self.run([self.openssl(), 'x509', '-in', str(staged[0]), '-pubkey', '-noout'],
                              check=True, capture_output=True).stdout
            private_public = self.run([self.openssl(), 'pkey', '-in', str(staged[1]), '-pubout'],
                                      check=True, capture_output=True).stdout
            if public != private_public:
                raise RuntimeError('Certificate and private key do not match')
        old_cert = self.path(current['AGENT_CERT'])
        old_key = self.path(current['AGENT_KEY'])
        old_hash = self.certificate_sha256(old_cert)
        new_hash = self.certificate_sha256(Path(cert))
        if new_hash == old_hash:
            raise RuntimeError('New client certificate is identical to the current one')
        base = self.path(STATE + '/certificate-rotations')
        rotation = 1
        if base.exists():
            rotation = max([int(entry.name) for entry in base.iterdir()
                            if re.fullmatch(r'[1-9][0-9]{0,5}', entry.name)], default=0) + 1
        backup = base / str(rotation)
        backup.mkdir(parents=True, exist_ok=False, mode=0o700)
        receipt = {
            'schema': 'yofc.agent.client-certificate-rotation.v1',
            'gatewayId': current.get('AGENT_GATEWAY_ID'),
            'bindingGeneration': current.get('AGENT_BINDING_GENERATION'),
            'consoleEndpoint': current.get('AGENT_CONSOLE_ENDPOINT'),
            'oldClientCertificateSha256': old_hash,
            'newClientCertificateSha256': new_hash,
            'operator': operator,
            'rotatedAtUnixMs': int(time.time() * 1000),
        }
        for name, source in [('agent.pem', old_cert), ('agent.key', old_key)]:
            self.put(backup / name, source.read_bytes())
        self.put(backup / 'receipt.json', json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        self.replace_bytes(self.path(CONFIG + '/agent.pem'), payload[0])
        self.replace_bytes(self.path(CONFIG + '/agent.key'), payload[1])
        self.check()
        return receipt

    def check_transfer_revocation(self, claims):
        """Fail closed unless the original center still reports the token ACTIVE.

        Identity comes from the current installed identity, the check uses the
        installed agent binary over its mTLS control channel, and every outcome
        other than ACTIVE (revoked, unknown id, unreachable center, timeout)
        refuses the transfer before any state is consumed.
        """
        binary = self.path('/usr/bin/yofc-management-agent')
        if not binary.is_file():
            raise RuntimeError('The installed agent cannot verify transfer revocation')
        current = self.settings()
        environment = {
            'AGENT_CONSOLE_ENDPOINT': current['AGENT_CONSOLE_ENDPOINT'],
            'AGENT_GATEWAY_ID': current['AGENT_GATEWAY_ID'],
            'AGENT_BINDING_GENERATION': current['AGENT_BINDING_GENERATION'],
            'AGENT_CA': str(self.path(current['AGENT_CA'])),
            'AGENT_CERT': str(self.path(current['AGENT_CERT'])),
            'AGENT_KEY': str(self.path(current['AGENT_KEY'])),
            'PATH': '/usr/bin:/bin',
            'RUST_LOG': 'error',
        }
        try:
            result = self.run([str(binary), 'check-transfer-revocation',
                               '--transfer-id', claims['transferId']],
                              capture_output=True, text=True, timeout=60,
                              env=environment)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError('Transfer revocation check timed out') from error
        if result.returncode != 0:
            raise RuntimeError('Transfer authorization is not ACTIVE; '
                               'request a new approval')

    def transfer_identity(self, endpoint, gateway, ca, cert, key, expected_generation, operator,
                          authorization_token=None):
        """Perform an explicit gateway-local rebind after unsettled side effects are resolved."""
        if not operator or len(operator) > 128 or any(char in operator for char in '\r\n\x00'):
            raise RuntimeError('A bounded operator identity is required')
        current = self.settings()
        try:
            old_generation = int(current['AGENT_BINDING_GENERATION'])
        except (KeyError, ValueError) as error:
            raise RuntimeError('Invalid current binding generation') from error
        if old_generation < 1 or old_generation != expected_generation:
            raise RuntimeError('Binding generation changed; inspect the gateway before transfer')
        ca_source = Path(ca)
        cert_source = Path(cert)
        ca_hash = self.certificate_sha256(ca_source)
        cert_hash = self.certificate_sha256(cert_source)
        token_claims = None
        if authorization_token is not None:
            token_claims = self.verify_transfer_token(
                authorization_token, current.get('AGENT_GATEWAY_ID'), old_generation,
                old_generation + 1, endpoint, gateway, ca_hash, cert_hash)
            self.check_transfer_revocation(token_claims)
        self.inactive()
        self.guard_writer()
        marker = self.path(CONFIG + '/.identity-transferring')
        if marker.exists():
            raise RuntimeError('Interrupted identity transfer; inspect state before retrying')
        settings = self.identity_settings(endpoint, gateway, old_generation + 1)
        sources = [Path(ca), Path(cert), Path(key)]
        for path in sources:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Identity input must be a bounded regular file')
        self.private_input(sources[2])
        payload = [path.read_bytes() for path in sources]
        with tempfile.TemporaryDirectory(prefix='kura-agent-transfer-') as directory:
            staged = [Path(directory) / name for name in ['ca.pem', 'agent.pem', 'agent.key']]
            for path, value in zip(staged, payload):
                self.put(path, value)
            self.run([self.openssl(), 'verify', '-purpose', 'sslclient', '-CAfile', str(staged[0]), str(staged[1])],
                     check=True, capture_output=True)
            public = self.run([self.openssl(), 'x509', '-in', str(staged[1]), '-pubkey', '-noout'], check=True,
                              capture_output=True).stdout
            private_public = self.run([self.openssl(), 'pkey', '-in', str(staged[2]), '-pubout'], check=True,
                                      capture_output=True).stdout
            if public != private_public:
                raise RuntimeError('Certificate and private key do not match')
        config = self.path(CONFIG)
        if config.stat().st_uid != os.getuid() or config.stat().st_mode & 0o077:
            raise RuntimeError('Identity directory must be owned and private')
        for name in ['ca.pem', 'agent.pem', 'agent.key', 'agent.env', '.identity-installing']:
            if self.path(CONFIG + '/.identity-transferring') == self.path(CONFIG + '/' + name):
                continue
        # Preserve explicit Kura authorization, but never carry a configured network writer.
        for key in ['AGENT_KURA_UID', 'AGENT_KURA_NETWORK_INTERFACES']:
            if key in current:
                settings[key] = current[key]
        token_use_path = None
        if token_claims:
            token_use_path = self.consume_transfer_token(
                authorization_token, token_claims, current, old_generation, endpoint,
                gateway, ca_hash, cert_hash, operator)
        old_cert = self.path(current['AGENT_CERT'])
        receipt = {
            'schema': 'yofc.agent.signed-transfer.v1' if token_claims else 'yofc.agent.local-rebind.v1',
            'fromEndpoint': current.get('AGENT_CONSOLE_ENDPOINT'),
            'fromGatewayId': current.get('AGENT_GATEWAY_ID'),
            'fromBindingGeneration': old_generation,
            'toEndpoint': endpoint,
            'toGatewayId': gateway,
            'toBindingGeneration': old_generation + 1,
            'newClientCertificateSha256': cert_hash,
            'oldClientCertificateSha256': self.certificate_sha256(old_cert),
            'operator': operator,
            'authorization': ('original-center-signed-transfer' if token_claims
                              else 'gateway-local-operator'),
        }
        if token_claims:
            receipt['transferId'] = token_claims['transferId']
            receipt['tokenExpiresAtUnixMs'] = token_claims['expiresAtUnixMs']
        backup = self.path(STATE + '/transfers/' + str(old_generation + 1))
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(not path.is_file() for path in backup.iterdir()):
            raise RuntimeError('Transfer backup path already contains unexpected data')
        for name in ['agent.env', 'ca.pem', 'agent.pem', 'agent.key']:
            source = self.path(CONFIG + '/' + name)
            if source.exists():
                target = backup / name
                if target.exists():
                    raise RuntimeError('Transfer backup already exists')
                self.put(target, source.read_bytes())
        self.put(backup / 'receipt.json', json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        marker.parent.mkdir(parents=True, exist_ok=True)
        self.put(marker, json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n')
        # Replace trust and identity first; agent.env goes last so a crash leaves the
        # old generation visible and a retry can continue without automatic repair.
        self.replace_bytes(self.path(CONFIG + '/ca.pem'), payload[0])
        self.replace_bytes(self.path(CONFIG + '/agent.pem'), payload[1])
        self.replace_bytes(self.path(CONFIG + '/agent.key'), payload[2])
        self.replace(self.path(CONFIG + '/agent.env'), self.serialize(settings))
        marker.unlink()
        self.systemctl('daemon-reload')
        self.check()

    @staticmethod
    def replace(path, text):
        fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as output:
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def guard_firewall_boot_unit(self):
        vendor = self.path(FIREWALL_BOOT_VENDOR)
        manifest = self.path(FIREWALL_BOOT_META)
        for prefix in ('/etc/systemd/system/', '/run/systemd/system/'):
            if os.path.lexists(self.root / (prefix + FIREWALL_BOOT_UNIT).lstrip('/')):
                raise RuntimeError('Externally supplied firewall boot unit requires explicit review')
        if not (vendor.exists() or manifest.exists()):
            return None
        raw = self.reader_file(FIREWALL_BOOT_VENDOR, limit=16384)
        pair = {'schemaVersion': 1, 'runtimeProfile': 'legacy-root-v1',
                'unitPath': FIREWALL_BOOT_VENDOR, 'unitSha256': hashlib.sha256(raw).hexdigest()}
        if self.reader_json(self.reader_file(FIREWALL_BOOT_META, limit=4096)) != pair:
            raise RuntimeError('Firewall boot unit and package manifest differ')
        result = self.systemctl('show', FIREWALL_BOOT_UNIT, '-p', 'FragmentPath', '-p', 'DropInPaths',
                                '-p', 'LoadState', '-p', 'ActiveState', '-p', 'MainPID', '-p', 'UnitFileState')
        if result is None:
            return None
        status = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if (status.get('LoadState') != 'loaded'
                or status.get('FragmentPath') not in (FIREWALL_BOOT_VENDOR, '/lib/systemd/system/' + FIREWALL_BOOT_UNIT)
                or (status.get('UnitFileState') == 'enabled' and status.get('DropInPaths') != '')
                or status.get('UnitFileState') not in ('enabled', 'disabled')):
            raise RuntimeError('Unexpected installed firewall boot unit or enablement')
        if status.get('ActiveState') not in ('inactive', 'failed') or status.get('MainPID') != '0':
            raise RuntimeError('Firewall boot actor is still executing; preserve its original attempt')
        return status['UnitFileState']

    def guard_writer(self, *, nm_upgrade=False):
        if not nm_upgrade:
            self.inactive()
        self.guard_firewall_boot_unit()
        env = self.path(CONFIG + '/agent.env')
        if env.exists() and self.settings().get('AGENT_NETWORK_INTERFACES', ''):
            raise RuntimeError('Explicit network writer handover required before package lifecycle changes')
        self.guard_transactions(nm_upgrade=nm_upgrade)
        database = self.path(STATE + '/results.sqlite')
        if database.exists():
            try:
                with closing(sqlite3.connect('file:' + quote(str(database), safe='/') + '?mode=ro', uri=True, timeout=2)) as connection:
                    table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='executions'").fetchone()
                    pending = table and connection.execute("SELECT 1 FROM executions WHERE state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23) LIMIT 1").fetchone()
            except sqlite3.DatabaseError as error:
                raise RuntimeError('Execution journal cannot be inspected; recovery required') from error
            if pending:
                raise RuntimeError('Settle uncertain executions before package lifecycle changes')

    def nm_package_upgrade(self, old, new, package, phase):
        """Admit only the specific original plan and two exact release generations."""
        if self.root != Path('/') or new != package['version']:
            raise RuntimeError('Original NM upgrade requires its exact candidate package')
        record = self.reader_file(NM_UPGRADE, mode=0o600, limit=16384)
        value = self.reader_json(record)
        if (value.get('schemaVersion') != 1 or value.get('oldVersion') != old
                or value.get('newVersion') != new
                or value.get('candidateBinarySha256') != package['binarySha256']):
            raise RuntimeError('Original NM upgrade does not bind these package versions')
        candidate = self.reader_file(NM_UPGRADE_CANDIDATE, mode=0o500, limit=64 * 1024 * 1024)
        if hashlib.sha256(candidate).hexdigest() != package['binarySha256']:
            raise RuntimeError('Original NM upgrade candidate binary differs')
        bridge = self.reader_file('/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar',
                                  limit=8 * 1024 * 1024)
        if hashlib.sha256(bridge).hexdigest() != package['bridgeSha256']:
            raise RuntimeError('Original live Java bridge must remain the paired release')
        settings = self.check()
        decision = self.path(STATE + '/remote-management.json')
        if (settings.get('AGENT_REMOTE_ENABLED', '0') != '0'
                or (decision.exists() and self.reader_json(decision.read_bytes()).get('enabled') is not False)):
            raise RuntimeError('Original NM package upgrade requires remote management disabled')
        self.guard_writer(nm_upgrade=True)
        stop = (hashlib.sha256(record).hexdigest() + '\n').encode()
        stopped_record = os.path.lexists(self.path(NM_UPGRADE_STOP))
        if stopped_record and self.reader_file(NM_UPGRADE_STOP, mode=0o600) != stop:
            raise RuntimeError('Original Agent stop intent changed')
        if not stopped_record and phase != 'before-stop':
            raise RuntimeError('Original Agent stop intent is required')
        if not stopped_record:
            result = self.systemctl('show', UNIT, '--property=FragmentPath,ExecStart')
            if result is None:
                raise RuntimeError('Actual packaged Agent systemd service required')
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if (fields.get('FragmentPath') not in ('/usr/lib/systemd/system/' + UNIT, '/lib/systemd/system/' + UNIT)
                    or not fields.get('ExecStart', '').startswith(
                        '{ path=/usr/bin/yofc-management-agent ; argv[]=/usr/bin/yofc-management-agent ;')):
                raise RuntimeError('Original installed Agent execution profile required')
        self.run(['/usr/bin/setpriv', '--regid=kura-management', '--clear-groups',
                  NM_UPGRADE_CANDIDATE, 'check-original-nm-upgrade', old, new,
                  'before-unpack' if stopped_record else phase],
                 check=True, timeout=70)
        if not stopped_record:
            self.put_durable(NM_UPGRADE_STOP, stop)
            if self.systemctl('stop', UNIT) is None:
                raise RuntimeError('Actual packaged Agent systemd service required')
            self.inactive()

    def publish_nm_fence(self, operation):
        self.authorization_id(operation)
        paths = {
            'unitSha256': (ROOT_FENCE_VENDOR, 0o644, 65536),
            'sourceManifestSha256': ('/usr/share/kura-management-agent/source-manifest.json', 0o644, 2 * 1024 * 1024),
            'setupSha256': ('/usr/lib/kura-management-agent/setup.py', 0o644, 1024 * 1024),
            'binarySha256': ('/usr/bin/yofc-management-agent', 0o755, 64 * 1024 * 1024),
            'bridgeSha256': ('/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar', 0o644, 8 * 1024 * 1024),
        }
        meta = self.reader_json(self.reader_file(ROOT_FENCE_META))
        if (set(meta) != {'schemaVersion', 'unitPath', 'coreLoaderSha256', *paths}
                or type(meta['schemaVersion']) is not int or meta['schemaVersion'] != 1
                or meta['unitPath'] != ROOT_FENCE_VENDOR):
            raise RuntimeError('Original Root fence package pairing is invalid')
        if self.reader_file('/usr/share/kura-management-agent/package-v1') != b'kura-management-agent-v1\n':
            raise RuntimeError('Original Root fence publisher requires its legacy package')
        self.guard_core_loader(meta['coreLoaderSha256'])
        for key, (filename, mode, limit) in paths.items():
            if hashlib.sha256(self.reader_file(filename, mode=mode, limit=limit)).hexdigest() != meta[key]:
                raise RuntimeError('Original Root fence package file changed')

        def show(unit, fields):
            result = self.systemctl('show', unit, '--property=' + ','.join(fields))
            if result is None:
                raise RuntimeError('Actual systemd fence pairing required')
            return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

        unit = ROOT_FENCE_UNIT.replace('@.', '@' + operation + '.')
        effective = show(unit, ('LoadState', 'FragmentPath', 'DropInPaths', 'ActiveState', 'User', 'Group',
                                'NoNewPrivileges', 'ProtectSystem', 'CapabilityBoundingSet'))
        if (effective.get('FragmentPath') not in (ROOT_FENCE_VENDOR, ROOT_FENCE_VENDOR.removeprefix('/usr'))
                or any(effective.get(key) != expected for key, expected in {
                    'LoadState': 'loaded', 'DropInPaths': '', 'ActiveState': 'activating',
                    'User': 'root', 'Group': 'kura-management', 'NoNewPrivileges': 'yes',
                    'ProtectSystem': 'strict', 'CapabilityBoundingSet': '',
                }.items())):
            raise RuntimeError('Original Root fence publisher unit differs from the reviewed profile')
        agent = show(UNIT, ('FragmentPath', 'ActiveState', 'MainPID', 'ExecStart'))
        pid = agent.get('MainPID', '')
        if (agent.get('FragmentPath') not in ('/usr/lib/systemd/system/' + UNIT, '/lib/systemd/system/' + UNIT)
                or agent.get('ActiveState') != 'active' or not re.fullmatch('[1-9][0-9]{0,9}', pid)
                or not agent.get('ExecStart', '').startswith('{ path=/usr/bin/yofc-management-agent ; argv[]=/usr/bin/yofc-management-agent ;')):
            raise RuntimeError('Original installed Agent process required')
        self.run([paths['binarySha256'][0], 'publish-original-nm-fence', operation, pid], check=True, timeout=85)

    def stop_packaged_fence_reader(self, remove):
        vendor = '/usr/lib/systemd/system/' + FENCE_READER_SOCKET_UNIT
        if not self.path(vendor).exists():
            return
        meta = self.reader_json(self.reader_file('/usr/share/kura-management-agent/root-fence-reader.json'))
        if hashlib.sha256(self.reader_file(vendor)).hexdigest() != meta.get('socketSha256'):
            raise RuntimeError('Original Root fence reader socket package bytes changed')
        status = self.systemctl('show', FENCE_READER_SOCKET_UNIT, '--property=LoadState,FragmentPath,DropInPaths')
        if status is not None:
            values = dict(row.split('=', 1) for row in status.stdout.splitlines() if '=' in row)
            if (values.get('LoadState') != 'loaded' or values.get('DropInPaths') != ''
                    or values.get('FragmentPath') not in (vendor, vendor.removeprefix('/usr'))):
                raise RuntimeError('Refusing lifecycle change to a substituted Root fence socket')
        self.systemctl('stop', FENCE_READER_SOCKET_UNIT)
        if remove:
            self.systemctl('disable', FENCE_READER_SOCKET_UNIT)

    def nm_handover_file(self, directory, name):
        path = self.path(STATE + '/' + directory + '/' + name)
        self.authorization_parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                     | getattr(os, 'O_NOATIME', 0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= 1024 * 1024):
                raise RuntimeError('Unsafe original NM handover record; preserve it')
            raw = stream.read(1024 * 1024 + 1)
            after = path.lstat()
            if (len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_ctime_ns)):
                raise RuntimeError('Original NM handover record changed during admission')
            return raw

    def nm_handover_records(self, directory):
        root = self.path(STATE + '/' + directory)
        if not root.exists():
            return False
        mode = root.lstat()
        if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) != 0o700:
            raise RuntimeError('Unsafe original NM handover directory; preserve it')
        return next(root.iterdir(), None) is not None

    def guard_nm_handover(self):
        # Existing immutable receipts, not a terminal string alone, separate a
        # retained handover from an in-flight operation in package maintenance.
        def read(directory, name, expected=None):
            try:
                raw = self.nm_handover_file(directory, name)
            except OSError as error:
                raise RuntimeError('Missing or unreadable original NM handover evidence') from error
            if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
                raise RuntimeError('Original NM handover evidence changed')
            value = self.reader_json(raw)
            if not isinstance(value, dict):
                raise RuntimeError('Invalid original NM handover record')
            return value

        def original(directory, key, allowed):
            if not self.nm_handover_records(directory):
                return None
            value = read(directory, 'transaction.json')
            ident = value.get('operationId')
            if (type(value.get('schemaVersion')) is not int or value['schemaVersion'] != 1
                    or not isinstance(ident, str) or not re.fullmatch('[a-f0-9-]{36}', ident)
                    or str(uuid.UUID(ident)) != ident or uuid.UUID(ident).int == 0):
                raise RuntimeError('Invalid original NM handover identity')
            if value.get(key) not in allowed:
                raise RuntimeError('Settle the original NM handover before package or identity changes')
            return value

        def digest(value, field):
            result = value.get(field)
            if not isinstance(result, str) or not re.fullmatch('[a-f0-9]{64}', result):
                raise RuntimeError('Missing original NM handover digest')
            return result

        owned, transfer = NM_HANDOVER_DIRECTORIES
        parent = original(owned, 'state', ('COMMITTED', 'CANCELLED'))
        stream = original(transfer, 'phase', ('READY', 'CANCELLED'))
        if parent is not None:
            ident = parent['operationId']
            plan_sha = digest(parent, 'planSha256')
            plan = read(owned, ident + '.intent.json', plan_sha)
            receipt = read(owned, ident + '.receipt.json', digest(parent, 'receiptSha256'))
            if plan.get('operationId') != ident or type(receipt.get('schemaVersion')) is not int or receipt != {
                'schemaVersion': 1, 'operationId': ident, 'planSha256': plan_sha, 'state': parent['state'],
                'leaseSha256': receipt.get('leaseSha256'),
            }:
                raise RuntimeError('Original NM ownership receipt differs from its plan')
            if parent['state'] == 'COMMITTED':
                lease = read(owned, ident + '.lease.json', digest(receipt, 'leaseSha256'))
                if lease.get('operationId') != ident or lease.get('planSha256') != plan_sha:
                    raise RuntimeError('Original NM ownership lease differs from its plan')
            elif receipt.get('leaseSha256') is not None:
                raise RuntimeError('Cancelled NM ownership receipt contains a lease')
            binding = plan.get('template')
            if (binding is not None) != (stream is not None):
                raise RuntimeError('Original NM ownership and template records do not pair')
        else:
            binding = None
        if stream is None:
            return
        ident = stream['operationId']
        intent_sha = digest(stream, 'intentSha256')
        intent = read(transfer, ident + '.intent.json', intent_sha)
        if intent.get('operationId') != ident or (parent is not None and parent['operationId'] != ident):
            raise RuntimeError('Original NM template operation differs from ownership')
        if stream['phase'] == 'CANCELLED':
            if (parent is not None and parent['state'] != 'CANCELLED') or read(transfer, ident + '.cancel.json') != {
                'schemaVersion': 1, 'operationId': ident, 'intentSha256': intent_sha,
                'state': 'CANCELLED', 'readyReceiptSha256': stream.get('receiptSha256'),
            }:
                raise RuntimeError('Original NM template cancellation does not match ownership')
            return
        if parent is None or parent['state'] != 'COMMITTED':
            raise RuntimeError('Settle the original NM handover before package or identity changes')
        ready_sha = digest(stream, 'receiptSha256')
        ready = read(transfer, ident + '.receipt.json', ready_sha)
        schema = ready.pop('schemaVersion', None)
        original_binding = {**ready, 'receiptSha256': ready_sha}
        if (type(schema) is not int or schema != 1 or original_binding != binding
                or ready.get('operationId') != ident or ready.get('intentSha256') != intent_sha
                or ready.get('manifestSha256') != digest(stream, 'manifestSha256')):
            raise RuntimeError('Original NM prepared template differs from the committed ownership receipt')

    def guard_transactions(self, *, nm_upgrade=False):
        self.guard_local_authorizations()
        if os.path.lexists(self.path(CONFIG + '/.system-control-installing')):
            raise RuntimeError('Interrupted system control installation; preserve grant, settings and audit')
        guard_system_control(self.path(STATE + '/system-control'))
        if not nm_upgrade:
            self.guard_nm_handover()
        early_firewall = self.path(STATE + '/firewall/boot-restore')
        if os.path.lexists(early_firewall):
            mode = early_firewall.lstat()
            if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
                raise RuntimeError('Unsafe confirmed firewall boot restore history')
            if os.path.lexists(early_firewall / 'pending.json'):
                raise RuntimeError('Resolve the original confirmed firewall boot restore before package or identity changes')
        guard_cancelled_handoff(self.path(STATE + '/recovery'))
        for name in ['remote-management-pending.json', 'remote-management-resolution.json', 'identity-enrollment-pending.json']:
            if self.path(STATE + '/' + name).exists():
                raise RuntimeError('Settle remote management control recovery before package or identity changes')
        for subsystem, terminal in [('network', ('COMMITTED', 'ROLLED_BACK')),
                                    ('firewall', ('COMMITTED', 'ROLLED_BACK')),
                                    ('recovery', ('SUCCEEDED', 'FAILED', 'COMPLETED_APPROVED_CHECKS', 'ORDINARY_ACTIVE_APPROVED_CHECKS', 'ORDINARY_CANCELLED')),
                                    ('ordinary-boot', ('BOOT_POLICY_COMMITTED', 'CANCELLED'))]:
            journal = self.path(STATE + '/' + subsystem + '/transaction.json')
            if subsystem == 'recovery' and not os.path.lexists(journal):
                commands = journal.parent / 'commands'
                if os.path.lexists(commands):
                    m = commands.lstat()
                    if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077 or any(commands.iterdir()):
                        raise RuntimeError('Recovery journal missing with handoff command evidence; preserve state')
            if subsystem == 'ordinary-boot':
                self.guard_boot_policy(journal)
                continue
            if journal.exists():
                if not journal.is_file() or journal.stat().st_size > 1024 * 1024:
                    raise RuntimeError('Unsafe ' + subsystem + ' transaction; recovery required')
                value = json.loads(journal.read_text())
                if value.get('state') not in terminal:
                    raise RuntimeError('Settle the ' + subsystem + ' transaction before package lifecycle changes')

    def guard_boot_policy(self, journal):
        root = journal.parent
        def read(path):
            m = path.parent.lstat()
            if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o022:
                raise RuntimeError('Unsafe ordinary boot evidence directory')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                m = os.fstat(fd)
                if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077 or m.st_size > 1024 * 1024:
                    raise RuntimeError('Unsafe ordinary boot evidence')
                with os.fdopen(fd, 'rb', closefd=False) as source:
                    return source.read(1024 * 1024 + 1)
            finally:
                os.close(fd)
        def record(path):
            value = json.loads(read(path))
            if value.get('state') not in ('BOOT_POLICY_COMMITTED', 'CANCELLED'):
                raise RuntimeError('Settle the ordinary-boot transaction before package lifecycle changes')
            expected = {'schema', 'id', 'token', 'state', 'expiresAt', 'request', 'target', 'retired', 'actionIntents', 'receiptSha256', 'previousConfirmedSha256'}
            optional = {'commandDecisions', 'issuedCommand'}
            if set(value) - optional != expected or value.get('schema') != 1:
                raise RuntimeError('Invalid ordinary boot policy journal')
            commands = value.get('commandDecisions', {})
            if not isinstance(commands, dict) or len(commands) > 64:
                raise RuntimeError('Invalid boot command decision map')
            bindings = {}
            for command_id, digest in commands.items():
                if str(uuid.UUID(command_id)) != command_id or not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise RuntimeError('Invalid boot command identity/digest')
                raw_decision = read(root / 'commands' / (command_id + '.json'))
                decision = json.loads(raw_decision)
                binding = decision.get('binding', {})
                if hashlib.sha256(raw_decision).hexdigest() != digest or decision.get('schema') != 1 or decision.get('transactionId') != value['id'] or set(binding) != {'commandId', 'requestSha256', 'operation'} or binding.get('commandId') != command_id or binding.get('operation') not in (16, 17, 18, 19) or not isinstance(binding.get('requestSha256'), str) or len(binding['requestSha256']) != 64 or any(c not in '0123456789abcdef' for c in binding['requestSha256']):
                    raise RuntimeError('Boot command decision changed; preserve state')
                bindings[command_id] = binding
            issued = value.get('issuedCommand')
            if issued is not None and (not isinstance(issued, dict) or set(issued) != {'commandId', 'requestSha256', 'operation'} or issued.get('operation') != 17 or bindings.get(issued.get('commandId')) != issued):
                raise RuntimeError('Invalid issued boot command')
            ident = value['id']
            if not ident.startswith('boot-') or str(uuid.UUID(ident[5:])) != ident[5:] or str(uuid.UUID(value['token'])) != value['token']:
                raise RuntimeError('Invalid ordinary boot identity')
            if value['state'] == 'CANCELLED':
                if value['actionIntents'] != [] or value['receiptSha256'] is not None:
                    raise RuntimeError('Cancelled ordinary boot policy contains issued intent')
                return value
            raw = read(root / 'receipts' / (ident + '.json'))
            proof = json.loads(raw)
            if proof.get('issuedCommand') != value.get('issuedCommand') or hashlib.sha256(raw).hexdigest() != value['receiptSha256'] or any(proof.get(k) != v for k, v in {
                'id': ident, 'request': value['request'], 'targetBefore': value['target'],
                'retiredBefore': value['retired'], 'actionIntents': value['actionIntents'],
                'status': 'BOOT_POLICY_COMMITTED', 'bootVerified': False, 'kuraRecoveryVerified': False,
            }.items()):
                raise RuntimeError('Ordinary boot receipt changed; preserve state')
            return value
        if not os.path.lexists(journal):
            if os.path.lexists(root / 'confirmed.json') or any(p.is_dir() and any(p.iterdir()) for p in [root / 'receipts', root / 'history', root / 'commands']):
                raise RuntimeError('Ordinary boot journal missing with retained evidence')
            return
        value = record(journal)
        confirmed = root / 'confirmed.json'
        policy = record(confirmed) if os.path.lexists(confirmed) else None
        if policy is not None and policy['state'] != 'BOOT_POLICY_COMMITTED':
            raise RuntimeError('Invalid confirmed boot policy')
        if value['state'] == 'BOOT_POLICY_COMMITTED' and {k: v for k, v in value.items() if k != 'commandDecisions'} != ({k: v for k, v in policy.items() if k != 'commandDecisions'} if policy else None):
            raise RuntimeError('Confirmed ordinary boot policy changed')

    def check(self, require_remote=True):
        self.guard_local_authorizations()
        if any(self.path(CONFIG + '/' + name).exists() for name in (
                '.identity-installing', '.identity-transferring', '.system-control-installing')):
            raise RuntimeError('Interrupted identity installation')
        settings = self.settings()
        self.check_reader(settings)
        fields = ['AGENT_CONSOLE_ENDPOINT', 'AGENT_GATEWAY_ID', 'AGENT_BINDING_GENERATION',
                  'AGENT_CA', 'AGENT_CERT', 'AGENT_KEY']
        bound = any(key in settings for key in fields)
        expected = self.local_settings()
        if bound:
            generation = settings.get('AGENT_BINDING_GENERATION')
            if generation is None:
                raise RuntimeError('Binding generation missing; explicit migration/recovery required')
            expected = self.identity_settings(settings.get('AGENT_CONSOLE_ENDPOINT', ''), settings.get('AGENT_GATEWAY_ID', ''), generation)
            for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY']:
                if settings.get(key) != expected[key]:
                    raise RuntimeError('Packaged identity/state/socket path changed; explicit migration required')
                self.private(self.path(settings[key]))
        elif any(self.path(CONFIG + '/' + name).exists() for name in ['ca.pem', 'agent.pem', 'agent.key', 'transfer-signer.pem']):
            raise RuntimeError('Identity files without a bound configuration require recovery')
        for key in ['AGENT_STATE_DB', 'AGENT_SOCKET', 'AGENT_ADMIN_UID']:
            if settings.get(key) != expected[key]:
                raise RuntimeError('Packaged identity/state/socket path changed; explicit migration required')
        for key in ['AGENT_REMOTE_ENABLED', 'AGENT_KURA_REMOTE_MANAGEMENT', 'AGENT_SYSTEM_CONTROL_REMOTE']:
            if key in settings and settings[key] not in ('0', '1'):
                raise RuntimeError('Remote settings must be 0 or 1')
        managed = self.path(STATE + "/enrollment/identity.json").exists()
        if bound and managed:
            raise RuntimeError("Legacy and managed identity cannot coexist")
        # The Rust startup independently validates the complete managed identity.
        # This pre-start check must allow an enabled, locally enrolled identity
        # whose environment deliberately contains no private identity paths.
        bound = bound or managed
        decision = self.path(STATE + '/remote-management.json')
        if decision.exists():
            self.private(decision)
            if decision.stat().st_size > 4096:
                raise RuntimeError('Remote decision requires recovery')
            record = json.loads(decision.read_bytes())
            if (set(record) != {'version', 'revision', 'enabled', 'actor'} or type(record['version']) is not int
                    or record['version'] != 1 or type(record['enabled']) is not bool
                    or not isinstance(record['actor'], str) or not isinstance(record['revision'], str)
                    or str(uuid.UUID(record['revision'])) != record['revision']):
                raise RuntimeError('Remote decision requires recovery')
            if not bound and record['enabled']:
                raise RuntimeError('Unbound agent cannot enable remote management')
        elif bound and require_remote and 'AGENT_REMOTE_ENABLED' not in settings:
            raise RuntimeError('Existing identity requires explicit migrate-remote-control decision')
        if not bound and settings.get('AGENT_REMOTE_ENABLED', '0') != '0':
            raise RuntimeError('Unbound agent cannot enable remote management')
        if self.path(TRANSFER_SIGNER).exists():
            self.public_key(self.path(TRANSFER_SIGNER))
            self.openssl_for_public_key(self.path(TRANSFER_SIGNER))
        uid = settings.get('AGENT_KURA_UID')
        if uid != '4294967295':
            profiles = self.authorization_dropins()
            if len(profiles) != 1:
                raise RuntimeError('Kura authorization drop-in missing or ambiguous')
            # A stopped/broken Core unit must not become an agent startup
            # dependency. Retained admission still binds its original account
            # UID and protected service-scoped group authorization.
            account = self.authorization_account(next(iter(profiles)), require_service=False)
            if uid != str(account.pw_uid):
                raise RuntimeError('Authorized Kura account UID changed')
        return settings

    def preflight(self):
        payload = self.path('/usr/share/kura-management-agent/package-v1')
        retained = self.path(STATE + '/.package-v1')
        known = payload.is_file() or (retained.is_file() and retained.read_text() == 'kura-management-agent-v1\n')
        local_unit = self.path('/etc/systemd/system/kura-management-agent.service')
        if local_unit.exists():
            raise RuntimeError('An unpackaged local agent unit requires explicit migration')
        for name in [CONFIG, STATE, '/var/log/kura-management-agent', '/usr/bin/yofc-management-agent']:
            path = self.path(name)
            if path.exists() and not known and (not path.is_dir() or any(path.iterdir())):
                raise RuntimeError('Existing unpackaged agent state requires an explicit migration')

    def purge(self):
        self.guard_writer()
        if any(self.nm_handover_records(directory) for directory in NM_HANDOVER_DIRECTORIES):
            raise RuntimeError('NM handover evidence requires an explicit verified archive before agent purge')
        authorizations = self.path(AUTHORIZATIONS)
        if os.path.lexists(self.path(READER_GRANT)) or authorizations.exists() and any(authorizations.iterdir()):
            raise RuntimeError('Local authorization grants and receipts require an explicit verified archive before agent purge')
        system = self.path(STATE + '/system-control')
        if system.exists() and any(path.is_file() or path.is_symlink() for path in system.rglob('*')):
            raise RuntimeError('System control records require an explicit verified archive before agent purge')
        boot_receipts = self.path(STATE + '/ordinary-boot/receipts')
        if boot_receipts.exists() and any(boot_receipts.iterdir()):
            raise RuntimeError('Ordinary boot policy receipts require an explicit verified handover before agent purge')
        if self.path(STATE + "/enrollment").exists():
            raise RuntimeError("Managed identity candidates/receipts require an explicit verified archive before agent purge")
        early_firewall = self.path(STATE + '/firewall/boot-restore')
        if early_firewall.exists() and any(early_firewall.iterdir()):
            raise RuntimeError('Confirmed firewall boot restore records require an explicit verified archive before agent purge')
        firewall = self.path(STATE + '/firewall/confirmed.json')
        if firewall.exists() and json.loads(firewall.read_text()).get('text'):
            raise RuntimeError('Confirmed firewall state requires explicit handover before agent purge')
        recovery = self.path(STATE + '/recovery')
        if recovery.exists() and any(path.is_file() or path.is_symlink() for path in recovery.rglob('*')):
            raise RuntimeError('Recovery backups and receipts require an explicit verified archive before agent purge')
        confirmed = self.path(STATE + '/network/confirmed.json')
        if confirmed.exists() and json.loads(confirmed.read_text()).get('yaml'):
            raise RuntimeError('Confirmed network state requires explicit handover before agent purge')
        dropins = self.authorization_dropins()
        paths = [self.path(name) for name in [CONFIG, STATE, '/var/log/kura-management-agent']]
        if any(path.exists() and not path.is_dir() for path in paths):
            raise RuntimeError('Unexpected agent state type')
        for dropin in dropins.values():
            dropin.unlink()
        for path in paths:
            if path.exists():
                shutil.rmtree(path)
        self.systemctl('daemon-reload')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    fence = actions.add_parser('publish-nm-fence', help='Internal packaged Root fence unit entry')
    fence.add_argument('--operation-id', required=True)
    identity = actions.add_parser('import-identity', help='Import an identity explicitly registered by this console; does not enroll or transfer')
    for name in ['endpoint', 'gateway', 'ca', 'cert', 'key']:
        identity.add_argument('--' + name, required=True)
    identity.add_argument('--transfer-signer')
    bundle = actions.add_parser('import-bundle', help='Import a one-time console-issued identity bundle (uncompressd tar with manifest/ca/cert/key)')
    bundle.add_argument('bundle')
    rotation_bundle = actions.add_parser('rotate-bundle', help='Rotate the installed client identity from a one-time console-issued rotation bundle')
    rotation_bundle.add_argument('bundle')
    rotation_bundle.add_argument('--operator', required=True)
    csr = actions.add_parser('create-certificate-request', help='Generate a private key and CSR locally; the key never leaves the gateway')
    csr.add_argument('--gateway', required=True)
    csr.add_argument('csr')
    activate_csr = actions.add_parser('activate-pending-certificate', help='Pair the pending locally-generated key with its issued certificate and bind the identity')
    for name in ['endpoint', 'ca', 'cert']:
        activate_csr.add_argument('--' + name, required=True)
    actions.add_parser('migrate-binding-generation', help='Add generation 1 to a proven same-center pre-generation identity')
    actions.add_parser('init-local', help='Initialize a clean local-only agent without generating TLS keys')
    remote = actions.add_parser('migrate-remote-control', help='Explicit remote decision for a stopped existing bound deployment')
    choice = remote.add_mutually_exclusive_group(required=True)
    choice.add_argument('--enabled', dest='enabled', action='store_true')
    choice.add_argument('--disabled', dest='enabled', action='store_false')
    remote.add_argument('--operator', required=True)
    signer = actions.add_parser('register-transfer-signer', help='Register the original-center transfer token signer')
    signer.add_argument('--public-key', required=True)
    signer.add_argument('--expected-generation', required=True, type=int)
    signer.add_argument('--operator', required=True)
    rotation = actions.add_parser('rotate-transfer-signer', help='Rotate signer with a one-time authorization signed by the current signer')
    rotation.add_argument('--public-key', required=True)
    rotation.add_argument('--expected-generation', required=True, type=int)
    rotation.add_argument('--operator', required=True)
    rotation.add_argument('--authorization-token', required=True)
    certificate = actions.add_parser('rotate-client-certificate', help='Replace the client certificate/key under the same center and binding generation')
    certificate.add_argument('--cert', required=True)
    certificate.add_argument('--key', required=True)
    certificate.add_argument('--operator', required=True)
    transfer = actions.add_parser('transfer-identity', help='Perform an explicit gateway-local rebind to new registered identity')
    for name in ['endpoint', 'gateway', 'ca', 'cert', 'key', 'operator']:
        transfer.add_argument('--' + name, required=True)
    transfer.add_argument('--expected-generation', required=True, type=int)
    transfer.add_argument('--authorization-token')
    authorization = actions.add_parser('authorize-kura', help='Authorize the packaged Kura UID for read-only UDS access')
    authorization.add_argument('--user', default='kura-netplan', choices=tuple(KURA_PROFILES))
    enrollment = actions.add_parser('grant-kura-enrollment', help='Grant fixed native staged-identity reading; does not start units or enable a remote channel')
    enrollment.add_argument('--request-id', required=True)
    enrollment.add_argument('--operator', required=True)
    original = actions.add_parser('local-authorization-status', help='Read one original local authorization without repeating it')
    original.add_argument('--request-id', required=True)
    system = actions.add_parser('configure-system-control', help='Seal a fixed Kura unit grant without starting or enabling any unit')
    system.add_argument('--request', required=True)
    system.add_argument('--operator', required=True)
    system_choice = system.add_mutually_exclusive_group(required=True)
    system_choice.add_argument('--remote-enabled', dest='remote', action='store_true')
    system_choice.add_argument('--remote-disabled', dest='remote', action='store_false')
    grant = actions.add_parser('grant-network-writer', help='Delegate network writing to this agent for exactly the named interfaces')
    grant.add_argument('--interfaces', required=True)
    grant.add_argument('--operator', required=True)
    handover = actions.add_parser('handover-network-writer', help='Return the network writer role and confirmed state to the system')
    handover.add_argument('--operator', required=True)
    handover.add_argument('--discard-config', action='store_true')
    for name in ['check', 'activate']:
        actions.add_parser(name)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run agent setup as root')
    setup = Setup()
    lock = setup.path('/run/lock/kura-management-agent-setup.lock')
    with os.fdopen(os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'r+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if args.action == 'import-identity':
            setup.import_identity(args.endpoint, args.gateway, args.ca, args.cert, args.key,
                                  args.transfer_signer)
        elif args.action == 'import-bundle':
            setup.import_bundle(args.bundle)
        elif args.action == 'rotate-bundle':
            setup.rotate_bundle(args.bundle, args.operator)
        elif args.action == 'create-certificate-request':
            setup.create_certificate_request(args.gateway, args.csr)
        elif args.action == 'activate-pending-certificate':
            setup.activate_pending_certificate(args.endpoint, args.ca, args.cert)
        elif args.action == 'init-local':
            setup.init_local()
        elif args.action == 'migrate-remote-control':
            setup.migrate_remote_control(args.enabled, args.operator)
        elif args.action == 'migrate-binding-generation':
            setup.migrate_binding_generation()
        elif args.action == 'register-transfer-signer':
            setup.register_transfer_signer(args.public_key, args.expected_generation,
                                           args.operator)
        elif args.action == 'rotate-transfer-signer':
            setup.rotate_transfer_signer(args.public_key, args.expected_generation,
                                         args.operator, args.authorization_token)
        elif args.action == 'rotate-client-certificate':
            setup.rotate_client_certificate(args.cert, args.key, args.operator)
        elif args.action == 'transfer-identity':
            setup.transfer_identity(args.endpoint, args.gateway, args.ca, args.cert, args.key,
                                    args.expected_generation, args.operator,
                                    args.authorization_token)
        elif args.action == 'publish-nm-fence':
            setup.publish_nm_fence(args.operation_id)
        elif args.action == 'authorize-kura':
            setup.authorize(args.user)
        elif args.action == 'grant-kura-enrollment':
            print(json.dumps(setup.grant_enrollment(args.request_id, args.operator)))
            return
        elif args.action == 'local-authorization-status':
            print(json.dumps(setup.authorization_status(args.request_id)))
            return
        elif args.action == 'configure-system-control':
            setup.configure_system_control(args.request, args.remote, args.operator)
        elif args.action == 'grant-network-writer':
            setup.grant_network_writer(args.interfaces, args.operator)
        elif args.action == 'handover-network-writer':
            setup.handover_network_writer(args.operator, args.discard_config)
        else:
            setup.check()
    # systemctl waits for ExecStartPre, whose check acquires the same lock. Release
    # it before starting; ExecStartPre validates again after systemd enters activating.
    if args.action == 'activate':
        if 'AGENT_KURA_ENROLLMENT_READER_SOCKET' in setup.settings():
            setup.systemctl('enable', '--now', READER_SOCKET_UNIT)
        setup.systemctl('enable', '--now', UNIT)
    print('Agent setup completed: ' + args.action)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # openssl/subprocess output may include caller paths; never dump credentials.
        print('Agent setup refused: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
