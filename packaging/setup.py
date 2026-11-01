#!/usr/bin/python3
"""Explicit, root-only identity import and read-only Kura OS authorization."""
import argparse
import base64
from contextlib import closing
import fcntl
import hashlib
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
import tempfile
import time
from urllib.parse import quote, urlsplit

CONFIG = '/etc/kura-management-agent'
STATE = '/var/lib/kura-management-agent'
DROPIN = '/etc/systemd/system/kura-netplan.service.d/agent-authorization.conf'
TRANSFER_SIGNER = '/etc/kura-management-agent/transfer-signer.pem'
UNIT = 'kura-management-agent.service'
DROPIN_CONTENT = '# Managed by kura-management-agent setup; read-only UDS access.\n[Service]\nSupplementaryGroups=kura-management\n'


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
        return {
            'AGENT_CONSOLE_ENDPOINT': endpoint, 'AGENT_GATEWAY_ID': gateway,
            'AGENT_CA': CONFIG + '/ca.pem', 'AGENT_CERT': CONFIG + '/agent.pem',
            'AGENT_KEY': CONFIG + '/agent.key', 'AGENT_STATE_DB': STATE + '/results.sqlite',
            'AGENT_SOCKET': '/run/kura-management-agent/control.sock',
            # Cross-center binding generation is independent of runtime connection epochs.
            'AGENT_BINDING_GENERATION': str(generation),
            # uid_t -1 is not a valid Linux user; nobody is not an authorization placeholder.
            'AGENT_KURA_UID': '4294967295', 'AGENT_ADMIN_UID': '0',
            'AGENT_NETWORK_INTERFACES': '', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE': '0',
            'RUST_LOG': 'info',
        }

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
                self.check()
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
        self.check()

    def import_identity(self, endpoint, gateway, ca, cert, key, transfer_signer=None):
        self.inactive()
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
        expected = [*payload, self.serialize(settings).encode()]
        if any(path.exists() for path in [*files, env, config / '.identity-installing']):
            # No force option: another console registration/partial import must be handled explicitly.
            if (all(path.is_file() and not path.is_symlink() and path.read_bytes() == value
                    for path, value in zip(files, payload)) and env.is_file()
                    and not (config / '.identity-installing').exists()):
                current = self.settings()
                if all(current.get(name) == value for name, value in settings.items()
                       if name not in ('AGENT_KURA_UID', 'AGENT_NETWORK_INTERFACES', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE')):
                    for path in files[:3]:
                        self.private(path)
                    if transfer_signer is not None:
                        self.public_key(signer)
                    return
            raise RuntimeError('Existing or interrupted identity; explicit transfer/recovery required')
        marker = config / '.identity-installing'
        self.put(marker, 'v1\n')
        for path, value in zip([*files, env], expected):
            if path == signer:
                self.put(path, value, 0o644)
            else:
                self.put(path, value)
        marker.unlink()

    def authorize(self, username):
        self.inactive()
        settings = self.settings()
        account = pwd.getpwnam(username)
        if username != 'kura-netplan' or account.pw_uid == 0 or account.pw_gid == 0:
            raise RuntimeError('Only the packaged unprivileged kura-netplan account can be authorized')
        if settings.get('AGENT_KURA_UID') not in ('4294967295', str(account.pw_uid)):
            raise RuntimeError('Another Kura UID is already authorized')
        self.guard_writer()
        dropin = self.path(DROPIN)
        if dropin.exists() and dropin.read_text() != DROPIN_CONTENT:
            raise RuntimeError('Kura authorization drop-in changed externally')
        settings['AGENT_KURA_UID'] = str(account.pw_uid)
        settings['AGENT_KURA_NETWORK_INTERFACES'] = ''
        dropin.parent.mkdir(parents=True, exist_ok=True)
        if not dropin.exists():
            self.put(dropin, DROPIN_CONTENT, 0o644)
        self.replace(self.path(CONFIG + '/agent.env'), self.serialize(settings))
        self.systemctl('daemon-reload')

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
        if not isinstance(transfer_id, str) or not 1 <= len(transfer_id) <= 128:
            raise RuntimeError('Invalid transfer authorization id')
        return claims

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

    def guard_writer(self):
        env = self.path(CONFIG + '/agent.env')
        if env.exists() and self.settings().get('AGENT_NETWORK_INTERFACES', ''):
            raise RuntimeError('Explicit network writer handover required before package lifecycle changes')
        journal = self.path(STATE + '/network/transaction.json')
        if journal.exists() and json.loads(journal.read_text()).get('state') not in ('COMMITTED', 'ROLLED_BACK'):
            raise RuntimeError('Settle the network transaction before package lifecycle changes')
        database = self.path(STATE + '/results.sqlite')
        if database.exists():
            try:
                with closing(sqlite3.connect('file:' + quote(str(database), safe='/') + '?mode=ro', uri=True, timeout=2)) as connection:
                    table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='executions'").fetchone()
                    pending = table and connection.execute("SELECT 1 FROM executions WHERE state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11) LIMIT 1").fetchone()
            except sqlite3.DatabaseError as error:
                raise RuntimeError('Execution journal cannot be inspected; recovery required') from error
            if pending:
                raise RuntimeError('Settle uncertain executions before package lifecycle changes')

    def check(self):
        if self.path(CONFIG + '/.identity-installing').exists():
            raise RuntimeError('Interrupted identity installation')
        settings = self.settings()
        generation = settings.get('AGENT_BINDING_GENERATION')
        if generation is None:
            raise RuntimeError('Binding generation missing; explicit migration/recovery required')
        expected = self.identity_settings(settings.get('AGENT_CONSOLE_ENDPOINT', ''), settings.get('AGENT_GATEWAY_ID', ''), generation)
        if generation != expected['AGENT_BINDING_GENERATION']:
            raise RuntimeError('Binding generation changed; explicit migration/recovery required')
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY', 'AGENT_STATE_DB', 'AGENT_SOCKET', 'AGENT_ADMIN_UID']:
            if settings.get(key) != expected[key]:
                raise RuntimeError('Packaged identity/state/socket path changed; explicit migration required')
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY']:
            self.private(self.path(settings[key]))
        if self.path(TRANSFER_SIGNER).exists():
            self.public_key(self.path(TRANSFER_SIGNER))
            self.openssl_for_public_key(self.path(TRANSFER_SIGNER))
        uid = settings.get('AGENT_KURA_UID')
        if uid != '4294967295':
            if uid != str(pwd.getpwnam('kura-netplan').pw_uid):
                raise RuntimeError('Authorized Kura account UID changed')
            if self.path(DROPIN).read_text() != DROPIN_CONTENT:
                raise RuntimeError('Kura authorization drop-in missing or changed')
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
        confirmed = self.path(STATE + '/network/confirmed.json')
        if confirmed.exists() and json.loads(confirmed.read_text()).get('yaml'):
            raise RuntimeError('Confirmed network state requires explicit handover before agent purge')
        dropin = self.path(DROPIN)
        if dropin.exists() and dropin.read_text() != DROPIN_CONTENT:
            raise RuntimeError('Refusing to purge externally modified authorization')
        paths = [self.path(name) for name in [CONFIG, STATE, '/var/log/kura-management-agent']]
        if any(path.exists() and not path.is_dir() for path in paths):
            raise RuntimeError('Unexpected agent state type')
        if dropin.exists():
            dropin.unlink()
        for path in paths:
            if path.exists():
                shutil.rmtree(path)
        self.systemctl('daemon-reload')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    identity = actions.add_parser('import-identity', help='Import an identity explicitly registered by this console; does not enroll or transfer')
    for name in ['endpoint', 'gateway', 'ca', 'cert', 'key']:
        identity.add_argument('--' + name, required=True)
    identity.add_argument('--transfer-signer')
    actions.add_parser('migrate-binding-generation', help='Add generation 1 to a proven same-center pre-generation identity')
    signer = actions.add_parser('register-transfer-signer', help='Register the original-center transfer token signer')
    signer.add_argument('--public-key', required=True)
    signer.add_argument('--expected-generation', required=True, type=int)
    signer.add_argument('--operator', required=True)
    transfer = actions.add_parser('transfer-identity', help='Perform an explicit gateway-local rebind to new registered identity')
    for name in ['endpoint', 'gateway', 'ca', 'cert', 'key', 'operator']:
        transfer.add_argument('--' + name, required=True)
    transfer.add_argument('--expected-generation', required=True, type=int)
    transfer.add_argument('--authorization-token')
    authorization = actions.add_parser('authorize-kura', help='Authorize the packaged Kura UID for read-only UDS access')
    authorization.add_argument('--user', default='kura-netplan', choices=['kura-netplan'])
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
        elif args.action == 'migrate-binding-generation':
            setup.migrate_binding_generation()
        elif args.action == 'register-transfer-signer':
            setup.register_transfer_signer(args.public_key, args.expected_generation,
                                           args.operator)
        elif args.action == 'transfer-identity':
            setup.transfer_identity(args.endpoint, args.gateway, args.ca, args.cert, args.key,
                                    args.expected_generation, args.operator,
                                    args.authorization_token)
        elif args.action == 'authorize-kura':
            setup.authorize(args.user)
        else:
            setup.check()
    # systemctl waits for ExecStartPre, whose check acquires the same lock. Release
    # it before starting; ExecStartPre validates again after systemd enters activating.
    if args.action == 'activate':
        setup.systemctl('enable', '--now', UNIT)
    print('Agent setup completed: ' + args.action)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # openssl/subprocess output may include caller paths; never dump credentials.
        print('Agent setup refused: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
