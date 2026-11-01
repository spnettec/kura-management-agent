#!/usr/bin/python3
"""Explicit, root-only identity import and read-only Kura OS authorization."""
import argparse
from contextlib import closing
import fcntl
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
from urllib.parse import quote, urlsplit

CONFIG = '/etc/kura-management-agent'
STATE = '/var/lib/kura-management-agent'
DROPIN = '/etc/systemd/system/kura-netplan.service.d/agent-authorization.conf'
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
    def identity_settings(endpoint, gateway):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+/?', endpoint)
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise RuntimeError('A plain HTTPS console endpoint is required')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', gateway):
            raise RuntimeError('Invalid gateway identifier')
        return {
            'AGENT_CONSOLE_ENDPOINT': endpoint, 'AGENT_GATEWAY_ID': gateway,
            'AGENT_CA': CONFIG + '/ca.pem', 'AGENT_CERT': CONFIG + '/agent.pem',
            'AGENT_KEY': CONFIG + '/agent.key', 'AGENT_STATE_DB': STATE + '/results.sqlite',
            'AGENT_SOCKET': '/run/kura-management-agent/control.sock',
            # uid_t -1 is not a valid Linux user; nobody is not an authorization placeholder.
            'AGENT_KURA_UID': '4294967295', 'AGENT_ADMIN_UID': '0',
            'AGENT_NETWORK_INTERFACES': '', 'AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE': '0',
            'RUST_LOG': 'info',
        }

    @staticmethod
    def serialize(settings):
        return ''.join(key + '=' + value + '\n' for key, value in settings.items())

    def import_identity(self, endpoint, gateway, ca, cert, key):
        self.inactive()
        settings = self.identity_settings(endpoint, gateway)
        sources = [Path(ca), Path(cert), Path(key)]
        for path in sources:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Identity input must be a bounded regular file')
        self.private(sources[2])
        # Validate exactly the bytes subsequently installed, not mutable caller paths.
        payload = [path.read_bytes() for path in sources]
        with tempfile.TemporaryDirectory(prefix='kura-agent-identity-') as directory:
            staged = [Path(directory) / name for name in ['ca.pem', 'agent.pem', 'agent.key']]
            for path, value in zip(staged, payload):
                self.put(path, value)
            self.run(['openssl', 'verify', '-purpose', 'sslclient', '-CAfile', str(staged[0]), str(staged[1])],
                     check=True, capture_output=True)
            public = self.run(['openssl', 'x509', '-in', str(staged[1]), '-pubkey', '-noout'], check=True, capture_output=True).stdout
            private_public = self.run(['openssl', 'pkey', '-in', str(staged[2]), '-pubout'], check=True, capture_output=True).stdout
            if public != private_public:
                raise RuntimeError('Certificate and private key do not match')
        config = self.path(CONFIG)
        config.mkdir(mode=0o700, parents=True, exist_ok=True)
        if config.stat().st_uid != os.getuid() or config.stat().st_mode & 0o077:
            raise RuntimeError('Identity directory must be owned and private')
        files = [config / name for name in ['ca.pem', 'agent.pem', 'agent.key']]
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
                    for path in files:
                        self.private(path)
                    return
            raise RuntimeError('Existing or interrupted identity; explicit transfer/recovery required')
        marker = config / '.identity-installing'
        self.put(marker, 'v1\n')
        for path, value in zip([*files, env], expected):
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
        expected = self.identity_settings(settings.get('AGENT_CONSOLE_ENDPOINT', ''), settings.get('AGENT_GATEWAY_ID', ''))
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY', 'AGENT_STATE_DB', 'AGENT_SOCKET', 'AGENT_ADMIN_UID']:
            if settings.get(key) != expected[key]:
                raise RuntimeError('Packaged identity/state/socket path changed; explicit migration required')
        for key in ['AGENT_CA', 'AGENT_CERT', 'AGENT_KEY']:
            self.private(self.path(settings[key]))
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
            setup.import_identity(args.endpoint, args.gateway, args.ca, args.cert, args.key)
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
