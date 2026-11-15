#!/usr/bin/env python3
"""Stage self-contained sources from a checksummed protocol crate, or package an ELF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / 'packaging'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(protocol, expected, destination):
    if sha(protocol) != expected or not re.fullmatch('[0-9a-f]{64}', expected):
        raise RuntimeError('Protocol artifact digest mismatch')
    if destination.exists():
        raise RuntimeError('Keep prior staged source; select a new destination')
    # Only regular files/directories under the declared crate prefix; no symlink or path traversal.
    prefix = 'yofc-management-protocol-0.1.0'
    with tarfile.open(protocol) as archive:
        entries = archive.getmembers()
        for member in entries:
            path = Path(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix
                    or not (member.isdir() or member.isfile()) or member.size > 8 * 1024 * 1024):
                raise RuntimeError('Unsafe protocol archive')
        if sum(member.size for member in entries) > 32 * 1024 * 1024:
            raise RuntimeError('Oversized protocol archive')
        destination.mkdir(parents=True)
        # Crate archives normalize mtimes. A fixed path/version can make Cargo
        # reuse generated wire types from an older artifact in a warm target.
        # Bind path dependency identity to the reviewed archive digest as well.
        vendor = destination / 'vendor' / expected
        vendor.mkdir(parents=True)
        archive.extractall(vendor, filter='data')
    manifest = tomllib.loads((vendor / prefix / 'Cargo.toml').read_text())
    if manifest['package']['name'] != 'yofc-management-protocol' or manifest['package']['version'] != '0.1.0':
        raise RuntimeError('Protocol crate identity mismatch')
    sources = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'rust-toolchain.toml', *sorted((ROOT / 'src').glob('**/*.rs'))]
    records = []
    for source in sources:
        if source.is_symlink():
            raise RuntimeError('Source symlinks are not release inputs')
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        records.append({'path': str(relative), 'sha256': sha(source)})
    cargo = destination / 'Cargo.toml'
    text = cargo.read_text()
    old = 'path = "../kura-management-console/crates/management-protocol"'
    if text.count(old) != 1:
        raise RuntimeError('Agent development protocol mapping changed; inspect before packaging')
    protocol_path = str((vendor / prefix).relative_to(destination))
    cargo.write_text(text.replace(old, 'path = "' + protocol_path + '"'))
    records.append({'path': 'Cargo.toml.staged', 'sha256': sha(cargo)})
    result = {'schemaVersion': 1, 'protocol': {'file': protocol.name, 'sha256': expected, 'version': '0.1.0', 'sourcePath': protocol_path},
              'sourceFiles': records, 'siblingSourceRequired': False}
    (destination / 'source-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def deb(binary, expected, architecture, version, destination, source_manifest):
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', version):
        raise RuntimeError('Invalid package version')
    if sha(binary) != expected:
        raise RuntimeError('Binary digest mismatch')
    with binary.open('rb') as source:
        header = source.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', header[18:20])[0] != {'arm64': 183, 'amd64': 62}[architecture]:
        raise RuntimeError('Expected a matching Linux ELF64 binary')
    versions = subprocess.check_output(['readelf', '--version-info', str(binary)], text=True)
    required = {(int(a), int(b)) for a, b in re.findall(r'GLIBC_(\d+)\.(\d+)', versions)}
    if not required or max(required) > (2, 39):
        raise RuntimeError('Binary does not satisfy the Ubuntu 24.04 glibc floor')
    provenance = json.loads(source_manifest.read_text())
    if provenance.get('siblingSourceRequired') is not False or not re.fullmatch('[0-9a-f]{64}', provenance['protocol']['sha256']):
        raise RuntimeError('Checksummed protocol/source provenance required')
    if destination.exists():
        raise RuntimeError('Keep prior package output; select a new destination')
    destination.mkdir(parents=True)
    root = destination / 'root'
    entries = [
        (binary, 'usr/bin/yofc-management-agent', 0o755),
        (PACKAGING / 'setup.py', 'usr/lib/kura-management-agent/setup.py', 0o644),
        (PACKAGING / 'kura-management-agent.service', 'usr/lib/systemd/system/kura-management-agent.service', 0o644),
        (PACKAGING / 'agent.env.example', 'usr/share/doc/kura-management-agent/agent.env.example', 0o644),
        (PACKAGING / 'system-control.json.example', 'usr/share/doc/kura-management-agent/system-control.json.example', 0o644),
        (PACKAGING / 'recovery.conf.example', 'usr/share/doc/kura-management-agent/recovery.conf.example', 0o644),
        (PACKAGING / 'network.conf.example', 'usr/share/doc/kura-management-agent/network.conf.example', 0o644),
        (source_manifest, 'usr/share/kura-management-agent/source-manifest.json', 0o644),
    ]
    for source, path, mode in entries:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(mode)
    marker = root / 'usr/share/kura-management-agent/package-v1'
    marker.write_text('kura-management-agent-v1\n')
    wrapper = root / 'usr/sbin/kura-agent-setup'
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/lib/kura-management-agent/setup.py "$@"\n')
    wrapper.chmod(0o755)
    control = root / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text(f'''Package: kura-management-agent
Version: {version}
Architecture: {architecture}
Section: admin
Priority: optional
Maintainer: YOFC Kura maintainers
Pre-Depends: python3
Depends: libc6 (>= 2.39), libgcc-s1, openssl, systemd, passwd, iproute2, netplan.io
Description: Independent YOFC Rust gateway management agent
 Explicit registered mTLS identity and OS UID authorization. No automatic network takeover.
''')
    setup = (PACKAGING / 'setup.py').read_text().split("if __name__ == '__main__':")[0]
    lifecycle = (PACKAGING / 'lifecycle.py').read_text()
    for name in ['preinst', 'postinst', 'prerm', 'postrm']:
        script = control / name
        script.write_text('#!/usr/bin/python3\nSCRIPT_NAME = ' + repr(name) + '\n' + setup + '\n' + lifecycle)
        script.chmod(0o755)
    for path in root.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
        elif not path.stat().st_mode & 0o111:
            path.chmod(0o644)
    package = destination / f'kura-management-agent_{version}_{architecture}.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(root), str(package)], check=True)
    receipt = {'package': str(package), 'sha256': sha(package), 'binarySha256': expected,
               'architecture': architecture, 'maximumGlibc': '.'.join(map(str, max(required))),
               'sourceManifestSha256': sha(source_manifest)}
    (destination / 'package.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    source = sub.add_parser('source')
    source.add_argument('--protocol', type=Path, required=True)
    source.add_argument('--sha256', required=True)
    source.add_argument('--destination', type=Path, required=True)
    package = sub.add_parser('deb')
    package.add_argument('--binary', type=Path, required=True)
    package.add_argument('--sha256', required=True)
    package.add_argument('--architecture', choices=['arm64', 'amd64'], required=True)
    package.add_argument('--version', required=True)
    package.add_argument('--destination', type=Path, required=True)
    package.add_argument('--source-manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'source':
        result = stage(args.protocol, args.sha256, args.destination)
    else:
        result = deb(args.binary, args.sha256, args.architecture, args.version, args.destination, args.source_manifest)
    print(json.dumps(result, indent=2))
