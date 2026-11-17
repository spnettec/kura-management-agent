#!/usr/bin/env python3
"""Stage self-contained Rust sources, or package the ELF with its Kura Java adapter."""
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
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / 'packaging'
READER_FILES = {
    '/usr/lib/kura-management-agent/enrollment_reader.py': 'enrollment_reader.py',
    '/usr/lib/systemd/system/kura-management-enrollment-reader.socket': 'kura-management-enrollment-reader.socket',
    '/usr/lib/systemd/system/kura-management-enrollment-reader@.service': 'kura-management-enrollment-reader@.service',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def enrollment_reader():
    return {'schemaVersion': 1, 'protocolVersion': 1, 'user': 'kurad',
            'socket': '/run/kura-management-enrollment-reader.sock',
            'sourceRoot': '/opt/eclipse/kura/data/management-enrollment',
            'files': {path: sha(PACKAGING / name) for path, name in READER_FILES.items()}}


def source_files():
    sources = [ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')]
    for directory in (ROOT / 'src', ROOT / 'packaging'):
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError('Source symlinks or missing source directory')
        tree = sorted(directory.rglob('*'))
        if any(path.is_symlink() for path in tree):
            raise RuntimeError('Source symlinks are not release inputs')
        sources += [path for path in tree if path.is_file() and not any(
            part in {'__pycache__', 'target', '.git'} for part in path.relative_to(ROOT).parts)]
    return sources


def verify_source_manifest(provenance):
    if provenance.get('schemaVersion') != 2 or provenance.get('siblingSourceRequired') is not False:
        raise RuntimeError('Complete release source provenance required')
    protocol = provenance.get('protocol', {})
    digest = protocol.get('sha256', '')
    if (not re.fullmatch('[0-9a-f]{64}', digest) or protocol.get('version') != '0.1.0'
            or protocol.get('sourcePath') != 'vendor/' + digest + '/yofc-management-protocol-0.1.0'):
        raise RuntimeError('Invalid checksummed protocol source path')
    rows = provenance.get('sourceFiles', [])
    records = {row['path']: row['sha256'] for row in rows}
    expected = {str(path.relative_to(ROOT)): path for path in source_files()}
    if len(records) != len(rows) or set(records) != set(expected) | {'Cargo.toml.staged'}:
        raise RuntimeError('Release source manifest does not cover the exact source set')
    for name, path in expected.items():
        accepted = {records[name]}
        if name == 'Cargo.toml':
            accepted.add(records['Cargo.toml.staged'])
        if path.is_symlink() or not path.is_file() or sha(path) not in accepted:
            raise RuntimeError('Release source differs from staged provenance: ' + name)
    # A self-contained export uses the staged Cargo mapping and must retain its
    # exact extracted protocol tree. Development checkouts bind the crate at stage.
    if sha(ROOT / 'Cargo.toml') == records['Cargo.toml.staged']:
        directory = ROOT / protocol['sourcePath']
        if directory.is_symlink() or any(path.is_symlink() for path in directory.rglob('*')):
            raise RuntimeError('Unsafe vendored protocol source')
        actual = {str(path.relative_to(directory)): sha(path)
                  for path in directory.rglob('*') if path.is_file()}
        if actual != protocol['sourceFiles']:
            raise RuntimeError('Vendored protocol differs from staged artifact')


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
    # Runtime resources and privileged packaging code belong to the same source
    # cohort as Rust. The exported directory can build its own package.
    sources = source_files()
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
    protocol_files = {str(path.relative_to(vendor / prefix)): sha(path)
                      for path in (vendor / prefix).rglob('*') if path.is_file()}
    result = {'schemaVersion': 2, 'protocol': {'file': protocol.name, 'sha256': expected, 'version': '0.1.0',
              'sourcePath': protocol_path, 'sourceFiles': protocol_files},
              'sourceFiles': records, 'siblingSourceRequired': False}
    (destination / 'source-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def java_bridge(bundle, expected):
    """Validate the reviewed OSGi adapter; installing Rust alone cannot connect Kura."""
    if bundle.is_symlink() or not bundle.is_file() or not re.fullmatch('[0-9a-f]{64}', expected) or sha(bundle) != expected:
        raise RuntimeError('Java bridge artifact digest mismatch')
    try:
        with zipfile.ZipFile(bundle) as archive:
            headers = {}
            key = None
            for line in archive.read('META-INF/MANIFEST.MF').decode('utf-8').splitlines():
                if not line:
                    break
                if line.startswith(' ') and key:
                    headers[key] += line[1:]
                else:
                    key, value = line.split(': ', 1)
                    key = key.lower()
                    if key in headers:
                        raise ValueError('duplicate manifest header')
                    headers[key] = value
            name = headers['bundle-symbolicname'].split(';', 1)[0]
            version = headers['bundle-version']
            if name != 'org.eclipse.kura.management.bridge' or not re.fullmatch(r'\d+\.\d+\.\d+(?:\.[A-Za-z0-9_-]+)?', version):
                raise ValueError('unexpected adapter identity')
            descriptor = 'OSGI-INF/management-bridge.xml'
            if descriptor not in [value.strip() for value in headers.get('service-component', '').split(',')]:
                raise ValueError('adapter component is not declared')
            component = ET.fromstring(archive.read(descriptor))
            implementation = next(x for x in component if x.tag.rsplit('}', 1)[-1] == 'implementation')
            entry = implementation.attrib['class'].replace('.', '/') + '.class'
            if entry not in archive.namelist():
                raise ValueError('adapter implementation is missing')
    except (KeyError, ValueError, StopIteration, zipfile.BadZipFile, ET.ParseError) as error:
        raise RuntimeError('Invalid Java bridge OSGi artifact') from error
    return {'symbolicName': name, 'version': version, 'sha256': expected,
            'path': '/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar'}


def deb(binary, expected, architecture, version, destination, source_manifest, bridge_bundle, bridge_expected,
        core_loader_sha256=None):
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
    verify_source_manifest(provenance)
    if not re.fullmatch('[0-9a-f]{64}', provenance['protocol']['sha256']):
        raise RuntimeError('Checksummed protocol/source provenance required')
    bridge = java_bridge(bridge_bundle, bridge_expected)
    if not isinstance(core_loader_sha256, str) or not re.fullmatch('[0-9a-f]{64}', core_loader_sha256):
        raise RuntimeError('Reviewed Core optional-adapter loader checksum required')
    bridge.update(coreLoaderProtocol=1, coreLoaderSha256=core_loader_sha256)
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
        (PACKAGING / 'core-snapshot-validator.json.example', 'usr/share/doc/kura-management-agent/core-snapshot-validator.json.example', 0o644),
        (PACKAGING / 'network.conf.example', 'usr/share/doc/kura-management-agent/network.conf.example', 0o644),
        (source_manifest, 'usr/share/kura-management-agent/source-manifest.json', 0o644),
        (bridge_bundle, bridge['path'].lstrip('/'), 0o644),
        *((PACKAGING / name, path.lstrip('/'), 0o644) for path, name in READER_FILES.items()),
    ]
    for source, path, mode in entries:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(mode)
    marker = root / 'usr/share/kura-management-agent/package-v1'
    marker.write_text('kura-management-agent-v1\n')
    (root / 'usr/share/kura-management-agent/java-bridge.json').write_text(json.dumps(bridge, indent=2) + '\n')
    reader = enrollment_reader()
    (root / 'usr/share/kura-management-agent/enrollment-reader.json').write_text(json.dumps(reader, indent=2) + '\n')
    wrapper = root / 'usr/sbin/kura-agent-setup'
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -I /usr/lib/kura-management-agent/setup.py "$@"\n')
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
        script.write_text('#!/usr/bin/python3 -I\nSCRIPT_NAME = ' + repr(name) +
                          '\nPACKAGE_CORE_LOADER_SHA256 = ' + repr(core_loader_sha256) + '\n' + setup + '\n' + lifecycle)
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
               'sourceManifestSha256': sha(source_manifest), 'javaBridge': bridge, 'enrollmentReader': reader}
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
    package.add_argument('--bridge-bundle', type=Path, required=True)
    package.add_argument('--bridge-sha256', required=True)
    package.add_argument('--core-loader-sha256', required=True)
    args = parser.parse_args()
    if args.action == 'source':
        result = stage(args.protocol, args.sha256, args.destination)
    else:
        result = deb(args.binary, args.sha256, args.architecture, args.version, args.destination, args.source_manifest,
                     args.bridge_bundle, args.bridge_sha256, args.core_loader_sha256)
    print(json.dumps(result, indent=2))
