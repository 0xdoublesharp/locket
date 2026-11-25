#!/usr/bin/env python3
"""Inspect archive contents without installing into a user's application profile."""
import argparse
import json
import pathlib
import plistlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

CANARIES = (b'lk-canary', b'LOCKET_CANARY', b'DATABASE_URL_CANARY')
MAX_ENTRY = 64 * 1024 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
VSIX_PUBLISHER = 'locket'
VSIX_NAME = 'locket-vscode'
VSIX_NAMESPACE = 'http://schemas.microsoft.com/developer/vsx-schema/2011'


def scan(data, name):
    if any(marker in data for marker in CANARIES):
        raise ValueError(f'known canary marker in {name}')


def inspect_vsix(filename, version):
    with zipfile.ZipFile(filename) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError('duplicate or excessive VSIX entries')
        if sum(e.file_size for e in entries) > MAX_ARCHIVE:
            raise ValueError('VSIX expanded size exceeds limit')
        for entry in entries:
            path = pathlib.PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or entry.file_size > MAX_ENTRY:
                raise ValueError('unsafe VSIX entry')
            scan(archive.read(entry), entry.filename)
        package = json.loads(archive.read('extension/package.json'))
        if (package.get('publisher'), package.get('name')) != (VSIX_PUBLISHER, VSIX_NAME):
            raise ValueError('VSIX extension identity mismatch')
        if package.get('version') != version:
            raise ValueError('VSIX version mismatch')
        main = package.get('main', '').removeprefix('./')
        if not main.endswith('.js') or f'extension/{main}' not in names:
            raise ValueError('VSIX compiled entry point is missing')
        if any('/node_modules/' in name or name.startswith(('extension/src/', 'extension/integration/'))
               or name.endswith(('.test.js', '.map')) for name in names):
            raise ValueError('VSIX contains development-only files')
        manifest = ET.fromstring(archive.read('extension.vsixmanifest'))
        identities = manifest.findall('Metadata/Identity', {'': VSIX_NAMESPACE})
        if (manifest.tag != f'{{{VSIX_NAMESPACE}}}PackageManifest' or len(identities) != 1
                or (identities[0].get('Publisher'), identities[0].get('Id')) != (VSIX_PUBLISHER, VSIX_NAME)):
            raise ValueError('VSIX manifest identity mismatch')
        if identities[0].get('Version') != version:
            raise ValueError('VSIX manifest version mismatch')
        return f'{VSIX_PUBLISHER}.{VSIX_NAME}'


def inspect_app(folder, version):
    root = pathlib.Path(folder)
    scan_tree(root)
    info = plistlib.loads((root / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'app.locket.desktop':
        raise ValueError('app identifier mismatch')
    if info.get('CFBundleShortVersionString') != version:
        raise ValueError('app version mismatch')
    executable = info.get('CFBundleExecutable')
    if (not isinstance(executable, str) or executable in ('.', '..')
            or pathlib.PurePosixPath(executable).name != executable or '\\' in executable):
        raise ValueError('app executable name must stay inside its bundle')
    desktop = root / 'Contents/MacOS' / executable
    cli = root / 'Contents/Resources/locket'
    if not desktop.is_file() or not cli.is_file() or cli.is_symlink():
        raise ValueError('app executable or bundled CLI missing')
    output = subprocess.run([str(cli), '--version'], check=True, capture_output=True, timeout=5).stdout
    if output.strip() != f'locket {version}'.encode():
        raise ValueError('bundled CLI version mismatch')
    return 'app.locket.desktop'


def scan_tree(folder):
    """Read expanded artifact files only, refusing links outside their artifact."""
    root = pathlib.Path(folder).resolve(strict=True)
    total = 0
    for file in root.rglob('*'):
        try:
            target = file.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ValueError('invalid link in expanded artifact') from error
        if not target.is_relative_to(root):
            raise ValueError('expanded artifact link points outside its root')
        if file.is_file():
            total += file.stat().st_size
            if total > 2 * 1024 * 1024 * 1024:
                raise ValueError('expanded native artifact exceeds size limit')
            with file.open('rb') as stream:
                tail = b''
                while block := stream.read(1024 * 1024):
                    scan(tail + block, file.name)
                    tail = block[-64:]


def inspect_pkg(filename, version, scratch_root):
    """Expand with pkgutil, verify actual payload/receipt, then remove our files.

    This never invokes installer, package scripts, or the desktop application.
    The bundled CLI is invoked with --version by the existing app content check.
    """
    package = pathlib.Path(filename).resolve(strict=True)
    scratch = pathlib.Path(scratch_root).resolve(strict=True)
    if not package.is_file() or package.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError('native package is missing or exceeds size limit')
    if not scratch.is_dir():
        raise ValueError('scratch root must be an existing disposable directory')
    with tempfile.TemporaryDirectory(prefix='locket-package-check-', dir=scratch) as temporary:
        expanded = pathlib.Path(temporary) / 'expanded'
        subprocess.run(['/usr/sbin/pkgutil', '--expand-full', str(package), str(expanded)],
                       check=True, capture_output=True, timeout=60)
        scan_tree(expanded)
        receipts = list(expanded.rglob('PackageInfo'))
        if len(receipts) != 1:
            raise ValueError('expected exactly one native package receipt')
        receipt = ET.parse(receipts[0]).getroot()
        if receipt.tag != 'pkg-info' or receipt.get('identifier') != 'app.locket.desktop.pkg':
            raise ValueError('native package receipt identifier mismatch')
        if receipt.get('version') != version:
            raise ValueError('native package receipt version mismatch')
        if receipt.get('install-location') != '/Applications':
            raise ValueError('native package receipt install location mismatch')
        apps = [app for app in expanded.rglob('*.app') if app.is_dir()]
        if len(apps) != 1 or apps[0].name != 'Locket.app':
            raise ValueError('expected exactly one Locket.app in native package')
        inspect_app(apps[0], version)
        return receipt.get('identifier')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--vsix')
    group.add_argument('--app')
    group.add_argument('--pkg')
    parser.add_argument('--scratch-root', help='existing disposable directory for native package expansion')
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        if args.pkg:
            if not args.scratch_root:
                parser.error('--pkg requires --scratch-root for disposable expansion')
            identity = inspect_pkg(args.pkg, args.version, args.scratch_root)
        else:
            identity = inspect_vsix(args.vsix, args.version) if args.vsix else inspect_app(args.app, args.version)
    except (ValueError, KeyError, OSError, ET.ParseError, plistlib.InvalidFileException, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(1, f'package content check failed: {error}\n')
    print(f'Package contents verified: {identity} {args.version}')


if __name__ == '__main__':
    main()
