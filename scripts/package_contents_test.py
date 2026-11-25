import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('contents', pathlib.Path(__file__).with_name('check-package-contents.py'))
contents = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contents)

class PackageContentsTests(unittest.TestCase):
    def artifact(self, root, extra=None, version='0.1.0', publisher='locket', name='locket-vscode', manifest=None):
        filename = pathlib.Path(root) / 'fixture.vsix'
        if manifest is None:
            manifest = ('<PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">'
                        '<Metadata>'
                        f'<Identity Publisher="{publisher}" Id="{name}" Version="{version}"/>'
                        '</Metadata></PackageManifest>')
        with zipfile.ZipFile(filename, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('extension/package.json', json.dumps(dict(publisher=publisher, name=name, version=version, main='./out/extension.js')))
            z.writestr('extension.vsixmanifest', manifest)
            z.writestr('extension/out/extension.js', 'exports.activate = () => {};')
            for name, data in (extra or {}).items():
                z.writestr(name, data)
        return filename

    def test_real_compressed_content_and_entrypoint(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            self.assertEqual(contents.inspect_vsix(self.artifact(root), '0.1.0'), 'locket.locket-vscode')
            with self.assertRaisesRegex(ValueError, 'version'):
                contents.inspect_vsix(self.artifact(root, version='0.0.0-dev'), '0.1.0')
            with self.assertRaisesRegex(ValueError, 'canary'):
                contents.inspect_vsix(self.artifact(root, {'extension/out/leak.js': 'LOCKET_CANARY=hidden'}), '0.1.0')
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                contents.inspect_vsix(self.artifact(root, {'../escape': 'bad'}), '0.1.0')

    def test_rejects_unrelated_or_inconsistent_vsix_identity(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            for publisher, name in [('other', 'locket-vscode'), ('locket', 'other')]:
                with self.subTest(publisher=publisher, name=name), self.assertRaisesRegex(ValueError, 'identity'):
                    contents.inspect_vsix(self.artifact(root, publisher=publisher, name=name), '0.1.0')
            wrong_manifest = ('<PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">'
                              '<Metadata><Identity Publisher="other" Id="locket-vscode" Version="0.1.0"/>'
                              '</Metadata></PackageManifest>')
            with self.assertRaisesRegex(ValueError, 'identity'):
                contents.inspect_vsix(self.artifact(root, manifest=wrong_manifest), '0.1.0')

    def test_rejects_development_files(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            for name in ('extension/out/a.test.js', 'extension/out/a.js.map', 'extension/integration/packaged-host.cjs'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'development'):
                    contents.inspect_vsix(self.artifact(root, {name: 'fixture'}), '0.1.0')


class NativePackageContentsTests(unittest.TestCase):
    def native_app(self, root, version='0.1.0', marker=None):
        import plistlib
        app = pathlib.Path(root) / 'payload' / 'Locket.app'
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/Resources').mkdir()
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'app.locket.desktop',
            'CFBundleShortVersionString': version,
            'CFBundleExecutable': 'locket-desktop',
        }))
        (app / 'Contents/MacOS/locket-desktop').write_text('synthetic desktop fixture')
        cli = app / 'Contents/Resources/locket'
        cli.write_text('#!/bin/sh\nprintf "locket 0.1.0\\n"\n')
        cli.chmod(0o755)
        if marker:
            (app / 'Contents/Resources/leak.txt').write_bytes(marker)
        return app

    @unittest.skipUnless(os.path.exists('/usr/bin/pkgbuild'), 'requires native macOS package tools')
    def test_real_compressed_pkg_expands_without_installing(self):
        import subprocess
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            app = self.native_app(root)
            package = pathlib.Path(root) / 'fixture.pkg'
            subprocess.run(['/usr/bin/pkgbuild', '--component', str(app), '--identifier', 'app.locket.desktop.pkg', '--version', '0.1.0', '--install-location', '/Applications', str(package)], check=True, capture_output=True)
            self.assertEqual(contents.inspect_pkg(package, '0.1.0', root), 'app.locket.desktop.pkg')
            if os.path.exists('/usr/bin/productbuild'):
                component = pathlib.Path(root) / 'locket-component.pkg'
                package.rename(component)
                distribution = pathlib.Path(root) / 'distribution.xml'
                template = pathlib.Path(__file__).resolve().parents[1] / 'dist/installers/macos/distribution.xml'
                distribution.write_text(template.read_text().replace('__LOCKET_VERSION__', '0.1.0'))
                subprocess.run(['/usr/bin/productbuild', '--distribution', str(distribution), '--package-path', root, str(package)], check=True, capture_output=True)
                self.assertEqual(contents.inspect_pkg(package, '0.1.0', root), 'app.locket.desktop.pkg')
            import sys
            checked = subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('check-package-contents.py')), '--pkg', str(package), '--scratch-root', root, '--version', '0.1.0'], check=True, capture_output=True)
            self.assertIn(b'app.locket.desktop.pkg 0.1.0', checked.stdout)
            # Only the fixture payload and pkg remain; expansion storage was removed.
            self.assertFalse(any(path.name.startswith('locket-package-check-') for path in pathlib.Path(root).iterdir()))
            with self.assertRaisesRegex(ValueError, 'receipt.*version'):
                contents.inspect_pkg(package, '9.9.9', root)

    @unittest.skipUnless(os.path.exists('/usr/bin/pkgbuild'), 'requires native macOS package tools')
    def test_pkg_rejects_compressed_canary_and_receipt_identity(self):
        import subprocess
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            app = self.native_app(root, marker=b'LOCKET_CANARY=compressed-secret')
            package = pathlib.Path(root) / 'canary.pkg'
            subprocess.run(['/usr/bin/pkgbuild', '--component', str(app), '--identifier', 'app.locket.desktop.pkg', '--version', '0.1.0', '--install-location', '/Applications', str(package)], check=True, capture_output=True)
            self.assertNotIn(b'LOCKET_CANARY=compressed-secret', package.read_bytes())
            with self.assertRaisesRegex(ValueError, 'canary'):
                contents.inspect_pkg(package, '0.1.0', root)
            (app / 'Contents/Resources/leak.txt').unlink()
            package = pathlib.Path(root) / 'wrong-id.pkg'
            subprocess.run(['/usr/bin/pkgbuild', '--component', str(app), '--identifier', 'wrong.product.pkg', '--version', '0.1.0', '--install-location', '/Applications', str(package)], check=True, capture_output=True)
            with self.assertRaisesRegex(ValueError, 'receipt.*identifier'):
                contents.inspect_pkg(package, '0.1.0', root)

    def test_app_link_escape_is_rejected_before_reading_outside_artifact(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            app = self.native_app(root)
            outside = pathlib.Path(root) / 'outside-artifact'
            outside.write_text('synthetic private content')
            (app / 'Contents/Resources/escape').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'outside'):
                contents.inspect_app(app, '0.1.0')

    def test_cross_arch_expected_arch_uses_macho_check(self):
        from unittest import mock
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            app = self.native_app(root)
            fake_lipo = mock.Mock(stdout=b'x86_64\n')
            with mock.patch.object(contents.platform, 'machine', return_value='arm64'), \
                 mock.patch.object(contents.subprocess, 'run', return_value=fake_lipo) as run_mock:
                self.assertEqual(contents.inspect_app(app, '0.1.0', expected_arch='x86_64'), 'app.locket.desktop')
                self.assertEqual(run_mock.call_count, 2)
            bad_lipo = mock.Mock(stdout=b'arm64\n')
            with mock.patch.object(contents.platform, 'machine', return_value='arm64'), \
                 mock.patch.object(contents.subprocess, 'run', return_value=bad_lipo):
                with self.assertRaisesRegex(ValueError, 'architecture mismatch'):
                    contents.inspect_app(app, '0.1.0', expected_arch='x86_64')

if __name__ == '__main__':
    unittest.main()
