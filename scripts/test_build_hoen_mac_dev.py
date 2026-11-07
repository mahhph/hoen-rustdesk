import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('trial_build', Path(__file__).with_name('build-hoen-mac-dev.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildSafetyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        flutter = root / 'flutter'
        config = flutter / 'macos/Runner/Configs/AppInfo.xcconfig'
        project = flutter / 'macos/Runner.xcodeproj/project.pbxproj'
        config.parent.mkdir(parents=True)
        project.parent.mkdir(parents=True)
        icon = flutter / 'macos/Runner/AppIcon.icns'
        dev_icon = flutter / 'macos/Runner/HoenRemoteDev.icns'
        icon.write_bytes(b'stock-icon')
        dev_icon.write_bytes(b'development-icon')
        config.write_text('PRODUCT_NAME = RustDesk\n')
        project.write_text('PRODUCT_BUNDLE_IDENTIFIER = com.carriez.rustdesk;\nuser-change\n')
        common = flutter / 'lib/common.dart'
        common.parent.mkdir(parents=True)
        common.write_text('static ThemeData lightTheme = ThemeData(\n'
                          'dialogTheme: DialogTheme(\ntabBarTheme: const TabBarTheme(\n'
                          'static ThemeData darkTheme = ThemeData(\n'
                          'dialogTheme: DialogTheme(\ntabBarTheme: const TabBarTheme(\n')
        pubspec = flutter / 'pubspec.yaml'
        pubspec.write_text('extended_text: 14.0.0\ngoogle_fonts: ^6.2.1\n')
        lock = flutter / 'pubspec.lock'
        lock.write_bytes(b'windows-lock')
        (flutter / 'pubspec.macos-arm64.lock').write_bytes(b'mac-lock')
        self.common, self.pubspec, self.lock = common, pubspec, lock
        self.config, self.project, self.icon = config, project, icon
        self.original = {p: p.read_bytes() for p in (config, project, icon)}
        self.patches = [
            mock.patch.object(build, 'ROOT', root),
            mock.patch.object(build, 'FLUTTER', flutter),
            mock.patch.object(build, 'BACKUPS', root / 'backups'),
            mock.patch.object(build.sys, 'platform', 'darwin'),
            mock.patch.object(build.platform, 'machine', return_value='arm64'),
            mock.patch.object(build.shutil, 'copy2'),
            mock.patch.object(build.subprocess, 'check_output', return_value=build.BUNDLE_ID),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_restores_existing_project_changes(self):
        def fake_run(args, **kwargs):
            if args[0] == 'flutter':
                self.assertIn('HoenRemoteDev', self.config.read_text())
                self.assertIn(build.BUNDLE_ID, self.project.read_text())
                self.assertEqual(self.icon.read_bytes(), b'development-icon')
        with mock.patch.object(build, 'run', side_effect=fake_run):
            build.build()
        self.assertEqual(self.config.read_bytes(), self.original[self.config])
        self.assertEqual(self.project.read_bytes(), self.original[self.project])
        self.assertEqual(self.icon.read_bytes(), self.original[self.icon])

    def test_never_overwrites_a_concurrent_project_edit(self):
        def fake_run(args, **kwargs):
            if args[0] == 'flutter':
                with self.project.open('a') as stream:
                    stream.write('concurrent-change\n')
        with mock.patch.object(build, 'run', side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                build.build()
        self.assertEqual(self.config.read_bytes(), self.original[self.config])
        self.assertIn('concurrent-change', self.project.read_text())
        self.assertTrue(any((p / '1.original').read_bytes() == self.original[self.project]
                            for p in build.BACKUPS.iterdir()))

    def test_restores_project_after_build_failure(self):
        def fake_run(args, **kwargs):
            if args[0] == 'flutter':
                raise build.subprocess.CalledProcessError(1, args)
        with mock.patch.object(build, 'run', side_effect=fake_run):
            with self.assertRaises(build.subprocess.CalledProcessError):
                build.build()
        self.assertEqual(self.config.read_bytes(), self.original[self.config])
        self.assertEqual(self.project.read_bytes(), self.original[self.project])

    def test_preserves_project_edit_made_during_cargo_build(self):
        def fake_run(args, **kwargs):
            if args[0] == 'cargo':
                with self.project.open('a') as stream:
                    stream.write('cargo-time-change\n')
        with mock.patch.object(build, 'run', side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                build.build()
        self.assertEqual(self.config.read_bytes(), self.original[self.config])
        self.assertIn('cargo-time-change', self.project.read_text())

    def test_arm64_resolves_pinned_dependencies_and_restores_shared_files(self):
        before = {p: p.read_bytes() for p in (self.common, self.pubspec, self.lock)}
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
            if args[:3] == ['flutter', 'pub', 'get']:
                self.assertIn('--enforce-lockfile', args)
                self.assertEqual(self.lock.read_bytes(), b'mac-lock')
                self.assertIn('extended_text: 15.0.2', self.pubspec.read_text())
                self.assertIn('DialogThemeData(', self.common.read_text())
        with mock.patch.object(build, 'run', side_effect=fake_run):
            build.build()
        self.assertTrue(any(args[:3] == ['flutter', 'pub', 'get'] for args in calls))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_shared_source_edit_during_build_is_not_overwritten(self):
        def fake_run(args, **kwargs):
            if args[:3] == ['flutter', 'build', 'macos']:
                with self.common.open('a') as stream:
                    stream.write('concurrent-change\n')
        with mock.patch.object(build, 'run', side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                build.build()
        self.assertIn('concurrent-change', self.common.read_text())
        self.assertEqual(self.lock.read_bytes(), b'windows-lock')

    def test_intel_build_does_not_replace_shared_dependencies(self):
        before = {p: p.read_bytes() for p in (self.common, self.pubspec, self.lock)}
        calls = []
        def fake_run(args, **kwargs):
            calls.append(args)
        with mock.patch.object(build.platform, 'machine', return_value='x86_64'):
            with mock.patch.object(build, 'run', side_effect=fake_run):
                build.build()
        self.assertFalse(any(args[:3] == ['flutter', 'pub', 'get'] for args in calls))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
