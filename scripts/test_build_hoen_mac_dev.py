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
        config.write_text('PRODUCT_NAME = RustDesk\n')
        project.write_text('PRODUCT_BUNDLE_IDENTIFIER = com.carriez.rustdesk;\nuser-change\n')
        self.config, self.project = config, project
        self.original = {p: p.read_bytes() for p in (config, project)}
        self.patches = [
            mock.patch.object(build, 'ROOT', root),
            mock.patch.object(build, 'FLUTTER', flutter),
            mock.patch.object(build, 'BACKUPS', root / 'backups'),
            mock.patch.object(build.sys, 'platform', 'darwin'),
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
        with mock.patch.object(build, 'run', side_effect=fake_run):
            build.build()
        self.assertEqual(self.config.read_bytes(), self.original[self.config])
        self.assertEqual(self.project.read_bytes(), self.original[self.project])

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


if __name__ == '__main__':
    unittest.main()
