import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("packager", Path(__file__).with_name("package-remote-desktop.py"))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        files = []
        for name in ("rustdesk.exe", "librustdesk.dll", "flutter_windows.dll"):
            path = self.payload / name
            path.write_bytes(name.encode())
            files.append({"path": name, "size": path.stat().st_size, "sha256": packager.digest(path)})
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"schema": 1, "product": "Remote Desktop Service", "serviceName": "RemoteDesktopService", "files": files}))
        self.output = self.root / "release.zip"

    def build(self):
        return packager.package(self.payload, self.manifest, self.output, "a" * 40)

    def test_bundle_contains_only_release_inputs(self):
        self.assertEqual(len(self.build()), 64)
        with zipfile.ZipFile(self.output) as archive:
            names = set(archive.namelist())
            self.assertIn("scripts/remote-desktop-setup.ps1", names)
            self.assertIn("payload/rustdesk.exe", names)
            self.assertEqual(json.loads(archive.read("release.json"))["signing"], "unsigned")
            self.assertFalse(any("client.json" in name for name in names))

    def test_rejects_changed_or_extra_payload(self):
        (self.payload / "rustdesk.exe").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_rejects_extra_file(self):
        (self.payload / "client.json").write_text("secret")
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
