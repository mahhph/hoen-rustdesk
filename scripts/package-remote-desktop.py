"""Create an unsigned Windows release bundle from a separately reviewed payload."""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = (
    "remote-desktop-setup.ps1", "remote-desktop-service-installer.ps1",
    "remote-desktop-bootstrap.ps1", "remote-desktop-firewall.ps1",
    "remote-desktop-upgrade.ps1", "remote-desktop-upgrade-flow.ps1",
)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def package(payload, manifest_path, output, revision):
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("Payload revision must be a full lowercase Git commit ID")
    payload = payload.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if (manifest.get("schema"), manifest.get("product"), manifest.get("serviceName")) != (1, "Remote Desktop Service", "RemoteDesktopService"):
        raise ValueError("Unexpected payload manifest")
    expected = {}
    for item in manifest["files"]:
        name = item["path"]
        path = PureWindowsPath(name)
        if path.is_absolute() or path.drive or any(p in (".", "..") for p in path.parts) or ":" in name or "/" in name:
            raise ValueError("Invalid manifest path")
        key = name.lower()
        if key in expected:
            raise ValueError("Duplicate manifest path")
        expected[key] = (name, item["size"], item["sha256"])
    if not {"rustdesk.exe", "librustdesk.dll", "flutter_windows.dll"} <= expected.keys():
        raise ValueError("Required payload files are missing")
    actual = {}
    for path in payload.rglob("*"):
        if path.is_symlink() or getattr(path.stat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Reparse points are not allowed in the payload")
        if path.is_file():
            name = str(PureWindowsPath(*path.relative_to(payload).parts))
            actual[name.lower()] = (name, path)
    if actual.keys() != expected.keys():
        raise ValueError("Payload files differ from the reviewed manifest")
    for key, (name, path) in actual.items():
        expected_name, size, sha = expected[key]
        if name != expected_name or path.stat().st_size != size or digest(path) != sha:
            raise ValueError(f"Payload mismatch: {name}")
    if output.exists():
        raise ValueError("Output already exists")
    if output.resolve().is_relative_to(payload):
        raise ValueError("Output must be outside the payload")
    metadata = {"format": 1, "product": "Remote Desktop", "payload_source_revision": revision,
                "signing": "unsigned", "note": "The revision is supplied by the packager and is not independently verified."}
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for _, (name, path) in sorted(actual.items()):
            archive.write(path, "payload/" + name.replace("\\", "/"))
        archive.writestr("payload-manifest.json", manifest_path.read_bytes())
        archive.writestr("release.json", json.dumps(metadata, indent=2) + "\n")
        for name in SCRIPTS:
            archive.write(ROOT / "scripts" / name, "scripts/" + name)
        archive.write(ROOT / "docs" / "WINDOWS-RELEASE-BUNDLE.md", "README.md")
        archive.write(ROOT / "docs" / "INSTALLER-TEST-GUIDE.md", "INSTALLER-TEST-GUIDE.md")
        archive.write(ROOT / "LICENCE", "LICENCE")
    return digest(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--payload-revision", required=True)
    args = parser.parse_args()
    print(f"SHA-256 {package(args.payload, args.manifest, args.output, args.payload_revision)}")


if __name__ == "__main__":
    main()
