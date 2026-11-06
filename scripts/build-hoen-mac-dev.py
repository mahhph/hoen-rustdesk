#!/usr/bin/env python3
"""Build a separate, locally signed macOS trial app without installing a service."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
FLUTTER = ROOT / 'flutter'
BACKUPS = ROOT / 'target' / 'hoen-mac-dev-builds'
APP_NAME = 'HoenRemoteDev'
BUNDLE_ID = 'com.hoensolutions.hoenremote.dev'
FEATURES = 'flutter,hwcodec,unix-file-copy-paste,screencapturekit,hoen-mac-dev'


def run(args, *, cwd=ROOT, env=None):
    print('+', ' '.join(str(arg) for arg in args), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def settings_files():
    config = FLUTTER / 'macos/Runner/Configs/AppInfo.xcconfig'
    project = FLUTTER / 'macos/Runner.xcodeproj/project.pbxproj'
    return {
        config: ('PRODUCT_NAME = RustDesk', f'PRODUCT_NAME = {APP_NAME}'),
        project: ('PRODUCT_BUNDLE_IDENTIFIER = com.carriez.rustdesk;',
                  f'PRODUCT_BUNDLE_IDENTIFIER = {BUNDLE_ID};'),
    }


def build():
    if sys.platform != 'darwin':
        raise RuntimeError('This development build requires macOS.')
    originals = {path: path.read_bytes() for path in settings_files()}
    modified = {}
    for path, (old, new) in settings_files().items():
        original = originals[path]
        if old.encode() not in original:
            raise RuntimeError(f'Expected Xcode setting not found in {path}; nothing changed.')
        modified[path] = original.replace(old.encode(), new.encode())
    BACKUPS.mkdir(parents=True, exist_ok=True)
    backup_dir = BACKUPS / uuid.uuid4().hex
    backup_dir.mkdir(mode=0o700)
    for index, path in enumerate(settings_files()):
        destination = backup_dir / f'{index}.original'
        destination.write_bytes(originals[path])
        destination.chmod(0o600)
    env = os.environ.copy()
    env['MACOSX_DEPLOYMENT_TARGET'] = '12.3'
    env.setdefault('CARGO_PROFILE_RELEASE_LTO', 'false')
    env['FLUTTER_XCODE_ARCHS'] = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x86_64'
    env['FLUTTER_XCODE_ONLY_ACTIVE_ARCH'] = 'YES'
    env['FLUTTER_XCODE_MACOSX_DEPLOYMENT_TARGET'] = '12.3'
    env.pop('FLUTTER_XCODE_PRODUCT_NAME', None)
    env.pop('FLUTTER_XCODE_PRODUCT_BUNDLE_IDENTIFIER', None)
    run(['cargo', 'build', '--locked', '--release', '--features', FEATURES], env=env)
    shutil.copy2(ROOT / 'target/release/liblibrustdesk.dylib', ROOT / 'target/release/librustdesk.dylib')
    restore_failed = False
    try:
        for path in modified:
            if path.read_bytes() != originals[path]:
                raise RuntimeError(f'Xcode file changed before the app build: {path}')
            path.write_bytes(modified[path])
        run(['flutter', 'build', 'macos', '--release', '--no-pub'], cwd=FLUTTER, env=env)
    finally:
        for path in modified:
            current = path.read_bytes()
            if current == modified[path]:
                path.write_bytes(originals[path])
            elif current == originals[path]:
                continue
            else:
                restore_failed = True
                print(f'Xcode file changed during build; not overwriting it: {path}', file=sys.stderr)
        if restore_failed:
            raise RuntimeError(f'Compare the changed files with the saved originals in {backup_dir}.')
    app = FLUTTER / f'build/macos/Build/Products/Release/{APP_NAME}.app'
    plist = app / 'Contents/Info.plist'
    actual = subprocess.check_output(['/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleIdentifier', str(plist)], text=True).strip()
    if actual != BUNDLE_ID:
        raise RuntimeError('Trial bundle identifier was not applied; refusing to sign or run it.')
    shutil.copy2(ROOT / 'target/release/service', app / 'Contents/MacOS/service')
    # Local development has no Developer ID identity. Keep app entitlements but do not
    # retain hardened-runtime flags, which require matching signed framework identities.
    run(['codesign', '--force', '--deep', '--sign', '-', '--preserve-metadata=entitlements', str(app)])
    run(['codesign', '--verify', '--deep', '--strict', str(app)])
    print(f'Development app: {app}\nSaved Xcode originals: {backup_dir}', flush=True)


if __name__ == '__main__':
    try:
        build()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'Development build failed: {error}', file=sys.stderr)
        sys.exit(1)
