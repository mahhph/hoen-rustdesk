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


def arm64_flutter_files():
    """Prepare the same Flutter 3.44 changes used by CI without editing source yet."""
    common = FLUTTER / 'lib/common.dart'
    pubspec = FLUTTER / 'pubspec.yaml'
    lock = FLUTTER / 'pubspec.lock'
    mac_lock = FLUTTER / 'pubspec.macos-arm64.lock'
    originals = {path: path.read_bytes() for path in (common, pubspec, lock)}
    theme = originals[common]
    dialog = b'dialogTheme: DialogTheme('
    tabs = b'tabBarTheme: const TabBarTheme('
    light = theme.find(b'static ThemeData lightTheme = ThemeData(')
    dark = theme.find(b'static ThemeData darkTheme = ThemeData(')
    if (theme.count(dialog) != 2 or theme.count(tabs) != 2 or light < 0 or dark <= light
            or theme[light:dark].count(dialog) != 1 or theme[dark:].count(dialog) != 1):
        raise RuntimeError('Flutter theme compatibility anchors changed; nothing changed.')
    theme = theme.replace(dialog, b'dialogTheme: DialogThemeData(\n      backgroundColor: Colors.white,', 1)
    theme = theme.replace(dialog, b'dialogTheme: DialogThemeData(\n      backgroundColor: Color(0xFF18191E),', 1)
    theme = theme.replace(tabs, b'tabBarTheme: const TabBarThemeData(')
    spec = originals[pubspec]
    for old, new in ((b'extended_text: 14.0.0', b'extended_text: 15.0.2'),
                     (b'google_fonts: ^6.2.1', b'google_fonts: ^8.1.0')):
        if spec.count(old) != 1:
            raise RuntimeError('Flutter dependency compatibility anchors changed; nothing changed.')
        spec = spec.replace(old, new)
    return originals, {common: theme, pubspec: spec, lock: mac_lock.read_bytes()}


def build():
    if sys.platform != 'darwin':
        raise RuntimeError('This development build requires macOS.')
    icon = FLUTTER / 'macos/Runner/AppIcon.icns'
    dev_icon = FLUTTER / 'macos/Runner/HoenRemoteDev.icns'
    originals = {path: path.read_bytes() for path in (*settings_files(), icon)}
    modified = {}
    for path, (old, new) in settings_files().items():
        original = originals[path]
        if old.encode() not in original:
            raise RuntimeError(f'Expected Xcode setting not found in {path}; nothing changed.')
        modified[path] = original.replace(old.encode(), new.encode())
    modified[icon] = dev_icon.read_bytes()
    arm64 = platform.machine().lower() in ('arm64', 'aarch64')
    if arm64:
        flutter_originals, flutter_modified = arm64_flutter_files()
        originals.update(flutter_originals)
        modified.update(flutter_modified)
    BACKUPS.mkdir(parents=True, exist_ok=True)
    backup_dir = BACKUPS / uuid.uuid4().hex
    backup_dir.mkdir(mode=0o700)
    for index, path in enumerate(originals):
        destination = backup_dir / f'{index}.original'
        destination.write_bytes(originals[path])
        destination.chmod(0o600)
    env = os.environ.copy()
    env['MACOSX_DEPLOYMENT_TARGET'] = '12.3'
    env.setdefault('CARGO_PROFILE_RELEASE_LTO', 'false')
    env['FLUTTER_XCODE_ARCHS'] = 'arm64' if arm64 else 'x86_64'
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
                raise RuntimeError(f'Build input changed before the app build: {path}')
            path.write_bytes(modified[path])
        if arm64:
            run(['flutter', 'pub', 'get', '--enforce-lockfile'], cwd=FLUTTER, env=env)
            if (FLUTTER / 'pubspec.lock').read_bytes() != modified[FLUTTER / 'pubspec.lock']:
                raise RuntimeError('Mac dependency lockfile changed during resolution.')
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
                print(f'Build input changed during build; not overwriting it: {path}', file=sys.stderr)
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
    print(f'Development app: {app}\nSaved build originals: {backup_dir}', flush=True)


if __name__ == '__main__':
    try:
        build()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'Development build failed: {error}', file=sys.stderr)
        sys.exit(1)
