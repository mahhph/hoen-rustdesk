#!/usr/bin/env python3
"""Prepare, but never install or start, a logged-in-user development host agent."""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess

LABEL = 'com.hoensolutions.hoenremote.host'
BUNDLE_ID = 'com.hoensolutions.hoenremote.dev'


def agent_for(app: Path) -> dict:
    if not app.is_absolute() or app.is_symlink() or not app.is_dir():
        raise ValueError('app must be an existing absolute, non-symlink bundle path')
    app = app.resolve(strict=True)
    with (app / 'Contents/Info.plist').open('rb') as source:
        info = plistlib.load(source)
    if info.get('CFBundleIdentifier') != BUNDLE_ID or info.get('CFBundleExecutable') != 'HoenRemoteDev':
        raise ValueError('not the expected HoenRemoteDev bundle')
    executable = app / 'Contents/MacOS/HoenRemoteDev'
    if executable.is_symlink() or not executable.is_file():
        raise ValueError('expected host executable is missing or a symlink')
    return {'Label': LABEL, 'ProgramArguments': [str(executable), '--server'],
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 15,
            'LimitLoadToSessionType': 'Aqua'}


def write_new(path: Path, data: dict) -> None:
    if not path.is_absolute():
        raise ValueError('output must be an absolute path')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        plistlib.dump(data, output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = agent_for(args.app)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(args.app)], check=True)
    write_new(args.output, data)
    print(f'Prepared {args.output}. No service was installed or started.')


if __name__ == '__main__':
    main()
