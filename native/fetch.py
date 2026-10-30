#!/usr/bin/env python3
"""Download checksum-pinned public inputs for optional native rebuilds."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

from paths import NATIVE, SOURCES, TOOLS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('groups', nargs='+', choices=['toolchain', 'dropbear', 'toolkit', 'usb', 'ramboot', 'all'])
    args = parser.parse_args()
    pins = json.loads((NATIVE / 'sources.lock.json').read_text())
    SOURCES.mkdir(parents=True, exist_ok=True)
    for name, row in pins['files'].items():
        if 'all' not in args.groups and row['group'] not in args.groups:
            continue
        target = SOURCES / name
        if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != row['sha256']:
            request = urllib.request.Request(row['url'], headers={'User-Agent': 'capsula-build'})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('source checksum mismatch: ' + name)
            target.write_bytes(data)
        if row['group'] == 'toolchain':
            TOOLS.mkdir(parents=True, exist_ok=True)
            with tarfile.open(target) as archive:
                archive.extractall(TOOLS, filter='data')
        elif row['group'] == 'dropbear':
            with tarfile.open(target) as archive:
                archive.extractall(SOURCES, filter='data')
        print('Verified', name)


if __name__ == '__main__':
    main()
