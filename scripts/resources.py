#!/usr/bin/env python3
"""Verify checksum-pinned runtime resources included in the repository."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'resources.lock.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory():
    record = json.loads(LOCK.read_text())
    if record['schema_version'] != 1 or not record['files']:
        raise ValueError('invalid resources.lock.json')
    for name, row in record['files'].items():
        p = Path(name)
        if (not name.startswith('resources/') or p.is_absolute() or
                '..' in p.parts or '\\' in name or p.as_posix() != name or
                row['mode'] not in (0o644, 0o755) or not 0 < row['bytes'] <= 64 << 20):
            raise ValueError('invalid resource record: ' + name)
    return record


def checked_file(root, name, row):
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing regular resource: ' + name)
    if path.resolve() != root.resolve().joinpath(name):
        raise ValueError('symlink in resource path: ' + name)
    if path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
        raise ValueError('resource checksum mismatch: ' + name)
    return path


def check_resources(root=None):
    root = ROOT if root is None else root
    record = inventory()
    for name, row in record['files'].items():
        checked_file(root, name, row)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify all runtime resources')
    parser.parse_args()
    print('Verified', len(check_resources()['files']), 'runtime resources')


if __name__ == '__main__':
    main()
