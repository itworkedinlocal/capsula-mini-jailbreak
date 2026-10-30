#!/usr/bin/env python3
"""Build pinned libusb-compat and libusb 1.x against glibc 2.17."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

from paths import NATIVE, STOCK as HERE, BUILD, SOURCES, ZIG


def main():
    pins = json.loads((HERE / 'host-usb-sources.json').read_text())
    output = BUILD / 'host-usb'; output.mkdir(parents=True, exist_ok=True)
    for name, row in pins['files'].items():
        archive = SOURCES / name
        if archive.stat().st_size != row['bytes'] or hashlib.sha256(archive.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('USB source changed: ' + name)
        with tarfile.open(archive) as source: source.extractall(output, filter='data')
    compiler = output / 'capsula-cc'
    compiler.write_text('#!/bin/sh\nexec "' + str(ZIG) + '" cc -target x86_64-linux-gnu.2.17 "$@"\n')
    compiler.chmod(0o755)
    prefix = output / 'install'
    env = {**os.environ, 'CC': str(compiler), 'AR': 'llvm-ar', 'RANLIB': 'llvm-ranlib',
           'CFLAGS': '-Os -fPIC',
           'ZIG_GLOBAL_CACHE_DIR': str(BUILD / 'zig-cache')}
    modern = output / 'libusb-1.0.30'
    subprocess.run(['./configure', '--host=x86_64-linux-gnu', '--prefix=' + str(prefix),
                    '--disable-static', '--enable-shared', '--disable-udev'], cwd=modern, env=env, check=True)
    subprocess.run(['make', '-j4'], cwd=modern, env=env, check=True)
    subprocess.run(['make', 'install'], cwd=modern, env=env, check=True)
    env.update(PKG_CONFIG_LIBDIR=str(prefix / 'lib/pkgconfig'),
               LD_LIBRARY_PATH=str(prefix / 'lib'), LDFLAGS='-L' + str(prefix / 'lib'))
    compat = output / 'libusb-compat-0.1.9'
    subprocess.run(['./configure', '--host=x86_64-linux-gnu', '--prefix=' + str(prefix),
                    '--disable-static', '--enable-shared'], cwd=compat, env=env, check=True)
    subprocess.run(['make', '-j4'], cwd=compat, env=env, check=True)
    files = {}
    for name, folder in [('libusb-1.0.so.0', modern / 'libusb/.libs'), ('libusb-0.1.so.4', compat / 'libusb/.libs')]:
        source = folder / name
        target = HERE / 'bin/x86_64' / name
        subprocess.run(['llvm-objcopy', '--strip-debug', str(source.resolve(strict=True)), str(target)], check=True)
        target.chmod(0o755)
        files[name] = {'path': 'bin/x86_64/' + name, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'bytes': target.stat().st_size}
    record = {'target': 'x86_64-linux-gnu.2.17', 'backend': 'libusb-compat 0.1.9 + libusb 1.0.30 (no udev dependency)',
              'sources': pins['files'], 'files': files}
    (HERE / 'host-usb.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__': main()
