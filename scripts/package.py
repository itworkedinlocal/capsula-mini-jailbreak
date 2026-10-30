#!/usr/bin/env python3
"""Build a distributable archive from public sources and pinned resources."""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from resources import ROOT, check_resources, digest


def build_release(platform):
    resources = check_resources()
    windows = platform == 'windows'
    subprocess.run(['make', 'build-windows' if windows else 'build'], cwd=ROOT, check=True)
    version = re.search(r'const Version = "([^"]+)"', (ROOT / 'internal/capsula/policy.go').read_text())[1]
    name = 'capsula-' + version + '-' + platform + '-x86_64'
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    binary = 'capsula.exe' if windows else 'capsula'
    common = ['resources/fastfetch.jsonc']
    common += ['resources/ramboot/' + n for n in ('Image', 'vk-mini-a113x-usb-only.dtb', 'initramfs.cpio.gz', 'ramboot-manifest.json', 'init')]
    common += ['resources/stock-root/' + n for n in ('dropbear-build.json', 'helpers-build.json', 'entware-sources.json', 'toolkit-sources.json', 'persist-control', 'overlay-install', 'inspect-stock', 'inspect-device', 'runtime-policy')]
    common += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'resources/stock-root/payload').iterdir()) if p.is_file()]
    for member in resources['files']:
        if member.startswith(('resources/stock-root/toolkit/', 'resources/stock-root/sources/', 'resources/stock-root/bin/aarch64/')):
            common.append(member)
    if windows:
        common += ['resources/stock-root/host-windows.json', 'resources/stock-root/bin/windows-x86_64/password-hash.exe']
    else:
        common += ['resources/update', 'resources/stock-root/host-usb.json', 'resources/stock-root/host-usb-sources.json']
        common += [n for n in resources['files'] if n.startswith('resources/stock-root/bin/x86_64/')]
        common += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'udev').iterdir()) if p.is_file()]
    common += ['LICENSE', 'THIRD_PARTY.md']
    common += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'licenses').rglob('*')) if p.is_file()]
    with tempfile.TemporaryDirectory(prefix='package-', dir=ROOT / 'build') as temp:
        stage = Path(temp) / name
        stage.mkdir()

        def copy(source, member):
            if source.is_symlink() or not source.is_file():
                raise ValueError('not a regular release input: ' + str(source))
            target = stage / member
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)

        copy(ROOT / 'build' / binary, binary)
        copy(ROOT / 'docs' / ('windows.md' if windows else 'linux.md'), 'README.md')
        for member in sorted(set(common)):
            copy(ROOT / member, member)
        if not windows:
            subprocess.run([str(stage / binary), 'diagnose', '--offline'], cwd=temp, check=True)
        manifest = {'version': version, 'channel': 'release-candidate' if '-rc' in version else 'stable',
                    'runtime': 'Go, CGO_ENABLED=0', 'system_python_required': False,
                    'hardware_tested': False, 'runtime_tested': False,
                    'target': 'Windows 10/11 x86_64' if windows else 'GNU/Linux x86_64', 'files': {}}
        for source in sorted(stage.rglob('*')):
            if source.is_file():
                manifest['files'][source.relative_to(stage).as_posix()] = {
                    'bytes': source.stat().st_size, 'sha256': digest(source), 'mode': source.stat().st_mode & 0o777}
        (stage / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        target = dist / (name + ('.zip' if windows else '.tar.gz'))
        if target.exists():
            previous = dist / 'candidates' / digest(target)[:12]
            previous.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, previous / target.name)
        if windows:
            with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for source in sorted(stage.rglob('*')):
                    if source.is_file():
                        info = zipfile.ZipInfo(name + '/' + source.relative_to(stage).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = (source.stat().st_mode & 0xffff) << 16
                        archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        else:
            with target.open('wb') as stream, gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=0, compresslevel=6) as zipped:
                with tarfile.open(fileobj=zipped, mode='w|') as archive:
                    for source in sorted(stage.rglob('*')):
                        if source.is_file():
                            info = archive.gettarinfo(str(source), name + '/' + source.relative_to(stage).as_posix())
                            info.uid = info.gid = info.mtime = 0
                            info.uname = info.gname = ''
                            with source.open('rb') as content:
                                archive.addfile(info, content)
        checksum = digest(target)
        (dist / (name + '.sha256')).write_text(checksum + '  ' + target.name + '\n')
        print(json.dumps({'archive': 'dist/' + target.name, 'sha256': checksum, 'files': len(manifest['files']),
                          'hardware_tested': False, 'windows_runtime_tested': False}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=['linux', 'windows'], default='linux')
    build_release(parser.parse_args().target)


if __name__ == '__main__':
    main()
