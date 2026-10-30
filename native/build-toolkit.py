#!/usr/bin/env python3
"""Build a static musl toolkit for Linux 4.9; no device access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from paths import NATIVE, STOCK as HERE, BUILD, SOURCES, ZIG
BUILD = BUILD / 'toolkit'
VERSIONS = {'ncurses': '6.6', 'nano': '9.3', 'htop': '3.5.3',
            'fastfetch': '2.70.0', 'openssh': '10.2p1', 'busybox': '1.37.0',
            'mbedtls': '3.6.7', 'curl': '8.23.0'}
APPLET_NAMES = 'ash awk basename base64 bunzip2 bzcat bzip2 cat chmod chown clear cp cut date df dirname du echo env expr false find free grep groups gunzip gzip head hostname id kill killall less ln ls mkdir mktemp more mv nice nohup od paste printf ps pwd readlink realpath reset rm rmdir sed seq sh sha256sum sha512sum sleep sort stat tail tar tee test time timeout top touch tr true uname uniq unzip uptime wc wget which whoami xargs xz xzcat'.split()
APPLET_NAMES += ['cmp', 'flock', 'mount', 'umount', 'sync', 'stty']


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def run(args, cwd, env, log, input=None):
    with log.open('ab') as stream:
        subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                       stdout=stream, stderr=subprocess.STDOUT, check=True, input=input)


def source(name, pins):
    version = VERSIONS[name]
    row = pins[name]
    archive = SOURCES / row['archive']
    if digest(archive) != row['sha256']:
        raise ValueError('source checksum mismatch: ' + name)
    folder = BUILD / 'sources' / (name + '-' + version)
    if not folder.exists():
        folder.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tar:
            tar.extractall(folder.parent, filter='data')
    return folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['aarch64', 'x86_64', 'all'], default='all')
    parser.add_argument('--only', choices=list(VERSIONS))
    args = parser.parse_args()
    pins = json.loads((HERE / 'toolkit-sources.json').read_text())
    BUILD.mkdir(parents=True, exist_ok=True)
    for arch in (['x86_64', 'aarch64'] if args.arch == 'all' else [args.arch]):
        base = BUILD / arch
        prefix = base / 'prefix'
        output = HERE / 'toolkit' / arch
        for p in (base, prefix, output): p.mkdir(parents=True, exist_ok=True)
        cc = base / 'cc'
        cc.write_text('#!/bin/sh\nexec "' + str(ZIG) + '" cc -target ' + arch + '-linux-musl "$@"\n')
        cc.chmod(0o755)
        env = {**os.environ, 'CC': str(cc), 'AR': 'llvm-ar', 'RANLIB': 'llvm-ranlib',
               'CFLAGS': '-Os', 'LDFLAGS': '-static', 'ZIG_GLOBAL_CACHE_DIR': str(BUILD / 'zig-cache'),
               'PKG_CONFIG_LIBDIR': str(prefix / 'lib/pkgconfig'),
               'CPPFLAGS': '-I' + str(prefix / 'include') + ' -I' + str(prefix / 'include/ncursesw'),
               'LIBS': '', 'SOURCE_DATE_EPOCH': '0', 'ac_cv_func_malloc_0_nonnull': 'yes', 'ac_cv_func_realloc_0_nonnull': 'yes'}
        for name in VERSIONS:
            if args.only and name != args.only: continue
            src = source(name, pins)
            folder = base / name
            folder.mkdir(exist_ok=True)
            log = folder / 'build.log'
            print('Building', name, VERSIONS[name], arch, flush=True)
            if name == 'busybox':
                # Zig's linker rejects GNU diagnostic/map options. Keep all
                # section and static-link flags unchanged.
                link = src / 'scripts/trylink'
                text = link.read_text()
                for flag in ('-Wl,--warn-common', '-Wl,-Map,$EXE.map', '-Wl,--verbose'):
                    text = text.replace(flag, '')
                link.write_text(text)
                # BusyBox requires an out-of-tree Kbuild configuration.
                run(['make', '-C', src, 'O=' + str(folder), 'allnoconfig'], folder, env, log)
                settings = {x: 'y' for x in (
                    'BUSYBOX STATIC LFS LONG_OPTS LARGEFILE UNICODE_SUPPORT UNICODE_USING_LOCALE '
                    'FEATURE_SH_STANDALONE FEATURE_SH_NOFORK FEATURE_PREFER_APPLETS '
                    'SH_IS_ASH ASH ASH_OPTIMIZE_FOR_SIZE ASH_INTERNAL_GLOB ASH_ALIAS '
                    'FEATURE_SH_MATH FEATURE_SH_MATH_64 '
                    'ASH_JOB_CONTROL ASH_PRINTF ASH_ECHO ASH_TEST ASH_GETOPTS ASH_CMDCMD '
                    'ASH_BASH_COMPAT ASH_EXPAND_PRMT FEATURE_EDITING FEATURE_EDITING_FANCY_PROMPT '
                    'FEATURE_TAB_COMPLETION FEATURE_USERNAME_COMPLETION FEATURE_EDITING_WINCH '
                    'FEATURE_LESS_MAXLINES FEATURE_LESS_REGEXP FEATURE_FIND_PRINT0 FEATURE_FIND_TYPE '
                    'FEATURE_FIND_NAME FEATURE_FIND_PATH FEATURE_FIND_EXEC FEATURE_FIND_EXEC_PLUS '
                    'FEATURE_FIND_DELETE FEATURE_STAT_FORMAT FEATURE_TAR_CREATE FEATURE_TAR_GNU_EXTENSIONS '
                    'FEATURE_TAR_LONG_OPTIONS FEATURE_TAR_AUTODETECT FEATURE_SEAMLESS_GZ '
                    'FEATURE_SEAMLESS_BZ2 FEATURE_SEAMLESS_XZ FEATURE_VERBOSE_USAGE SHOW_USAGE '
                    'FEATURE_TOP_CPU_USAGE_PERCENTAGE FEATURE_TOP_CPU_GLOBAL_PERCENTS '
                    'FEATURE_MOUNT_FLAGS '
                    'FEATURE_WGET_HTTPS TLS FEATURE_WGET_LONG_OPTIONS FEATURE_WGET_STATUSBAR'
                ).split()}
                settings.update({x.upper(): 'y' for x in APPLET_NAMES if x != 'sh'})
                settings.update({'FEATURE_EDITING_HISTORY': '256', 'FEATURE_EDITING_SAVEHISTORY': 'y',
                                 'FEATURE_EDITING_SAVE_ON_EXIT': 'y', 'SUBST_WCHAR': '0',
                                 'LAST_SUPPORTED_WCHAR': '1114111'})
                config = folder / '.config'
                lines = config.read_text().splitlines()
                for i, line in enumerate(lines):
                    key = line.removeprefix('# ').split('=', 1)[0].split(' ', 1)[0].removeprefix('CONFIG_')
                    if key in settings: lines[i] = 'CONFIG_' + key + '=' + settings[key]
                config.write_text('\n'.join(lines) + '\n')
                run(['make', '-C', src, 'O=' + str(folder), 'oldconfig'], folder, {**env, 'KCONFIG_NOTIMESTAMP': '1'}, log, input=b'\n' * 16384)
                run(['make', '-C', src, 'O=' + str(folder), '-j8', 'CC=' + str(cc), 'AR=llvm-ar',
                     # BusyBox documents this switch in include/libbb.h. LLVM
                     # can hoist the load of its nominally const globals before
                     # INIT_G stores the allocated pointer (ARM awk SIGSEGV).
                     'STRIP=llvm-strip', 'EXTRA_CFLAGS=-Os -DBB_GLOBAL_CONST='], folder, env, log)
                shutil.copy2(folder / 'busybox', output / 'busybox')
            elif name == 'mbedtls':
                run(['cmake', '-S', src, '-B', folder, '-DCMAKE_SYSTEM_NAME=Linux',
                     '-DCMAKE_SYSTEM_PROCESSOR=' + arch, '-DCMAKE_C_COMPILER=' + str(cc),
                     '-DCMAKE_BUILD_TYPE=MinSizeRel', '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
                     '-DCMAKE_LINK_DEPENDS_USE_LINKER=OFF', '-DENABLE_TESTING=OFF',
                     '-DENABLE_PROGRAMS=OFF', '-DUSE_SHARED_MBEDTLS_LIBRARY=OFF',
                     '-DUSE_STATIC_MBEDTLS_LIBRARY=ON'], folder, env, log)
                run(['cmake', '--build', folder, '-j8'], folder, env, log)
                run(['cmake', '--install', folder], folder, env, log)
            elif name == 'curl':
                run([src / 'configure', '--host=' + arch + '-linux-musl',
                     '--prefix=' + str(prefix), '--disable-shared', '--enable-static',
                     '--with-mbedtls=' + str(prefix), '--without-openssl',
                     '--without-libpsl', '--without-libidn2', '--without-libssh2',
                     '--without-nghttp2', '--without-nghttp3', '--without-zlib',
                     '--without-zstd', '--without-brotli', '--disable-ldap', '--disable-ldaps',
                     '--disable-rtsp', '--disable-dict', '--disable-telnet', '--disable-tftp',
                     '--disable-pop3', '--disable-imap', '--disable-smtp', '--disable-gopher',
                     '--disable-smb', '--disable-mqtt', '--disable-manual',
                     '--with-ca-bundle=/usr/lib/capsula-root/entware-bootstrap/cacert.pem',
                     '--without-ca-path'], folder, env, log)
                run(['make', '-j8'], folder, env, log)
                shutil.copy2(folder / 'src/curl', output / 'curl')
            elif name == 'fastfetch':
                cmake_source = src / 'CMakeLists.txt'
                text = cmake_source.read_text()
                if '-Wl,--copy-dt-needed-entries' in text:
                    cmake_source.write_text(text.replace('-Wl,--copy-dt-needed-entries', ''))
                run(['cmake', '-S', src, '-B', folder, '-DCMAKE_SYSTEM_NAME=Linux',
                     '-DCMAKE_SYSTEM_PROCESSOR=' + arch, '-DCMAKE_C_COMPILER=' + str(cc),
                     '-DCMAKE_BUILD_TYPE=MinSizeRel', '-DBINARY_LINK_TYPE=static', '-DIS_MUSL=ON',
                     '-DCMAKE_C_FLAGS=-Wno-error=date-time',
                     '-DCMAKE_LINK_DEPENDS_USE_LINKER=OFF',
                     '-DCMAKE_EXE_LINKER_FLAGS=-static', '-DENABLE_THREADS=OFF', '-DENABLE_LUA=OFF',
                     '-DENABLE_QUICKJS=OFF', '-DENABLE_IMAGE_LOGO=OFF', '-DENABLE_ZLIB=OFF',
                     '-DBUILD_FLASHFETCH=OFF', '-DENABLE_WORDEXP=OFF', '-DENABLE_LIBZFS=OFF',
                     '-DENABLE_VULKAN=OFF', '-DENABLE_OPENCL=OFF', '-DENABLE_DRM=OFF',
                     '-DENABLE_DBUS=OFF', '-DENABLE_PULSE=OFF', '-DENABLE_GIO=OFF',
                     '-DENABLE_WAYLAND=OFF', '-DENABLE_XCB_RANDR=OFF', '-DENABLE_XRANDR=OFF',
                     '-DENABLE_SQLITE3=OFF', '-DENABLE_RPM=OFF'], folder, env, log)
                run(['cmake', '--build', folder, '--target', 'fastfetch', '-j8'], folder, env, log)
                shutil.copy2(folder / 'fastfetch', output / 'fastfetch')
            else:
                options = ['--host=' + arch + '-linux-musl', '--prefix=' + str(prefix), '--disable-nls']
                if name == 'ncurses':
                    options += ['--with-normal', '--without-shared', '--enable-widec', '--without-cxx',
                                '--without-cxx-binding', '--without-ada', '--without-manpages',
                                '--without-tests', '--without-progs', '--disable-db-install',
                                '--with-terminfo-dirs=/usr/lib/capsula-root/terminfo:/usr/share/terminfo',
                                '--with-default-terminfo-dir=/usr/lib/capsula-root/terminfo']
                elif name == 'nano':
                    options += ['--enable-utf8', '--disable-libmagic', '--disable-speller']
                elif name == 'htop':
                    options += ['--enable-static', '--disable-sensors', '--disable-capabilities',
                                '--disable-hwloc', '--disable-delayacct', '--disable-unwind', '--disable-backtrace']
                elif name == 'openssh':
                    options += ['--without-openssl', '--without-zlib', '--without-pam', '--without-selinux',
                                '--without-libedit', '--without-zstd', '--without-kerberos5']
                localenv = {**env, 'LDFLAGS': '-static -L' + str(prefix / 'lib')}
                if name in ('nano', 'htop'):
                    localenv['NCURSES_CFLAGS'] = env['CPPFLAGS']
                    localenv['NCURSES_LIBS'] = '-L' + str(prefix / 'lib') + ' -lncursesw'
                run([src / 'configure', *options], folder, localenv, log)
                run(['make', '-j8', *(['sftp-server'] if name == 'openssh' else [])], folder, localenv, log)
                if name == 'ncurses':
                    run(['make', 'install.libs', 'install.includes'], folder, localenv, log)
                else:
                    binary = {'nano': 'src/nano', 'htop': 'htop', 'openssh': 'sftp-server'}[name]
                    shutil.copy2(folder / binary, output / Path(binary).name)
            if name not in ('ncurses', 'mbedtls'):
                target = output / ('sftp-server' if name == 'openssh' else name)
                run(['llvm-strip', target], folder, env, log)
                target.chmod(0o755)
            license_path = next((src / p for p in ('COPYING', 'LICENSE', 'LICENCE', 'COPYING.txt') if (src / p).is_file()), None)
            if license_path:
                licenses = output / 'licenses'
                licenses.mkdir(exist_ok=True)
                shutil.copy2(license_path, licenses / (name + '.txt'))
        # Terminfo is platform-independent compiled data, included for modern clients.
        terminfo = output / 'terminfo'
        terminfo.mkdir(exist_ok=True)
        for term in ('xterm', 'xterm-256color', 'screen', 'screen-256color', 'tmux', 'tmux-256color', 'linux', 'vt100', 'ansi', 'dumb', 'xterm-kitty', 'alacritty'):
            result = subprocess.run(['infocmp', '-x', term], capture_output=True)
            if result.returncode: continue
            subprocess.run(['tic', '-x', '-o', str(terminfo), '-'], input=result.stdout, check=True)
        tables = base / 'busybox/include/applet_tables.h'
        applets = re.findall(r'^"([^"\\]+)" "\\0"$', tables.read_text(), re.M) if tables.exists() else []
        if (output / 'busybox').exists() and not set(APPLET_NAMES).issubset(applets):
            raise ValueError('BusyBox applets missing: ' + ', '.join(sorted(set(APPLET_NAMES) - set(applets))))
        required = {'busybox', 'nano', 'htop', 'fastfetch', 'sftp-server', 'curl'}
        record = {'schema_version': 2, 'architecture': arch, 'static_musl': True,
                  'busybox_compiler_flags': '-Os -DBB_GLOBAL_CONST=',
                  'complete': all((output / name).is_file() for name in required),
                  'applets': APPLET_NAMES if applets else [], 'versions': VERSIONS,
                  'files': {str(p.relative_to(output)): {'sha256': digest(p), 'bytes': p.stat().st_size,
                            'mode': 0o755 if p.parent == output else 0o644}
                            for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'manifest.json'}}
        (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
        print('Toolkit ready:', output, flush=True)


if __name__ == '__main__': main()
