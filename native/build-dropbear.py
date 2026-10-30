#!/usr/bin/env python3
"""Build password-auth Dropbear for ARM64 and an isolated native test."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from paths import NATIVE, STOCK as HERE, BUILD, SOURCES, ZIG
SOURCE = BUILD / "dropbear-password-source"
OPTIONS = """/* Capsule root SSH: password authentication and private SFTP server. */
#define DROPBEAR_SVR_PASSWORD_AUTH 1
#define DROPBEAR_SVR_PUBKEY_AUTH 0
#define DROPBEAR_SK_ECDSA 0
#define DROPBEAR_SK_ED25519 0
#define DROPBEAR_SFTPSERVER 1
#define SFTPSERVER_PATH "/usr/lib/capsula-root/sftp-server"
#define DEFAULT_ROOT_PATH "/usr/lib/capsula-root/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define DO_MOTD 0
"""


def main():
    checks = {
        "dropbear-2026.94.tar.bz2": "e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81",
        "zig-0.15.2-x86_64.tar.xz": "02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239",
    }
    for name, expected in checks.items():
        with (SOURCES / name).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError("source hash mismatch: " + name)
    # Upstream hides this declaration when public-key login is disabled,
    # although dropbearkey still uses the always-built fingerprint function.
    shutil.copytree(SOURCES / "dropbear-2026.94", SOURCE, dirs_exist_ok=True)
    header = SOURCE / "src/signkey.h"
    original = header.read_text()
    declaration = "char * sign_key_fingerprint(const unsigned char* keyblob, unsigned int keybloblen);"
    if original.count(declaration) != 1:
        raise ValueError("unrecognized Dropbear fingerprint declaration")
    header.write_text(original.replace(declaration + "\n#endif", "#endif\n" + declaration))
    bounds = SOURCE / 'src/sysoptions.h'
    text = bounds.read_text()
    if text.count('#define DROPBEAR_MAX_PASSWORD_LEN 100') != 1: raise ValueError('unrecognized password bound')
    bounds.write_text(text.replace('#define DROPBEAR_MAX_PASSWORD_LEN 100', '#define DROPBEAR_MAX_PASSWORD_LEN 512'))
    shutil.copy2(NATIVE / 'sha512-crypt.c', SOURCE / 'src/capsula-sha512.c')
    auth = SOURCE / 'src/svr-authpasswd.c'
    text = auth.read_text()
    old = 'testcrypt = crypt(password, passwdcrypt);'
    if text.count(old) != 1: raise ValueError('unrecognized password verifier')
    text = text.replace('#if DROPBEAR_SVR_PASSWORD_AUTH', '#if DROPBEAR_SVR_PASSWORD_AUTH\n#include "capsula-sha512.c"', 1)
    text = text.replace('char * testcrypt = NULL;', 'char capsula_crypt_output[128];\n\tchar * testcrypt = NULL;', 1)
    text = text.replace('valid_user && passwordlen <= DROPBEAR_MAX_PASSWORD_LEN',
                        "valid_user && passwordlen > 0 && passwordlen <= DROPBEAR_MAX_PASSWORD_LEN && !memchr(password, 0, passwordlen) && !memchr(password, '\\r', passwordlen) && !memchr(password, '\\n', passwordlen)")
    auth.write_text(text.replace(old, 'testcrypt = strncmp(passwdcrypt, "$6$", 3) ? NULL : capsula_sha512_crypt(password, passwdcrypt, capsula_crypt_output);'))
    records = {}
    for machine in ("aarch64", "x86_64"):
        folder = BUILD / ("dropbear-" + machine)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "localoptions.h").write_text(OPTIONS)
        wrapper = folder / "capsula-cc"
        wrapper.write_text('#!/bin/sh\nexec "' + str(ZIG) + '" cc -target ' + machine + '-linux-musl "$@"\n')
        wrapper.chmod(0o755)
        env = {**os.environ, "CC": str(wrapper), "AR": "llvm-ar", "RANLIB": "llvm-ranlib",
               "ZIG_GLOBAL_CACHE_DIR": str(BUILD / "zig-cache"), "CFLAGS": "-Os"}
        arguments = [str(SOURCE / "configure"), "--host=" + machine + "-linux-musl", "--enable-static",
                     "--disable-zlib", "--disable-lastlog", "--disable-utmp", "--disable-utmpx",
                     "--disable-wtmp", "--disable-wtmpx"]
        print("Configuring", machine, flush=True)
        with (folder / "configure-output.log").open("wb") as log:
            if (folder / "Makefile").exists():
                subprocess.run(["make", "clean"], cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            subprocess.run(arguments, cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        print("Building", machine, flush=True)
        with (folder / "make-output.log").open("wb") as log:
            subprocess.run(["make", "-j8", "PROGRAMS=dropbear dropbearkey", "MULTI=1"],
                           cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        output = HERE / "bin" / machine / "dropbearmulti"
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["llvm-objcopy", "--strip-debug", str(folder / "dropbearmulti"), str(output)], check=True)
        output.chmod(0o755)
        data = output.read_bytes()
        records[machine] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                            "target": machine + "-linux-musl", "static": True, "version": "2026.94"}
        print("Built", output, len(data), "bytes", flush=True)
    (HERE / "dropbear-build.json").write_text(json.dumps({"options": OPTIONS, "binaries": records,
        'password_max_utf8_bytes': 512, 'sha512_crypt_source_sha256': hashlib.sha256((NATIVE / 'sha512-crypt.c').read_bytes()).hexdigest()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
