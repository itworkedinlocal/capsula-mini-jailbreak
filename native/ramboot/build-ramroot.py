#!/usr/bin/env python3
"""Build a minimal RAM-only USB console, without communicating with hardware."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import zlib
import sys

from fdt import Fdt, usb_only_targets

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from paths import ROOT, SOURCES

HERE = ROOT / 'resources/ramboot'
ALPINE = "alpine-minirootfs-3.24.3-aarch64.tar.gz"
PINNED = {
    "Image": "7a155fcd0fbab5af149094f408e3bbb2209d478e4adac924659cd2b049014226",
    "vk-mini-a113x.dtb": "aa02c59464db78f777d6168156aeebc8481d98f768ee82da5b9cb6f55ca2e36c",
    ALPINE: "4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50",
}


def add_entry(stream, inode, name, mode, content=b"", rdev=(0, 0)):
    encoded = name.encode() + b"\0"
    fields = [inode, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
              len(content), 0, 0, rdev[0], rdev[1], len(encoded), 0]
    header = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
    stream.write(header + encoded)
    stream.write(b"\0" * (-(len(header) + len(encoded)) % 4))
    stream.write(content)
    stream.write(b"\0" * (-len(content) % 4))


def main():
    inputs = {name: (HERE if name == 'Image' else SOURCES) / name for name in PINNED}
    HERE.mkdir(parents=True, exist_ok=True)
    if not (HERE / 'Image').exists() and (SOURCES / 'Image').exists():
        import shutil
        shutil.copyfile(SOURCES / 'Image', HERE / 'Image')
    for name, expected in PINNED.items():
        if hashlib.sha256(inputs[name].read_bytes()).hexdigest() != expected:
            raise ValueError("input SHA256 mismatch: " + name)
    image = (HERE / "Image").read_bytes()
    if image[56:60] != b"ARM\x64" or struct.unpack_from("<Q", image, 8)[0] != 0x1080000:
        raise ValueError("kernel header not prepared for this U-Boot")
    tree = Fdt.read(inputs["vk-mini-a113x.dtb"].read_bytes())
    targets = usb_only_targets(tree)
    for path in targets:
        tree.nodes[path]["status"] = b"disabled\0"
    dtb = tree.write()
    parsed = Fdt.read(dtb)
    if parsed.nodes != tree.nodes or parsed.reservations != tree.reservations:
        raise ValueError("DTB roundtrip mismatch")
    (HERE / "vk-mini-a113x-usb-only.dtb").write_bytes(dtb)
    entries = []
    for name in ("bin", "lib", "sbin", "etc", "proc", "sys", "dev", "dev/pts", "run", "tmp", "root"):
        entries.append((name, stat.S_IFDIR | (0o700 if name == "root" else 0o755), b"", (0, 0)))
    # Deliberately exclude distro init, networking setup, fstab, and vendor scripts.
    with tarfile.open(inputs[ALPINE], "r:gz") as archive:
        members = {m.name.removeprefix("./"): m for m in archive}
        for name in ("bin/busybox", "lib/ld-musl-aarch64.so.1"):
            member = members[name]
            if not member.isfile():
                raise ValueError("expected a regular ELF in Alpine archive")
            data = archive.extractfile(member).read()
            if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
                raise ValueError("expected ARM64 ELF")
            entries.append((name, stat.S_IFREG | 0o755, data, (0, 0)))
    for applet in ("sh", "mount", "mkdir", "sleep", "cat", "id", "uname", "ls", "readlink", "dmesg", "grep", "head", "wc"):
        entries.append(("bin/" + applet, stat.S_IFLNK | 0o777, b"/bin/busybox", (0, 0)))
    entries.append(("lib/libc.musl-aarch64.so.1", stat.S_IFLNK | 0o777, b"ld-musl-aarch64.so.1", (0, 0)))
    for source, guest in (("init", "capsula-ram-init"), ("console", "capsula-console"), ("status", "capsula-status")):
        entries.append((guest, stat.S_IFREG | 0o755, (HERE / source).read_bytes(), (0, 0)))
    entries.append(("dev/console", stat.S_IFCHR | 0o600, b"", (5, 1)))
    entries.append(("dev/null", stat.S_IFCHR | 0o666, b"", (1, 3)))
    entries.append(("TRAILER!!!", 0, b"", (0, 0)))
    output = io.BytesIO()
    for inode, (name, mode, data, rdev) in enumerate(entries, 1):
        add_entry(output, inode, name, mode, data, rdev)
    compressed = gzip.compress(output.getvalue(), mtime=0)
    (HERE / "initramfs.cpio.gz").write_bytes(compressed)
    header = struct.pack(">7I4B32s", 0x27051956, 0, 0, len(compressed), 0, 0,
                         zlib.crc32(compressed), 5, 22, 3, 1, b"Capsula USB RAM test")
    header = header[:4] + struct.pack(">I", zlib.crc32(header)) + header[8:]
    (HERE / "initramfs.uimg").write_bytes(header + compressed)
    manifest = {
        "purpose": "Minimal temporary USB ACM root console; DTB disables storage and optional peripherals",
        "hardware_tested": False, "stock_root_tested": False,
        "disabled_nodes": targets, "cpio_entries": [e[0] for e in entries], "files": {},
    }
    for name in ("Image", "vk-mini-a113x-usb-only.dtb", "initramfs.cpio.gz", "initramfs.uimg", "init", "console", "status"):
        data = (HERE / name).read_bytes()
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (HERE / "ramboot-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Built", len(compressed), "byte initramfs; disabled", len(targets), "DTB nodes; hardware not tested.")


if __name__ == "__main__":
    main()
