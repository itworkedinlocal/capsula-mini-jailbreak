"""Offline FDT reader/writer preserving nodes, properties, and reservations."""
from dataclasses import dataclass
import struct


@dataclass
class Fdt:
    nodes: dict
    reservations: bytes
    version: int
    compatible_version: int
    boot_cpu: int

    @classmethod
    def read(cls, blob):
        if len(blob) < 40:
            raise ValueError("short FDT header")
        magic, total, off, so, ro, version, compat, cpu, ns, nt = struct.unpack_from(">10I", blob)
        if magic != 0xD00DFEED or total != len(blob) or version != 17:
            raise ValueError("unexpected FDT header")
        if not (40 <= off <= off + nt <= total and 40 <= so <= so + ns <= total):
            raise ValueError("FDT section outside blob")
        rp = ro
        while True:
            if rp < 40 or rp + 16 > total:
                raise ValueError("invalid FDT reservation map")
            pair = struct.unpack_from(">QQ", blob, rp)
            rp += 16
            if pair == (0, 0):
                break
        names = blob[so:so + ns]
        nodes, stack, p = {}, [], off
        while p < off + nt:
            token = struct.unpack_from(">I", blob, p)[0]
            p += 4
            if token == 1:
                end = blob.index(0, p, off + nt)
                name = blob[p:end].decode("ascii")
                if "/" in name or (not stack and name):
                    raise ValueError("invalid FDT node name")
                stack.append(name)
                path = "/".join(stack) or "/"
                if path in nodes:
                    raise ValueError("duplicate FDT node")
                nodes[path] = {}
                p = (end + 4) & ~3
            elif token == 2:
                if not stack:
                    raise ValueError("unbalanced FDT node")
                stack.pop()
            elif token == 3:
                if not stack or p + 8 > off + nt:
                    raise ValueError("invalid FDT property")
                length, name_off = struct.unpack_from(">II", blob, p)
                p += 8
                if name_off >= len(names) or p + length > off + nt:
                    raise ValueError("FDT property outside section")
                name = names[name_off:names.index(0, name_off)].decode("ascii")
                props = nodes["/".join(stack) or "/"]
                if name in props:
                    raise ValueError("duplicate FDT property")
                props[name] = blob[p:p + length]
                p = (p + length + 3) & ~3
            elif token == 4:
                continue
            elif token == 9:
                if stack or p != off + nt:
                    raise ValueError("unbalanced/trailing FDT structure")
                return cls(nodes, blob[ro:rp], version, compat, cpu)
            else:
                raise ValueError("unexpected FDT token")
        raise ValueError("FDT has no end token")

    def write(self, padding=4096):
        names, offsets = bytearray(), {}
        for props in self.nodes.values():
            for name in props:
                if name not in offsets:
                    offsets[name] = len(names)
                    names.extend(name.encode("ascii") + b"\0")
        children = {p: [] for p in self.nodes}
        for path in self.nodes:
            if path != "/":
                children[path.rsplit("/", 1)[0] or "/"].append(path)
        structure = bytearray()

        def word(value):
            structure.extend(struct.pack(">I", value))

        def padded(value):
            structure.extend(value)
            structure.extend(b"\0" * (-len(structure) % 4))

        def emit(path):
            word(1)
            padded(("" if path == "/" else path.rsplit("/", 1)[1]).encode() + b"\0")
            for name, value in self.nodes[path].items():
                word(3)
                word(len(value))
                word(offsets[name])
                padded(value)
            for child in children[path]:
                emit(child)
            word(2)

        emit("/")
        word(9)
        off = 40 + len(self.reservations)
        so = off + len(structure)
        header = struct.pack(">10I", 0xD00DFEED, so + len(names) + padding, off, so, 40,
                             self.version, self.compatible_version, self.boot_cpu,
                             len(names), len(structure))
        return header + self.reservations + structure + names + b"\0" * padding


def usb_only_targets(tree):
    targets = []
    for path in tree.nodes:
        name = path.rsplit("/", 1)[-1]
        if name.startswith(("nand-controller@", "mmc@", "i2c@", "spi@", "watchdog@", "audio-controller-")):
            targets.append(path)
        elif path in ("/sound", "/display", "/audio-codec-0", "/sdio-pwrseq", "/wifi32k", "/efuse"):
            targets.append(path)
    if not any("nand-controller@" in p for p in targets):
        raise ValueError("expected NAND controller missing")
    return targets
