# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
A closer static look at captured honeypot data: decoding content that was hidden by encoding, and reading the structure
of a Linux program (ELF).

SAFETY: everything here treats its input as bytes to be read. Nothing is executed, loaded or passed to another program.
Every loop and every output is bounded, because the input is written by an attacker.
"""
from __future__ import annotations

import base64
import re
import struct
import zlib

MAX_BLOBS = 12                 # decoded pieces reported for one script or session
MAX_ENCODED = 3_000_000        # longest encoded run looked at (characters)
MAX_DECODED = 1_000_000        # most bytes kept of one decoded piece, also the cap when decompressing
MAX_DEPTH = 2                  # an encoded script inside an encoded script is followed once

_B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_HEXESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_MAGIC = (b"\x7fELF", b"MZ", b"\x1f\x8b", b"#!", b"PK\x03\x04", b"BZh", b"\xfd7zXZ")


def _meaningful(b: bytes) -> bool:
    """True when decoded bytes look like something real (readable text or a known file type), not a random match."""
    if len(b) < 12:
        return False
    if b.startswith(_MAGIC):
        return True
    head = b[:4096]
    return sum(1 for c in head if c in (9, 10, 13) or 32 <= c < 127) / len(head) >= 0.9


def _b64(s: str) -> bytes | None:
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except ValueError:
        return None


def _gunzip(b: bytes) -> bytes | None:
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(b, MAX_DECODED)
    except zlib.error:
        return None


def decode_blobs(text: str, depth: int = 1, via: tuple = ()) -> list[dict]:
    """Encoded content found in a script or in typed commands, decoded: base64 runs, and bytes written as \\xNN escapes
    (how droppers echo a program into a file). Each item is {how, line, encoded_chars, data}."""
    out: list[dict] = []

    def add(how: str, pos: int, n: int, data: bytes):
        layers = via + (how,)
        if data[:2] == b"\x1f\x8b":
            plain = _gunzip(data)
            if plain:
                data, layers = plain, layers + ("gzip",)
        data = data[:MAX_DECODED]
        out.append({"how": " > ".join(layers), "line": text.count("\n", 0, pos) + 1, "encoded_chars": n, "data": data})
        if depth < MAX_DEPTH and _meaningful(data) and not data.startswith(_MAGIC):
            out.extend(decode_blobs(data.decode("latin-1"), depth + 1, layers))

    for m in _B64.finditer(text):
        if len(out) >= MAX_BLOBS:
            break
        if m.end() - m.start() > MAX_ENCODED:
            continue
        data = _b64(m.group())
        if data and _meaningful(data):
            add("base64", m.start(), m.end() - m.start(), data)

    runs = [m for m in _HEXESC.finditer(text)][:5000]
    if runs and len(out) < MAX_BLOBS:
        pieces, total = [], 0
        for m in runs:
            if total > MAX_ENCODED:
                break
            pieces.append(bytes.fromhex(m.group().replace("\\x", "")))
            total += m.end() - m.start()
        joined = b"".join(pieces)
        if len(pieces) > 1 and _meaningful(joined):         # a program echoed in many small pieces: put it back together
            add(f"\\x escapes, {len(pieces)} pieces joined", runs[0].start(), total, joined)
        else:
            for m, piece in zip(runs, pieces):
                if len(out) >= MAX_BLOBS:
                    break
                if _meaningful(piece):
                    add("\\x escapes", m.start(), m.end() - m.start(), piece)
    return out[:MAX_BLOBS]


# ------------------------------------------------------------------ ELF structure
# Functions a program asks the system for, and what each suggests. A hint about capability, never a verdict.
NOTABLE_IMPORTS = {
    "socket": "opens network connections", "connect": "opens network connections", "sendto": "sends network packets",
    "recvfrom": "receives network packets", "bind": "listens for connections", "listen": "listens for connections",
    "accept": "listens for connections", "gethostbyname": "looks up host names", "getaddrinfo": "looks up host names",
    "execve": "runs other programs", "execl": "runs other programs", "execvp": "runs other programs",
    "system": "runs shell commands", "popen": "runs shell commands", "fork": "starts copies of itself",
    "vfork": "starts copies of itself", "daemon": "runs in the background", "setsid": "runs in the background",
    "ptrace": "inspects or blocks debuggers", "prctl": "can rename its own process", "kill": "stops other processes",
    "chmod": "changes file permissions", "unlink": "deletes files", "mprotect": "changes memory protection",
    "dlopen": "loads code at run time", "getifaddrs": "reads the network interfaces",
}
_ELF_TYPES = {1: "relocatable object", 2: "executable", 3: "position-independent executable or shared library", 4: "core dump"}


def _name(data: bytes, off: int, limit: int = 120) -> str:
    """A NUL-terminated name from the file, reduced to plain printable ASCII."""
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    raw = data[off:end if end != -1 else off + limit]
    return "".join(chr(c) for c in raw if 32 < c < 127)


def elf_details(data: bytes) -> dict | None:
    """The structure of a Linux program, read from its headers: segments, libraries it needs, functions it imports and
    anything appended after the program. Returns None when the data is not an ELF file."""
    if data[:4] != b"\x7fELF" or len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    is64, e = data[4] == 2, "<" if data[5] == 1 else ">"
    out = {"bits": 64 if is64 else 32, "type": "", "entry": "", "interp": "", "segments": [], "rwx": False,
           "sections": [], "needed": [], "imports": [], "notable": [], "overlay": 0, "stripped": True, "notes": []}
    try:
        (e_type, _m, _v, entry, phoff, shoff, _f, _eh, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from(e + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"), data, 16)
        out["type"], out["entry"] = _ELF_TYPES.get(e_type, f"type {e_type}"), hex(entry)
        end_of_file, loads, dyn = 0, [], None
        for i in range(min(phnum, 64)):
            o = phoff + i * phentsize
            if is64:
                p_type, flags, off, vaddr, _p, filesz, memsz, _a = struct.unpack_from(e + "IIQQQQQQ", data, o)
            else:
                p_type, off, vaddr, _p, filesz, memsz, flags, _a = struct.unpack_from(e + "IIIIIIII", data, o)
            end_of_file = max(end_of_file, off + filesz)
            if p_type == 1:                                   # PT_LOAD
                perm = ("r" if flags & 4 else "-") + ("w" if flags & 2 else "-") + ("x" if flags & 1 else "-")
                out["segments"].append({"perm": perm, "file_size": filesz, "mem_size": memsz})
                out["rwx"] = out["rwx"] or perm.endswith("wx")
                loads.append((vaddr, off, filesz))
            elif p_type == 3:                                 # PT_INTERP
                out["interp"] = _name(data, off)
            elif p_type == 2:                                 # PT_DYNAMIC
                dyn = (off, filesz)

        def at(vaddr: int) -> int:                            # a memory address back to its place in the file
            for v, off, size in loads:
                if v <= vaddr < v + size:
                    return off + (vaddr - v)
            return -1

        secs = []
        if shoff and shnum:
            end_of_file = max(end_of_file, shoff + min(shnum, 4096) * shentsize)
            for i in range(min(shnum, 128)):
                o = shoff + i * shentsize
                if is64:
                    nm, typ, _fl, _ad, off, size, link, _in, _al, entsize = struct.unpack_from(e + "IIQQQQIIQQ", data, o)
                else:
                    nm, typ, _fl, _ad, off, size, link, _in, _al, entsize = struct.unpack_from(e + "IIIIIIIIII", data, o)
                secs.append((nm, typ, off, size, link, entsize))
                if typ != 8:                                  # SHT_NOBITS takes no room in the file
                    end_of_file = max(end_of_file, off + size)
            if shstrndx < len(secs):
                base = secs[shstrndx][2]
                out["sections"] = [n for n in (_name(data, base + s[0], 40) for s in secs) if n][:60]
            out["stripped"] = not any(s[1] == 2 for s in secs)                       # SHT_SYMTAB
            for nm, typ, off, size, link, entsize in secs:
                if typ == 11 and link < len(secs):                                    # SHT_DYNSYM: what it imports
                    strtab, step = secs[link][2], (24 if is64 else 16)
                    for j in range(1, min(size // step, 2000)):
                        if is64:
                            s_name, _i, _o, shndx = struct.unpack_from(e + "IBBH", data, off + j * step)
                        else:
                            s_name, _v2, _s2, _i, _o, shndx = struct.unpack_from(e + "IIIBBH", data, off + j * step)
                        if shndx == 0 and s_name:
                            n = _name(data, strtab + s_name, 60)
                            if n and n not in out["imports"]:
                                out["imports"].append(n)
        if dyn:                                               # libraries it needs, from the dynamic table
            off, size = dyn
            step, fmt = (16, "qQ") if is64 else (8, "iI")
            entries = [struct.unpack_from(e + fmt, data, off + j * step) for j in range(min(size // step, 512))
                       if off + (j + 1) * step <= len(data)]
            strtab = next((at(v) for t, v in entries if t == 5), -1)                  # DT_STRTAB
            if strtab >= 0:
                out["needed"] = [n for n in (_name(data, strtab + v, 80) for t, v in entries if t == 1) if n][:40]
        out["overlay"] = max(0, len(data) - end_of_file) if end_of_file else 0
    except (struct.error, IndexError, ValueError, OverflowError):
        out["notes"].append("The program's headers are damaged or cut short, so this is incomplete.")
    out["imports"] = out["imports"][:300]
    seen = {}
    for n in out["imports"]:
        why = NOTABLE_IMPORTS.get(n.split("@")[0])
        if why:
            seen.setdefault(why, []).append(n)
    out["notable"] = [{"why": w, "names": names[:8]} for w, names in seen.items()]
    if out["rwx"]:
        out["notes"].append("Has a memory segment that is both writable and executable, which packers and self-modifying code use.")
    if out["overlay"] > 64:
        out["notes"].append(f"{out['overlay']} bytes follow the end of the program. Droppers store a second payload or settings there.")
    if not out["sections"] and out["segments"]:
        out["notes"].append("No section table: it was stripped or packed, so imported functions can't be listed.")
    return out
