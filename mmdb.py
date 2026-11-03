# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""A small, dependency-free reader for MaxMind DB (.mmdb) files such as DB-IP Lite and GeoLite2.

Written from the public MaxMind DB format specification
(https://maxmind.github.io/MaxMind-DB/) so LanPulse doesn't need the Apache-licensed `maxminddb` package.
Only what LanPulse needs is here: open a file and look up one IP address.
"""
from __future__ import annotations

import ipaddress
import mmap
import struct

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
_DATA_SEPARATOR = 16


class InvalidDatabaseError(Exception):
    pass


class Reader:
    def __init__(self, path: str):
        self._file = open(path, "rb")
        try:
            self._buf = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):           # empty or unmappable file
            self._buf = self._file.read()
        start = self._buf.rfind(METADATA_MARKER, max(0, len(self._buf) - 128 * 1024))
        if start < 0:
            raise InvalidDatabaseError(f"{path} is not a MaxMind DB file (no metadata section)")
        meta_start = start + len(METADATA_MARKER)
        self.metadata, _ = _Decoder(self._buf, meta_start).decode(meta_start)
        try:
            self.node_count = int(self.metadata["node_count"])
            self.record_size = int(self.metadata["record_size"])
            self.ip_version = int(self.metadata["ip_version"])
        except (KeyError, TypeError, ValueError):
            raise InvalidDatabaseError(f"{path} has incomplete metadata")
        if self.record_size not in (24, 28, 32):
            raise InvalidDatabaseError(f"Unsupported record size {self.record_size}")
        self._node_bytes = self.record_size // 4          # two records per node
        self._tree_size = self.node_count * self._node_bytes
        self._data_start = self._tree_size + _DATA_SEPARATOR
        if self._data_start > meta_start:
            raise InvalidDatabaseError(f"{path} has a search tree larger than the file")
        self._decoder = _Decoder(self._buf, self._data_start)
        self._ipv4_start = None

    # ---- public
    def get(self, ip) -> dict | None:
        addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(ip))
        if addr.version == 6 and self.ip_version == 4:
            raise ValueError("This database only contains IPv4 addresses")
        packed = addr.packed
        bits = len(packed) * 8
        node = self._start_node(bits)
        node_count = self.node_count
        i = 0
        while i < bits and node < node_count:
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._record(node, bit)
            i += 1
        if node == node_count:
            return None                                # not in the database
        if node > node_count:
            offset = node - node_count - _DATA_SEPARATOR
            value, _ = self._decoder.decode(self._data_start + offset)
            return value
        raise InvalidDatabaseError("Search tree ended inside the tree (corrupt database)")

    def close(self):
        try:
            if isinstance(self._buf, mmap.mmap):
                self._buf.close()
        finally:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- search tree
    def _start_node(self, bits: int) -> int:
        if self.ip_version == 6 and bits == 32:        # IPv4 lives under ::/96 in an IPv6 tree
            if self._ipv4_start is None:
                node = 0
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._record(node, 0)
                self._ipv4_start = node
            return self._ipv4_start
        return 0

    def _record(self, node: int, right: int) -> int:
        base = node * self._node_bytes
        if base + self._node_bytes > self._tree_size:
            raise InvalidDatabaseError("Search tree points outside the tree")
        b = self._buf
        if self.record_size == 24:
            o = base + 3 * right
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if self.record_size == 28:
            if right:
                return ((b[base + 3] & 0x0F) << 24) | (b[base + 4] << 16) | (b[base + 5] << 8) | b[base + 6]
            return ((b[base + 3] & 0xF0) << 20) | (b[base] << 16) | (b[base + 1] << 8) | b[base + 2]
        o = base + 4 * right
        return struct.unpack_from(">I", b, o)[0]


class _Decoder:
    """Decodes the MaxMind DB data section format (maps, arrays, strings, numbers and pointers)."""

    MAX_DEPTH = 64

    def __init__(self, buf, pointer_base: int):
        self.buf = buf
        self.base = pointer_base

    def decode(self, offset: int, depth: int = 0):
        if depth > self.MAX_DEPTH:
            raise InvalidDatabaseError("Data nested too deeply")
        buf = self.buf
        if offset >= len(buf):
            raise InvalidDatabaseError("Data offset outside the file")
        ctrl = buf[offset]
        offset += 1
        kind = ctrl >> 5
        if kind == 1:                                       # pointer
            ptr, offset = self._pointer(ctrl, offset)
            value, _ = self.decode(self.base + ptr, depth + 1)
            return value, offset
        if kind == 0:                                       # extended type
            kind = 7 + buf[offset]
            offset += 1
            if kind < 8:
                raise InvalidDatabaseError("Bad extended type")
        size, offset = self._size(ctrl, offset)
        if kind == 2:                                       # UTF-8 string
            end = offset + size
            return bytes(buf[offset:end]).decode("utf-8"), end
        if kind == 3:                                       # double
            if size != 8:
                raise InvalidDatabaseError("Bad double size")
            return struct.unpack_from(">d", buf, offset)[0], offset + 8
        if kind == 4:                                       # bytes
            end = offset + size
            return bytes(buf[offset:end]), end
        if kind in (5, 6, 9, 10):                           # unsigned 16/32/64/128
            end = offset + size
            return int.from_bytes(bytes(buf[offset:end]), "big"), end
        if kind == 7:                                       # map
            out = {}
            for _ in range(size):
                key, offset = self.decode(offset, depth + 1)
                val, offset = self.decode(offset, depth + 1)
                out[key] = val
            return out, offset
        if kind == 8:                                       # signed 32-bit
            end = offset + size
            n = int.from_bytes(bytes(buf[offset:end]), "big")
            if size == 4 and n & 0x80000000:
                n -= 1 << 32
            return n, end
        if kind == 11:                                      # array
            out = []
            for _ in range(size):
                val, offset = self.decode(offset, depth + 1)
                out.append(val)
            return out, offset
        if kind == 14:                                      # boolean (value is the size)
            return bool(size), offset
        if kind == 15:                                      # float
            if size != 4:
                raise InvalidDatabaseError("Bad float size")
            return struct.unpack_from(">f", buf, offset)[0], offset + 4
        raise InvalidDatabaseError(f"Unknown data type {kind}")

    def _size(self, ctrl: int, offset: int):
        size = ctrl & 0x1F
        if size < 29:
            return size, offset
        buf = self.buf
        if size == 29:
            return 29 + buf[offset], offset + 1
        if size == 30:
            return 285 + ((buf[offset] << 8) | buf[offset + 1]), offset + 2
        return 65821 + ((buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]), offset + 3

    def _pointer(self, ctrl: int, offset: int):
        buf = self.buf
        ss = (ctrl >> 3) & 0x3
        vvv = ctrl & 0x7
        if ss == 0:
            return (vvv << 8) | buf[offset], offset + 1
        if ss == 1:
            return ((vvv << 16) | (buf[offset] << 8) | buf[offset + 1]) + 2048, offset + 2
        if ss == 2:
            return ((vvv << 24) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]) + 526336, offset + 3
        return struct.unpack_from(">I", buf, offset)[0], offset + 4


def open_database(path: str) -> Reader:
    return Reader(path)
