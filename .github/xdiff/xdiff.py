#!/usr/bin/env python3
"""Differential UPER test: asn1c vs asn1tools.

For every (type, value) case below, the value is UPER-encoded with the
independent asn1tools Python implementation, then relayed through the
asn1c-generated converter (-iper -oper).  A correct asn1c decoder+encoder
pair reproduces the input byte-for-byte; any disagreement between the two
implementations (or any asn1c decode failure) fails the test.

This is deliberately green-by-construction: the corpus only contains
shapes both implementations are expected to agree on today, so a red run
always means a regression on one side of the relay.

Run from anywhere inside the build tree after `make`:
    python3 .github/xdiff/xdiff.py
Requires: pip install asn1tools
"""

import glob
import os
import pathlib
import subprocess
import sys
import tempfile

import asn1tools

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = HERE / "schemas" / "xdiff.asn1"
ASN1C = ROOT / "asn1c" / "asn1c"
SKELETONS = ROOT / "skeletons"

# (type-name, value in asn1tools conventions)
CASES = [
    ("EInterleaved", "a"),
    ("EInterleaved", "c"),
    ("EInterleaved", "b"),          # extension addition below root max
    ("EAuto", "x"),
    ("EAuto", "z"),                 # extension addition
    ("IConstr", 0),
    ("IConstr", 17),
    ("IConstr", 255),
    ("IWide", -1234),
    ("IWide", 0),
    ("IWide", 123456789),
    ("IExt", 0),
    ("IExt", 7),
    ("IExt", 100),                  # outside the extensible root range
    ("BStr", (bytes([0b10100000]), 4)),
    ("BStr", (bytes([0b11110000, 0b11110000]), 12)),
    # Note: sizes beyond the extensible root are omitted — asn1tools
    # raises NotImplementedError("BIT STRING extension") for them, so
    # only asn1c's root-size handling of the extensible type is compared.
    ("BStrExt", (bytes([0b10100000]), 4)),
    ("BStrExt", (bytes([0b10101010]), 8)),
    ("OStr", b""),
    ("OStr", b"hello"),
    ("SeqExt", {"i": 5, "b": True}),
    ("SeqExt", {"i": 5, "b": False, "s": "hi", "j": 3}),  # additions present
    ("ChExt", ("i", 42)),
    ("ChExt", ("b", True)),
    ("ChExt", ("o", b"\x01\x02")),  # extension alternative (open type)
    ("Nested", {"e": "b", "ch": ("i", 1)}),
    ("Nested", {"e": "a", "ch": ("o", b"\xff"),
                "bs": (bytes([0b10101010]), 8)}),
]


def build_converter(workdir):
    subprocess.run(
        [str(ASN1C), "-S", str(SKELETONS), "-no-gen-OER", "-pdu=all",
         str(SCHEMA)],
        cwd=workdir, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    cc = os.environ.get("CC", "cc")
    sources = sorted(glob.glob(os.path.join(workdir, "*.c")))
    # -DASN_DISABLE_OER_SUPPORT matches -no-gen-OER above: the OER
    # skeletons are not copied, and constr_TYPE.h includes their headers
    # unless the macro is defined (the generated Makefile does the same).
    subprocess.run(
        [cc, "-O1", "-I.", "-DASN_PDU_COLLECTION",
         "-DASN_DISABLE_OER_SUPPORT", "-o", "conv"]
        + [os.path.basename(s) for s in sources] + ["-lm"],
        cwd=workdir, check=True)
    return os.path.join(workdir, "conv")


def relay(conv, workdir, type_name, encoded):
    infile = os.path.join(workdir, "in.bin")
    with open(infile, "wb") as f:
        f.write(encoded)
    res = subprocess.run(
        [conv, "-p", type_name, "-iper", "-oper", "-1", infile],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res


def main():
    spec = asn1tools.compile_files(str(SCHEMA), "uper")
    failures = 0
    with tempfile.TemporaryDirectory() as workdir:
        conv = build_converter(workdir)
        for type_name, value in CASES:
            expected = spec.encode(type_name, value)
            res = relay(conv, workdir, type_name, expected)
            status = "OK"
            if res.returncode != 0:
                status = "DECODE-FAILED"
            elif res.stdout != expected:
                status = "MISMATCH"
            print("%-14s %-40r ref=%s asn1c=%s %s" % (
                type_name, value, expected.hex(),
                res.stdout.hex() if res.returncode == 0 else "-", status))
            if status != "OK":
                failures += 1
                sys.stderr.write(res.stderr.decode(errors="replace"))
    print("=" * 60)
    print("%d/%d cases agree" % (len(CASES) - failures, len(CASES)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
