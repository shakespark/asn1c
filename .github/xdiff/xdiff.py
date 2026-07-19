#!/usr/bin/env python3
"""Differential UPER test: asn1c vs asn1tools.

For every (type, value) case below, the value is UPER-encoded with the
independent asn1tools Python implementation, then checked against the
asn1c-generated converter two different ways:

  1. Byte relay (-iper -oper): decode with asn1c, re-encode with asn1c,
     and compare the result byte-for-byte against the asn1tools encoding.
  2. Cross-modal semantic check (-iper -oxer): decode with asn1c into XER
     and compare the *meaning* of the XER against the abstract Python
     value, independently of asn1c's own encoder.

Check (1) alone is blind to a whole class of bugs: asn1c's UPER decoder
and encoder share the same value<->wire mapping table (e.g. the
ENUMERATED root/addition index map, or a CHOICE alternative ordering
table). If that shared table is wrong in a way that is *consistently*
wrong -- the decoder misreads a value and the encoder, using the same
table, re-emits the same bytes for its (equally wrong) in-memory value
-- the relay bytes still match and check (1) reports a false OK.

This was observed directly: on commit acd87391 (parent of the ENUMERATED
map-layout fix dce4cb10), the extensible ENUMERATED root/addition index
map was miscomputed such that decoding 0x00/0x40/0x80 produced "a"/"c"/"b"
instead of "a"/"b"/"c". Because the encoder used the very same
(miscomputed) map, re-encoding the wrongly-decoded value still produced
the original bytes, and the byte-relay check reported all cases green.
Check (2) decodes into XER -- a human/machine-readable rendering that
never goes back through asn1c's own encoder -- so the wrong identifier
name ("c" printed for what should be "b") shows up directly in the XER
text and is caught.

A case only passes overall if *both* checks agree.

This is deliberately green-by-construction: the corpus only contains
shapes both implementations are expected to agree on today, so a red run
always means a regression on one side of the relay or in the XER
rendering.

Run from anywhere inside the build tree after `make`:
    python3 .github/xdiff/xdiff.py
Requires: pip install asn1tools

A standalone, build-free sanity check of the XER semantic comparator
itself (including a deliberately tampered XER, proving the comparator
can actually detect a b/c mixup) is available via:
    python3 .github/xdiff/xdiff.py --selftest
"""

import glob
import os
import pathlib
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

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
    res = subprocess.run(
        [str(ASN1C), "-S", str(SKELETONS), "-no-gen-OER", "-pdu=all",
         str(SCHEMA)],
        cwd=workdir,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        sys.stderr.write("asn1c codegen failed:\n")
        sys.stderr.write(res.stdout.decode(errors="replace"))
        res.check_returncode()
    cc = os.environ.get("CC", "cc")
    sources = sorted(glob.glob(os.path.join(workdir, "*.c")))
    # -DASN_DISABLE_OER_SUPPORT matches -no-gen-OER above: the OER
    # skeletons are not copied, and constr_TYPE.h includes their headers
    # unless the macro is defined (the generated Makefile does the same).
    res = subprocess.run(
        [cc, "-O1", "-I.", "-DASN_PDU_COLLECTION",
         "-DASN_DISABLE_OER_SUPPORT", "-o", "conv"]
        + [os.path.basename(s) for s in sources] + ["-lm"],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        sys.stderr.write("converter build failed:\n")
        sys.stderr.write(res.stdout.decode(errors="replace"))
        res.check_returncode()
    return os.path.join(workdir, "conv")


def relay(conv, workdir, type_name, encoded):
    """Byte relay: asn1c decode + asn1c re-encode, compared to the
    original asn1tools-encoded bytes."""
    infile = os.path.join(workdir, "in.bin")
    with open(infile, "wb") as f:
        f.write(encoded)
    return subprocess.run(
        [conv, "-p", type_name, "-iper", "-oper", "-1", infile],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def to_xer(conv, workdir, type_name, encoded):
    """Cross-modal decode: asn1c decode -> XER text (never touches
    asn1c's own encoder)."""
    infile = os.path.join(workdir, "in.bin")
    with open(infile, "wb") as f:
        f.write(encoded)
    return subprocess.run(
        [conv, "-p", type_name, "-iper", "-oxer", "-1", infile],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


# --------------------------------------------------------------------
# XER <-> abstract-value semantic comparator.
#
# asn1c's XER output is well-formed XML (self-closing tags for
# ENUMERATED identifiers and BOOLEAN, plain text content for INTEGER/
# OCTET STRING/BIT STRING/character strings, nested elements for
# SEQUENCE fields and the chosen CHOICE alternative), so it can be
# parsed with the standard library's ElementTree rather than a
# hand-rolled tokenizer.
#
# The comparator is driven by the *shape* of the expected Python value
# (using the same asn1tools value conventions as CASES above), since
# that unambiguously determines which ASN.1 construct produced a given
# XML element:
#   bool                       -> BOOLEAN            <true/> / <false/>
#   int (not bool)             -> INTEGER             <Tag>N</Tag>
#   bytes                      -> OCTET STRING        <Tag>AA BB CC</Tag>
#   (bytes, nbits) tuple       -> BIT STRING          <Tag>0101..</Tag>
#   (name, value) tuple,
#     name is str              -> CHOICE              <Tag><name>...</name></Tag>
#   dict                       -> SEQUENCE            one child per key
#   str                        -> ENUMERATED ident. if a single
#                                 self-closing child matches the string,
#                                 otherwise a character string (IA5String)
# --------------------------------------------------------------------

class XerMismatch(Exception):
    pass


def _is_self_closing_ident(elem, name):
    if elem.tag != name:
        return False
    if (elem.text or "").strip():
        return False
    if list(elem):
        return False
    return True


def semantic_compare(elem, value, path=""):
    """Compare an ElementTree element against an abstract asn1tools-style
    value. Returns None on success, or a human-readable mismatch
    description."""
    if isinstance(value, bool):
        children = list(elem)
        want = "true" if value else "false"
        if len(children) == 1 and _is_self_closing_ident(children[0], want):
            return None
        got = [c.tag for c in children]
        return "%s: expected <%s/>, got children=%r" % (path, want, got)

    if isinstance(value, int):
        text = (elem.text or "").strip()
        if text == str(value):
            return None
        return "%s: expected INTEGER %d, got %r" % (path, value, text)

    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bytes):
        bitstr, nbits = value
        bits = "".join("{:08b}".format(b) for b in bitstr)[:nbits]
        text = "".join((elem.text or "").split())
        if text == bits:
            return None
        return "%s: expected BIT STRING %r (%d bits), got %r" % (
            path, bits, nbits, text)

    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        alt_name, alt_value = value
        children = list(elem)
        if len(children) != 1 or children[0].tag != alt_name:
            got = [c.tag for c in children]
            return "%s: expected CHOICE alternative <%s>, got %r" % (
                path, alt_name, got)
        return semantic_compare(children[0], alt_value,
                                 "%s.%s" % (path, alt_name))

    if isinstance(value, bytes):
        text = (elem.text or "").strip()
        want = " ".join("{:02X}".format(b) for b in value)
        if text == want:
            return None
        return "%s: expected OCTET STRING %r, got %r" % (path, want, text)

    if isinstance(value, dict):
        for key, sub in value.items():
            child = elem.find(key)
            if child is None:
                return "%s: missing field <%s>" % (path, key)
            err = semantic_compare(child, sub, "%s.%s" % (path, key))
            if err:
                return err
        return None

    if isinstance(value, str):
        children = list(elem)
        if len(children) == 1 and _is_self_closing_ident(children[0], value):
            return None
        text = (elem.text or "").strip()
        if text == value:
            return None
        return "%s: expected %r (identifier or character string), got %r" % (
            path, value, text if not children else [c.tag for c in children])

    return "%s: don't know how to compare Python value %r" % (path, value)


def xer_semantic_check(xer_bytes, type_name, value):
    """Parse the converter's XER stdout and semantically compare it to
    the abstract value. Returns None on success, else an error string."""
    try:
        root = ET.fromstring(xer_bytes)
    except ET.ParseError as exc:
        return "XER did not parse as XML: %s" % exc
    if root.tag != type_name:
        return "XER root element is <%s>, expected <%s>" % (root.tag, type_name)
    return semantic_compare(root, value, type_name)


def _selftest():
    """Build-free sanity check of the comparator, including a
    deliberately tampered XER (b swapped for c) to prove it actually
    catches the acd87391-style ENUMERATED map mixup."""
    ok_xer = b"<EInterleaved><b/></EInterleaved>"
    err = xer_semantic_check(ok_xer, "EInterleaved", "b")
    assert err is None, "expected match, got: %s" % err

    tampered_xer = b"<EInterleaved><c/></EInterleaved>"
    err = xer_semantic_check(tampered_xer, "EInterleaved", "b")
    assert err is not None, (
        "comparator FAILED to detect a b/c mixup in a tampered XER "
        "-- this is exactly the acd87391 regression shape")
    print("selftest: tampered XER (identifier 'c' substituted for 'b') "
          "correctly detected as a mismatch:")
    print("  " + err)

    nested_xer = (b"<Nested><e><a/></e><ch><o>FF</o></ch>"
                  b"<bs>10101010</bs></Nested>")
    assert xer_semantic_check(
        nested_xer, "Nested",
        {"e": "a", "ch": ("o", b"\xff"), "bs": (bytes([0b10101010]), 8)}
    ) is None

    seq_xer = b"<SeqExt><i>5</i><b><false/></b><s>hi</s><j>3</j></SeqExt>"
    assert xer_semantic_check(
        seq_xer, "SeqExt", {"i": 5, "b": False, "s": "hi", "j": 3}
    ) is None
    tampered_seq = b"<SeqExt><i>5</i><b><true/></b><s>hi</s><j>3</j></SeqExt>"
    assert xer_semantic_check(
        tampered_seq, "SeqExt", {"i": 5, "b": False, "s": "hi", "j": 3}
    ) is not None

    print("selftest: all comparator checks passed")
    return 0


def main():
    if "--selftest" in sys.argv[1:]:
        return _selftest()

    spec = asn1tools.compile_files(str(SCHEMA), "uper")
    failures = 0
    with tempfile.TemporaryDirectory() as workdir:
        conv = build_converter(workdir)
        for type_name, value in CASES:
            expected = spec.encode(type_name, value)

            relay_res = relay(conv, workdir, type_name, expected)
            relay_status = "OK"
            if relay_res.returncode != 0:
                relay_status = "DECODE-FAILED"
            elif relay_res.stdout != expected:
                relay_status = "MISMATCH"

            xer_res = to_xer(conv, workdir, type_name, expected)
            xer_status = "OK"
            xer_err = None
            if xer_res.returncode != 0:
                xer_status = "XER-DECODE-FAILED"
            else:
                xer_err = xer_semantic_check(xer_res.stdout, type_name, value)
                if xer_err is not None:
                    xer_status = "XER-MISMATCH"

            status = relay_status if relay_status != "OK" else xer_status
            if xer_status != "OK" and relay_status == "OK":
                status = xer_status

            print("%-14s %-40r ref=%s asn1c=%s relay=%s xer=%s" % (
                type_name, value, expected.hex(),
                relay_res.stdout.hex() if relay_res.returncode == 0 else "-",
                relay_status, xer_status))

            if relay_status != "OK" or xer_status != "OK":
                failures += 1
                if relay_status != "OK":
                    sys.stderr.write(
                        "-- %s %r: byte-relay converter stderr --\n" % (
                            type_name, value))
                    sys.stderr.write(relay_res.stderr.decode(errors="replace"))
                if xer_status != "OK":
                    sys.stderr.write(
                        "-- %s %r: XER cross-modal converter stderr --\n" % (
                            type_name, value))
                    sys.stderr.write(xer_res.stderr.decode(errors="replace"))
                    sys.stderr.write(
                        "-- %s %r: XER output --\n" % (type_name, value))
                    sys.stderr.write(xer_res.stdout.decode(errors="replace"))
                    sys.stderr.write("\n")
                    if xer_err:
                        sys.stderr.write(
                            "-- %s %r: semantic mismatch: %s --\n" % (
                                type_name, value, xer_err))
    print("=" * 60)
    print("%d/%d cases agree (byte relay + XER cross-modal)" % (
        len(CASES) - failures, len(CASES)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
