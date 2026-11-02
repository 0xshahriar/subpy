"""Unit tests for the DNS wire-format layer.

These never touch the network: every packet is built or parsed in memory, so
the suite runs identically on CI, on a plane, and on a phone.
"""

from __future__ import annotations

import struct
import unittest

from subpy.core.dns import (
    QTYPE,
    RCODE,
    DNSFormatError,
    build_query,
    decode_name,
    encode_name,
    normalize_name,
    parse_message,
)


class TestNormalizeName(unittest.TestCase):
    def test_lowercases_and_strips_dot(self):
        self.assertEqual(normalize_name("Example.COM."), "example.com")

    def test_strips_url_scheme_and_path(self):
        self.assertEqual(normalize_name("https://example.com/path"), "example.com")

    def test_rejects_empty(self):
        self.assertEqual(normalize_name(""), "")
        self.assertEqual(normalize_name("   "), "")

    def test_strips_credentials_and_port(self):
        self.assertEqual(normalize_name("user:pw@example.com:8443"), "example.com")

    def test_strips_query_and_fragment(self):
        self.assertEqual(normalize_name("example.com?x=1#y"), "example.com")

    def test_handles_idn(self):
        # IDNA encoding must produce punycode, never raw unicode on the wire.
        result = normalize_name("münchen.de")
        self.assertEqual(result, "xn--mnchen-3ya.de")

    def test_rejects_absurd_length(self):
        self.assertEqual(normalize_name("a" * 300 + ".com"), "")

    def test_trailing_whitespace(self):
        self.assertEqual(normalize_name(" example.com "), "example.com")


class TestEncodeDecodeName(unittest.TestCase):
    def test_roundtrip(self):
        packet = encode_name("www.example.com")
        name, end = decode_name(packet, 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(end, len(packet))

    def test_roundtrip_root(self):
        packet = encode_name(".")
        name, _ = decode_name(packet, 0)
        self.assertEqual(name, "")
        self.assertEqual(packet, b"\x00")

    def test_compression_pointer(self):
        # "www.example.com" followed by a pointer back to "example.com"
        # (which starts at offset 4: 3www = 4 bytes).
        packet = encode_name("www.example.com")
        pointer = struct.pack("!H", 0xC000 | 4)
        name, end = decode_name(packet + pointer, len(packet))
        self.assertEqual(name, "example.com")
        self.assertEqual(end, len(packet) + 2)

    def test_pointer_loop_does_not_hang(self):
        # A pointer that points at itself must raise, not spin forever.
        packet = struct.pack("!H", 0xC000)
        with self.assertRaises(DNSFormatError):
            decode_name(packet, 0)

    def test_label_too_long(self):
        # normalize_name screens invalid names out before they reach the wire,
        # so an over-long label simply never becomes a query.
        self.assertEqual(normalize_name("a" * 64 + ".com"), "")
        self.assertEqual(encode_name(""), b"\x00")

    def test_truncated_packet(self):
        with self.assertRaises(DNSFormatError):
            decode_name(b"\x05abc", 0)


class TestBuildQuery(unittest.TestCase):
    def test_header_fields(self):
        packet, qid = build_query("example.com", QTYPE["A"], qid=0x1234)
        got_id, flags, qdcount = struct.unpack("!HHH", packet[:6])
        self.assertEqual(got_id, 0x1234)
        self.assertEqual(qdcount, 1)
        self.assertEqual(flags & 0x0100, 0x0100)  # RD set
        self.assertEqual(qid, 0x1234)

    def test_random_id_when_omitted(self):
        _, qid_a = build_query("example.com", QTYPE["A"])
        self.assertGreaterEqual(qid_a, 0)
        self.assertLessEqual(qid_a, 0xFFFF)

    def test_edns_adds_opt_record(self):
        plain, _ = build_query("example.com", QTYPE["A"], edns=False)
        with_edns, _ = build_query("example.com", QTYPE["A"], edns=True, edns_size=1232)
        arcount_plain = struct.unpack("!HHHHHH", plain[:12])[5]
        arcount_edns = struct.unpack("!HHHHHH", with_edns[:12])[5]
        self.assertEqual(arcount_plain, 0)
        self.assertEqual(arcount_edns, 1)
        self.assertGreater(len(with_edns), len(plain))


def _response(
    name: str,
    qtype: int,
    answers: list,
    rcode: int = 0,
    qid: int = 0x4321,
    authority: list = None,
    additional: list = None,
) -> bytes:
    """Hand-assemble a response packet for parser tests."""
    qname = encode_name(name)
    question = qname + struct.pack("!HH", qtype, 1)
    body = b""
    for rr_name, rr_type, rr_class, ttl, rdata in answers or []:
        rn = encode_name(rr_name)
        body += rn + struct.pack("!HHIH", rr_type, rr_class, ttl, len(rdata)) + rdata
    auth = b""
    for rr_name, rr_type, rr_class, ttl, rdata in authority or []:
        rn = encode_name(rr_name)
        auth += rn + struct.pack("!HHIH", rr_type, rr_class, ttl, len(rdata)) + rdata
    add = b""
    for rr_name, rr_type, rr_class, ttl, rdata in additional or []:
        rn = encode_name(rr_name)
        add += rn + struct.pack("!HHIH", rr_type, rr_class, ttl, len(rdata)) + rdata

    flags = 0x8000 | 0x0080 | (rcode & 0xF)
    header = struct.pack(
        "!HHHHHH",
        qid,
        flags,
        1,
        len(answers or []),
        len(authority or []),
        len(additional or []),
    )
    return header + question + body + auth + add


A_RDATA = b"\x5d\xb8\xd8\x22"  # 93.184.216.34
CNAME_RDATA = encode_name("target.example.net")


class TestParseMessage(unittest.TestCase):
    def test_parses_a_record(self):
        raw = _response("example.com", QTYPE["A"], [("example.com", QTYPE["A"], 1, 300, A_RDATA)])
        msg = parse_message(raw, expect_id=0x4321)
        self.assertEqual(msg.rcode, RCODE["NOERROR"])
        self.assertEqual(msg.addresses(), ["93.184.216.34"])
        self.assertEqual(msg.answers[0].ttl, 300)

    def test_rejects_wrong_transaction_id(self):
        raw = _response("example.com", QTYPE["A"], [])
        with self.assertRaises(DNSFormatError):
            parse_message(raw, expect_id=0x9999)

    def test_nxdomain_flag(self):
        raw = _response("nope.example.com", QTYPE["A"], [], rcode=RCODE["NXDOMAIN"])
        msg = parse_message(raw)
        self.assertTrue(msg.is_nxdomain)
        self.assertFalse(msg.answers)

    def test_noerror_nodata_is_not_nxdomain(self):
        # The distinction that matters: several large zones answer NOERROR
        # with zero records for names that do not exist.
        raw = _response("nope.example.com", QTYPE["A"], [], rcode=RCODE["NOERROR"])
        msg = parse_message(raw)
        self.assertFalse(msg.is_nxdomain)
        self.assertEqual(len(msg.answers), 0)

    def test_parses_cname(self):
        raw = _response(
            "www.example.com",
            QTYPE["A"],
            [
                ("www.example.com", QTYPE["CNAME"], 1, 60, CNAME_RDATA),
                ("target.example.net", QTYPE["A"], 1, 60, A_RDATA),
            ],
        )
        msg = parse_message(raw)
        self.assertEqual(msg.cnames(), ["target.example.net"])
        self.assertEqual(msg.addresses(), ["93.184.216.34"])

    def test_opt_record_is_not_an_answer(self):
        # OPT (type 41) rides along in the additional section even on
        # NXDOMAIN. If it leaked into `answers`, every existence check would
        # report a hit, so this is a regression guard.
        opt_rdata = b""
        raw = _response(
            "nope.example.com",
            QTYPE["A"],
            [],
            rcode=RCODE["NXDOMAIN"],
            additional=[("", QTYPE["OPT"], 1232, 0, opt_rdata)],
        )
        msg = parse_message(raw)
        self.assertEqual(len(msg.answers), 0)
        self.assertFalse(any(rr.rtype == QTYPE["OPT"] for rr in msg.answers))
        self.assertFalse(msg.resolved())

    def test_truncated_flag(self):
        raw = _response("example.com", QTYPE["A"], [])
        patched = bytearray(raw)
        patched[2] |= 0x02  # set TC
        msg = parse_message(bytes(patched))
        self.assertTrue(msg.truncated)

    def test_soa_in_authority(self):
        soa = (
            encode_name("ns.example.com")
            + encode_name("host.example.com")
            + struct.pack("!IIIII", 1, 2, 3, 4, 60)
        )
        raw = _response(
            "nope.example.com",
            QTYPE["A"],
            [],
            rcode=RCODE["NOERROR"],
            authority=[("example.com", QTYPE["SOA"], 1, 60, soa)],
        )
        msg = parse_message(raw)
        self.assertIsNotNone(msg.soa())
        self.assertTrue(msg.is_dangling())

    def test_malformed_packet_raises(self):
        with self.assertRaises(DNSFormatError):
            parse_message(b"\x00\x01")

    def test_rdata_past_end_raises(self):
        raw = _response("example.com", QTYPE["A"], [("example.com", QTYPE["A"], 1, 300, A_RDATA)])
        with self.assertRaises(DNSFormatError):
            parse_message(raw[:-2])


class TestHostValidation(unittest.TestCase):
    def test_clean_hostname_accepts_valid(self):
        from subpy.sources.base import clean_hostname

        self.assertEqual(clean_hostname("WWW.Example.com"), "www.example.com")
        self.assertEqual(clean_hostname("a.b.example.com."), "a.b.example.com")

    def test_clean_hostname_rejects_junk(self):
        from subpy.sources.base import clean_hostname

        # The contract is Optional[str]: None means "not a usable hostname".
        for bad in (
            "",
            "*.example.com",
            "1.2.3.4",
            "-bad.example.com",
            "a" * 300,
            "example",
            "a..b.com",
            "user@example.com",
        ):
            self.assertIsNone(clean_hostname(bad), f"accepted {bad!r}")

    def test_clean_hostname_strips_url_parts(self):
        from subpy.sources.base import clean_hostname

        self.assertEqual(clean_hostname("https://example.com/x"), "example.com")
        self.assertEqual(clean_hostname("EXAMPLE.com:8443"), "example.com")
        self.assertEqual(clean_hostname("  sub.example.com  "), "sub.example.com")

    def test_is_valid_name(self):
        from subpy.core.dns import is_valid_name

        self.assertTrue(is_valid_name("a.example.com"))
        for bad in ("*", "*.example.com", "bad-.com", "-bad.com", "a..b", "localhost"):
            self.assertFalse(is_valid_name(bad), f"accepted {bad!r}")

    def test_belongs_to(self):
        from subpy.sources.base import belongs_to

        self.assertTrue(belongs_to("a.example.com", "example.com"))
        self.assertTrue(belongs_to("example.com", "example.com"))
        self.assertFalse(belongs_to("notexample.com", "example.com"))
        self.assertFalse(belongs_to("a.example.com.evil.com", "example.com"))


if __name__ == "__main__":
    unittest.main()
