"""Minimal, dependency-free DNS wire-format encoder/decoder.

This module speaks DNS directly over the wire so `subpy` never needs a
third-party resolver library. Everything here is pure stdlib and works
identically on Linux, macOS, Windows and Termux (Android).

Design notes
------------
* Only what a subdomain enumerator needs is implemented: query building
  (A, AAAA, CNAME, NS, MX, TXT, SOA, CAA, ANY) and response parsing
  with full compression-pointer support, EDNS0, and TCP fallback on TC=1.
* Parsing is defensive: malformed packets raise :class:`DNSFormatError`
  instead of crashing a worker, and every read is bounds-checked.
* Names are returned as lowercase, dot-terminated-free ASCII strings.
"""

from __future__ import annotations

import ipaddress
import random
import re
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "QTYPE",
    "QTYPE_NAMES",
    "RCODE",
    "RCODE_NAMES",
    "DNSFormatError",
    "DNSQueryError",
    "ResourceRecord",
    "DNSMessage",
    "build_query",
    "parse_message",
    "encode_name",
    "ip_type",
    "is_ip",
    "normalize_name",
    "is_valid_name",
]

# --------------------------------------------------------------------------
# Record type / class / status codes
# --------------------------------------------------------------------------

QTYPE: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "MD": 3,
    "MF": 4,
    "CNAME": 5,
    "SOA": 6,
    "MB": 7,
    "MG": 8,
    "MR": 9,
    "PTR": 12,
    "HINFO": 13,
    "MINFO": 14,
    "MX": 15,
    "TXT": 16,
    "RP": 17,
    "AFSDB": 18,
    "SIG": 24,
    "KEY": 25,
    "AAAA": 28,
    "LOC": 29,
    "SRV": 33,
    "NAPTR": 35,
    "CERT": 37,
    "DNAME": 39,
    "OPT": 41,
    "DS": 43,
    "SSHFP": 44,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "NSEC3": 50,
    "NSEC3PARAM": 51,
    "TLSA": 52,
    "SMIMEA": 53,
    "HIP": 55,
    "CDS": 59,
    "CDNSKEY": 60,
    "OPENPGPKEY": 61,
    "CSYNC": 62,
    "ZONEMD": 63,
    "SVCB": 64,
    "HTTPS": 65,
    "SPF": 99,
    "EUI48": 108,
    "EUI64": 109,
    "TKEY": 249,
    "TSIG": 250,
    "IXFR": 251,
    "AXFR": 252,
    "ANY": 255,
    "URI": 256,
    "CAA": 257,
}

QTYPE_NAMES: dict[int, str] = {v: k for k, v in QTYPE.items()}

QCLASS_IN = 1
QCLASS_ANY = 255

RCODE: dict[str, int] = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMP": 4,
    "REFUSED": 5,
    "YXDOMAIN": 6,
    "YXRRSET": 7,
    "NXRRSET": 8,
    "NOTAUTH": 9,
    "NOTZONE": 10,
    "BADVERS": 16,
}

RCODE_NAMES: dict[int, str] = {v: k for k, v in RCODE.items()}

# Flags
FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080
FLAG_AD = 0x0020
FLAG_CD = 0x0010

MAX_LABEL = 63
MAX_NAME = 255
MAX_PACKET_UDP = 4096  # advertised via EDNS0

# Record types that carry an IP the caller may care about.
ADDRESS_TYPES = frozenset({QTYPE["A"], QTYPE["AAAA"]})


class DNSFormatError(ValueError):
    """Raised when a packet cannot be decoded."""


class DNSQueryError(RuntimeError):
    """Raised when a query cannot be completed (network/timeout)."""


# --------------------------------------------------------------------------
# Name helpers
# --------------------------------------------------------------------------


_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?$", re.IGNORECASE)


def normalize_name(name: str) -> str:
    """Return a canonical query name: lowercase, no trailing dot.

    Accepts the shapes users actually paste - ``https://Example.COM/path``,
    ``user@example.com``, ``example.com:8443`` - and reduces them to the bare
    hostname. Internationalised names are punycode-encoded so the wire format
    stays ASCII-safe; this also makes deduplication reliable.

    Returns ``""`` for anything that cannot be a valid DNS name, so callers
    can use a truthiness check rather than catching exceptions.
    """
    if not name:
        return ""
    name = name.strip().strip("\x00")

    # Tolerate URLs, credentials, ports and paths pasted from a browser.
    if "://" in name:
        name = name.split("://", 1)[1]
    name = name.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in name:
        name = name.rsplit("@", 1)[1]
    if name.startswith("["):  # IPv6 literal
        return ""
    if name.count(":") == 1:  # host:port
        name = name.split(":", 1)[0]

    name = name.strip().rstrip(".")
    if not name:
        return ""

    # Fast path: already ASCII.
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        try:
            name = name.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            # Fall back to a lossy ASCII form rather than exploding.
            name = name.encode("ascii", "ignore").decode("ascii")

    name = name.lower()
    if len(name) > MAX_NAME - 1:
        return ""
    for label in name.split("."):
        if not label or len(label) > MAX_LABEL:
            return ""
    return name


def is_valid_name(name: str) -> bool:
    """True when *name* is a syntactically valid hostname.

    Rejects wildcards and bare ``*``: those are query patterns, never hosts,
    and letting one through would poison deduplication and output.
    """
    if not name or "*" in name or len(name) > MAX_NAME - 1:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > MAX_LABEL:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not _LABEL_RE.match(label):
            return False
    return True


def is_ip(value: str) -> bool:
    """True when *value* is a valid IPv4/IPv6 literal."""
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def ip_type(value: str) -> int | None:
    """Return the QTYPE matching an IP literal, or ``None``."""
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return QTYPE["A"] if ip.version == 4 else QTYPE["AAAA"]


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format (uncompressed)."""
    name = normalize_name(name)
    if not name:
        return b"\x00"
    out = bytearray()
    total = 1
    for label in name.split("."):
        if not label:
            raise DNSFormatError(f"empty label in {name!r}")
        raw = label.encode("ascii", "ignore")
        if not raw:
            raise DNSFormatError(f"label has no ASCII content: {label!r}")
        if len(raw) > MAX_LABEL:
            raise DNSFormatError(f"label too long ({len(raw)} > {MAX_LABEL}): {label!r}")
        total += len(raw) + 1
        if total > MAX_NAME:
            raise DNSFormatError(f"name too long ({total} > {MAX_NAME}): {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed name starting at *offset*.

    Returns ``(name, next_offset)`` where ``next_offset`` points just past
    the name in the *original* (uncompressed) stream, ready for the RR
    fields that follow.
    """
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen = set()
    hops = 0

    while True:
        if offset >= len(data):
            raise DNSFormatError("name runs past end of packet")
        length = data[offset]

        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            hops += 1
            if hops > 64:
                raise DNSFormatError("compression pointer loop")
            if pointer in seen:
                raise DNSFormatError("compression pointer cycle")
            seen.add(pointer)
            if pointer >= len(data):
                raise DNSFormatError("compression pointer out of range")
            offset = pointer
            continue

        if length & 0xC0:  # 0x40 / 0x80 reserved
            raise DNSFormatError(f"reserved label type 0x{length:02x}")

        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break

        if offset + length > len(data):
            raise DNSFormatError("truncated label")
        label = data[offset : offset + length]
        offset += length
        # Labels are normally ASCII; keep anything else escaped and readable.
        labels.append(label.decode("ascii", "replace"))

        if not jumped:
            next_offset = offset

    name = ".".join(labels)
    return name.lower(), next_offset


# --------------------------------------------------------------------------
# Resource records
# --------------------------------------------------------------------------


@dataclass(slots=True)
class ResourceRecord:
    """A single decoded DNS resource record."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    data: bytes
    # Decoded convenience views (only one is typically filled).
    address: str | None = None
    target: str | None = None
    text: str | None = None
    preference: int | None = None

    @property
    def type_name(self) -> str:
        return QTYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    def value(self) -> str:
        """Best human-readable representation of the record payload."""
        if self.address:
            return self.address
        if self.target is not None:
            if self.preference is not None:
                return f"{self.preference} {self.target}"
            return self.target
        if self.text is not None:
            return self.text
        return self.data.hex()


@dataclass(slots=True)
class DNSMessage:
    """A decoded DNS response."""

    id: int
    flags: int
    question: list[tuple[str, int, int]] = field(default_factory=list)
    answers: list[ResourceRecord] = field(default_factory=list)
    authority: list[ResourceRecord] = field(default_factory=list)
    additional: list[ResourceRecord] = field(default_factory=list)

    # ---- convenience -------------------------------------------------
    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def truncated(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & FLAG_AA)

    @property
    def is_nxdomain(self) -> bool:
        return self.rcode == RCODE["NXDOMAIN"]

    @property
    def is_noerror(self) -> bool:
        return self.rcode == RCODE["NOERROR"]

    @property
    def answer_count(self) -> int:
        return len(self.answers)

    def addresses(self) -> list[str]:
        """All A/AAAA addresses in the answer section."""
        return [r.address for r in self.answers if r.address]

    def cnames(self) -> list[str]:
        """CNAME targets, in the order returned."""
        return [r.target for r in self.answers if r.rtype == QTYPE["CNAME"] and r.target]

    def txt(self) -> list[str]:
        return [r.text for r in self.answers if r.rtype == QTYPE["TXT"] and r.text is not None]

    def soa(self) -> ResourceRecord | None:
        for section in (self.answers, self.authority):
            for rr in section:
                if rr.rtype == QTYPE["SOA"]:
                    return rr
        return None

    def ns_names(self) -> list[str]:
        return [r.target for r in self.answers if r.rtype == QTYPE["NS"] and r.target]

    def nsec_names(self) -> list[str]:
        """Names enumerated by NSEC records (for zone walking)."""
        out: list[str] = []
        for rr in self.answers + self.authority:
            if rr.rtype == QTYPE["NSEC"] and rr.target:
                out.append(rr.target)
        return out

    def resolved(self) -> bool:
        """True when this answer actually pins the name to something."""
        if self.rcode not in (RCODE["NOERROR"],):
            return False
        return any(rr.rtype in ADDRESS_TYPES or rr.rtype == QTYPE["CNAME"] for rr in self.answers)

    def is_dangling(self) -> bool:
        """NOERROR + SOA in authority + no answers => NODATA (not NXDOMAIN)."""
        return self.rcode == RCODE["NOERROR"] and not self.answers and bool(self.authority)


# --------------------------------------------------------------------------
# Query construction
# --------------------------------------------------------------------------


def build_query(
    name: str,
    qtype: int = QTYPE["A"],
    qid: int | None = None,
    edns: bool = True,
    edns_size: int = 1232,
    rd: bool = True,
    cd: bool = False,
    dnssec: bool = False,
) -> tuple[bytes, int]:
    """Build a DNS query packet.

    Returns ``(packet, query_id)``. EDNS0 (and optionally DO) is advertised
    so large answers arrive over UDP instead of being truncated.
    """
    if qid is None:
        qid = random.getrandbits(16)

    flags = FLAG_RD if rd else 0
    if cd:
        flags |= FLAG_CD

    arcount = 1 if edns else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, arcount)

    try:
        qname = encode_name(name)
    except DNSFormatError:
        raise
    question = qname + struct.pack("!HH", qtype, QCLASS_IN)

    packet = bytearray(header + question)
    if edns:
        # OPT pseudo-RR: root name, type 41, class = UDP payload size,
        # TTL = extended-rcode/flags (DO bit = 0x8000 when dnssec).
        opt_ttl = 0x00008000 if dnssec else 0
        packet += b"\x00" + struct.pack("!HHIH", QTYPE["OPT"], edns_size, opt_ttl, 0)
    return bytes(packet), qid


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def _parse_rdata(data: bytes, rtype: int, rclass: int, rdata_offset: int, rdlength: int) -> dict:
    """Decode the interesting parts of an RDATA blob into kwargs."""
    out: dict[str, Any] = {}
    end = rdata_offset + rdlength
    if end > len(data):
        raise DNSFormatError("rdata runs past end of packet")

    if rtype == QTYPE["A"]:
        if rdlength == 4:
            out["address"] = str(ipaddress.IPv4Address(data[rdata_offset:end]))
    elif rtype == QTYPE["AAAA"]:
        if rdlength == 16:
            out["address"] = str(ipaddress.IPv6Address(data[rdata_offset:end]))
    elif rtype in (QTYPE["CNAME"], QTYPE["NS"], QTYPE["PTR"], QTYPE["DNAME"]):
        target, _ = decode_name(data, rdata_offset)
        out["target"] = target
    elif rtype == QTYPE["MX"]:
        if rdlength >= 3:
            pref = struct.unpack("!H", data[rdata_offset : rdata_offset + 2])[0]
            target, _ = decode_name(data, rdata_offset + 2)
            out["preference"] = pref
            out["target"] = target
    elif rtype == QTYPE["SRV"]:
        if rdlength >= 7:
            pref = struct.unpack("!H", data[rdata_offset : rdata_offset + 2])[0]
            target, _ = decode_name(data, rdata_offset + 6)
            out["preference"] = pref
            out["target"] = target
    elif rtype in (QTYPE["TXT"], QTYPE["SPF"]):
        chunks: list[str] = []
        pos = rdata_offset
        while pos < end:
            ln = data[pos]
            pos += 1
            if pos + ln > end:
                break
            chunks.append(data[pos : pos + ln].decode("utf-8", "replace"))
            pos += ln
        out["text"] = "".join(chunks)
    elif rtype == QTYPE["SOA"]:
        mname, pos = decode_name(data, rdata_offset)
        rname, pos = decode_name(data, pos)
        out["target"] = mname
        out["text"] = rname
    elif rtype == QTYPE["NSEC"]:
        nxt, _ = decode_name(data, rdata_offset)
        out["target"] = nxt
    elif rtype == QTYPE["CAA"] and rdlength >= 2:
        flags_byte = data[rdata_offset]
        tag_len = data[rdata_offset + 1]
        tag_start = rdata_offset + 2
        tag = data[tag_start : tag_start + tag_len].decode("ascii", "replace")
        value = data[tag_start + tag_len : end].decode("utf-8", "replace")
        out["text"] = f"{tag}={value}"
        out["preference"] = flags_byte
    return out


def parse_message(data: bytes, expect_id: int | None = None) -> DNSMessage:
    """Decode a raw DNS packet into a :class:`DNSMessage`."""
    if len(data) < 12:
        raise DNSFormatError("packet shorter than DNS header")

    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if expect_id is not None and qid != expect_id:
        raise DNSFormatError(f"transaction id mismatch ({qid} != {expect_id})")

    msg = DNSMessage(id=qid, flags=flags)
    offset = 12

    for _ in range(qdcount):
        qname, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSFormatError("truncated question section")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        msg.question.append((qname, qtype, qclass))

    def _read_section(count: int) -> list[ResourceRecord]:
        nonlocal offset
        records: list[ResourceRecord] = []
        for _ in range(count):
            rname, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise DNSFormatError("truncated resource record")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            offset += rdlength
            if offset > len(data):
                raise DNSFormatError("rdata past end of packet")
            if rtype == QTYPE["OPT"]:
                # EDNS pseudo-record: not an answer, just skip.
                continue
            try:
                extras = _parse_rdata(data, rtype, rclass, rdata_offset, rdlength)
            except (DNSFormatError, ValueError, struct.error):
                extras = {}
            records.append(
                ResourceRecord(
                    name=rname,
                    rtype=rtype,
                    rclass=rclass,
                    ttl=ttl,
                    data=data[rdata_offset : rdata_offset + rdlength],
                    **extras,
                )
            )
        return records

    msg.answers = _read_section(ancount)
    msg.authority = _read_section(nscount)
    msg.additional = _read_section(arcount)
    return msg


def iter_addresses(records: Iterable[ResourceRecord]) -> Iterable[str]:
    for rr in records:
        if rr.address:
            yield rr.address
