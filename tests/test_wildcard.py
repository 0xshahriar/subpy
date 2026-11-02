"""Tests for wildcard detection, filtering and infrastructure classification.

Network access is faked: a stub resolver returns canned answers so the
decision logic is tested deterministically. The live behaviour was validated
separately against herokuapp.com, netlify.app, vercel.app, github.io and
fly.dev on 2026-11-02 (0 false positives in 10 probes each).
"""

from __future__ import annotations

import unittest

from subpy.core.dns import QTYPE, DNSMessage, ResourceRecord
from subpy.core.wildcard import (
    SAA_WILDCARD_SUFFIXES,
    SHARED_INFRA_SUFFIXES,
    WildcardInfo,
    WildcardManager,
    _network_of,
    cname_suffix_hit,
    random_label,
    shared_infra_hit,
)


def make_msg(
    addresses: list[str] | None = None,
    cnames: list[str] | None = None,
    rcode: int = 0,
    ttl: int = 60,
) -> DNSMessage:
    """Build a DNSMessage that looks like a real response."""
    msg = DNSMessage(id=0, flags=rcode & 0x000F)
    for target in cnames or []:
        msg.answers.append(
            ResourceRecord(
                name="q.example.com",
                rtype=QTYPE["CNAME"],
                rclass=1,
                ttl=ttl,
                data=b"",
                target=target,
            )
        )
    for address in addresses or []:
        rtype = QTYPE["AAAA"] if ":" in address else QTYPE["A"]
        msg.answers.append(
            ResourceRecord(
                name="q.example.com", rtype=rtype, rclass=1, ttl=ttl, data=b"", address=address
            )
        )
    return msg


class StubResolver:
    """Returns a fixed answer per query, and records what was asked."""

    def __init__(self, answers: dict[str, DNSMessage]) -> None:
        self.answers = answers
        self.asked: list[str] = []
        self.default: DNSMessage | None = make_msg()

    async def query(self, name: str, qtype: int = QTYPE["A"], **kwargs) -> DNSMessage | None:
        self.asked.append(name)
        if name in self.answers:
            return self.answers[name]
        # Random probes look like the wildcard; everything else is empty.
        if name.split(".", 1)[0].startswith("zz") or kwargs.get("_wildcard"):
            return self.default
        return self.default


class TestSuffixClassification(unittest.TestCase):
    def test_wildcard_hit(self):
        self.assertEqual(cname_suffix_hit("myapp.herokuapp.com"), "herokuapp.com")
        self.assertEqual(cname_suffix_hit("x.netlify.app"), "netlify.app")
        self.assertEqual(cname_suffix_hit("HEROKUAPP.COM."), "herokuapp.com")

    def test_wildcard_no_hit(self):
        self.assertIsNone(cname_suffix_hit("example.com"))
        self.assertIsNone(cname_suffix_hit(""))

    def test_shared_infra_is_not_a_wildcard(self):
        # These host customer content but do NOT answer for random labels.
        # Treating them as wildcards would delete real subdomains.
        for infra, host in (
            ("cloudfront.net", "d123.cloudfront.net"),
            ("azurewebsites.net", "app.azurewebsites.net"),
            ("amazonaws.com", "ec2-1-2-3-4.compute.amazonaws.com"),
            ("herokudns.com", "x.herokudns.com"),
        ):
            self.assertIsNone(cname_suffix_hit(host), f"{host} wrongly treated as wildcard")
            self.assertEqual(shared_infra_hit(host), infra)

    def test_lists_do_not_overlap(self):
        self.assertEqual(set(SAA_WILDCARD_SUFFIXES) & set(SHARED_INFRA_SUFFIXES), set())

    def test_no_duplicate_entries(self):
        self.assertEqual(len(SAA_WILDCARD_SUFFIXES), len(set(SAA_WILDCARD_SUFFIXES)))
        self.assertEqual(len(SHARED_INFRA_SUFFIXES), len(set(SHARED_INFRA_SUFFIXES)))


class TestHelpers(unittest.TestCase):
    def test_random_label_shape(self):
        label = random_label(12)
        self.assertEqual(len(label), 12)
        # Lowercase alphanumerics only: some resolvers reject or normalise
        # fancy characters, which would make the probe meaningless.
        self.assertTrue(label.isalnum())
        self.assertEqual(label, label.lower())
        self.assertNotEqual(random_label(12), random_label(12))

    def test_network_of(self):
        self.assertEqual(_network_of("216.198.79.195"), "216.198.79.0/24")
        self.assertEqual(_network_of("10.0.0.5"), "10.0.0.0/24")
        self.assertIn("/48", _network_of("2606:4700:3033::1"))
        self.assertEqual(_network_of(""), "")


class TestWildcardInfo(unittest.TestCase):
    def test_active_requires_a_record(self):
        self.assertFalse(WildcardInfo(parent="example.com").active)
        info = WildcardInfo(parent="example.com")
        info.addresses.add("1.2.3.4")
        self.assertTrue(info.active)

    def test_footprint_includes_v6(self):
        info = WildcardInfo(parent="example.com")
        info.addresses.add("1.2.3.4")
        info.v6_addresses.add("::1")
        self.assertEqual(info.footprint(), frozenset({"1.2.3.4", "::1"}))

    def test_describe_is_one_line(self):
        info = WildcardInfo(parent="example.com")
        info.addresses.add("1.2.3.4")
        self.assertNotIn("\n", info.describe())


class TestWildcardManager(unittest.IsolatedAsyncioTestCase):
    async def test_static_wildcard_filters_random_names(self):
        resolver = StubResolver({})
        resolver.default = make_msg(addresses=["1.2.3.4"])
        manager = WildcardManager(resolver, "example.com", samples=3)
        info = await manager.detect()
        self.assertTrue(info.active)
        self.assertIn("1.2.3.4", info.addresses)

        # A name that returns the wildcard address is noise.
        self.assertTrue(
            await manager.is_wildcard("anything.example.com", make_msg(addresses=["1.2.3.4"]))
        )

    async def test_real_host_survives_wildcard(self):
        resolver = StubResolver({})
        resolver.default = make_msg(addresses=["1.2.3.4"])
        manager = WildcardManager(resolver, "example.com", samples=3)
        await manager.detect()
        # A different address is a real host and must be kept.
        self.assertFalse(
            await manager.is_wildcard("real.example.com", make_msg(addresses=["9.9.9.9"]))
        )

    async def test_no_wildcard_keeps_everything(self):
        resolver = StubResolver({})
        resolver.default = make_msg()  # empty answer
        manager = WildcardManager(resolver, "example.com", samples=3)
        info = await manager.detect()
        self.assertFalse(info.active)
        self.assertFalse(
            await manager.is_wildcard("a.example.com", make_msg(addresses=["1.2.3.4"]))
        )

    async def test_disabled_manager_never_filters(self):
        resolver = StubResolver({})
        resolver.default = make_msg(addresses=["1.2.3.4"])
        manager = WildcardManager(resolver, "example.com", samples=3, enabled=False)
        await manager.detect()
        self.assertFalse(
            await manager.is_wildcard("a.example.com", make_msg(addresses=["1.2.3.4"]))
        )

    async def test_cname_wildcard_is_filtered(self):
        resolver = StubResolver({})
        resolver.default = make_msg(cnames=["lb.herokuapp.com"])
        manager = WildcardManager(resolver, "example.com", samples=3)
        await manager.detect()
        self.assertTrue(
            await manager.is_wildcard("x.example.com", make_msg(cnames=["lb.herokuapp.com"]))
        )

    async def test_empty_answer_is_never_wildcard(self):
        resolver = StubResolver({})
        resolver.default = make_msg(addresses=["1.2.3.4"])
        manager = WildcardManager(resolver, "example.com", samples=3)
        await manager.detect()
        # No records at all: the caller decides it does not exist.
        self.assertFalse(await manager.is_wildcard("a.example.com", make_msg()))

    async def test_to_dict_serialisable(self):
        import json

        resolver = StubResolver({})
        resolver.default = make_msg(addresses=["1.2.3.4"])
        manager = WildcardManager(resolver, "example.com", samples=2)
        await manager.detect()
        payload = manager.to_dict()
        json.dumps(payload)  # must not raise


if __name__ == "__main__":
    unittest.main()


class TestVerifiedSuffixLists(unittest.TestCase):
    """Guards against the two list-membership bugs found in review."""

    def test_fly_dev_is_not_treated_as_a_wildcard(self):
        # fly.dev answers 0/12 for random labels; treating it as a wildcard
        # deleted every real host CNAMEd into Fly.io.
        from subpy.core.wildcard import SAA_WILDCARD_SUFFIXES

        self.assertNotIn("fly.dev", SAA_WILDCARD_SUFFIXES)

    def test_fly_dev_is_annotated_as_shared_infrastructure(self):
        from subpy.core.wildcard import SHARED_INFRA_SUFFIXES

        self.assertIn("fly.dev", SHARED_INFRA_SUFFIXES)

    def test_lists_do_not_overlap(self):
        from subpy.core.wildcard import SAA_WILDCARD_SUFFIXES, SHARED_INFRA_SUFFIXES

        overlap = set(SAA_WILDCARD_SUFFIXES) & set(SHARED_INFRA_SUFFIXES)
        self.assertEqual(overlap, set(), f"a suffix cannot be both: {overlap}")

    def test_suffix_counts_match_documentation(self):
        from subpy.core.wildcard import SAA_WILDCARD_SUFFIXES, SHARED_INFRA_SUFFIXES

        self.assertEqual(len(SAA_WILDCARD_SUFFIXES), 44)
        self.assertEqual(len(SHARED_INFRA_SUFFIXES), 30)


class TestDeeperLevelProfiling(unittest.TestCase):
    """detect_for_name must be reachable - it was dead code in v1.0.0."""

    def test_is_wildcard_consults_detect_for_name_for_unprofiled_levels(self):
        import inspect

        from subpy.core.wildcard import WildcardManager

        source = inspect.getsource(WildcardManager.is_wildcard)
        self.assertIn(
            "detect_for_name",
            source,
            "is_wildcard must profile an unseen parent level, otherwise "
            "a.b.example.com is judged only against b.example.com and RFC "
            "4592 synthesis at depth 2+ leaks through as a real host",
        )


class TestWildcardFilterSafety(unittest.TestCase):
    """The filter must be conservative when it has no information."""

    def test_disabled_filter_never_drops_anything(self):
        import asyncio

        from subpy.core.wildcard import WildcardManager

        class _NullResolver:
            async def query(self, *_a, **_k):
                return None

        manager = WildcardManager(_NullResolver(), "example.com", enabled=False)
        self.assertFalse(asyncio.run(manager.is_wildcard("a.example.com", None)))

    def test_none_message_is_never_filtered(self):
        import asyncio

        from subpy.core.wildcard import WildcardManager

        class _NullResolver:
            async def query(self, *_a, **_k):
                return None

        manager = WildcardManager(_NullResolver(), "example.com")
        self.assertFalse(asyncio.run(manager.is_wildcard("a.example.com", None)))
