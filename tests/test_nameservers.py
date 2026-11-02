"""The domain's own nameservers are delegation, not discovered subdomains.

Live case: hackerone.com is served by a.ns.hackerone.com and
b.ns.hackerone.com. Both resolve, so every source returns them, but reporting
them as findings is noise. The exclusion must be exact set membership — a
pattern like "starts with ns" would delete real hosts.
"""

import unittest

from subpy.core.nameservers import NameserverIndex


class TestNameserverIndex(unittest.TestCase):
    def setUp(self):
        self.index = NameserverIndex("hackerone.com")
        self.index.extend(["a.ns.hackerone.com", "b.ns.hackerone.com"])

    def test_delegation_members_are_excluded(self):
        self.assertIn("a.ns.hackerone.com", self.index)
        self.assertIn("b.ns.hackerone.com", self.index)

    def test_similar_names_are_kept(self):
        # These are ordinary hosts, not delegation. Excluding them by label
        # pattern would silently delete real infrastructure.
        for name in (
            "ns1.hackerone.com",
            "ns2.hackerone.com",
            "ns.hackerone.com",
            "ns0.hackerone.com",
            "nameserver.hackerone.com",
            "ns.internal.hackerone.com",
        ):
            with self.subTest(name=name):
                self.assertNotIn(name, self.index)

    def test_case_and_trailing_dot_are_normalised(self):
        self.assertIn("A.NS.HACKERONE.COM", self.index)
        self.assertIn("a.ns.hackerone.com.", self.index)

    def test_empty_index_excludes_nothing(self):
        empty = NameserverIndex("example.com")
        self.assertNotIn("ns1.example.com", empty)

    def test_disabled_index_excludes_nothing(self):
        off = NameserverIndex("hackerone.com", enabled=False)
        off.extend(["a.ns.hackerone.com", "b.ns.hackerone.com"])
        self.assertNotIn("a.ns.hackerone.com", off)

    def test_add_reports_novelty(self):
        self.assertTrue(self.index.add("c.ns.hackerone.com"))
        self.assertFalse(self.index.add("c.ns.hackerone.com"))

    def test_invalid_names_are_ignored(self):
        for bad in ("", "   ", "localhost", None, "."):
            with self.subTest(value=bad):
                self.assertFalse(self.index.add(bad))

    def test_skipped_names_are_recorded_once(self):
        self.index.note_skipped("a.ns.hackerone.com")
        self.index.note_skipped("a.ns.hackerone.com")
        self.assertEqual(self.index.skipped, ["a.ns.hackerone.com"])


class TestScanSummaryReportsExclusions(unittest.TestCase):
    def test_summary_exposes_the_count(self):
        from subpy.core.models import ScanSummary

        summary = ScanSummary(domain="hackerone.com")
        self.assertEqual(summary.nameservers_excluded, 0)
        self.assertIn("nameservers_excluded", summary.to_dict())


class TestHarvestFromRecords(unittest.TestCase):
    def test_ns_and_soa_targets_are_collected(self):
        from subpy.core.dns import QTYPE, DNSMessage, ResourceRecord

        msg = DNSMessage(id=0, flags=0)
        msg.answers.append(
            ResourceRecord(
                name="hackerone.com",
                rtype=QTYPE["NS"],
                rclass=1,
                ttl=60,
                data=b"",
                target="a.ns.hackerone.com",
            )
        )
        msg.authority.append(
            ResourceRecord(
                name="hackerone.com",
                rtype=QTYPE["SOA"],
                rclass=1,
                ttl=60,
                data=b"",
                target="ns-primary.hackerone.com",
            )
        )
        index = NameserverIndex("hackerone.com")
        index.add_from_message(msg)
        self.assertIn("a.ns.hackerone.com", index)
        self.assertIn("ns-primary.hackerone.com", index)

    def test_none_message_is_safe(self):
        index = NameserverIndex("example.com")
        index.add_from_message(None)
        self.assertEqual(len(index), 0)


if __name__ == "__main__":
    unittest.main()
