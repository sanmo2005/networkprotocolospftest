"""
Tests for OSPF LSA Types - RFC 2328 Section 12 / Appendix A.4
Covers: LSA Header, Router-LSA, Network-LSA, Summary-LSA, AS-External-LSA
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.packets import (
    LSAHeader, RouterLSA, RouterLink, NetworkLSA,
    SummaryLSA, ASExternalLSA, fletcher_checksum
)
from ospf_lib.constants import *


class TestLSAHeader(unittest.TestCase):
    """RFC 2328 A.4.1 - LSA Header field validation"""

    def _make_lsa_header(self, **kwargs):
        defaults = dict(
            age=0, options=0x02, lsa_type=LSA_TYPE_ROUTER,
            link_state_id="1.1.1.1", adv_router="1.1.1.1",
            seq_number=LSA_INITIAL_SEQUENCE, checksum=0, length=36,
        )
        defaults.update(kwargs)
        return LSAHeader(**defaults)

    # ── LS Age ──────────────────────────────────────────────────
    def test_lsa_age_initial_value_is_zero(self):
        h = self._make_lsa_header(age=0)
        self.assertEqual(h.age, 0)

    def test_lsa_age_max_age_3600(self):
        """MaxAge is 3600 seconds (RFC 2328 Section A.4.1)"""
        self.assertEqual(LSA_MAX_AGE, 3600)

    def test_lsa_age_is_maxage(self):
        h = self._make_lsa_header(age=3600)
        self.assertTrue(h.is_maxage())

    def test_lsa_age_below_max_is_not_maxage(self):
        h = self._make_lsa_header(age=3599)
        self.assertFalse(h.is_maxage())

    def test_lsa_age_roundtrip(self):
        for age in [0, 100, 1800, 3600]:
            h = self._make_lsa_header(age=age)
            raw = h.encode()
            decoded = LSAHeader.decode(raw)
            self.assertEqual(decoded.age, age)

    # ── Options Field ───────────────────────────────────────────
    def test_options_roundtrip(self):
        for opts in [0x00, 0x02, 0x22, 0xFF]:
            h = self._make_lsa_header(options=opts)
            raw = h.encode()
            decoded = LSAHeader.decode(raw)
            self.assertEqual(decoded.options, opts)

    # ── LSA Type ────────────────────────────────────────────────
    def test_all_lsa_types_valid(self):
        for lsa_type in LSA_TYPES:
            h = self._make_lsa_header(lsa_type=lsa_type)
            self.assertTrue(h.is_valid_type(), f"Type {lsa_type} should be valid")

    def test_invalid_lsa_type_rejected(self):
        h = self._make_lsa_header(lsa_type=99)
        self.assertFalse(h.is_valid_type())

    def test_lsa_type_values(self):
        self.assertEqual(LSA_TYPE_ROUTER,       1)
        self.assertEqual(LSA_TYPE_NETWORK,      2)
        self.assertEqual(LSA_TYPE_SUMMARY_NET,  3)
        self.assertEqual(LSA_TYPE_SUMMARY_ASBR, 4)
        self.assertEqual(LSA_TYPE_AS_EXTERNAL,  5)
        self.assertEqual(LSA_TYPE_NSSA_EXTERNAL,7)

    # ── Link State ID ───────────────────────────────────────────
    def test_link_state_id_roundtrip(self):
        for lsid in ["1.1.1.1", "10.0.0.0", "172.16.5.0", "192.168.255.0"]:
            h = self._make_lsa_header(link_state_id=lsid)
            raw = h.encode()
            decoded = LSAHeader.decode(raw)
            self.assertEqual(decoded.link_state_id, lsid)

    # ── Advertising Router ──────────────────────────────────────
    def test_adv_router_roundtrip(self):
        h = self._make_lsa_header(adv_router="3.3.3.3")
        raw = h.encode()
        decoded = LSAHeader.decode(raw)
        self.assertEqual(decoded.adv_router, "3.3.3.3")

    # ── Sequence Number ─────────────────────────────────────────
    def test_sequence_number_initial_min(self):
        """MinLSSequenceNumber = 0x80000001 (RFC 2328 A.4.1)"""
        self.assertEqual(LSA_INITIAL_SEQUENCE, 0x80000001)

    def test_sequence_number_max(self):
        """MaxLSSequenceNumber = 0x7FFFFFFF (RFC 2328 A.4.1)"""
        self.assertEqual(LSA_MAX_SEQUENCE, 0x7FFFFFFF)

    def test_sequence_number_roundtrip(self):
        h = self._make_lsa_header(seq_number=LSA_INITIAL_SEQUENCE)
        raw = h.encode()
        decoded = LSAHeader.decode(raw)
        self.assertEqual(decoded.seq_number, LSA_INITIAL_SEQUENCE)

    # ── Length Field ─────────────────────────────────────────────
    def test_lsa_header_size_is_20(self):
        self.assertEqual(LSAHeader.SIZE, 20)

    def test_lsa_length_roundtrip(self):
        h = self._make_lsa_header(length=36)
        raw = h.encode()
        decoded = LSAHeader.decode(raw)
        self.assertEqual(decoded.length, 36)

    # ── More Recent Comparison ───────────────────────────────────
    def test_more_recent_by_sequence(self):
        h1 = self._make_lsa_header(seq_number=0x80000001)
        h2 = self._make_lsa_header(seq_number=0x80000002)
        self.assertTrue(h2.is_more_recent(h1))
        self.assertFalse(h1.is_more_recent(h2))

    def test_more_recent_by_checksum_when_seq_equal(self):
        h1 = self._make_lsa_header(seq_number=0x80000001, checksum=100)
        h2 = self._make_lsa_header(seq_number=0x80000001, checksum=200)
        self.assertTrue(h2.is_more_recent(h1))

    def test_more_recent_maxage_wins_over_non_maxage(self):
        h1 = self._make_lsa_header(seq_number=0x80000001, age=3600)
        h2 = self._make_lsa_header(seq_number=0x80000001, age=0)
        self.assertTrue(h1.is_more_recent(h2))

    def test_more_recent_smaller_age_wins_when_diff_over_900(self):
        h1 = self._make_lsa_header(seq_number=0x80000001, checksum=100, age=0)
        h2 = self._make_lsa_header(seq_number=0x80000001, checksum=100, age=1000)
        self.assertTrue(h1.is_more_recent(h2))

    # ── Decode from short buffer ─────────────────────────────────
    def test_lsa_header_decode_short_raises(self):
        with self.assertRaises(ValueError):
            LSAHeader.decode(b'\x00' * 10)


class TestRouterLSA(unittest.TestCase):
    """RFC 2328 A.4.2 - Router-LSA"""

    def _make_router_lsa(self, flags=0, links=None):
        lsa = RouterLSA(flags=flags, links=links or [])
        lsa.header.adv_router = "1.1.1.1"
        lsa.header.link_state_id = "1.1.1.1"
        return lsa

    def test_router_lsa_type_is_1(self):
        lsa = self._make_router_lsa()
        self.assertEqual(lsa.header.lsa_type, LSA_TYPE_ROUTER)

    def test_router_flag_abr(self):
        lsa = self._make_router_lsa(flags=ROUTER_FLAG_B)
        self.assertTrue(lsa.is_abr())
        self.assertFalse(lsa.is_asbr())

    def test_router_flag_asbr(self):
        lsa = self._make_router_lsa(flags=ROUTER_FLAG_E)
        self.assertTrue(lsa.is_asbr())
        self.assertFalse(lsa.is_abr())

    def test_router_flag_virtual_link(self):
        lsa = self._make_router_lsa(flags=ROUTER_FLAG_V)
        self.assertTrue(lsa.is_virtual_link_endpoint())

    def test_router_flag_combined_abr_and_asbr(self):
        lsa = self._make_router_lsa(flags=ROUTER_FLAG_B | ROUTER_FLAG_E)
        self.assertTrue(lsa.is_abr())
        self.assertTrue(lsa.is_asbr())

    def test_no_links_encodes(self):
        lsa = self._make_router_lsa()
        raw = lsa.encode()
        self.assertGreaterEqual(len(raw), LSAHeader.SIZE + 4)

    def test_single_p2p_link(self):
        link = RouterLink(
            link_id="2.2.2.2", link_data="10.0.0.1",
            link_type=ROUTER_LINK_P2P, num_tos=0, metric=10
        )
        lsa = self._make_router_lsa(links=[link])
        raw = lsa.encode()
        self.assertGreater(len(raw), LSAHeader.SIZE + 4)

    def test_stub_link_type(self):
        link = RouterLink(link_type=ROUTER_LINK_STUB, metric=1)
        self.assertEqual(link.link_type, ROUTER_LINK_STUB)

    def test_transit_link_type(self):
        link = RouterLink(link_type=ROUTER_LINK_TRANSIT, metric=10)
        self.assertEqual(link.link_type, ROUTER_LINK_TRANSIT)

    def test_virtual_link_type(self):
        link = RouterLink(link_type=ROUTER_LINK_VIRTUAL, metric=0)
        self.assertEqual(link.link_type, ROUTER_LINK_VIRTUAL)

    def test_link_metric_range(self):
        for metric in [1, 10, 100, OSPF_MAX_METRIC]:
            link = RouterLink(metric=metric)
            raw = link.encode()
            decoded = RouterLink.decode(raw)
            self.assertEqual(decoded.metric, metric)

    def test_multiple_links(self):
        links = [
            RouterLink(link_id="2.2.2.2", link_type=ROUTER_LINK_P2P, metric=10),
            RouterLink(link_id="10.0.0.0", link_type=ROUTER_LINK_STUB, metric=1),
        ]
        lsa = self._make_router_lsa(links=links)
        raw = lsa.encode()
        # Header + 4-byte flags/count + 2 × 12-byte links
        self.assertEqual(len(raw), LSAHeader.SIZE + 4 + 2 * RouterLink.SIZE)


class TestNetworkLSA(unittest.TestCase):
    """RFC 2328 A.4.3 - Network-LSA"""

    def test_network_lsa_type_is_2(self):
        lsa = NetworkLSA()
        self.assertEqual(lsa.header.lsa_type, LSA_TYPE_NETWORK)

    def test_network_mask_encoded(self):
        lsa = NetworkLSA(network_mask="255.255.255.0")
        raw = lsa.encode()
        self.assertGreaterEqual(len(raw), LSAHeader.SIZE + 4)

    def test_attached_routers_included(self):
        lsa = NetworkLSA(
            network_mask="255.255.255.0",
            attached_routers=["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        )
        raw = lsa.encode()
        # Header + mask + 3 routers × 4 bytes
        self.assertEqual(len(raw), LSAHeader.SIZE + 4 + 3 * 4)

    def test_network_lsa_no_attached_routers(self):
        lsa = NetworkLSA(network_mask="255.255.255.0", attached_routers=[])
        raw = lsa.encode()
        self.assertEqual(len(raw), LSAHeader.SIZE + 4)


class TestSummaryLSA(unittest.TestCase):
    """RFC 2328 A.4.4 - Summary-LSA (Types 3 & 4)"""

    def test_summary_net_type_is_3(self):
        lsa = SummaryLSA()
        self.assertEqual(lsa.header.lsa_type, LSA_TYPE_SUMMARY_NET)

    def test_summary_asbr_type_is_4(self):
        from ospf_lib.packets import LSAHeader as LH
        h = LH(lsa_type=LSA_TYPE_SUMMARY_ASBR)
        lsa = SummaryLSA(header=h)
        self.assertEqual(lsa.header.lsa_type, LSA_TYPE_SUMMARY_ASBR)

    def test_summary_lsa_encodes_mask_and_metric(self):
        lsa = SummaryLSA(network_mask="255.255.255.0", metric=100)
        raw = lsa.encode()
        self.assertEqual(len(raw), LSAHeader.SIZE + 8)

    def test_summary_lsa_metric_max(self):
        lsa = SummaryLSA(metric=OSPF_MAX_METRIC)
        raw = lsa.encode()
        self.assertEqual(len(raw), LSAHeader.SIZE + 8)

    def test_summary_lsa_inter_area_route(self):
        lsa = SummaryLSA(
            network_mask="255.255.0.0",
            metric=20
        )
        lsa.header.link_state_id = "10.1.0.0"
        lsa.header.adv_router = "1.1.1.1"
        raw = lsa.encode()
        self.assertIsNotNone(raw)


class TestASExternalLSA(unittest.TestCase):
    """RFC 2328 A.4.5 - AS-External-LSA (Type 5)"""

    def test_as_external_lsa_type_is_5(self):
        lsa = ASExternalLSA()
        self.assertEqual(lsa.header.lsa_type, LSA_TYPE_AS_EXTERNAL)

    def test_metric_type_1_e_bit_clear(self):
        lsa = ASExternalLSA(e_bit=False, metric=10)
        self.assertEqual(lsa.metric_type, EXTERNAL_TYPE_1)

    def test_metric_type_2_e_bit_set(self):
        lsa = ASExternalLSA(e_bit=True, metric=10)
        self.assertEqual(lsa.metric_type, EXTERNAL_TYPE_2)

    def test_forwarding_address_zero_means_originator(self):
        """FA = 0.0.0.0 means use originating router (RFC 2328 16.4)"""
        lsa = ASExternalLSA(forwarding_addr="0.0.0.0")
        self.assertEqual(lsa.forwarding_addr, "0.0.0.0")

    def test_forwarding_address_non_zero(self):
        lsa = ASExternalLSA(forwarding_addr="10.0.0.1")
        raw = lsa.encode()
        self.assertIsNotNone(raw)

    def test_external_route_tag(self):
        lsa = ASExternalLSA(external_tag=0xDEADBEEF)
        raw = lsa.encode()
        self.assertIsNotNone(raw)

    def test_external_lsa_length(self):
        lsa = ASExternalLSA()
        raw = lsa.encode()
        # Header(20) + mask(4) + e_metric(4) + fwd_addr(4) + tag(4) = 36
        self.assertEqual(len(raw), 36)

    def test_default_metric_value(self):
        lsa = ASExternalLSA(metric=OSPF_DEFAULT_COST)
        self.assertEqual(lsa.metric, 10)


class TestLSAConstants(unittest.TestCase):
    """Verify all LSA-related constants per RFC 2328"""

    def test_lsa_initial_sequence_number(self):
        self.assertEqual(LSA_INITIAL_SEQUENCE, 0x80000001)

    def test_lsa_max_sequence_number(self):
        self.assertEqual(LSA_MAX_SEQUENCE, 0x7FFFFFFF)

    def test_lsa_max_age(self):
        self.assertEqual(LSA_MAX_AGE, 3600)

    def test_lsa_max_age_diff(self):
        self.assertEqual(LSA_MAX_AGE_DIFF, 900)

    def test_ls_refresh_time(self):
        """LS Refresh Time = 1800s (RFC 2328 App. B)"""
        self.assertEqual(DEFAULT_LS_REFRESH_TIME, 1800)

    def test_min_ls_interval(self):
        self.assertEqual(DEFAULT_MIN_LS_INTERVAL, 5)

    def test_min_ls_arrival(self):
        self.assertEqual(DEFAULT_MIN_LS_ARRIVAL, 1)

    def test_router_link_types_all_defined(self):
        self.assertEqual(ROUTER_LINK_P2P,     1)
        self.assertEqual(ROUTER_LINK_TRANSIT, 2)
        self.assertEqual(ROUTER_LINK_STUB,    3)
        self.assertEqual(ROUTER_LINK_VIRTUAL, 4)


class TestFletcherChecksum(unittest.TestCase):
    """RFC 905 Fletcher checksum used in LSA (RFC 2328 C.1)"""

    def test_checksum_returns_two_values(self):
        data = b'\x00' * 20
        result = fletcher_checksum(data)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_checksum_values_in_byte_range(self):
        data = bytes(range(20))
        c0, c1 = fletcher_checksum(data)
        self.assertGreaterEqual(c0, 0)
        self.assertLessEqual(c0, 255)
        self.assertGreaterEqual(c1, 0)
        self.assertLessEqual(c1, 255)

    def test_checksum_deterministic(self):
        data = b'\x01\x02\x03\x04' + b'\x00' * 16
        r1 = fletcher_checksum(data)
        r2 = fletcher_checksum(data)
        self.assertEqual(r1, r2)

    def test_different_data_different_checksum(self):
        d1 = b'\x01\x02\x03\x04' + b'\x00' * 16
        d2 = b'\x05\x06\x07\x08' + b'\x00' * 16
        self.assertNotEqual(fletcher_checksum(d1), fletcher_checksum(d2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
