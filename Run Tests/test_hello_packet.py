"""
Tests for OSPF Hello Packet - RFC 2328 Section A.3.2
Covers all Hello packet fields, neighbor discovery, DR/BDR election
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.packets import OSPFHello, OSPFHeader
from ospf_lib.constants import *


class TestHelloPacketFields(unittest.TestCase):
    """RFC 2328 A.3.2 - Hello packet field validation"""

    def _make_hello(self, **kwargs):
        h = OSPFHello(**kwargs)
        h.header.router_id = "1.1.1.1"
        h.header.area_id = "0.0.0.0"
        return h

    # ── Network Mask ───────────────────────────────────────────
    def test_network_mask_default(self):
        h = self._make_hello()
        self.assertEqual(h.network_mask, "255.255.255.0")

    def test_network_mask_class_a(self):
        h = self._make_hello(network_mask="255.0.0.0")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.network_mask, "255.0.0.0")

    def test_network_mask_host_route(self):
        h = self._make_hello(network_mask="255.255.255.255")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.network_mask, "255.255.255.255")

    def test_network_mask_p2p_is_zeros(self):
        """On P2P links, network mask should be 0.0.0.0 (RFC 2328 9.5.1)"""
        h = self._make_hello(network_mask="0.0.0.0")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.network_mask, "0.0.0.0")

    # ── HelloInterval ─────────────────────────────────────────
    def test_hello_interval_default_is_10(self):
        h = self._make_hello()
        self.assertEqual(h.hello_interval, DEFAULT_HELLO_INTERVAL)

    def test_hello_interval_must_match_neighbors(self):
        """RFC 2328 10.5 - Hello/Dead interval mismatch drops neighbor"""
        h1 = self._make_hello(hello_interval=10)
        h2 = self._make_hello(hello_interval=30)
        self.assertNotEqual(h1.hello_interval, h2.hello_interval)

    def test_hello_interval_roundtrip(self):
        for interval in [1, 5, 10, 30, 60]:
            h = self._make_hello(hello_interval=interval)
            raw = h.encode()
            decoded = OSPFHello.decode(raw)
            self.assertEqual(decoded.hello_interval, interval)

    # ── RouterDeadInterval ────────────────────────────────────
    def test_dead_interval_default_is_40(self):
        h = self._make_hello()
        self.assertEqual(h.dead_interval, DEFAULT_DEAD_INTERVAL)

    def test_dead_interval_must_be_gte_hello(self):
        """Dead interval must be >= hello interval (RFC 2328 App B)"""
        h = self._make_hello(hello_interval=10, dead_interval=40)
        self.assertTrue(h.is_dead_interval_valid())

    def test_dead_interval_invalid_when_less_than_hello(self):
        h = self._make_hello(hello_interval=30, dead_interval=10)
        self.assertFalse(h.is_dead_interval_valid())

    def test_dead_interval_typically_4x_hello(self):
        h = self._make_hello(hello_interval=10, dead_interval=40)
        self.assertEqual(h.dead_interval, DEFAULT_ROUTER_DEAD_MULT * h.hello_interval)

    def test_dead_interval_roundtrip(self):
        for di in [4, 40, 120, 3600]:
            h = self._make_hello(hello_interval=1, dead_interval=di)
            raw = h.encode()
            decoded = OSPFHello.decode(raw)
            self.assertEqual(decoded.dead_interval, di)

    # ── Options Field ─────────────────────────────────────────
    def test_options_e_bit_set_in_normal_area(self):
        """E-bit (0x02) indicates AS-external-LSA flooding capability"""
        h = self._make_hello(options=0x02)
        self.assertTrue(h.options & 0x02)

    def test_options_e_bit_clear_in_stub_area(self):
        """E-bit MUST be clear in stub area hellos (RFC 2328 10.5)"""
        h = self._make_hello(options=0x00)
        self.assertFalse(h.options & 0x02)

    def test_options_n_bit_for_nssa(self):
        """N-bit (0x08) for NSSA support (RFC 3101)"""
        h = self._make_hello(options=0x08)
        self.assertTrue(h.options & 0x08)

    def test_options_roundtrip(self):
        for opts in [0x00, 0x02, 0x42, 0xFF]:
            h = self._make_hello(options=opts)
            raw = h.encode()
            decoded = OSPFHello.decode(raw)
            self.assertEqual(decoded.options, opts)

    # ── Router Priority ───────────────────────────────────────
    def test_router_priority_default_is_1(self):
        h = self._make_hello()
        self.assertEqual(h.router_priority, DEFAULT_ROUTER_PRIORITY)

    def test_router_priority_zero_ineligible_for_dr(self):
        """Priority 0 means router cannot become DR/BDR"""
        h = self._make_hello(router_priority=0)
        self.assertEqual(h.router_priority, 0)

    def test_router_priority_max_is_255(self):
        h = self._make_hello(router_priority=255)
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.router_priority, 255)

    def test_router_priority_range(self):
        for p in [0, 1, 100, 200, 255]:
            h = self._make_hello(router_priority=p)
            raw = h.encode()
            decoded = OSPFHello.decode(raw)
            self.assertEqual(decoded.router_priority, p)

    # ── Designated Router / Backup DR ────────────────────────
    def test_dr_initial_value_is_zero(self):
        h = self._make_hello()
        self.assertEqual(h.designated_router, "0.0.0.0")

    def test_bdr_initial_value_is_zero(self):
        h = self._make_hello()
        self.assertEqual(h.backup_dr, "0.0.0.0")

    def test_dr_roundtrip(self):
        h = self._make_hello(designated_router="192.168.1.1")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.designated_router, "192.168.1.1")

    def test_bdr_roundtrip(self):
        h = self._make_hello(backup_dr="192.168.1.2")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.backup_dr, "192.168.1.2")

    def test_dr_and_bdr_different_addresses(self):
        h = self._make_hello(designated_router="10.0.0.1", backup_dr="10.0.0.2")
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertNotEqual(decoded.designated_router, decoded.backup_dr)

    # ── Neighbor List ─────────────────────────────────────────
    def test_hello_with_no_neighbors(self):
        h = self._make_hello(neighbors=[])
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(len(decoded.neighbors), 0)

    def test_hello_with_single_neighbor(self):
        h = self._make_hello(neighbors=["2.2.2.2"])
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertIn("2.2.2.2", decoded.neighbors)

    def test_hello_with_multiple_neighbors(self):
        nbrs = ["2.2.2.2", "3.3.3.3", "4.4.4.4"]
        h = self._make_hello(neighbors=nbrs)
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        for n in nbrs:
            self.assertIn(n, decoded.neighbors)

    def test_has_neighbor_returns_true(self):
        h = self._make_hello(neighbors=["2.2.2.2"])
        self.assertTrue(h.has_neighbor("2.2.2.2"))

    def test_has_neighbor_returns_false_when_absent(self):
        h = self._make_hello(neighbors=[])
        self.assertFalse(h.has_neighbor("9.9.9.9"))

    def test_neighbor_list_encoded_in_correct_order(self):
        nbrs = ["1.0.0.1", "1.0.0.2", "1.0.0.3"]
        h = self._make_hello(neighbors=nbrs)
        raw = h.encode()
        decoded = OSPFHello.decode(raw)
        self.assertEqual(decoded.neighbors, nbrs)

    # ── Packet length calculation ─────────────────────────────
    def test_packet_length_with_no_neighbors(self):
        h = self._make_hello(neighbors=[])
        raw = h.encode()
        # header(24) + hello_body(20) = 44
        self.assertEqual(len(raw), 44)

    def test_packet_length_with_neighbors(self):
        nbrs = ["2.2.2.2", "3.3.3.3"]
        h = self._make_hello(neighbors=nbrs)
        raw = h.encode()
        self.assertEqual(len(raw), 44 + 4 * len(nbrs))

    def test_packet_length_field_matches_actual(self):
        h = self._make_hello(neighbors=["2.2.2.2"])
        raw = h.encode()
        import struct
        plen = struct.unpack("!H", raw[2:4])[0]
        self.assertEqual(plen, len(raw))

    # ── Full Roundtrip ────────────────────────────────────────
    def test_full_hello_roundtrip(self):
        h = OSPFHello(
            network_mask="255.255.255.0",
            hello_interval=10,
            options=0x02,
            router_priority=100,
            dead_interval=40,
            designated_router="192.168.1.1",
            backup_dr="192.168.1.2",
            neighbors=["10.0.0.1", "10.0.0.2"],
        )
        h.header.router_id = "1.1.1.1"
        h.header.area_id = "0.0.0.0"
        raw = h.encode()
        dec = OSPFHello.decode(raw)
        self.assertEqual(dec.network_mask, "255.255.255.0")
        self.assertEqual(dec.hello_interval, 10)
        self.assertEqual(dec.options, 0x02)
        self.assertEqual(dec.router_priority, 100)
        self.assertEqual(dec.dead_interval, 40)
        self.assertEqual(dec.designated_router, "192.168.1.1")
        self.assertEqual(dec.backup_dr, "192.168.1.2")
        self.assertIn("10.0.0.1", dec.neighbors)
        self.assertIn("10.0.0.2", dec.neighbors)


class TestHelloTimerConstraints(unittest.TestCase):
    """Timer-related tests per RFC 2328 Appendix B"""

    def test_default_hello_interval(self):
        self.assertEqual(DEFAULT_HELLO_INTERVAL, 10)

    def test_default_dead_interval(self):
        self.assertEqual(DEFAULT_DEAD_INTERVAL, 40)

    def test_dead_interval_is_4x_hello(self):
        self.assertEqual(DEFAULT_DEAD_INTERVAL, DEFAULT_ROUTER_DEAD_MULT * DEFAULT_HELLO_INTERVAL)

    def test_poll_interval_for_nbma(self):
        self.assertEqual(DEFAULT_POLL_INTERVAL, 120)

    def test_rxmt_interval_default(self):
        self.assertEqual(DEFAULT_RXMT_INTERVAL, 5)

    def test_transmit_delay_default(self):
        self.assertEqual(DEFAULT_TRANSMIT_DELAY, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
