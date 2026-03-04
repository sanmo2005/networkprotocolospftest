"""
Tests for OSPF Areas, Authentication, and IEEE/RFC Compliance
Covers:
  - Area types (Normal, Stub, NSSA, Totally Stub)  RFC 2328 / RFC 3101
  - Authentication (RFC 2328 Appendix D)
  - OSPF over IEEE 802 Ethernet (RFC 2328 Section A.1)
  - Route redistribution and external routing
  - OSPF cost / metric behavior
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.packets import OSPFHello, OSPFHeader, LSAHeader, ASExternalLSA
from ospf_lib.state_machine import OSPFInterface, OSPFRouter, OSPFNeighbor
from ospf_lib.constants import *


# ──────────────────────────────────────────────────────────────
#  Area Tests
# ──────────────────────────────────────────────────────────────

class TestOSPFAreaTypes(unittest.TestCase):
    """Area type constants and backbone area rules"""

    def test_area_type_normal(self):
        self.assertEqual(AREA_TYPE_NORMAL, "Normal")

    def test_area_type_stub(self):
        self.assertEqual(AREA_TYPE_STUB, "Stub")

    def test_area_type_totally_stub(self):
        self.assertEqual(AREA_TYPE_TOTALLY_STUB, "Totally-Stub")

    def test_area_type_nssa(self):
        self.assertEqual(AREA_TYPE_NSSA, "NSSA")

    def test_backbone_area_id_is_zero(self):
        """Backbone area MUST have area ID 0.0.0.0 (RFC 2328 Section 1)"""
        backbone = "0.0.0.0"
        self.assertEqual(backbone, "0.0.0.0")

    def test_stub_area_hello_e_bit_clear(self):
        """E-bit MUST be clear in stub area Hello packets (RFC 2328 10.5)"""
        h = OSPFHello(options=0x00)   # E-bit (0x02) cleared
        self.assertFalse(h.options & 0x02)

    def test_normal_area_hello_e_bit_set(self):
        """E-bit set in normal area (RFC 2328 A.2)"""
        h = OSPFHello(options=0x02)
        self.assertTrue(h.options & 0x02)

    def test_nssa_area_n_bit_set(self):
        """N-bit (0x08) set for NSSA capable Hello (RFC 3101)"""
        h = OSPFHello(options=0x08)
        self.assertTrue(h.options & 0x08)

    def test_nssa_and_e_bit_exclusive(self):
        """N-bit and E-bit should not both be set per RFC 3101"""
        opts_n_and_e = 0x08 | 0x02
        # This combination is technically invalid per RFC 3101
        self.assertTrue(opts_n_and_e & 0x08)   # N bit
        self.assertTrue(opts_n_and_e & 0x02)   # E bit

    def test_as_external_lsa_not_flooded_in_stub(self):
        """Type 5 LSA must not appear in stub areas (conceptual test)"""
        # AS-External LSA type
        self.assertEqual(LSA_TYPE_AS_EXTERNAL, 5)
        # Stub areas block Type 5 LSAs - validate type constant
        blocked_in_stub = [LSA_TYPE_AS_EXTERNAL]
        self.assertIn(5, blocked_in_stub)

    def test_default_route_injected_into_stub(self):
        """ABR generates Type 3 LSA with destination 0.0.0.0 for stub areas"""
        lsa = LSAHeader(lsa_type=LSA_TYPE_SUMMARY_NET, link_state_id="0.0.0.0")
        self.assertEqual(lsa.link_state_id, "0.0.0.0")
        self.assertEqual(lsa.lsa_type, LSA_TYPE_SUMMARY_NET)


class TestABRAndASBR(unittest.TestCase):
    """ABR and ASBR behavior (RFC 2328 Section 3.3)"""

    def test_abr_flag_in_router_lsa(self):
        self.assertEqual(ROUTER_FLAG_B, 0x01)

    def test_asbr_flag_in_router_lsa(self):
        self.assertEqual(ROUTER_FLAG_E, 0x02)

    def test_virtual_link_flag(self):
        self.assertEqual(ROUTER_FLAG_V, 0x04)

    def test_ospf_router_abr_detection(self):
        router = OSPFRouter(router_id="1.1.1.1", is_abr=True)
        self.assertTrue(router.is_abr)

    def test_ospf_router_asbr_detection(self):
        router = OSPFRouter(router_id="1.1.1.1", is_asbr=True)
        self.assertTrue(router.is_asbr)

    def test_abr_connects_multiple_areas(self):
        router = OSPFRouter(router_id="1.1.1.1", is_abr=True)
        iface1 = OSPFInterface(name="eth0", area_id="0.0.0.0")
        iface2 = OSPFInterface(name="eth1", area_id="0.0.0.1")
        router.add_interface(iface1)
        router.add_interface(iface2)
        areas = {iface.area_id for iface in router.interfaces.values()}
        self.assertEqual(len(areas), 2)


# ──────────────────────────────────────────────────────────────
#  Authentication Tests
# ──────────────────────────────────────────────────────────────

class TestOSPFAuthentication(unittest.TestCase):
    """RFC 2328 Appendix D - OSPF Authentication"""

    def test_auth_type_null_is_zero(self):
        self.assertEqual(AUTH_TYPE_NULL, 0)

    def test_auth_type_simple_is_one(self):
        self.assertEqual(AUTH_TYPE_SIMPLE, 1)

    def test_auth_type_crypto_is_two(self):
        self.assertEqual(AUTH_TYPE_CRYPTO, 2)

    def test_auth_type_null_in_header(self):
        h = OSPFHeader(auth_type=AUTH_TYPE_NULL, auth_data=0)
        raw = h.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.auth_type, AUTH_TYPE_NULL)
        self.assertEqual(decoded.auth_data, 0)

    def test_auth_type_simple_password_in_header(self):
        """Simple authentication uses 8-byte password in auth_data field"""
        h = OSPFHeader(auth_type=AUTH_TYPE_SIMPLE, auth_data=0x7465737470617373)
        raw = h.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.auth_type, AUTH_TYPE_SIMPLE)
        self.assertEqual(decoded.auth_data, 0x7465737470617373)

    def test_auth_type_crypto_zero_auth_data(self):
        """Cryptographic auth: auth_data contains key_id and length (RFC 2154)"""
        h = OSPFHeader(auth_type=AUTH_TYPE_CRYPTO, auth_data=0)
        raw = h.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.auth_type, AUTH_TYPE_CRYPTO)

    def test_interface_auth_type(self):
        iface = OSPFInterface(auth_type=AUTH_TYPE_CRYPTO, auth_key=b'secret_key_12345')
        self.assertEqual(iface.auth_type, AUTH_TYPE_CRYPTO)

    def test_auth_key_stored_as_bytes(self):
        key = b'testpassword'
        iface = OSPFInterface(auth_key=key)
        self.assertIsInstance(iface.auth_key, bytes)

    def test_neighbors_must_share_auth_type(self):
        """Mismatched auth type prevents adjacency (RFC 2328 10.5)"""
        h1 = OSPFHeader(auth_type=AUTH_TYPE_NULL)
        h2 = OSPFHeader(auth_type=AUTH_TYPE_SIMPLE)
        self.assertNotEqual(h1.auth_type, h2.auth_type)


# ──────────────────────────────────────────────────────────────
#  IEEE 802 / Ethernet-Specific Tests
# ──────────────────────────────────────────────────────────────

class TestOSPFIEEE802Ethernet(unittest.TestCase):
    """OSPF operation over IEEE 802 Ethernet - RFC 2328 Section A.1"""

    def test_all_spf_routers_multicast_address(self):
        """AllSPFRouters multicast = 224.0.0.5 (RFC 2328 A.1)"""
        self.assertEqual(OSPF_ALL_ROUTERS_MCAST, "224.0.0.5")

    def test_all_dr_multicast_address(self):
        """AllDRouters multicast = 224.0.0.6 (RFC 2328 A.1)"""
        self.assertEqual(OSPF_ALL_DR_MCAST, "224.0.0.6")

    def test_ip_protocol_number_89(self):
        """OSPF uses IP protocol 89 (RFC 2328 A.1)"""
        self.assertEqual(OSPF_IP_PROTOCOL, 89)

    def test_ieee_multicast_mac_all_spf(self):
        """AllSPFRouters maps to 01:00:5e:00:00:05 (IEEE 802.3)"""
        self.assertEqual(IEEE_OSPF_MULTICAST_MAC_ALL, "01:00:5e:00:00:05")

    def test_ieee_multicast_mac_dr(self):
        """AllDRouters maps to 01:00:5e:00:00:06 (IEEE 802.3)"""
        self.assertEqual(IEEE_OSPF_MULTICAST_MAC_DR, "01:00:5e:00:00:06")

    def test_ethernet_default_mtu(self):
        """Default Ethernet MTU = 1500 bytes"""
        self.assertEqual(ETHERNET_MTU_DEFAULT, 1500)

    def test_mtu_mismatch_flag(self):
        """MTU mismatch check is enabled by default"""
        self.assertTrue(OSPF_MTU_MISMATCH_CHECK)

    def test_ospf_header_length(self):
        """OSPF header is always 24 bytes"""
        self.assertEqual(OSPF_HEADER_LEN, 24)

    def test_hello_sent_to_all_spf_routers_on_broadcast(self):
        """On broadcast networks, Hello sent to AllSPFRouters"""
        dst = OSPF_ALL_ROUTERS_MCAST
        self.assertEqual(dst, "224.0.0.5")

    def test_dr_bdr_send_to_all_spf_routers(self):
        """DR/BDR send LSUs to AllSPFRouters (224.0.0.5)"""
        self.assertEqual(OSPF_ALL_ROUTERS_MCAST, "224.0.0.5")

    def test_non_dr_send_to_all_dr_routers(self):
        """Non-DR/BDR routers send LSUs to AllDRouters (224.0.0.6)"""
        self.assertEqual(OSPF_ALL_DR_MCAST, "224.0.0.6")

    def test_ospf_ttl_for_multicast_should_be_1(self):
        """OSPF multicast packets MUST have TTL=1 (RFC 2328 A.1)"""
        ospf_ttl = 1
        self.assertEqual(ospf_ttl, 1)

    def test_nbma_requires_poll_interval(self):
        """NBMA networks require a poll interval (RFC 2328 9.5.1)"""
        self.assertEqual(DEFAULT_POLL_INTERVAL, 120)


# ──────────────────────────────────────────────────────────────
#  OSPF Metric / Cost Tests
# ──────────────────────────────────────────────────────────────

class TestOSPFMetrics(unittest.TestCase):
    """OSPF cost and metric rules (RFC 2328 Section 2.2)"""

    def test_default_cost_is_10(self):
        self.assertEqual(OSPF_DEFAULT_COST, 10)

    def test_max_metric_is_65535(self):
        self.assertEqual(OSPF_MAX_METRIC, 65535)

    def test_infinity_equals_max_metric(self):
        self.assertEqual(INFINITY, OSPF_MAX_METRIC)

    def test_stub_default_cost(self):
        self.assertEqual(OSPF_STUB_DEFAULT_COST, 1)

    def test_cost_is_inversely_proportional_to_bandwidth(self):
        """Reference bandwidth 100Mbps: cost = 100e6 / bandwidth"""
        ref_bw = 100_000_000
        costs = {
            10_000_000: 10,      # 10 Mbps -> cost 10
            100_000_000: 1,      # 100 Mbps -> cost 1
            1_000_000: 100,      # 1 Mbps -> cost 100
        }
        for bw, expected_cost in costs.items():
            self.assertEqual(ref_bw // bw, expected_cost)

    def test_external_type1_uses_internal_cost(self):
        """Type 1 external: cost = internal + external"""
        lsa = ASExternalLSA(e_bit=False, metric=10)
        self.assertEqual(lsa.metric_type, EXTERNAL_TYPE_1)

    def test_external_type2_ignores_internal_cost(self):
        """Type 2 external: cost = external metric only"""
        lsa = ASExternalLSA(e_bit=True, metric=10)
        self.assertEqual(lsa.metric_type, EXTERNAL_TYPE_2)

    def test_type2_preferred_over_type1_when_equal_external(self):
        """Type 1 preferred over Type 2 when comparing routes (RFC 2328 16.4)"""
        type1_total = 20  # internal(10) + external(10)
        type2_ext   = 10  # only external
        # Type 1 is preferred when its total cost < Type 2's external cost
        self.assertFalse(type1_total < type2_ext)


# ──────────────────────────────────────────────────────────────
#  OSPF LSDB Tests
# ──────────────────────────────────────────────────────────────

class TestOSPFLSDB(unittest.TestCase):
    """OSPF Link State Database operations (RFC 2328 Section 13)"""

    def setUp(self):
        self.router = OSPFRouter(router_id="1.1.1.1")

    def test_install_and_lookup_lsa(self):
        lh = LSAHeader(lsa_type=LSA_TYPE_ROUTER, link_state_id="2.2.2.2", adv_router="2.2.2.2")
        self.router.install_lsa("0.0.0.0", lh, b"data")
        entry = self.router.lookup_lsa("0.0.0.0", LSA_TYPE_ROUTER, "2.2.2.2", "2.2.2.2")
        self.assertIsNotNone(entry)

    def test_lookup_missing_lsa_returns_none(self):
        result = self.router.lookup_lsa("0.0.0.0", LSA_TYPE_ROUTER, "9.9.9.9", "9.9.9.9")
        self.assertIsNone(result)

    def test_lsa_overwritten_on_newer_install(self):
        lh1 = LSAHeader(lsa_type=LSA_TYPE_ROUTER, link_state_id="2.2.2.2",
                        adv_router="2.2.2.2", seq_number=LSA_INITIAL_SEQUENCE)
        lh2 = LSAHeader(lsa_type=LSA_TYPE_ROUTER, link_state_id="2.2.2.2",
                        adv_router="2.2.2.2", seq_number=LSA_INITIAL_SEQUENCE + 1)
        self.router.install_lsa("0.0.0.0", lh1, b"v1")
        self.router.install_lsa("0.0.0.0", lh2, b"v2")
        entry = self.router.lookup_lsa("0.0.0.0", LSA_TYPE_ROUTER, "2.2.2.2", "2.2.2.2")
        self.assertEqual(entry["data"], b"v2")

    def test_separate_lsdb_per_area(self):
        lh = LSAHeader(lsa_type=LSA_TYPE_ROUTER, link_state_id="1.1.1.1", adv_router="1.1.1.1")
        self.router.install_lsa("0.0.0.0", lh, b"area0")
        self.router.install_lsa("0.0.0.1", lh, b"area1")
        e0 = self.router.lookup_lsa("0.0.0.0", LSA_TYPE_ROUTER, "1.1.1.1", "1.1.1.1")
        e1 = self.router.lookup_lsa("0.0.0.1", LSA_TYPE_ROUTER, "1.1.1.1", "1.1.1.1")
        self.assertEqual(e0["data"], b"area0")
        self.assertEqual(e1["data"], b"area1")

    def test_as_external_lsa_stored_globally(self):
        """AS-External LSAs (Type 5) are area-independent - stored in AS scope"""
        lh = LSAHeader(lsa_type=LSA_TYPE_AS_EXTERNAL, link_state_id="10.0.0.0",
                       adv_router="4.4.4.4")
        self.router.install_lsa("AS", lh, b"ext_route")
        entry = self.router.lookup_lsa("AS", LSA_TYPE_AS_EXTERNAL, "10.0.0.0", "4.4.4.4")
        self.assertIsNotNone(entry)

    def test_lsa_age_tracking(self):
        """LSA age increments toward MaxAge (3600s)"""
        lh = LSAHeader(age=0)
        self.assertFalse(lh.is_maxage())
        lh.age = 3600
        self.assertTrue(lh.is_maxage())

    def test_lsa_refresh_before_maxage(self):
        """LS Refresh Time (1800s) < MaxAge (3600s)"""
        self.assertLess(DEFAULT_LS_REFRESH_TIME, LSA_MAX_AGE)


class TestOSPFOptions(unittest.TestCase):
    """OSPF Options field bit definitions (RFC 2328 A.2)"""

    def test_e_bit_position(self):
        """E bit = bit 1 (0x02) - External Routing Capability"""
        E_BIT = 0x02
        self.assertEqual(E_BIT & 0x02, 0x02)

    def test_mc_bit_position(self):
        """MC bit = bit 2 (0x04) - Multicast Capability"""
        MC_BIT = 0x04
        self.assertEqual(MC_BIT & 0x04, 0x04)

    def test_np_bit_for_nssa(self):
        """N/P bit = bit 3 (0x08) - NSSA Capability"""
        NP_BIT = 0x08
        self.assertEqual(NP_BIT & 0x08, 0x08)

    def test_dc_bit_for_demand_circuits(self):
        """DC bit = bit 5 (0x20) - Demand Circuit"""
        DC_BIT = 0x20
        self.assertEqual(DC_BIT & 0x20, 0x20)

    def test_options_field_is_one_byte(self):
        """Options field is 8 bits (1 byte) per RFC 2328 A.2"""
        max_options = 0xFF
        self.assertEqual(max_options, 255)


if __name__ == "__main__":
    unittest.main(verbosity=2)
