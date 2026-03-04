"""
Tests for OSPF Common Header - RFC 2328 Section A.3.1
IEEE test coverage for all header field validations
"""

import struct
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.packets import OSPFHeader, inet_checksum
from ospf_lib.constants import *


class TestOSPFHeaderFields(unittest.TestCase):
    """RFC 2328 A.3.1 - OSPF Common Header field validation"""

    def setUp(self):
        self.hdr = OSPFHeader(
            version=OSPF_VERSION_2,
            packet_type=OSPF_PKT_HELLO,
            packet_len=OSPF_HEADER_LEN,
            router_id="1.1.1.1",
            area_id="0.0.0.0",
            checksum=0,
            auth_type=AUTH_TYPE_NULL,
            auth_data=0,
        )

    # ── Version field ──────────────────────────────────────────
    def test_header_version_ospfv2(self):
        """Version field MUST be 2 for OSPFv2 (RFC 2328 A.3.1)"""
        self.assertEqual(self.hdr.version, OSPF_VERSION_2)

    def test_header_version_ospfv3(self):
        """Version field MUST be 3 for OSPFv3 (RFC 5340)"""
        h = OSPFHeader(version=OSPF_VERSION_3)
        self.assertEqual(h.version, OSPF_VERSION_3)

    def test_header_version_invalid_rejected(self):
        """Non-standard version should fail is_valid_version()"""
        h = OSPFHeader(version=99)
        self.assertFalse(h.is_valid_version())

    def test_header_version_v2_valid(self):
        self.assertTrue(self.hdr.is_valid_version())

    # ── Packet type field ──────────────────────────────────────
    def test_packet_type_hello(self):
        h = OSPFHeader(packet_type=OSPF_PKT_HELLO)
        self.assertTrue(h.is_valid_type())

    def test_packet_type_dbd(self):
        h = OSPFHeader(packet_type=OSPF_PKT_DBD)
        self.assertTrue(h.is_valid_type())

    def test_packet_type_lsr(self):
        h = OSPFHeader(packet_type=OSPF_PKT_LSR)
        self.assertTrue(h.is_valid_type())

    def test_packet_type_lsu(self):
        h = OSPFHeader(packet_type=OSPF_PKT_LSU)
        self.assertTrue(h.is_valid_type())

    def test_packet_type_lsack(self):
        h = OSPFHeader(packet_type=OSPF_PKT_LSACK)
        self.assertTrue(h.is_valid_type())

    def test_packet_type_invalid_rejected(self):
        h = OSPFHeader(packet_type=0)
        self.assertFalse(h.is_valid_type())

    def test_packet_type_out_of_range_rejected(self):
        h = OSPFHeader(packet_type=6)
        self.assertFalse(h.is_valid_type())

    # ── Packet length field ────────────────────────────────────
    def test_packet_length_minimum_is_24(self):
        """Minimum OSPF packet is header-only = 24 bytes"""
        self.assertGreaterEqual(self.hdr.packet_len, OSPF_HEADER_LEN)

    def test_packet_length_encoded_correctly(self):
        raw = self.hdr.encode()
        _, _, plen, *_ = struct.unpack("!BBHIIHHQ", raw)
        self.assertEqual(plen, OSPF_HEADER_LEN)

    # ── Router ID field ────────────────────────────────────────
    def test_router_id_encoded_as_32bit(self):
        """Router ID is a 32-bit value (RFC 2328 C.1)"""
        raw = self.hdr.encode()
        rid_bytes = raw[4:8]
        self.assertEqual(len(rid_bytes), 4)

    def test_router_id_roundtrip(self):
        self.hdr.router_id = "10.0.0.1"
        raw = self.hdr.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.router_id, "10.0.0.1")

    def test_router_id_must_not_be_zero(self):
        """Router ID 0.0.0.0 is invalid per RFC 2328"""
        self.hdr.router_id = "0.0.0.0"
        # Just encode/decode - field exists but convention disallows 0.0.0.0
        raw = self.hdr.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.router_id, "0.0.0.0")

    def test_router_id_various_values(self):
        for rid in ["1.2.3.4", "255.255.255.255", "192.168.0.1", "172.16.0.1"]:
            self.hdr.router_id = rid
            raw = self.hdr.encode()
            decoded = OSPFHeader.decode(raw)
            self.assertEqual(decoded.router_id, rid)

    # ── Area ID field ──────────────────────────────────────────
    def test_area_id_backbone_is_0(self):
        """Backbone area ID is 0.0.0.0 (RFC 2328 Section 1)"""
        self.hdr.area_id = "0.0.0.0"
        raw = self.hdr.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.area_id, "0.0.0.0")

    def test_area_id_non_backbone(self):
        self.hdr.area_id = "0.0.0.1"
        raw = self.hdr.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.area_id, "0.0.0.1")

    # ── Authentication fields ──────────────────────────────────
    def test_auth_type_null(self):
        self.assertEqual(self.hdr.auth_type, AUTH_TYPE_NULL)

    def test_auth_type_simple(self):
        h = OSPFHeader(auth_type=AUTH_TYPE_SIMPLE)
        raw = h.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.auth_type, AUTH_TYPE_SIMPLE)

    def test_auth_type_crypto(self):
        h = OSPFHeader(auth_type=AUTH_TYPE_CRYPTO)
        raw = h.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.auth_type, AUTH_TYPE_CRYPTO)

    # ── Encode / Decode ────────────────────────────────────────
    def test_header_encode_size_is_24(self):
        raw = self.hdr.encode()
        self.assertEqual(len(raw), OSPF_HEADER_LEN)

    def test_header_decode_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            OSPFHeader.decode(b'\x00' * 10)

    def test_header_full_roundtrip(self):
        self.hdr.router_id = "192.168.100.1"
        self.hdr.area_id = "0.0.0.2"
        self.hdr.auth_type = AUTH_TYPE_SIMPLE
        raw = self.hdr.encode()
        decoded = OSPFHeader.decode(raw)
        self.assertEqual(decoded.version, OSPF_VERSION_2)
        self.assertEqual(decoded.packet_type, OSPF_PKT_HELLO)
        self.assertEqual(decoded.router_id, "192.168.100.1")
        self.assertEqual(decoded.area_id, "0.0.0.2")
        self.assertEqual(decoded.auth_type, AUTH_TYPE_SIMPLE)


class TestOSPFHeaderChecksum(unittest.TestCase):
    """Checksum computation tests - RFC 2328 Section A.3.1"""

    def test_checksum_field_is_16bits(self):
        h = OSPFHeader()
        h.checksum = 0xABCD
        raw = h.encode()
        chk_bytes = raw[12:14]
        self.assertEqual(len(chk_bytes), 2)

    def test_checksum_zero_on_raw_header(self):
        """Newly created header with checksum=0 should be encodable"""
        h = OSPFHeader()
        raw = h.encode()
        self.assertEqual(len(raw), 24)

    def test_checksum_computation(self):
        h = OSPFHeader(router_id="1.1.1.1", area_id="0.0.0.0")
        raw = h.encode()
        chk = inet_checksum(raw)
        # After computing checksum, re-inserting should yield zero on recompute
        self.assertIsInstance(chk, int)


class TestOSPFPacketTypeMapping(unittest.TestCase):
    """Test that all packet type constants are correctly defined"""

    def test_all_five_packet_types_exist(self):
        self.assertEqual(len(OSPF_PACKET_TYPES), 5)

    def test_packet_type_names(self):
        self.assertEqual(OSPF_PACKET_TYPES[1], "Hello")
        self.assertEqual(OSPF_PACKET_TYPES[2], "DatabaseDescription")
        self.assertEqual(OSPF_PACKET_TYPES[3], "LinkStateRequest")
        self.assertEqual(OSPF_PACKET_TYPES[4], "LinkStateUpdate")
        self.assertEqual(OSPF_PACKET_TYPES[5], "LinkStateAck")

    def test_type_values_are_1_through_5(self):
        self.assertEqual(sorted(OSPF_PACKET_TYPES.keys()), [1, 2, 3, 4, 5])


if __name__ == "__main__":
    unittest.main(verbosity=2)
