"""
Tests for OSPF Control Packets:
  - Database Description (DBD)   RFC 2328 A.3.3
  - Link State Request (LSR)     RFC 2328 A.3.4
  - Link State Update (LSU)      RFC 2328 A.3.5
  - Link State Acknowledge (LSAck) RFC 2328 A.3.6
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.packets import (
    OSPFDatabaseDescription, OSPFLinkStateRequest, OSPFLinkStateUpdate,
    OSPFLinkStateAck, LSAHeader, LSRequest, RouterLSA, RouterLink,
    SummaryLSA
)
from ospf_lib.constants import *


class TestDatabaseDescription(unittest.TestCase):
    """RFC 2328 A.3.3 - Database Description packet"""

    def _make_dbd(self, **kwargs):
        dbd = OSPFDatabaseDescription(**kwargs)
        dbd.header.router_id = "1.1.1.1"
        dbd.header.area_id = "0.0.0.0"
        return dbd

    # ── Interface MTU ──────────────────────────────────────────
    def test_mtu_default_is_ethernet(self):
        dbd = self._make_dbd()
        self.assertEqual(dbd.interface_mtu, ETHERNET_MTU_DEFAULT)

    def test_mtu_roundtrip(self):
        for mtu in [576, 1500, 4096, 9000]:
            dbd = self._make_dbd(interface_mtu=mtu)
            raw = dbd.encode()
            decoded = OSPFDatabaseDescription.decode(raw)
            self.assertEqual(decoded.interface_mtu, mtu)

    def test_mtu_mismatch_detection(self):
        """Different MTU values should be detectable"""
        dbd1 = self._make_dbd(interface_mtu=1500)
        dbd2 = self._make_dbd(interface_mtu=9000)
        self.assertNotEqual(dbd1.interface_mtu, dbd2.interface_mtu)

    # ── DBD Flags ──────────────────────────────────────────────
    def test_flag_ms_set_by_default(self):
        dbd = self._make_dbd(flags=DBD_FLAG_MS | DBD_FLAG_I)
        self.assertTrue(dbd.is_master)

    def test_flag_ms_clear_for_slave(self):
        dbd = self._make_dbd(flags=0)
        self.assertFalse(dbd.is_master)

    def test_flag_more_set(self):
        dbd = self._make_dbd(flags=DBD_FLAG_M)
        self.assertTrue(dbd.is_more)

    def test_flag_init_set(self):
        dbd = self._make_dbd(flags=DBD_FLAG_I)
        self.assertTrue(dbd.is_init)

    def test_flag_all_set(self):
        dbd = self._make_dbd(flags=DBD_FLAG_MS | DBD_FLAG_M | DBD_FLAG_I)
        self.assertTrue(dbd.is_master)
        self.assertTrue(dbd.is_more)
        self.assertTrue(dbd.is_init)

    def test_flag_constants_values(self):
        self.assertEqual(DBD_FLAG_MS, 0x01)
        self.assertEqual(DBD_FLAG_M,  0x02)
        self.assertEqual(DBD_FLAG_I,  0x04)

    # ── DD Sequence Number ─────────────────────────────────────
    def test_sequence_roundtrip(self):
        for seq in [1, 1000, 0xDEAD, 0xFFFFFFFF]:
            dbd = self._make_dbd(sequence=seq)
            raw = dbd.encode()
            decoded = OSPFDatabaseDescription.decode(raw)
            self.assertEqual(decoded.sequence, seq)

    def test_sequence_increments_logically(self):
        seq1, seq2 = 1000, 1001
        self.assertGreater(seq2, seq1)

    # ── LSA Headers in DBD ─────────────────────────────────────
    def test_dbd_with_no_lsa_headers(self):
        dbd = self._make_dbd(lsa_headers=[])
        raw = dbd.encode()
        decoded = OSPFDatabaseDescription.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 0)

    def test_dbd_with_single_lsa_header(self):
        lh = LSAHeader(lsa_type=LSA_TYPE_ROUTER, adv_router="1.1.1.1")
        dbd = self._make_dbd(lsa_headers=[lh])
        raw = dbd.encode()
        decoded = OSPFDatabaseDescription.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 1)

    def test_dbd_with_multiple_lsa_headers(self):
        headers = [
            LSAHeader(lsa_type=LSA_TYPE_ROUTER,      adv_router="1.1.1.1"),
            LSAHeader(lsa_type=LSA_TYPE_NETWORK,     adv_router="2.2.2.2"),
            LSAHeader(lsa_type=LSA_TYPE_SUMMARY_NET, adv_router="3.3.3.3"),
        ]
        dbd = self._make_dbd(lsa_headers=headers)
        raw = dbd.encode()
        decoded = OSPFDatabaseDescription.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 3)

    def test_dbd_packet_type_is_2(self):
        dbd = self._make_dbd()
        raw = dbd.encode()
        decoded = OSPFDatabaseDescription.decode(raw)
        self.assertEqual(decoded.header.packet_type, OSPF_PKT_DBD)

    def test_dbd_length_no_lsa_headers(self):
        dbd = self._make_dbd(lsa_headers=[])
        raw = dbd.encode()
        # header(24) + body(8) = 32
        self.assertEqual(len(raw), 32)

    def test_dbd_length_with_lsa_headers(self):
        headers = [LSAHeader(), LSAHeader()]
        dbd = self._make_dbd(lsa_headers=headers)
        raw = dbd.encode()
        self.assertEqual(len(raw), 32 + 2 * LSAHeader.SIZE)


class TestLinkStateRequest(unittest.TestCase):
    """RFC 2328 A.3.4 - Link State Request packet"""

    def _make_lsr(self, requests=None):
        lsr = OSPFLinkStateRequest(requests=requests or [])
        lsr.header.router_id = "1.1.1.1"
        return lsr

    def test_empty_lsr(self):
        lsr = self._make_lsr()
        raw = lsr.encode()
        decoded = OSPFLinkStateRequest.decode(raw)
        self.assertEqual(len(decoded.requests), 0)

    def test_single_request(self):
        req = LSRequest(lsa_type=LSA_TYPE_ROUTER, link_state_id="2.2.2.2", adv_router="2.2.2.2")
        lsr = self._make_lsr(requests=[req])
        raw = lsr.encode()
        decoded = OSPFLinkStateRequest.decode(raw)
        self.assertEqual(len(decoded.requests), 1)
        self.assertEqual(decoded.requests[0].lsa_type, LSA_TYPE_ROUTER)
        self.assertEqual(decoded.requests[0].adv_router, "2.2.2.2")

    def test_multiple_requests(self):
        reqs = [
            LSRequest(lsa_type=LSA_TYPE_ROUTER, link_state_id="1.1.1.1", adv_router="1.1.1.1"),
            LSRequest(lsa_type=LSA_TYPE_NETWORK, link_state_id="10.0.0.1", adv_router="2.2.2.2"),
            LSRequest(lsa_type=LSA_TYPE_SUMMARY_NET, link_state_id="172.16.0.0", adv_router="3.3.3.3"),
        ]
        lsr = self._make_lsr(requests=reqs)
        raw = lsr.encode()
        decoded = OSPFLinkStateRequest.decode(raw)
        self.assertEqual(len(decoded.requests), 3)

    def test_lsr_packet_type_is_3(self):
        lsr = self._make_lsr()
        raw = lsr.encode()
        decoded = OSPFLinkStateRequest.decode(raw)
        self.assertEqual(decoded.header.packet_type, OSPF_PKT_LSR)

    def test_ls_request_size_is_12(self):
        self.assertEqual(LSRequest.SIZE, 12)

    def test_request_lsa_types_roundtrip(self):
        for lsa_type in [LSA_TYPE_ROUTER, LSA_TYPE_NETWORK, LSA_TYPE_SUMMARY_NET,
                         LSA_TYPE_SUMMARY_ASBR, LSA_TYPE_AS_EXTERNAL]:
            req = LSRequest(lsa_type=lsa_type, adv_router="1.1.1.1")
            raw = req.encode()
            decoded = LSRequest.decode(raw)
            self.assertEqual(decoded.lsa_type, lsa_type)


class TestLinkStateUpdate(unittest.TestCase):
    """RFC 2328 A.3.5 - Link State Update packet"""

    def _make_lsu(self, lsas=None):
        lsu = OSPFLinkStateUpdate(lsas=lsas or [])
        lsu.header.router_id = "1.1.1.1"
        lsu.header.area_id = "0.0.0.0"
        return lsu

    def test_empty_lsu(self):
        lsu = self._make_lsu()
        raw = lsu.encode()
        decoded = OSPFLinkStateUpdate.decode(raw)
        self.assertEqual(decoded.num_lsas, 0)

    def test_lsu_packet_type_is_4(self):
        lsu = self._make_lsu()
        raw = lsu.encode()
        decoded = OSPFLinkStateUpdate.decode(raw)
        self.assertEqual(decoded.header.packet_type, OSPF_PKT_LSU)

    def test_lsu_with_router_lsa(self):
        rlsa = RouterLSA()
        rlsa.header.adv_router = "1.1.1.1"
        rlsa.header.link_state_id = "1.1.1.1"
        raw_lsa = rlsa.encode()
        lsu = self._make_lsu(lsas=[raw_lsa])
        raw = lsu.encode()
        decoded = OSPFLinkStateUpdate.decode(raw)
        self.assertEqual(decoded.num_lsas, 1)

    def test_lsu_with_multiple_lsas(self):
        lsas = []
        for i in range(3):
            lsa = SummaryLSA()
            lsa.header.adv_router = f"1.1.1.{i+1}"
            lsa.header.link_state_id = f"10.0.{i}.0"
            lsas.append(lsa.encode())
        lsu = self._make_lsu(lsas=lsas)
        self.assertEqual(lsu.num_lsas, 3)

    def test_lsu_num_lsas_field(self):
        lsas = [RouterLSA().encode(), RouterLSA().encode()]
        lsu = self._make_lsu(lsas=lsas)
        self.assertEqual(lsu.num_lsas, 2)

    def test_lsu_length_includes_count_field(self):
        lsu = self._make_lsu()
        raw = lsu.encode()
        # header(24) + count(4) = 28 minimum
        self.assertEqual(len(raw), 28)


class TestLinkStateAck(unittest.TestCase):
    """RFC 2328 A.3.6 - Link State Acknowledgment packet"""

    def _make_lsack(self, headers=None):
        lsack = OSPFLinkStateAck(lsa_headers=headers or [])
        lsack.header.router_id = "1.1.1.1"
        return lsack

    def test_empty_lsack(self):
        lsack = self._make_lsack()
        raw = lsack.encode()
        decoded = OSPFLinkStateAck.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 0)

    def test_lsack_packet_type_is_5(self):
        lsack = self._make_lsack()
        raw = lsack.encode()
        decoded = OSPFLinkStateAck.decode(raw)
        self.assertEqual(decoded.header.packet_type, OSPF_PKT_LSACK)

    def test_lsack_with_single_header(self):
        lh = LSAHeader(lsa_type=LSA_TYPE_ROUTER, adv_router="2.2.2.2")
        lsack = self._make_lsack(headers=[lh])
        raw = lsack.encode()
        decoded = OSPFLinkStateAck.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 1)
        self.assertEqual(decoded.lsa_headers[0].adv_router, "2.2.2.2")

    def test_lsack_with_multiple_headers(self):
        headers = [
            LSAHeader(lsa_type=LSA_TYPE_ROUTER, adv_router="1.1.1.1"),
            LSAHeader(lsa_type=LSA_TYPE_NETWORK, adv_router="2.2.2.2"),
            LSAHeader(lsa_type=LSA_TYPE_AS_EXTERNAL, adv_router="3.3.3.3"),
        ]
        lsack = self._make_lsack(headers=headers)
        raw = lsack.encode()
        decoded = OSPFLinkStateAck.decode(raw)
        self.assertEqual(len(decoded.lsa_headers), 3)

    def test_lsack_length_with_headers(self):
        headers = [LSAHeader(), LSAHeader(), LSAHeader()]
        lsack = self._make_lsack(headers=headers)
        raw = lsack.encode()
        # header(24) + 3 × lsa_header(20) = 84
        self.assertEqual(len(raw), 24 + 3 * 20)

    def test_lsack_acknowledges_correct_lsa(self):
        lh = LSAHeader(
            lsa_type=LSA_TYPE_ROUTER,
            link_state_id="5.5.5.5",
            adv_router="5.5.5.5",
            seq_number=LSA_INITIAL_SEQUENCE + 5,
        )
        lsack = self._make_lsack(headers=[lh])
        raw = lsack.encode()
        decoded = OSPFLinkStateAck.decode(raw)
        self.assertEqual(decoded.lsa_headers[0].link_state_id, "5.5.5.5")
        self.assertEqual(decoded.lsa_headers[0].seq_number, LSA_INITIAL_SEQUENCE + 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
