"""
Tests for OSPF Interface State Machine - RFC 2328 Section 9
and DR/BDR Election - RFC 2328 Section 9.4
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.state_machine import (
    OSPFInterface, OSPFNeighbor, elect_dr_bdr,
    INTERFACE_TRANSITIONS, INTERFACE_EVENTS, INTERFACE_STATES,
    IFACE_EVT_IFACE_UP, IFACE_EVT_WAIT_TIMER, IFACE_EVT_BACKUP_SEEN,
    IFACE_EVT_NBR_CHANGE, IFACE_EVT_LOOP_IND, IFACE_EVT_UNLOOP_IND,
    IFACE_EVT_IFACE_DOWN,
)
from ospf_lib.constants import *


class TestInterfaceFSMConstants(unittest.TestCase):
    """Verify interface FSM state/event constants per RFC 2328 Section 9"""

    def test_all_7_interface_states(self):
        self.assertEqual(len(INTERFACE_STATES), 7)

    def test_state_names(self):
        expected = ["Down", "Loopback", "Waiting", "Point-to-Point",
                    "DROther", "Backup", "DR"]
        self.assertEqual(INTERFACE_STATES, expected)

    def test_all_interface_events_defined(self):
        self.assertEqual(len(INTERFACE_EVENTS), 7)


class TestInterfaceFSMFromDown(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_DOWN)

    def test_down_iface_up_goes_to_waiting(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_UP), IFACE_STATE_WAITING)

    def test_down_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_down_unknown_event_stays_down(self):
        self.assertEqual(self.iface.process_event("SomeOtherEvent"), IFACE_STATE_DOWN)


class TestInterfaceFSMFromLoopback(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="lo0", state=IFACE_STATE_LOOPBACK)

    def test_loopback_unloop_ind_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_UNLOOP_IND), IFACE_STATE_DOWN)

    def test_loopback_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceFSMFromWaiting(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_WAITING)

    def test_waiting_wait_timer_goes_to_dr_other(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_WAIT_TIMER), IFACE_STATE_DR_OTHER)

    def test_waiting_backup_seen_goes_to_dr_other(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_BACKUP_SEEN), IFACE_STATE_DR_OTHER)

    def test_waiting_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_waiting_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceFSMFromP2P(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_P2P)

    def test_p2p_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_p2p_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceFSMFromDROther(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_DR_OTHER)

    def test_dr_other_nbr_change_stays_dr_other(self):
        # After NeighborChange, re-election may keep same result
        result = self.iface.process_event(IFACE_EVT_NBR_CHANGE)
        self.assertEqual(result, IFACE_STATE_DR_OTHER)

    def test_dr_other_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_dr_other_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceFSMFromBDR(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_BDR)

    def test_bdr_nbr_change_goes_to_dr_other(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_NBR_CHANGE), IFACE_STATE_DR_OTHER)

    def test_bdr_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_bdr_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceFSMFromDR(unittest.TestCase):

    def setUp(self):
        self.iface = OSPFInterface(name="eth0", state=IFACE_STATE_DR)

    def test_dr_nbr_change_goes_to_dr_other(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_NBR_CHANGE), IFACE_STATE_DR_OTHER)

    def test_dr_loop_ind_goes_to_loopback(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_LOOP_IND), IFACE_STATE_LOOPBACK)

    def test_dr_iface_down_goes_to_down(self):
        self.assertEqual(self.iface.process_event(IFACE_EVT_IFACE_DOWN), IFACE_STATE_DOWN)


class TestInterfaceHelpers(unittest.TestCase):

    def test_is_dr(self):
        iface = OSPFInterface(state=IFACE_STATE_DR)
        self.assertTrue(iface.is_dr())

    def test_is_not_dr(self):
        iface = OSPFInterface(state=IFACE_STATE_BDR)
        self.assertFalse(iface.is_dr())

    def test_is_bdr(self):
        iface = OSPFInterface(state=IFACE_STATE_BDR)
        self.assertTrue(iface.is_bdr())

    def test_is_active_when_dr_other(self):
        iface = OSPFInterface(state=IFACE_STATE_DR_OTHER)
        self.assertTrue(iface.is_active())

    def test_is_not_active_when_down(self):
        iface = OSPFInterface(state=IFACE_STATE_DOWN)
        self.assertFalse(iface.is_active())

    def test_is_not_active_when_loopback(self):
        iface = OSPFInterface(state=IFACE_STATE_LOOPBACK)
        self.assertFalse(iface.is_active())

    def test_add_neighbor(self):
        iface = OSPFInterface()
        nbr = OSPFNeighbor(router_id="2.2.2.2")
        iface.add_neighbor(nbr)
        self.assertIn("2.2.2.2", iface.neighbors)

    def test_remove_neighbor(self):
        iface = OSPFInterface()
        nbr = OSPFNeighbor(router_id="2.2.2.2")
        iface.add_neighbor(nbr)
        iface.remove_neighbor("2.2.2.2")
        self.assertNotIn("2.2.2.2", iface.neighbors)

    def test_get_full_neighbors(self):
        iface = OSPFInterface()
        iface.add_neighbor(OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_FULL))
        iface.add_neighbor(OSPFNeighbor(router_id="3.3.3.3", state=NBR_STATE_2WAY))
        full = iface.get_full_neighbors()
        self.assertEqual(len(full), 1)
        self.assertEqual(full[0].router_id, "2.2.2.2")

    def test_event_log_records_transitions(self):
        iface = OSPFInterface(state=IFACE_STATE_DOWN)
        iface.process_event(IFACE_EVT_IFACE_UP)
        iface.process_event(IFACE_EVT_WAIT_TIMER)
        self.assertEqual(len(iface.event_log), 2)


class TestDRBDRElection(unittest.TestCase):
    """RFC 2328 Section 9.4 - DR/BDR Election"""

    def _make_iface(self, self_priority=1, self_router_id="1.1.1.1"):
        iface = OSPFInterface(
            priority=self_priority,
            ip_address="192.168.1.1",
            state=IFACE_STATE_WAITING,
        )
        return iface

    def test_election_with_no_neighbors_self_becomes_dr(self):
        iface = self._make_iface(self_priority=1)
        dr, bdr = elect_dr_bdr(iface, "1.1.1.1")
        # With only ourselves and priority > 0, we become DR
        self.assertEqual(dr, "1.1.1.1")

    def test_higher_priority_wins_dr(self):
        iface = self._make_iface(self_priority=1)
        nbr = OSPFNeighbor(
            router_id="2.2.2.2", ip_address="192.168.1.2",
            priority=200, state=NBR_STATE_2WAY
        )
        iface.add_neighbor(nbr)
        dr, bdr = elect_dr_bdr(iface, "1.1.1.1")
        self.assertEqual(dr, "2.2.2.2")

    def test_tie_broken_by_router_id(self):
        """Higher router ID wins when priority is equal"""
        iface = self._make_iface(self_priority=1)
        nbr = OSPFNeighbor(
            router_id="9.9.9.9", ip_address="192.168.1.9",
            priority=1, state=NBR_STATE_2WAY
        )
        iface.add_neighbor(nbr)
        dr, bdr = elect_dr_bdr(iface, "1.1.1.1")
        self.assertEqual(dr, "9.9.9.9")

    def test_priority_zero_ineligible_for_dr(self):
        """Priority 0 router must not become DR or BDR"""
        iface = self._make_iface(self_priority=0)
        dr, bdr = elect_dr_bdr(iface, "1.1.1.1")
        # With only ourselves and priority 0, no DR
        self.assertEqual(dr, "0.0.0.0")

    def test_election_returns_tuple(self):
        iface = self._make_iface()
        result = elect_dr_bdr(iface, "1.1.1.1")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class TestInterfaceConfiguration(unittest.TestCase):
    """Interface configuration parameters - RFC 2328 Appendix C.3"""

    def test_default_hello_interval(self):
        iface = OSPFInterface()
        self.assertEqual(iface.hello_interval, DEFAULT_HELLO_INTERVAL)

    def test_default_dead_interval(self):
        iface = OSPFInterface()
        self.assertEqual(iface.dead_interval, DEFAULT_DEAD_INTERVAL)

    def test_default_rxmt_interval(self):
        iface = OSPFInterface()
        self.assertEqual(iface.rxmt_interval, DEFAULT_RXMT_INTERVAL)

    def test_default_transmit_delay(self):
        iface = OSPFInterface()
        self.assertEqual(iface.transmit_delay, DEFAULT_TRANSMIT_DELAY)

    def test_default_router_priority(self):
        iface = OSPFInterface()
        self.assertEqual(iface.priority, DEFAULT_ROUTER_PRIORITY)

    def test_default_cost(self):
        iface = OSPFInterface()
        self.assertEqual(iface.cost, OSPF_DEFAULT_COST)

    def test_default_mtu(self):
        iface = OSPFInterface()
        self.assertEqual(iface.mtu, ETHERNET_MTU_DEFAULT)

    def test_auth_type_default_null(self):
        iface = OSPFInterface()
        self.assertEqual(iface.auth_type, AUTH_TYPE_NULL)

    def test_interface_types_defined(self):
        types = [IFACE_TYPE_BROADCAST, IFACE_TYPE_P2P, IFACE_TYPE_NBMA,
                 IFACE_TYPE_P2MP, IFACE_TYPE_VIRTUAL]
        self.assertEqual(len(types), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
