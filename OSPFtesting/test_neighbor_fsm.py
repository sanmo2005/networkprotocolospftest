"""
Tests for OSPF Neighbor State Machine - RFC 2328 Section 10.3
All state transitions per the FSM definition
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.state_machine import (
    OSPFNeighbor, NEIGHBOR_TRANSITIONS, NEIGHBOR_STATES, NEIGHBOR_EVENTS,
    NBR_EVT_HELLO_RECEIVED, NBR_EVT_START, NBR_EVT_2WAY_RECEIVED,
    NBR_EVT_NEGOTIATION_DONE, NBR_EVT_EXCHANGE_DONE, NBR_EVT_BAD_LS_REQ,
    NBR_EVT_LOADING_DONE, NBR_EVT_ADJ_OK, NBR_EVT_SEQ_MISMATCH,
    NBR_EVT_1WAY, NBR_EVT_KILL, NBR_EVT_INACTIVITY, NBR_EVT_LL_DOWN,
)
from ospf_lib.constants import *


class TestNeighborStateMachineConstants(unittest.TestCase):
    """Verify FSM state and event constants"""

    def test_all_8_states_defined(self):
        self.assertEqual(len(NEIGHBOR_STATES), 8)

    def test_state_names_correct(self):
        expected = ["Down", "Attempt", "Init", "2-Way",
                    "ExStart", "Exchange", "Loading", "Full"]
        self.assertEqual(NEIGHBOR_STATES, expected)

    def test_all_events_defined(self):
        self.assertEqual(len(NEIGHBOR_EVENTS), 13)

    def test_transition_table_covers_all_states(self):
        for state in NEIGHBOR_STATES:
            self.assertIn(state, NEIGHBOR_TRANSITIONS,
                          f"State '{state}' missing from transition table")


class TestNeighborFSMFromDown(unittest.TestCase):
    """Transitions out of Down state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_DOWN)

    def test_down_hello_received_goes_to_init(self):
        new_state = self.nbr.process_event(NBR_EVT_HELLO_RECEIVED)
        self.assertEqual(new_state, NBR_STATE_INIT)

    def test_down_start_goes_to_attempt(self):
        new_state = self.nbr.process_event(NBR_EVT_START)
        self.assertEqual(new_state, NBR_STATE_ATTEMPT)

    def test_down_unknown_event_stays_in_down(self):
        new_state = self.nbr.process_event("UnknownEvent")
        self.assertEqual(new_state, NBR_STATE_DOWN)


class TestNeighborFSMFromAttempt(unittest.TestCase):
    """Transitions out of Attempt state (NBMA)"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_ATTEMPT)

    def test_attempt_hello_received_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_HELLO_RECEIVED), NBR_STATE_INIT)

    def test_attempt_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_attempt_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)

    def test_attempt_inactivity_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_INACTIVITY), NBR_STATE_DOWN)


class TestNeighborFSMFromInit(unittest.TestCase):
    """Transitions out of Init state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_INIT)

    def test_init_hello_received_stays_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_HELLO_RECEIVED), NBR_STATE_INIT)

    def test_init_2way_received_goes_to_2way(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_2WAY_RECEIVED), NBR_STATE_2WAY)

    def test_init_1way_stays_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_init_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_init_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)

    def test_init_inactivity_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_INACTIVITY), NBR_STATE_DOWN)


class TestNeighborFSMFrom2Way(unittest.TestCase):
    """Transitions out of 2-Way state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_2WAY)

    def test_2way_adj_ok_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_ADJ_OK), NBR_STATE_EXSTART)

    def test_2way_hello_received_stays_2way(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_HELLO_RECEIVED), NBR_STATE_2WAY)

    def test_2way_1way_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_2way_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_2way_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)

    def test_2way_inactivity_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_INACTIVITY), NBR_STATE_DOWN)


class TestNeighborFSMFromExStart(unittest.TestCase):
    """Transitions out of ExStart state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_EXSTART)

    def test_exstart_negotiation_done_goes_to_exchange(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_NEGOTIATION_DONE), NBR_STATE_EXCHANGE)

    def test_exstart_seq_mismatch_stays_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_SEQ_MISMATCH), NBR_STATE_EXSTART)

    def test_exstart_1way_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_exstart_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_exstart_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)


class TestNeighborFSMFromExchange(unittest.TestCase):
    """Transitions out of Exchange state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_EXCHANGE)

    def test_exchange_done_with_empty_request_list_goes_to_loading(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_EXCHANGE_DONE), NBR_STATE_LOADING)

    def test_exchange_bad_ls_req_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_BAD_LS_REQ), NBR_STATE_EXSTART)

    def test_exchange_seq_mismatch_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_SEQ_MISMATCH), NBR_STATE_EXSTART)

    def test_exchange_1way_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_exchange_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_exchange_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)


class TestNeighborFSMFromLoading(unittest.TestCase):
    """Transitions out of Loading state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_LOADING)

    def test_loading_done_goes_to_full(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LOADING_DONE), NBR_STATE_FULL)

    def test_loading_bad_ls_req_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_BAD_LS_REQ), NBR_STATE_EXSTART)

    def test_loading_seq_mismatch_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_SEQ_MISMATCH), NBR_STATE_EXSTART)

    def test_loading_1way_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_loading_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)


class TestNeighborFSMFromFull(unittest.TestCase):
    """Transitions out of Full state"""

    def setUp(self):
        self.nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_FULL)

    def test_full_hello_received_stays_full(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_HELLO_RECEIVED), NBR_STATE_FULL)

    def test_full_adj_ok_stays_full(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_ADJ_OK), NBR_STATE_FULL)

    def test_full_seq_mismatch_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_SEQ_MISMATCH), NBR_STATE_EXSTART)

    def test_full_bad_ls_req_goes_to_exstart(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_BAD_LS_REQ), NBR_STATE_EXSTART)

    def test_full_1way_goes_to_init(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_1WAY), NBR_STATE_INIT)

    def test_full_kill_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_KILL), NBR_STATE_DOWN)

    def test_full_ll_down_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_LL_DOWN), NBR_STATE_DOWN)

    def test_full_inactivity_goes_to_down(self):
        self.assertEqual(self.nbr.process_event(NBR_EVT_INACTIVITY), NBR_STATE_DOWN)


class TestNeighborFSMCompleteLifecycle(unittest.TestCase):
    """Full neighbor lifecycle test - Down to Full and back"""

    def test_full_lifecycle_down_to_full(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2")
        self.assertEqual(nbr.state, NBR_STATE_DOWN)

        nbr.process_event(NBR_EVT_HELLO_RECEIVED)
        self.assertEqual(nbr.state, NBR_STATE_INIT)

        nbr.process_event(NBR_EVT_2WAY_RECEIVED)
        self.assertEqual(nbr.state, NBR_STATE_2WAY)

        nbr.process_event(NBR_EVT_ADJ_OK)
        self.assertEqual(nbr.state, NBR_STATE_EXSTART)

        nbr.process_event(NBR_EVT_NEGOTIATION_DONE)
        self.assertEqual(nbr.state, NBR_STATE_EXCHANGE)

        nbr.process_event(NBR_EVT_EXCHANGE_DONE)
        self.assertEqual(nbr.state, NBR_STATE_LOADING)

        nbr.process_event(NBR_EVT_LOADING_DONE)
        self.assertEqual(nbr.state, NBR_STATE_FULL)

    def test_full_then_down_via_kill(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_FULL)
        nbr.process_event(NBR_EVT_KILL)
        self.assertEqual(nbr.state, NBR_STATE_DOWN)

    def test_event_log_tracks_transitions(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2")
        nbr.process_event(NBR_EVT_HELLO_RECEIVED)
        nbr.process_event(NBR_EVT_2WAY_RECEIVED)
        self.assertEqual(len(nbr.event_log), 2)

    def test_is_adjacent_during_exchange(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_EXCHANGE)
        self.assertTrue(nbr.is_adjacent())

    def test_is_adjacent_during_loading(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_LOADING)
        self.assertTrue(nbr.is_adjacent())

    def test_is_adjacent_when_full(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_FULL)
        self.assertTrue(nbr.is_adjacent())

    def test_not_adjacent_when_2way(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_2WAY)
        self.assertFalse(nbr.is_adjacent())

    def test_is_full_only_when_full(self):
        for state in NEIGHBOR_STATES:
            nbr = OSPFNeighbor(state=state)
            if state == NBR_STATE_FULL:
                self.assertTrue(nbr.is_full())
            else:
                self.assertFalse(nbr.is_full())

    def test_reset_clears_lists_and_state(self):
        nbr = OSPFNeighbor(router_id="2.2.2.2", state=NBR_STATE_FULL)
        nbr.retransmit_list.append("something")
        nbr.reset()
        self.assertEqual(nbr.state, NBR_STATE_DOWN)
        self.assertEqual(len(nbr.retransmit_list), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
