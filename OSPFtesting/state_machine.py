"""
OSPF State Machines - RFC 2328
Neighbor FSM (Section 10.3) and Interface FSM (Section 9.2)
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from .constants import *


# ──────────────────────────────────────────────────────────────
#  Neighbor State Machine (RFC 2328 Section 10.3)
# ──────────────────────────────────────────────────────────────

# Neighbor Events
NBR_EVT_HELLO_RECEIVED   = "HelloReceived"
NBR_EVT_START            = "Start"
NBR_EVT_2WAY_RECEIVED    = "2-WayReceived"
NBR_EVT_NEGOTIATION_DONE = "NegotiationDone"
NBR_EVT_EXCHANGE_DONE    = "ExchangeDone"
NBR_EVT_BAD_LS_REQ       = "BadLSReq"
NBR_EVT_LOADING_DONE     = "LoadingDone"
NBR_EVT_ADJ_OK           = "AdjOK?"
NBR_EVT_SEQ_MISMATCH     = "SeqNumberMismatch"
NBR_EVT_1WAY             = "1-Way"
NBR_EVT_KILL             = "KillNbr"
NBR_EVT_INACTIVITY       = "InactivityTimer"
NBR_EVT_LL_DOWN          = "LLDown"

NEIGHBOR_EVENTS = [
    NBR_EVT_HELLO_RECEIVED, NBR_EVT_START, NBR_EVT_2WAY_RECEIVED,
    NBR_EVT_NEGOTIATION_DONE, NBR_EVT_EXCHANGE_DONE, NBR_EVT_BAD_LS_REQ,
    NBR_EVT_LOADING_DONE, NBR_EVT_ADJ_OK, NBR_EVT_SEQ_MISMATCH,
    NBR_EVT_1WAY, NBR_EVT_KILL, NBR_EVT_INACTIVITY, NBR_EVT_LL_DOWN,
]

# RFC 2328 Section 10.3 - Neighbor state transition table
NEIGHBOR_TRANSITIONS = {
    NBR_STATE_DOWN:     {NBR_EVT_HELLO_RECEIVED: NBR_STATE_INIT,
                         NBR_EVT_START: NBR_STATE_ATTEMPT},
    NBR_STATE_ATTEMPT:  {NBR_EVT_HELLO_RECEIVED: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_INIT:     {NBR_EVT_HELLO_RECEIVED: NBR_STATE_INIT,
                         NBR_EVT_2WAY_RECEIVED: NBR_STATE_2WAY,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_2WAY:     {NBR_EVT_ADJ_OK: NBR_STATE_EXSTART,
                         NBR_EVT_HELLO_RECEIVED: NBR_STATE_2WAY,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_EXSTART:  {NBR_EVT_NEGOTIATION_DONE: NBR_STATE_EXCHANGE,
                         NBR_EVT_SEQ_MISMATCH: NBR_STATE_EXSTART,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_EXCHANGE: {NBR_EVT_EXCHANGE_DONE: NBR_STATE_LOADING,
                         NBR_EVT_BAD_LS_REQ: NBR_STATE_EXSTART,
                         NBR_EVT_SEQ_MISMATCH: NBR_STATE_EXSTART,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_LOADING:  {NBR_EVT_LOADING_DONE: NBR_STATE_FULL,
                         NBR_EVT_BAD_LS_REQ: NBR_STATE_EXSTART,
                         NBR_EVT_SEQ_MISMATCH: NBR_STATE_EXSTART,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
    NBR_STATE_FULL:     {NBR_EVT_HELLO_RECEIVED: NBR_STATE_FULL,
                         NBR_EVT_ADJ_OK: NBR_STATE_FULL,
                         NBR_EVT_SEQ_MISMATCH: NBR_STATE_EXSTART,
                         NBR_EVT_BAD_LS_REQ: NBR_STATE_EXSTART,
                         NBR_EVT_1WAY: NBR_STATE_INIT,
                         NBR_EVT_KILL: NBR_STATE_DOWN,
                         NBR_EVT_LL_DOWN: NBR_STATE_DOWN,
                         NBR_EVT_INACTIVITY: NBR_STATE_DOWN},
}


@dataclass
class OSPFNeighbor:
    router_id:       str = "0.0.0.0"
    state:           str = NBR_STATE_DOWN
    priority:        int = DEFAULT_ROUTER_PRIORITY
    ip_address:      str = "0.0.0.0"
    options:         int = 0
    dr:              str = "0.0.0.0"
    bdr:             str = "0.0.0.0"
    is_master:       bool = True
    dd_sequence:     int = 0
    retransmit_list: List = field(default_factory=list)
    db_summary_list: List = field(default_factory=list)
    ls_request_list: List = field(default_factory=list)
    event_log:       List[str] = field(default_factory=list)

    def process_event(self, event: str) -> str:
        """Process FSM event and return new state."""
        transitions = NEIGHBOR_TRANSITIONS.get(self.state, {})
        new_state = transitions.get(event, self.state)
        self.event_log.append(f"{self.state} --[{event}]--> {new_state}")
        self.state = new_state
        return new_state

    def is_adjacent(self) -> bool:
        return self.state in (NBR_STATE_EXCHANGE, NBR_STATE_LOADING, NBR_STATE_FULL)

    def is_full(self) -> bool:
        return self.state == NBR_STATE_FULL

    def reset(self):
        self.state = NBR_STATE_DOWN
        self.retransmit_list.clear()
        self.db_summary_list.clear()
        self.ls_request_list.clear()


# ──────────────────────────────────────────────────────────────
#  Interface State Machine (RFC 2328 Section 9.2)
# ──────────────────────────────────────────────────────────────

# Interface Events
IFACE_EVT_IFACE_UP      = "InterfaceUp"
IFACE_EVT_WAIT_TIMER    = "WaitTimer"
IFACE_EVT_BACKUP_SEEN   = "BackupSeen"
IFACE_EVT_NBR_CHANGE    = "NeighborChange"
IFACE_EVT_LOOP_IND      = "LoopInd"
IFACE_EVT_UNLOOP_IND    = "UnloopInd"
IFACE_EVT_IFACE_DOWN    = "InterfaceDown"

INTERFACE_EVENTS = [
    IFACE_EVT_IFACE_UP, IFACE_EVT_WAIT_TIMER, IFACE_EVT_BACKUP_SEEN,
    IFACE_EVT_NBR_CHANGE, IFACE_EVT_LOOP_IND, IFACE_EVT_UNLOOP_IND,
    IFACE_EVT_IFACE_DOWN,
]

# RFC 2328 Section 9.2 Interface FSM transitions
INTERFACE_TRANSITIONS = {
    IFACE_STATE_DOWN:    {IFACE_EVT_IFACE_UP:   IFACE_STATE_WAITING,
                          IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK},
    IFACE_STATE_LOOPBACK:{IFACE_EVT_UNLOOP_IND: IFACE_STATE_DOWN,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
    IFACE_STATE_WAITING: {IFACE_EVT_WAIT_TIMER: IFACE_STATE_DR_OTHER,
                          IFACE_EVT_BACKUP_SEEN: IFACE_STATE_DR_OTHER,
                          IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
    IFACE_STATE_P2P:     {IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
    IFACE_STATE_DR_OTHER:{IFACE_EVT_NBR_CHANGE: IFACE_STATE_DR_OTHER,
                          IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
    IFACE_STATE_BDR:     {IFACE_EVT_NBR_CHANGE: IFACE_STATE_DR_OTHER,
                          IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
    IFACE_STATE_DR:      {IFACE_EVT_NBR_CHANGE: IFACE_STATE_DR_OTHER,
                          IFACE_EVT_LOOP_IND:   IFACE_STATE_LOOPBACK,
                          IFACE_EVT_IFACE_DOWN: IFACE_STATE_DOWN},
}


@dataclass
class OSPFInterface:
    name:             str  = "eth0"
    iface_type:       str  = IFACE_TYPE_BROADCAST
    state:            str  = IFACE_STATE_DOWN
    ip_address:       str  = "192.168.1.1"
    network_mask:     str  = "255.255.255.0"
    area_id:          str  = "0.0.0.0"
    hello_interval:   int  = DEFAULT_HELLO_INTERVAL
    dead_interval:    int  = DEFAULT_DEAD_INTERVAL
    rxmt_interval:    int  = DEFAULT_RXMT_INTERVAL
    transmit_delay:   int  = DEFAULT_TRANSMIT_DELAY
    priority:         int  = DEFAULT_ROUTER_PRIORITY
    cost:             int  = OSPF_DEFAULT_COST
    mtu:              int  = ETHERNET_MTU_DEFAULT
    auth_type:        int  = AUTH_TYPE_NULL
    auth_key:         bytes= b""
    options:          int  = 0x02
    dr:               str  = "0.0.0.0"
    bdr:              str  = "0.0.0.0"
    neighbors:        Dict[str, OSPFNeighbor] = field(default_factory=dict)
    event_log:        List[str] = field(default_factory=list)

    def process_event(self, event: str) -> str:
        transitions = INTERFACE_TRANSITIONS.get(self.state, {})
        new_state = transitions.get(event, self.state)
        self.event_log.append(f"{self.state} --[{event}]--> {new_state}")
        self.state = new_state
        return new_state

    def is_dr(self) -> bool:
        return self.state == IFACE_STATE_DR

    def is_bdr(self) -> bool:
        return self.state == IFACE_STATE_BDR

    def is_active(self) -> bool:
        return self.state not in (IFACE_STATE_DOWN, IFACE_STATE_LOOPBACK)

    def get_full_neighbors(self) -> List[OSPFNeighbor]:
        return [n for n in self.neighbors.values() if n.is_full()]

    def add_neighbor(self, nbr: OSPFNeighbor):
        self.neighbors[nbr.router_id] = nbr

    def remove_neighbor(self, router_id: str):
        self.neighbors.pop(router_id, None)


# ──────────────────────────────────────────────────────────────
#  DR/BDR Election (RFC 2328 Section 9.4)
# ──────────────────────────────────────────────────────────────

def elect_dr_bdr(interface: OSPFInterface, self_router_id: str) -> tuple:
    """
    Simulate DR/BDR election per RFC 2328 Section 9.4.
    Returns (elected_dr, elected_bdr) as router_id strings.
    """
    candidates = []
    for nbr in interface.neighbors.values():
        if nbr.priority > 0 and nbr.state in (NBR_STATE_2WAY, NBR_STATE_FULL,
                                                NBR_STATE_EXSTART, NBR_STATE_EXCHANGE,
                                                NBR_STATE_LOADING):
            candidates.append((nbr.priority, nbr.router_id, nbr.ip_address))
    if interface.priority > 0:
        candidates.append((interface.priority, self_router_id, interface.ip_address))

    if not candidates:
        return "0.0.0.0", "0.0.0.0"

    # BDR: highest priority among non-declared-DR; ties broken by router_id
    sorted_cands = sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)
    bdr_candidate = sorted_cands[0][1]
    dr_candidate  = sorted_cands[0][1] if len(sorted_cands) == 1 else sorted_cands[0][1]

    return dr_candidate, bdr_candidate


# ──────────────────────────────────────────────────────────────
#  OSPF Router (simplified)
# ──────────────────────────────────────────────────────────────

@dataclass
class OSPFRouter:
    router_id:    str = "1.1.1.1"
    interfaces:   Dict[str, OSPFInterface] = field(default_factory=dict)
    areas:        Dict[str, dict] = field(default_factory=dict)
    lsdb:         Dict[str, dict] = field(default_factory=dict)   # area_id -> {lsa_key -> LSAHeader}
    is_abr:       bool = False
    is_asbr:      bool = False

    def add_interface(self, iface: OSPFInterface):
        self.interfaces[iface.name] = iface

    def get_lsdb_for_area(self, area_id: str) -> dict:
        return self.lsdb.setdefault(area_id, {})

    def install_lsa(self, area_id: str, lsa_header, lsa_data):
        db = self.get_lsdb_for_area(area_id)
        key = (lsa_header.lsa_type, lsa_header.link_state_id, lsa_header.adv_router)
        db[key] = {"header": lsa_header, "data": lsa_data}

    def lookup_lsa(self, area_id: str, lsa_type: int, link_state_id: str, adv_router: str):
        db = self.get_lsdb_for_area(area_id)
        return db.get((lsa_type, link_state_id, adv_router))
