"""
OSPF Constants - RFC 2328 (OSPFv2) / RFC 5340 (OSPFv3)
IEEE 802 related constants for OSPF over different link types
"""

# ─────────────────────────────────────────────
#  OSPF Packet Types (RFC 2328 Section A.3.1)
# ─────────────────────────────────────────────
OSPF_PKT_HELLO         = 1
OSPF_PKT_DBD           = 2   # Database Description
OSPF_PKT_LSR           = 3   # Link State Request
OSPF_PKT_LSU           = 4   # Link State Update
OSPF_PKT_LSACK         = 5   # Link State Acknowledgment

OSPF_PACKET_TYPES = {
    OSPF_PKT_HELLO: "Hello",
    OSPF_PKT_DBD:   "DatabaseDescription",
    OSPF_PKT_LSR:   "LinkStateRequest",
    OSPF_PKT_LSU:   "LinkStateUpdate",
    OSPF_PKT_LSACK: "LinkStateAck",
}

# ─────────────────────────────────────────────
#  OSPF Version
# ─────────────────────────────────────────────
OSPF_VERSION_2 = 2  # OSPFv2 (IPv4)  RFC 2328
OSPF_VERSION_3 = 3  # OSPFv3 (IPv6)  RFC 5340

# ─────────────────────────────────────────────
#  Well-Known Addresses (RFC 2328 Appendix A.1)
# ─────────────────────────────────────────────
OSPF_ALL_ROUTERS_MCAST  = "224.0.0.5"   # AllSPFRouters
OSPF_ALL_DR_MCAST       = "224.0.0.6"   # AllDRouters
OSPF_IP_PROTOCOL        = 89
OSPF_HEADER_LEN         = 24            # bytes

# ─────────────────────────────────────────────
#  LSA Types (RFC 2328 Section 12.1.3)
# ─────────────────────────────────────────────
LSA_TYPE_ROUTER         = 1
LSA_TYPE_NETWORK        = 2
LSA_TYPE_SUMMARY_NET    = 3
LSA_TYPE_SUMMARY_ASBR   = 4
LSA_TYPE_AS_EXTERNAL    = 5
LSA_TYPE_NSSA_EXTERNAL  = 7   # RFC 3101
LSA_TYPE_OPAQUE_LINK    = 9   # RFC 5250
LSA_TYPE_OPAQUE_AREA    = 10
LSA_TYPE_OPAQUE_AS      = 11

LSA_TYPES = {
    LSA_TYPE_ROUTER:        "Router-LSA",
    LSA_TYPE_NETWORK:       "Network-LSA",
    LSA_TYPE_SUMMARY_NET:   "Summary-LSA (Network)",
    LSA_TYPE_SUMMARY_ASBR:  "Summary-LSA (ASBR)",
    LSA_TYPE_AS_EXTERNAL:   "AS-External-LSA",
    LSA_TYPE_NSSA_EXTERNAL: "NSSA-External-LSA",
    LSA_TYPE_OPAQUE_LINK:   "Opaque-LSA (link-local)",
    LSA_TYPE_OPAQUE_AREA:   "Opaque-LSA (area)",
    LSA_TYPE_OPAQUE_AS:     "Opaque-LSA (AS)",
}

# ─────────────────────────────────────────────
#  Router-LSA Link Types (RFC 2328 A.4.2)
# ─────────────────────────────────────────────
ROUTER_LINK_P2P         = 1
ROUTER_LINK_TRANSIT     = 2
ROUTER_LINK_STUB        = 3
ROUTER_LINK_VIRTUAL     = 4

# ─────────────────────────────────────────────
#  OSPF Neighbor States (RFC 2328 Section 10.1)
# ─────────────────────────────────────────────
NBR_STATE_DOWN          = "Down"
NBR_STATE_ATTEMPT       = "Attempt"
NBR_STATE_INIT          = "Init"
NBR_STATE_2WAY          = "2-Way"
NBR_STATE_EXSTART       = "ExStart"
NBR_STATE_EXCHANGE      = "Exchange"
NBR_STATE_LOADING       = "Loading"
NBR_STATE_FULL          = "Full"

NEIGHBOR_STATES = [
    NBR_STATE_DOWN, NBR_STATE_ATTEMPT, NBR_STATE_INIT,
    NBR_STATE_2WAY, NBR_STATE_EXSTART, NBR_STATE_EXCHANGE,
    NBR_STATE_LOADING, NBR_STATE_FULL,
]

# ─────────────────────────────────────────────
#  Interface States (RFC 2328 Section 9.1)
# ─────────────────────────────────────────────
IFACE_STATE_DOWN        = "Down"
IFACE_STATE_LOOPBACK    = "Loopback"
IFACE_STATE_WAITING     = "Waiting"
IFACE_STATE_P2P         = "Point-to-Point"
IFACE_STATE_DR_OTHER    = "DROther"
IFACE_STATE_BDR         = "Backup"
IFACE_STATE_DR          = "DR"

INTERFACE_STATES = [
    IFACE_STATE_DOWN, IFACE_STATE_LOOPBACK, IFACE_STATE_WAITING,
    IFACE_STATE_P2P, IFACE_STATE_DR_OTHER, IFACE_STATE_BDR, IFACE_STATE_DR,
]

# ─────────────────────────────────────────────
#  Interface Types (RFC 2328 Section 1.2)
# ─────────────────────────────────────────────
IFACE_TYPE_BROADCAST    = "Broadcast"
IFACE_TYPE_P2P          = "Point-to-Point"
IFACE_TYPE_NBMA         = "NBMA"
IFACE_TYPE_P2MP         = "Point-to-Multipoint"
IFACE_TYPE_VIRTUAL      = "Virtual"

# ─────────────────────────────────────────────
#  Area Types
# ─────────────────────────────────────────────
AREA_TYPE_NORMAL        = "Normal"
AREA_TYPE_STUB          = "Stub"
AREA_TYPE_TOTALLY_STUB  = "Totally-Stub"
AREA_TYPE_NSSA          = "NSSA"

# ─────────────────────────────────────────────
#  Default Timer Values (RFC 2328 Appendix B)
# ─────────────────────────────────────────────
DEFAULT_HELLO_INTERVAL      = 10    # seconds
DEFAULT_DEAD_INTERVAL       = 40    # seconds (4 × hello)
DEFAULT_RXMT_INTERVAL       = 5     # seconds
DEFAULT_TRANSMIT_DELAY      = 1     # seconds
DEFAULT_ROUTER_PRIORITY     = 1
DEFAULT_ROUTER_DEAD_MULT    = 4
DEFAULT_POLL_INTERVAL       = 120   # NBMA
DEFAULT_MAX_AGE             = 3600  # seconds (1 hour)
DEFAULT_LS_REFRESH_TIME     = 1800  # seconds (30 min)
DEFAULT_MIN_LS_INTERVAL     = 5     # seconds
DEFAULT_MIN_LS_ARRIVAL      = 1     # seconds
DEFAULT_MAX_AGE_DIFF        = 900   # seconds

# ─────────────────────────────────────────────
#  LSA Header Field Ranges (RFC 2328 A.4.1)
# ─────────────────────────────────────────────
LSA_MAX_AGE             = 3600
LSA_MAX_AGE_DIFF        = 900
LSA_INITIAL_SEQUENCE    = 0x80000001  # MinLSSequenceNumber
LSA_MAX_SEQUENCE        = 0x7FFFFFFF  # MaxLSSequenceNumber
LSA_CHECKSUM_OFFSET     = 16

# ─────────────────────────────────────────────
#  DBD Packet Flags (RFC 2328 A.3.3)
# ─────────────────────────────────────────────
DBD_FLAG_MS             = 0x01   # Master/Slave
DBD_FLAG_M              = 0x02   # More
DBD_FLAG_I              = 0x04   # Init

# ─────────────────────────────────────────────
#  Router-LSA Flags (RFC 2328 A.4.2)
# ─────────────────────────────────────────────
ROUTER_FLAG_B           = 0x01   # Area Border Router
ROUTER_FLAG_E           = 0x02   # AS Boundary Router
ROUTER_FLAG_V           = 0x04   # Virtual Link Endpoint
ROUTER_FLAG_Nt          = 0x10   # NSSA capable (RFC 3101)

# ─────────────────────────────────────────────
#  External Route Types
# ─────────────────────────────────────────────
EXTERNAL_TYPE_1         = 1
EXTERNAL_TYPE_2         = 2

# ─────────────────────────────────────────────
#  OSPF over IEEE 802 (Ethernet) - Link Layer
# ─────────────────────────────────────────────
IEEE_OSPF_MULTICAST_MAC_ALL   = "01:00:5e:00:00:05"   # AllSPFRouters
IEEE_OSPF_MULTICAST_MAC_DR    = "01:00:5e:00:00:06"   # AllDRouters
ETHERNET_MTU_DEFAULT          = 1500
OSPF_MTU_MISMATCH_CHECK       = True

# ─────────────────────────────────────────────
#  Authentication Types (RFC 2328 D)
# ─────────────────────────────────────────────
AUTH_TYPE_NULL          = 0
AUTH_TYPE_SIMPLE        = 1
AUTH_TYPE_CRYPTO        = 2   # MD5 (RFC 2154)

# ─────────────────────────────────────────────
#  SPF Calculation
# ─────────────────────────────────────────────
SPF_DELAY               = 5    # seconds
SPF_HOLD_TIME           = 10   # seconds
INFINITY                = 0xFFFF  # RFC 2328 Section 2.4

# ─────────────────────────────────────────────
#  OSPF Metric / Cost
# ─────────────────────────────────────────────
OSPF_DEFAULT_COST       = 10
OSPF_MAX_METRIC         = 0xFFFF    # 65535
OSPF_STUB_DEFAULT_COST  = 1
