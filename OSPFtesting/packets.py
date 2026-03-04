"""
OSPF Packet Structures - RFC 2328
Full encode/decode for all 5 OSPF packet types + LSA headers
"""

import struct
import socket
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from .constants import *


# ──────────────────────────────────────────────────────────────
#  Helper utilities
# ──────────────────────────────────────────────────────────────

def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))

def int_to_ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))

def fletcher_checksum(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """RFC 905 Fletcher checksum used for LSA checksum (C0, C1)."""
    c0 = c1 = 0
    for i, b in enumerate(data):
        if i == offset or i == offset + 1:
            continue
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - offset - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return x, y

def inet_checksum(data: bytes) -> int:
    """Standard Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ──────────────────────────────────────────────────────────────
#  OSPF Common Header (RFC 2328 A.3.1) - 24 bytes
# ──────────────────────────────────────────────────────────────

@dataclass
class OSPFHeader:
    version:      int = OSPF_VERSION_2
    packet_type:  int = OSPF_PKT_HELLO
    packet_len:   int = OSPF_HEADER_LEN
    router_id:    str = "0.0.0.0"
    area_id:      str = "0.0.0.0"
    checksum:     int = 0
    auth_type:    int = AUTH_TYPE_NULL
    auth_data:    int = 0          # 64-bit field

    FORMAT = "!BBHIIHHQ"
    SIZE   = 24

    def encode(self) -> bytes:
        return struct.pack(
            self.FORMAT,
            self.version,
            self.packet_type,
            self.packet_len,
            ip_to_int(self.router_id),
            ip_to_int(self.area_id),
            self.checksum,
            self.auth_type,
            self.auth_data & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "OSPFHeader":
        if len(data) < cls.SIZE:
            raise ValueError(f"Header too short: {len(data)} < {cls.SIZE}")
        v, pt, pl, rid, aid, chk, at, ad = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(
            version=v, packet_type=pt, packet_len=pl,
            router_id=int_to_ip(rid), area_id=int_to_ip(aid),
            checksum=chk, auth_type=at, auth_data=ad,
        )

    def is_valid_version(self) -> bool:
        return self.version in (OSPF_VERSION_2, OSPF_VERSION_3)

    def is_valid_type(self) -> bool:
        return self.packet_type in OSPF_PACKET_TYPES


# ──────────────────────────────────────────────────────────────
#  Hello Packet (RFC 2328 A.3.2)
# ──────────────────────────────────────────────────────────────

@dataclass
class OSPFHello:
    header:              OSPFHeader = field(default_factory=lambda: OSPFHeader(packet_type=OSPF_PKT_HELLO))
    network_mask:        str  = "255.255.255.0"
    hello_interval:      int  = DEFAULT_HELLO_INTERVAL
    options:             int  = 0x02   # E-bit set (external routing capability)
    router_priority:     int  = DEFAULT_ROUTER_PRIORITY
    dead_interval:       int  = DEFAULT_DEAD_INTERVAL
    designated_router:   str  = "0.0.0.0"
    backup_dr:           str  = "0.0.0.0"
    neighbors:           List[str] = field(default_factory=list)

    BODY_FORMAT = "!IHBBIII"
    BODY_SIZE   = 20

    def encode(self) -> bytes:
        nbr_bytes = b"".join(struct.pack("!I", ip_to_int(n)) for n in self.neighbors)
        body = struct.pack(
            self.BODY_FORMAT,
            ip_to_int(self.network_mask),
            self.hello_interval,
            self.options,
            self.router_priority,
            self.dead_interval,
            ip_to_int(self.designated_router),
            ip_to_int(self.backup_dr),
        ) + nbr_bytes
        self.header.packet_len = OSPFHeader.SIZE + len(body)
        self.header.packet_type = OSPF_PKT_HELLO
        hdr = self.header.encode()
        raw = hdr + body
        chk = inet_checksum(raw)
        return raw[:12] + struct.pack("!H", chk) + raw[14:]

    @classmethod
    def decode(cls, data: bytes) -> "OSPFHello":
        hdr = OSPFHeader.decode(data)
        offset = OSPFHeader.SIZE
        nm, hi, opts, rp, di, dr, bdr = struct.unpack(
            cls.BODY_FORMAT, data[offset:offset + cls.BODY_SIZE]
        )
        offset += cls.BODY_SIZE
        neighbors = []
        while offset + 4 <= len(data):
            neighbors.append(int_to_ip(struct.unpack("!I", data[offset:offset+4])[0]))
            offset += 4
        return cls(
            header=hdr,
            network_mask=int_to_ip(nm),
            hello_interval=hi,
            options=opts,
            router_priority=rp,
            dead_interval=di,
            designated_router=int_to_ip(dr),
            backup_dr=int_to_ip(bdr),
            neighbors=neighbors,
        )

    def is_dead_interval_valid(self) -> bool:
        return self.dead_interval >= self.hello_interval

    def has_neighbor(self, router_id: str) -> bool:
        return router_id in self.neighbors


# ──────────────────────────────────────────────────────────────
#  Database Description (DBD) Packet (RFC 2328 A.3.3)
# ──────────────────────────────────────────────────────────────

@dataclass
class LSAHeader:
    age:          int = 0
    options:      int = 0
    lsa_type:     int = LSA_TYPE_ROUTER
    link_state_id: str = "0.0.0.0"
    adv_router:   str = "0.0.0.0"
    seq_number:   int = LSA_INITIAL_SEQUENCE
    checksum:     int = 0
    length:       int = 20

    FORMAT = "!HBBIIiHH"
    SIZE   = 20

    def encode(self) -> bytes:
        # seq_number is RFC 2328 signed int; convert unsigned 0x80000001 to signed equivalent
        seq = self.seq_number if self.seq_number <= 0x7FFFFFFF else self.seq_number - 0x100000000
        return struct.pack(
            self.FORMAT,
            self.age, self.options, self.lsa_type,
            ip_to_int(self.link_state_id),
            ip_to_int(self.adv_router),
            seq, self.checksum, self.length,
        )

    @classmethod
    def decode(cls, data: bytes) -> "LSAHeader":
        if len(data) < cls.SIZE:
            raise ValueError(f"LSA header too short: {len(data)}")
        age, opts, typ, lsid, advr, seq, chk, ln = struct.unpack(
            cls.FORMAT, data[:cls.SIZE]
        )
        # Normalize signed int to unsigned for comparison
        if seq < 0:
            seq = seq + 0x100000000
        return cls(
            age=age, options=opts, lsa_type=typ,
            link_state_id=int_to_ip(lsid),
            adv_router=int_to_ip(advr),
            seq_number=seq, checksum=chk, length=ln,
        )

    def is_maxage(self) -> bool:
        return self.age >= LSA_MAX_AGE

    def is_valid_type(self) -> bool:
        return self.lsa_type in LSA_TYPES

    def is_valid_sequence(self) -> bool:
        return LSA_INITIAL_SEQUENCE <= (self.seq_number & 0xFFFFFFFF) <= 0xFFFFFFFF

    def is_more_recent(self, other: "LSAHeader") -> bool:
        """RFC 2328 Section 13.1 - determine which LSA is more recent."""
        if self.seq_number != other.seq_number:
            return self.seq_number > other.seq_number
        if self.checksum != other.checksum:
            return self.checksum > other.checksum
        if self.age >= LSA_MAX_AGE and other.age < LSA_MAX_AGE:
            return True
        if abs(self.age - other.age) > LSA_MAX_AGE_DIFF:
            return self.age < other.age
        return False


@dataclass
class OSPFDatabaseDescription:
    header:      OSPFHeader = field(default_factory=lambda: OSPFHeader(packet_type=OSPF_PKT_DBD))
    interface_mtu: int = ETHERNET_MTU_DEFAULT
    options:     int = 0x02
    flags:       int = DBD_FLAG_MS | DBD_FLAG_I
    sequence:    int = 0
    lsa_headers: List[LSAHeader] = field(default_factory=list)

    BODY_FORMAT = "!HBBI"
    BODY_SIZE   = 8

    @property
    def is_master(self) -> bool:
        return bool(self.flags & DBD_FLAG_MS)

    @property
    def is_more(self) -> bool:
        return bool(self.flags & DBD_FLAG_M)

    @property
    def is_init(self) -> bool:
        return bool(self.flags & DBD_FLAG_I)

    def encode(self) -> bytes:
        body = struct.pack(self.BODY_FORMAT, self.interface_mtu, self.options, self.flags, self.sequence)
        for lh in self.lsa_headers:
            body += lh.encode()
        self.header.packet_len = OSPFHeader.SIZE + len(body)
        self.header.packet_type = OSPF_PKT_DBD
        return self.header.encode() + body

    @classmethod
    def decode(cls, data: bytes) -> "OSPFDatabaseDescription":
        hdr = OSPFHeader.decode(data)
        offset = OSPFHeader.SIZE
        mtu, opts, flags, seq = struct.unpack(cls.BODY_FORMAT, data[offset:offset + cls.BODY_SIZE])
        offset += cls.BODY_SIZE
        lsa_headers = []
        while offset + LSAHeader.SIZE <= len(data):
            lsa_headers.append(LSAHeader.decode(data[offset:offset + LSAHeader.SIZE]))
            offset += LSAHeader.SIZE
        return cls(header=hdr, interface_mtu=mtu, options=opts, flags=flags,
                   sequence=seq, lsa_headers=lsa_headers)


# ──────────────────────────────────────────────────────────────
#  Link State Request (RFC 2328 A.3.4)
# ──────────────────────────────────────────────────────────────

@dataclass
class LSRequest:
    lsa_type:      int = LSA_TYPE_ROUTER
    link_state_id: str = "0.0.0.0"
    adv_router:    str = "0.0.0.0"

    FORMAT = "!III"
    SIZE   = 12

    def encode(self) -> bytes:
        return struct.pack(self.FORMAT, self.lsa_type,
                           ip_to_int(self.link_state_id), ip_to_int(self.adv_router))

    @classmethod
    def decode(cls, data: bytes) -> "LSRequest":
        t, lsid, advr = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(lsa_type=t, link_state_id=int_to_ip(lsid), adv_router=int_to_ip(advr))


@dataclass
class OSPFLinkStateRequest:
    header:   OSPFHeader = field(default_factory=lambda: OSPFHeader(packet_type=OSPF_PKT_LSR))
    requests: List[LSRequest] = field(default_factory=list)

    def encode(self) -> bytes:
        body = b"".join(r.encode() for r in self.requests)
        self.header.packet_len = OSPFHeader.SIZE + len(body)
        self.header.packet_type = OSPF_PKT_LSR
        return self.header.encode() + body

    @classmethod
    def decode(cls, data: bytes) -> "OSPFLinkStateRequest":
        hdr = OSPFHeader.decode(data)
        offset = OSPFHeader.SIZE
        requests = []
        while offset + LSRequest.SIZE <= len(data):
            requests.append(LSRequest.decode(data[offset:]))
            offset += LSRequest.SIZE
        return cls(header=hdr, requests=requests)


# ──────────────────────────────────────────────────────────────
#  Router LSA (RFC 2328 A.4.2)
# ──────────────────────────────────────────────────────────────

@dataclass
class RouterLink:
    link_id:    str = "0.0.0.0"
    link_data:  str = "0.0.0.0"
    link_type:  int = ROUTER_LINK_STUB
    num_tos:    int = 0
    metric:     int = OSPF_DEFAULT_COST

    FORMAT = "!IIBBH"
    SIZE   = 12

    def encode(self) -> bytes:
        return struct.pack(self.FORMAT, ip_to_int(self.link_id), ip_to_int(self.link_data),
                           self.link_type, self.num_tos, self.metric)

    @classmethod
    def decode(cls, data: bytes) -> "RouterLink":
        lid, ldata, ltype, ntos, metric = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(link_id=int_to_ip(lid), link_data=int_to_ip(ldata),
                   link_type=ltype, num_tos=ntos, metric=metric)


@dataclass
class RouterLSA:
    header: LSAHeader = field(default_factory=lambda: LSAHeader(lsa_type=LSA_TYPE_ROUTER))
    flags:  int = 0
    links:  List[RouterLink] = field(default_factory=list)

    def is_abr(self) -> bool:
        return bool(self.flags & ROUTER_FLAG_B)

    def is_asbr(self) -> bool:
        return bool(self.flags & ROUTER_FLAG_E)

    def is_virtual_link_endpoint(self) -> bool:
        return bool(self.flags & ROUTER_FLAG_V)

    def encode(self) -> bytes:
        body = struct.pack("!HH", self.flags, len(self.links))
        for lnk in self.links:
            body += lnk.encode()
        self.header.length = LSAHeader.SIZE + len(body)
        return self.header.encode() + body


# ──────────────────────────────────────────────────────────────
#  Network LSA (RFC 2328 A.4.3)
# ──────────────────────────────────────────────────────────────

@dataclass
class NetworkLSA:
    header:         LSAHeader = field(default_factory=lambda: LSAHeader(lsa_type=LSA_TYPE_NETWORK))
    network_mask:   str = "255.255.255.0"
    attached_routers: List[str] = field(default_factory=list)

    def encode(self) -> bytes:
        body = struct.pack("!I", ip_to_int(self.network_mask))
        for r in self.attached_routers:
            body += struct.pack("!I", ip_to_int(r))
        self.header.length = LSAHeader.SIZE + len(body)
        return self.header.encode() + body


# ──────────────────────────────────────────────────────────────
#  Summary LSA (RFC 2328 A.4.4)
# ──────────────────────────────────────────────────────────────

@dataclass
class SummaryLSA:
    header:       LSAHeader = field(default_factory=lambda: LSAHeader(lsa_type=LSA_TYPE_SUMMARY_NET))
    network_mask: str = "255.255.255.0"
    metric:       int = OSPF_DEFAULT_COST

    def encode(self) -> bytes:
        body = struct.pack("!II", ip_to_int(self.network_mask), self.metric & 0x00FFFFFF)
        self.header.length = LSAHeader.SIZE + len(body)
        return self.header.encode() + body


# ──────────────────────────────────────────────────────────────
#  AS External LSA (RFC 2328 A.4.5)
# ──────────────────────────────────────────────────────────────

@dataclass
class ASExternalLSA:
    header:          LSAHeader = field(default_factory=lambda: LSAHeader(lsa_type=LSA_TYPE_AS_EXTERNAL))
    network_mask:    str = "255.255.255.0"
    e_bit:           bool = False
    metric:          int = OSPF_DEFAULT_COST
    forwarding_addr: str = "0.0.0.0"
    external_tag:    int = 0

    @property
    def metric_type(self) -> int:
        return EXTERNAL_TYPE_2 if self.e_bit else EXTERNAL_TYPE_1

    def encode(self) -> bytes:
        e_metric = (0x80000000 if self.e_bit else 0) | (self.metric & 0x00FFFFFF)
        body = struct.pack("!IIII", ip_to_int(self.network_mask), e_metric,
                           ip_to_int(self.forwarding_addr), self.external_tag)
        self.header.length = LSAHeader.SIZE + len(body)
        return self.header.encode() + body


# ──────────────────────────────────────────────────────────────
#  Link State Update (RFC 2328 A.3.5)
# ──────────────────────────────────────────────────────────────

@dataclass
class OSPFLinkStateUpdate:
    header:   OSPFHeader = field(default_factory=lambda: OSPFHeader(packet_type=OSPF_PKT_LSU))
    lsas:     List[bytes] = field(default_factory=list)   # raw encoded LSAs

    def encode(self) -> bytes:
        body = struct.pack("!I", len(self.lsas))
        for lsa in self.lsas:
            body += lsa
        self.header.packet_len = OSPFHeader.SIZE + len(body)
        self.header.packet_type = OSPF_PKT_LSU
        return self.header.encode() + body

    @classmethod
    def decode(cls, data: bytes) -> "OSPFLinkStateUpdate":
        hdr = OSPFHeader.decode(data)
        offset = OSPFHeader.SIZE
        count = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4
        lsas = []
        for _ in range(count):
            if offset + LSAHeader.SIZE > len(data):
                break
            lh = LSAHeader.decode(data[offset:])
            lsa_end = offset + lh.length
            lsas.append(data[offset:lsa_end])
            offset = lsa_end
        return cls(header=hdr, lsas=lsas)

    @property
    def num_lsas(self) -> int:
        return len(self.lsas)


# ──────────────────────────────────────────────────────────────
#  Link State Acknowledgment (RFC 2328 A.3.6)
# ──────────────────────────────────────────────────────────────

@dataclass
class OSPFLinkStateAck:
    header:      OSPFHeader = field(default_factory=lambda: OSPFHeader(packet_type=OSPF_PKT_LSACK))
    lsa_headers: List[LSAHeader] = field(default_factory=list)

    def encode(self) -> bytes:
        body = b"".join(lh.encode() for lh in self.lsa_headers)
        self.header.packet_len = OSPFHeader.SIZE + len(body)
        self.header.packet_type = OSPF_PKT_LSACK
        return self.header.encode() + body

    @classmethod
    def decode(cls, data: bytes) -> "OSPFLinkStateAck":
        hdr = OSPFHeader.decode(data)
        offset = OSPFHeader.SIZE
        headers = []
        while offset + LSAHeader.SIZE <= len(data):
            headers.append(LSAHeader.decode(data[offset:]))
            offset += LSAHeader.SIZE
        return cls(header=hdr, lsa_headers=headers)
