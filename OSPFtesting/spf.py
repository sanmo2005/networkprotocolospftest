"""
OSPF SPF (Dijkstra) Algorithm - RFC 2328 Section 16
Computes shortest-path tree from Router-LSA / Network-LSA LSDB
"""

import heapq
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from .constants import *


@dataclass
class SPFNode:
    router_id: str
    cost:      int = 0
    nexthop:   str = ""
    via_iface: str = ""

    def __lt__(self, other: "SPFNode"):
        return self.cost < other.cost


@dataclass
class SPFGraph:
    """
    Simplified OSPF SPF graph built from RouterLSA data.
    nodes: router_id -> SPFNode
    edges: router_id -> [(neighbor_id, cost)]
    """
    nodes: Dict[str, SPFNode]  = field(default_factory=dict)
    edges: Dict[str, List[Tuple[str, int]]] = field(default_factory=dict)

    def add_node(self, router_id: str):
        if router_id not in self.nodes:
            self.nodes[router_id] = SPFNode(router_id=router_id, cost=INFINITY)

    def add_edge(self, src: str, dst: str, cost: int):
        self.add_node(src)
        self.add_node(dst)
        self.edges.setdefault(src, []).append((dst, cost))

    def run_dijkstra(self, source: str) -> Dict[str, SPFNode]:
        """
        RFC 2328 Section 16.1 - Shortest Path First calculation.
        Returns dict of router_id -> SPFNode with costs set.
        """
        if source not in self.nodes:
            return {}

        dist: Dict[str, int] = {n: INFINITY for n in self.nodes}
        prev: Dict[str, Optional[str]] = {n: None for n in self.nodes}
        dist[source] = 0

        pq: List[Tuple[int, str]] = [(0, source)]
        visited: Set[str] = set()

        while pq:
            cost, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)

            for v, w in self.edges.get(u, []):
                alt = cost + w
                if alt < dist.get(v, INFINITY):
                    dist[v] = alt
                    prev[v] = u
                    heapq.heappush(pq, (alt, v))

        result = {}
        for node_id, node_cost in dist.items():
            result[node_id] = SPFNode(
                router_id=node_id,
                cost=node_cost,
                nexthop=self._find_nexthop(source, node_id, prev),
            )
        return result

    def _find_nexthop(self, source: str, dest: str, prev: Dict[str, Optional[str]]) -> str:
        """Trace back path to find first-hop after source."""
        if dest == source:
            return source
        path = []
        cur = dest
        while cur and cur != source:
            path.append(cur)
            cur = prev.get(cur)
        if not path or cur != source:
            return ""
        return path[-1]

    def get_routing_table(self, source: str) -> List[dict]:
        """Build a simple routing table from SPF results."""
        spf = self.run_dijkstra(source)
        table = []
        for router_id, node in spf.items():
            if router_id != source and node.cost < INFINITY:
                table.append({
                    "destination": router_id,
                    "cost":        node.cost,
                    "nexthop":     node.nexthop,
                })
        return table


# ──────────────────────────────────────────────────────────────
#  Intra-area route computation helpers (RFC 2328 Section 16.1)
# ──────────────────────────────────────────────────────────────

def build_graph_from_router_lsas(router_lsas: List) -> SPFGraph:
    """
    Build an SPF graph from a list of RouterLSA objects.
    Each RouterLSA represents a router with its links.
    """
    graph = SPFGraph()
    for rlsa in router_lsas:
        src = rlsa.header.adv_router
        graph.add_node(src)
        for link in rlsa.links:
            if link.link_type in (ROUTER_LINK_P2P, ROUTER_LINK_TRANSIT):
                graph.add_edge(src, link.link_id, link.metric)
    return graph
