"""
Tests for OSPF SPF (Dijkstra) Algorithm - RFC 2328 Section 16
Validates shortest path computation from LSDB
"""

import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ospf_lib.spf import SPFGraph, SPFNode, build_graph_from_router_lsas
from ospf_lib.packets import RouterLSA, RouterLink, LSAHeader
from ospf_lib.constants import *


class TestSPFGraphBasic(unittest.TestCase):
    """Basic SPF graph construction and Dijkstra"""

    def test_empty_graph_returns_empty(self):
        g = SPFGraph()
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result, {})

    def test_single_node_cost_zero(self):
        g = SPFGraph()
        g.add_node("1.1.1.1")
        g.nodes["1.1.1.1"].cost = 0
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["1.1.1.1"].cost, 0)

    def test_direct_neighbor_cost_equals_link_cost(self):
        g = SPFGraph()
        g.add_edge("1.1.1.1", "2.2.2.2", 10)
        g.add_edge("2.2.2.2", "1.1.1.1", 10)
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["2.2.2.2"].cost, 10)

    def test_two_hop_path_cost(self):
        g = SPFGraph()
        g.add_edge("A", "B", 5)
        g.add_edge("B", "C", 5)
        g.add_edge("A", "C", 100)  # longer direct path
        result = g.run_dijkstra("A")
        self.assertEqual(result["C"].cost, 10)   # via B: 5+5 < 100

    def test_shortest_path_chosen_over_longer(self):
        g = SPFGraph()
        g.add_edge("1.1.1.1", "2.2.2.2", 1)
        g.add_edge("1.1.1.1", "3.3.3.3", 10)
        g.add_edge("2.2.2.2", "3.3.3.3", 1)
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["3.3.3.3"].cost, 2)   # via 2.2.2.2: 1+1 < 10

    def test_unreachable_node_cost_infinity(self):
        g = SPFGraph()
        g.add_node("1.1.1.1")
        g.add_node("9.9.9.9")   # isolated
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["9.9.9.9"].cost, INFINITY)

    def test_unknown_source_returns_empty(self):
        g = SPFGraph()
        g.add_node("1.1.1.1")
        result = g.run_dijkstra("99.99.99.99")
        self.assertEqual(result, {})

    def test_source_has_zero_cost(self):
        g = SPFGraph()
        g.add_edge("1.1.1.1", "2.2.2.2", 10)
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["1.1.1.1"].cost, 0)


class TestSPFGraphTopologies(unittest.TestCase):
    """Test SPF on various real-world topologies"""

    def test_linear_chain(self):
        """A--10--B--10--C--10--D"""
        g = SPFGraph()
        for src, dst in [("A","B"), ("B","C"), ("C","D")]:
            g.add_edge(src, dst, 10)
            g.add_edge(dst, src, 10)
        result = g.run_dijkstra("A")
        self.assertEqual(result["B"].cost, 10)
        self.assertEqual(result["C"].cost, 20)
        self.assertEqual(result["D"].cost, 30)

    def test_ring_topology(self):
        """A--1--B--1--C--100--A (ring, shortest path avoids expensive link)"""
        g = SPFGraph()
        g.add_edge("A", "B", 1)
        g.add_edge("B", "A", 1)
        g.add_edge("B", "C", 1)
        g.add_edge("C", "B", 1)
        g.add_edge("A", "C", 100)
        g.add_edge("C", "A", 100)
        result = g.run_dijkstra("A")
        self.assertEqual(result["C"].cost, 2)   # via B

    def test_diamond_topology(self):
        """
            B(cost 1)
           / \
          A   D
           \ /
            C(cost 5)
        """
        g = SPFGraph()
        g.add_edge("A", "B", 1)
        g.add_edge("B", "D", 1)
        g.add_edge("A", "C", 5)
        g.add_edge("C", "D", 5)
        result = g.run_dijkstra("A")
        self.assertEqual(result["D"].cost, 2)   # via B: 1+1

    def test_full_mesh_3_nodes(self):
        g = SPFGraph()
        for src, dst, cost in [("R1","R2",10), ("R2","R1",10),
                                 ("R1","R3",20), ("R3","R1",20),
                                 ("R2","R3",5),  ("R3","R2",5)]:
            g.add_edge(src, dst, cost)
        result = g.run_dijkstra("R1")
        self.assertEqual(result["R2"].cost, 10)
        self.assertEqual(result["R3"].cost, 15)   # R1->R2->R3: 10+5

    def test_data_center_spine_leaf(self):
        """Spine-Leaf topology: 2 spines, 4 leaves, all-active uplinks"""
        g = SPFGraph()
        spines = ["S1", "S2"]
        leaves = ["L1", "L2", "L3", "L4"]
        for leaf in leaves:
            for spine in spines:
                g.add_edge(leaf, spine, 1)
                g.add_edge(spine, leaf, 1)
        result = g.run_dijkstra("L1")
        # L1 to L2: L1->S1->L2 = cost 2
        self.assertEqual(result["L2"].cost, 2)
        self.assertEqual(result["S1"].cost, 1)

    def test_ecmp_equal_cost_paths(self):
        """Two equal-cost paths - final cost should be same regardless of path"""
        g = SPFGraph()
        g.add_edge("A", "B1", 5)
        g.add_edge("B1", "C", 5)
        g.add_edge("A", "B2", 5)
        g.add_edge("B2", "C", 5)
        result = g.run_dijkstra("A")
        self.assertEqual(result["C"].cost, 10)

    def test_ospf_default_cost_10(self):
        self.assertEqual(OSPF_DEFAULT_COST, 10)

    def test_ospf_max_metric_65535(self):
        self.assertEqual(OSPF_MAX_METRIC, 0xFFFF)


class TestSPFRoutingTable(unittest.TestCase):
    """Test routing table generation from SPF results"""

    def test_routing_table_excludes_source(self):
        g = SPFGraph()
        g.add_edge("R1", "R2", 10)
        table = g.get_routing_table("R1")
        dests = [e["destination"] for e in table]
        self.assertNotIn("R1", dests)

    def test_routing_table_includes_reachable(self):
        g = SPFGraph()
        g.add_edge("R1", "R2", 10)
        g.add_edge("R2", "R3", 10)
        table = g.get_routing_table("R1")
        dests = [e["destination"] for e in table]
        self.assertIn("R2", dests)
        self.assertIn("R3", dests)

    def test_routing_table_excludes_unreachable(self):
        g = SPFGraph()
        g.add_node("R1")
        g.add_node("ISOLATED")
        table = g.get_routing_table("R1")
        dests = [e["destination"] for e in table]
        self.assertNotIn("ISOLATED", dests)

    def test_routing_table_has_cost(self):
        g = SPFGraph()
        g.add_edge("R1", "R2", 15)
        table = g.get_routing_table("R1")
        entry = next(e for e in table if e["destination"] == "R2")
        self.assertEqual(entry["cost"], 15)

    def test_routing_table_has_nexthop(self):
        g = SPFGraph()
        g.add_edge("R1", "R2", 10)
        g.add_edge("R2", "R3", 10)
        table = g.get_routing_table("R1")
        r3_entry = next(e for e in table if e["destination"] == "R3")
        self.assertNotEqual(r3_entry["nexthop"], "")


class TestBuildGraphFromRouterLSAs(unittest.TestCase):
    """Test building SPF graph from RouterLSA objects"""

    def _make_router_lsa(self, router_id, links):
        lsa = RouterLSA()
        lsa.header.adv_router = router_id
        lsa.header.link_state_id = router_id
        lsa.links = links
        return lsa

    def test_single_router_lsa_no_links(self):
        rlsa = self._make_router_lsa("1.1.1.1", [])
        g = build_graph_from_router_lsas([rlsa])
        self.assertIn("1.1.1.1", g.nodes)

    def test_p2p_link_creates_edges(self):
        link = RouterLink(link_id="2.2.2.2", link_type=ROUTER_LINK_P2P, metric=10)
        rlsa = self._make_router_lsa("1.1.1.1", [link])
        g = build_graph_from_router_lsas([rlsa])
        self.assertIn(("2.2.2.2", 10), g.edges.get("1.1.1.1", []))

    def test_transit_link_creates_edges(self):
        link = RouterLink(link_id="10.0.0.1", link_type=ROUTER_LINK_TRANSIT, metric=5)
        rlsa = self._make_router_lsa("1.1.1.1", [link])
        g = build_graph_from_router_lsas([rlsa])
        self.assertIn(("10.0.0.1", 5), g.edges.get("1.1.1.1", []))

    def test_stub_link_not_added_as_edge(self):
        """Stub links are prefixes, not topology links"""
        link = RouterLink(link_id="10.0.0.0", link_type=ROUTER_LINK_STUB, metric=1)
        rlsa = self._make_router_lsa("1.1.1.1", [link])
        g = build_graph_from_router_lsas([rlsa])
        self.assertEqual(g.edges.get("1.1.1.1", []), [])

    def test_full_two_router_topology(self):
        link1 = RouterLink(link_id="2.2.2.2", link_type=ROUTER_LINK_P2P, metric=10)
        link2 = RouterLink(link_id="1.1.1.1", link_type=ROUTER_LINK_P2P, metric=10)
        r1 = self._make_router_lsa("1.1.1.1", [link1])
        r2 = self._make_router_lsa("2.2.2.2", [link2])
        g = build_graph_from_router_lsas([r1, r2])
        result = g.run_dijkstra("1.1.1.1")
        self.assertEqual(result["2.2.2.2"].cost, 10)


class TestSPFNodeOrdering(unittest.TestCase):
    """Test SPFNode priority queue ordering"""

    def test_lower_cost_node_is_less_than(self):
        n1 = SPFNode(router_id="1.1.1.1", cost=5)
        n2 = SPFNode(router_id="2.2.2.2", cost=10)
        self.assertLess(n1, n2)

    def test_equal_cost_nodes_not_less(self):
        n1 = SPFNode(router_id="1.1.1.1", cost=10)
        n2 = SPFNode(router_id="2.2.2.2", cost=10)
        self.assertFalse(n1 < n2)

    def test_infinity_constant(self):
        self.assertEqual(INFINITY, 0xFFFF)
        self.assertEqual(INFINITY, 65535)


if __name__ == "__main__":
    unittest.main(verbosity=2)
