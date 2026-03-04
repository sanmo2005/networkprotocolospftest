#!/usr/bin/env python3
"""
OSPF Test Suite Runner
Discovers and runs all tests, produces a detailed report.
Compatible with both: python run_tests.py  AND  pytest run_tests.py
"""

import unittest
import sys
import os
import time
import io
from datetime import datetime

# Ensure we can import ospf_lib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SUITES = [
    ("OSPF Header (RFC 2328 A.3.1)",       "tests.test_ospf_header"),
    ("Hello Packet (RFC 2328 A.3.2)",       "tests.test_hello_packet"),
    ("LSA Types (RFC 2328 A.4)",             "tests.test_lsa_types"),
    ("DBD/LSR/LSU/LSAck (RFC 2328 A.3)",    "tests.test_dbd_lsr_lsu_lsack"),
    ("Neighbor FSM (RFC 2328 Sec 10.3)",    "tests.test_neighbor_fsm"),
    ("Interface FSM + DR/BDR (RFC 2328 9)", "tests.test_interface_fsm"),
    ("SPF Algorithm (RFC 2328 Sec 16)",     "tests.test_spf_algorithm"),
    ("Areas + Auth + IEEE 802",              "tests.test_areas_auth_ieee"),
]

BANNER = "═" * 72


def run_all():
    start_time = time.time()
    loader = unittest.TestLoader()
    total_pass = total_fail = total_error = total_skip = 0

    print(f"\n{BANNER}")
    print(f"  OSPF Protocol Test Suite — RFC 2328 / IEEE 802 Compliance")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(BANNER)

    failures_detail = []

    for suite_name, module_name in SUITES:
        suite = loader.loadTestsFromName(module_name)
        buf = io.StringIO()
        runner = unittest.TextTestRunner(stream=buf, verbosity=2)
        result = runner.run(suite)

        p = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
        f = len(result.failures)
        e = len(result.errors)
        s = len(result.skipped)

        total_pass  += p
        total_fail  += f
        total_error += e
        total_skip  += s

        status = "✅ PASS" if (f + e) == 0 else "❌ FAIL"
        print(f"\n  {status}  {suite_name}")
        print(f"         Tests: {result.testsRun}  Pass: {p}  Fail: {f}  Error: {e}  Skip: {s}")

        if result.failures or result.errors:
            for test, tb in result.failures + result.errors:
                failures_detail.append((str(test), tb))

    elapsed = time.time() - start_time
    total = total_pass + total_fail + total_error + total_skip
    overall = "ALL TESTS PASSED ✅" if (total_fail + total_error) == 0 else "SOME TESTS FAILED ❌"

    print(f"\n{BANNER}")
    print(f"  RESULTS: {overall}")
    print(f"  Total: {total}  Pass: {total_pass}  Fail: {total_fail}  "
          f"Error: {total_error}  Skip: {total_skip}")
    print(f"  Duration: {elapsed:.2f}s")
    print(BANNER)

    if failures_detail:
        print("\n  FAILURE DETAILS:")
        for name, tb in failures_detail:
            print(f"\n  ── {name}")
            for line in tb.splitlines():
                print(f"     {line}")

    return 0 if (total_fail + total_error) == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all())
