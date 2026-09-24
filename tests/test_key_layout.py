#!/usr/bin/env python3

import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sojourn_monitor


class KeyLayoutTest(unittest.TestCase):
    def make_flow_bytes(self, protocol):
        return (
            socket.inet_aton("192.168.3.103")
            + socket.inet_aton("192.168.3.122")
            + struct.pack("=HHB3x", 50000, 5201, protocol)
        )

    def test_flow_id_layout(self):
        key = self.make_flow_bytes(sojourn_monitor.IPPROTO_UDP)

        self.assertEqual(len(key), sojourn_monitor.FLOW_ID_SIZE)
        self.assertEqual(
            sojourn_monitor.parse_flow_id(key),
            (
                "192.168.3.103",
                "192.168.3.122",
                50000,
                5201,
                sojourn_monitor.IPPROTO_UDP,
            ),
        )

    def test_pkt_id_embeds_flow_id(self):
        flow = self.make_flow_bytes(sojourn_monitor.IPPROTO_TCP)
        key = flow + struct.pack("=I", 123456)

        self.assertEqual(len(key), sojourn_monitor.PKT_ID_SIZE)
        self.assertEqual(
            sojourn_monitor.parse_pkt_id(key),
            (
                "192.168.3.103",
                "192.168.3.122",
                50000,
                5201,
                sojourn_monitor.IPPROTO_TCP,
                123456,
            ),
        )

    def test_invalid_key_sizes_are_rejected(self):
        with self.assertRaises(ValueError):
            sojourn_monitor.parse_flow_id(b"\x00" * 15)
        with self.assertRaises(ValueError):
            sojourn_monitor.parse_pkt_id(b"\x00" * 19)


if __name__ == "__main__":
    unittest.main()
