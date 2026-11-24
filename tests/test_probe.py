import ipaddress
import unittest

from fritzrouter import CaptureInterface, interfaces_from_page, solve_challenge
from probe import FIELDS, Packet, decode_packet, identify


class RouterTests(unittest.TestCase):
    def test_challenge_pbkdf2(self):
        self.assertEqual(
            solve_challenge("2$10$aabb$20$ccdd", "prova"),
            "ccdd$08e96021ab873829c6104d6801ea079e1651f6540fdd6f53d52dde254a16503e",
        )

    def test_interface_ids_come_from_capture_page(self):
        reply = b'{"data":{"snapshot":{"interfaces":[{"name":"1-lan","displayname":"LAN"}]}}}'
        self.assertEqual(interfaces_from_page(reply), {"1-lan": CaptureInterface("LAN")})

    def test_legacy_html_supplies_actual_stop_parameters(self):
        reply = b'''<table><tr>
            <th>Routing interface</th>
            <td><button name="start" value="3-0">Start</button></td>
            <td><button name="stop" value="3;0;all">Stop</button></td>
            </tr></table>'''
        expected = CaptureInterface("Routing interface", ("3", "0", "all"))
        self.assertEqual(interfaces_from_page(reply), {"3-0": expected})


class PacketTests(unittest.TestCase):
    def test_ipv4_directions_preserve_client_mac(self):
        nets = [ipaddress.ip_network("192.168.178.0/24")]
        pc = "02:00:00:00:00:01"
        gateway = "02:00:00:00:00:02"
        local = ipaddress.ip_address("192.168.178.34")
        remote = ipaddress.ip_address("1.1.1.1")
        self.assertEqual(identify(Packet(local, remote, pc, gateway, 100), nets), (str(local), pc, True))
        self.assertEqual(identify(Packet(remote, local, gateway, pc, 100), nets), (str(local), pc, False))

    def test_globally_routed_ipv6_lan_prefix(self):
        nets = [ipaddress.ip_network("2001:4860:1234::/64")]
        local = ipaddress.ip_address("2001:4860:1234::3")
        remote = ipaddress.ip_address("2606:4700::1111")
        packet = Packet(local, remote, "", "", 74)
        self.assertEqual(identify(packet, nets), (str(local), "", True))
        self.assertIsNone(identify(Packet(remote, remote, "", "", 74), nets))

    def test_local_only_and_multicast_do_not_count(self):
        nets = [ipaddress.ip_network("192.168.178.0/24")]
        local = ipaddress.ip_address("192.168.178.34")
        for peer in ("192.168.178.1", "224.0.0.1", "169.254.1.1"):
            self.assertIsNone(identify(Packet(local, ipaddress.ip_address(peer), "", "", 100), nets))

    def test_dns_response_uses_multiple_addresses_but_only_outer_ips(self):
        values = {
            "frame.protocols": "raw:ip:udp:dns", "frame.time_epoch": "1795525489.120022",
            "ip.src": "192.168.178.1,10.0.0.1", "ip.dst": "192.168.178.34",
            "frame.len": "148", "udp.srcport": "53", "udp.dstport": "42000",
            "dns.flags.response": "1", "dns.qry.name": "example.org",
            "dns.a": "192.0.2.1,192.0.2.2", "dns.aaaa": "2001:db8::1", "dns.resp.ttl": "300",
        }
        packet = decode_packet("\t".join(values.get(field, "") for field in FIELDS))
        self.assertEqual(str(packet.source), "192.168.178.1")
        self.assertEqual((packet.protocol, packet.source_port, packet.dns_ttl), ("UDP", 53, 300))
        self.assertEqual(packet.dns_addresses, ("192.0.2.1", "192.0.2.2", "2001:db8::1"))
