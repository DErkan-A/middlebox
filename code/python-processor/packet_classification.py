from scapy.all import Ether, IP, TCP, UDP

class NetworkRule:
    def __init__(self, protocol=None, src_port=None, dst_port=None):
        """
        protocol: integer IP proto (6=TCP,17=UDP) or None
        src_port, dst_port: integer or None
        """
        self.protocol = protocol
        self.src_port  = src_port
        self.dst_port  = dst_port

    def matches(self, pkt) -> bool:
        # must have IP
        if not pkt.haslayer(IP):
            return False
        ip = pkt[IP]

        # protocol check
        if self.protocol is not None and ip.proto != self.protocol:
            return False

        # pick L4
        l4 = None
        if ip.proto == 6 and pkt.haslayer(TCP):
            l4 = pkt[TCP]
        elif ip.proto == 17 and pkt.haslayer(UDP):
            l4 = pkt[UDP]
        else:
            # if user wants port checks but no L4, fail
            if self.src_port is not None or self.dst_port is not None:
                return False

        # port checks
        if self.src_port is not None and l4.sport != self.src_port:
            return False
        if self.dst_port is not None and l4.dport != self.dst_port:
            return False

        return True


class NetworkRuleSet:
    def __init__(self):
        self._rules = []

    def add_rule(self, protocol=None, src_port=None, dst_port=None):
        """
        Any of protocol/src_port/dst_port can be None to wildcard.
        """
        self._rules.append(NetworkRule(protocol, src_port, dst_port))

    def match_packet(self, pkt):
        """
        Returns the index of the first rule that matches, or None.
        """
        for idx, rule in enumerate(self._rules):
            if rule.matches(pkt):
                return idx
        return None
