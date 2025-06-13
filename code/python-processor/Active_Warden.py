from scapy.all import IP, TCP, UDP

class NetworkRule:
    def __init__(self, protocol=None, src_port=None, dst_port=None):
        self.protocol = protocol
        self.src_port  = src_port
        self.dst_port  = dst_port

    def matches(self, pkt) -> bool:
        if not pkt.haslayer(IP):
            return False
        ip = pkt[IP]
        if self.protocol is not None and ip.proto != self.protocol:
            return False

        l4 = None
        if ip.proto == 6 and pkt.haslayer(TCP):
            l4 = pkt[TCP]
        elif ip.proto == 17 and pkt.haslayer(UDP):
            l4 = pkt[UDP]
        else:
            if self.src_port is not None or self.dst_port is not None:
                return False

        if self.src_port is not None and l4.sport != self.src_port:
            return False
        if self.dst_port is not None and l4.dport != self.dst_port:
            return False

        return True

class ActiveWarden:
    def __init__(self):
        self._rules   = []      # list of NetworkRule
        self._hits    = []      # parallel list of hit counts
        self._actions = []      # parallel list of action codes (ints)
        self._total   = 0       # total packets seen
        self._pairs   = []      # precomputed list of (i, j) "pair rules"

    def add_rule(self, protocol=None, src_port=None, dst_port=None, action=0):
        """
        Add a new rule, init its hit counter & action, update pair list.
        `action` is an int code (0=forward,1=drop,…).
        """
        new_idx = len(self._rules)
        # record any new "pairs" with existing rules
        for old_idx, old_rule in enumerate(self._rules):
            if (old_rule.src_port == src_port and
                old_rule.dst_port == dst_port and
                old_rule.protocol != protocol):
                self._pairs.append((old_idx, new_idx))

        # append the new rule + stats + action
        self._rules.append(NetworkRule(protocol, src_port, dst_port))
        self._hits.append(0)
        self._actions.append(action)

    def set_action(self, rule_idx, action):
        """Change the action code for rule `rule_idx`."""
        self._actions[rule_idx] = action

    def get_action(self, rule_idx):
        """Return the action code for rule `rule_idx`."""
        return self._actions[rule_idx]

    def add_rule_from_packet(self, pkt, action=0):
        """
        Learn a rule (TCP/UDP only) from `pkt` and assign it `action`.
        Non-TCP/UDP packets are ignored.
        """
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        proto = ip.proto
        if proto == 6 and pkt.haslayer(TCP):
            l4 = pkt[TCP]
        elif proto == 17 and pkt.haslayer(UDP):
            l4 = pkt[UDP]
        else:
            return

        self.add_rule(protocol=proto,
                      src_port=l4.sport,
                      dst_port=l4.dport,
                      action=action)

    def match_packet(self, pkt):
        """Return index of first matching rule, or None."""
        for idx, rule in enumerate(self._rules):
            if rule.matches(pkt):
                return idx
        return None

    def record_packet(self, pkt):
        """
        Process `pkt`:
          - find matching rule (if any) → idx
          - increment total count
          - bump its hit count
        Returns (idx, action) where idx is the rule index or None.
        """
        idx = self.match_packet(pkt)
        if idx is not None:
            self._total += 1
            self._hits[idx] += 1
            return idx, self._actions[idx]
        return None, None

    def get_hit_count(self, rule_idx):
        return self._hits[rule_idx]

    def get_hit_rate(self, rule_idx):
        return (self._hits[rule_idx] / self._total) if self._total else 0.0

    def get_all_hit_rates(self):
        return [h / self._total if self._total else 0.0 for h in self._hits]

    def get_pair_rules(self):
        """Return the precomputed list of (i, j) pairs."""
        return list(self._pairs)

# Usage example:
#
# aw = ActiveWarden()
# aw.add_rule(protocol=6, src_port=1000, dst_port=2000, action=0)   # forward
# aw.add_rule(protocol=17, src_port=1000, dst_port=2000, action=1)  # drop
# print(aw.get_pair_rules())  # [(0, 1)]
#
# def handle(pkt):
#     idx, action = aw.record_packet(pkt)
#     if idx is not None:
#         print(f"Matched rule {idx} → action {action}")
#
# sniff(iface="eth0", filter="ip and (tcp or udp)", prn=handle, store=False)
c