import time
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from arguments_reader import ArgumentsReader
from whois_function import whois_func


class Traceroute:
    def __init__(self):
        self.args = ArgumentsReader().args
        self.maintain_functions = {'icmp': self.maintain_icmp,
                                   'tcp': self.maintain_tcp,
                                   'udp': self.maintain_udp}
        self.main_function(self.args.ip, self.args.protocol)

    def main_function(self, ip, protocol):
        if not self.is_input_correct():
            return
        try:
            main_func = self.maintain_functions[protocol]
        except KeyError:
            print('Unknown protocol. Try again!')
            return

        ttl = 1
        while True:
            start_time = time.time()
            response = main_func(ip, ttl)
            elapsed_time = int((time.time() - start_time) * 1000)

            if response:
                print(f"{ttl} {response.src} [{elapsed_time} ms] "
                      f"{whois_func(response.src) if self.args.verbose else ''}")
            else:
                print(f"{ttl} *")

            ttl += 1

            if response and response.src == ip:
                break

            if self.args.max_count and ttl > self.args.max_count:
                break

    @staticmethod
    def maintain_icmp(ip, ttl):
        _packet = IPv6(dst=ip, hlim=ttl) / ICMPv6EchoRequest() if ':' in ip \
            else IP(dst=ip, ttl=ttl) / ICMP()
        return sr1(_packet, timeout=1, verbose=False)

    def maintain_tcp(self, ip, ttl):
        _packet = IPv6(dst=ip, hlim=ttl) / TCP(dport=self.args.port, flags="S") if ':' in ip \
            else IP(dst=ip, ttl=ttl)/TCP(dport=self.args.port, flags="S")
        return sr1(_packet, timeout=1, verbose=False)

    def maintain_udp(self, ip, ttl):
        _packet = IPv6(dst=ip, hlim=ttl) / UDP(dport=self.args.port) if ':' in ip \
            else IP(dst=ip, ttl=ttl)/UDP(dport=self.args.port)
        return sr1(_packet, timeout=1, verbose=False)

    def is_input_correct(self):
        if self.args.protocol == 'tcp' or self.args.protocol == 'udp':
            if not self.args.port:
                print('No port for tcp/udp. Please, try again!')
                return False
        return True
