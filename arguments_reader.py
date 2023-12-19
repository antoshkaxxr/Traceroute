import argparse


class ArgumentsReader:
    def __init__(self):
        self.args = None
        self.read_from_cmd()

    def read_from_cmd(self):
        parser = argparse.ArgumentParser(description='Traceroute')
        parser.add_argument('-t', '--timeout', type=float, default=2.0,
                            help='how long to wait for a response')
        parser.add_argument('-p', '--port', type=int,
                            help='port number (for tcp and udp)')
        parser.add_argument('-n', '--max-count', type=int,
                            help='max requests count')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='output of the autonomous system number')
        parser.add_argument('ip', type=str,
                            help='target host IP')
        parser.add_argument('protocol', type=str,
                            help='tcp/udp/icmp')

        self.args = parser.parse_args()
