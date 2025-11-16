"""
Network Monitor for VM Traffic Capture
Captures and analyzes network traffic from VMs
"""

import subprocess
import threading
import time
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, DNSQR, DNSRR
import queue


class NetworkMonitor:
    """Monitors network traffic from VM"""

    def __init__(self, interface='virbr0'):
        """Initialize network monitor"""
        self.interface = interface
        self.capture_active = False
        self.packets = queue.Queue()
        self.capture_thread = None
        self.session_id = None

    def start_capture(self, session_id, vm_ip=None):
        """Start capturing network traffic"""
        self.session_id = session_id
        self.capture_active = True

        # Build filter
        bpf_filter = f"host {vm_ip}" if vm_ip else ""

        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(bpf_filter,),
            daemon=True
        )
        self.capture_thread.start()

        return {'success': True, 'session_id': session_id}

    def stop_capture(self):
        """Stop capturing traffic"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        return {'success': True, 'packets_captured': self.packets.qsize()}

    def _capture_packets(self, bpf_filter):
        """Capture packets using scapy"""
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.capture_active
            )
        except Exception as e:
            print(f"Capture error: {e}")

    def _process_packet(self, packet):
        """Process captured packet"""
        if not packet.haslayer(IP):
            return

        packet_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': self.session_id,
            'protocol': None,
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'source_port': None,
            'destination_port': None,
            'length': len(packet),
            'flags': []
        }

        # TCP
        if packet.haslayer(TCP):
            packet_data['protocol'] = 'TCP'
            packet_data['source_port'] = packet[TCP].sport
            packet_data['destination_port'] = packet[TCP].dport
            packet_data['flags'] = self._get_tcp_flags(packet[TCP])

            # HTTP detection
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if self._is_http(payload):
                    packet_data['protocol'] = 'HTTP'
                    http_data = self._parse_http(payload)
                    packet_data.update(http_data)

        # UDP
        elif packet.haslayer(UDP):
            packet_data['protocol'] = 'UDP'
            packet_data['source_port'] = packet[UDP].sport
            packet_data['destination_port'] = packet[UDP].dport

            # DNS detection
            if packet.haslayer(DNS):
                packet_data['protocol'] = 'DNS'
                dns_data = self._parse_dns(packet[DNS])
                packet_data.update(dns_data)

        # Add to queue
        self.packets.put(packet_data)

    def _get_tcp_flags(self, tcp_layer):
        """Extract TCP flags"""
        flags = []
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        return flags

    def _is_http(self, payload):
        """Check if payload is HTTP"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            return any(payload_str.startswith(method) for method in http_methods) or \
                   payload_str.startswith('HTTP/')
        except:
            return False

    def _parse_http(self, payload):
        """Parse HTTP request/response"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')

            if not lines:
                return {}

            first_line = lines[0]
            headers = {}

            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # Request
            if any(first_line.startswith(m) for m in ['GET', 'POST', 'PUT', 'DELETE']):
                parts = first_line.split()
                return {
                    'http_method': parts[0] if len(parts) > 0 else None,
                    'http_path': parts[1] if len(parts) > 1 else None,
                    'http_version': parts[2] if len(parts) > 2 else None,
                    'http_headers': headers,
                    'http_host': headers.get('Host', '')
                }

            # Response
            elif first_line.startswith('HTTP/'):
                parts = first_line.split()
                return {
                    'http_version': parts[0] if len(parts) > 0 else None,
                    'http_status': int(parts[1]) if len(parts) > 1 else None,
                    'http_headers': headers
                }

        except Exception as e:
            print(f"HTTP parse error: {e}")

        return {}

    def _parse_dns(self, dns_layer):
        """Parse DNS query/response"""
        dns_data = {
            'dns_query': None,
            'dns_response': [],
            'dns_type': 'query' if dns_layer.qr == 0 else 'response'
        }

        # Query
        if dns_layer.haslayer(DNSQR):
            dns_data['dns_query'] = dns_layer[DNSQR].qname.decode('utf-8', errors='ignore')

        # Response
        if dns_layer.haslayer(DNSRR):
            answers = []
            for i in range(dns_layer.ancount):
                rr = dns_layer[DNSRR][i] if dns_layer.ancount > 1 else dns_layer[DNSRR]
                answers.append({
                    'name': rr.rrname.decode('utf-8', errors='ignore') if hasattr(rr, 'rrname') else '',
                    'type': rr.type,
                    'data': rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                })
            dns_data['dns_response'] = answers

        return dns_data

    def get_packets(self, limit=100):
        """Get captured packets from queue"""
        packets = []
        count = 0

        while not self.packets.empty() and count < limit:
            try:
                packets.append(self.packets.get_nowait())
                count += 1
            except queue.Empty:
                break

        return packets

    def get_statistics(self):
        """Get capture statistics"""
        return {
            'active': self.capture_active,
            'queue_size': self.packets.qsize(),
            'session_id': self.session_id
        }

    def export_pcap(self, output_file):
        """Export captured traffic to PCAP file"""
        # Use tcpdump to capture to file
        cmd = [
            'tcpdump',
            '-i', self.interface,
            '-w', output_file,
            '-n'
        ]

        try:
            process = subprocess.Popen(cmd)
            return {'success': True, 'process': process.pid}
        except Exception as e:
            return {'success': False, 'error': str(e)}
