"""Feature extraction from a captured pcap file (FR-3)."""
import statistics
from collections import Counter

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, rdpcap
from scapy.layers.inet6 import ICMPv6Unknown, IPv6

# Protocol categories surfaced in the fingerprint, per the spec.
PROTOCOL_KEYS = ('TCP', 'UDP', 'DNS', 'HTTPS', 'ICMP', 'ARP', 'Other')


def extract_features(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception:
        return _empty_features()

    if not packets:
        return _empty_features()

    features = _empty_features()
    features['total_packets'] = len(packets)

    proto_counts = Counter()
    dest_ips = set()
    dns_queries = []
    prev_time = None

    for pkt in packets:
        size = len(pkt)
        features['total_bytes'] += size
        features['packet_sizes'].append(size)

        if hasattr(pkt, 'time'):
            curr_time = float(pkt.time)
            features['packet_times'].append(curr_time)
            if prev_time is not None:
                delta = curr_time - prev_time
                if 0 < delta < 5:
                    features['inter_arrival_times'].append(delta)
            prev_time = curr_time

        label = _classify_packet(pkt, dest_ips, dns_queries)
        proto_counts[label] += 1
        features['protocols'].append(label)

    if features['packet_sizes']:
        features['mean_packet_size'] = statistics.mean(features['packet_sizes'])
        features['min_packet_size'] = min(features['packet_sizes'])
        features['max_packet_size'] = max(features['packet_sizes'])

    features['unique_ips'] = sorted(dest_ips)
    features['unique_ip_count'] = len(dest_ips)

    features['dns_queries'] = list(dict.fromkeys(dns_queries))  # de-dup, keep order
    features['dns_query_count'] = len(features['dns_queries'])

    features['tcp_count'] = proto_counts.get('TCP', 0) + proto_counts.get('HTTPS', 0)
    features['udp_count'] = proto_counts.get('UDP', 0) + proto_counts.get('DNS', 0)
    features['dns_count'] = proto_counts.get('DNS', 0)
    features['https_count'] = proto_counts.get('HTTPS', 0)

    total = features['total_packets']
    features['protocol_distribution'] = {
        key: round((proto_counts.get(key, 0) / total) * 100, 1)
        for key in PROTOCOL_KEYS
        if proto_counts.get(key, 0) > 0
    }

    if proto_counts:
        features['top_protocol'] = proto_counts.most_common(1)[0][0]

    if len(features['packet_times']) > 1:
        duration = features['packet_times'][-1] - features['packet_times'][0]
        features['capture_duration'] = duration if duration > 0 else 10
    if features['capture_duration'] > 0:
        features['bytes_per_second'] = features['total_bytes'] / features['capture_duration']
        features['packets_per_second'] = features['total_packets'] / features['capture_duration']

    return features


def _classify_packet(pkt, dest_ips, dns_queries):
    """Map a packet to one of PROTOCOL_KEYS and side-effect IP/DNS sets.

    Handles both IPv4 and IPv6 — macOS prefers IPv6 (Happy Eyeballs) for
    sites that publish AAAA records, so v4-only logic miscounted them all
    as 'Other' with no destination IP.
    """
    if ARP in pkt:
        return 'ARP'

    has_ipv4 = IP in pkt
    has_ipv6 = IPv6 in pkt
    if not (has_ipv4 or has_ipv6):
        return 'Other'

    dest_ips.add(pkt[IP].dst if has_ipv4 else pkt[IPv6].dst)

    if TCP in pkt:
        tcp = pkt[TCP]
        if tcp.sport == 443 or tcp.dport == 443:
            return 'HTTPS'
        return 'TCP'

    if UDP in pkt:
        udp = pkt[UDP]
        if udp.sport == 53 or udp.dport == 53:
            if DNS in pkt and pkt[DNS].qd is not None:
                try:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if qname:
                        dns_queries.append(qname)
                except Exception:
                    pass
            return 'DNS'
        # QUIC / HTTP-3 lives on UDP/443 — bucket it as HTTPS so the
        # protocol distribution reflects what the site actually uses.
        if udp.sport == 443 or udp.dport == 443:
            return 'HTTPS'
        return 'UDP'

    if ICMP in pkt or ICMPv6Unknown in pkt:
        return 'ICMP'

    return 'Other'


def _empty_features():
    return {
        'total_packets': 0,
        'total_bytes': 0,
        'packet_sizes': [],
        'protocols': [],
        'unique_ips': [],
        'unique_ip_count': 0,
        'dns_queries': [],
        'dns_query_count': 0,
        'tcp_count': 0,
        'udp_count': 0,
        'dns_count': 0,
        'https_count': 0,
        'protocol_distribution': {},
        'top_protocol': 'Unknown',
        'mean_packet_size': 0,
        'min_packet_size': 0,
        'max_packet_size': 0,
        'packet_times': [],
        'inter_arrival_times': [],
        'capture_duration': 10,
        'bytes_per_second': 0,
        'packets_per_second': 0,
    }
