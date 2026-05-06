from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter
import statistics

def extract_features(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        
        if not packets:
            return _empty_features()
        
        features = {
            'total_packets': len(packets),
            'total_bytes': 0,
            'packet_sizes': [],
            'protocols': [],
            'unique_ips': set(),
            'dns_queries': [],
            'tcp_count': 0,
            'udp_count': 0,
            'dns_count': 0,
            'https_count': 0,
            'packet_times': [],
            'inter_arrival_times': []
        }
        
        prev_time = None
        
        for pkt in packets:
            size = len(pkt)
            features['total_bytes'] += size
            features['packet_sizes'].append(size)
            
            if hasattr(pkt, 'time'):
                curr_time = float(pkt.time)
                features['packet_times'].append(curr_time)
                if prev_time:
                    diff = curr_time - prev_time
                    if 0 < diff < 5:
                        features['inter_arrival_times'].append(diff)
                prev_time = curr_time
            
            if IP in pkt:
                ip = pkt[IP]
                features['unique_ips'].add(ip.src)
                features['unique_ips'].add(ip.dst)
                
                if TCP in pkt:
                    tcp = pkt[TCP]
                    features['tcp_count'] += 1
                    features['protocols'].append('TCP')
                    if tcp.sport == 443 or tcp.dport == 443:
                        features['https_count'] += 1
                
                elif UDP in pkt:
                    udp = pkt[UDP]
                    features['udp_count'] += 1
                    features['protocols'].append('UDP')
                    if udp.sport == 53 or udp.dport == 53:
                        features['dns_count'] += 1
                        if DNS in pkt and pkt[DNS].qd:
                            try:
                                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                                if qname and qname not in features['dns_queries']:
                                    features['dns_queries'].append(qname)
                            except:
                                pass
            else:
                features['protocols'].append('Other')
        
        if features['packet_sizes']:
            features['mean_packet_size'] = statistics.mean(features['packet_sizes'])
            features['min_packet_size'] = min(features['packet_sizes'])
            features['max_packet_size'] = max(features['packet_sizes'])
        
        features['unique_ip_count'] = len(features['unique_ips'])
        features['unique_ips'] = list(features['unique_ips'])
        
        total = features['tcp_count'] + features['udp_count'] + (features['total_packets'] - features['tcp_count'] - features['udp_count'])
        if total > 0:
            features['protocol_distribution'] = {
                'TCP': round((features['tcp_count'] / total) * 100, 1),
                'UDP': round((features['udp_count'] / total) * 100, 1),
                'Other': round(((total - features['tcp_count'] - features['udp_count']) / total) * 100, 1)
            }
        
        proto_counts = Counter(features['protocols'])
        features['top_protocol'] = proto_counts.most_common(1)[0][0] if proto_counts else 'Unknown'
        
        if len(features['packet_times']) > 1:
            features['capture_duration'] = features['packet_times'][-1] - features['packet_times'][0]
        else:
            features['capture_duration'] = 10
        
        if features['capture_duration'] > 0:
            features['bytes_per_second'] = features['total_bytes'] / features['capture_duration']
            features['packets_per_second'] = features['total_packets'] / features['capture_duration']
        
        features['dns_query_count'] = len(set(features['dns_queries']))
        
        return features
    
    except Exception:
        return _empty_features()


def _empty_features():
    return {
        'total_packets': 0, 'total_bytes': 0, 'packet_sizes': [],
        'protocols': [], 'unique_ips': [], 'unique_ip_count': 0,
        'dns_queries': [], 'dns_query_count': 0,
        'tcp_count': 0, 'udp_count': 0, 'dns_count': 0, 'https_count': 0,
        'protocol_distribution': {}, 'top_protocol': 'Unknown',
        'mean_packet_size': 0, 'min_packet_size': 0, 'max_packet_size': 0,
        'packet_times': [], 'inter_arrival_times': [],
        'capture_duration': 10, 'bytes_per_second': 0, 'packets_per_second': 0
    }