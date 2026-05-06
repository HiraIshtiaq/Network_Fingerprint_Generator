def classify_behavior(features):
    try:
        total_packets = features.get('total_packets', 0)
        total_bytes = features.get('total_bytes', 0)
        unique_ips = features.get('unique_ip_count', 0)
        mean_pkt_size = features.get('mean_packet_size', 0)
        dns_count = len(set(features.get('dns_queries', [])))
        duration = features.get('capture_duration', 10)
        pps = features.get('packets_per_second', 0)
        bps = features.get('bytes_per_second', 0)
        
        proto_dist = features.get('protocol_distribution', {})
        tcp_pct = proto_dist.get('TCP', 0)
        
        if total_packets < 10:
            return {
                'label': 'Unknown',
                'confidence': 0.5,
                'characteristics': ['Insufficient traffic data']
            }
        
        # Streaming detection
        if total_bytes > 500000 or mean_pkt_size > 800 or (tcp_pct > 60 and bps > 25000):
            confidence = 0.90
            if total_bytes > 1000000:
                confidence = 0.95
            return {
                'label': 'Streaming',
                'confidence': confidence,
                'characteristics': [
                    f'High data transfer: {_format_bytes(total_bytes)}',
                    f'Large packets: {mean_pkt_size:.0f} bytes avg',
                    f'Throughput: {_format_bytes(bps)}/s'
                ]
            }
        
        # Social media detection
        if unique_ips > 8 or (pps > 15 and mean_pkt_size < 400):
            confidence = 0.85
            if unique_ips > 15:
                confidence = 0.90
            return {
                'label': 'Social Media',
                'confidence': confidence,
                'characteristics': [
                    f'Many endpoints: {unique_ips} unique IPs',
                    f'Packet rate: {pps:.1f}/s',
                    f'DNS queries: {dns_count}'
                ]
            }
        
        # Static content detection
        if total_packets < 50 and total_bytes < 200000 and dns_count < 4:
            confidence = 0.88
            return {
                'label': 'Static Content',
                'confidence': confidence,
                'characteristics': [
                    f'Low traffic: {total_packets} packets',
                    f'Small transfer: {_format_bytes(total_bytes)}',
                    f'Minimal DNS activity'
                ]
            }
        
        # API-heavy detection
        if mean_pkt_size < 300 and pps > 10 and tcp_pct > 70 and unique_ips < 6:
            confidence = 0.87
            return {
                'label': 'API-Heavy',
                'confidence': confidence,
                'characteristics': [
                    f'Small packets: {mean_pkt_size:.0f} bytes avg',
                    f'High frequency: {pps:.1f} req/s',
                    f'HTTPS dominant'
                ]
            }
        
        return {
            'label': 'Unknown',
            'confidence': 0.6,
            'characteristics': [
                f'Mixed pattern: {total_packets} packets, {unique_ips} IPs',
                f'Packet size: {mean_pkt_size:.0f} bytes avg'
            ]
        }
    
    except Exception:
        return {
            'label': 'Unknown',
            'confidence': 0.0,
            'characteristics': ['Classification error']
        }


def _format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b/1024:.1f} KB"
    else:
        return f"{b/(1024*1024):.1f} MB"