"""Fingerprint assembly (FR-4)."""
import hashlib
import json
import os
from datetime import datetime
from urllib.parse import urlparse


def generate_fingerprint(url, features):
    try:
        fingerprint = {
            'site_url': url,
            'capture_timestamp': datetime.now().isoformat(),
            'total_packets': features.get('total_packets', 0),
            'total_bytes': features.get('total_bytes', 0),
            'top_protocol': features.get('top_protocol', 'Unknown'),
            'protocol_distribution': dict(features.get('protocol_distribution', {})),
            'unique_ips': features.get('unique_ip_count', 0),
            'unique_ip_list': features.get('unique_ips', [])[:15],
            'dns_queries': list(features.get('dns_queries', [])),
            'mean_packet_size': round(features.get('mean_packet_size', 0), 2),
            'min_packet_size': features.get('min_packet_size', 0),
            'max_packet_size': features.get('max_packet_size', 0),
            'capture_duration': round(features.get('capture_duration', 0), 3),
            'bytes_per_second': round(features.get('bytes_per_second', 0), 2),
            'packets_per_second': round(features.get('packets_per_second', 0), 2),
            'packet_sizes_sample': features.get('packet_sizes', [])[:200],
            'inter_arrival_times': features.get('inter_arrival_times', [])[:200],
            'behavior_label': 'Pending',
            'confidence': 0.0,
            'classification_characteristics': [],
        }

        # Re-normalize protocol percentages so they sum to 100.
        proto_dist = fingerprint['protocol_distribution']
        total = sum(proto_dist.values())
        if total > 0 and abs(total - 100) > 0.1:
            for proto in proto_dist:
                proto_dist[proto] = round((proto_dist[proto] / total) * 100, 1)

        # Stable hash over the structural fields only.
        hash_keys = (
            'site_url', 'total_packets', 'total_bytes', 'top_protocol',
            'protocol_distribution', 'unique_ips', 'mean_packet_size',
            'max_packet_size',
        )
        hash_data = {k: fingerprint[k] for k in hash_keys}
        hash_str = json.dumps(hash_data, sort_keys=True, default=str)
        fingerprint['fingerprint_hash'] = hashlib.sha256(hash_str.encode()).hexdigest()

        return fingerprint

    except Exception as exc:  # noqa: BLE001
        return {
            'site_url': url,
            'error': str(exc),
            'capture_timestamp': datetime.now().isoformat(),
            'total_packets': 0,
            'total_bytes': 0,
            'behavior_label': 'Error',
            'confidence': 0.0,
            'fingerprint_hash': hashlib.sha256(url.encode()).hexdigest(),
        }


def save_fingerprint(fingerprint, output_dir='fingerprints'):
    os.makedirs(output_dir, exist_ok=True)

    domain = urlparse(fingerprint['site_url']).netloc or fingerprint['site_url']
    domain = domain.replace('.', '_').replace(':', '_')
    timestamp = fingerprint['capture_timestamp'].replace(':', '-').replace('.', '-')
    filepath = os.path.join(output_dir, f'{domain}_{timestamp}.json')

    with open(filepath, 'w') as fh:
        json.dump(fingerprint, fh, indent=2, default=str)

    return filepath
