
def classify_behavior(features):
    try:
        total_packets = features.get('total_packets', 0)
        total_bytes = features.get('total_bytes', 0)
        unique_ips = features.get('unique_ip_count', 0)
        mean_pkt_size = features.get('mean_packet_size', 0)
        dns_count = features.get('dns_query_count', 0)
        pps = features.get('packets_per_second', 0)
        bps = features.get('bytes_per_second', 0)

        proto_dist = features.get('protocol_distribution', {}) or {}
        tcp_pct = proto_dist.get('TCP', 0) + proto_dist.get('HTTPS', 0)
        https_pct = proto_dist.get('HTTPS', 0)
        proto_mix = sum(1 for v in proto_dist.values() if v >= 5)

        if total_packets < 10:
            return _result('Unknown', 0.5, ['Insufficient traffic data'])


        if total_bytes >= 200_000 and mean_pkt_size >= 700 and tcp_pct >= 70:
            confidence = 0.95 if total_bytes >= 1_000_000 else 0.90
            if total_bytes < 500_000:
                confidence = 0.85
            return _result(
                'Streaming',
                confidence,
                [
                    f'High data transfer: {_fmt(total_bytes)}',
                    f'Large packets: {mean_pkt_size:.0f} B avg',
                    f'TCP-dominant: {tcp_pct:.0f}%',
                    f'Throughput: {_fmt(bps)}/s',
                ],
            )

        if (
            mean_pkt_size <= 500
            and pps >= 15
            and https_pct >= 70
            and 0 < unique_ips <= 5
        ):
            return _result(
                'API-Heavy',
                0.88,
                [
                    f'Very small packets: {mean_pkt_size:.0f} B avg',
                    f'High request rate: {pps:.1f} pkt/s',
                    f'HTTPS-dominant: {https_pct:.0f}%',
                    f'Few backends: {unique_ips} IPs',
                ],
            )

        if unique_ips >= 8 and proto_mix >= 2 and mean_pkt_size <= 600:
            confidence = 0.90 if unique_ips >= 15 else 0.85
            return _result(
                'Social Media',
                confidence,
                [
                    f'Many endpoints: {unique_ips} unique IPs',
                    f'Mixed protocols: {proto_mix} active',
                    f'Frequent small packets: {mean_pkt_size:.0f} B avg',
                    f'DNS queries: {dns_count}',
                ],
            )

       
        if total_packets <= 150 and dns_count <= 3 and total_bytes <= 250_000:
            return _result(
                'Static Content',
                0.85,
                [
                    f'Low packet count: {total_packets}',
                    f'Minimal DNS activity: {dns_count} queries',
                    f'Small transfer: {_fmt(total_bytes)}',
                    f'Single origin: {unique_ips} IPs',
                ],
            )
        return _result(
            'Unknown',
            0.6,
            [
                f'Mixed pattern: {total_packets} packets, {unique_ips} IPs',
                f'Mean size: {mean_pkt_size:.0f} B',
                f'Throughput: {_fmt(bps)}/s',
            ],
        )

    except Exception as exc:  # noqa: BLE001
        return _result('Unknown', 0.0, [f'Classification error: {exc}'])


def _result(label, confidence, characteristics):
    return {
        'label': label,
        'confidence': confidence,
        'characteristics': characteristics,
    }


def _fmt(num):
    if num < 1024:
        return f'{num:.0f} B'
    if num < 1024 * 1024:
        return f'{num / 1024:.1f} KB'
    return f'{num / (1024 * 1024):.1f} MB'
