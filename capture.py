import os
import socket
import threading
import time
from urllib.parse import urlparse

import requests
from scapy.all import sniff, wrpcap

CAPTURE_INTERFACE = os.environ.get('CAPTURE_INTERFACE') or None

REQUEST_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}


def _hostname_variants(hostname):
   
    variants = {hostname}
    if hostname.startswith('www.'):
        variants.add(hostname[4:])
    else:
        variants.add(f'www.{hostname}')
    return variants


def _resolve_all_ips(hostname):
    
    ips = set()
    for host in _hostname_variants(hostname):
        try:
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip:
                    ips.add(ip)
        except socket.gaierror:
            continue
    return ips


def _build_bpf(ips):
    
    parts = [f'host {ip}' for ip in ips]
    parts.append('port 53')
    return ' or '.join(parts)


def capture_traffic(url, output_file, duration=10):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {'success': False, 'error': 'Invalid URL', 'packet_count': 0}

        ips = _resolve_all_ips(hostname)
        if not ips:
            return {
                'success': False,
                'error': f'Could not resolve {hostname}',
                'packet_count': 0,
            }

        bpf = _build_bpf(ips)

        packets = []
        sniff_error = {'msg': None}
        sniff_started = threading.Event()
        request_done = threading.Event()

        def _on_packet(pkt):
            packets.append(pkt)

        def _stop_filter(_pkt):

            return request_done.is_set() and (
                time.time() - request_done.completed_at >= 1.5
            )

        def _sniff():
            try:
                sniff_started.set()
                sniff_kwargs = dict(
                    filter=bpf,
                    prn=_on_packet,
                    timeout=duration,
                    stop_filter=_stop_filter,
                    store=False,
                )
                if CAPTURE_INTERFACE:
                    sniff_kwargs['iface'] = CAPTURE_INTERFACE
                sniff(**sniff_kwargs)
            except PermissionError:
                sniff_error['msg'] = (
                    'Packet capture needs root. Run: sudo .venv/bin/python app.py'
                )
            except OSError as exc:
                sniff_error['msg'] = f'Network interface error: {exc}'
            except Exception as exc:  # noqa: BLE001
                sniff_error['msg'] = str(exc)

        sniff_thread = threading.Thread(target=_sniff, daemon=True)
        sniff_thread.start()

        sniff_started.wait(timeout=2)
        time.sleep(1.0)

        if sniff_error['msg']:
            return {
                'success': False,
                'error': sniff_error['msg'],
                'packet_count': 0,
            }

        try:
            requests.get(
                url,
                timeout=8,
                headers=REQUEST_HEADERS,
                allow_redirects=True,
            )
        except requests.RequestException:
            pass
        request_done.completed_at = time.time()
        request_done.set()

        sniff_thread.join(timeout=duration + 5)

        if sniff_error['msg']:
            return {
                'success': False,
                'error': sniff_error['msg'],
                'packet_count': 0,
            }

        wrpcap(output_file, packets)

        return {
            'success': True,
            'packet_count': len(packets),
            'raw_packet_count': len(packets),
            'target_hostname': hostname,
            'target_ips': sorted(ips),
            'bpf_filter': bpf,
        }

    except Exception as exc: 
        return {'success': False, 'error': str(exc), 'packet_count': 0}
