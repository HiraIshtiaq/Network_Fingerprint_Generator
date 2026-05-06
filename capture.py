import os
import time
import socket
import threading
from urllib.parse import urlparse
import requests
from scapy.all import sniff, wrpcap, IP, TCP, UDP, DNS

def capture_traffic(url, output_file, duration=10):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return {'success': False, 'error': 'Invalid URL', 'packet_count': 0}
        
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            pass
        
        packets = []
        sniff_error = None
        
        def _callback(pkt):
            packets.append(pkt)
        
        def _sniff_thread():
            nonlocal sniff_error
            try:
                sniff(prn=_callback, timeout=duration, store=False)
            except PermissionError:
                sniff_error = "Need root/Admin privileges"
            except Exception as e:
                sniff_error = str(e)
        
        thread = threading.Thread(target=_sniff_thread, daemon=True)
        thread.start()
        
        time.sleep(1.5)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        try:
            requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        except Exception:
            pass
        
        thread.join(timeout=duration + 5)
        
        if sniff_error:
            return {'success': False, 'error': sniff_error, 'packet_count': 0}
        
        wrpcap(output_file, packets)
        
        return {
            'success': True,
            'packet_count': len(packets),
            'raw_packet_count': len(packets),
            'target_hostname': hostname,
            'target_ip': resolved_ip
        }
    
    except Exception as e:
        return {'success': False, 'error': str(e), 'packet_count': 0}