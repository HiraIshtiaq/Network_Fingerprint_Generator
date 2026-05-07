from flask import Flask, render_template, request, jsonify
import os
import socket
from datetime import datetime
from urllib.parse import urlparse
import threading
import time
from capture import capture_traffic
from extract import extract_features
from fingerprint import generate_fingerprint
from classify import classify_behavior

app = Flask(__name__)
app.config['TEMP_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)

active_captures = {}
capture_lock = threading.Lock()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(parsed_url.hostname)
        except socket.gaierror:
            pass
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        pcap_file = os.path.join(app.config['TEMP_FOLDER'], f'capture_{timestamp}.pcap')
        
        capture_result = capture_traffic(url, pcap_file, duration=10)
        
        if not capture_result['success']:
            return jsonify({'error': capture_result.get('error', 'Capture failed')}), 500
        
        features = extract_features(pcap_file)
        fingerprint = generate_fingerprint(url, features)
        classification = classify_behavior(features)
        
        fingerprint['behavior_label'] = classification['label']
        fingerprint['confidence'] = classification['confidence']
        fingerprint['classification_characteristics'] = classification['characteristics']
        
        fingerprint['capture_metadata'] = {
            'dns_resolved_ip': resolved_ip,
            'packets_captured_raw': capture_result.get('raw_packet_count', 0),
            'packets_filtered': capture_result.get('packet_count', 0),
            'target_hostname': parsed_url.hostname,
            'target_ips': capture_result.get('target_ips', []),
            'bpf_filter': capture_result.get('bpf_filter', ''),
        }
        
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
        
        return jsonify(fingerprint)
    
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/api/compare', methods=['POST'])
def compare():
    try:
        data = request.get_json()
        url1 = data.get('url1', '')
        url2 = data.get('url2', '')
        
        if not url1 or not url2:
            return jsonify({'error': 'Both URLs required'}), 400
        
        if not url1.startswith(('http://', 'https://')):
            url1 = 'https://' + url1
        if not url2.startswith(('http://', 'https://')):
            url2 = 'https://' + url2
        
        fp1, f1 = _process_url(url1, 'site1')
        if fp1 is None:
            return jsonify({'error': f'Failed to analyze {url1}'}), 500
        
        fp2, f2 = _process_url(url2, 'site2')
        if fp2 is None:
            return jsonify({'error': f'Failed to analyze {url2}'}), 500
        
        diff = _generate_diff(fp1, fp2, f1, f2)
        timeline = _prepare_timeline(f1, f2)
        
        return jsonify({
            'fingerprint1': fp1,
            'fingerprint2': fp2,
            'diff': diff,
            'timeline_data': timeline
        })
    
    except Exception as e:
        return jsonify({'error': f'Comparison failed: {str(e)}'}), 500


def _process_url(url, label):
    try:
        parsed = urlparse(url)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        pcap_file = os.path.join(app.config['TEMP_FOLDER'], f'compare_{label}_{timestamp}.pcap')
        
        result = capture_traffic(url, pcap_file, duration=10)
        if not result['success']:
            return None, None
        
        features = extract_features(pcap_file)
        fingerprint = generate_fingerprint(url, features)
        classification = classify_behavior(features)
        
        fingerprint['behavior_label'] = classification['label']
        fingerprint['confidence'] = classification['confidence']
        fingerprint['classification_characteristics'] = classification['characteristics']
        
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
        
        return fingerprint, features
    
    except Exception:
        return None, None


def _generate_diff(fp1, fp2, f1, f2):
    def _compare(name, v1, v2):
        return {
            'site1': v1,
            'site2': v2,
            'winner': 'site1' if v1 > v2 else ('site2' if v2 > v1 else 'tie'),
            'difference': abs(v1 - v2)
        }
    
    proto1 = fp1.get('protocol_distribution', {})
    proto2 = fp2.get('protocol_distribution', {})
    
    all_protos = set(proto1.keys()) | set(proto2.keys())
    proto_diffs = {}
    for proto in all_protos:
        proto_diffs[proto] = {
            'site1': proto1.get(proto, 0),
            'site2': proto2.get(proto, 0),
            'difference': abs(proto1.get(proto, 0) - proto2.get(proto, 0))
        }
    
    return {
        'total_packets': _compare('Total Packets', fp1.get('total_packets', 0), fp2.get('total_packets', 0)),
        'total_bytes': _compare('Total Data', fp1.get('total_bytes', 0), fp2.get('total_bytes', 0)),
        'unique_ips': _compare('Unique IPs', fp1.get('unique_ips', 0), fp2.get('unique_ips', 0)),
        'mean_packet_size': _compare('Mean Packet Size', fp1.get('mean_packet_size', 0), fp2.get('mean_packet_size', 0)),
        'behavior_label': {
            'site1': fp1.get('behavior_label', 'Unknown'),
            'site2': fp2.get('behavior_label', 'Unknown'),
            'match': fp1.get('behavior_label') == fp2.get('behavior_label')
        },
        'protocol_distribution': proto_diffs,
        'dns_queries': {
            'site1_count': len(fp1.get('dns_queries', [])),
            'site2_count': len(fp2.get('dns_queries', []))
        }
    }


def _prepare_timeline(f1, f2):
    times1 = f1.get('inter_arrival_times', [])
    times2 = f2.get('inter_arrival_times', [])
    bytes1 = f1.get('packet_sizes', [])
    bytes2 = f2.get('packet_sizes', [])
    
    t1 = _calc_timeline(times1, bytes1)
    t2 = _calc_timeline(times2, bytes2)
    
    return {
        'site1': t1,
        'site2': t2,
        'max_duration': max(t1.get('max_time', 10), t2.get('max_time', 10))
    }


def _calc_timeline(times, sizes):
    if not times or not sizes:
        return {'time_points': list(range(11)), 'bytes_per_second': [0] * 11, 'max_time': 10}
    
    cumulative_time = 0
    time_points = [0]
    cumulative_bytes = [0]
    
    for interval, size in zip(times[:100], sizes[:100]):
        cumulative_time += interval
        time_points.append(cumulative_time)
        cumulative_bytes.append(cumulative_bytes[-1] + size)
    
    max_time = max(time_points) if time_points else 10
    num_buckets = min(int(max_time) + 2, 15)
    bytes_per_sec = [0] * num_buckets
    
    for i in range(len(time_points) - 1):
        bucket = int(time_points[i])
        if bucket < num_buckets:
            bytes_per_sec[bucket] += cumulative_bytes[i + 1] - cumulative_bytes[i]
    
    return {
        'time_points': list(range(num_buckets)),
        'bytes_per_second': [round(b, 2) for b in bytes_per_sec],
        'max_time': round(max_time, 2)
    }


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    print(f"Starting server on http://localhost:5000")
    print(f"Temp folder: {app.config['TEMP_FOLDER']}")
    app.run(debug=True, host='0.0.0.0', port=5000)