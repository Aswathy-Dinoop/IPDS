from flask import Flask, render_template, jsonify
# import threading
# import database
# import sniffer
import os
import random
import time

app = Flask(__name__)

# START_MOCK
# On PythonAnywhere, we cannot sniff packets or block IPs physically.
# We will simulate valid traffic and attacks for demonstration purposes.

sniffer_active = False

def get_mock_stats():
    # Simulate DB stats
    types = {
        'Malicious Traffic': random.randint(5, 50),
        'DoS Attack': random.randint(1, 10),
        'Port Scan': random.randint(2, 15)
    }
    total = sum(types.values())
    return total, types

def get_mock_logs():
    # Simulate logs
    logs = []
    actions = ['Blocked', 'Logged']
    protos = ['TCP', 'UDP', 'ICMP']
    
    for i in range(5):
        logs.append({
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': f"192.168.1.{random.randint(10, 200)}",
            'dst_ip': "10.0.0.5",
            'protocol': random.choice(protos),
            'type': 'Malicious Traffic',
            'action': 'Blocked'
        })
    return logs
# END_MOCK

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    if not sniffer_active:
        return jsonify({
            'total_attacks': 0,
            'attack_types': {},
            'recent_logs': [],
            'status': 'Inactive'
        })
        
    # PythonAnywhere Logic: Return Mock Data because we can't run the real sniffer
    total, types = get_mock_stats()
    logs = get_mock_logs()
        
    return jsonify({
        'total_attacks': total,
        'attack_types': types,
        'recent_logs': logs,
        'status': 'Active'
    })

@app.route('/api/start_sniffer')
def start_sniffer_route():
    global sniffer_active
    sniffer_active = True
    return jsonify({'status': 'started'})

if __name__ == '__main__':
    # Force pure Flask run for cloud
    app.run(debug=True)
