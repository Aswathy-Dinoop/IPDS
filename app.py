from flask import Flask, render_template, jsonify
import threading
import database
import sniffer
import os

app = Flask(__name__)

# Global flag for sniffer thread
sniffer_active = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    total, types = database.get_stats()
    recent = database.get_recent_alerts(10)
    
    # Format recent for JSON
    recent_list = []
    for r in recent:
        # r: id, timestamp, src, dst, proto, type, confidence, action
        recent_list.append({
            'id': r[0],
            'timestamp': r[1],
            'src_ip': r[2],
            'dst_ip': r[3],
            'protocol': r[4],
            'type': r[5],
            'action': r[7]
        })
        
    return jsonify({
        'total_attacks': total,
        'attack_types': types,
        'recent_logs': recent_list,
        'status': 'Active' if sniffer_active else 'Inactive'
    })

def run_sniffer_background():
    global sniffer_active
    sniffer_active = True
    try:
        # Only run if not already running to avoid duplicates
        # In a production app, use proper process management
        sniffer.start_sniffer() 
    except Exception as e:
        print(f"Sniffer error: {e}")
    finally:
        sniffer_active = False

@app.route('/api/start_sniffer')
def start_sniffer_route():
    global sniffer_active
    if not sniffer_active:
        t = threading.Thread(target=run_sniffer_background)
        t.daemon = True
        t.start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already_running'})

@app.route('/api/reset_stats')
def reset_stats():
    print("[DEBUG] Reset request received")
    try:
        database.clear_all_logs()
        sniffer.reset_blocked_ips()
        print("[DEBUG] Logs and blocked IPs cleared")
        return jsonify({'message': 'All logs and blocked IPs cleared successfully', 'status': 'success'})
    except Exception as e:
        print(f"[ERROR] Reset failed: {e}")
        return jsonify({'message': str(e), 'status': 'error'}), 500

if __name__ == '__main__':
    # Initialize DB
    database.init_db()
    
    print("Starting Web Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=True) 
    # use_reloader=False prevents double execution of sniffer if we put it in main
