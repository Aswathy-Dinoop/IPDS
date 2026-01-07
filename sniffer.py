import logging
import time
import os
import random
import numpy as np
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from tensorflow.keras.models import load_model
import pickle
import sys
import subprocess

# Local imports
try:
    from database import log_attack
    from preprocessing import preprocess_data
except ImportError:
    # Fix for running as script
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from database import log_attack
    from preprocessing import preprocess_data

# Configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'cnn_model.h5')
ENCODER_PATH = os.path.join(os.path.dirname(__file__), 'model', 'encoders.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'model', 'scaler.pkl')

BLOCKED_IPS = set()
running = True

def reset_blocked_ips():
    global BLOCKED_IPS
    BLOCKED_IPS.clear()
    print("[*] Internal Blocked IPs list cleared.")

# Load Model & Preprocessors
print("Loading IDPS Model...")
try:
    model = load_model(MODEL_PATH)
    with open(ENCODER_PATH, 'rb') as f:
        encoders = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}. Ensure you have run 'python train_model.py' first.")
    # Create valid dummy objects to prevent immediate crash if just exploring code
    model = None
    encoders = {}
    scaler = None

def block_ip(ip_address):
    """
    Executes OS command to block IP.
    Windows: netsh advfirewall firewall add rule name="BlockIP" dir=in action=block remoteip=...
    Linux: iptables -A INPUT -s ... -j DROP
    """
    if ip_address in BLOCKED_IPS:
        return
    
    print(f"!!! BLOCKING MALICIOUS IP: {ip_address} !!!")
    BLOCKED_IPS.add(ip_address)
    
    if os.name == 'nt': # Windows
        cmd = f'netsh advfirewall firewall add rule name="IDPS_Block_{ip_address}" dir=in action=block remoteip={ip_address}'
    else: # Linux
        cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
    
    try:
        # We assume the script is run as Admin. If not, this will fail.
        # Check execution:
        # subprocess.run(cmd, shell=True) 
        pass # Commented out to prevent accidental lockout during dev/testing. Uncomment for real usage.
    except Exception as e:
        print(f"Failed to execute block command: {e}")

def extract_features(packet):
    """
    Map a Scapy packet to the 41 NSL-KDD features.
    Note: Many flow-based features (count, serror_rate, etc.) are impossible 
    to calculate on a single packet basis without state. 
    We fill them with zeros or heuristic values for this demonstration.
    """
    features = {}
    
    # 1. Basic Header Features
    if IP in packet:
        features['src_bytes'] = len(packet[IP].payload)
        features['dst_bytes'] = 0 # Can't know response size yet
    else:
        features['src_bytes'] = 0
        features['dst_bytes'] = 0

    if TCP in packet:
        features['protocol_type'] = 'tcp'
        features['service'] = 'http' # Simplified: mapping ports is complex, default to common
        if packet[TCP].dport == 80: features['service'] = 'http'
        elif packet[TCP].dport == 21: features['service'] = 'ftp'
        elif packet[TCP].dport == 25: features['service'] = 'smtp'
        
        # Flags mapping simplified
        flags = packet[TCP].flags
        if 'S' in flags: features['flag'] = 'S0'
        elif 'F' in flags: features['flag'] = 'SF'
        else: features['flag'] = 'SF'
        
    elif UDP in packet:
        features['protocol_type'] = 'udp'
        features['service'] = 'private'
        features['flag'] = 'SF'
    elif ICMP in packet:
        features['protocol_type'] = 'icmp'
        features['service'] = 'ecr_i'
        features['flag'] = 'SF'
    else:
        features['protocol_type'] = 'tcp'
        features['service'] = 'private'
        features['flag'] = 'SF'

    # 2. Fill missing features with defaults (0) as per KDD schema
    COL_NAMES = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"]

    row = []
    for col in COL_NAMES:
        if col in features:
            val = features[col]
        else:
            val = 0 # Default for flow features
        row.append(val)
    
    return [row]

def predict_packet(packet):
    if not model:
        return 0
        
    # Extract features
    raw_row = extract_features(packet)
    
    # Needs to match dataframe columns structure for preprocessing
    # We reconstruct a DataFrame to reuse preprocess_data logic
    import pandas as pd
    COL_NAMES = ["duration","protocol_type","service","flag","src_bytes",
        "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
        "logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
        "is_host_login","is_guest_login","count","srv_count","serror_rate",
        "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
        "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
        "dst_host_rerror_rate","dst_host_srv_rerror_rate"] # No label here
        
    # Add dummy label col for compatibility with preprocessing func if needed, 
    # but preprocess_data expects 'label' to drop it.
    df = pd.DataFrame(raw_row, columns=COL_NAMES)
    df['label'] = 'normal' # Dummy
    
    # Preprocess
    # Pass is_training=False to use loaded scalar/encoders
    try:
        X, _ = preprocess_data(df, is_training=False)
        prediction = model.predict(X, verbose=0)
        return prediction[0][0]
    except Exception as e:
        print(f"Prediction error: {e}")
        return 0

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet: proto = 'TCP'
        elif UDP in packet: proto = 'UDP'
        elif ICMP in packet: proto = 'ICMP'
        else: proto = 'OTHER'

        # Predict
        confidence = predict_packet(packet)
        
        # Threshold for attack detection
        if confidence > 0.5:
            attack_type = "Malicious Traffic" # Multi-class would give specific name
            action = "Blocked"
            print(f"[ALERT] Attack detected from {src_ip} -> {dst_ip} ({confidence:.2f})")
            log_attack(src_ip, dst_ip, proto, attack_type, confidence, action)
            block_ip(src_ip)
        else:
            # print(f"Normal packet: {src_ip}")
            pass

def simulation_mode_sniffer():
    """
    Fallback mode for Windows systems without Npcap.
    Monitors a signal file to detect when 'attack_simulation.py' is run,
    and forwards that to the ML model.
    """
    print("[*] Sniffer running in SIMULATION/COMPATIBILITY mode.")
    print("[*] Waiting for traffic from attack_simulation.py...")
    
    SIGNAL_FILE = os.path.join(os.path.dirname(__file__), 'attack_signal.txt')
    
    while running:
        # 1. Check for explicit attack signals from simulation script
        if os.path.exists(SIGNAL_FILE):
            try:
                with open(SIGNAL_FILE, 'r') as f:
                    attack_type = f.read().strip()
                
                print(f"[!] Signal received: {attack_type}")
                
                # Create a mock packet based on the signal
                if attack_type == 'DoS':
                    # Simulated SYN Flood packet
                    pkt = IP(src="192.168.1.100", dst="127.0.0.1")/TCP(dport=80, flags='S')
                elif attack_type == 'PortScan':
                    # Simulated Port Scan packet
                    pkt = IP(src="192.168.1.101", dst="127.0.0.1")/TCP(dport=random.choice([21,22,80,443]), flags='S')
                else:
                    pkt = IP(src="192.168.1.200", dst="127.0.0.1")/TCP(dport=80, flags='PA')

                # Process it through the ML pipeline
                packet_callback(pkt)
                
                # Remove signal
                os.remove(SIGNAL_FILE)
            except Exception as e:
                print(f"Error reading signal: {e}")
        
        # 2. Simulate random background 'Normal' traffic
        else:
            if random.random() < 0.2: # 20% chance every loop
                # Normal HTTP traffic
                pkt = IP(src=f"192.168.1.{random.randint(50,200)}", dst="127.0.0.1")/TCP(dport=80, flags='PA')
                packet_callback(pkt)

        time.sleep(0.5)

def start_sniffer(interface=None):
    print(f"[*] Starting Sniffer...")
    
    try:
        # Try real sniffing first
        # timeout=1 allows us to periodically check if 'running' is still True (if we were using a while loop)
        # but sniff() is blocking. 
        # We try to bind. if it fails immediately, we go to catch.
        if os.name == 'nt':
            # Windows compatibility check
            print("[*] Attempting to bind to Scapy interface...")
        
        sniff(prn=packet_callback, filter="ip", store=0, count=0)
        
    except Exception as e:
        print(f"\n[!] SCAPY SNIFFER ERROR: {e}")
        print("[!] It seems you don't have Npcap installed or have interface issues.")
        print("[*] Switching to FAULT-TOLERANT SIMULATION MODE so you can still demo the project.")
        simulation_mode_sniffer()

if __name__ == "__main__":
    # If run standalone
    start_sniffer()
