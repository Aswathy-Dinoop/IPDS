import socket
import threading
import time
import random
import os

# Configuration
TARGET_IP = "127.0.0.1" 
TARGET_PORT = 80 # Ensure your app.py is listening or just target an open port relative to the IDPS host
SIGNAL_FILE = os.path.join(os.path.dirname(__file__), 'attack_signal.txt')

def signal_attack(attack_type):
    """
    Writes a signal file for the IDPS to pick up if it's running in 
    simulation/fallback mode (no Npcap).
    """
    try:
        with open(SIGNAL_FILE, 'w') as f:
            f.write(attack_type)
    except Exception as e:
        print(f"Warning: Could not write signal file: {e}")

def dos_thread():
    """Single thread attempting connections to simulate traffic/DoS"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        # Attempt connection
        s.connect((TARGET_IP, TARGET_PORT))
        # Send a little bit of garbage to create 'src_bytes'
        s.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        s.close()
    except:
        pass

def simulate_dos_attack():
    """
    Simulates a DoS-like pattern by spawning many threads 
    that connect rapidly to the target.
    """
    print(f"[*] Simulating DoS Attack (High Volume Traffic) -----> {TARGET_IP}:{TARGET_PORT}")
    
    # Signal the IDPS
    signal_attack('DoS')
    
    threads = []
    # Launch 500 connections rapidly
    for i in range(100):
        t = threading.Thread(target=dos_thread)
        t.daemon = True
        t.start()
        threads.append(t)
        if i % 10 == 0:
            time.sleep(0.1) # Slight stagger to not instantly freeze script
            
    print("[*] DoS Simulation Traffic Sent.\n")

def simulate_port_scan():
    """
    Simulates a Port Scan using standard sockets.
    """
    print(f"[*] Simulating Port Scan -----> {TARGET_IP}")
    
    # Signal the IDPS
    signal_attack('PortScan')
    
    target_ports = [21, 22, 23, 25, 80, 443, 8080, 3306, 5000]
    
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((TARGET_IP, port))
        
        status = "OPEN" if result == 0 else "CLOSED/FILTERED"
        # We don't print status to reduce clutter, just generating the traffic
        # print(f"Port {port}: {status}")
        
        sock.close()
        time.sleep(0.2)
        
    print("[*] Port Scan Simulation Complete.\n")

if __name__ == "__main__":
    print("WARNING: This script simulates network traffic for IDPS testing.")
    print("Ensure your IDPS (python app.py) is ACTIVE before running this.")
    print("-------------------------------------------------------------")
    
    choice = input("1. Simulate DoS Attack (Traffic Flood)\n2. Simulate Port Scan\nEnter choice (1/2): ")
    
    if choice == '1':
        simulate_dos_attack()
    elif choice == '2':
        simulate_port_scan()
    else:
        print("Invalid choice.")
