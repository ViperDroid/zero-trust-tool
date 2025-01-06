import hashlib
import time
import json
from datetime import datetime
import socket
import threading
import csv
import requests
import sys
import configparser
from cryptography.fernet import Fernet
from scapy.all import sniff, IP
from sklearn.ensemble import IsolationForest
import numpy as np
import subprocess
import pyotp
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt


print(


"""
     ██╗   ██╗██╗██████╗ ███████╗███████╗██████╗ 
     ██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔══██╗
     ██║   ██║██║██████╔╝█████╗  █████╗  ██████╔╝
     ██║   ██║██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██╗
     ╚██████╔╝██║██║     ███████╗███████╗██║  ██║
      ╚═════╝ ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
    Powered by Viper Droid

    """

)

# Load Configuration
config = configparser.ConfigParser()
config.read('config.ini')

BLOCKCHAIN_NODES = config['DEFAULT'].get('BLOCKCHAIN_NODES', '').split(',')
THREAT_INTELLIGENCE_API = config['DEFAULT'].get('THREAT_INTELLIGENCE_API', '')
ENCRYPTION_KEY = config['DEFAULT'].get('ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

# User and Device Management
USERS = {
    "admin": {"password": "admin123", "otp_secret": pyotp.random_base32(), "role": "admin"},
    "user1": {"password": "password123", "otp_secret": pyotp.random_base32(), "role": "user"},
}
DEVICES = {"device123": True, "device456": False}

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_logs = []
        self.nodes = set(BLOCKCHAIN_NODES)
        self.create_block(previous_hash="0", proof=100)

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.now()),
            'logs': self.pending_logs,
            'proof': proof,
            'previous_hash': previous_hash,
        }
        self.pending_logs = []
        self.chain.append(block)
        self.broadcast_block(block)
        return block

    def add_log(self, username, device_id, status):
        log = {
            'username': username,
            'device_id': device_id,
            'status': status,
            'timestamp': str(datetime.now()),
        }
        self.pending_logs.append(log)

    def get_last_block(self):
        return self.chain[-1]

    def hash_block(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def proof_of_work(self, previous_proof):
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()
            ).hexdigest()
            if hash_operation[:4] == "0000":
                break
            new_proof += 1
        return new_proof

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash_block(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()
            ).hexdigest()
            if hash_operation[:4] != "0000":
                return False
            previous_block = block
            block_index += 1
        return True

    def add_node(self, address):
        self.nodes.add(address)
        config['DEFAULT']['BLOCKCHAIN_NODES'] = ','.join(self.nodes)
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    def broadcast_block(self, block):
        for node in self.nodes:
            self.send_block(node, block)

    def send_block(self, node, block):
        try:
            node_ip, node_port = node.split(":")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((node_ip, int(node_port)))
                s.send(json.dumps(block).encode())
        except Exception as e:
            print(f"Failed to send block to {node}: {e}")

class ZeroTrustSystem:
    def __init__(self):
        self.blockchain = Blockchain()
        self.ml_model = IsolationForest(contamination=0.1)

    def log_access_attempt(self, username, device_id, status):
        encrypted_log = self.encrypt_log(username, device_id, status)
        self.blockchain.add_log(username, device_id, status)
        last_block = self.blockchain.get_last_block()
        proof = self.blockchain.proof_of_work(last_block['proof'])
        previous_hash = self.blockchain.hash_block(last_block)
        self.blockchain.create_block(proof, previous_hash)

    def encrypt_log(self, username, device_id, status):
        log = {
            'username': username,
            'device_id': device_id,
            'status': status,
            'timestamp': str(datetime.now()),
        }
        encrypted_log = cipher_suite.encrypt(json.dumps(log).encode())
        return encrypted_log

    def verify_integrity(self):
        return self.blockchain.is_chain_valid(self.blockchain.chain)

    def display_blockchain(self):
        for block in self.blockchain.chain:
            print(f"Block {block['index']}")
            print(f"Timestamp: {block['timestamp']}")
            print(f"Logs: {block['logs']}")
            print(f"Proof: {block['proof']}")
            print(f"Previous Hash: {block['previous_hash']}")
            print("-" * 50)

    def export_logs_to_csv(self, filename="access_logs.csv"):
        with open(filename, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Index", "Timestamp", "Username", "Device ID", "Status"])
            for block in self.blockchain.chain:
                for log in block['logs']:
                    writer.writerow([block['index'], log['timestamp'], log['username'], log['device_id'], log['status']])
        print(f"Logs exported to {filename}")

    def check_threat_intelligence(self, ip_address):
        print(f"Checking threat intelligence for IP: {ip_address}")
        response = requests.get(f"{THREAT_INTELLIGENCE_API}?ip={ip_address}")
        return response.json()

    def start_node_server(self, host, port):
        def handle_client(conn, addr):
            with conn:
                data = conn.recv(1024).decode()
                block = json.loads(data)
                self.blockchain.chain.append(block)
                print(f"New block received from {addr}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            print(f"Node server started on {host}:{port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr)).start()

    def monitor_network(self):
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                print(f"Packet: {src_ip} -> {dst_ip}")
                self.detect_anomaly(src_ip)

        sniff(prn=packet_callback, store=False)

    def detect_anomaly(self, ip_address):
        data = np.random.rand(100, 10)  # Simulated network traffic data
        predictions = self.ml_model.fit_predict(data)
        if -1 in predictions:
            print(f"Anomaly detected from IP: {ip_address}")
            self.block_ip(ip_address)

    def block_ip(self, ip_address):
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
            print(f"Blocked IP: {ip_address}")
        except Exception as e:
            print(f"Failed to block IP: {e}")

    def verify_user(self, username, password, otp):
        if username in USERS:
            user = USERS[username]
            if user["password"] == password:
                totp = pyotp.TOTP(user["otp_secret"])
                if totp.verify(otp):
                    return True
        return False

    def add_user(self, username, password, role):
        if username not in USERS:
            USERS[username] = {
                "password": password,
                "otp_secret": pyotp.random_base32(),
                "role": role,
            }
            print(f"User {username} added.")
        else:
            print(f"User {username} already exists.")

    def add_device(self, device_id, trusted):
        if device_id not in DEVICES:
            DEVICES[device_id] = trusted
            print(f"Device {device_id} added.")
        else:
            print(f"Device {device_id} already exists.")

def interactive_cli():
    zero_trust_system = ZeroTrustSystem()

    while True:
        print("\n=== Zero-Trust Cybersecurity Tool ===")
        print("1. Log Access Attempt")
        print("2. Display Blockchain")
        print("3. Verify Blockchain Integrity")
        print("4. Export Logs to CSV")
        print("5. Check Threat Intelligence")
        print("6. Add Node")
        print("7. Monitor Network Traffic")
        print("8. Add User")
        print("9. Add Device")
        print("10. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            otp = input("Enter OTP: ")
            if zero_trust_system.verify_user(username, password, otp):
                device_id = input("Enter device ID: ")
                status = input("Enter status (GRANTED/DENIED): ")
                zero_trust_system.log_access_attempt(username, device_id, status)
                print("Access attempt logged.")
            else:
                print("Authentication failed.")

        elif choice == "2":
            zero_trust_system.display_blockchain()

        elif choice == "3":
            if zero_trust_system.verify_integrity():
                print("Blockchain integrity verified.")
            else:
                print("Blockchain integrity compromised.")

        elif choice == "4":
            filename = input("Enter filename (e.g., access_logs.csv): ")
            zero_trust_system.export_logs_to_csv(filename)

        elif choice == "5":
            ip_address = input("Enter IP address to check: ")
            threat_report = zero_trust_system.check_threat_intelligence(ip_address)
            print(f"Threat Report: {threat_report}")

        elif choice == "6":
            node_address = input("Enter node address (e.g., 127.0.0.1:5001): ")
            zero_trust_system.blockchain.add_node(node_address)
            print(f"Node {node_address} added.")

        elif choice == "7":
            print("Starting network monitoring...")
            zero_trust_system.monitor_network()

        elif choice == "8":
            username = input("Enter username: ")
            password = input("Enter password: ")
            role = input("Enter role (admin/user): ")
            zero_trust_system.add_user(username, password, role)

        elif choice == "9":
            device_id = input("Enter device ID: ")
            trusted = input("Is device trusted? (True/False): ").lower() == "true"
            zero_trust_system.add_device(device_id, trusted)

        elif choice == "10":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        node_ip = sys.argv[1]
        node_port = int(sys.argv[2])
        zero_trust_system = ZeroTrustSystem()
        zero_trust_system.start_node_server(node_ip, node_port)
    else:
        interactive_cli()
