import socket
import threading
import time
import random
from scapy.all import IP, TCP, UDP, Raw, send
import requests
import logging

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    COLOR = True
except ImportError:
    COLOR = False
    class Dummy:
        def __getattr__(self, k): return ''
    Fore = Style = Dummy()

# Configure logging
logging.basicConfig(
    filename='test_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def cprint(msg, color=None):
    if COLOR and color:
        print(getattr(Fore, color.upper(), '') + msg + Style.RESET_ALL)
    else:
        print(msg)

class AlertTester:
    def __init__(self, target_ip="127.0.0.1", port=80, verbose=True):
        self.target_ip = target_ip
        self.port = port
        self.verbose = verbose
        self.running = False
        self.test_threads = []

    def start_test(self, test_type, **kwargs):
        if test_type == "all":
            self._run_all_tests(**kwargs)
        elif test_type == "port_scan":
            self._test_port_scan(**kwargs)
        elif test_type == "sql_injection":
            self._test_sql_injection(**kwargs)
        elif test_type == "xss":
            self._test_xss(**kwargs)
        elif test_type == "flood":
            self._test_connection_flood(**kwargs)
        elif test_type == "data_exfil":
            self._test_data_exfiltration(**kwargs)
        else:
            logging.error(f"Unknown test type: {test_type}")

    def _run_all_tests(self, **kwargs):
        tests = [
            self._test_port_scan,
            self._test_sql_injection,
            self._test_xss,
            self._test_connection_flood,
            self._test_data_exfiltration
        ]
        for test in tests:
            test(**kwargs)
            time.sleep(2)

    def _test_port_scan(self, ports=None, delay=0.05):
        cprint("[Port Scan] Starting port scan test", "yellow")
        logging.info("Starting port scan test")
        if ports is None:
            ports = list(range(20, 40)) + [53, 80, 443, 445, 3306, 3389, 8080]
        ports = list(set(ports))
        random.shuffle(ports)
        for port in ports:
            try:
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent SYN to port {port}", "cyan")
                logging.info(f"Port scan: Sent SYN packet to port {port}")
                time.sleep(delay)
            except Exception as e:
                logging.error(f"Port scan error: {e}")
        cprint(f"[Port Scan] Sent SYN packets to {len(ports)} ports.", "green")

    def _test_sql_injection(self, delay=0.1):
        cprint("[SQL Injection] Starting SQL injection test", "yellow")
        logging.info("Starting SQL injection test")
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR '1'='1' -- ",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' UNION SELECT password FROM users--",
            "' UNION SELECT * FROM users; --",
            "' AND 1=0 UNION ALL SELECT username, password FROM users--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "' OR 1=1 LIMIT 1;--",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1;",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1--",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1#",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1/*",
            "DROP TABLE users;",
            "SELECT password FROM users WHERE username = 'admin';"
        ]
        for payload in sql_payloads:
            try:
                # GET request
                packet = IP(dst=self.target_ip)/TCP(dport=self.port)/Raw(load=f"GET /login.php?user={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n")
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent SQLi GET payload: {payload[:40]}...", "cyan")
                # POST request
                packet = IP(dst=self.target_ip)/TCP(dport=self.port)/Raw(load=f"POST /login.php HTTP/1.1\r\nHost: {self.target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)+5}\r\n\r\nuser={payload}")
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent SQLi POST payload: {payload[:40]}...", "magenta")
                logging.info(f"SQL injection: Sent payload: {payload}")
                time.sleep(delay)
            except Exception as e:
                logging.error(f"SQL injection error: {e}")
        cprint(f"[SQL Injection] Sent {len(sql_payloads)*2} payloads (GET+POST).", "green")

    def _test_xss(self, delay=0.1):
        cprint("[XSS] Starting XSS test", "yellow")
        logging.info("Starting XSS test")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<div onmouseover=alert('XSS')>XSS</div>",
            "<a href=javascript:alert('XSS')>click</a>",
            "<input onfocus=alert('XSS') autofocus>",
            "<math href=javascript:alert(1)>XSS</math>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<form action=javascript:alert('XSS')>",
            "<img src='x' onerror='alert(1)'>"
        ]
        for payload in xss_payloads:
            try:
                packet = IP(dst=self.target_ip)/TCP(dport=self.port)/Raw(load=f"GET /search?q={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n")
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent XSS payload: {payload[:40]}...", "cyan")
                logging.info(f"XSS: Sent payload: {payload}")
                time.sleep(delay)
            except Exception as e:
                logging.error(f"XSS error: {e}")
        cprint(f"[XSS] Sent {len(xss_payloads)} payloads.", "green")

    def _test_connection_flood(self, count=1300, delay=0.01):
        cprint(f"[Flood] Starting connection flood: {count} SYNs, {delay}s delay", "yellow")
        logging.info("Starting connection flood test")
        try:
            for _ in range(count):
                packet = IP(dst=self.target_ip)/TCP(dport=self.port, flags="S")
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent SYN flood packet", "cyan")
                time.sleep(delay)
            logging.info(f"Connection flood: Sent {count} rapid connection attempts")
        except Exception as e:
            logging.error(f"Connection flood error: {e}")
        cprint(f"[Flood] Sent {count} SYN packets.", "green")

    def _test_data_exfiltration(self, packets=11000, size=1400, delay=0.005):
        cprint(f"[Exfiltration] Sending {packets} packets of {size} bytes each", "yellow")
        logging.info("Starting data exfiltration test")
        try:
            for i in range(packets):
                large_data = "A" * size
                packet = IP(dst=self.target_ip)/TCP(dport=self.port)/Raw(load=large_data)
                send(packet, verbose=0)
                if self.verbose:
                    cprint(f"  Sent exfil packet {i+1}/{packets}", "cyan")
                time.sleep(delay)
            logging.info(f"Data exfiltration: Sent {packets} large data packets")
        except Exception as e:
            logging.error(f"Data exfiltration error: {e}")
        cprint(f"[Exfiltration] Sent {packets} packets.", "green")

def main():
    print("Alert Testing Tool")
    print("=================")
    print("1. Run all tests")
    print("2. Port scan test")
    print("3. SQL injection test")
    print("4. XSS test")
    print("5. Connection flood test")
    print("6. Data exfiltration test")
    print("7. Exit")
    
    target_ip = input("Enter target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
    port = input("Enter target port (default: 80): ").strip() or "80"
    try:
        port = int(port)
    except Exception:
        port = 80
    tester = AlertTester(target_ip, port)
    
    while True:
        choice = input("\nSelect test to run (1-7): ").strip()
        if choice == "1":
            tester.start_test("all")
        elif choice == "2":
            count = input("How many ports to scan? (default 10): ").strip() or "10"
            try:
                count = int(count)
            except Exception:
                count = 10
            ports = list(range(20, 20+count))
            tester.start_test("port_scan", ports=ports)
        elif choice == "3":
            delay = input("Delay between SQLi payloads (default 0.1s): ").strip() or "0.1"
            try:
                delay = float(delay)
            except Exception:
                delay = 0.1
            tester.start_test("sql_injection", delay=delay)
        elif choice == "4":
            delay = input("Delay between XSS payloads (default 0.1s): ").strip() or "0.1"
            try:
                delay = float(delay)
            except Exception:
                delay = 0.1
            tester.start_test("xss", delay=delay)
        elif choice == "5":
            count = input("How many SYNs? (default 1300): ").strip() or "1300"
            delay = input("Delay between SYNs (default 0.01s): ").strip() or "0.01"
            try:
                count = int(count)
                delay = float(delay)
            except Exception:
                count = 1300
                delay = 0.01
            tester.start_test("flood", count=count, delay=delay)
        elif choice == "6":
            packets = input("How many exfil packets? (default 11000): ").strip() or "11000"
            size = input("Packet size in bytes? (default 1400): ").strip() or "1400"
            delay = input("Delay between packets (default 0.005s): ").strip() or "0.005"
            try:
                packets = int(packets)
                size = int(size)
                delay = float(delay)
            except Exception:
                packets = 11000
                size = 1400
                delay = 0.005
            tester.start_test("data_exfil", packets=packets, size=size, delay=delay)
        elif choice == "7":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 