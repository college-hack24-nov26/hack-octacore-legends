"""Safe Controlled Live Traffic Generator for UniGuard AI Testing.

Generates continuous benign and simulated attack traffic on localhost (127.0.0.1)
or a controlled test subnet so that UniGuard AI can be demonstrated live without attacking public networks.
"""

import time
import socket
import urllib.request
import threading
import sys


def generate_benign_http_traffic(stop_event: threading.Event) -> None:
    """Generates continuous benign HTTP/DNS request bursts."""
    print("[+] Starting benign web browsing thread...")
    test_urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://httpbin.org/get",
    ]
    while not stop_event.is_set():
        for url in test_urls:
            if stop_event.is_set():
                break
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "UniGuard-TestClient/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    _ = resp.read(1024)
                print(f"[Benign] Completed HTTP GET to {url}")
            except Exception:
                pass
            time.sleep(2.0)


def generate_controlled_port_scan(target_ip: str = "127.0.0.1", ports: list = None) -> None:
    """Simulates a rapid multi-port scan against localhost."""
    ports = ports or [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 9000]
    print(f"\n[!] Simulating Port Scan against {target_ip} on ports: {ports}...")
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target_ip, p))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)
    print("[!] Port scan complete.\n")


def generate_controlled_udp_burst(target_ip: str = "127.0.0.1", target_port: int = 53535, count: int = 100) -> None:
    """Simulates a fast burst of UDP datagrams."""
    print(f"\n[!] Simulating fast UDP burst of {count} packets to {target_ip}:{target_port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 512
    for _ in range(count):
        try:
            s.sendto(payload, (target_ip, target_port))
        except Exception:
            pass
        time.sleep(0.005) # 200 packets/second
    s.close()
    print("[!] UDP burst complete.\n")


def main() -> None:
    print("=" * 70)
    print(" UNIGUARD AI: CONTROLLED LIVE TRAFFIC GENERATOR")
    print(" Safe demonstration tool for hackathon evaluation")
    print("=" * 70)

    stop_event = threading.Event()
    benign_thread = threading.Thread(target=generate_benign_http_traffic, args=(stop_event,), daemon=True)
    benign_thread.start()

    try:
        time.sleep(5)
        generate_controlled_port_scan()
        time.sleep(5)
        generate_controlled_udp_burst()
        time.sleep(5)
        print("[*] Test cycle complete. Press Ctrl+C to stop benign background requests.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping traffic generator.")
        stop_event.set()


if __name__ == "__main__":
    main()
