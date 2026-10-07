import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

# Common ports and the service usually running on them
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}

HTTP_PORTS = (80, 8080)
HTTPS_PORTS = (443,)

# Ports that deserve a warning when exposed
RISKY_PORTS = {
    21: "FTP sends credentials in plain text",
    23: "Telnet sends everything in plain text",
    139: "NetBIOS exposure can leak host information",
    445: "SMB exposed; check patching and restrict access",
    3306: "Database port exposed to the network",
    3389: "RDP exposed; common brute-force target",
    5432: "Database port exposed to the network",
}

# Security headers we expect on a web response
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS (HTTPS sites only)",
    "Content-Security-Policy": "Helps prevent XSS",
    "X-Frame-Options": "Helps prevent clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser features",
}


def scan_port(target, port, timeout=1.0):
    """Try to connect to one port. Return True if it is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target, port)) == 0
    except socket.error:
        return False


def scan_ports(target, ports):
    """Scan many ports in parallel. Return a sorted list of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(lambda p: (p, scan_port(target, p)), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def grab_banner(ip, port, host, timeout=2.0):
    """Connect to an open port and read the service banner, if any."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            if port in HTTP_PORTS:
                # HTTP servers wait for a request before they talk
                request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                s.sendall(request.encode())

            data = s.recv(1024).decode(errors="ignore").strip()
    except (socket.error, OSError):
        return None

    if not data:
        return None

    if port in HTTP_PORTS:
        # Show the Server header if present, else the status line
        for line in data.splitlines():
            if line.lower().startswith("server:"):
                return line.strip()
        return data.splitlines()[0]

    # Other services (SSH, FTP, SMTP) send a banner on connect
    return data.splitlines()[0]


def check_http_headers(host, port):
    """Fetch the web page and report missing security headers."""
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{host}:{port}/"

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True, verify=False)
    except requests.RequestException as err:
        return {"url": url, "error": str(err)}

    missing = []
    for header, why in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and scheme != "https":
            continue
        if header not in resp.headers:
            missing.append({"header": header, "why": why})

    info_leaks = []
    for header in ("Server", "X-Powered-By"):
        if header in resp.headers:
            info_leaks.append(f"{header}: {resp.headers[header]}")

    return {
        "url": url,
        "status": resp.status_code,
        "missing_headers": missing,
        "info_leaks": info_leaks,
    }


def save_report(report, target):
    """Save the scan result as a timestamped JSON file."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    filename = f"scan_{safe_target}_{stamp}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve {target}")
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()

    print(f"Scanning {target} ({ip})")
    print("Only scan systems you own or have permission to test.\n")

    report = {
        "target": target,
        "ip": ip,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "open_ports": [],
        "web_checks": [],
    }

    open_ports = scan_ports(ip, COMMON_PORTS.keys())

    if not open_ports:
        print("No open ports found among the common ports.")
    else:
        print("== Open ports ==")
        for port in open_ports:
            banner = grab_banner(ip, port, target)
            warning = RISKY_PORTS.get(port)

            line = f"[OPEN] {port}/tcp  {COMMON_PORTS[port]}"
            if banner:
                line += f"  ->  {banner}"
            print(line)
            if warning:
                print(f"       [!] {warning}")

            report["open_ports"].append({
                "port": port,
                "service": COMMON_PORTS[port],
                "banner": banner,
                "warning": warning,
            })

    web_ports = [p for p in open_ports if p in HTTP_PORTS + HTTPS_PORTS]
    if web_ports:
        print("\n== Web security headers ==")
    for port in web_ports:
        result = check_http_headers(target, port)
        report["web_checks"].append(result)

        print(f"{result['url']}")
        if "error" in result:
            print(f"   Could not fetch: {result['error']}")
            continue

        print(f"   Status: {result['status']}")
        for item in result["missing_headers"]:
            print(f"   [MISSING] {item['header']}  ({item['why']})")
        for leak in result["info_leaks"]:
            print(f"   [INFO] {leak}  (version disclosure)")
        if not result["missing_headers"]:
            print("   All checked security headers present.")

    filename = save_report(report, target)
    print(f"\nReport saved: {filename}")


if __name__ == "__main__":
    main()