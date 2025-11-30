import argparse
import socket
import json
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to scan (you can extend this later)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
}


def grab_banner(ip: str, port: int, sock: socket.socket) -> str:
    """Try to grab a simple banner from the service."""
    try:
        sock.settimeout(1.5)
        try:
            sock.sendall(b"\r\n")
        except OSError:
            # Some services don't like data being sent first
            pass
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def check_ftp_anonymous(ip: str) -> dict:
    """Check if FTP allows anonymous login."""
    result = {"supported": False, "allowed": False, "banner": ""}
    try:
        with socket.create_connection((ip, 21), timeout=3) as s:
            banner = s.recv(1024).decode(errors="ignore")
            result["supported"] = True
            result["banner"] = banner.strip()

            s.sendall(b"USER anonymous\r\n")
            resp_user = s.recv(1024).decode(errors="ignore")

            s.sendall(b"PASS anonymous@example.com\r\n")
            resp_pass = s.recv(1024).decode(errors="ignore")

            if "230" in resp_pass:
                result["allowed"] = True
    except Exception:
        # Service not available or no response; ignore silently
        pass
    return result


def analyze_http_banner(banner: str) -> dict:
    """Very basic heuristic to flag potentially outdated web stack versions."""
    info = {"outdated": False, "reason": ""}
    banner_lower = banner.lower()

    # Check Apache version
    if "apache/" in banner_lower:
        import re

        m = re.search(r"apache/(\d+)\.(\d+)", banner_lower)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            # Example heuristic: Apache < 2.4 is considered old
            if major < 2 or (major == 2 and minor < 4):
                info["outdated"] = True
                info["reason"] = f"Apache version looks old: {m.group(0)}"

    # Check PHP version
    if "php/" in banner_lower:
        import re

        m = re.search(r"php/(\d+)\.(\d+)", banner_lower)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            # Example heuristic: PHP < 7 is considered old
            if major < 7:
                info["outdated"] = True
                r = f"PHP version looks old: {m.group(0)}"
                info["reason"] = f"{info['reason']} | {r}" if info["reason"] else r

    return info


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single TCP port and return information about it."""
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "state": "closed",
        "banner": "",
        "weaknesses": [],
    }

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            result["state"] = "open"

            # Banner grabbing
            banner = grab_banner(ip, port, s)
            if banner:
                result["banner"] = banner

            # Weak FTP config check
            if port == 21:
                ftp_res = check_ftp_anonymous(ip)
                if ftp_res["supported"]:
                    result["banner"] = ftp_res["banner"] or banner
                    if ftp_res["allowed"]:
                        result["weaknesses"].append("FTP allows anonymous login")

            # Very basic web stack analysis
            if port in (80, 443) and banner:
                http_info = analyze_http_banner(banner)
                if http_info["outdated"]:
                    result["weaknesses"].append(http_info["reason"])

    except (ConnectionRefusedError, TimeoutError, OSError):
        # Closed / filtered port
        pass
    except Exception:
        # Any other unexpected error
        pass

    return result


def scan_host(ip: str, ports: list[int], max_workers: int = 50) -> dict:
    """Scan all specified ports on a host using threads."""
    host_result = {"ip": ip, "ports": []}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port): port for port in ports
        }

        for future in as_completed(future_to_port):
            res = future.result()
            if res["state"] == "open":
                host_result["ports"].append(res)

    return host_result


def expand_targets(target: str) -> list[str]:
    """Turn a single IP or CIDR into a list of IPs."""
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            ipaddress.ip_address(target)
            return [target]
    except ValueError:
        raise SystemExit(f"Invalid target: {target}")


def generate_html_report(report: dict, path: str) -> None:
    """Generate a simple HTML report from the JSON report dict."""
    html_parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>Python Vulnerability Scanner Report</title>",
        "<style>",
        "body{font-family:Arial, sans-serif;background:#0f172a;color:#e5e7eb;padding:20px;}",
        "h1,h2{color:#38bdf8;}",
        "table{border-collapse:collapse;width:100%;margin-bottom:20px;}",
        "th,td{border:1px solid #4b5563;padding:8px;font-size:14px;}",
        "th{background:#111827;color:#f9fafb;}",
        "tr:nth-child(even){background:#020617;}",
        ".badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:12px;}",
        ".open{background:#16a34a;color:#dcfce7;}",
        ".weak{background:#b91c1c;color:#fee2e2;margin-left:4px;}",
        "</style></head><body>",
    ]

    html_parts.append("<h1>Python Vulnerability Scanner Report</h1>")
    html_parts.append(f"<p>Generated at: {report['metadata']['generated_at']}</p>")
    html_parts.append(
        f"<p>Target: {report['metadata']['target']} | "
        f"Ports: {report['metadata']['ports_scanned']}</p>"
    )

    for host in report["hosts"]:
        html_parts.append(f"<h2>Host: {host['ip']}</h2>")
        if not host["ports"]:
            html_parts.append("<p>No open ports found.</p>")
            continue

        html_parts.append(
            "<table><tr>"
            "<th>Port</th><th>Service</th><th>Banner</th><th>Weaknesses</th>"
            "</tr>"
        )

        for p in sorted(host["ports"], key=lambda x: x["port"]):
            weaknesses = ""
            if p["weaknesses"]:
                weaknesses = "".join(
                    f"<span class='badge weak'>{w}</span>" for w in p["weaknesses"]
                )

            html_parts.append(
                "<tr>"
                f"<td><span class='badge open'>{p['port']}</span></td>"
                f"<td>{p['service']}</td>"
                f"<td><pre style='white-space:pre-wrap;margin:0'>"
                f"{(p['banner'] or '').replace('<', '&lt;')}</pre></td>"
                f"<td>{weaknesses}</td>"
                "</tr>"
            )

        html_parts.append("</table>")

    html_parts.append("</body></html>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))


def main():
    parser = argparse.ArgumentParser(description="Python Vulnerability Scanner")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP or CIDR range, e.g. 192.168.1.10 or 192.168.1.0/24",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="21,22,23,80,443,3306,3389",
        help="Comma-separated list of ports to scan, or 'common' to use built-in common ports",
    )
    parser.add_argument(
        "-o",
        "--output-prefix",
        default="report",
        help="Prefix for output files (JSON and HTML)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=100,
        help="Maximum number of concurrent threads",
    )

    args = parser.parse_args()

    # Port parsing
    if args.ports == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
        except ValueError:
            raise SystemExit("Ports must be integers or 'common'")

    # Targets
    targets = expand_targets(args.target)

    print(f"[+] Scanning {len(targets)} host(s)...")
    print(f"[+] Ports: {ports}")

    hosts_results = []
    for ip in targets:
        print(f"\n[+] Scanning host: {ip}")
        host_result = scan_host(ip, ports, max_workers=args.max_workers)
        hosts_results.append(host_result)

        for p in sorted(host_result["ports"], key=lambda x: x["port"]):
            print(f"    - Port {p['port']}/tcp OPEN ({p['service']})")

    # Build report structure
    report = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "target": args.target,
            "ports_scanned": ports,
            "host_count": len(targets),
        },
        "hosts": hosts_results,
    }

    # Save JSON
    json_path = f"{args.output_prefix}.json"
    html_path = f"{args.output_prefix}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    # Save HTML
    generate_html_report(report, html_path)

    print("\n[+] Scan complete!")
    print(f"[+] JSON report saved to {json_path}")
    print(f"[+] HTML report saved to {html_path}")


if __name__ == "__main__":
    main()
