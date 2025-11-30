import argparse
import socket
import json
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re


##############################################
# COMMON PORTS
##############################################
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


##############################################
# OFFLINE CVE-LIKE RULESET
# (No internet required)
##############################################
RULES = [
    {
        "pattern": r"apache/(\d+)\.(\d+)",
        "check": lambda major, minor: major < 2 or (major == 2 and minor < 4),
        "severity": "HIGH",
        "message": "Apache version is outdated (Apache < 2.4). Known vulnerabilities like CVE‑2017‑15710."
    },
    {
        "pattern": r"php/(\d+)\.(\d+)",
        "check": lambda major, minor: major < 7,
        "severity": "HIGH",
        "message": "PHP version is obsolete (PHP < 7). Many remote code execution CVEs exist."
    },
    {
        "pattern": r"openssh_(\d+)\.(\d+)",
        "check": lambda major, minor: major < 7 or (major == 7 and minor < 6),
        "severity": "HIGH",
        "message": "OpenSSH version outdated (<7.6). Multiple privilege escalation CVEs."
    },
    {
        "pattern": r"mysql\s+(\d+)\.(\d+)",
        "check": lambda major, minor: major < 5 or (major == 5 and minor < 7),
        "severity": "MEDIUM",
        "message": "MySQL version outdated (<5.7). Known authentication bypass vulnerabilities."
    },
]


##############################################
# BANNER GRABBING
##############################################
def grab_banner(ip: str, port: int, sock: socket.socket) -> str:
    try:
        sock.settimeout(1.5)
        try:
            sock.sendall(b"\r\n")
        except:
            pass
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except:
        return ""


##############################################
# FTP ANONYMOUS CHECK
##############################################
def check_ftp_anonymous(ip: str) -> dict:
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

            if "230" in resp_pass:  # 230 = successful login
                result["allowed"] = True

    except:
        pass

    return result


##############################################
# APPLY OFFLINE CVE RULES
##############################################
def analyze_banner_with_rules(banner: str) -> list[dict]:
    findings = []
    b = banner.lower()

    for rule in RULES:
        match = re.search(rule["pattern"], b)
        if match:
            try:
                major = int(match.group(1))
                minor = int(match.group(2))
                if rule["check"](major, minor):
                    findings.append({
                        "severity": rule["severity"],
                        "description": rule["message"]
                    })
            except:
                pass

    return findings


##############################################
# WEAK PROTOCOL CHECKS
##############################################
WEAK_PROTOCOLS = {
    23: ("TELNET uses plaintext communication", "HIGH"),
    21: ("FTP transmits passwords in plaintext", "MEDIUM"),
    445: ("SMB exposed on internet is dangerous", "HIGH"),
    3389: ("RDP exposure increases brute force risk", "MEDIUM"),
}


##############################################
# SCAN A SINGLE PORT
##############################################
def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "state": "closed",
        "banner": "",
        "vulnerabilities": [],
    }

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            result["state"] = "open"
            banner = grab_banner(ip, port, s)
            if banner:
                result["banner"] = banner

            # Weak protocol warning
            if port in WEAK_PROTOCOLS:
                msg, sev = WEAK_PROTOCOLS[port]
                result["vulnerabilities"].append({
                    "severity": sev,
                    "description": msg,
                })

            # FTP anonymous login
            if port == 21:
                ftp_res = check_ftp_anonymous(ip)
                if ftp_res["supported"]:
                    result["banner"] = ftp_res["banner"]
                    if ftp_res["allowed"]:
                        result["vulnerabilities"].append({
                            "severity": "MEDIUM",
                            "description": "FTP allows anonymous login (unauthorized access risk)"
                        })

            # Offline CVE banner analysis
            result["vulnerabilities"].extend(analyze_banner_with_rules(banner))

    except:
        pass

    return result


##############################################
# SCAN ALL PORTS ON A HOST
##############################################
def scan_host(ip: str, ports: list[int], max_workers: int = 50) -> dict:
    host_result = {"ip": ip, "ports": []}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}

        for future in as_completed(future_to_port):
            res = future.result()
            if res["state"] == "open":
                host_result["ports"].append(res)

    return host_result


##############################################
# CIDR → IP LIST
##############################################
def expand_targets(target: str) -> list[str]:
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            ipaddress.ip_address(target)
            return [target]
    except:
        raise SystemExit(f"Invalid target: {target}")


##############################################
# HTML REPORT GENERATOR
##############################################
def generate_html(report: dict, path: str) -> None:
    html = [
        "<html><head><meta charset='utf-8'><title>Scan Report</title>",
        "<style>body{background:#0f172a;color:#e5e7eb;font-family:Arial;padding:20px;} "
        "h1,h2{color:#38bdf8;} table{width:100%;border-collapse:collapse;margin:20px 0;} "
        "td,th{border:1px solid #475569;padding:8px;} .sev-HIGH{color:#f87171;} "
        ".sev-MEDIUM{color:#fbbf24;} .sev-LOW{color:#94a3b8;} .sev-CRITICAL{color:#ef4444;}"
        "</style></head><body>"
    ]

    html.append(f"<h1>Python Vulnerability Scanner Report</h1>")
    html.append(f"<p>Generated: {report['metadata']['generated_at']}</p>")
    html.append(f"<p>Target: {report['metadata']['target']}</p>")

    for host in report["hosts"]:
        html.append(f"<h2>Host: {host['ip']}</h2>")
        if not host["ports"]:
            html.append("<p>No open ports.</p>")
            continue

        html.append("<table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Vulnerabilities</th></tr>")
        for p in host["ports"]:
            vulns = "<br>".join([
                f"<span class='sev-{v['severity']}'>{v['severity']}:</span> {v['description']}"
                for v in p["vulnerabilities"]
            ]) or "None"

            html.append(
                f"<tr>"
                f"<td>{p['port']}</td>"
                f"<td>{p['service']}</td>"
                f"<td><pre>{p['banner'].replace('<','&lt;')}</pre></td>"
                f"<td>{vulns}</td>"
                f"</tr>"
            )

        html.append("</table>")

    html.append("</body></html>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))


##############################################
# MAIN
##############################################
def main():
    parser = argparse.ArgumentParser(description="Python Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="IP or CIDR range")
    parser.add_argument("-p", "--ports", default="common", help="'common' or comma-separated ports")
    parser.add_argument("-o", "--output-prefix", default="report", help="Output filename prefix")
    parser.add_argument("--max-workers", type=int, default=100)

    args = parser.parse_args()

    # Parse ports
    if args.ports == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        ports = sorted({int(x.strip()) for x in args.ports.split(",")})

    # Target expansion
    targets = expand_targets(args.target)

    print(f"[+] Scanning {len(targets)} host(s)")
    print(f"[+] Ports: {ports}")

    hosts_results = []
    for ip in targets:
        print(f"\n[+] Scanning {ip}")
        host_result = scan_host(ip, ports, max_workers=args.max_workers)
        hosts_results.append(host_result)

        for p in host_result["ports"]:
            print(f"    - Port {p['port']} OPEN ({p['service']})")

    # Build report
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

    generate_html(report, html_path)

    print("\n[+] Scan complete!")
    print(f"[+] JSON: {json_path}")
    print(f"[+] HTML: {html_path}")


if __name__ == "__main__":
    main()
