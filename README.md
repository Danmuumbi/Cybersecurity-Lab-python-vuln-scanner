# Vulnerability Scanner - Cybersecurity Lab

Welcome! This project contains **Python-based network vulnerability scanners** designed to help you discover open ports and running services on devices within a network. It's simple to use, beginner-friendly, and intended for educational purposes or ethical hacking practice **within your own network**.

---

## **Files in this project**

- **scanner.py** – The main scanner script. Scans target IP addresses for common ports and identifies open services.
- **scanner1.py** – An enhanced version of the scanner with extra features like output options (HTML, JSON) and multithreading for faster scanning.

Other files/directories:  
- `requirements.txt` – Python packages required to run the scanners.  
- `scanner1_reports/` – Directory where you can organize scanned reports (optional).  
- `README.md` – This file.  
- `sample-output/` – Example reports for reference.  
- `screenshots/` – Optional screenshots to show results visually.

---

## **What is this scanner for?**

Think of your network devices like buildings:  

- **IP address** = building address  
- **Port** = a door in the building  
- **Service** = what the door leads to (like HTTP for websites, SSH for remote login)  

This scanner tells you **which doors are open** on your devices and what services are running, which helps:

- **Network troubleshooting** – find misconfigured devices  
- **Security testing** – see if any unwanted doors are open  
- **Learning and practice** – understand networking and port scanning  

⚠️ **Important:** Only scan networks and devices you own or have permission to scan. Unauthorized scanning is illegal.

---

## **Common ports scanned**

| Port | Service | Description |
|------|---------|------------|
| 21   | FTP     | File transfer |
| 22   | SSH     | Remote terminal access |
| 23   | Telnet  | Old unsecure remote access |
| 25   | SMTP    | Send email |
| 53   | DNS     | Domain name resolution |
| 80   | HTTP    | Web traffic (websites) |
| 110  | POP3    | Email retrieval |
| 143  | IMAP    | Email management |
| 443  | HTTPS   | Secure web traffic |
| 445  | SMB     | File sharing (Windows) |
| 3306 | MySQL   | Database server |
| 3389 | RDP     | Remote desktop |

> These are “well-known ports” that most services use. Scanning them helps identify running services.

---

## **Installation & Setup**

1. **Clone the repository**  

```bash
git clone <your-repo-url>
cd Cybersecurity-Lab-python-vuln-scanner
```


Create a Python virtual environment
```bash
python3 -m venv vulnscan-env
source vulnscan-env/bin/activate
```

pip install -r requirements.txt

How to Use
1. Using scanner.py

```bash
python3 scanner.py -t <target_IP_or_range>

```

Example:
```bash

```


This scans all devices in the network 192.168.1.0/24

Default ports scanned: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389

Optional arguments may include specifying ports or adjusting the number of threads (faster scanning).

2. Using scanner1.py

```bash
python3 scanner1.py -t <target_IP_or_range> [-p PORTS] [-o OUTPUT_PREFIX] [--max-workers MAX_WORKERS]

```
-t / --target → Required, specify target IP or subnet

-p / --ports → Optional, comma-separated ports to scan

-o / --output-prefix → Optional, prefix for saving output reports

--max-workers → Optional, number of parallel threads for faster scanning

Output formats include JSON and HTML, which can be saved in scanner1_reports/.

Recommended workflow

Run scanner1.py for faster scanning and report generation.

Check HTML reports visually. You can place a screenshot of results in screenshots/ for documentation.

Learn from open ports: identify services running, and check if any unnecessary ports are exposed.

Example: If port 22 (SSH) is open on a router, you may need to secure it with a strong password.

Optional images/screenshots

Network scan results – Put in screenshots/scan_results.png

HTML report example – Put in screenshots/report_example.png

Images help beginners understand what a real scan looks like.

Summary

This project teaches you:

What ports are and why they matter

How to scan devices in a network for open ports

How to interpret results and identify services

How to document reports in JSON/HTML for analysis

It’s perfect for beginners in cybersecurity, ethical hacking, and networking.

License

This project is for educational purposes only. Do not use it for unauthorized scanning.



