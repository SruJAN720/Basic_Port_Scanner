import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
target = "localhost"
ports = [80, 21, 22, 23, 443, 3389, 445, 8080, 8443, 8000, 8888, 5900, 2222, 3306, 5432, 1433, 27017, 6379, 139, 2049, 25, 110, 143, 587, 2375, 3000]
port_vulnerabilities = {
    21: {
        "description": "FTP - Insecure if not encrypted or misconfigured",
        "severity": "Medium",
        "fix": "Disable FTP or use SFTP/FTPS. Disable anonymous login."
    },
    22: {
        "description": "SSH - Secure remote access",
        "severity": "Medium",
        "fix": "Use key-based authentication. Disable root login."
    },
    23: {
        "description": "Telnet - Insecure remote access",
        "severity": "High",
        "fix": "Disable Telnet. Replace with SSH."
    },
    25: {
        "description": "SMTP - Mail server, open relay risk",
        "severity": "Medium",
        "fix": "Disable open relay. Require authentication."
    },
    80: {
        "description": "HTTP - Unencrypted web traffic",
        "severity": "Medium",
        "fix": "Redirect to HTTPS. Disable directory listing."
    },
    110: {
        "description": "POP3 - Mail retrieval",
        "severity": "Low",
        "fix": "Use POP3S (port 995). Enforce authentication."
    },
    139: {
        "description": "NetBIOS - Windows file sharing",
        "severity": "High",
        "fix": "Restrict to internal network only."
    },
    143: {
        "description": "IMAP - Mail retrieval",
        "severity": "Low",
        "fix": "Use IMAPS (port 993)."
    },
    443: {
        "description": "HTTPS - Encrypted web traffic",
        "severity": "Low",
        "fix": "Use strong TLS configuration."
    },
    445: {
        "description": "SMB - Server Message Block",
        "severity": "High",
        "fix": "Block from internet. Patch system regularly."
    },
    587: {
        "description": "SMTP Submission",
        "severity": "Low",
        "fix": "Require authentication and TLS."
    },
    3306: {
        "description": "MySQL - Database service",
        "severity": "High",
        "fix": "Bind to localhost. Require strong passwords."
    },
    3389: {
        "description": "RDP - Remote Desktop Protocol",
        "severity": "High",
        "fix": "Restrict via firewall/VPN. Enable NLA."
    },
    5432: {
        "description": "PostgreSQL - Database service",
        "severity": "High",
        "fix": "Restrict to internal network."
    },
    5900: {
        "description": "VNC - Remote desktop",
        "severity": "High",
        "fix": "Require password. Restrict to VPN."
    },
    6379: {
        "description": "Redis - Often exposed without authentication",
        "severity": "High",
        "fix": "Enable authentication. Bind to localhost."
    },
    8080: {
        "description": "HTTP-Alt - Dev/Admin panels",
        "severity": "Medium",
        "fix": "Enable authentication and restrict access."
    },
    8443: {
        "description": "HTTPS-Alt",
        "severity": "Low",
        "fix": "Ensure strong TLS configuration."
    },
    8888: {
        "description": "Jupyter Notebook",
        "severity": "High",
        "fix": "Enable token/password authentication."
    },
    27017: {
        "description": "MongoDB - Often misconfigured",
        "severity": "High",
        "fix": "Enable authentication. Disable public access."
    },
    2375: {
        "description": "Docker Remote API",
        "severity": "Critical",
        "fix": "Disable remote API or secure with TLS."
    },
    3000: {
        "description": "Node/React Dev Server",
        "severity": "Medium",
        "fix": "Restrict access. Do not expose publicly."
    }
}

def scan_port(port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((target, port))
    if result == 0:
        return port
    sock.close()
    return None

print("Scanning"+target+"for open ports...")
start_time = datetime.now()
with ThreadPoolExecutor(max_workers=50) as executor:
    open_ports = list(executor.map(scan_port, ports))
    open_ports = [port for port in open_ports if port is not None]
end_time = datetime.now()
with open("network_report.txt","w") as file:
    file.write(f"Scan report for {target}\n")
    file.write(f"Scan started at: {start_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}\n")
    file.write(f"Scan completed at: {end_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}\n")
    file.write(f"Total scan duration: {end_time - start_time}\n\n")
    for port in open_ports:
        info = port_vulnerabilities.get(port)
        if info:
            file.write(f"Port {port}\n")
            file.write(f"  Description: {info['description']}\n")
            file.write(f"  Severity: {info['severity']}\n")
            file.write(f"  Recommended Fix: {info['fix']}\n\n")
        else:
            file.write(f"Port {port} - No specific vulnerability information available.\n\n")
    if(not open_ports):
        file.write("No open ports found.\n")

print("Report generated as network_report.txt")
