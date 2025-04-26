from urllib.parse import urlparse
import subprocess
import datetime
import socket
def clean_hostname(url):
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        else:
            return parsed.path
    except:
        return url

def run_nmap_scan(target_url):
    try:
        host = clean_hostname(target_url)
        socket.gethostbyname(host)  # To validate the host
        command = ["nmap", "-Pn", "-T4", "-F", host]
        result = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
        ports = []
        for line in result.split('\n'):
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                     ports.append({
                        "port": parts[0].split("/")[0],
                        "protocol": parts[0].split("/")[1],
                        "state": parts[1]
                        })
        return {
             "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "host": host,
             "hostname": target_url,
             "state": "Scanned",
             "ports": ports
               }
    except Exception as e:
        return {"error": str(e)}