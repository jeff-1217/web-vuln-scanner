from urllib.parse import urlparse
import subprocess
import datetime
import socket
import json
import re

def clean_hostname(url):
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        else:
            return parsed.path
    except:
        return url

def run_nmap_scan(target_url, scan_type="basic"):
    """
    Enhanced nmap scanner with multiple scan types
    scan_type options: basic, comprehensive, vuln, stealth
    """
    try:
        host = clean_hostname(target_url)
        socket.gethostbyname(host)  # To validate the host
        
        # Define scan profiles
        scan_profiles = {
            "basic": ["nmap", "-Pn", "-T4", "-F", host],
            "comprehensive": ["nmap", "-Pn", "-T4", "-sS", "-sV", "-O", "--version-intensity", "5", host],
            "vuln": ["nmap", "-Pn", "-T4", "-sV", "--script=vuln", host],
            "stealth": ["nmap", "-Pn", "-T2", "-sS", "-f", "--mtu", "16", host],
            "full": ["nmap", "-Pn", "-T4", "-sS", "-sV", "-O", "-A", "--script=vuln", host]
        }
        
        command = scan_profiles.get(scan_type, scan_profiles["basic"])
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=300).decode()
        
        # Parse results
        ports = []
        services = []
        os_info = "Unknown"
        vulnerabilities = []
        
        lines = result.split('\n')
        for line in lines:
            # Parse port information
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0].split("/")[0],
                        "protocol": parts[0].split("/")[1],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    ports.append(port_info)
                    
                    # Extract service information
                    if len(parts) > 3:
                        service_info = " ".join(parts[3:])
                        if service_info and service_info != "unknown":
                            services.append({
                                "port": port_info["port"],
                                "service": service_info
                            })
            
            # Parse OS information
            if "OS details:" in line:
                os_info = line.split("OS details:")[1].strip()
            elif "Running:" in line:
                os_info = line.split("Running:")[1].strip()
            
            # Parse vulnerability information
            if "VULNERABLE:" in line:
                vuln_info = line.split("VULNERABLE:")[1].strip()
                vulnerabilities.append(vuln_info)
        
        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "hostname": target_url,
            "scan_type": scan_type,
            "state": "Scanned",
            "ports": ports,
            "services": services,
            "os_info": os_info,
            "vulnerabilities": vulnerabilities,
            "total_ports": len(ports),
            "open_ports": len([p for p in ports if p["state"] == "open"]),
            "raw_output": result
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 5 minutes"}
    except Exception as e:
        return {"error": str(e)}

def run_quick_scan(target_url):
    """Quick scan for basic port information"""
    return run_nmap_scan(target_url, "basic")

def run_comprehensive_scan(target_url):
    """Comprehensive scan with service and OS detection"""
    return run_nmap_scan(target_url, "comprehensive")

def run_vulnerability_scan(target_url):
    """Vulnerability-focused scan using nmap scripts"""
    return run_nmap_scan(target_url, "vuln")

def run_stealth_scan(target_url):
    """Stealth scan to avoid detection"""
    return run_nmap_scan(target_url, "stealth")

def run_full_scan(target_url):
    """Full scan with all options enabled"""
    return run_nmap_scan(target_url, "full")