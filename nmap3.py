import os
import sys
import subprocess
import json
import socket

def parse_nmap_output(output):
    info = {
        "General": [],
        "Ports": [],
        "OS Info": [],
        "Network Distance": "",
        "Service Info": []
    }

    lines = output.splitlines()
    for line in lines:
        if "Nmap scan report for" in line:
            info["General"].append(line.strip())
        elif 'open' in line and '/' in line:
            parts = line.split()
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else "unknown version"
            port_info = {
                "port": parts[0].split('/')[0],
                "state": parts[1],
                "service": service,
                "description": version
            }
            info["Ports"].append(port_info)
        elif "MAC Address:" in line:
            info["General"].append(line.strip())
        elif "Device type:" in line or "Running:" in line:
            info["OS Info"].append(line.strip())
        elif "Network Distance:" in line:
            info["Network Distance"] = line.split(":")[1].strip()
        elif "Service Info:" in line:
            info["Service Info"].append(line.split(":", 1)[1].strip())

    return info

def save_results_to_file(info):
    with open('nmap_results2.json', 'w') as file:
        json.dump(info, file, indent=2)

def is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False

def run_scan(target_ip):
    if not os.geteuid() == 0:
        print("This script must be run as root.")
        sys.exit(1)

    ipv6 = is_ipv6(target_ip)
    command = ["nmap", "-sV", "-O", "--script=default"]
    if ipv6:
        command.append("-6")
    command.append(target_ip)

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        parsed_info = parse_nmap_output(result.stdout)
        save_results_to_file(parsed_info)
        print("Nmap scan completed and results are saved in 'nmap_results2.json'.")
    except subprocess.CalledProcessError as e:
        print("Error executing Nmap:", e.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: nmap3.py <target_ip>")
        sys.exit(1)
    run_scan(sys.argv[1])
