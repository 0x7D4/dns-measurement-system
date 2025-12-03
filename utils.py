import json
import socket
import subprocess
import platform
import requests
import os
import glob
from typing import List, Set
from datetime import datetime


def load_dns_servers(json_file: str) -> List[str]:
    """
    Load DNS server IPs from JSON file.
    Supports both formats:
    - New format: List of objects with "ip" field (*.json)
    - Old format: List of objects with "servers" array (recursive_servers_detailed.json)
    """
    with open(json_file, 'r') as f:
        data = json.load(f)

    dns_servers: List[str] = []

    # New format: List of objects with "ip" field directly
    if isinstance(data, list) and len(data) > 0 and "ip" in data[0]:
        for item in data:
            if "ip" in item and item["ip"]:
                ip = item["ip"].strip()
                if ip and ip not in dns_servers:
                    dns_servers.append(ip)
        print(f"Loaded {len(dns_servers)} IPs from new format (direct IP list)")

    # Old format: List of dicts with nested "servers" array
    elif isinstance(data, list):
        for item in data:
            if "servers" in item and isinstance(item["servers"], list):
                for server in item["servers"]:
                    if isinstance(server, str):
                        ip = server.strip()
                    elif isinstance(server, dict) and "ip" in server:
                        ip = server["ip"].strip()
                    else:
                        continue
                    if ip and ip not in dns_servers:
                        dns_servers.append(ip)
        print(f"Loaded {len(dns_servers)} IPs from old format (nested servers)")

    # Dict format
    elif isinstance(data, dict):
        if "servers" in data and isinstance(data["servers"], list):
            for server in data["servers"]:
                if isinstance(server, str):
                    ip = server.strip()
                elif isinstance(server, dict) and "ip" in server:
                    ip = server["ip"].strip()
                else:
                    continue
                if ip and ip not in dns_servers:
                    dns_servers.append(ip)
        print(f"Loaded {len(dns_servers)} IPs from dictionary format")

    if not dns_servers:
        raise ValueError(f"No DNS server IPs found in {json_file}")

    return dns_servers


def get_utc_timestamp() -> str:
    """Get current timestamp in UTC."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def get_system_dns_servers() -> Set[str]:
    """
    Detect system-configured DNS servers (cross-platform).
    Returns a set of DNS server IPs.
    """
    dns_servers: Set[str] = set()
    system = platform.system()

    try:
        if system == "Windows":
            # Windows: Use ipconfig /all
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                encoding="cp1252",  # Windows console encoding
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "DNS Servers" in line or "DNS-Server" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if ip and ip[0].isdigit() and validate_ip(ip):
                            dns_servers.add(ip)
                elif line and line[0].isdigit() and "." in line:
                    # Continuation line with just IP
                    ip = line.strip()
                    if validate_ip(ip):
                        dns_servers.add(ip)

        elif system == "Linux":
            # Linux: Check /etc/resolv.conf
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) == 2:
                                ip = parts[1]
                                if validate_ip(ip):
                                    dns_servers.add(ip)
            except FileNotFoundError:
                pass

        elif system == "Darwin":  # macOS
            # macOS: Use scutil --dns
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "nameserver" in line.lower():
                    parts = line.split()
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if validate_ip(ip):
                            dns_servers.add(ip)

    except Exception as e:
        print(f"Warning: could not detect system DNS servers: {e}")

    return dns_servers


def get_dhcp_server_ips() -> Set[str]:
    """
    Detect DHCP server IPs (typically router/gateway that leases addresses).
    
    Windows: Parse ipconfig /all and read the "DHCP Server" line.
    Linux: Best-effort parse of common dhclient/dhcpcd lease files and systemd-networkd lease files:
        - /var/lib/dhcp/dhclient*.leases
        - /var/lib/dhcpcd/*.lease
        - /run/systemd/netif/leases/*
    
    For dhclient-style leases, we look for: option dhcp-server-identifier <ip>;
    For systemd-networkd leases, we look for: SERVER_ADDRESS=<ip> or DHCP_SERVER_IDENTIFIER=<ip>
    
    Other OS: Returns an empty set by default.
    """
    servers: Set[str] = set()
    system = platform.system()

    try:
        if system == "Windows":
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                encoding="cp1252",
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("DHCP Server") or line.startswith("DHCP-Server"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if validate_ip(ip):
                            servers.add(ip)

        elif system == "Linux":
            # 1) dhclient-style leases
            lease_paths = []
            lease_paths.extend(glob.glob("/var/lib/dhcp/dhclient*.leases"))
            lease_paths.extend(glob.glob("/var/lib/dhcp3/dhclient*.leases"))
            lease_paths.extend(glob.glob("/var/lib/dhcpcd/*.lease"))

            for path in lease_paths:
                try:
                    with open(path, "r") as f:
                        # Keep last occurrence (latest lease in the file)
                        last_ip = None
                        for line in f:
                            line = line.strip()
                            if "dhcp-server-identifier" in line:
                                # e.g. "option dhcp-server-identifier 192.0.2.1;"
                                parts = line.replace(";", "").split()
                                if parts:
                                    candidate = parts[-1]  # last token should be IP
                                    if validate_ip(candidate):
                                        last_ip = candidate
                        if last_ip:
                            servers.add(last_ip)
                except (IOError, OSError):
                    continue

            # 2) systemd-networkd leases (/run/systemd/netif/leases/*)
            netif_dir = "/run/systemd/netif/leases"
            if os.path.isdir(netif_dir):
                for fname in os.listdir(netif_dir):
                    path = os.path.join(netif_dir, fname)
                    if not os.path.isfile(path):
                        continue
                    try:
                        with open(path, "r") as f:
                            dhcp_id_ip = None
                            server_addr_ip = None
                            for line in f:
                                line = line.strip()
                                if line.startswith("DHCP_SERVER_IDENTIFIER="):
                                    value = line.split("=", 1)[1].strip()
                                    if validate_ip(value):
                                        dhcp_id_ip = value
                                elif line.startswith("SERVER_ADDRESS="):
                                    value = line.split("=", 1)[1].strip()
                                    if validate_ip(value):
                                        server_addr_ip = value

                            # Prefer DHCP_SERVER_IDENTIFIER, fall back to SERVER_ADDRESS
                            if dhcp_id_ip:
                                servers.add(dhcp_id_ip)
                            elif server_addr_ip:
                                servers.add(server_addr_ip)
                    except (IOError, OSError):
                        continue

        # macOS, others: nothing for now, could be extended later

    except Exception as e:
        print(f"Warning: could not detect DHCP servers: {e}")

    return servers


def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (socket.error, ValueError):
        return False


def get_system_hostname() -> str:
    """Get system hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def get_public_ip() -> str:
    """Get public IP address."""
    try:
        response = requests.get("https://api.ipify.org?format=text", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass

    # Fallback method
    try:
        response = requests.get("https://ifconfig.me/ip", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass

    return None
