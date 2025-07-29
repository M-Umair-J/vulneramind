import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

def ping_host(ip):
    """Ping a single IP address. Returns True if host is alive, False otherwise."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Timeout param: Windows uses -w (ms), Linux uses -W (s)
    timeout = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    try:
        result = subprocess.run([
            'ping', param, '1', timeout, timeout_val, str(ip)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def discover_live_hosts(subnet, max_workers=100):
    """
    Given a subnet in CIDR notation (e.g., '192.168.1.0/24') or a single IP,
    returns a list of live hosts (as strings).
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        # If not a subnet, treat as single IP
        net = [ipaddress.ip_address(subnet)]
    hosts = list(net.hosts()) if hasattr(net, 'hosts') else net
    live_hosts = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as executor:
        results = list(executor.map(ping_host, hosts))
    for ip, alive in zip(hosts, results):
        if alive:
            live_hosts.append(str(ip))
    return live_hosts

# Optional: For better performance, install 'pythonping' and use it instead of subprocess
# pip install pythonping
# from pythonping import ping
# def ping_host(ip):
#     try:
#         response = ping(str(ip), count=1, timeout=1, verbose=False)
#         return response.success()
#     except Exception:
#         return False
