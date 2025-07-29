import socket
import ssl
import json

# Common ports to service mapping (fallback, low confidence)
COMMON_PORTS = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    111: 'rpcbind',
    135: 'msrpc',
    139: 'netbios-ssn',
    143: 'imap',
    443: 'https',
    445: 'microsoft-ds',
    465: 'smtps',
    993: 'imaps',
    995: 'pop3s',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    8080: 'http-proxy',
    8443: 'https-alt',
    # Add more as needed
}

# Banner grabbing (generic TCP)
def grab_banner(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024)
                return banner.decode(errors='ignore').strip()
            except Exception:
                return ''
    except Exception:
        return ''

# HTTP probe
def probe_http(ip, port, timeout=2):
    try:
        import http.client
        conn = http.client.HTTPConnection(ip, int(port), timeout=timeout)
        conn.request('HEAD', '/')
        resp = conn.getresponse()
        server = resp.getheader('Server', '')
        return f"HTTP {resp.status} {resp.reason}; Server: {server}"
    except Exception:
        return ''

# HTTPS probe
def probe_https(ip, port, timeout=2):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return f"SSL Cert: {cert.get('subject', '')}"
    except Exception:
        return ''

# FTP probe
def probe_ftp(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            banner = sock.recv(1024)
            return banner.decode(errors='ignore').strip()
    except Exception:
        return ''

# SMTP probe
def probe_smtp(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            banner = sock.recv(1024)
            return banner.decode(errors='ignore').strip()
    except Exception:
        return ''

# Protocol-specific probe dispatcher
def protocol_probe(ip, port, service_guess=None, timeout=2):
    port = int(port)
    if service_guess is None:
        service_guess = COMMON_PORTS.get(port, None)
    if service_guess == 'http':
        return probe_http(ip, port, timeout)
    elif service_guess == 'https':
        return probe_https(ip, port, timeout)
    elif service_guess == 'ftp':
        return probe_ftp(ip, port, timeout)
    elif service_guess == 'smtp':
        return probe_smtp(ip, port, timeout)
    else:
        return grab_banner(ip, port, timeout)

# Fallback: Guess service from port
def guess_service_from_port(port):
    return COMMON_PORTS.get(int(port), 'unknown') 