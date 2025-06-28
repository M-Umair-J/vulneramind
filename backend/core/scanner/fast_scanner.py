import nmap
import os
import platform
def check_if_user_is_root_or_admin():
    if platform.system() == 'Windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() # check if the user is an admin on windows
    else:
        return os.geteuid() == 0
    
def port_scan(target, ports = '1-1024'):# default ports 1-1024 will be scanned if no ports are specified
    scanner = nmap.PortScanner()
    results = {'target': target, 'ports': []}

    if check_if_user_is_root_or_admin():
        tcp_scan = scanner.scan(target, ports,arguments = '-sS -T3 -Pn') # running a stealth tcp scan
        results['ports'].append({"type": "stealth_tcp", "result": tcp_scan})

        udp_scan = scanner.scan(target, ports, arguments = '-sU -T3 -Pn') # running a udp scan
        results['ports'].append({"type": "udp", "result": udp_scan})
    else:
        tcp_scan = scanner.scan(target, ports, arguments = '-sT -T3 -Pn') # running a tcp connect scan
        results['ports'].append({"type": "tcp_connect", "result": tcp_scan})
    return results

# def extract_open_ports_and_protocols(scan_result, target): # parsing for clean output
#     open_ports = []
#     for proto in ['tcp', 'udp', 'ip']:
#         if 'scan' in scan_result and target in scan_result['scan']:
#             proto_section = scan_result['scan'][target].get(proto, {})
#             for port, port_data in proto_section.items():
#                 if port_data.get('state') == 'open':
#                     open_ports.append({'port': port, 'protocol': proto})
#     return open_ports


def extract_open_ports_and_protocols(results, target):
    open_ports = []
    for scan in results['ports']:
        scan_result = scan['result']
        scan_type = scan['type']

        if scan_type in ['stealth_tcp', 'tcp_connect']:
            proto = 'tcp'
        elif scan_type == 'udp':
            proto = 'udp'
        else:
            continue

        if 'scan' in scan_result and target in scan_result['scan']:
            proto_section = scan_result['scan'][target].get(proto, {})
            for port, port_data in proto_section.items():
                if port_data.get('state') == 'open':
                    open_ports.append({'port': port, 'protocol': proto})
    return open_ports
