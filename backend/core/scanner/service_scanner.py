from nmap import PortScanner

def service_scan(target, open_ports):
    scanner = PortScanner()
    final_output = []

    # for tcp ports
    tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
    if tcp_ports:
        ports_str = ','.join(tcp_ports)
        print(f"[+] Running service detection on TCP ports: {ports_str}")
        scan_result = scanner.scan(target, ports_str, arguments='-sV -Pn -T4')
        if 'scan' in scan_result and target in scan_result['scan']:
            tcp_section = scan_result['scan'][target].get('tcp', {})
            for port, port_data in tcp_section.items():
                service = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                full_version = f"{product} {version}".strip() if product else version

                final_output.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': service,
                    'product': product,
                    'version': full_version
                })

    # udp ports do only if there are any
    udp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'udp']
    if udp_ports:
        ports_str = ','.join(udp_ports)
        print(f"[+] Running UDP service detection on ports: {ports_str} (slow & limited)")
        scan_result = scanner.scan(target, ports_str, arguments='-sU -sV -Pn -T4')
        if 'scan' in scan_result and target in scan_result['scan']:
            udp_section = scan_result['scan'][target].get('udp', {})
            for port, port_data in udp_section.items():
                service = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                full_version = f"{product} {version}".strip() if product else version

                final_output.append({
                    'port': port,
                    'protocol': 'udp',
                    'service': service,
                    'product': product,
                    'version': full_version
                })

    return final_output
