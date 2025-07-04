# from nmap import PortScanner

# def service_scan(target, open_ports):
#     scanner = PortScanner()
#     final_output = []

#     # for tcp ports
#     tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
#     if tcp_ports:
#         ports_str = ','.join(tcp_ports) # so that it can be passed to nmap
#         print(f"[+] Running service detection on TCP ports: {ports_str}")
#         scan_result = scanner.scan(target, ports_str, arguments='-sV -Pn -T4')
#         if 'scan' in scan_result and target in scan_result['scan']:
#             tcp_section = scan_result['scan'][target].get('tcp', {})
#             for port, port_data in tcp_section.items():
#                 service = port_data.get('name', '')
#                 product = port_data.get('product', '')
#                 version = port_data.get('version', '')
#                 full_version = f"{product} {version}".strip() if product else version

#                 final_output.append({
#                     'port': port,
#                     'protocol': 'tcp',
#                     'service': service,
#                     'product': product,
#                     'version': full_version
#                 })

#     # udp ports do only if there are any
#     udp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'udp']
#     # print(udp_ports)
#     if udp_ports:
#         ports_str = ','.join(udp_ports)
#         print(f"[+] Running UDP service detection on ports: {ports_str} (slow & limited)")
#         scan_result = scanner.scan(target, ports_str, arguments='-sU -sV -Pn -T4')

#         # import json
#         # print(json.dumps(scan_result, indent=2))

#         if 'scan' in scan_result and target in scan_result['scan']:
#             udp_section = scan_result['scan'][target].get('udp', {})
#             for port, port_data in udp_section.items():
#                 service = port_data.get('name', '')
#                 product = port_data.get('product', '')
#                 version = port_data.get('version', '')
#                 full_version = f"{product} {version}".strip() if product else version

#                 final_output.append({
#                     'port': port,
#                     'protocol': 'udp',
#                     'service': service,
#                     'product': product,
#                     'version': full_version
#                 })

#     return final_output

from nmap import PortScanner

def service_scan(target, open_ports):
    scanner = PortScanner()
    final_output = []

    # ========== TCP Scan with OS Detection ==========
    tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
    if tcp_ports:
        ports_str = ','.join(tcp_ports)
        print(f"[+] Running service detection on TCP ports: {ports_str}")

        scan_result = scanner.scan(target, ports_str, arguments='-sV -O -Pn -T4')  # -O for OS fingerprinting

        if 'scan' in scan_result and target in scan_result['scan']:
            target_data = scan_result['scan'][target]

            # Extract TCP service info
            tcp_section = target_data.get('tcp', {})
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

            # Extract OS info if available
            os_matches = target_data.get('osmatch', [])

            # ✅ Logging OS fingerprinting status
            if os_matches:
                os_name = os_matches[0].get('name', 'Unknown')
                print(f"[+] OS fingerprinting successful: {os_name}")
            else:
                print("[!] OS fingerprinting failed or inconclusive.")

            if os_matches:
                best_guess = os_matches[0]
                os_name = best_guess.get('name', '')
                os_cpe = ''
                if 'osclass' in best_guess and best_guess['osclass']:
                    os_classes = best_guess['osclass']
                    for os_class in os_classes:
                        cpe = os_class.get('cpe')
                        if cpe:
                            os_cpe = cpe[0]  # Pick the first matching CPE
                            break

                # Inject OS info as a special entry (pseudo port = "OS")
                final_output.append({
                    'port': 'OS',
                    'protocol': 'os',
                    'service': os_name,
                    'product': os_name,
                    'version': '',
                    'cpe': os_cpe
                })

    # ========== UDP Scan ==========
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

