from nmap import PortScanner
from . import utils

def service_scan(target, open_ports):
    scanner = PortScanner()
    final_output = []
    # running TCP scan on the open ports along with OS detection
    tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
    if tcp_ports:
        ports_str = ','.join(tcp_ports)
        print(f"-> Running service detection on TCP ports: {ports_str}")
        # Use aggressive nmap scan for best detection
        scan_result = scanner.scan(target, ports_str, arguments='-sV -A --version-intensity 5 --max-rtt-timeout 500ms')
        if 'scan' in scan_result and target in scan_result['scan']:
            target_data = scan_result['scan'][target]
            # extract TCP service info
            tcp_section = target_data.get('tcp', {})
            for port, port_data in tcp_section.items():
                service = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extrabanner = ''
                confidence = 'high' if service or product or version else 'medium'
                # If nmap is inconclusive, try protocol-specific probe
                if not (service or product or version):
                    guessed = utils.guess_service_from_port(port)
                    extrabanner = utils.protocol_probe(target, port, guessed)
                    if extrabanner:
                        confidence = 'medium'
                    else:
                        confidence = 'low'
                    service = guessed
                # Always try to grab a banner for logging
                raw_banner = utils.grab_banner(target, port)
                print(f"Port {port}: service='{service}', product='{product}', version='{version}', banner='{raw_banner}', probe='{extrabanner}'")
                final_output.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': service,
                    'product': product,
                    'version': version,
                    'banner': raw_banner,
                    'probe': extrabanner,
                    'confidence': confidence
                })
            # extract OS info if available
            os_matches = target_data.get('osmatch', [])
            if os_matches:
                os_name = os_matches[0].get('name', 'Unknown')
                os_cpe = ''
                if 'osclass' in os_matches[0] and os_matches[0]['osclass']:
                    os_classes = os_matches[0]['osclass']
                    for os_class in os_classes:
                        cpe = os_class.get('cpe')
                        if cpe:
                            os_cpe = cpe[0]
                            break
                final_output.append({
                    'port': 'OS',
                    'protocol': 'os',
                    'service': os_name,
                    'product': os_name,
                    'version': '',
                    'cpe': os_cpe,
                    'confidence': 'high'
                })
    # running UDP scan for services on open ports
    udp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'udp']
    if udp_ports:
        ports_str = ','.join(udp_ports)
        print(f"-> Running UDP service detection on ports: {ports_str}")
        scan_result = scanner.scan(target, ports_str, arguments='-sU -sV -A --version-intensity 5 --max-rtt-timeout 500ms')
        if 'scan' in scan_result and target in scan_result['scan']:
            udp_section = scan_result['scan'][target].get('udp', {})
            for port, port_data in udp_section.items():
                service = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extrabanner = ''
                confidence = 'high' if service or product or version else 'medium'
                if not (service or product or version):
                    guessed = utils.guess_service_from_port(port)
                    extrabanner = utils.protocol_probe(target, port, guessed)
                    if extrabanner:
                        confidence = 'medium'
                    else:
                        confidence = 'low'
                    service = guessed
                raw_banner = utils.grab_banner(target, port)
                print(f"UDP Port {port}: service='{service}', product='{product}', version='{version}', banner='{raw_banner}', probe='{extrabanner}'")
                final_output.append({
                    'port': port,
                    'protocol': 'udp',
                    'service': service,
                    'product': product,
                    'version': version,
                    'banner': raw_banner,
                    'probe': extrabanner,
                    'confidence': confidence
                })
    return final_output