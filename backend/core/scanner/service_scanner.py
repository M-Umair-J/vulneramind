# from nmap import PortScanner
# from . import utils
# from .cve_mapper import get_cve_mapper

# def service_scan(target, open_ports):
#     scanner = PortScanner()
#     cve_mapper = get_cve_mapper()
#     final_output = []
    
#     # running TCP scan on the open ports along with OS detection
#     tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
#     if tcp_ports:
#         ports_str = ','.join(tcp_ports)
#         print(f"-> Running service detection on TCP ports: {ports_str}")
#         # Use aggressive nmap scan for best detection
#         scan_result = scanner.scan(target, ports_str, arguments='-sV -A --version-intensity 5 --max-rtt-timeout 500ms')
#         if 'scan' in scan_result and target in scan_result['scan']:
#             target_data = scan_result['scan'][target]
#             # extract TCP service info
#             tcp_section = target_data.get('tcp', {})
#             for port, port_data in tcp_section.items():
#                 service = port_data.get('name', '')
#                 product = port_data.get('product', '')
#                 version = port_data.get('version', '')
#                 extrabanner = ''
#                 confidence = 'high' if service or product or version else 'medium'
#                 # If nmap is inconclusive, try protocol-specific probe
#                 if not (service or product or version):
#                     guessed = utils.guess_service_from_port(port)
#                     extrabanner = utils.protocol_probe(target, port, guessed)
#                     if extrabanner:
#                         confidence = 'medium'
#                     else:
#                         confidence = 'low'
#                     service = guessed
#                 # Always try to grab a banner for logging
#                 raw_banner = utils.grab_banner(target, port)
#                 print(f"Port {port}: service='{service}', product='{product}', version='{version}', banner='{raw_banner}', probe='{extrabanner}'")
                
#                 # Map service to CVEs
#                 cve_result = cve_mapper.map_service_to_cves(service, product, version)
#                 cves = cve_result['cves']
#                 cve_ids = cve_result.get('cve_ids', [])
#                 cve_summary = cve_result['cve_summary']
                
#                 print(f"  -> Found {len(cves)} CVEs (Highest: {cve_summary.get('by_severity', {}).get('HIGH', 0) + cve_summary.get('by_severity', {}).get('CRITICAL', 0)} high/critical, Avg Score: {cve_summary.get('avg_score', 0):.1f})")
                
#                 final_output.append({
#                     'port': port,
#                     'protocol': 'tcp',
#                     'service': service,
#                     'product': product,
#                     'version': version,
#                     'banner': raw_banner,
#                     'probe': extrabanner,
#                     'confidence': confidence,
#                     'cves': cves,
#                     'cve_ids': cve_ids,  # For exploitation modules
#                     'cve_summary': cve_summary
#                 })
#             # extract OS info if available
#             os_matches = target_data.get('osmatch', [])
#             if os_matches:
#                 os_name = os_matches[0].get('name', 'Unknown')
#                 os_cpe = ''
#                 if 'osclass' in os_matches[0] and os_matches[0]['osclass']:
#                     os_classes = os_matches[0]['osclass']
#                     for os_class in os_classes:
#                         cpe = os_class.get('cpe')
#                         if cpe:
#                             os_cpe = cpe[0]
#                             break
                
#                 # Map OS to CVEs
#                 os_cve_result = cve_mapper.map_service_to_cves('operating_system', os_name, '')
#                 os_cves = os_cve_result['cves']
#                 os_cve_summary = os_cve_result['cve_summary']
                
#                 print(f"OS: {os_name} -> Found {len(os_cves)} CVEs (High/Critical: {os_cve_summary.get('by_severity', {}).get('HIGH', 0) + os_cve_summary.get('by_severity', {}).get('CRITICAL', 0)})")
                
#                 final_output.append({
#                     'port': 'OS',
#                     'protocol': 'os',
#                     'service': os_name,
#                     'product': os_name,
#                     'version': '',
#                     'cpe': os_cpe,
#                     'confidence': 'high',
#                     'cves': os_cves,
#                     'cve_summary': os_cve_summary
#                 })
    
#     # running UDP scan for services on open ports
#     udp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'udp']
#     if udp_ports:
#         ports_str = ','.join(udp_ports)
#         print(f"-> Running UDP service detection on ports: {ports_str}")
#         scan_result = scanner.scan(target, ports_str, arguments='-sU -sV -A --version-intensity 5 --max-rtt-timeout 500ms')
#         if 'scan' in scan_result and target in scan_result['scan']:
#             udp_section = scan_result['scan'][target].get('udp', {})
#             for port, port_data in udp_section.items():
#                 service = port_data.get('name', '')
#                 product = port_data.get('product', '')
#                 version = port_data.get('version', '')
#                 extrabanner = ''
#                 confidence = 'high' if service or product or version else 'medium'
#                 if not (service or product or version):
#                     guessed = utils.guess_service_from_port(port)
#                     extrabanner = utils.protocol_probe(target, port, guessed)
#                     if extrabanner:
#                         confidence = 'medium'
#                     else:
#                         confidence = 'low'
#                     service = guessed
#                 raw_banner = utils.grab_banner(target, port)
#                 print(f"UDP Port {port}: service='{service}', product='{product}', version='{version}', banner='{raw_banner}', probe='{extrabanner}'")
                
#                 # Map service to CVEs
#                 cve_result = cve_mapper.map_service_to_cves(service, product, version)
#                 cves = cve_result['cves']
#                 cve_ids = cve_result.get('cve_ids', [])
#                 cve_summary = cve_result['cve_summary']
                
#                 print(f"  -> Found {len(cves)} CVEs (High/Critical: {cve_summary.get('by_severity', {}).get('HIGH', 0) + cve_summary.get('by_severity', {}).get('CRITICAL', 0)}, Avg Score: {cve_summary.get('avg_score', 0):.1f})")
                
#                 final_output.append({
#                     'port': port,
#                     'protocol': 'udp',
#                     'service': service,
#                     'product': product,
#                     'version': version,
#                     'banner': raw_banner,
#                     'probe': extrabanner,
#                     'confidence': confidence,
#                     'cves': cves,
#                     'cve_ids': cve_ids,  # For exploitation modules
#                     'cve_summary': cve_summary
#                 })
    
#     return final_output

from nmap import PortScanner
from . import utils
from .cve_mapper_real import get_cve_mapper  # ✅ Use real CVE mapper
from logger import log_message

def service_scan(target, open_ports):
    scanner = PortScanner()
    cve_mapper = get_cve_mapper()
    final_output = []
    
    # TCP ports
    tcp_ports = [str(p['port']) for p in open_ports if p['protocol'] == 'tcp']
    if tcp_ports:
        ports_str = ','.join(tcp_ports)
        log_message(f"-> Running service detection on TCP ports: {ports_str}")
        
        scan_result = scanner.scan(target, ports_str, arguments='-sV -A --version-intensity 5 --max-rtt-timeout 500ms')
        if 'scan' in scan_result and target in scan_result['scan']:
            tcp_section = scan_result['scan'][target].get('tcp', {})
            for port, port_data in tcp_section.items():
                service = port_data.get('name', '')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extrabanner = ''
                confidence = 'high' if service or product or version else 'medium'

                if not (service or product or version):
                    guessed = utils.guess_service_from_port(port)
                    extrabanner = utils.protocol_probe(target, port, guessed)
                    confidence = 'medium' if extrabanner else 'low'
                    service = guessed

                raw_banner = utils.grab_banner(target, port)
                log_message(f"Port {port}: service='{service}', product='{product}', version='{version}', banner='{raw_banner}', probe='{extrabanner}'")

                cve_result = cve_mapper.map_service_to_cves(service, product, version)
                cves = cve_result['cves']
                cve_ids = cve_result.get('cve_ids', [])
                cve_summary = cve_result['cve_summary']

                log_message(f"  -> Found {len(cves)} CVEs (Highest: {cve_summary.get('by_severity', {}).get('HIGH', 0) + cve_summary.get('by_severity', {}).get('CRITICAL', 0)} high/critical, Avg Score: {cve_summary.get('avg_score', 0):.1f})")

                final_output.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': service,
                    'product': product,
                    'version': version,
                    'banner': raw_banner,
                    'probe': extrabanner,
                    'confidence': confidence,
                    'cves': cves,
                    'cve_ids': cve_ids,
                    'cve_summary': cve_summary
                })

            # OS detection
            os_matches = scan_result['scan'][target].get('osmatch', [])
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

                os_cve_result = cve_mapper.map_service_to_cves('operating_system', os_name, '')
                os_cves = os_cve_result['cves']
                os_cve_summary = os_cve_result['cve_summary']

                log_message(f"OS: {os_name} -> Found {len(os_cves)} CVEs (High/Critical: {os_cve_summary.get('by_severity', {}).get('HIGH', 0) + os_cve_summary.get('by_severity', {}).get('CRITICAL', 0)})")

                final_output.append({
                    'port': 'OS',
                    'protocol': 'os',
                    'service': os_name,
                    'product': os_name,
                    'version': '',
                    'cpe': os_cpe,
                    'confidence': 'high',
                    'cves': os_cves,
                    'cve_summary': os_cve_summary
                })

    # UDP scan (if needed) — same pattern, can be added similarly if desired

    return final_output
