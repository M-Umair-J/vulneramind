# _init_.py

import fast_scanner
import service_scanner
import cve_mapper

def main():
    target = '192.168.18.67'  # Replace with your target IP
    ports = '1-65535'  # Full port scan

    print(f"[+] Starting full port scan on {target}")
    scan_results = fast_scanner.port_scan(target, ports)

    open_ports = fast_scanner.extract_open_ports_and_protocols(scan_results, target)
    if not open_ports:
        print("[!] No open ports found.")
        return

    print(f"[+] Found {len(open_ports)} open ports. Running service detection...")
    service_info = service_scanner.service_scan(target, open_ports)

    print(f"[+] Mapping services to CVEs...")
    enriched_info = cve_mapper.map_services_to_vulnerabilities(service_info)

    print("\n========== Final Vulnerability Report ==========")
    for item in enriched_info:
        print(f"\n[Port {item['port']}/{item['protocol'].upper()}] {item['product']} {item['version']}")
        if item['vulnerabilities']:
            for vuln in item['vulnerabilities']:
                print(f"  - CVE: {vuln['id']} (CVSS: {vuln['cvss']})")
                print(f"    Summary: {vuln['summary']}")
        else:
            print("  - No known vulnerabilities found.")

    print("\n[+] Scan complete. Unmatched products (if any) are logged in 'unmapped_products.log'.")

if __name__ == "__main__":
    main()
