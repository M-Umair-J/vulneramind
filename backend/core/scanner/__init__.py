# __init__.py

import fast_scanner
import service_scanner
from cve_mapper_cpe import map_services_to_cves

# Target machine IP and port range
target = "192.168.18.67"
ports = '1-65535'

# Step 1: Perform fast port scan
results = fast_scanner.port_scan(target, ports)

# Step 2: Extract open ports from scan results
filtered_ports = fast_scanner.extract_open_ports_and_protocols(results, target)

# Step 3: Perform detailed service detection (product/version)
enriched_results = service_scanner.service_scan(target, filtered_ports)

# Step 4: Map services to CVEs using official CPE-based lookup
print("\n[+] Mapping services to CVEs...")
cve_results = map_services_to_cves(enriched_results)

# Step 5: Display final CVE report
print("\n[+] CVE Summary:")
for item in cve_results:
    cves = ", ".join(item["cves"]) if item["cves"] else "No CVEs found"
    print(f"Port: {item['port']}, Service: {item['service']}, Version: {item['version']} → CVEs: {cves}")
