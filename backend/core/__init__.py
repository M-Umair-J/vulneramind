import sys
import scanner.fast_scanner as fast_scanner
import scanner.service_scanner as service_scanner
from scanner.cve_mapper_cpe import map_services_to_cves
# import exploit.smart_exploit_runner as exploit_runner

# target machine IP and port range
if len(sys.argv) > 1:
    target = sys.argv[1]
else:
    target = "192.168.56.102"  # default target (my kali machine for current testing)

# ports = '1-1024'  # expanded port range
ports = '1-1000'
# perform fast port scan
results = fast_scanner.port_scan(target, ports)

# extract open ports from scan results
filtered_ports = fast_scanner.extract_open_ports_and_protocols(results, target)

print(filtered_ports)
# perform detailed service detection (product/version)
enriched_results = service_scanner.service_scan(target, filtered_ports)
print(enriched_results)
# map services to CVEs using official CPE-based lookup
print("\n-> Mapping services to CVEs...")
cve_results = map_services_to_cves(enriched_results)
print(cve_results)
# display final CVE report
print("\n-> CVE Summary:")
for item in cve_results:
    cves = ", ".join(item["cves"]) if item["cves"] else "No CVEs found"
    cve_summary = f"Port: {item['port']}, Service: {item['service']}, Product: {item['product']}, Version: {item['version']} → CVEs: {cves}"
    print(f"Port: {item['port']}, Service: {item['service']}, Version: {item['version']} → CVEs: {cves}")

# run exploitation module
from exploit.exploitation import exploit_services
if not cve_results:
    print("! No CVEs found to exploit.")
else:
    print("\n-> Starting exploitation...")
    cve_results = exploit_services(cve_results)  # Update cve_results with exploits
    print("-> Exploitation completed.")

# run exploits dynamically with smart filtering
print("\n-> Running exploits with smart exploit runner...")
from exploit.smart_exploit_runner import run_exploits_smart
successful_exploits = run_exploits_smart(cve_results, target)
print("-> Smart exploit runner completed.")

# final summary
if successful_exploits:
    print(f"\n SUCCESS! Found {len(successful_exploits)} working exploits!")
    print("You can now:")
    print("1. Connect to opened backdoors")
    print("2. Use successful exploits for further penetration")
    print("3. Escalate privileges on compromised services")
else:
    print("\n No exploits succeeded on this target.")
    print("This could mean:")
    print("1. Target is well-patched and secure")
    print("2. Services are properly configured") 
    print("3. Network filtering is in place")
    print("4. Try testing on Metasploitable 2 for guaranteed results")
