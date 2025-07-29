import sys
import scanner.fast_scanner as fast_scanner
import scanner.service_scanner as service_scanner
from scanner.cve_mapper_cpe import map_services_to_cves
# import exploit.smart_exploit_runner as exploit_runner
import scanner.host_discovery as host_discovery

# target machine IP or subnet
if len(sys.argv) > 1:
    target_input = sys.argv[1]
else:
    target_input = "192.168.56.102"  # default target (my kali machine for current testing)

# Discover live hosts (works for both single IP and subnet)
live_hosts = host_discovery.discover_live_hosts(target_input)
print(f"\n-> Live hosts discovered: {live_hosts}")
if not live_hosts:
    print("No live hosts found in the given range/subnet.")
    sys.exit(0)

scanned_hosts = set()
ports = '1-1000'

while True:
    print("\nSelect a host to scan:")
    for idx, host in enumerate(live_hosts, 1):
        mark = "*" if host in scanned_hosts else ""
        print(f"  {idx}. {host} {mark}")
    print("  0. Cancel/Exit")
    selection = input("Enter the number of the host to scan (or 0 to exit): ").strip()
    if selection == '0':
        print("Exiting host scanning loop.")
        break
    try:
        idx = int(selection) - 1
        if 0 <= idx < len(live_hosts):
            target = live_hosts[idx]
            print(f"\n=== Scanning host: {target} ===")
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
            scanned_hosts.add(target)
        else:
            print("Invalid selection. Please try again.")
    except Exception:
        print("Invalid input. Please enter a valid number.")
