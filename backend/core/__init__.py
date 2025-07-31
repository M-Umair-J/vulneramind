import sys
import scanner.fast_scanner as fast_scanner
import scanner.service_scanner as service_scanner
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
            
            # perform detailed service detection with integrated CVE mapping
            enriched_results = service_scanner.service_scan(target, filtered_ports)
            print("\n=== Service Detection & CVE Mapping Results ===")
            
            # Display comprehensive results
            for item in enriched_results:
                port = item.get('port', 'Unknown')
                service = item.get('service', 'Unknown')
                product = item.get('product', 'Unknown')
                version = item.get('version', 'Unknown')
                confidence = item.get('confidence', 'Unknown')
                
                # CVE information from new mapper
                cves = item.get('cves', [])
                cve_summary = item.get('cve_summary', {})
                
                print(f"\nPort {port} ({item.get('protocol', 'Unknown')}):")
                print(f"  Service: {service}")
                print(f"  Product: {product}")
                print(f"  Version: {version}")
                print(f"  Confidence: {confidence}")
                
                if cves:
                    print(f"  CVEs Found: {len(cves)}")
                    print(f"  Highest Severity: {cve_summary.get('highest_severity', 'Unknown')}")
                    print(f"  Average CVSS Score: {cve_summary.get('average_score', 0):.1f}")
                    
                    # Show top 3 CVEs
                    for i, cve in enumerate(cves[:3]):
                        print(f"    {i+1}. {cve['id']} - {cve['severity']} (Score: {cve['score']})")
                        print(f"       {cve['description'][:80]}...")
                else:
                    print("  CVEs: None found")
            
            # run exploitation module with classification
            from exploit.exploitation import exploit_services, present_exploit_summary
            if not enriched_results:
                print("! No services found to exploit.")
            else:
                print("\n-> Starting exploitation...")
                exploit_results = exploit_services(enriched_results)  # Update with exploits
                print("-> Exploitation completed.")
                
                # Present exploit summary and get user choice
                execution_choice = present_exploit_summary(enriched_results)
                
                if execution_choice == "1":
                    print("\n🚀 Running Smart Auto Exploitation...")
                    from exploit.exploitation import smart_auto_execution
                    successful_exploits = smart_auto_execution(enriched_results, target)
                elif execution_choice == "2":
                    print("\n🎯 Manual Selection Mode...")
                    from exploit.exploitation import manual_selection_execution
                    successful_exploits = manual_selection_execution(enriched_results, target)
                elif execution_choice == "3":
                    print("\n💥 RCE Only Mode...")
                    from exploit.exploitation import rce_only_execution
                    successful_exploits = rce_only_execution(enriched_results, target)
                elif execution_choice == "4":
                    print("\n⏭️ Skipping exploitation.")
                    successful_exploits = []
                else:
                    print("\n❌ Invalid choice. Skipping exploitation.")
                    successful_exploits = []
            
            # run exploits dynamically with smart filtering (legacy)
            print("\n-> Running exploits with smart exploit runner...")
            from exploit.smart_exploit_runner import run_exploits_smart
            successful_exploits = run_exploits_smart(enriched_results, target)
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
    except Exception as e:
        print(f"Error during scanning: {e}")
        print("Invalid input. Please enter a valid number.")
