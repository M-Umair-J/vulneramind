import sys
import os
import scanner.fast_scanner as fast_scanner
import scanner.service_scanner as service_scanner
import scanner.host_discovery as host_discovery
from logger import log_message

# Print banner
print("🛡️  VulneraMind Security Scanner")
print("=" * 50)
print("📋 Workflow: Input → Discover → Scan → Exploits → AI → Metasploit")
print("🔥 Using real CVE database with 88,820+ vulnerabilities")
print("💥 Using real ExploitDB with 50,000+ exploits")
print("=" * 50)

# Verify data sources
try:
    from scanner.cve_mapper_real import get_cve_mapper
    cve_mapper = get_cve_mapper()
    db_status = cve_mapper.get_database_status()
    log_message(f"📊 CVE Database: {db_status['status']} ({db_status.get('cve_count', 'unknown')} CVEs)")
except Exception as e:
    log_message(f"⚠️ CVE mapper issue: {e}")

try:
    import json
    from pathlib import Path
    exploitdb_path = Path('exploitdb.json')
    if exploitdb_path.exists():
        size_mb = exploitdb_path.stat().st_size / (1024 * 1024)
        log_message(f"💥 ExploitDB: File loaded ({size_mb:.1f}MB)")
    else:
        log_message("⚠️ ExploitDB: File not found")
except Exception as e:
    log_message(f"⚠️ ExploitDB check failed: {e}")

print("=" * 50)

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
                
                if execution_choice == "5":
                    print("\n⚡ Opening Metasploit terminal...")
                    
                    # Check if we're on Windows or Linux/WSL
                    import platform
                    import subprocess
                    system = platform.system().lower()
                    
                    if system == "windows":
                        try:
                            os.system("start cmd /k python e:\\vulneramind_on_cursor\\vulneramind\\backend\\core\\msf_rpc_terminal.py")
                            print("✅ Metasploit terminal opened in new window")
                        except Exception as e:
                            print(f"❌ Failed to open Windows terminal: {e}")
                    else:
                        # For Linux/WSL, try different approaches
                        terminal_opened = False
                        
                        # First try: Check which terminal is available
                        available_terminals = []
                        terminal_commands = [
                            ("gnome-terminal", "gnome-terminal -- python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                            ("xterm", "xterm -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                            ("konsole", "konsole -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                            ("terminator", "terminator -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                            ("x-terminal-emulator", "x-terminal-emulator -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py")
                        ]
                        
                        # Check which terminals are available
                        for term_name, term_cmd in terminal_commands:
                            try:
                                result = subprocess.run(["which", term_name], capture_output=True, text=True)
                                if result.returncode == 0:
                                    available_terminals.append((term_name, term_cmd))
                            except:
                                continue
                        
                        # Try to open with available terminals
                        for term_name, term_cmd in available_terminals:
                            try:
                                subprocess.Popen(term_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                print(f"✅ Metasploit terminal opened using {term_name}")
                                terminal_opened = True
                                break
                            except Exception as e:
                                print(f"❌ Failed to open {term_name}: {e}")
                                continue
                        
                        if not terminal_opened:
                            print("❌ Could not open terminal automatically.")
                            print("🔧 No suitable terminal emulator found.")
                            print("📋 Please run manually in a new terminal:")
                            print("   cd /mnt/e/vulneramind_on_cursor/vulneramind/backend/core")
                            print("   python3 msf_rpc_terminal.py")
                            print("\n💡 Or install a terminal emulator:")
                            print("   sudo apt install gnome-terminal")
                            choice = input("\nPress Enter to continue or 'q' to quit: ")
                            if choice.lower() == 'q':
                                sys.exit(0)
                    
                    # Generate AI suggestions for all found exploits
                    print("\n🤖 Generating AI Metasploit Suggestions...")
                    print("=" * 60)
                    
                    try:
                        # Import the AI module  
                        from find_metasploit_exploit import find_metasploit_exploit
                        
                        # Collect all exploits from all services
                        all_exploits = []
                        for service in enriched_results:
                            exploits = service.get('exploits', [])
                            for exploit in exploits:
                                # Prepare exploit data for AI
                                exploit_data = {
                                    'host': target,
                                    'port': service.get('port'),
                                    'service': service.get('service'),
                                    'product': service.get('product', 'Unknown'),
                                    'version': service.get('version', 'Unknown'),
                                    'exploit_title': exploit.get('Title', ''),
                                    'exploit_description': exploit.get('Description', ''),
                                    'exploit_type': exploit.get('Type', ''),
                                    'exploit_platform': exploit.get('Platform', ''),
                                    'exploit_path': exploit.get('Path', ''),
                                    'cves': service.get('cves', [])
                                }
                                all_exploits.append((exploit, exploit_data))
                        
                        if all_exploits:
                            print(f"🎯 Processing {len(all_exploits)} exploits for AI analysis...\n")
                            
                            for i, (exploit, exploit_data) in enumerate(all_exploits, 1):
                                print(f"📋 [{i}/{len(all_exploits)}] {exploit.get('Title', 'Unknown Exploit')}")
                                print(f"🎯 Target: {exploit_data['host']}:{exploit_data['port']}")
                                print(f"📡 Service: {exploit_data['service']} ({exploit_data['product']} {exploit_data['version']})")
                                
                                # Get AI suggestion
                                ai_suggestion = find_metasploit_exploit(exploit_data)
                                
                                if 'error' in ai_suggestion:
                                    print(f"❌ AI Error: {ai_suggestion['error']}")
                                else:
                                    print(f"🔥 Suggested Module: {ai_suggestion.get('exploit_module', 'N/A')}")
                                    print(f"💾 Payload: {ai_suggestion.get('payload', 'N/A')}")
                                    
                                    # Show commands
                                    commands = ai_suggestion.get('commands', [])
                                    if commands:
                                        print("📝 Commands:")
                                        for cmd in commands:
                                            print(f"   {cmd}")
                                    
                                    # Show required options
                                    req_opts = ai_suggestion.get('required_options', {})
                                    if req_opts:
                                        print("⚙️ Required Options:")
                                        for opt, val in req_opts.items():
                                            print(f"   {opt} = {val}")
                                
                                print("-" * 50)
                        else:
                            print("❌ No exploits found to analyze")
                    
                    except ImportError as e:
                        print(f"❌ Could not import AI module: {e}")
                        print("💡 Make sure the find_metasploit_exploit module is available")
                    except Exception as e:
                        print(f"❌ Error generating AI suggestions: {e}")
                    
                    print("\n💡 Use the suggestions above in your Metasploit terminal")
                    print("💡 You can now use Metasploit commands to exploit the target")
                    continue  # Go back to host selection
                elif execution_choice == "1":
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
