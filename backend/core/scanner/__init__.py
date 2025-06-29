# import json

if __name__ == "__main__":
    import fast_scanner, service_scanner
    target = '192.168.56.101' # test target virutal machine on local device replace it with actual target
    ports = '1-65535'  # scanning ports 1-65535
    results = fast_scanner.port_scan(target, ports)
    # print(json.dumps(results, indent=2))  # print the raw scan results for debugging
    filtered_ports = fast_scanner.extract_open_ports_and_protocols(results, target)
    enriched_results = service_scanner.service_scan(target, filtered_ports)
    print("Open Ports and Services:")
    for item in enriched_results:
        print(f"Port: {item['port']}, Protocol: {item['protocol']}, Service: {item['service']}, Product: {item['product']}, Version: {item['version']}")
    