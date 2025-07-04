# cve_mapper.py
import requests
import difflib

BASE_URL = "https://cve.circl.lu/api/search"

# Initial mappings — extend this over time
PRODUCT_MAPPING = {
    "apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "microsoft iis": ("microsoft", "iis"),
    "proftpd": ("proftpd", "proftpd"),
    "ftp": ("unknown", "ftp_server"),
    "samba": ("samba", "samba"),
    "openvpn": ("openvpn", "openvpn"),
    "php": ("php", "php"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "exim": ("exim", "exim"),
    "lighttpd": ("lighttpd", "lighttpd")
}

def get_closest_match(product_name):
    """
    Use fuzzy matching to find the closest product name from the mapping.
    """
    candidates = list(PRODUCT_MAPPING.keys())
    match = difflib.get_close_matches(product_name.lower(), candidates, n=1, cutoff=0.6)
    if match:
        return PRODUCT_MAPPING[match[0]]
    return None, None

def query_cve_api(product_raw, version):
    """
    Query CVE API using mapped or fuzzy-matched vendor/product.
    """
    normalized = product_raw.lower().strip()
    vendor, product = PRODUCT_MAPPING.get(normalized, (None, None))

    if not vendor:
        vendor, product = get_closest_match(normalized)

    if not vendor:
        print(f"[!] No mapping found for product: '{product_raw}'")
        with open("unmapped_products.log", "a") as f:
            f.write(f"{product_raw}\n")
        return []

    url = f"{BASE_URL}/{vendor}/{product}"
    print(f"[*] Querying: {url}")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []

            for item in data.get("data", []):
                # Optional: Match version in summary
                if version.lower() in item.get("summary", "").lower():
                    vulnerabilities.append({
                        'id': item.get('id'),
                        'summary': item.get('summary'),
                        'cvss': item.get('cvss', 'N/A')
                    })

            return vulnerabilities
        else:
            print(f"[!] Failed to fetch data for {product} ({response.status_code})")
            return []
    except Exception as e:
        print(f"[!] Exception querying CVE API: {e}")
        return []

def map_services_to_vulnerabilities(service_results):
    """
    Maps scanned services to vulnerabilities using product/version.
    """
    full_output = []
    for service in service_results:
        product = service['product']
        version = service['version']

        if product and version:
            cves = query_cve_api(product, version)
            service['vulnerabilities'] = cves
        else:
            service['vulnerabilities'] = []

        full_output.append(service)

    return full_output
