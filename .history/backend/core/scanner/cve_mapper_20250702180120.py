# cve_mapper.py
import requests
import difflib
import time

BASE_URL = "https://cve.circl.lu/api/search"

# Cache to avoid repeated API calls
_query_cache = {}

# Expanded product → vendor/product mapping
PRODUCT_MAPPING = {
    "apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "microsoft sql server 2022": ("microsoft", "sql_server"),
    "microsoft windows rpc": ("microsoft", "windows"),
    "microsoft httpapi httpd": ("microsoft", "windows"),
    "iis": ("microsoft", "iis"),
    "mongoose httpd": ("cesanta", "mongoose"),
    "mysql x protocol listener": ("oracle", "mysql"),
}

def normalize_product_name(product_raw):
    """
    Lowercase and clean up product name for mapping
    """
    name = product_raw.lower().strip()
    for word in ["db", "listener"]:
        name = name.replace(word, "")
    return name.strip()

def get_closest_match(product_name):
    """
    Fuzzy matching to get the best-matching product name from PRODUCT_MAPPING
    """
    candidates = list(PRODUCT_MAPPING.keys())
    match = difflib.get_close_matches(product_name, candidates, n=1, cutoff=0.6)
    if match:
        return PRODUCT_MAPPING[match[0]]
    return None, None

def query_cve_api(product_raw, version):
    """
    Given a product and version, query CVE API and return CVEs
    """
    # Caching
    cache_key = (product_raw.lower(), version.lower())
    if cache_key in _query_cache:
        return _query_cache[cache_key]

    normalized = normalize_product_name(product_raw)
    vendor, product = PRODUCT_MAPPING.get(normalized, (None, None))

    if not vendor:
        vendor, product = get_closest_match(normalized)

    if not vendor:
        print(f"[!] No mapping found for product: '{product_raw}'")
        with open("unmapped_products.log", "a") as f:
            f.write(f"{product_raw}\n")
        _query_cache[cache_key] = []
        return []

    url = f"{BASE_URL}/{vendor}/{product}"
    print(f"[*] Querying: {url}")

    # Retry logic
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []

                for item in data.get("data", []):
                    if version.lower() in item.get("summary", "").lower():
                        vulnerabilities.append({
                            'id': item.get('id'),
                            'summary': item.get('summary'),
                            'cvss': item.get('cvss', 'N/A')
                        })

                _query_cache[cache_key] = vulnerabilities
                return vulnerabilities
            else:
                print(f"[!] HTTP error ({response.status_code}) for {url}")
                break

        except requests.exceptions.RequestException as e:
            print(f"[!] Retry {attempt+1}/3 failed: {e}")
            time.sleep(2)

    _query_cache[cache_key] = []
    return []

def map_services_to_vulnerabilities(service_results):
    """
    Maps services to CVEs and returns enriched list
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
