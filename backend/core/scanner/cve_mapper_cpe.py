import requests
import time
import re

NVD_API_KEY = "0c7dff2c-8e3c-41df-8269-c829c06caec2"
CPE_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "apiKey": NVD_API_KEY,
    "User-Agent": "NVAS-CVE-Scanner"
}

PREFERRED_VENDORS = ["microsoft", "mysql", "oracle", "postgresql", "apache", "erlang-solutions", "mongodb", "vmware", "vsftpd"]

# Updated KNOWN_CPE with better mapping logic - we'll use patterns instead of exact matches
KNOWN_SERVICE_PATTERNS = {
    "vsftpd": {
        "vendor": "vsftpd",
        "product": "vsftpd",
        "common_versions": ["2.3.4", "3.0.2", "3.0.3", "2.2.2"]
    },
    "apache": {
        "vendor": "apache", 
        "product": "http_server",
        "common_versions": ["2.2.8", "2.4.1", "2.4.41"]
    },
    "mysql": {
        "vendor": "mysql",
        "product": "mysql", 
        "common_versions": ["5.7.0", "8.0.0"]
    }
}
def build_cpe_from_service(service, product, version):
    """Build a CPE string based on service detection results."""
    service_lower = service.lower()
    product_lower = product.lower()
    
    # Handle vsftpd specifically
    if "vsftpd" in service_lower or "vsftpd" in product_lower:
        if version:
            return f"cpe:2.3:a:vsftpd:vsftpd:{version}:*:*:*:*:*:*:*"
        else:
            # If no version, try common vulnerable versions
            return f"cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"
    
    # Handle Apache
    elif "apache" in service_lower or "apache" in product_lower or "httpd" in product_lower:
        if version:
            return f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"
        else:
            return f"cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"
    
    # Handle MySQL
    elif "mysql" in service_lower or "mysql" in product_lower:
        if version:
            return f"cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*"
        else:
            return f"cpe:2.3:a:mysql:mysql:5.7.0:*:*:*:*:*:*:*"
    
    return None

def extract_version_from_product(product):
    """Extract version number from product string."""
    if not product:
        return ""
    
    # Look for version patterns like "2.3.4", "1.0", etc.
    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', product)
    if version_match:
        return version_match.group(1)
    
    return ""

def clean_text(text):
    """Clean input string for better matching."""
    if not text:
        return ""
    text = re.sub(r"(?i)\b(db|httpd|protocol|listener|server|service|version)\b", "", text)
    text = re.sub(r"[^\w\s\-\.]", "", text)
    text = re.sub(r"\s+", " ", text.strip())
    return text.lower()

def try_cpe_search(keyword):
    """Query CPE API and return the most relevant cpeMatchString."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5
    }

    try:
        response = requests.get(CPE_SEARCH_URL, headers=HEADERS, params=params)
        if response.status_code != 200:
            print(f"[!] CPE API Error {response.status_code}: {response.text}")
            return None

        products = response.json().get("products", [])
        for p in products:
            cpe_obj = p["cpe"]
            cpe_name = cpe_obj.get("cpeName", "")
            vendor = cpe_name.split(":")[3] if ":" in cpe_name else ""
            if vendor in PREFERRED_VENDORS:
                return cpe_name
        return products[0]["cpe"]["cpeName"] if products else None

    except Exception as e:
        print(f"[!] Exception during CPE search: {e}")
        return None

# def get_cves_for_cpe(cpe_name):
#     try:
#         parts = cpe_name.split(":")
#         if len(parts) < 6:
#             return []

#         vendor = parts[3]
#         product = parts[4]
#         version = parts[5]

#         keyword = f"{vendor} {product}"
#         if version and version not in ["*", "-"]:
#             keyword += f" {version}"

#         params = {
#             "resultsPerPage": 100,
#             "startIndex": 0,
#             "keywordSearch": keyword
#         }

#         response = requests.get(CVE_SEARCH_URL, headers=HEADERS, params=params)
#         if response.status_code != 200:
#             print(f"[!] CVE API Error {response.status_code}: {response.text}")
#             return []

#         data = response.json()
#         vulnerabilities = data.get("vulnerabilities", [])
#         cve_ids = [vuln["cve"]["id"] for vuln in vulnerabilities]
#         return cve_ids

#     except Exception as e:
#         print(f"[!] Exception during CVE fetch: {e}")
#         return []

def get_cves_for_cpe(cpe_name):
    try:
        # Use keyword search with CPE components for better results
        parts = cpe_name.split(":")
        if len(parts) >= 6:
            vendor = parts[3]
            product = parts[4]
            version = parts[5]
            
            # First try exact CPE match
            params = {
                "resultsPerPage": 100,
                "startIndex": 0,
                "cpeName": cpe_name
            }

            response = requests.get(CVE_SEARCH_URL, headers=HEADERS, params=params)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_ids = [vuln["cve"]["id"] for vuln in vulnerabilities]
                    print(f"[+] Found {len(cve_ids)} CVEs using exact CPE match")
                    return cve_ids
            
            # If no exact match, try keyword search
            keyword = f"{vendor} {product}"
            if version and version not in ["*", "-"]:
                keyword += f" {version}"
            
            params = {
                "resultsPerPage": 100,
                "startIndex": 0,
                "keywordSearch": keyword
            }

            response = requests.get(CVE_SEARCH_URL, headers=HEADERS, params=params)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                cve_ids = [vuln["cve"]["id"] for vuln in vulnerabilities]
                print(f"[+] Found {len(cve_ids)} CVEs using keyword search: {keyword}")
                return cve_ids
            else:
                print(f"[!] CVE API Error {response.status_code}: {response.text}")
        
        return []

    except Exception as e:
        print(f"[!] Exception during CVE fetch: {e}")
        return []


def map_services_to_cves(enriched_results):
    final_output = []

    for entry in enriched_results:
        port = entry.get("port")
        service = entry.get("service", "")
        product = entry.get("product", "")
        version = entry.get("version", "")
        explicit_cpe = entry.get("cpe", None)

        print(f"\n[DEBUG] Processing port {port}:")
        print(f"  Service: '{service}'")
        print(f"  Product: '{product}'")
        print(f"  Version: '{version}'")
        print(f"  Explicit CPE: {explicit_cpe}")

        # Skip portless entries (if malformed)
        if port is None:
            continue

        # cpe_name = None
        # if explicit_cpe:
        #     # Use the provided CPE (like from OS fingerprinting)
        #     cpe_name = explicit_cpe
        #     print(f"[*] Using provided CPE for port {port}: {cpe_name}")
        # else:
        #     # Generate CPE search queries from fields
        #     queries = list(dict.fromkeys(filter(None, [
        #     clean_text(f"{product} {version}"),
        #     clean_text(f"{service} {version}"),
        #     clean_text(product),
        #     clean_text(service)
        # ])))

        #     for q in queries:
        #         print(f"[*] Searching CPE for: {q} on port {port}...")
        #         cpe_name = try_cpe_search(q)
        #         if cpe_name:
        #             break
        cpe_name = None

        # First, check for explicit CPE (from OS scan)
        if explicit_cpe:
            cpe_name = explicit_cpe
            print(f"[*] Using provided CPE for port {port}: {cpe_name}")

        # Try to build CPE from service/product detection
        else:
            # Extract version if it's embedded in product string
            extracted_version = extract_version_from_product(product) if not version else version
            print(f"  Extracted version: '{extracted_version}'")
            
            # Try to build CPE using known patterns
            cpe_name = build_cpe_from_service(service, product, extracted_version)
            
            if cpe_name:
                print(f"[*] Built CPE for {service}/{product} on port {port}: {cpe_name}")
            else:
                # Fallback to dynamic CPE search
                queries = list(dict.fromkeys(filter(None, [
                    clean_text(f"{product} {extracted_version}"),
                    clean_text(f"{service} {extracted_version}"),
                    clean_text(product),
                    clean_text(service)
                ])))

                print(f"  Fallback queries: {queries}")
                for q in queries:
                    print(f"[*] Searching CPE for: {q} on port {port}...")
                    cpe_name = try_cpe_search(q)
                    if cpe_name:
                        break

        # Fetch CVEs for valid CPE
        if cpe_name:
            print(f"[+] Found CPE: {cpe_name} → Fetching CVEs...")
            cves = get_cves_for_cpe(cpe_name)
        else:
            print(f"[!] No valid CPE found for port {port}")
            cves = []

        final_output.append({
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "cves": cves
        })

        time.sleep(1.6)  # NVD API rate limit

    return final_output
