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

PREFERRED_VENDORS = ["microsoft", "mysql", "oracle", "postgresql", "apache", "erlang-solutions", "mongodb", "vmware"]

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

def get_cves_for_cpe(cpe_name):
    try:
        parts = cpe_name.split(":")
        if len(parts) < 6:
            return []

        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        keyword = f"{vendor} {product}"
        if version and version not in ["*", "-"]:
            keyword += f" {version}"

        params = {
            "resultsPerPage": 100,
            "startIndex": 0,
            "keywordSearch": keyword
        }

        response = requests.get(CVE_SEARCH_URL, headers=HEADERS, params=params)
        if response.status_code != 200:
            print(f"[!] CVE API Error {response.status_code}: {response.text}")
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        cve_ids = [vuln["cve"]["id"] for vuln in vulnerabilities]
        return cve_ids

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

        # Skip portless entries (if malformed)
        if port is None:
            continue

        cpe_name = None
        if explicit_cpe:
            # Use the provided CPE (like from OS fingerprinting)
            cpe_name = explicit_cpe
            print(f"[*] Using provided CPE for port {port}: {cpe_name}")
        else:
            # Generate CPE search queries from fields
            queries = list(dict.fromkeys(filter(None, [
            clean_text(f"{product} {version}"),
            clean_text(f"{service} {version}"),
            clean_text(product),
            clean_text(service)
        ])))

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
