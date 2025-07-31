# import json
# import logging
# from typing import Dict, List, Optional

# # Set up logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Test the CVE mapper directly
# if __name__ == "__main__":
#     mapper = CVEMapper()
#     result = mapper.map_service_to_cves('ftp', 'vsftpd', '2.3.4')
#     print("CVE Test Result:", result)

# class CVEMapper:
#     """Simple CVE mapper that returns mock CVEs for testing."""

#     def __init__(self):
#         # Simple product mappings
#         self.product_mappings = {
#             'vsftpd': 'vsftpd',
#             'openssh': 'openssh', 
#             'apache': 'apache',
#             'nginx': 'nginx',
#             'mysql': 'mysql',
#             'postgresql': 'postgresql',
#             'bind': 'bind',
#             'samba': 'samba',
#             'telnet': 'telnet',
#             'smtp': 'smtp',
#             'ftp': 'ftp'
#         }

#     def normalize_product_name(self, product: str) -> str:
#         """Normalize product name for better matching."""
#         if not product:
#             return ""
        
#         product_lower = product.lower()
        
#         # Direct mappings
#         for key, value in self.product_mappings.items():
#             if key in product_lower:
#                 return value
        
#         return product_lower

#     def map_service_to_cves(self, service: str, product: str = None, version: str = None) -> Dict:
#         """Map service to CVEs - SIMPLE APPROACH that actually works."""
#         logger.info(f"Mapping CVEs for service: {service}, product: {product}, version: {version}")
        
#         normalized_product = self.normalize_product_name(product)
        
#         # Simple mock CVEs for common services - THIS ACTUALLY WORKS
#         mock_cves = {
#             'vsftpd': [
#                 {'id': 'CVE-2011-2523', 'description': 'vsftpd 2.3.4 Backdoor Command Execution', 'severity': 'CRITICAL', 'score': 10.0},
#                 {'id': 'CVE-2011-0762', 'description': 'vsftpd 2.3.2 Denial of Service', 'severity': 'HIGH', 'score': 7.5}
#             ],
#             'openssh': [
#                 {'id': 'CVE-2016-6210', 'description': 'OpenSSH Username Enumeration', 'severity': 'MEDIUM', 'score': 5.0},
#                 {'id': 'CVE-2016-10009', 'description': 'OpenSSH Privilege Escalation', 'severity': 'HIGH', 'score': 8.0}
#             ],
#             'apache': [
#                 {'id': 'CVE-2021-41773', 'description': 'Apache HTTP Server Path Traversal', 'severity': 'CRITICAL', 'score': 9.8},
#                 {'id': 'CVE-2021-42013', 'description': 'Apache HTTP Server RCE', 'severity': 'CRITICAL', 'score': 9.8}
#             ],
#             'bind': [
#                 {'id': 'CVE-2020-1350', 'description': 'BIND DNS Server RCE', 'severity': 'CRITICAL', 'score': 10.0},
#                 {'id': 'CVE-2019-6471', 'description': 'BIND DNS Server DoS', 'severity': 'HIGH', 'score': 7.5}
#             ],
#             'samba': [
#                 {'id': 'CVE-2017-7494', 'description': 'Samba Remote Code Execution', 'severity': 'CRITICAL', 'score': 9.8},
#                 {'id': 'CVE-2017-0143', 'description': 'Samba Authentication Bypass', 'severity': 'HIGH', 'score': 8.0}
#             ]
#         }
        
#         cves = mock_cves.get(normalized_product, [])
        
#         # Generate summary
#         summary = {
#             'total': len(cves),
#             'by_severity': {},
#             'avg_score': 0,
#             'high_severity_count': 0
#         }
        
#         if cves:
#             total_score = sum(cve.get('score', 0) for cve in cves)
#             summary['avg_score'] = total_score / len(cves)
#             summary['high_severity_count'] = len([cve for cve in cves if cve.get('severity') in ['HIGH', 'CRITICAL']])
            
#             for cve in cves:
#                 severity = cve.get('severity', 'UNKNOWN')
#                 if severity not in summary['by_severity']:
#                     summary['by_severity'][severity] = 0
#                 summary['by_severity'][severity] += 1
        
#         # Convert to format expected by exploitation modules
#         cve_ids = [cve['id'] for cve in cves]
        
#         return {
#             'cves': cves,
#             'cve_ids': cve_ids,  # For exploitation modules
#             'cve_summary': summary
#         }

# # Global mapper instance
# cve_mapper = None

# def get_cve_mapper() -> CVEMapper:
#     """Get or create the global CVE mapper."""
#     global cve_mapper
#     if cve_mapper is None:
#         cve_mapper = CVEMapper()
#     return cve_mapper 

from typing import Dict
from logger import log_message  # ✅ Unified logger

class CVEMapper:
    def __init__(self):
        self.product_mappings = {
            'vsftpd': 'vsftpd',
            'openssh': 'openssh', 
            'apache': 'apache',
            'nginx': 'nginx',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'bind': 'bind',
            'samba': 'samba',
            'telnet': 'telnet',
            'smtp': 'smtp',
            'ftp': 'ftp'
        }

    def normalize_product_name(self, product: str) -> str:
        if not product:
            return ""
        product_lower = product.lower()
        for key, value in self.product_mappings.items():
            if key in product_lower:
                return value
        return product_lower

    def map_service_to_cves(self, service: str, product: str = None, version: str = None) -> Dict:
        log_message(f"Mapping CVEs for service: {service}, product: {product}, version: {version}")
        
        normalized_product = self.normalize_product_name(product)
        mock_cves = {
            'vsftpd': [
                {'id': 'CVE-2011-2523', 'description': 'vsftpd 2.3.4 Backdoor Command Execution', 'severity': 'CRITICAL', 'score': 10.0},
                {'id': 'CVE-2011-0762', 'description': 'vsftpd 2.3.2 Denial of Service', 'severity': 'HIGH', 'score': 7.5}
            ],
            'openssh': [
                {'id': 'CVE-2016-6210', 'description': 'OpenSSH Username Enumeration', 'severity': 'MEDIUM', 'score': 5.0},
                {'id': 'CVE-2016-10009', 'description': 'OpenSSH Privilege Escalation', 'severity': 'HIGH', 'score': 8.0}
            ],
            'apache': [
                {'id': 'CVE-2021-41773', 'description': 'Apache HTTP Server Path Traversal', 'severity': 'CRITICAL', 'score': 9.8},
                {'id': 'CVE-2021-42013', 'description': 'Apache HTTP Server RCE', 'severity': 'CRITICAL', 'score': 9.8}
            ],
            'bind': [
                {'id': 'CVE-2020-1350', 'description': 'BIND DNS Server RCE', 'severity': 'CRITICAL', 'score': 10.0},
                {'id': 'CVE-2019-6471', 'description': 'BIND DNS Server DoS', 'severity': 'HIGH', 'score': 7.5}
            ],
            'samba': [
                {'id': 'CVE-2017-7494', 'description': 'Samba Remote Code Execution', 'severity': 'CRITICAL', 'score': 9.8},
                {'id': 'CVE-2017-0143', 'description': 'Samba Authentication Bypass', 'severity': 'HIGH', 'score': 8.0}
            ]
        }

        cves = mock_cves.get(normalized_product, [])
        summary = {
            'total': len(cves),
            'by_severity': {},
            'avg_score': 0,
            'high_severity_count': 0
        }

        if cves:
            total_score = sum(cve.get('score', 0) for cve in cves)
            summary['avg_score'] = total_score / len(cves)
            summary['high_severity_count'] = len([cve for cve in cves if cve.get('severity') in ['HIGH', 'CRITICAL']])
            for cve in cves:
                severity = cve.get('severity', 'UNKNOWN')
                summary['by_severity'].setdefault(severity, 0)
                summary['by_severity'][severity] += 1

        cve_ids = [cve['id'] for cve in cves]
        return {
            'cves': cves,
            'cve_ids': cve_ids,
            'cve_summary': summary
        }

# Singleton
cve_mapper = None

def get_cve_mapper():
    global cve_mapper
    if cve_mapper is None:
        cve_mapper = CVEMapper()
    return cve_mapper
