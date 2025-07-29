import re
from typing import List, Dict, Optional, Tuple
from .data_loader import get_nvd_loader
import logging

logger = logging.getLogger(__name__)

class CVEMapper:
    """Maps detected services to CVEs using NVD data."""
    
    def __init__(self):
        self.nvd_loader = get_nvd_loader()
        
        # Common product name mappings for better CPE matching
        self.product_mappings = {
            'apache': 'apache',
            'httpd': 'apache',
            'http_server': 'apache',
            'nginx': 'nginx',
            'mysql': 'mysql',
            'mariadb': 'mariadb',
            'postgresql': 'postgresql',
            'postgres': 'postgresql',
            'ssh': 'openssh',
            'openssh': 'openssh',
            'ftp': 'vsftpd',
            'vsftpd': 'vsftpd',
            'smtp': 'postfix',
            'postfix': 'postfix',
            'dovecot': 'dovecot',
            'imap': 'dovecot',
            'pop3': 'dovecot',
            'telnet': 'telnet',
            'rdp': 'microsoft',
            'vnc': 'tightvnc',
            'tightvnc': 'tightvnc',
            'realvnc': 'realvnc',
            'ultravnc': 'ultravnc',
            'php': 'php',
            'python': 'python',
            'java': 'oracle',
            'tomcat': 'apache',
            'jboss': 'redhat',
            'weblogic': 'oracle',
            'websphere': 'ibm',
            'iis': 'microsoft',
            'exchange': 'microsoft',
            'sharepoint': 'microsoft',
            'wordpress': 'wordpress',
            'joomla': 'joomla',
            'drupal': 'drupal',
            'magento': 'magento',
            'oscommerce': 'oscommerce',
            'prestashop': 'prestashop',
        }
        
    def normalize_product_name(self, product: str) -> str:
        """Normalize product name for better CPE matching."""
        if not product:
            return ""
            
        product_lower = product.lower().strip()
        
        # Check direct mappings first
        for key, value in self.product_mappings.items():
            if key in product_lower:
                return value
                
        # Remove common suffixes/prefixes
        product_clean = re.sub(r'[^\w\s]', '', product_lower)
        product_clean = re.sub(r'\s+(server|service|daemon|web|http|https)', '', product_clean)
        
        return product_clean
        
    def find_cpes_for_service(self, service_info: Dict) -> List[str]:
        """Find relevant CPEs for a detected service."""
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        service = service_info.get('service', '')
        
        if not product and not service:
            return []
            
        # Normalize product name
        normalized_product = self.normalize_product_name(product or service)
        
        # Find CPE matches
        cpe_matches = self.nvd_loader.find_cpe_matches(normalized_product, version)
        
        # If no exact matches, try broader search
        if not cpe_matches:
            cpe_matches = self.nvd_loader.find_cpe_matches(normalized_product)
            
        return cpe_matches
        
    def get_cves_for_service(self, service_info: Dict) -> List[Dict]:
        """Get all CVEs that affect a detected service."""
        cpes = self.find_cpes_for_service(service_info)
        all_cves = []
        
        for cpe in cpes:
            cves = self.nvd_loader.find_cves_for_cpe(cpe)
            all_cves.extend(cves)
            
        # Remove duplicates (same CVE might affect multiple CPEs)
        unique_cves = {}
        for cve in all_cves:
            cve_id = cve.get('cve', {}).get('id')
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = cve
                
        return list(unique_cves.values())
        
    def extract_cve_details(self, cve_data: Dict) -> Dict:
        """Extract relevant details from CVE data."""
        cve_info = cve_data.get('cve', {})
        
        # Extract basic info
        cve_id = cve_info.get('id', '')
        description = ''
        
        # Get description from different possible locations
        descriptions = cve_info.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
                
        # Get CVSS metrics
        metrics = cve_info.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else metrics.get('cvssMetricV30', [{}])[0]
        cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
        
        # Extract severity and score
        severity = 'Unknown'
        base_score = 0.0
        
        if cvss_v3:
            cvss_data = cvss_v3.get('cvssData', {})
            severity = cvss_data.get('baseSeverity', 'Unknown')
            base_score = cvss_data.get('baseScore', 0.0)
        elif cvss_v2:
            cvss_data = cvss_v2.get('cvssData', {})
            severity = cvss_data.get('severity', 'Unknown')
            base_score = cvss_data.get('baseScore', 0.0)
            
        # Get references
        references = []
        refs = cve_info.get('references', [])
        for ref in refs:
            ref_info = {
                'url': ref.get('url', ''),
                'name': ref.get('name', ''),
                'tags': ref.get('tags', [])
            }
            references.append(ref_info)
            
        return {
            'id': cve_id,
            'description': description,
            'severity': severity,
            'base_score': base_score,
            'references': references,
            'published_date': cve_info.get('published', ''),
            'last_modified_date': cve_info.get('lastModified', ''),
            'raw_data': cve_data  # Keep full data for advanced analysis
        }
        
    def map_service_to_cves(self, service_info: Dict) -> List[Dict]:
        """Main function: map a detected service to relevant CVEs with details."""
        logger.info(f"Mapping service to CVEs: {service_info}")
        
        # Get raw CVE data
        raw_cves = self.get_cves_for_service(service_info)
        
        # Extract details for each CVE
        detailed_cves = []
        for cve_data in raw_cves:
            cve_details = self.extract_cve_details(cve_data)
            detailed_cves.append(cve_details)
            
        # Sort by severity (Critical, High, Medium, Low, Unknown)
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
        detailed_cves.sort(key=lambda x: (severity_order.get(x['severity'], 5), -x['base_score']))
        
        logger.info(f"Found {len(detailed_cves)} CVEs for service")
        return detailed_cves
        
    def get_cve_summary(self, cves: List[Dict]) -> Dict:
        """Generate a summary of CVEs by severity."""
        summary = {
            'total_cves': len(cves),
            'by_severity': {},
            'highest_severity': 'Unknown',
            'average_score': 0.0
        }
        
        if not cves:
            return summary
            
        # Count by severity
        for cve in cves:
            severity = cve['severity']
            if severity not in summary['by_severity']:
                summary['by_severity'][severity] = 0
            summary['by_severity'][severity] += 1
            
        # Find highest severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
        highest_severity = min(cves, key=lambda x: severity_order.get(x['severity'], 5))
        summary['highest_severity'] = highest_severity['severity']
        
        # Calculate average score
        scores = [cve['base_score'] for cve in cves if cve['base_score'] > 0]
        if scores:
            summary['average_score'] = sum(scores) / len(scores)
            
        return summary

# Global mapper instance
cve_mapper = None

def get_cve_mapper() -> CVEMapper:
    """Get or create the global CVE mapper."""
    global cve_mapper
    if cve_mapper is None:
        cve_mapper = CVEMapper()
    return cve_mapper 