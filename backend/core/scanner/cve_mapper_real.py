import os
import sys
from typing import Dict, List, Optional
from pathlib import Path

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, current_dir)
sys.path.insert(0, parent_dir)

from logger import log_message

class CVEMapper:
    """Real CVE mapper that uses the SQLite database."""
    
    def __init__(self):
        self.sqlite_loader = None
        self._init_sqlite_loader()
        
        # Fallback mock data in case database is not working
        self.mock_cves = {
            'vsftpd': [
                {'id': 'CVE-2011-2523', 'description': 'vsftpd 2.3.4 Backdoor Command Execution', 'severity': 'CRITICAL', 'score': 10.0},
                {'id': 'CVE-2011-0762', 'description': 'vsftpd 2.3.2 Denial of Service', 'severity': 'HIGH', 'score': 7.5}
            ],
            'openssh': [
                {'id': 'CVE-2016-6210', 'description': 'OpenSSH Username Enumeration', 'severity': 'MEDIUM', 'score': 5.0},
                {'id': 'CVE-2016-10009', 'description': 'OpenSSH Privilege Escalation', 'severity': 'HIGH', 'score': 8.0},
                {'id': 'CVE-2020-15778', 'description': 'OpenSSH Remote Code Execution', 'severity': 'CRITICAL', 'score': 9.8}
            ],
            'apache': [
                {'id': 'CVE-2021-41773', 'description': 'Apache HTTP Server Path Traversal', 'severity': 'CRITICAL', 'score': 9.8},
                {'id': 'CVE-2021-42013', 'description': 'Apache HTTP Server RCE', 'severity': 'CRITICAL', 'score': 9.8}
            ],
            'nginx': [
                {'id': 'CVE-2019-20372', 'description': 'Nginx HTTP Request Smuggling', 'severity': 'HIGH', 'score': 7.5},
                {'id': 'CVE-2017-7529', 'description': 'Nginx Range Filter Integer Overflow', 'severity': 'HIGH', 'score': 7.5}
            ],
            'mysql': [
                {'id': 'CVE-2020-2574', 'description': 'MySQL Server Privilege Escalation', 'severity': 'HIGH', 'score': 8.0},
                {'id': 'CVE-2020-2752', 'description': 'MySQL Server Authentication Bypass', 'severity': 'CRITICAL', 'score': 9.0}
            ],
            'bind': [
                {'id': 'CVE-2020-1350', 'description': 'BIND DNS Server RCE (SIGRed)', 'severity': 'CRITICAL', 'score': 10.0},
                {'id': 'CVE-2019-6471', 'description': 'BIND DNS Server DoS', 'severity': 'HIGH', 'score': 7.5}
            ],
            'samba': [
                {'id': 'CVE-2017-7494', 'description': 'Samba Remote Code Execution (SambaCry)', 'severity': 'CRITICAL', 'score': 9.8},
                {'id': 'CVE-2017-0143', 'description': 'Samba Authentication Bypass', 'severity': 'HIGH', 'score': 8.0}
            ],
            'ftp': [
                {'id': 'CVE-2011-2523', 'description': 'vsftpd 2.3.4 Backdoor Command Execution', 'severity': 'CRITICAL', 'score': 10.0}
            ],
            'ssh': [
                {'id': 'CVE-2016-6210', 'description': 'OpenSSH Username Enumeration', 'severity': 'MEDIUM', 'score': 5.0},
                {'id': 'CVE-2020-15778', 'description': 'OpenSSH Remote Code Execution', 'severity': 'CRITICAL', 'score': 9.8}
            ],
            'telnet': [
                {'id': 'CVE-2011-4862', 'description': 'Telnet Daemon Buffer Overflow', 'severity': 'HIGH', 'score': 8.5}
            ],
            'smtp': [
                {'id': 'CVE-2020-8927', 'description': 'SMTP Server Buffer Overflow', 'severity': 'HIGH', 'score': 7.8}
            ]
        }

    def _init_sqlite_loader(self):
        """Initialize SQLite loader if available."""
        try:
            # First, let's check what's actually in the database
            import sqlite3
            db_path = os.path.join(current_dir, '..', 'data', 'nvd.db')
            
            # Check if database file exists and what tables it has
            if not os.path.exists(db_path):
                log_message(f"❌ Database file not found: {db_path}")
                self.sqlite_loader = None
                return
            
            # Connect and check schema
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check what tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            log_message(f"📋 Database tables found: {tables}")
            
            # Check CPE table schema if it exists
            if 'cpes' in tables:
                cursor.execute("PRAGMA table_info(cpes);")
                cpe_columns = [row[1] for row in cursor.fetchall()]
                log_message(f"📋 CPE table columns: {cpe_columns}")
            
            # Check CVE table schema if it exists
            if 'cves' in tables:
                cursor.execute("PRAGMA table_info(cves);")
                cve_columns = [row[1] for row in cursor.fetchall()]
                log_message(f"📋 CVE table columns: {cve_columns}")
                
                # Count records
                cursor.execute("SELECT COUNT(*) FROM cves;")
                cve_count = cursor.fetchone()[0]
                log_message(f"� CVE records in database: {cve_count}")
                
                if cve_count > 0:
                    # Test query to see what works
                    cursor.execute("SELECT cve_id, description, severity, score FROM cves LIMIT 3;")
                    sample_cves = cursor.fetchall()
                    log_message(f"📝 Sample CVEs: {len(sample_cves)} found")
                    for cve in sample_cves:
                        log_message(f"  - {cve[0]}: {cve[2]} (score: {cve[3]})")
            
            conn.close()
            
            # Now try to initialize the real loader
            from sqlite_data_loader import get_sqlite_loader
            self.sqlite_loader = get_sqlite_loader()
            log_message("✅ SQLite loader initialized successfully")
                
        except Exception as e:
            log_message(f"⚠️ Could not load SQLite database: {e}")
            log_message("🔄 Falling back to mock CVE data")
            self.sqlite_loader = None

    def normalize_product_name(self, product: str) -> str:
        """Normalize product name for better matching."""
        if not product:
            return ""
        
        product_lower = product.lower().strip()
        
        # Common product name mappings
        mappings = {
            'vsftpd': 'vsftpd',
            'openssh': 'openssh',
            'ssh': 'openssh',
            'apache': 'apache',
            'httpd': 'apache', 
            'nginx': 'nginx',
            'mysql': 'mysql',
            'mariadb': 'mysql',
            'postgresql': 'postgresql',
            'postgres': 'postgresql',
            'bind': 'bind',
            'named': 'bind',
            'samba': 'samba',
            'smb': 'samba',
            'telnet': 'telnet',
            'smtp': 'smtp',
            'ftp': 'ftp',
            'proftpd': 'proftpd',
            'pureftpd': 'pureftpd'
        }
        
        # Check for exact matches first
        for key, value in mappings.items():
            if key in product_lower:
                return value
        
        return product_lower

    def map_service_to_cves(self, service: str, product: str = None, version: str = None) -> Dict:
        """Map service to CVEs using SQLite database or fallback to mock data."""
        log_message(f"🔍 Mapping CVEs for service: {service}, product: {product}, version: {version}")
        
        # Normalize product name
        normalized_product = self.normalize_product_name(product) if product else service.lower()
        
        cves = []
        data_source = "mock"
        
        # Try direct database query first (bypass the complex loader)
        if self._try_direct_database_query(normalized_product, version):
            cves, data_source = self._try_direct_database_query(normalized_product, version)
        
        # If direct query didn't work, try the sqlite_loader
        elif self.sqlite_loader:
            try:
                log_message(f"🗄️ Searching database for product: {normalized_product}")
                
                # Search for CVEs using the product name
                db_cves = self.sqlite_loader.find_cves_for_service(normalized_product, version)
                
                if db_cves:
                    # Convert database format to our expected format
                    cves = []
                    for db_cve in db_cves[:10]:  # Limit to top 10 CVEs
                        cve = {
                            'id': db_cve['cve_id'],
                            'description': db_cve['description'],  # Show full description
                            'severity': db_cve['severity'] or 'UNKNOWN',
                            'score': db_cve['score'] or 0.0
                        }
                        cves.append(cve)
                    
                    data_source = "database"
                    log_message(f"✅ Found {len(cves)} CVEs from database")
                else:
                    log_message(f"❌ No CVEs found in database for {normalized_product}")
                    
            except Exception as e:
                log_message(f"❌ Database query failed: {e}")
                self.sqlite_loader = None  # Disable for future queries
        
        # Fallback to mock data if database didn't work or no results
        if not cves:
            log_message(f"🔄 Using mock CVE data for {normalized_product}")
            mock_cves = self.mock_cves.get(normalized_product, [])
            
            # Also try the original service name
            if not mock_cves and service.lower() != normalized_product:
                mock_cves = self.mock_cves.get(service.lower(), [])
            
            cves = mock_cves
            data_source = "mock"
        
        # Generate summary
        summary = self._generate_summary(cves)
        
        # Add data source info
        summary['data_source'] = data_source
        summary['highest_severity'] = self._get_highest_severity(cves)
        summary['average_score'] = summary.get('avg_score', 0)
        
        # Convert to format expected by exploitation modules
        cve_ids = [cve['id'] for cve in cves]
        
        log_message(f"📊 CVE Summary: {len(cves)} total, {summary['high_severity_count']} high/critical (source: {data_source})")
        
        return {
            'cves': cves,
            'cve_ids': cve_ids,  # For exploitation modules
            'cve_summary': summary
        }

    def _try_direct_database_query(self, product: str, version: str = None) -> tuple:
        """Try direct database query bypassing the complex loader."""
        try:
            import sqlite3
            db_path = os.path.join(current_dir, '..', 'data', 'nvd.db')
            
            if not os.path.exists(db_path):
                return [], "mock"
            
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Simple direct query for CVEs containing the product name
            query = """
                SELECT cve_id, description, severity, score 
                FROM cves 
                WHERE LOWER(description) LIKE LOWER(?) 
                ORDER BY score DESC 
                LIMIT 10
            """
            
            search_term = f"%{product}%"
            cursor.execute(query, (search_term,))
            db_results = cursor.fetchall()
            
            if db_results:
                cves = []
                for row in db_results:
                    cve = {
                        'id': row['cve_id'],
                        'description': row['description'],  # Show full description
                        'severity': row['severity'] or 'UNKNOWN',
                        'score': row['score'] or 0.0
                    }
                    cves.append(cve)
                
                conn.close()
                log_message(f"✅ Direct query found {len(cves)} CVEs for {product}")
                return cves, "database"
            
            conn.close()
            return [], "mock"
            
        except Exception as e:
            log_message(f"❌ Direct database query failed: {e}")
            return [], "mock"

    def _generate_summary(self, cves: List[Dict]) -> Dict:
        """Generate CVE summary statistics."""
        summary = {
            'total': len(cves),
            'by_severity': {},
            'avg_score': 0,
            'high_severity_count': 0
        }
        
        if not cves:
            return summary
        
        total_score = 0
        score_count = 0
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN')
            score = cve.get('score', 0)
            
            # Count by severity
            if severity not in summary['by_severity']:
                summary['by_severity'][severity] = 0
            summary['by_severity'][severity] += 1
            
            # Calculate average score
            if score and score > 0:
                total_score += score
                score_count += 1
            
            # Count high severity
            if severity in ['HIGH', 'CRITICAL']:
                summary['high_severity_count'] += 1
        
        if score_count > 0:
            summary['avg_score'] = round(total_score / score_count, 1)
        
        return summary

    def _get_highest_severity(self, cves: List[Dict]) -> str:
        """Get the highest severity level from CVEs."""
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        
        highest = 0
        highest_severity = 'UNKNOWN'
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN')
            if severity_order.get(severity, 0) > highest:
                highest = severity_order[severity]
                highest_severity = severity
        
        return highest_severity

    def get_database_status(self) -> Dict:
        """Get the status of the CVE database."""
        if self.sqlite_loader:
            try:
                stats = self.sqlite_loader.get_database_stats()
                return {
                    'status': 'connected',
                    'cve_count': stats['cve_count'],
                    'cpe_count': stats['cpe_count'],
                    'severity_distribution': stats.get('severity_distribution', {})
                }
            except Exception as e:
                return {
                    'status': 'error',
                    'error': str(e)
                }
        else:
            return {
                'status': 'mock_data',
                'message': 'Using fallback mock CVE data'
            }

# Global mapper instance
cve_mapper = None

def get_cve_mapper() -> CVEMapper:
    """Get or create the global CVE mapper."""
    global cve_mapper
    if cve_mapper is None:
        cve_mapper = CVEMapper()
    return cve_mapper

# Test function
if __name__ == "__main__":
    mapper = get_cve_mapper()
    
    # Test some common services
    test_services = [
        ('ftp', 'vsftpd', '2.3.4'),
        ('ssh', 'openssh', '7.4'),
        ('http', 'apache', '2.4.41'),
        ('mysql', 'mysql', '5.7.30')
    ]
    
    print("🧪 Testing CVE Mapper:")
    print("=" * 50)
    
    for service, product, version in test_services:
        print(f"\n🔍 Testing: {service} ({product} {version})")
        result = mapper.map_service_to_cves(service, product, version)
        
        print(f"  📊 Found {len(result['cves'])} CVEs")
        print(f"  🎯 Data source: {result['cve_summary'].get('data_source', 'unknown')}")
        print(f"  ⚠️ High/Critical: {result['cve_summary']['high_severity_count']}")
        
        if result['cves']:
            print(f"  🔥 Top CVE: {result['cves'][0]['id']} ({result['cves'][0]['severity']})")
    
    print(f"\n📈 Database Status:")
    status = mapper.get_database_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
