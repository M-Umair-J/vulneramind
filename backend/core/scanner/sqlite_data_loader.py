import sqlite3
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import logging
from functools import lru_cache

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SQLiteNVDLoader:
    """SQLite-based NVD data loader for efficient offline vulnerability analysis."""
    
    def __init__(self, data_dir: str = "backend/core/data", db_path: str = "backend/core/data/nvd.db"):
        self.data_dir = Path(data_dir)
        self.db_path = Path(db_path)
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with schema."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        
        # Performance optimizations
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging for better concurrency
        self.conn.execute("PRAGMA synchronous = NORMAL")  # Faster writes
        self.conn.execute("PRAGMA cache_size = 10000")  # Larger cache
        self.conn.execute("PRAGMA temp_store = MEMORY")  # Use memory for temp storage
        
        # Create tables if they don't exist
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS cpes (
                id INTEGER PRIMARY KEY,
                cpe_name TEXT UNIQUE NOT NULL,
                product TEXT,
                version TEXT,
                vendor TEXT,
                title TEXT,
                created_date TEXT
            );
            
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                severity TEXT,
                score REAL,
                published_date TEXT,
                last_modified_date TEXT,
                refs TEXT  -- JSON array of references (renamed to avoid reserved word)
            );
            
            CREATE TABLE IF NOT EXISTS cpe_cve_matches (
                id INTEGER PRIMARY KEY,
                cpe_id INTEGER,
                cve_id INTEGER
            );
            
            -- Create indexes for faster queries
            CREATE INDEX IF NOT EXISTS idx_cpes_product ON cpes(product);
            CREATE INDEX IF NOT EXISTS idx_cpes_vendor ON cpes(vendor);
            CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(score);
            CREATE INDEX IF NOT EXISTS idx_matches_cpe ON cpe_cve_matches(cpe_id);
            CREATE INDEX IF NOT EXISTS idx_matches_cve ON cpe_cve_matches(cve_id);
        """)
        self.conn.commit()
    
    def import_cpe_dictionary(self, force_reimport: bool = False):
        """Import CPE dictionary from XML file."""
        if not force_reimport and self._table_has_data('cpes'):
            logger.info("CPE dictionary already imported, skipping...")
            return
        
        xml_file = self.data_dir / "official-cpe-dictionary_v2.3.xml"
        if not xml_file.exists():
            logger.warning(f"CPE dictionary not found: {xml_file}")
            return
        
        logger.info("Importing CPE dictionary...")
        
        # Clear existing data
        self.conn.execute("DELETE FROM cpes")
        
        try:
            # Use iterparse for memory efficiency
            context = ET.iterparse(xml_file, events=('end',))
            
            batch_size = 5000  # Increased batch size for better performance
            batch = []
            count = 0
            
            for event, elem in context:
                if elem.tag.endswith('cpe-item'):
                    cpe_name = elem.get('name')
                    if cpe_name:
                        # Convert CPE 2.2 format to 2.3 format for CVE compatibility
                        if cpe_name.startswith('cpe:/'):
                            parts = cpe_name.split(':')
                            if len(parts) >= 4:
                                cpe_name = f"cpe:2.3:{parts[1]}:{parts[2]}:{parts[3]}:*:*:*:*:*:*:*"
                        
                        # Parse CPE components
                        parts = cpe_name.split(':')
                        if len(parts) >= 6:
                            vendor = parts[3] if parts[3] != '*' else None
                            product = parts[4] if parts[4] != '*' else None
                            version = parts[5] if parts[5] != '*' else None
                        else:
                            vendor = product = version = None
                        
                        # Get title
                        title_elem = elem.find('.//{http://cpe.mitre.org/dictionary/2.0}title')
                        title = title_elem.text if title_elem is not None else ''
                        
                        batch.append((
                            cpe_name,
                            product,
                            version,
                            vendor,
                            title,
                            None  # created_date
                        ))
                        
                        count += 1
                        if len(batch) >= batch_size:
                            self._insert_cpe_batch(batch)
                            logger.info(f"Imported {count} CPEs so far...")
                            batch = []
                    
                    elem.clear()  # Free memory
            
            # Insert remaining batch
            if batch:
                self._insert_cpe_batch(batch)
            
            self.conn.commit()
            logger.info(f"CPE dictionary import completed - {count} total CPEs")
            
        except Exception as e:
            logger.error(f"Error importing CPE dictionary: {e}")
            self.conn.rollback()
    
    def _insert_cpe_batch(self, batch):
        """Insert a batch of CPEs efficiently."""
        self.conn.executemany(
            "INSERT OR IGNORE INTO cpes (cpe_name, product, version, vendor, title, created_date) VALUES (?, ?, ?, ?, ?, ?)",
            batch
        )
    
    def import_cve_data(self, years: List[str] = None, force_reimport: bool = False):
        """Import CVE data from JSON files."""
        if years is None:
            years = ["recent", "modified", "2024", "2023"]
        
        if not force_reimport and self._table_has_data('cves'):
            logger.info("CVE data already imported, skipping...")
            return
        
        logger.info("Importing CVE data...")
        
        # Clear existing data
        self.conn.execute("DELETE FROM cves")
        self.conn.execute("DELETE FROM cpe_cve_matches")
        
        for year in years:
            file_path = self.data_dir / f"nvdcve-2.0-{year}.json"
            if not file_path.exists():
                logger.warning(f"CVE file not found: {file_path}")
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                cves = data.get('vulnerabilities', [])
                logger.info(f"Processing {len(cves)} CVEs from {year}")
                
                batch_size = 2000  # Increased batch size
                cve_batch = []
                match_batch = []
                count = 0
                
                for cve_item in cves:
                    cve_data = cve_item.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    if not cve_id:
                        continue
                    
                    count += 1
                    
                    # Extract CVE details
                    description = ""
                    for desc in cve_data.get('descriptions', []):
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Get metrics for severity/score
                    metrics = cve_data.get('metrics', {})
                    severity = None
                    score = None
                    
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0]
                        severity = cvss.get('cvssData', {}).get('baseSeverity')
                        score = cvss.get('cvssData', {}).get('baseScore')
                    elif 'cvssMetricV30' in metrics:
                        cvss = metrics['cvssMetricV30'][0]
                        severity = cvss.get('cvssData', {}).get('baseSeverity')
                        score = cvss.get('cvssData', {}).get('baseScore')
                    elif 'cvssMetricV2' in metrics:
                        cvss = metrics['cvssMetricV2'][0]
                        severity = cvss.get('baseSeverity')
                        score = cvss.get('cvssData', {}).get('baseScore')
                    
                    # Get references
                    references = []
                    for ref in cve_data.get('references', []):
                        references.append({
                            'url': ref.get('url', ''),
                            'name': ref.get('name', ''),
                            'tags': ref.get('tags', [])
                        })
                    
                    cve_batch.append((
                        cve_id,
                        description,
                        severity,
                        score,
                        cve_data.get('published'),
                        cve_data.get('lastModified'),
                        json.dumps(references)
                    ))
                    
                    # Process configurations for CPE-CVE matches
                    for config in cve_data.get('configurations', []):
                        for node in config.get('nodes', []):
                            for cpe_match in node.get('cpeMatch', []):
                                cpe_name = cpe_match.get('criteria')
                                if cpe_name:
                                    match_batch.append((cpe_name, cve_id))
                    
                    if len(cve_batch) >= batch_size:
                        self._insert_cve_batch(cve_batch)
                        self._insert_match_batch(match_batch)
                        logger.info(f"Processed {count} CVEs from {year}...")
                        cve_batch = []
                        match_batch = []
                
                # Insert remaining batches
                if cve_batch:
                    self._insert_cve_batch(cve_batch)
                if match_batch:
                    self._insert_match_batch(match_batch)
                
                logger.info(f"Completed import for {year}")
                
            except Exception as e:
                logger.error(f"Error importing {file_path}: {e}")
                self.conn.rollback()
        
        self.conn.commit()
        logger.info("CVE data import completed")
    
    def _insert_cve_batch(self, batch):
        """Insert a batch of CVEs efficiently."""
        self.conn.executemany(
            "INSERT OR IGNORE INTO cves (cve_id, description, severity, score, published_date, last_modified_date, refs) VALUES (?, ?, ?, ?, ?, ?, ?)",
            batch
        )
    
    def _insert_match_batch(self, batch):
        """Insert a batch of CPE-CVE matches efficiently."""
        # Create lookup dictionaries for faster matching
        cpe_lookup = {}
        cve_lookup = {}
        
        # Get all unique CPE names and CVE IDs from the batch
        unique_cpes = set(cpe_name for cpe_name, _ in batch)
        unique_cves = set(cve_id for _, cve_id in batch)
        
        # Bulk lookup CPE IDs
        if unique_cpes:
            placeholders = ','.join(['?' for _ in unique_cpes])
            cpe_cursor = self.conn.execute(f"SELECT id, cpe_name FROM cpes WHERE cpe_name IN ({placeholders})", list(unique_cpes))
            cpe_lookup = {row['cpe_name']: row['id'] for row in cpe_cursor.fetchall()}
        
        # Bulk lookup CVE IDs
        if unique_cves:
            placeholders = ','.join(['?' for _ in unique_cves])
            cve_cursor = self.conn.execute(f"SELECT id, cve_id FROM cves WHERE cve_id IN ({placeholders})", list(unique_cves))
            cve_lookup = {row['cve_id']: row['id'] for row in cve_cursor.fetchall()}
        
        # Create matches
        matches = []
        for cpe_name, cve_id in batch:
            cpe_id = cpe_lookup.get(cpe_name)
            cve_id_row = cve_lookup.get(cve_id)
            
            if cpe_id and cve_id_row:
                matches.append((cpe_id, cve_id_row))
        
        if matches:
            self.conn.executemany(
                "INSERT OR IGNORE INTO cpe_cve_matches (cpe_id, cve_id) VALUES (?, ?)",
                matches
            )
    
    def _table_has_data(self, table_name: str) -> bool:
        """Check if a table has data."""
        result = self.conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
        return result[0] > 0
    
    @lru_cache(maxsize=1000)
    def find_cpes_for_service(self, product: str, version: str = None) -> List[Dict]:
        """Find CPEs that match a product and optional version."""
        query = """
            SELECT cpe_name, product, version, vendor, title 
            FROM cpes 
            WHERE product LIKE ? 
        """
        params = [f"%{product}%"]
        
        if version:
            query += " AND version LIKE ?"
            params.append(f"%{version}%")
        
        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def find_cves_for_cpe(self, cpe_name: str) -> List[Dict]:
        """Find all CVEs that affect a given CPE."""
        query = """
            SELECT c.cve_id, c.description, c.severity, c.score, c.published_date, c.refs
            FROM cves c
            JOIN cpe_cve_matches m ON c.id = m.cve_id
            JOIN cpes p ON m.cpe_id = p.id
            WHERE p.cpe_name = ?
            ORDER BY c.score DESC NULLS LAST
        """
        
        cursor = self.conn.execute(query, (cpe_name,))
        results = []
        
        for row in cursor.fetchall():
            result = dict(row)
            # Parse references JSON
            if result['refs']:
                try:
                    result['references'] = json.loads(result['refs'])
                except:
                    result['references'] = []
            else:
                result['references'] = []
            results.append(result)
        
        return results
    
    def find_cves_for_service(self, product: str, version: str = None) -> List[Dict]:
        """Find CVEs for a service by finding matching CPEs first."""
        cpes = self.find_cpes_for_service(product, version)
        all_cves = []
        
        for cpe in cpes:
            cves = self.find_cves_for_cpe(cpe['cpe_name'])
            for cve in cves:
                cve['matching_cpe'] = cpe['cpe_name']
            all_cves.extend(cves)
        
        # Remove duplicates and sort by score
        unique_cves = {}
        for cve in all_cves:
            if cve['cve_id'] not in unique_cves:
                unique_cves[cve['cve_id']] = cve
        
        return sorted(unique_cves.values(), key=lambda x: (x['score'] or 0), reverse=True)
    
    def get_cve_summary(self, cves: List[Dict]) -> Dict:
        """Generate a summary of CVEs by severity."""
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
            
            if severity not in summary['by_severity']:
                summary['by_severity'][severity] = 0
            summary['by_severity'][severity] += 1
            
            if score:
                total_score += score
                score_count += 1
            
            if severity in ['HIGH', 'CRITICAL']:
                summary['high_severity_count'] += 1
        
        if score_count > 0:
            summary['avg_score'] = total_score / score_count
        
        return summary
    
    def get_database_stats(self) -> Dict:
        """Get statistics about the database."""
        stats = {}
        
        # Count records
        stats['cpe_count'] = self.conn.execute("SELECT COUNT(*) FROM cpes").fetchone()[0]
        stats['cve_count'] = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        stats['match_count'] = self.conn.execute("SELECT COUNT(*) FROM cpe_cve_matches").fetchone()[0]
        
        # Severity distribution
        cursor = self.conn.execute("""
            SELECT severity, COUNT(*) as count 
            FROM cves 
            WHERE severity IS NOT NULL 
            GROUP BY severity
        """)
        stats['severity_distribution'] = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        return stats
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

# Global loader instance
sqlite_loader = None

def get_sqlite_loader() -> SQLiteNVDLoader:
    """Get or create the global SQLite NVD data loader."""
    global sqlite_loader
    if sqlite_loader is None:
        sqlite_loader = SQLiteNVDLoader()
        # Import data if database is empty
        if not sqlite_loader._table_has_data('cpes'):
            sqlite_loader.import_cpe_dictionary()
        if not sqlite_loader._table_has_data('cves'):
            sqlite_loader.import_cve_data()
    return sqlite_loader 