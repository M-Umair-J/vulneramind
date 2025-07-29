import json
import gzip
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDDataLoader:
    """Loads and manages NVD CVE and CPE data for offline vulnerability analysis."""
    
    def __init__(self, data_dir: str = "backend/core/data"):
        self.data_dir = Path(data_dir)
        self.cve_data = {}  # CVE ID -> CVE details
        self.cpe_dict = {}  # CPE URI -> CPE details
        self.cpe_match_index = {}  # CPE URI -> list of CVE IDs
        self.loaded_chunks = set()  # Track loaded CPE match chunks
        
    def load_cve_data(self, years: List[str] = None) -> Dict[str, dict]:
        """Load CVE data from JSON files."""
        if years is None:
            years = ["recent", "modified", "2024", "2023"]
        
        logger.info("Loading CVE data...")
        
        for year in years:
            file_path = self.data_dir / f"nvdcve-2.0-{year}.json"
            if not file_path.exists():
                logger.warning(f"CVE file not found: {file_path}")
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Extract CVEs from the JSON structure
                cves = data.get('vulnerabilities', [])
                for cve_item in cves:
                    cve_id = cve_item.get('cve', {}).get('id')
                    if cve_id:
                        self.cve_data[cve_id] = cve_item
                        
                logger.info(f"Loaded {len(cves)} CVEs from {year}")
                
            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
                
        logger.info(f"Total CVEs loaded: {len(self.cve_data)}")
        return self.cve_data
    
    def load_cpe_dictionary(self) -> Dict[str, dict]:
        """Load CPE dictionary from XML file."""
        xml_file = self.data_dir / "official-cpe-dictionary_v2.3.xml"
        if not xml_file.exists():
            logger.warning(f"CPE dictionary not found: {xml_file}")
            return {}
            
        logger.info("Loading CPE dictionary...")
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Define namespace
            ns = {'cpe': 'http://cpe.mitre.org/dictionary/2.0'}
            
            for cpe_item in root.findall('.//cpe:cpe-item', ns):
                cpe_name = cpe_item.get('name')
                if cpe_name:
                    # Extract basic info
                    cpe_info = {
                        'name': cpe_name,
                        'title': '',
                        'references': []
                    }
                    
                    # Get title
                    title_elem = cpe_item.find('.//cpe:title', ns)
                    if title_elem is not None:
                        cpe_info['title'] = title_elem.text or ''
                    
                    # Get references
                    for ref in cpe_item.findall('.//cpe:reference', ns):
                        ref_info = {
                            'href': ref.get('href', ''),
                            'description': ref.text or ''
                        }
                        cpe_info['references'].append(ref_info)
                    
                    self.cpe_dict[cpe_name] = cpe_info
                    
            logger.info(f"Loaded {len(self.cpe_dict)} CPEs from dictionary")
            
        except Exception as e:
            logger.error(f"Error loading CPE dictionary: {e}")
            
        return self.cpe_dict
    
    def build_cpe_match_index(self) -> Dict[str, List[str]]:
        """Build index from CPE match chunks for fast lookup."""
        chunks_dir = self.data_dir / "nvdcpematch-2.0-chunks"
        if not chunks_dir.exists():
            logger.warning(f"CPE match chunks directory not found: {chunks_dir}")
            return {}
            
        logger.info("Building CPE match index...")
        
        # Load all chunk files
        chunk_files = list(chunks_dir.glob("*.json"))
        logger.info(f"Found {len(chunk_files)} chunk files")
        
        for chunk_file in chunk_files:
            try:
                with open(chunk_file, 'r', encoding='utf-8') as f:
                    chunk_data = json.load(f)
                
                # Process matches in this chunk
                matches = chunk_data.get('matches', [])
                for match in matches:
                    cpe_name = match.get('cpeName')
                    cve_id = match.get('cveId')
                    
                    if cpe_name and cve_id:
                        if cpe_name not in self.cpe_match_index:
                            self.cpe_match_index[cpe_name] = []
                        self.cpe_match_index[cpe_name].append(cve_id)
                        
                self.loaded_chunks.add(chunk_file.name)
                
            except Exception as e:
                logger.error(f"Error loading chunk {chunk_file}: {e}")
                
        logger.info(f"Built index for {len(self.cpe_match_index)} CPEs")
        return self.cpe_match_index
    
    def find_cves_for_cpe(self, cpe_name: str) -> List[dict]:
        """Find all CVEs that affect a given CPE."""
        if cpe_name not in self.cpe_match_index:
            return []
            
        cve_ids = self.cpe_match_index[cpe_name]
        cves = []
        
        for cve_id in cve_ids:
            if cve_id in self.cve_data:
                cves.append(self.cve_data[cve_id])
                
        return cves
    
    def find_cpe_matches(self, product: str, version: str = None) -> List[str]:
        """Find CPEs that match a product and optional version."""
        matches = []
        product_lower = product.lower()
        
        for cpe_name in self.cpe_dict.keys():
            # Simple matching - can be improved with regex
            if product_lower in cpe_name.lower():
                if version is None or version in cpe_name:
                    matches.append(cpe_name)
                    
        return matches
    
    def get_cve_details(self, cve_id: str) -> Optional[dict]:
        """Get detailed information about a specific CVE."""
        return self.cve_data.get(cve_id)
    
    def get_cpe_details(self, cpe_name: str) -> Optional[dict]:
        """Get detailed information about a specific CPE."""
        return self.cpe_dict.get(cpe_name)
    
    def load_all_data(self, years: List[str] = None) -> None:
        """Load all NVD data (CVE, CPE dictionary, and CPE matches)."""
        logger.info("Loading all NVD data...")
        
        # Load CVE data
        self.load_cve_data(years)
        
        # Load CPE dictionary
        self.load_cpe_dictionary()
        
        # Build CPE match index
        self.build_cpe_match_index()
        
        logger.info("All NVD data loaded successfully!")

# Global loader instance
nvd_loader = None

def get_nvd_loader() -> NVDDataLoader:
    """Get or create the global NVD data loader."""
    global nvd_loader
    if nvd_loader is None:
        nvd_loader = NVDDataLoader()
        nvd_loader.load_all_data()
    return nvd_loader 