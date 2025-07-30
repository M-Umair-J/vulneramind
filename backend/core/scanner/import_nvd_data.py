#!/usr/bin/env python3
"""
NVD Data Import Script for SQLite Database

This script imports NVD CVE and CPE data into a SQLite database for efficient
offline vulnerability analysis. The SQLite approach provides:

- Much faster startup times (seconds vs minutes)
- Lower memory usage (MB vs GB)
- Faster lookups with indexed queries
- Persistent storage between runs

Usage:
    python import_nvd_data.py [--force-reimport] [--years 2023,2024,2025]

Example:
    python import_nvd_data.py --force-reimport --years 2023,2024,2025
"""

import argparse
import sys
import time
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

from scanner.sqlite_data_loader import SQLiteNVDLoader

def main():
    parser = argparse.ArgumentParser(description='Import NVD data into SQLite database')
    parser.add_argument('--force-reimport', action='store_true', 
                       help='Force reimport even if data already exists')
    parser.add_argument('--years', type=str, default='2023,2024,2025',
                       help='Comma-separated list of years to import (default: 2023,2024,2025)')
    parser.add_argument('--data-dir', type=str, default='backend/core/data',
                       help='Directory containing NVD data files')
    
    args = parser.parse_args()
    
    # Parse years
    years = [year.strip() for year in args.years.split(',')]
    
    print("=" * 60)
    print("NVD Data Import Script for SQLite Database")
    print("=" * 60)
    print(f"Data directory: {args.data_dir}")
    print(f"Years to import: {', '.join(years)}")
    print(f"Force reimport: {args.force_reimport}")
    print()
    
    # Check if data directory exists
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"❌ Error: Data directory '{data_dir}' does not exist!")
        print("Please ensure you have downloaded the NVD data files:")
        print("  - official-cpe-dictionary_v2.3.xml")
        print("  - nvdcve-2.0-YYYY.json files")
        return 1
    
    # Check for required files
    required_files = [
        "official-cpe-dictionary_v2.3.xml"
    ] + [f"nvdcve-2.0-{year}.json" for year in years]
    
    missing_files = []
    for file in required_files:
        if not (data_dir / file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Error: Missing required files:")
        for file in missing_files:
            print(f"  - {file}")
        print("\nPlease download the missing files from:")
        print("  - CPE Dictionary: https://nvd.nist.gov/products/cpe")
        print("  - CVE Feeds: https://nvd.nist.gov/vuln/data-feeds")
        return 1
    
    print("✅ All required files found!")
    print()
    
    # Initialize loader
    print("Initializing SQLite database...")
    loader = SQLiteNVDLoader(data_dir=str(data_dir))
    
    # Import CPE dictionary
    print("\n📦 Importing CPE dictionary...")
    start_time = time.time()
    loader.import_cpe_dictionary(force_reimport=args.force_reimport)
    cpe_time = time.time() - start_time
    print(f"✅ CPE dictionary imported in {cpe_time:.1f} seconds")
    
    # Import CVE data
    print(f"\n📦 Importing CVE data for years: {', '.join(years)}...")
    start_time = time.time()
    loader.import_cve_data(years=years, force_reimport=args.force_reimport)
    cve_time = time.time() - start_time
    print(f"✅ CVE data imported in {cve_time:.1f} seconds")
    
    # Get database statistics
    print("\n📊 Database Statistics:")
    stats = loader.get_database_stats()
    print(f"  - CPEs: {stats['cpe_count']:,}")
    print(f"  - CVEs: {stats['cve_count']:,}")
    print(f"  - CPE-CVE matches: {stats['match_count']:,}")
    
    if stats['severity_distribution']:
        print("  - CVE Severity Distribution:")
        for severity, count in sorted(stats['severity_distribution'].items()):
            print(f"    {severity}: {count:,}")
    
    total_time = cpe_time + cve_time
    print(f"\n✅ Import completed in {total_time:.1f} seconds")
    print(f"📁 Database location: {loader.db_path}")
    print("\n🎉 Your NVD data is now ready for offline vulnerability analysis!")
    print("   The SQLite approach will provide much faster startup and lower memory usage.")
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 