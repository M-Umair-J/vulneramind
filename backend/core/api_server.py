#!/usr/bin/env python3
"""
VulneraMind Scanner API - Matches __init__.py functionality exactly
Workflow: Input IP/Subnet -> Discover Hosts -> Select Host -> Scan -> Find Exploits -> AI Recommendations -> Open Metasploit
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
import sys
import platform
import subprocess

# Add the current directory to Python path for direct execution
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import scanner modules (same as __init__.py)
import scanner.fast_scanner as fast_scanner
import scanner.service_scanner as service_scanner
import scanner.host_discovery as host_discovery
from exploit.exploitation import exploit_services, present_exploit_summary
from find_metasploit_exploit import find_metasploit_exploit

app = FastAPI(title="VulneraMind Scanner API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Models
class HostDiscoveryRequest(BaseModel):
    target: str  # IP or subnet

class HostScanRequest(BaseModel):
    host: str
    ports: str = "1-1000"

class ExploitSearchRequest(BaseModel):
    host: str
    scan_results: List[Dict[str, Any]]

class AIRecommendationRequest(BaseModel):
    host: str
    exploit_results: List[Dict[str, Any]]

class VulnerabilityReportRequest(BaseModel):
    host: str
    scan_results: List[Dict[str, Any]]
    exploit_results: Optional[List[Dict[str, Any]]] = None
    ai_recommendations: Optional[List[Dict[str, Any]]] = None

# Response Models
class HostDiscoveryResponse(BaseModel):
    hosts: List[str]
    total_hosts: int

class ScanResult(BaseModel):
    port: int
    protocol: str
    service: str
    product: str
    version: str
    confidence: str
    cves: List[Dict[str, Any]]
    cve_summary: Dict[str, Any]

class HostScanResponse(BaseModel):
    host: str
    scan_results: List[ScanResult]
    total_services: int

class ExploitResult(BaseModel):
    Title: str
    Description: str
    Type: str
    Platform: str
    Path: str

class ExploitSearchResponse(BaseModel):
    host: str
    exploits: List[Dict[str, Any]]
    total_exploits: int
    exploitation_summary: Dict[str, Any]

class AIRecommendation(BaseModel):
    exploit: Dict[str, Any]
    ai_suggestion: Dict[str, Any]
    exploit_data: Dict[str, Any]

class AIRecommendationResponse(BaseModel):
    host: str
    recommendations: List[AIRecommendation]
    total_recommendations: int

@app.get("/")
async def root():
    return {"message": "VulneraMind Scanner API - Ready", "workflow": "IP/Subnet -> Discover -> Scan -> Exploits -> AI -> Metasploit"}

@app.post("/discover-hosts", response_model=HostDiscoveryResponse)
async def discover_hosts(request: HostDiscoveryRequest):
    """
    Step 1: Discover live hosts from IP or subnet (matches __init__.py line 14)
    """
    try:
        print(f"🔍 Discovering hosts for: {request.target}")
        
        # Use the same function as __init__.py
        live_hosts = host_discovery.discover_live_hosts(request.target)
        
        if not live_hosts:
            raise HTTPException(status_code=404, detail="No live hosts found in the given range/subnet")
        
        print(f"✅ Found {len(live_hosts)} live hosts: {live_hosts}")
        
        return HostDiscoveryResponse(
            hosts=live_hosts,
            total_hosts=len(live_hosts)
        )
        
    except Exception as e:
        print(f"❌ Host discovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Host discovery failed: {str(e)}")

@app.post("/scan-host", response_model=HostScanResponse)
async def scan_host(request: HostScanRequest):
    """
    Step 2: Scan selected host for services and CVEs (matches __init__.py lines 37-77)
    """
    try:
        target = request.host
        ports = request.ports
        
        print(f"🎯 Scanning host: {target} (ports: {ports})")
        
        # Step 1: Fast port scan (same as __init__.py line 39)
        results = fast_scanner.port_scan(target, ports)
        filtered_ports = fast_scanner.extract_open_ports_and_protocols(results, target)
        print(f"🔍 Found open ports: {filtered_ports}")
        
        # Step 2: Service detection with CVE mapping (same as __init__.py line 43)
        enriched_results = service_scanner.service_scan(target, filtered_ports)
        print(f"✅ Service scan completed, found {len(enriched_results)} services")
        
        # Format results same as __init__.py display format
        scan_results = []
        for item in enriched_results:
            scan_result = ScanResult(
                port=item.get('port', 0),
                protocol=item.get('protocol', 'Unknown'),
                service=item.get('service', 'Unknown'),
                product=item.get('product', 'Unknown'),
                version=item.get('version', 'Unknown'),
                confidence=item.get('confidence', 'Unknown'),
                cves=item.get('cves', []),
                cve_summary=item.get('cve_summary', {})
            )
            scan_results.append(scan_result)
        
        return HostScanResponse(
            host=target,
            scan_results=scan_results,
            total_services=len(scan_results)
        )
        
    except Exception as e:
        print(f"❌ Host scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Host scan failed: {str(e)}")

@app.post("/find-exploits", response_model=ExploitSearchResponse)
async def find_exploits(request: ExploitSearchRequest):
    """
    Step 3: Find exploits for scanned services (matches __init__.py lines 79-86)
    """
    try:
        target = request.host
        enriched_results = request.scan_results
        
        print(f"💥 Finding exploits for: {target}")
        
        if not enriched_results:
            raise HTTPException(status_code=400, detail="No scan results provided")
        
        # Run exploitation module (same as __init__.py line 82)
        exploit_results = exploit_services(enriched_results)
        print(f"✅ Exploitation analysis completed")
        
        # Collect all exploits from all services
        all_exploits = []
        for service in enriched_results:
            exploits = service.get('exploits', [])
            all_exploits.extend(exploits)
        
        # Create exploitation summary
        exploitation_summary = {
            "total_exploits": len(all_exploits),
            "services_with_exploits": len([s for s in enriched_results if s.get('exploits')]),
            "total_services": len(enriched_results)
        }
        
        return ExploitSearchResponse(
            host=target,
            exploits=enriched_results,  # Contains services with their exploits
            total_exploits=len(all_exploits),
            exploitation_summary=exploitation_summary
        )
        
    except Exception as e:
        print(f"❌ Exploit search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Exploit search failed: {str(e)}")

@app.post("/ai-recommendations", response_model=AIRecommendationResponse)
async def get_ai_recommendations(request: AIRecommendationRequest):
    """
    Step 4: Generate AI Metasploit recommendations (matches __init__.py lines 148-221)
    """
    try:
        target = request.host
        enriched_results = request.exploit_results
        
        print(f"🤖 Generating AI Metasploit recommendations for: {target}")
        
        # Collect all exploits from all services (same as __init__.py lines 154-166)
        all_exploits = []
        for service in enriched_results:
            exploits = service.get('exploits', [])
            for exploit in exploits:
                # Prepare exploit data for AI (same format as __init__.py lines 158-165)
                exploit_data = {
                    'host': target,
                    'port': service.get('port'),
                    'service': service.get('service'),
                    'product': service.get('product', 'Unknown'),
                    'version': service.get('version', 'Unknown'),
                    'exploit_title': exploit.get('Title', ''),
                    'exploit_description': exploit.get('Description', ''),
                    'exploit_type': exploit.get('Type', ''),
                    'exploit_platform': exploit.get('Platform', ''),
                    'exploit_path': exploit.get('Path', ''),
                    'cves': service.get('cves', [])
                }
                all_exploits.append((exploit, exploit_data))
        
        if not all_exploits:
            raise HTTPException(status_code=404, detail="No exploits found to analyze")
        
        # With local AI, we can process all exploits without quota limits!
        print(f"🎯 Processing ALL {len(all_exploits)} exploits with local AI...")
        
        recommendations = []
        total_exploits = len(all_exploits)
        
        for i, (exploit, exploit_data) in enumerate(all_exploits, 1):
            # Log progress every 10 exploits instead of every single one
            if i % 10 == 0 or i == 1 or i == total_exploits:
                print(f"📋 Processing exploits: {i}/{total_exploits} ({(i/total_exploits)*100:.1f}%)")
            
            # Get AI suggestion (same as __init__.py line 176)
            ai_suggestion = find_metasploit_exploit(exploit_data)
            
            recommendation = AIRecommendation(
                exploit=exploit,
                ai_suggestion=ai_suggestion,
                exploit_data=exploit_data
            )
            recommendations.append(recommendation)
        
        print(f"✅ Generated {len(recommendations)} AI recommendations")
        
        return AIRecommendationResponse(
            host=target,
            recommendations=recommendations,
            total_recommendations=len(recommendations)
        )
        
    except Exception as e:
        print(f"❌ AI recommendations failed: {e}")
        raise HTTPException(status_code=500, detail=f"AI recommendations failed: {str(e)}")

@app.post("/generate-report")
async def generate_vulnerability_report_endpoint(request: VulnerabilityReportRequest):
    """
    Generate comprehensive AI vulnerability assessment report
    """
    try:
        print(f"🤖 Generating vulnerability report for: {request.host}")
        
        # Import the report generator
        sys.path.insert(0, os.path.join(current_dir, '..', 'ai', 'reporting'))
        from vulnerability_report_generator import generate_vulnerability_report
        
        # Generate the comprehensive report
        report = generate_vulnerability_report(
            target_host=request.host,
            scan_results=request.scan_results,
            exploit_results=request.exploit_results or [],
            ai_recommendations=request.ai_recommendations or []
        )
        
        # Convert to markdown format
        from vulnerability_report_generator import VulnerabilityReportGenerator
        generator = VulnerabilityReportGenerator()
        markdown_report = generator.format_as_markdown(report)
        
        print(f"✅ Report generated successfully for {request.host}")
        
        return {
            "success": True,
            "message": f"Vulnerability report generated for {request.host}",
            "report": report,
            "markdown": markdown_report,
            "metadata": {
                "total_vulnerabilities": sum(len(service.get('cves', [])) for service in request.scan_results),
                "total_services": len(request.scan_results),
                "report_length": len(markdown_report),
                "generation_timestamp": report['metadata']['scan_date']
            }
        }
        
    except Exception as e:
        print(f"❌ Report generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.post("/open-metasploit")
async def open_metasploit():
    """
    Step 5: Open Metasploit RPC terminal (matches __init__.py lines 88-147)
    """
    try:
        print("⚡ Opening Metasploit terminal...")
        
        # Check if we're on Windows or Linux/WSL (same as __init__.py lines 93-94)
        system = platform.system().lower()
        
        if system == "windows":
            try:
                # Windows command (same as __init__.py line 96)
                os.system("start cmd /k python e:\\vulneramind_on_cursor\\vulneramind\\backend\\core\\msf_rpc_terminal.py")
                return {"message": "✅ Metasploit terminal opened in new Windows terminal", "success": True}
            except Exception as e:
                print(f"❌ Failed to open Windows terminal: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to open Windows terminal: {str(e)}")
        else:
            # Linux/WSL approach (same as __init__.py lines 101-139)
            terminal_opened = False
            
            # Available terminal commands (same as __init__.py lines 105-111)
            terminal_commands = [
                ("gnome-terminal", "gnome-terminal -- python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                ("xterm", "xterm -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                ("konsole", "konsole -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                ("terminator", "terminator -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py"),
                ("x-terminal-emulator", "x-terminal-emulator -e python3 /mnt/e/vulneramind_on_cursor/vulneramind/backend/core/msf_rpc_terminal.py")
            ]
            
            # Check which terminals are available (same as __init__.py lines 113-119)
            available_terminals = []
            for term_name, term_cmd in terminal_commands:
                try:
                    result = subprocess.run(["which", term_name], capture_output=True, text=True)
                    if result.returncode == 0:
                        available_terminals.append((term_name, term_cmd))
                except:
                    continue
            
            # Try to open with available terminals (same as __init__.py lines 121-131)
            for term_name, term_cmd in available_terminals:
                try:
                    subprocess.Popen(term_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return {"message": f"✅ Metasploit terminal opened using {term_name}", "success": True}
                except Exception as e:
                    print(f"❌ Failed to open {term_name}: {e}")
                    continue
            
            # If no terminal worked (same as __init__.py lines 133-139)
            if not terminal_opened:
                error_msg = ("❌ Could not open terminal automatically. "
                           "🔧 No suitable terminal emulator found. "
                           "📋 Please run manually: cd /mnt/e/vulneramind_on_cursor/vulneramind/backend/core && python3 msf_rpc_terminal.py")
                raise HTTPException(status_code=500, detail=error_msg)
        
    except Exception as e:
        print(f"❌ Failed to open Metasploit: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to open Metasploit terminal: {str(e)}")

if __name__ == "__main__":
    print("🚀 Starting VulneraMind Scanner API Server...")
    print("📋 Workflow: IP/Subnet -> Discover -> Scan -> Exploits -> AI -> Metasploit")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
