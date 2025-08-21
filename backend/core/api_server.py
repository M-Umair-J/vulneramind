#!/usr/bin/env python3
"""
VulneraMind Scanner API - Matches __init__.py functionality exactly
Workflow: Input IP/Subnet -> Discover Hosts -> Select Host -> Scan -> Find Exploits -> AI Recommendations -> Open Metasploit
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime
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
        # Clean the target input by stripping whitespace
        target = request.target.strip()
        print(f"🔍 Discovering hosts for: {target}")
        
        # Use the same function as __init__.py
        live_hosts = host_discovery.discover_live_hosts(target)
        
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
        # Clean inputs by stripping whitespace
        target = request.host.strip()
        ports = request.ports.strip()
        
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
        target = request.host.strip()
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
        target = request.host.strip()
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
            print("⚠️ No exploits found for AI analysis")
            return {
                "success": True,
                "message": "No exploits found for the scanned services",
                "recommendations": [],
                "metadata": {
                    "total_exploits_analyzed": 0,
                    "recommendations_generated": 0,
                    "analysis_status": "No exploits available for analysis"
                }
            }
        
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
        print(f"🤖 Generating vulnerability report for: {request.host.strip()}")
        
        # Import the report generator
        sys.path.insert(0, os.path.join(current_dir, '..', 'ai', 'reporting'))
        from vulnerability_report_generator import generate_vulnerability_report
        
        # Generate the comprehensive report
        report = generate_vulnerability_report(
            target_host=request.host.strip(),
            scan_results=request.scan_results,
            exploit_results=request.exploit_results or [],
            ai_recommendations=request.ai_recommendations or []
        )
        
        # Convert to markdown format
        from vulnerability_report_generator import VulnerabilityReportGenerator
        generator = VulnerabilityReportGenerator()
        markdown_report = generator.format_as_markdown(report)
        
        # Convert markdown to properly formatted HTML
        def markdown_to_html(markdown_text):
            # Replace markdown formatting with proper HTML
            html_text = markdown_text
            
            # Convert headers
            html_text = html_text.replace('# ', '<h1>').replace('\n# ', '</h1>\n<h1>')
            html_text = html_text.replace('## ', '<h2>').replace('\n## ', '</h2>\n<h2>')
            html_text = html_text.replace('### ', '<h3>').replace('\n### ', '</h3>\n<h3>')
            
            # Convert bold text **text** to <strong>text</strong>
            import re
            html_text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_text)
            
            # Convert bullet points
            html_text = re.sub(r'^- (.*?)$', r'<li>\1</li>', html_text, flags=re.MULTILINE)
            html_text = re.sub(r'(<li>.*?</li>)', r'<ul>\1</ul>', html_text, flags=re.DOTALL)
            
            # Convert line breaks to proper paragraphs
            paragraphs = html_text.split('\n\n')
            formatted_paragraphs = []
            for para in paragraphs:
                para = para.strip()
                if para and not para.startswith('<'):
                    para = f'<p>{para}</p>'
                formatted_paragraphs.append(para)
            
            html_text = '\n'.join(formatted_paragraphs)
            
            # Close any open headers
            html_text = html_text.replace('</h1>\n<h1>', '</h1>\n').replace('</h2>\n<h2>', '</h2>\n').replace('</h3>\n<h3>', '</h3>\n')
            if '<h1>' in html_text and '</h1>' not in html_text:
                html_text += '</h1>'
            if '<h2>' in html_text and html_text.count('<h2>') > html_text.count('</h2>'):
                html_text += '</h2>'
            if '<h3>' in html_text and html_text.count('<h3>') > html_text.count('</h3>'):
                html_text += '</h3>'
                
            return html_text
        
        formatted_html_content = markdown_to_html(markdown_report)
        
        # Convert markdown to HTML for download with professional styling
        html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulneraMind Security Assessment Report - {request.host.strip()}</title>
    <style>
        /* Import professional fonts */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        :root {{
            --primary-color: #1e40af;
            --primary-light: #3b82f6;
            --accent-color: #dc2626;
            --warning-color: #ea580c;
            --success-color: #16a34a;
            --background-color: #f8fafc;
            --surface-color: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border-color: #e2e8f0;
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --border-radius: 8px;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--background-color);
            font-size: 14px;
        }}

        .report-container {{
            max-width: 8.5in;
            margin: 0 auto;
            background: var(--surface-color);
            box-shadow: var(--shadow-lg);
            border-radius: var(--border-radius);
            overflow: hidden;
        }}

        .classification-banner {{
            background: linear-gradient(135deg, var(--accent-color), #b91c1c);
            color: white;
            text-align: center;
            padding: 8px 16px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 12px;
        }}

        .report-header {{
            background: linear-gradient(135deg, var(--primary-color), #0891b2);
            color: white;
            padding: var(--spacing-xl);
            text-align: center;
            position: relative;
        }}

        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)" /></svg>');
            opacity: 0.3;
        }}

        .logo-container {{
            margin-bottom: var(--spacing-lg);
            position: relative;
            z-index: 2;
        }}

        .logo-text {{
            font-size: 2rem;
            font-weight: 800;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }}

        .report-title {{
            font-size: 1.8em;
            font-weight: 800;
            margin-bottom: 8px;
            position: relative;
            z-index: 2;
        }}

        .report-subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
            font-weight: 300;
            position: relative;
            z-index: 2;
        }}

        .report-content {{
            padding: var(--spacing-xl);
        }}

        .section {{
            margin-bottom: var(--spacing-xl);
            page-break-inside: avoid;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            margin-bottom: var(--spacing-lg);
            padding-bottom: 8px;
            border-bottom: 2px solid var(--border-color);
        }}

        .section-title {{
            color: var(--primary-color);
            font-size: 1.8rem;
            font-weight: 700;
            margin: 0;
        }}

        .executive-summary {{
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            border-radius: var(--border-radius);
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-xl);
            border: 1px solid var(--border-color);
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: var(--spacing-lg);
            margin: var(--spacing-xl) 0;
        }}

        .metric-card {{
            background: var(--surface-color);
            padding: var(--spacing-lg);
            border-radius: var(--border-radius);
            border: 1px solid var(--border-color);
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .metric-value {{
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--primary-color);
            line-height: 1;
        }}

        .metric-label {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 4px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}

        .vulnerability-card {{
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: var(--spacing-lg);
            margin: var(--spacing-md) 0;
            position: relative;
            border-left: 4px solid var(--accent-color);
        }}

        .vulnerability-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .cve-id {{
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--primary-color);
            font-family: 'JetBrains Mono', monospace;
        }}

        .cvss-score {{
            background: var(--accent-color);
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.875rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        .service-info {{
            background: #f1f5f9;
            padding: var(--spacing-md);
            border-radius: 4px;
            margin: 8px 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
        }}

        .severity-critical {{ border-left-color: #dc2626; }}
        .severity-high {{ border-left-color: #ea580c; }}
        .severity-medium {{ border-left-color: #d97706; }}
        .severity-low {{ border-left-color: #16a34a; }}

        .risk-indicator {{
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }}

        .risk-critical {{ background: #dc2626; color: white; }}
        .risk-high {{ background: #ea580c; color: white; }}
        .risk-medium {{ background: #d97706; color: white; }}
        .risk-low {{ background: #16a34a; color: white; }}

        .code-block {{
            background: #1e293b;
            color: #e2e8f0;
            padding: var(--spacing-md);
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            margin: var(--spacing-md) 0;
            border-left: 4px solid var(--primary-color);
        }}

        .report-footer {{
            background: #1e293b;
            color: white;
            padding: var(--spacing-xl);
            text-align: center;
            margin-top: var(--spacing-xl);
        }}

        .footer-text {{
            font-size: 0.875rem;
            opacity: 0.8;
            margin: 4px 0;
        }}

        h1, h2, h3 {{ color: var(--primary-color); margin: var(--spacing-lg) 0 var(--spacing-md) 0; }}
        h1 {{ font-size: 1.8em; border-bottom: 2px solid var(--primary-color); padding-bottom: 8px; }}
        h2 {{ font-size: 1.4em; }}
        h3 {{ font-size: 1.2em; }}

        strong {{ color: var(--text-primary); }}
        em {{ color: var(--text-secondary); font-style: italic; }}

        pre {{
            background: #f8fafc;
            padding: var(--spacing-md);
            border-radius: var(--border-radius);
            border-left: 4px solid var(--primary-color);
            overflow-x: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        @media print {{
            .report-container {{ box-shadow: none; max-width: none; border-radius: 0; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Classification Banner -->
        <div class="classification-banner">
            🔒 CONFIDENTIAL - VULNERABILITY ASSESSMENT REPORT
        </div>

        <!-- Header -->
        <div class="report-header">
            <div class="logo-container">
                <div class="logo-text">
                    🛡️ VulneraMind Security
                </div>
            </div>
            <h1 class="report-title">Vulnerability Assessment Report</h1>
            <div class="report-subtitle">
                Target: {request.host.strip()} | Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
            </div>
        </div>

        <!-- Content -->
        <div class="report-content">
            {formatted_html_content}
        </div>

        <!-- Footer -->
        <div class="report-footer">
            <div class="footer-text">
                <strong>🛡️ VulneraMind Security Platform</strong>
            </div>
            <div class="footer-text">
                Powered by AI-Driven Vulnerability Assessment Technology
            </div>
            <div class="footer-text">
                Report Classification: CONFIDENTIAL | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
            <div class="footer-text" style="margin-top: 16px; opacity: 0.6;">
                This report contains sensitive security information and should be handled according to your organization's data classification policies.
            </div>
        </div>
    </div>
</body>
</html>"""
        
        print(f"✅ Report generated successfully for {request.host.strip()}")
        
        return {
            "success": True,
            "message": f"Vulnerability report generated for {request.host.strip()}",
            "report": report,
            "markdown": markdown_report,
            "html": html_report,
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
