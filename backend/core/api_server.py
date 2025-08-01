from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Dict

from scanner import host_discovery, fast_scanner, service_scanner
from logger import log_message, get_logs, clear_logs, stream_log_generator

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

@app.post("/discover")
def discover_hosts(request: ScanRequest):
    target = request.target
    log_message(f"Discovering hosts for subnet: {target}")
    try:
        hosts = host_discovery.discover_live_hosts(target)
        log_message(f"Discovered {len(hosts)} live hosts.")
        return hosts
    except Exception as e:
        log_message(f"Error discovering hosts: {str(e)}")
        raise HTTPException(status_code=500, detail="Discovery failed.")

@app.post("/scan")
def scan_network(request: ScanRequest):
    target_input = request.target
    clear_logs()
    log_message(f"Initiating scan for: {target_input}")

    try:
        live_hosts = [target_input]
        results = []

        for host in live_hosts:
            log_message(f"→ Scanning host: {host}")
            ports = fast_scanner.port_scan(host)
            open_ports = fast_scanner.extract_open_ports_and_protocols(ports, host)
            log_message(f"→ Open ports found: {open_ports}")
            enriched = service_scanner.service_scan(host, open_ports)
            log_message(f"→ Service scan complete for {host}")
            results.append({
                "host": host,
                "open_ports": open_ports,
                "services": enriched
            })

        log_message("✅ Scan finished.")
        return {"results": results, "logs": get_logs()}

    except Exception as e:
        log_message(f"❌ Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed.")

@app.get("/log-stream")
def log_stream():
    return StreamingResponse(stream_log_generator(), media_type="text/event-stream")

class ExploitRequest(BaseModel):
    host: str
    services: List[Dict]

@app.post("/exploit")
def find_exploits(request: ExploitRequest):
    host = request.host
    services = request.services
    clear_logs()
    log_message(f"🎯 Starting exploitation for host: {host}")
    
    try:
        # Import the exploitation module
        from exploit.exploitation import exploit_services, classify_exploits
        
        log_message(f"→ Analyzing {len(services)} services for exploits...")
        
        # Run the exploitation discovery (same as in __init__.py)
        enriched_services = exploit_services(services)
        log_message("→ Exploitation analysis completed.")
        
        # Get the exploit summary data with proper classification
        summary_data = []
        for service in enriched_services:
            exploits = service.get('exploits', [])
            if exploits:
                # Classify the exploits properly
                classified = classify_exploits(exploits)
                
                # Debug: Log some exploit titles for verification
                log_message(f"   🔍 Sample exploits for {service.get('service')} port {service.get('port')}:")
                for i, exploit in enumerate(exploits[:3]):  # Show first 3
                    log_message(f"      {i+1}. {exploit.get('Title', 'No title')}")
                
                summary_data.append({
                    'service': f"{service.get('service', 'Unknown')} {service.get('product', '')} {service.get('version', '')}".strip(),
                    'port': service.get('port'),
                    'total_exploits': len(exploits),
                    'rce_count': len(classified.get('RCE', [])),
                    'dos_count': len(classified.get('DOS', [])),
                    'auth_bypass_count': len(classified.get('AUTH_BYPASS', [])),
                    'info_disclosure_count': len(classified.get('INFO_DISCLOSURE', [])),
                })
                
                # Log the classification for debugging
                log_message(f"   📊 {service.get('service')} (Port {service.get('port')}): "
                          f"Total={len(exploits)}, RCE={len(classified.get('RCE', []))}, "
                          f"DoS={len(classified.get('DOS', []))}, "
                          f"Auth Bypass={len(classified.get('AUTH_BYPASS', []))}, "
                          f"Info Disclosure={len(classified.get('INFO_DISCLOSURE', []))}")
                
                # Debug: Show some classified exploits
                for category, category_exploits in classified.items():
                    if category_exploits:
                        log_message(f"      {category}: {category_exploits[0].get('Title', 'No title')[:50]}...")
            else:
                log_message(f"   ❌ No exploits found for {service.get('service')} on port {service.get('port')}")
        
        log_message("✅ Exploit discovery completed.")
        return {
            "status": "success",
            "summary": summary_data,
            "services": enriched_services,
            "logs": get_logs()
        }
        
    except Exception as e:
        log_message(f"❌ Error during exploit discovery: {str(e)}")
        raise HTTPException(status_code=500, detail="Exploit discovery failed.")

@app.post("/execute-exploits")
def execute_exploits(request: ExploitRequest):
    host = request.host
    services = request.services
    clear_logs()
    log_message(f"🚀 Starting exploit execution for host: {host}")
    
    try:
        # Import smart exploit runner
        from exploit.smart_exploit_runner import run_exploits_smart
        
        log_message(f"→ Running smart exploit execution...")
        successful_exploits = run_exploits_smart(services, host)
        log_message("→ Smart exploit execution completed.")
        
        if successful_exploits:
            log_message(f"✅ SUCCESS! Found {len(successful_exploits)} working exploits!")
            log_message("You can now:")
            log_message("1. Connect to opened backdoors")
            log_message("2. Use successful exploits for further penetration")
            log_message("3. Escalate privileges on compromised services")
        else:
            log_message("❌ No exploits succeeded on this target.")
            log_message("This could mean:")
            log_message("1. Target is well-patched and secure")
            log_message("2. Services are properly configured")
            log_message("3. Network filtering is in place")
            log_message("4. Try testing on Metasploitable 2 for guaranteed results")
        
        return {
            "status": "success",
            "successful_exploits": successful_exploits,
            "total_attempts": len([e for s in services for e in s.get('exploits', [])]),
            "success_count": len(successful_exploits),
            "logs": get_logs()
        }
        
    except Exception as e:
        log_message(f"❌ Error during exploit execution: {str(e)}")
        raise HTTPException(status_code=500, detail="Exploit execution failed.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
