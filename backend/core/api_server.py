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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
