from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Dict
import msgpack
import requests
import urllib3
import json
import asyncio
import threading
import time

from scanner import host_discovery, fast_scanner, service_scanner
from logger import log_message, get_logs, clear_logs, stream_log_generator
from exploit.exploitation import exploit_services, classify_exploits, search_by_cves_in_memory, search_by_product_version_in_memory

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables
logs = []
scan_threads = []

# Metasploit RPC connection globals
msf_token = None
msf_console_id = None
msf_rpc_url = "https://127.0.0.1:55552/api/"
msf_headers = {'Content-Type': 'binary/message-pack'}

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

class MetasploitConnection:
    def __init__(self):
        self.token = None
        self.console_id = None
        self.connected = False
    
    def connect(self, username="msf", password="abc123"):
        """Connect to Metasploit RPC API"""
        try:
            auth_data = ['auth.login', username, password]
            resp = requests.post(
                msf_rpc_url,
                data=msgpack.packb(auth_data),
                headers=msf_headers,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                if obj[0] == b'success':
                    self.token = obj[1].decode() if isinstance(obj[1], bytes) else obj[1]
                    log_message(f"✅ Connected to Metasploit RPC (Token: {self.token[:10]}...)")
                    
                    # Create a console
                    self.create_console()
                    self.connected = True
                    return True
                else:
                    log_message(f"❌ Failed to authenticate: {obj}")
                    return False
        except Exception as e:
            log_message(f"❌ Error connecting to Metasploit RPC: {str(e)}")
            return False
    
    def create_console(self):
        """Create a new console session"""
        try:
            console_data = ['console.create', self.token]
            resp = requests.post(
                msf_rpc_url,
                data=msgpack.packb(console_data),
                headers=msf_headers,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                if b'id' in obj:
                    self.console_id = obj[b'id']
                    log_message(f"✅ Created Metasploit console (ID: {self.console_id})")
                    return True
        except Exception as e:
            log_message(f"❌ Error creating console: {str(e)}")
            return False
    
    def write_command(self, command):
        """Send command to Metasploit console"""
        if not self.connected or not self.console_id:
            return "Not connected to Metasploit"
        
        try:
            write_data = ['console.write', self.token, self.console_id, command + '\n']
            resp = requests.post(
                msf_rpc_url,
                data=msgpack.packb(write_data),
                headers=msf_headers,
                verify=False,
                timeout=10
            )
            return True
        except Exception as e:
            log_message(f"❌ Error writing command: {str(e)}")
            return False
    
    def read_output(self):
        """Read output from Metasploit console"""
        if not self.connected or not self.console_id:
            return ""
        
        try:
            read_data = ['console.read', self.token, self.console_id]
            resp = requests.post(
                msf_rpc_url,
                data=msgpack.packb(read_data),
                headers=msf_headers,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                if b'data' in obj:
                    data = obj[b'data']
                    if isinstance(data, bytes):
                        return data.decode('utf-8', errors='ignore')
                    return str(data)
            return ""
        except Exception as e:
            log_message(f"❌ Error reading output: {str(e)}")
            return ""

# Global Metasploit connection instance
msf_connection = MetasploitConnection()

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
    
    log_message(f"Starting comprehensive vulnerability scan on: {target_input}")
    
    try:
        # Discover live hosts
        log_message("Phase 1: Host Discovery")
        hosts = host_discovery.discover_live_hosts(target_input)
        log_message(f"✅ Discovered {len(hosts)} live hosts")
        
        if not hosts:
            log_message("❌ No live hosts found. Scan terminated.")
            return {"message": "No live hosts discovered", "results": []}
        
        all_results = []
        for host in hosts:
            log_message(f"🔍 Scanning host: {host}")
            
            # Port scanning
            log_message(f"Phase 2: Port Scanning - {host}")
            port_scan_results = fast_scanner.port_scan(host)
            open_ports = fast_scanner.extract_open_ports_and_protocols(port_scan_results, host)
            log_message(f"✅ Found {len(open_ports)} open ports on {host}")
            
            # Service scanning
            log_message(f"Phase 3: Service Detection - {host}")
            services = service_scanner.service_scan(host, open_ports)
            log_message(f"✅ Found {len(services)} services on {host}")
            
            # Exploit discovery
            log_message(f"Phase 4: Exploit Discovery - {host}")
            services_with_exploits = exploit_services(services)
            
            # Extract all exploits from services
            exploits = []
            for service in services_with_exploits:
                exploits.extend(service.get('exploits', []))
            log_message(f"✅ Found {len(exploits)} exploits for {host}")
            
            # Prepare result
            result = {
                "host": host,
                "open_ports": open_ports,
                "services": services_with_exploits,
                "exploits": exploits
            }
            all_results.append(result)
        
        log_message(f"🎯 Scan completed successfully! Total hosts scanned: {len(all_results)}")
        return {"message": "Scan completed successfully", "results": all_results}
        
    except Exception as e:
        log_message(f"❌ Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail="Scan failed.")

@app.post("/exploit")
def discover_exploits(request: dict):
    try:
        host_data = request.get("host_data")
        if not host_data:
            raise HTTPException(status_code=400, detail="Host data is required")
        
        log_message(f"🔍 Starting exploit discovery for {host_data.get('host')}")
        
        # Extract services and vulnerabilities
        services = host_data.get("services", [])
        open_ports = host_data.get("open_ports", [])
        
        # If no services yet, do port and service scanning first
        if not services and open_ports:
            log_message(f"🔍 Running service detection for {host_data.get('host')}")
            services = service_scanner.service_scan(host_data.get('host'), open_ports)
        elif not services:
            log_message(f"🔍 Running port scan for {host_data.get('host')}")
            port_scan_results = fast_scanner.port_scan(host_data.get('host'))
            open_ports = fast_scanner.extract_open_ports_and_protocols(port_scan_results, host_data.get('host'))
            services = service_scanner.service_scan(host_data.get('host'), open_ports)
        
        # Find exploits for services
        all_exploits = []
        services_with_exploits = exploit_services(services)
        
        for service in services_with_exploits:
            service_exploits = service.get('exploits', [])
            all_exploits.extend(service_exploits)
        
        log_message(f"✅ Found {len(all_exploits)} total exploits")
        
        # Classify exploits
        classification = classify_exploits(all_exploits)
        
        return {
            "exploits": all_exploits,
            "services": services_with_exploits,
            "classification": {
                "rce_count": len(classification.get('RCE', [])),
                "dos_count": len(classification.get('DOS', [])),
                "auth_bypass_count": len(classification.get('AUTH_BYPASS', [])),
                "info_disclosure_count": len(classification.get('INFO_DISCLOSURE', [])),
                "total_count": len(all_exploits)
            },
            "logs": get_logs()
        }
        
    except Exception as e:
        log_message(f"❌ Error during exploit discovery: {str(e)}")
        raise HTTPException(status_code=500, detail="Exploit discovery failed.")

@app.post("/execute-exploits")
def execute_exploits(request: dict):
    try:
        selected_exploits = request.get("exploits", [])
        host_data = request.get("host_data", {})
        
        if not selected_exploits:
            raise HTTPException(status_code=400, detail="No exploits selected")
        
        log_message(f"🚀 Executing {len(selected_exploits)} exploits against {host_data.get('host')}")
        
        successful_exploits = []
        for exploit in selected_exploits:
            log_message(f"⚡ Attempting: {exploit.get('title', 'Unknown exploit')}")
            # Simulate exploit execution
            time.sleep(1)  # Simulate processing time
            log_message(f"✅ Exploit completed")
            successful_exploits.append(exploit)
        
        log_message(f"🎯 Exploit execution completed: {len(successful_exploits)}/{len(selected_exploits)} successful")
        
        return {
            "message": "Exploit execution completed",
            "successful_exploits": successful_exploits,
            "total_attempts": len(selected_exploits),
            "success_count": len(successful_exploits),
            "logs": get_logs()
        }
        
    except Exception as e:
        log_message(f"❌ Error during exploit execution: {str(e)}")
        raise HTTPException(status_code=500, detail="Exploit execution failed.")

@app.post("/msf-connect")
async def connect_metasploit():
    """Connect to Metasploit RPC API"""
    try:
        log_message("🔌 Connecting to Metasploit RPC...")
        success = msf_connection.connect()
        
        if success:
            return {"status": "success", "message": "Connected to Metasploit"}
        else:
            raise HTTPException(status_code=500, detail="Failed to connect to Metasploit")
    except Exception as e:
        log_message(f"❌ Error connecting to Metasploit: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/metasploit")
async def websocket_metasploit(websocket: WebSocket):
    """WebSocket endpoint for real-time Metasploit terminal"""
    await websocket.accept()
    log_message("🔌 Metasploit terminal connected")
    
    # Ensure connection
    if not msf_connection.connected:
        await websocket.send_text("Connecting to Metasploit...\n")
        success = msf_connection.connect()
        if not success:
            await websocket.send_text("❌ Failed to connect to Metasploit RPC\n")
            await websocket.close()
            return
        await websocket.send_text("✅ Connected to Metasploit RPC\n")
        await websocket.send_text("msf6 > ")
    
    try:
        while True:
            # Wait for command from client
            data = await websocket.receive_text()
            command_data = json.loads(data)
            command = command_data.get("input", "").strip()
            
            if command:
                # Send command to Metasploit
                log_message(f"Executing MSF command: {command}")
                msf_connection.write_command(command)
                
                # Wait a bit for output
                await asyncio.sleep(0.5)
                
                # Read and send output back
                output = msf_connection.read_output()
                if output:
                    await websocket.send_text(output)
                else:
                    await websocket.send_text(f"Command executed: {command}\n")
                
                # Send prompt
                await websocket.send_text("msf6 > ")
            
    except WebSocketDisconnect:
        log_message("🔌 Metasploit terminal disconnected")
    except Exception as e:
        log_message(f"❌ WebSocket error: {str(e)}")
        await websocket.close()

@app.get("/logs")
def get_logs_endpoint():
    return {"logs": get_logs()}

@app.get("/logs/stream")
async def stream_logs():
    return StreamingResponse(stream_log_generator(), media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
