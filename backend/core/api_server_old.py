from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Dict

from scanner import host_discovery, fast_scanner, service_scanner
from logger import log_message, get_logs, clear_logs, stream_log_generator
import subprocess
import asyncio
import os
import tempfile
import signal
import time
import threading
import queue
import requests
import json

# Add this global variable to track current working directory
current_wd = os.path.expanduser("~")

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

def start_metasploit():
    global metasploit_process, current_wd
    try:
        # Kill any existing process
        if metasploit_process:
            metasploit_process.terminate()
            metasploit_process.wait()
        
        # Start msfconsole in the metasploit-framework directory
        metasploit_process = subprocess.Popen(
            ['./msfconsole'],
            cwd=os.path.expanduser("~/metasploit-framework"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Wait for msfconsole to start
        time.sleep(3)
        
        return True
    except Exception as e:
        log_message(f"❌ Error during exploit execution: {str(e)}")
        raise HTTPException(status_code=500, detail="Exploit execution failed.")

        
if __name__ == "__main__":
        return False

def send_metasploit_command(command):
    global metasploit_process
    if not metasploit_process or metasploit_process.poll() is not None:
        return "Metasploit is not running. Start it first with ./msfconsole"
    
    try:
        # Send command to msfconsole
        metasploit_process.stdin.write(command + '\n')
        metasploit_process.stdin.flush()
        
        # Wait a bit for output
        time.sleep(1)
        
        # Read available output
        output = ""
        while True:
            try:
                line = metasploit_process.stdout.readline()
                if not line:
                    break
                output += line
                # Stop reading when we see the prompt
                if 'msf6' in line and '>' in line:
                    break
            except:
                break
        
        return output if output else f"Command '{command}' sent to Metasploit"
        
    except Exception as e:
        return f"Error sending command: {str(e)}"

def connect_to_metasploit_rpc():
    """Connect to Metasploit RPC API"""
    global msf_rpc_client, msf_token
    
    try:
        log_message("Starting Metasploit RPC connection...")
        
        # Check if msfrpcd is already running
        check_running = subprocess.run(
            ['bash', '-c', 'ps aux | grep msfrpcd | grep -v grep'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if check_running.returncode == 0:
            log_message("msfrpcd is already running")
            # Extract PID from the output
            pid_line = check_running.stdout.strip().split('\n')[0]
            pid = pid_line.split()[1]
            log_message(f"msfrpcd running with PID: {pid}")
        else:
            log_message("msfrpcd not running, starting it...")
            
            # Kill any existing msfrpcd processes first
            subprocess.run(
                ['bash', '-c', 'pkill -f msfrpcd'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            time.sleep(2)
            
            # Start msfrpcd with full path and proper working directory
            start_cmd = f"cd {os.path.expanduser('~/metasploit-framework')} && ./msfrpcd -P password123 -a 127.0.0.1 -p 55553"
            log_message(f"Starting command: {start_cmd}")
            
            # Start in background
            result = subprocess.run(
                ['bash', '-c', f"{start_cmd} &"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=os.path.expanduser("~/metasploit-framework")
            )
            
            log_message(f"Start result: {result.stdout} {result.stderr}")
            
            # Wait for msfrpcd to start
            log_message("Waiting for msfrpcd to start...")
            time.sleep(5)
        
        # Check if msfrpcd is now running
        check_again = subprocess.run(
            ['bash', '-c', 'ps aux | grep msfrpcd | grep -v grep'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        log_message(f"msfrpcd check: {check_again.stdout}")
        
        if check_again.returncode != 0:
            log_message("msfrpcd failed to start")
            return False
        
        # Test if port 55553 is listening
        port_check = subprocess.run(
            ['bash', '-c', 'netstat -tlnp | grep 55553'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        log_message(f"Port check: {port_check.stdout}")
        
        if port_check.returncode != 0:
            log_message("Port 55553 is not listening")
            return False
        
        # Now try to connect to RPC API
        log_message("Attempting to connect to RPC API...")
        rpc_url = "http://127.0.0.1:55553/api"
        
        # First, check if the API is responding
        try:
            test_response = requests.get(f"{rpc_url}/version", timeout=10)
            log_message(f"API test response: {test_response.status_code} - {test_response.text}")
        except Exception as e:
            log_message(f"API test failed: {str(e)}")
            return False
        
        # Authenticate
        auth_data = {
            "username": "msf",
            "password": "password123"
        }
        
        log_message(f"Sending auth request to {rpc_url}/auth/login")
        response = requests.post(f"{rpc_url}/auth/login", json=auth_data, timeout=10)
        log_message(f"Auth response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            msf_token = response.json()["token"]
            msf_rpc_client = requests.Session()
            msf_rpc_client.headers.update({"Authorization": f"Bearer {msf_token}"})
            log_message("Successfully connected to Metasploit RPC API")
            return True
        else:
            log_message(f"Failed to authenticate with Metasploit RPC: {response.text}")
            return False
            
    except Exception as e:
        log_message(f"Failed to connect to Metasploit RPC: {str(e)}")
        return False

def execute_metasploit_command(command):
    """Execute a Metasploit command via RPC API"""
    global msf_rpc_client, msf_token
    
    if not msf_rpc_client or not msf_token:
        return "Not connected to Metasploit RPC API"
    
    try:
        # Parse the command
        if command.startswith('use '):
            module_path = command[4:]
            # Use the module
            response = msf_rpc_client.post(
                "http://127.0.0.1:55553/api/console/write",
                json={"console_id": "1", "data": f"use {module_path}\n"}
            )
            return f"Using module: {module_path}"
            
        elif command.startswith('set '):
            parts = command[4:].split(' ')
            if len(parts) >= 2:
                option, value = parts[0], ' '.join(parts[1:])
                response = msf_rpc_client.post(
                    "http://127.0.0.1:55553/api/console/write",
                    json={"console_id": "1", "data": f"set {option} {value}\n"}
                )
                return f"Set {option} => {value}"
            else:
                return "Invalid set command format"
                
        elif command in ['exploit', 'run']:
            response = msf_rpc_client.post(
                "http://127.0.0.1:55553/api/console/write",
                json={"console_id": "1", "data": "exploit\n"}
            )
            return "Executing exploit..."
            
        elif command.startswith('show '):
            what = command[5:]
            response = msf_rpc_client.post(
                "http://127.0.0.1:55553/api/console/write",
                json={"console_id": "1", "data": f"show {what}\n"}
            )
            # Read the output
            time.sleep(1)
            read_response = msf_rpc_client.get("http://127.0.0.1:55553/api/console/read", params={"console_id": "1"})
            if read_response.status_code == 200:
                return read_response.json().get("data", f"Showing {what}")
            return f"Showing {what}"
            
        else:
            # Generic command
            response = msf_rpc_client.post(
                "http://127.0.0.1:55553/api/console/write",
                json={"console_id": "1", "data": f"{command}\n"}
            )
            return f"Command '{command}' executed"
            
    except Exception as e:
        return f"Error executing command: {str(e)}"

@app.post("/execute-wsl-command")
async def execute_wsl_command(request: Request):
    global current_wd, msf_rpc_client
    
    try:
        data = await request.json()
        command = data.get('command', '')
        
        if not command:
            raise HTTPException(status_code=400, detail="No command provided")
        
        log_message(f"Executing command: {command} from {current_wd}")
        
        # Handle cd command specially
        if command.startswith('cd '):
            new_dir = command[3:].strip()
            if new_dir == '~' or new_dir == '~/metasploit-framework':
                current_wd = os.path.expanduser("~/metasploit-framework")
            elif new_dir.startswith('~/'):
                current_wd = os.path.expanduser(new_dir)
            elif new_dir.startswith('/'):
                current_wd = new_dir
            else:
                current_wd = os.path.join(current_wd, new_dir)
            
            return {
                "success": True,
                "output": f"Changed directory to: {current_wd}",
                "return_code": 0,
                "command": command,
                "current_directory": current_wd
            }
        
        # Handle msfconsole startup
        if command in ['./msfconsole', 'msfconsole']:
            if connect_to_metasploit_rpc():
                return {
                    "success": True,
                    "output": "🚀 Connected to Metasploit RPC API successfully!\n\nmsf6 > \n\nYou can now run Metasploit commands via RPC.",
                    "return_code": 0,
                    "command": command,
                    "current_directory": current_wd,
                    "is_interactive": True
                }
            else:
                return {
                    "success": False,
                    "output": "Failed to connect to Metasploit RPC API",
                    "return_code": 1,
                    "command": command,
                    "current_directory": current_wd
                }
        
        # Handle Metasploit commands via RPC
        if command.startswith(('use ', 'set ', 'show ', 'exploit', 'run', 'search ', 'info ')):
            if not msf_rpc_client:
                return {
                    "success": False,
                    "output": "Not connected to Metasploit RPC API. Start it first with ./msfconsole",
                    "return_code": 1,
                    "command": command,
                    "current_directory": current_wd
                }
            
            # Execute command via RPC
            output = execute_metasploit_command(command)
            
            return {
                "success": True,
                "output": output,
                "return_code": 0,
                "command": command,
                "current_directory": current_wd
            }
        
        # For other commands, run from the current working directory
        result = subprocess.run(
            ['bash', '-c', command],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=current_wd
        )
        
        output = result.stdout + result.stderr
        
        log_message(f"Command completed with return code: {result.returncode}")
        if result.stderr:
            log_message(f"Stderr: {result.stderr}")
        
        return {
            "success": result.returncode == 0,
            "output": output,
            "return_code": result.returncode,
            "command": command,
            "current_directory": current_wd
        }
        
    except subprocess.TimeoutExpired:
        log_message(f"Command execution timed out: {command}")
        raise HTTPException(status_code=408, detail="Command execution timed out")
    except Exception as e:
        log_message(f"Error executing command '{command}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Command execution failed: {str(e)}")

# Add cleanup endpoint
@app.post("/stop-metasploit")
async def stop_metasploit():
    global metasploit_process
    if metasploit_process:
        metasploit_process.terminate()
        metasploit_process.wait()
        metasploit_process = None
        return {"success": True, "message": "Metasploit stopped"}
    return {"success": False, "message": "No Metasploit process running"}

# Add status endpoint
@app.get("/metasploit-status")
async def get_metasploit_status():
    global metasploit_process
    if metasploit_process and metasploit_process.poll() is None:
        return {"running": True, "pid": metasploit_process.pid}
    return {"running": False}

# Add RPC status endpoint
@app.get("/metasploit-rpc-status")
async def get_metasploit_rpc_status():
    global msf_rpc_client, msf_token
    if msf_rpc_client and msf_token:
        return {"connected": True, "token": msf_token[:10] + "..."}
    return {"connected": False}

# Add this endpoint to get current working directory
@app.get("/get-current-directory")
async def get_current_directory():
    global current_wd
    return {"current_directory": current_wd}

@app.get("/check-wsl-status")
async def check_wsl_status():
    try:
        # Since we're already in WSL, check the current environment
        # Check current working directory
        pwd_result = subprocess.run(
            ['pwd'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Check if metasploit-framework directory exists
        msf_check = subprocess.run(
            ['bash', '-c', 'ls -la ~/metasploit-framework'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        msf_exists = msf_check.returncode == 0
        
        # Check if msfconsole is available
        msfconsole_check = subprocess.run(
            ['which', 'msfconsole'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        msfconsole_available = msfconsole_check.returncode == 0
        
        # Check if we're in WSL
        wsl_check = subprocess.run(
            ['bash', '-c', 'cat /proc/version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        is_wsl = 'microsoft' in wsl_check.stdout.lower() or 'wsl' in wsl_check.stdout.lower()
        
        return {
            "wsl_available": True,
            "is_running_in_wsl": is_wsl,
            "current_directory": pwd_result.stdout.strip(),
            "metasploit_directory_exists": msf_exists,
            "msfconsole_available": msfconsole_available,
            "metasploit_path": msfconsole_check.stdout.strip() if msfconsole_available else None,
            "wsl_version_info": wsl_check.stdout.strip()
        }
        
    except Exception as e:
        return {
            "wsl_available": False,
            "error": str(e)
        }

# Add this endpoint to get Metasploit details
@app.post("/metasploit-details")
async def get_metasploit_details(request: Request):
    try:
        data = await request.json()
        log_message(f"Metasploit details request received for host: {data.get('host', 'unknown')}")
        
        # Check if we have enriched services with exploits
        services = data.get('services', [])
        log_message(f"Services with exploits: {len(services)}")
        
        # If services don't have exploits, we need to run exploit discovery first
        if not any(service.get('exploits') for service in services):
            log_message("No exploits found in services, running exploit discovery first...")
            from exploit.exploitation import exploit_services
            services = exploit_services(services)
        
        # Now process the exploits for Metasploit details
        from find_metasploit_exploit import process_exploits_for_host
        
        # Create the host data structure
        host_data = {
            'host': data.get('host'),
            'services': services
        }
        
        results = process_exploits_for_host(host_data)
        log_message(f"AI generated {len(results)} exploit details")
        
        return {"exploits": results}
    except Exception as e:
        log_message(f"Error in metasploit-details: {str(e)}")
        return {"error": str(e)}

        
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
